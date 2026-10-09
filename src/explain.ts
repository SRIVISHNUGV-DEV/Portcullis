// Plain-English descriptions for human reviewers.
//
// Addresses are always printed in full: shortened forms (0x1234…abcd) are exactly
// what address-poisoning attacks imitate.

import type { Action } from './decoder.js';
import type { CompiledPolicy } from './policy.js';
import { formatUnits } from './units.js';

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

export function label(policy: CompiledPolicy, address: string, wallet?: string): string {
  if (address === wallet) return `the agent wallet (${address})`;
  if (address === ZERO_ADDRESS) return `the zero address (${address})`;
  const name =
    policy.protocols.get(address)?.name ?? policy.tokens.get(address)?.symbol ?? policy.nfts.get(address)?.name;
  return name ? `${name} (${address})` : address;
}

export function formatNative(policy: CompiledPolicy, amount: bigint): string {
  return `${formatUnits(amount, 18)} ${policy.policy.native.symbol}`;
}

export function formatTokenAmount(policy: CompiledPolicy, token: string, amount: bigint): string {
  const rule = policy.tokens.get(token);
  return rule ? `${formatUnits(amount, rule.decimals)} ${rule.symbol}` : `${amount} base units of unlisted token ${token}`;
}

function tokenName(policy: CompiledPolicy, token: string): string {
  const rule = policy.tokens.get(token);
  return rule ? `${rule.symbol} (${token})` : `unlisted token ${token}`;
}

function withValue(policy: CompiledPolicy, text: string, value: bigint): string {
  return value > 0n ? `${text}, sending ${formatNative(policy, value)}` : text;
}

export function describeAction(action: Action, policy: CompiledPolicy, wallet: string): string {
  const l = (a: string) => label(policy, a, wallet);
  switch (action.type) {
    case 'native_transfer':
      return `Send ${formatNative(policy, action.amount)} to ${l(action.to)}`;
    case 'token_transfer': {
      const amount = action.standardKnown
        ? formatTokenAmount(policy, action.token, action.amount)
        : `amount or token ID ${action.amount} of unlisted contract ${action.token} (ERC-20 vs ERC-721 not confirmed)`;
      switch (action.method) {
        case 'transfer':
          return `Transfer ${amount} to ${l(action.to)}`;
        case 'transferAndCall':
          return `Transfer ${amount} to ${l(action.to)} and trigger the recipient's onTokenTransfer callback`;
        case 'transferWithAuthorization':
          return `Submit a signed EIP-3009 authorization moving ${amount} from ${l(action.from)} to ${l(action.to)}`;
        case 'transferFrom':
          return action.from === wallet
            ? `Transfer ${amount} from ${l(action.from)} to ${l(action.to)}`
            : `Pull ${amount} from ${l(action.from)} to ${l(action.to)} using an existing allowance`;
      }
      break;
    }
    case 'token_approval': {
      const via =
        action.method === 'permit2.approve'
          ? ` through Permit2${action.expiration !== undefined ? `, expiring ${expiry(action.expiration)}` : ''}`
          : action.method === 'permit'
            ? ` via a signed EIP-2612 permit from ${l(action.owner)}`
            : '';
      if (action.amount === 0n && action.method !== 'increaseAllowance') {
        return `Revoke ${l(action.spender)}'s allowance for ${tokenName(policy, action.token)}${via}`;
      }
      if (action.unlimited) {
        return `Grant ${l(action.spender)} an UNLIMITED allowance for ${tokenName(policy, action.token)}${via} — it could move the entire balance at any time without another agent transaction`;
      }
      const amount = formatTokenAmount(policy, action.token, action.amount);
      return action.method === 'increaseAllowance'
        ? `Increase ${l(action.spender)}'s allowance by ${amount}${via}`
        : `Allow ${l(action.spender)} to spend up to ${amount}${via}`;
    }
    case 'token_allowance_decrease':
      return `Reduce ${l(action.spender)}'s allowance by ${formatTokenAmount(policy, action.token, action.amount)}`;
    case 'nft_transfer': {
      const what = action.standard === 'erc1155' ? `${action.amount} of token #${action.tokenId}` : `NFT #${action.tokenId}`;
      const from = action.from === wallet ? '' : ` from ${l(action.from)}`;
      return `Transfer ${what} of ${l(action.collection)}${from} to ${l(action.to)}`;
    }
    case 'nft_approval':
      return action.spender === ZERO_ADDRESS
        ? `Clear the approval for NFT #${action.tokenId} of ${l(action.collection)}`
        : `Allow ${l(action.spender)} to transfer NFT #${action.tokenId} of ${l(action.collection)}`;
    case 'operator_approval':
      return action.approved
        ? `Grant ${l(action.operator)} control of ALL tokens in ${l(action.collection)} (setApprovalForAll)`
        : `Revoke ${l(action.operator)}'s operator access to ${l(action.collection)}`;
    case 'swap': {
      const route = action.pools.length > 1 ? ` via ${action.pools.length} pools` : '';
      const amounts = action.exact === 'input'
        ? `${formatTokenAmount(policy, action.tokenIn, action.amountIn)} for at least ${formatTokenAmount(policy, action.tokenOut, action.amountOut)}`
        : `at most ${formatTokenAmount(policy, action.tokenIn, action.amountIn)} for exactly ${formatTokenAmount(policy, action.tokenOut, action.amountOut)}`;
      return `Swap ${amounts} on ${l(action.router)}${route}, sending the output to ${l(action.recipient)}`;
    }
    case 'router_withdrawal':
      return `Withdraw ${action.token ? tokenName(policy, action.token) : 'unwrapped WETH as ETH'} held by ${l(action.router)} to ${l(action.recipient)}`;
    case 'contract_call':
      return withValue(
        policy,
        action.selector
          ? `Call function ${action.selector} on ${l(action.target)}`
          : `Call the fallback/receive function of ${l(action.target)}`,
        action.value,
      );
    case 'contract_deployment':
      return withValue(policy, `Deploy a new contract (${action.initCodeBytes} bytes of init code)`, action.value);
    case 'wallet_self_call':
      return `Call function ${action.selector ?? '(fallback)'} on the agent wallet itself — this can change owners, modules or session keys`;
  }
}

function expiry(seconds: bigint): string {
  if (seconds === 0n) return 'at the end of the block (Permit2 default)';
  if (seconds >= 253_402_300_800n) return 'never (far-future expiration)';
  return new Date(Number(seconds) * 1000).toISOString();
}

export function formatDuration(seconds: number): string {
  const units: [number, string][] = [[86_400, 'day'], [3_600, 'hour'], [60, 'minute'], [1, 'second']];
  const [size, name] = units.find(([n]) => seconds % n === 0)!;
  const count = seconds / size;
  return `${count} ${name}${count === 1 ? '' : 's'}`;
}

export function joinSentences(items: readonly string[]): string {
  if (items.length <= 1) return items[0] ?? '';
  return `${items.slice(0, -1).join('; ')}; and ${items[items.length - 1]}`;
}

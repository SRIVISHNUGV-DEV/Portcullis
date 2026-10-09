// Calldata decoder: turns raw EVM calls into the asset-level actions they perform.
//
// Every recognised selector is decoded strictly (see abi.ts). A recognised selector
// with unreadable or non-canonical arguments is reported as an issue — never silently
// downgraded to "unknown call", which would let a malformed transfer bypass token
// limits. Calls from the agent wallet to itself through `execute`/`executeBatch` are
// unwrapped recursively so nested transfers cannot hide behind a wallet wrapper.

import { AbiError, T, bytesToHex, decodeAbi, hexToBytes, type AbiType, type AbiValue } from './abi.js';
import type { CompiledPolicy } from './policy.js';
import type { NormalizedRequest } from './schemas.js';

/** Canonical Uniswap Permit2 deployment (same address on all supported chains). */
export const PERMIT2_ADDRESS = '0x000000000022d473030f116ddee9f6b43ac78ba3';

/**
 * Allowances at or above 2^128 base units are treated as unlimited. No real token
 * supply approaches this, so such an approval is effectively a blank cheque.
 */
export const UNLIMITED_APPROVAL_THRESHOLD = 1n << 128n;

export const SELECTORS = {
  transfer: '0xa9059cbb',
  transferFrom: '0x23b872dd',
  approve: '0x095ea7b3',
  increaseAllowance: '0x39509351',
  decreaseAllowance: '0xa457c2d7',
  transferAndCall: '0x4000aea0',
  transferWithAuthorization: '0xe3ee160e',
  permit: '0xd505accf',
  safeTransferFrom721: '0x42842e0e',
  safeTransferFrom721WithData: '0xb88d4fde',
  setApprovalForAll: '0xa22cb465',
  safeTransferFrom1155: '0xf242432a',
  safeBatchTransferFrom1155: '0x2eb2c2d6',
  permit2Approve: '0x87517c45',
  walletExecute: '0xb61d27f6',
  walletExecuteBatch: '0x34fcd5be',
} as const;

/** Uniswap SwapRouter02 functions decoded for protocols with `kind: 'uniswap-v3-router'`. */
export const UNISWAP_V3_ROUTER_SELECTORS = {
  exactInputSingle: '0x04e45aaf',
  exactInput: '0xb858183f',
  exactOutputSingle: '0x5023b4df',
  exactOutput: '0x09b81346',
  multicall: '0xac9650d8',
  multicallWithDeadline: '0x5ae401dc',
  multicallWithBlockhash: '0x1f0464d1',
  unwrapWETH9: '0x49404b7c',
  unwrapWETH9ToSender: '0x49616997',
  sweepToken: '0xdf2ab5bb',
  sweepTokenToSender: '0xe90a182f',
  refundETH: '0x12210e8a',
} as const;

const ROUTER_SELECTOR_SET: ReadonlySet<string> = new Set(Object.values(UNISWAP_V3_ROUTER_SELECTORS));

/** True if `selector` is a SwapRouter02 function the decoder understands. */
export function isDecodedRouterSelector(selector: string | null): boolean {
  return selector !== null && ROUTER_SELECTOR_SET.has(selector);
}

/** SwapRouter02 recipient placeholders: msg.sender and the router itself. */
const ROUTER_MSG_SENDER = '0x0000000000000000000000000000000000000001';
const ROUTER_ADDRESS_THIS = '0x0000000000000000000000000000000000000002';

/** One pool hop, in swap direction. */
export interface SwapPool {
  readonly tokenIn: string;
  readonly tokenOut: string;
  readonly fee: number;
}

export type Action =
  | { type: 'native_transfer'; path: string; to: string; amount: bigint }
  | {
      type: 'token_transfer';
      path: string;
      token: string;
      from: string;
      to: string;
      amount: bigint;
      method: 'transfer' | 'transferFrom' | 'transferAndCall' | 'transferWithAuthorization';
      /** False when the contract is not configured, so ERC-20 vs ERC-721 cannot be confirmed. */
      standardKnown: boolean;
    }
  | {
      type: 'token_approval';
      path: string;
      token: string;
      owner: string;
      spender: string;
      amount: bigint;
      unlimited: boolean;
      method: 'approve' | 'increaseAllowance' | 'permit' | 'permit2.approve';
      standardKnown: boolean;
      expiration?: bigint;
    }
  | { type: 'token_allowance_decrease'; path: string; token: string; spender: string; amount: bigint }
  | {
      type: 'nft_transfer';
      path: string;
      collection: string;
      standard: 'erc721' | 'erc1155';
      from: string;
      to: string;
      tokenId: bigint;
      amount: bigint;
    }
  | { type: 'nft_approval'; path: string; collection: string; spender: string; tokenId: bigint }
  | { type: 'operator_approval'; path: string; collection: string; operator: string; approved: boolean }
  | {
      type: 'swap';
      path: string;
      router: string;
      /** `input`: amountIn is exact, amountOut is the minimum. `output`: amountOut is exact, amountIn is the maximum. */
      exact: 'input' | 'output';
      tokenIn: string;
      tokenOut: string;
      pools: SwapPool[];
      /** Placeholders resolved: msg.sender is the agent wallet, ADDRESS_THIS is the router. */
      recipient: string;
      amountIn: bigint;
      amountOut: bigint;
    }
  | { type: 'router_withdrawal'; path: string; router: string; /** null: WETH unwrapped to ETH */ token: string | null; recipient: string; minimum: bigint }
  | { type: 'contract_call'; path: string; target: string; selector: string | null; value: bigint }
  | { type: 'contract_deployment'; path: string; value: bigint; initCodeBytes: number }
  | { type: 'wallet_self_call'; path: string; selector: string | null };

export type DecodeIssueCode =
  | 'CALLDATA_MALFORMED'
  | 'CALLDATA_NON_CANONICAL'
  | 'CALLDATA_TOO_LARGE'
  | 'NESTING_TOO_DEEP'
  | 'TOO_MANY_CALLS';

export interface DecodeIssue {
  readonly path: string;
  readonly code: DecodeIssueCode;
  readonly message: string;
}

/** A call that leaves the agent wallet (or deploys a contract). Wrapper self-calls are not listed. */
export interface EffectiveCall {
  readonly path: string;
  readonly to: string | null;
  readonly value: bigint;
  readonly data: string;
  readonly selector: string | null;
}

export interface DecodeResult {
  readonly calls: EffectiveCall[];
  readonly actions: Action[];
  readonly issues: DecodeIssue[];
}

interface Ctx {
  readonly wallet: string;
  readonly policy: CompiledPolicy;
  readonly out: { calls: EffectiveCall[]; actions: Action[]; issues: DecodeIssue[] };
  callCount: number;
}

const str = (v: AbiValue | undefined) => v as string;
const big = (v: AbiValue | undefined) => v as bigint;

type Handler = (args: AbiValue[], target: string, path: string, ctx: Ctx) => Action[] | null;

interface Method {
  readonly types: readonly AbiType[];
  readonly handle: Handler;
}

const approval = (
  path: string,
  token: string,
  owner: string,
  spender: string,
  amount: bigint,
  method: Extract<Action, { type: 'token_approval' }>['method'],
  ctx: Ctx,
  expiration?: bigint,
): Action => ({
  type: 'token_approval',
  path,
  token,
  owner,
  spender,
  amount,
  unlimited: amount >= UNLIMITED_APPROVAL_THRESHOLD,
  method,
  standardKnown: ctx.policy.tokens.has(token),
  ...(expiration !== undefined ? { expiration } : {}),
});

const METHODS: Readonly<Record<string, Method>> = {
  [SELECTORS.transfer]: {
    types: [T.address, T.uint256],
    handle: ([to, amount], token, path, ctx) => [
      { type: 'token_transfer', path, token, from: ctx.wallet, to: str(to), amount: big(amount), method: 'transfer', standardKnown: ctx.policy.tokens.has(token) },
    ],
  },
  [SELECTORS.transferFrom]: {
    types: [T.address, T.address, T.uint256],
    handle: ([from, to, amountOrId], target, path, ctx) =>
      ctx.policy.nfts.has(target)
        ? [{ type: 'nft_transfer', path, collection: target, standard: 'erc721', from: str(from), to: str(to), tokenId: big(amountOrId), amount: 1n }]
        : [{ type: 'token_transfer', path, token: target, from: str(from), to: str(to), amount: big(amountOrId), method: 'transferFrom', standardKnown: ctx.policy.tokens.has(target) }],
  },
  [SELECTORS.approve]: {
    types: [T.address, T.uint256],
    handle: ([spender, amountOrId], target, path, ctx) =>
      ctx.policy.nfts.has(target)
        ? [{ type: 'nft_approval', path, collection: target, spender: str(spender), tokenId: big(amountOrId) }]
        : [approval(path, target, ctx.wallet, str(spender), big(amountOrId), 'approve', ctx)],
  },
  [SELECTORS.increaseAllowance]: {
    types: [T.address, T.uint256],
    handle: ([spender, amount], token, path, ctx) => [approval(path, token, ctx.wallet, str(spender), big(amount), 'increaseAllowance', ctx)],
  },
  [SELECTORS.decreaseAllowance]: {
    types: [T.address, T.uint256],
    handle: ([spender, amount], token, path) => [{ type: 'token_allowance_decrease', path, token, spender: str(spender), amount: big(amount) }],
  },
  [SELECTORS.transferAndCall]: {
    types: [T.address, T.uint256, T.bytes],
    handle: ([to, amount], token, path, ctx) => [
      { type: 'token_transfer', path, token, from: ctx.wallet, to: str(to), amount: big(amount), method: 'transferAndCall', standardKnown: ctx.policy.tokens.has(token) },
    ],
  },
  [SELECTORS.transferWithAuthorization]: {
    types: [T.address, T.address, T.uint256, T.uint256, T.uint256, T.bytes32, T.uint8, T.bytes32, T.bytes32],
    handle: ([from, to, amount], token, path, ctx) => [
      { type: 'token_transfer', path, token, from: str(from), to: str(to), amount: big(amount), method: 'transferWithAuthorization', standardKnown: ctx.policy.tokens.has(token) },
    ],
  },
  [SELECTORS.permit]: {
    types: [T.address, T.address, T.uint256, T.uint256, T.uint8, T.bytes32, T.bytes32],
    handle: ([owner, spender, amount, deadline], token, path, ctx) => [approval(path, token, str(owner), str(spender), big(amount), 'permit', ctx, big(deadline))],
  },
  [SELECTORS.safeTransferFrom721]: {
    types: [T.address, T.address, T.uint256],
    handle: ([from, to, id], collection, path) => [{ type: 'nft_transfer', path, collection, standard: 'erc721', from: str(from), to: str(to), tokenId: big(id), amount: 1n }],
  },
  [SELECTORS.safeTransferFrom721WithData]: {
    types: [T.address, T.address, T.uint256, T.bytes],
    handle: ([from, to, id], collection, path) => [{ type: 'nft_transfer', path, collection, standard: 'erc721', from: str(from), to: str(to), tokenId: big(id), amount: 1n }],
  },
  [SELECTORS.setApprovalForAll]: {
    types: [T.address, T.bool],
    handle: ([operator, approved], collection, path) => [{ type: 'operator_approval', path, collection, operator: str(operator), approved: approved as boolean }],
  },
  [SELECTORS.safeTransferFrom1155]: {
    types: [T.address, T.address, T.uint256, T.uint256, T.bytes],
    handle: ([from, to, id, amount], collection, path) => [{ type: 'nft_transfer', path, collection, standard: 'erc1155', from: str(from), to: str(to), tokenId: big(id), amount: big(amount) }],
  },
  [SELECTORS.safeBatchTransferFrom1155]: {
    types: [T.address, T.address, T.array(T.uint256), T.array(T.uint256), T.bytes],
    handle: ([from, to, ids, amounts], collection, path, ctx) => {
      const idList = ids as bigint[];
      const amountList = amounts as bigint[];
      if (idList.length !== amountList.length) {
        ctx.out.issues.push({ path, code: 'CALLDATA_MALFORMED', message: 'ERC-1155 batch transfer has mismatched ids/amounts lengths' });
        return [];
      }
      return idList.map((tokenId, i) => ({
        type: 'nft_transfer' as const, path, collection, standard: 'erc1155' as const, from: str(from), to: str(to), tokenId, amount: amountList[i]!,
      }));
    },
  },
  [SELECTORS.permit2Approve]: {
    types: [T.address, T.address, T.uint160, T.uint48],
    handle: ([token, spender, amount, expiration], target, path, ctx) =>
      target === PERMIT2_ADDRESS
        ? [approval(path, str(token), ctx.wallet, str(spender), big(amount), 'permit2.approve', ctx, big(expiration))]
        : null,
  },
};

export type SwapAction = Extract<Action, { type: 'swap' }>;

const SWAP_SINGLE = T.tuple(T.address, T.address, T.uint24, T.address, T.uint256, T.uint256, T.uint160);
const SWAP_MULTI = T.tuple(T.bytes, T.address, T.uint256, T.uint256);

/** Parse a packed V3 path (token, fee, token, …). Exact-output paths are encoded tokenOut-first. */
function decodeRoute(hex: string, reversed: boolean): SwapPool[] | null {
  const b = hexToBytes(hex);
  if (b.length < 43 || (b.length - 20) % 23 !== 0) return null;
  const tokens: string[] = [];
  const fees: number[] = [];
  for (let o = 0; ; o += 23) {
    tokens.push(bytesToHex(b.subarray(o, o + 20)));
    if (o + 20 === b.length) break;
    fees.push((b[o + 20]! << 16) | (b[o + 21]! << 8) | b[o + 22]!);
  }
  if (reversed) {
    tokens.reverse();
    fees.reverse();
  }
  return fees.map((fee, i) => ({ tokenIn: tokens[i]!, tokenOut: tokens[i + 1]!, fee }));
}

/** Decode one SwapRouter02 call. Returns false for functions it doesn't understand. */
function routerCall(router: string, data: Uint8Array, selector: string, path: string, ctx: Ctx, nested: boolean): boolean {
  const R = UNISWAP_V3_ROUTER_SELECTORS;
  const resolve = (r: string) => (r === ROUTER_MSG_SENDER ? ctx.wallet : r === ROUTER_ADDRESS_THIS ? router : r);
  const swap = (exact: 'input' | 'output', pools: SwapPool[], recipient: string, amountIn: bigint, amountOut: bigint) => {
    ctx.out.actions.push({
      type: 'swap', path, router, exact, tokenIn: pools[0]!.tokenIn, tokenOut: pools[pools.length - 1]!.tokenOut,
      pools, recipient: resolve(recipient), amountIn, amountOut,
    });
  };
  const withdraw = (token: string | null, recipient: string, minimum: bigint) => {
    ctx.out.actions.push({ type: 'router_withdrawal', path, router, token, recipient: resolve(recipient), minimum });
  };
  switch (selector) {
    case R.exactInputSingle:
    case R.exactOutputSingle: {
      const args = decodeArgs([SWAP_SINGLE], data, path, ctx);
      if (!args) return true;
      const [tokenIn, tokenOut, fee, recipient, a, b] = args[0] as AbiValue[];
      const pools = [{ tokenIn: str(tokenIn), tokenOut: str(tokenOut), fee: Number(big(fee)) }];
      if (selector === R.exactInputSingle) swap('input', pools, str(recipient), big(a), big(b));
      else swap('output', pools, str(recipient), big(b), big(a));
      return true;
    }
    case R.exactInput:
    case R.exactOutput: {
      const args = decodeArgs([SWAP_MULTI], data, path, ctx);
      if (!args) return true;
      const [route, recipient, a, b] = args[0] as AbiValue[];
      const pools = decodeRoute(str(route), selector === R.exactOutput);
      if (!pools) {
        ctx.out.issues.push({ path, code: 'CALLDATA_MALFORMED', message: 'Swap path is not a valid Uniswap V3 path' });
        return true;
      }
      if (selector === R.exactInput) swap('input', pools, str(recipient), big(a), big(b));
      else swap('output', pools, str(recipient), big(b), big(a));
      return true;
    }
    case R.unwrapWETH9: {
      const args = decodeArgs([T.uint256, T.address], data, path, ctx);
      if (args) withdraw(null, str(args[1]), big(args[0]));
      return true;
    }
    case R.unwrapWETH9ToSender: {
      const args = decodeArgs([T.uint256], data, path, ctx);
      if (args) withdraw(null, ctx.wallet, big(args[0]));
      return true;
    }
    case R.sweepToken: {
      const args = decodeArgs([T.address, T.uint256, T.address], data, path, ctx);
      if (args) withdraw(str(args[0]), str(args[2]), big(args[1]));
      return true;
    }
    case R.sweepTokenToSender: {
      const args = decodeArgs([T.address, T.uint256], data, path, ctx);
      if (args) withdraw(str(args[0]), ctx.wallet, big(args[1]));
      return true;
    }
    case R.refundETH:
      decodeArgs([], data, path, ctx);
      return true;
    case R.multicall:
    case R.multicallWithDeadline:
    case R.multicallWithBlockhash: {
      if (nested) {
        ctx.out.issues.push({ path, code: 'NESTING_TOO_DEEP', message: 'Nested router multicall is not supported' });
        return true;
      }
      const types = selector === R.multicall ? [T.array(T.bytes)] : [selector === R.multicallWithDeadline ? T.uint256 : T.bytes32, T.array(T.bytes)];
      const args = decodeArgs(types, data, path, ctx);
      if (!args) return true;
      (args[args.length - 1] as string[]).forEach((innerHex, i) => {
        const inner = hexToBytes(innerHex);
        const innerPath = `${path}/${i}`;
        const innerSelector = inner.length >= 4 ? innerHex.slice(0, 10) : null;
        if (!innerSelector || !routerCall(router, inner, innerSelector, innerPath, ctx, true)) {
          ctx.out.actions.push({ type: 'contract_call', path: innerPath, target: router, selector: innerSelector, value: 0n });
        }
      });
      return true;
    }
    default:
      return false;
  }
}

const EXECUTE_TYPES = [T.address, T.uint256, T.bytes] as const;
const EXECUTE_BATCH_TYPES = [T.array(T.tuple(T.address, T.uint256, T.bytes))] as const;

function decodeArgs(types: readonly AbiType[], data: Uint8Array, path: string, ctx: Ctx): AbiValue[] | null {
  try {
    return decodeAbi(types, data.subarray(4), { maxArrayLength: ctx.policy.policy.limits.maxCalls * 16 });
  } catch (e) {
    const nonCanonical = e instanceof AbiError && e.code === 'NON_CANONICAL';
    ctx.out.issues.push({
      path,
      code: nonCanonical ? 'CALLDATA_NON_CANONICAL' : 'CALLDATA_MALFORMED',
      message: e instanceof Error ? e.message : 'Calldata could not be decoded',
    });
    return null;
  }
}

function visit(to: string | null, value: bigint, dataHex: string, path: string, depth: number, ctx: Ctx): void {
  ctx.callCount += 1;
  if (ctx.callCount > ctx.policy.policy.limits.maxCalls) {
    if (ctx.callCount === ctx.policy.policy.limits.maxCalls + 1) {
      ctx.out.issues.push({ path, code: 'TOO_MANY_CALLS', message: `Request exceeds the ${ctx.policy.policy.limits.maxCalls}-call limit` });
    }
    return;
  }
  const byteLength = (dataHex.length - 2) / 2;
  if (byteLength > ctx.policy.policy.limits.maxCalldataBytes) {
    ctx.out.issues.push({ path, code: 'CALLDATA_TOO_LARGE', message: `Calldata is ${byteLength} bytes; limit is ${ctx.policy.policy.limits.maxCalldataBytes}` });
    return;
  }
  const data = hexToBytes(dataHex);
  const selector = data.length >= 4 ? dataHex.slice(0, 10) : null;

  if (to === null) {
    ctx.out.calls.push({ path, to, value, data: dataHex, selector: null });
    ctx.out.actions.push({ type: 'contract_deployment', path, value, initCodeBytes: byteLength });
    return;
  }

  if (to === ctx.wallet) {
    if (data.length === 0) return; // Value sent to itself: no outflow.
    if (selector === SELECTORS.walletExecute || selector === SELECTORS.walletExecuteBatch) {
      if (depth >= ctx.policy.policy.limits.maxNestingDepth) {
        ctx.out.issues.push({ path, code: 'NESTING_TOO_DEEP', message: `Wallet calls nested deeper than ${ctx.policy.policy.limits.maxNestingDepth} levels` });
        return;
      }
      if (selector === SELECTORS.walletExecute) {
        const args = decodeArgs(EXECUTE_TYPES, data, path, ctx);
        if (args) visit(str(args[0]), big(args[1]), str(args[2]), `${path}.0`, depth + 1, ctx);
      } else {
        const args = decodeArgs(EXECUTE_BATCH_TYPES, data, path, ctx);
        if (args) {
          (args[0] as AbiValue[][]).forEach((c, i) => visit(str(c[0]), big(c[1]), str(c[2]), `${path}.${i}`, depth + 1, ctx));
        }
      }
      return;
    }
    ctx.out.actions.push({ type: 'wallet_self_call', path, selector });
    return;
  }

  ctx.out.calls.push({ path, to, value, data: dataHex, selector });

  if (data.length === 0 && value > 0n) {
    ctx.out.actions.push({ type: 'native_transfer', path, to, amount: value });
    return;
  }

  if (ctx.policy.protocols.get(to)?.kind === 'uniswap-v3-router') {
    ctx.out.actions.push({ type: 'contract_call', path, target: to, selector, value });
    if (selector) routerCall(to, data, selector, path, ctx, false);
    return;
  }

  const method = selector ? METHODS[selector] : undefined;
  if (method && selector) {
    const args = decodeArgs(method.types, data, path, ctx);
    if (!args) return;
    const actions = method.handle(args, to, path, ctx);
    if (actions) {
      ctx.out.actions.push(...actions);
      return;
    }
  }
  ctx.out.actions.push({ type: 'contract_call', path, target: to, selector, value });
}

/** Decode a normalized request into effective calls, asset actions and decoding issues. Never throws. */
export function decodeRequest(request: NormalizedRequest, policy: CompiledPolicy): DecodeResult {
  const ctx: Ctx = { wallet: request.from, policy, out: { calls: [], actions: [], issues: [] }, callCount: 0 };
  request.calls.forEach((c, i) => {
    try {
      visit(c.to, c.value, c.data, String(i), 0, ctx);
    } catch (e) {
      ctx.out.issues.push({ path: String(i), code: 'CALLDATA_MALFORMED', message: e instanceof Error ? e.message : 'Decode failure' });
    }
  });
  return ctx.out;
}

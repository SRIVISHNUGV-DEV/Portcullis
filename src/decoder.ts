// Calldata decoder: turns raw EVM calls into the asset-level actions they perform.
//
// Every recognised selector is decoded strictly (see abi.ts). A recognised selector
// with unreadable or non-canonical arguments is reported as an issue — never silently
// downgraded to "unknown call", which would let a malformed transfer bypass token
// limits. Calls from the agent wallet to itself through `execute`/`executeBatch` are
// unwrapped recursively so nested transfers cannot hide behind a wallet wrapper.
//
// KNOWN LIMITATION — Permit2 SignatureTransfer (off-chain path):
// This decoder handles Permit2 `approve` (selector 0x87517c45, on-chain allowance grant).
// It does NOT handle `permitTransferFrom` / `SignatureTransfer` because those are executed
// by the *recipient*, not the agent: the agent signs an off-chain message, and then a third
// party calls Permit2 with that signature. The firewall therefore never sees the on-chain
// leg. Mitigation: route signing through check_sign_typed_data (which blocks PermitTransferFrom
// typed data) so the signature step is intercepted before anything is broadcast.

import { AbiError, T, decodeAbi, hexToBytes, type AbiType, type AbiValue } from './abi.js';
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
  // permit2.approve (on-chain allowance grant to Permit2). Note: Permit2 SignatureTransfer
  // (off-chain PermitTransferFrom) is NOT decoded here — it has no agent-initiated on-chain
  // leg. See the file-level comment for the mitigation.
  [SELECTORS.permit2Approve]: {
    types: [T.address, T.address, T.uint160, T.uint48],
    handle: ([token, spender, amount, expiration], target, path, ctx) =>
      target === PERMIT2_ADDRESS
        ? [approval(path, str(token), ctx.wallet, str(spender), big(amount), 'permit2.approve', ctx, big(expiration))]
        : null,
  },
};

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

import { T, bytesToHex, encodeAbi, type AbiType, type AbiValue } from '../src/abi.js';
import { PERMIT2_ADDRESS, SELECTORS } from '../src/decoder.js';
import type { PolicyInput } from '../src/schemas.js';
import { parseUnits, UINT256_MAX } from '../src/units.js';

export const CHAIN = 8453;
export const WALLET = '0x1111111111111111111111111111111111111111';
export const USDC = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
export const WETH = '0x4200000000000000000000000000000000000006';
export const ROUTER = '0x2626664c2603336e57b271c5c0b26f421741e481';
export const NFT = '0x3333333333333333333333333333333333333333';
export const ALICE = '0xa11ce00000000000000000000000000000000001';
export const BOB = '0xb0b0000000000000000000000000000000000002';
export const MALLORY = '0xbad0000000000000000000000000000000000bad';
export const TREASURY = '0x7ea5000000000000000000000000000000000007';
export const UNKNOWN_TOKEN = '0x9999999999999999999999999999999999999999';
export const UNKNOWN_CONTRACT = '0x8888888888888888888888888888888888888888';
export { PERMIT2_ADDRESS, UINT256_MAX };

export const usdc = (v: string) => parseUnits(v, 6);
export const eth = (v: string) => parseUnits(v, 18);

export function encodeCall(selector: string, types: readonly AbiType[], values: readonly AbiValue[]): string {
  return selector + bytesToHex(encodeAbi(types, values)).slice(2);
}

export const erc20 = {
  transfer: (to: string, amount: bigint) => encodeCall(SELECTORS.transfer, [T.address, T.uint256], [to, amount]),
  transferFrom: (from: string, to: string, amount: bigint) =>
    encodeCall(SELECTORS.transferFrom, [T.address, T.address, T.uint256], [from, to, amount]),
  approve: (spender: string, amount: bigint) => encodeCall(SELECTORS.approve, [T.address, T.uint256], [spender, amount]),
  increaseAllowance: (spender: string, amount: bigint) =>
    encodeCall(SELECTORS.increaseAllowance, [T.address, T.uint256], [spender, amount]),
  decreaseAllowance: (spender: string, amount: bigint) =>
    encodeCall(SELECTORS.decreaseAllowance, [T.address, T.uint256], [spender, amount]),
  transferAndCall: (to: string, amount: bigint, data = '0x') =>
    encodeCall(SELECTORS.transferAndCall, [T.address, T.uint256, T.bytes], [to, amount, data]),
  transferWithAuthorization: (from: string, to: string, amount: bigint) =>
    encodeCall(
      SELECTORS.transferWithAuthorization,
      [T.address, T.address, T.uint256, T.uint256, T.uint256, T.bytes32, T.uint8, T.bytes32, T.bytes32],
      [from, to, amount, 0n, 2n ** 40n, `0x${'01'.repeat(32)}`, 27n, `0x${'02'.repeat(32)}`, `0x${'03'.repeat(32)}`],
    ),
  permit: (owner: string, spender: string, amount: bigint) =>
    encodeCall(
      SELECTORS.permit,
      [T.address, T.address, T.uint256, T.uint256, T.uint8, T.bytes32, T.bytes32],
      [owner, spender, amount, 2n ** 40n, 27n, `0x${'02'.repeat(32)}`, `0x${'03'.repeat(32)}`],
    ),
};

export const erc721 = {
  safeTransferFrom: (from: string, to: string, id: bigint) =>
    encodeCall(SELECTORS.safeTransferFrom721, [T.address, T.address, T.uint256], [from, to, id]),
  safeTransferFromWithData: (from: string, to: string, id: bigint, data: string) =>
    encodeCall(SELECTORS.safeTransferFrom721WithData, [T.address, T.address, T.uint256, T.bytes], [from, to, id, data]),
  setApprovalForAll: (operator: string, approved: boolean) =>
    encodeCall(SELECTORS.setApprovalForAll, [T.address, T.bool], [operator, approved]),
};

export const erc1155 = {
  safeTransferFrom: (from: string, to: string, id: bigint, amount: bigint) =>
    encodeCall(SELECTORS.safeTransferFrom1155, [T.address, T.address, T.uint256, T.uint256, T.bytes], [from, to, id, amount, '0x']),
  safeBatchTransferFrom: (from: string, to: string, ids: bigint[], amounts: bigint[]) =>
    encodeCall(
      SELECTORS.safeBatchTransferFrom1155,
      [T.address, T.address, T.array(T.uint256), T.array(T.uint256), T.bytes],
      [from, to, ids, amounts, '0x'],
    ),
};

export const permit2Approve = (token: string, spender: string, amount: bigint, expiration: bigint) =>
  encodeCall(SELECTORS.permit2Approve, [T.address, T.address, T.uint160, T.uint48], [token, spender, amount, expiration]);

export const walletExecute = (to: string, value: bigint, data: string) =>
  encodeCall(SELECTORS.walletExecute, [T.address, T.uint256, T.bytes], [to, value, data]);

export const walletExecuteBatch = (calls: Array<[string, bigint, string]>) =>
  encodeCall(SELECTORS.walletExecuteBatch, [T.array(T.tuple(T.address, T.uint256, T.bytes))], [calls]);

/** exactInputSingle on Uniswap's SwapRouter02. */
export const SWAP_SELECTOR = '0x04e45aaf';

const SWAP_SINGLE = T.tuple(T.address, T.address, T.uint24, T.address, T.uint256, T.uint256, T.uint160);

export const router = {
  exactInputSingle: (tokenIn: string, tokenOut: string, recipient: string, amountIn: bigint, amountOutMinimum: bigint, fee = 500n) =>
    encodeCall(SWAP_SELECTOR, [SWAP_SINGLE], [[tokenIn, tokenOut, fee, recipient, amountIn, amountOutMinimum, 0n]]),
  exactOutputSingle: (tokenIn: string, tokenOut: string, recipient: string, amountOut: bigint, amountInMaximum: bigint, fee = 500n) =>
    encodeCall('0x5023b4df', [SWAP_SINGLE], [[tokenIn, tokenOut, fee, recipient, amountOut, amountInMaximum, 0n]]),
  /** Packed path: token, fee, token, … */
  exactInput: (path: string, recipient: string, amountIn: bigint, amountOutMinimum: bigint) =>
    encodeCall('0xb858183f', [T.tuple(T.bytes, T.address, T.uint256, T.uint256)], [[path, recipient, amountIn, amountOutMinimum]]),
  unwrapWETH9: (amountMinimum: bigint, recipient: string) => encodeCall('0x49404b7c', [T.uint256, T.address], [amountMinimum, recipient]),
  multicall: (deadline: bigint, calls: string[]) => encodeCall('0x5ae401dc', [T.uint256, T.array(T.bytes)], [deadline, calls]),
};

export const packPath = (...parts: (string | number)[]) =>
  `0x${parts.map((x) => (typeof x === 'number' ? x.toString(16).padStart(6, '0') : x.slice(2))).join('')}`;

export function basePolicy(overrides: Partial<PolicyInput> = {}): PolicyInput {
  return {
    version: 1,
    name: 'test-agent',
    chainIds: [CHAIN],
    native: { perTransactionMax: eth('0.1'), sessionMax: eth('0.5'), requireApprovalAbove: eth('0.05') },
    tokens: [
      {
        address: USDC,
        symbol: 'USDC',
        decimals: 6,
        perTransactionMax: usdc('1000'),
        sessionMax: usdc('5000'),
        requireApprovalAbove: usdc('500'),
      },
      {
        address: WETH,
        symbol: 'WETH',
        decimals: 18,
        perTransactionMax: eth('1'),
        sessionMax: eth('2'),
        allowedFunctions: ['0xd0e30db0'],
      },
    ],
    nfts: [{ address: NFT, name: 'Agent Badges', standard: 'erc721', allowTransfers: true }],
    protocols: [{ name: 'Uniswap SwapRouter02', address: ROUTER, selectors: [SWAP_SELECTOR], maxNativeValue: eth('0.05') }],
    approvals: { spenders: [PERMIT2_ADDRESS] },
    denylist: [MALLORY],
    ...overrides,
  };
}

export function tx(call: { to?: string | null; value?: bigint; data?: string }) {
  return { chainId: CHAIN, from: WALLET, ...call };
}

export function batch(calls: Array<{ to?: string | null; value?: bigint; data?: string }>) {
  return { chainId: CHAIN, from: WALLET, calls };
}

/** Deterministic clock and ID generator for reproducible tests. */
export function fixedEnv(start = Date.UTC(2026, 9, 8, 12, 0, 0)) {
  let now = start;
  let id = 0;
  return {
    clock: () => now,
    advance: (ms: number) => {
      now += ms;
    },
    generateId: () => `id-${++id}`,
  };
}

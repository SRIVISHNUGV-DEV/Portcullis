import { T, bytesToHex, encodeAbi, hexToBytes } from './abi.js';
import type { SwapAction, SwapPool } from './decoder.js';
import type { QuoteOutcome, SimulationOutcome } from './engine.js';
import type { NormalizedRequest } from './schemas.js';

/**
 * Optional pre-execution simulation. Return `unavailable` (or throw) when the request
 * cannot be simulated faithfully; the firewall then applies
 * `policy.simulation.onUnavailable` rather than assuming success.
 */
export type Simulator = (request: NormalizedRequest, signal: AbortSignal) => Promise<SimulationOutcome>;

export interface RpcSimulatorOptions {
  /** JSON-RPC endpoint for the request's chain. Treat URLs containing API keys as secrets. */
  readonly url: string;
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
}

/**
 * `eth_call` revert check for single-call requests. Batches are reported as
 * unavailable: simulating batched calls independently ignores state changes
 * between them (e.g. approve-then-swap) and would give misleading results.
 */
export function createRpcSimulator(options: RpcSimulatorOptions): Simulator {
  const doFetch = options.fetch ?? fetch;
  const timeoutMs = options.timeoutMs ?? 1500;
  return async (request, signal) => {
    if (request.calls.length !== 1) {
      return { status: 'unavailable', reason: 'eth_call cannot faithfully simulate batched calls' };
    }
    const call = request.calls[0]!;
    const timeout = AbortSignal.timeout(timeoutMs);
    const params: Record<string, string> = {
      from: request.from,
      value: `0x${call.value.toString(16)}`,
      data: call.data,
    };
    if (call.to) params.to = call.to;
    let response: Response;
    try {
      response = await doFetch(options.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [params, 'latest'] }),
        signal: AbortSignal.any([signal, timeout]),
      });
    } catch {
      return { status: 'unavailable', reason: timeout.aborted ? `RPC timed out after ${timeoutMs} ms` : 'RPC request failed' };
    }
    if (!response.ok) return { status: 'unavailable', reason: `RPC returned HTTP ${response.status}` };
    let body: { result?: unknown; error?: { code?: number; message?: string; data?: unknown } };
    try {
      body = (await response.json()) as typeof body;
    } catch {
      return { status: 'unavailable', reason: 'RPC returned invalid JSON' };
    }
    if (body.error) {
      const message = String(body.error.message ?? 'unknown error');
      // Node implementations report reverts as code 3 or with "revert" in the message.
      if (body.error.code === 3 || /revert/i.test(message)) return { status: 'reverted', reason: message.slice(0, 200) };
      return { status: 'unavailable', reason: `RPC error: ${message.slice(0, 200)}` };
    }
    if (typeof body.result !== 'string') return { status: 'unavailable', reason: 'RPC returned no result' };
    return { status: 'ok' };
  };
}

/**
 * Live quote for a decoded swap. Return `unavailable` (or throw) when no quote can be
 * obtained; the firewall then applies `policy.swaps.quoteUnavailable`.
 */
export type Quoter = (swap: SwapAction, signal: AbortSignal) => Promise<QuoteOutcome>;

export interface UniswapV3QuoterOptions {
  /** JSON-RPC endpoint for the swap's chain. Treat URLs containing API keys as secrets. */
  readonly url: string;
  /** QuoterV2 contract, e.g. 0x3d4e44eb1374240ce5f1b871ab261cd16335b76a on Base. */
  readonly quoter: string;
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
}

const QUOTE_SINGLE = T.tuple(T.address, T.address, T.uint256, T.uint24, T.uint160);

function packPath(pools: readonly SwapPool[], reversed: boolean): string {
  const tokens = [pools[0]!.tokenIn, ...pools.map((x) => x.tokenOut)];
  const fees = pools.map((x) => x.fee);
  if (reversed) {
    tokens.reverse();
    fees.reverse();
  }
  let hex = tokens[0]!.slice(2);
  fees.forEach((fee, i) => {
    hex += fee.toString(16).padStart(6, '0') + tokens[i + 1]!.slice(2);
  });
  return `0x${hex}`;
}

/** Calldata for the QuoterV2 call matching a swap. */
export function uniswapV3QuoteCalldata(swap: SwapAction): string {
  const single = swap.pools.length === 1;
  const pool = swap.pools[0]!;
  const encode = (selector: string, data: Uint8Array) => selector + bytesToHex(data).slice(2);
  if (swap.exact === 'input') {
    return single
      ? encode('0xc6a5026a', encodeAbi([QUOTE_SINGLE], [[pool.tokenIn, pool.tokenOut, swap.amountIn, BigInt(pool.fee), 0n]]))
      : encode('0xcdca1753', encodeAbi([T.bytes, T.uint256], [packPath(swap.pools, false), swap.amountIn]));
  }
  return single
    ? encode('0xbd21704a', encodeAbi([QUOTE_SINGLE], [[pool.tokenIn, pool.tokenOut, swap.amountOut, BigInt(pool.fee), 0n]]))
    : encode('0x2f80bb1d', encodeAbi([T.bytes, T.uint256], [packPath(swap.pools, true), swap.amountOut]));
}

/** Quotes Uniswap V3 swaps with QuoterV2 over `eth_call`. */
export function createUniswapV3Quoter(options: UniswapV3QuoterOptions): Quoter {
  const doFetch = options.fetch ?? fetch;
  const timeoutMs = options.timeoutMs ?? 1500;
  const quoter = options.quoter.toLowerCase();
  return async (swap, signal) => {
    const timeout = AbortSignal.timeout(timeoutMs);
    let body: { result?: unknown; error?: { message?: string } };
    try {
      const response = await doFetch(options.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: quoter, data: uniswapV3QuoteCalldata(swap) }, 'latest'] }),
        signal: AbortSignal.any([signal, timeout]),
      });
      if (!response.ok) return { status: 'unavailable', reason: `quote RPC returned HTTP ${response.status}` };
      body = (await response.json()) as typeof body;
    } catch {
      return { status: 'unavailable', reason: timeout.aborted ? `quote RPC timed out after ${timeoutMs} ms` : 'quote RPC request failed' };
    }
    if (body.error) return { status: 'unavailable', reason: `quote failed: ${String(body.error.message ?? 'unknown error').slice(0, 200)}` };
    if (typeof body.result !== 'string' || !/^0x[0-9a-fA-F]{64,}$/.test(body.result)) return { status: 'unavailable', reason: 'quoter returned no amount' };
    const first = hexToBytes(body.result).subarray(0, 32);
    return { status: 'ok', amount: BigInt(bytesToHex(first)) };
  };
}

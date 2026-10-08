import type { SimulationOutcome } from './engine.js';
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

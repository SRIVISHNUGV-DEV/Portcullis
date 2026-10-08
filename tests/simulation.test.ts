import { describe, expect, it, vi } from 'vitest';
import { TransactionRequestSchema } from '../src/schemas.js';
import { createRpcSimulator } from '../src/simulation.js';
import { ALICE, USDC, batch, erc20, tx, usdc } from './helpers.js';

const single = TransactionRequestSchema.parse(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('1')) }));
const signal = new AbortController().signal;

function rpc(body: unknown, status = 200) {
  return vi.fn(async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;
}

describe('RPC simulator', () => {
  it('sends eth_call from the agent wallet and reports success', async () => {
    const fetchMock = rpc({ jsonrpc: '2.0', id: 1, result: '0x' });
    const outcome = await createRpcSimulator({ url: 'http://127.0.0.1:8545', fetch: fetchMock })(single, signal);
    expect(outcome).toEqual({ status: 'ok' });
    const [, init] = (fetchMock as unknown as ReturnType<typeof vi.fn>).mock.calls[0]!;
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body).toMatchObject({ method: 'eth_call', params: [{ from: single.from, to: USDC, value: '0x0' }, 'latest'] });
  });

  it('distinguishes reverts from infrastructure failures', async () => {
    const reverted = await createRpcSimulator({ url: 'x', fetch: rpc({ error: { code: 3, message: 'execution reverted: insufficient balance' } }) })(single, signal);
    expect(reverted).toEqual({ status: 'reverted', reason: 'execution reverted: insufficient balance' });
    expect((await createRpcSimulator({ url: 'x', fetch: rpc({ error: { code: -32005, message: 'rate limited' } }) })(single, signal)).status).toBe('unavailable');
    expect((await createRpcSimulator({ url: 'x', fetch: rpc({}, 502) })(single, signal)).status).toBe('unavailable');
    const throwing = vi.fn(async () => { throw new TypeError('fetch failed'); }) as unknown as typeof fetch;
    expect(await createRpcSimulator({ url: 'x', fetch: throwing })(single, signal)).toEqual({ status: 'unavailable', reason: 'RPC request failed' });
  });

  it('times out slow RPCs', async () => {
    const hanging = ((_: unknown, init: RequestInit) =>
      new Promise((_resolve, reject) => init.signal!.addEventListener('abort', () => reject(new Error('aborted'))))) as unknown as typeof fetch;
    const outcome = await createRpcSimulator({ url: 'x', fetch: hanging, timeoutMs: 20 })(single, signal);
    expect(outcome).toEqual({ status: 'unavailable', reason: 'RPC timed out after 20 ms' });
  });

  it('refuses to simulate batches call-by-call', async () => {
    const fetchMock = rpc({ result: '0x' });
    const request = TransactionRequestSchema.parse(batch([{ to: ALICE, value: 1n }, { to: ALICE, value: 1n }]));
    expect((await createRpcSimulator({ url: 'x', fetch: fetchMock })(request, signal)).status).toBe('unavailable');
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

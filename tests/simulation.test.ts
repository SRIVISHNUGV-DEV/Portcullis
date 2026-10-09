import { describe, expect, it, vi } from 'vitest';
import { TransactionRequestSchema } from '../src/schemas.js';
import type { SwapAction } from '../src/decoder.js';
import { createRpcSimulator, createUniswapV3Quoter, uniswapV3QuoteCalldata } from '../src/simulation.js';
import { ALICE, ROUTER, USDC, WALLET, WETH, batch, encodeCall, erc20, eth, packPath, tx, usdc } from './helpers.js';
import { T } from '../src/abi.js';

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

describe('Uniswap V3 quoter', () => {
  const DAI = '0x50c5725949a6f0c72e6c4a641f24049a917db0cb';
  const swap = (exact: 'input' | 'output', pools: SwapAction['pools']): SwapAction => ({
    type: 'swap', path: '0', router: ROUTER, exact, tokenIn: pools[0]!.tokenIn, tokenOut: pools[pools.length - 1]!.tokenOut,
    pools, recipient: WALLET, amountIn: usdc('200'), amountOut: eth('0.05'),
  });
  const hops = [{ tokenIn: USDC, tokenOut: WETH, fee: 500 }, { tokenIn: WETH, tokenOut: DAI, fee: 3000 }];

  it('encodes single and multi-hop quotes, reversing exact-output paths', () => {
    expect(uniswapV3QuoteCalldata(swap('input', hops.slice(0, 1)))).toBe(
      encodeCall('0xc6a5026a', [T.tuple(T.address, T.address, T.uint256, T.uint24, T.uint160)], [[USDC, WETH, usdc('200'), 500n, 0n]]),
    );
    expect(uniswapV3QuoteCalldata(swap('input', hops))).toBe(encodeCall('0xcdca1753', [T.bytes, T.uint256], [packPath(USDC, 500, WETH, 3000, DAI), usdc('200')]));
    expect(uniswapV3QuoteCalldata(swap('output', hops))).toBe(encodeCall('0x2f80bb1d', [T.bytes, T.uint256], [packPath(DAI, 3000, WETH, 500, USDC), eth('0.05')]));
  });

  it('returns the first word of the result and reports failures as unavailable', async () => {
    const word = (v: bigint) => v.toString(16).padStart(64, '0');
    const ok = rpc({ result: `0x${word(eth('0.051'))}${word(1n)}` });
    const quoter = createUniswapV3Quoter({ url: 'x', quoter: '0x3d4e44Eb1374240CE5F1B871ab261CD16335B76a', fetch: ok });
    expect(await quoter(swap('input', hops.slice(0, 1)), signal)).toEqual({ status: 'ok', amount: eth('0.051') });
    const [, init] = (ok as unknown as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(JSON.parse((init as RequestInit).body as string).params[0].to).toBe('0x3d4e44eb1374240ce5f1b871ab261cd16335b76a');
    const failing = createUniswapV3Quoter({ url: 'x', quoter: ROUTER, fetch: rpc({ error: { message: 'execution reverted' } }) });
    expect(await failing(swap('input', hops), signal)).toEqual({ status: 'unavailable', reason: 'quote failed: execution reverted' });
  });
});

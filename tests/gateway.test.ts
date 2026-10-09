import type { AddressInfo } from 'node:net';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { Gateway, WalletRejectedError, hashToken, type GatewayConfigInput, type WalletBackend, type WalletCall } from '../src/gateway.js';
import { createGatewayServer, handleMcpMessage } from '../src/mcp.js';
import { ALICE, BOB, CHAIN, MALLORY, USDC, basePolicy, erc20, usdc } from './helpers.js';

const AGENT_A = '0x000000000000000000000000000000000000a001';
const AGENT_B = '0x000000000000000000000000000000000000b002';
const TOKENS = { a: 'token-agent-a', b: 'token-agent-b', admin: 'token-admin' };

class MockWallet implements WalletBackend {
  readonly sent: WalletCall[] = [];
  failWith: Error | undefined;
  async send(call: WalletCall): Promise<string> {
    if (this.failWith) throw this.failWith;
    this.sent.push(call);
    return `0x${this.sent.length.toString(16).padStart(64, '0')}`;
  }
}

function config(overrides: Partial<GatewayConfigInput> = {}): GatewayConfigInput {
  return {
    chainId: CHAIN,
    adminTokenSha256: hashToken(TOKENS.admin),
    agents: [
      { id: 'agent-a', tokenSha256: hashToken(TOKENS.a), wallet: AGENT_A, policy: basePolicy({ name: 'a' }) },
      { id: 'agent-b', tokenSha256: hashToken(TOKENS.b), wallet: AGENT_B, policy: basePolicy({ name: 'b' }) },
    ],
    ...overrides,
  };
}

async function setup(overrides: Partial<GatewayConfigInput> = {}) {
  const wallet = new MockWallet();
  const gateway = await Gateway.create(config(overrides), { wallet });
  return { wallet, gateway };
}

const call = (gateway: Gateway, agent: string, name: string, args: Record<string, unknown>) =>
  handleMcpMessage(gateway, agent, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) as Promise<{
    result: { isError: boolean; structuredContent: Record<string, any> };
  }>;

describe('Gateway', () => {
  it('executes an allowed transfer through the wallet and commits the spend', async () => {
    const { gateway, wallet } = await setup();
    const r = await gateway.transferToken('agent-a', { token: 'usdc', to: ALICE, amount: '25.5' });
    expect(r.status).toBe('executed');
    expect(r.txHash).toMatch(/^0x0+1$/);
    expect(wallet.sent).toEqual([{ from: AGENT_A, to: USDC, value: 0n, data: erc20.transfer(ALICE, usdc('25.5')) }]);
    const budget = (await gateway.budget('agent-a')) as { tokens: { symbol: string; remaining: string }[]; transactions: number };
    expect(budget.tokens.find((t) => t.symbol === 'USDC')?.remaining).toBe('4974.5');
    expect(budget.transactions).toBe(1);
  });

  it('never calls the wallet for blocked requests', async () => {
    const { gateway, wallet } = await setup();
    const unlimited = await gateway.approveToken('agent-a', { token: 'USDC', spender: BOB, amount: 'unlimited' });
    const denylisted = await gateway.transferToken('agent-a', { token: 'USDC', to: MALLORY, amount: '1' });
    expect(unlimited.status).toBe('blocked');
    expect(unlimited.reasons.map((x) => x.code)).toContain('UNLIMITED_APPROVAL');
    expect(denylisted.reasons.map((x) => x.code)).toContain('DENYLISTED_ADDRESS');
    expect(wallet.sent).toHaveLength(0);
  });

  it('holds escalations until an admin decides; the agent cannot approve', async () => {
    const { gateway, wallet } = await setup();
    const pending = await gateway.transferToken('agent-a', { token: 'USDC', to: ALICE, amount: '600' });
    expect(pending.status).toBe('pending_approval');
    expect(wallet.sent).toHaveLength(0);
    expect(gateway.pending().map((p) => p.requestId)).toEqual([pending.requestId]);
    expect(() => gateway.status('agent-b', pending.requestId)).toThrow(/Unknown request/);

    const done = await gateway.decide(pending.requestId, { approve: true, approver: 'ops@example.com' });
    expect(done.status).toBe('executed');
    expect(gateway.status('agent-a', pending.requestId).status).toBe('executed');
    expect(wallet.sent).toHaveLength(1);
    await expect(gateway.decide(pending.requestId, { approve: true, approver: 'ops@example.com' })).rejects.toThrow(/No pending approval/);

    const second = await gateway.transferToken('agent-a', { token: 'USDC', to: ALICE, amount: '700' });
    const rejected = await gateway.decide(second.requestId, { approve: false, approver: 'ops@example.com', note: 'unexpected' });
    expect(rejected).toMatchObject({ status: 'rejected', decision: { approved: false, by: 'ops@example.com', note: 'unexpected' } });
    expect(rejected.summary).not.toMatch(/NEEDS HUMAN APPROVAL/);
    expect(wallet.sent).toHaveLength(1);
  });

  it('releases the budget when the wallet rejects before broadcast, keeps it when the outcome is unknown', async () => {
    const { gateway, wallet } = await setup();
    wallet.failWith = new WalletRejectedError('insufficient funds for gas');
    expect((await gateway.transferToken('agent-a', { token: 'USDC', to: ALICE, amount: '100' })).status).toBe('failed');
    wallet.failWith = new Error('socket hang up');
    expect((await gateway.transferToken('agent-a', { token: 'USDC', to: ALICE, amount: '100' })).status).toBe('unknown');
    const budget = (await gateway.budget('agent-a')) as { tokens: { symbol: string; remaining: string }[] };
    expect(budget.tokens.find((t) => t.symbol === 'USDC')?.remaining).toBe('4900');
  });

  it('isolates agents and enforces session caps exactly under concurrency', async () => {
    const { gateway, wallet } = await setup();
    const results = await Promise.all(
      Array.from({ length: 60 }, (_, i) =>
        gateway.transferToken(i % 2 ? 'agent-b' : 'agent-a', { token: 'USDC', to: ALICE, amount: '400' }),
      ),
    );
    const executed = (agent: string) => wallet.sent.filter((c) => c.from === (agent === 'a' ? AGENT_A : AGENT_B)).length;
    // sessionMax 5000 / 400 per transfer = 12 per agent; the rest hit TOKEN_SESSION_LIMIT.
    expect(executed('a')).toBe(12);
    expect(executed('b')).toBe(12);
    expect(results.filter((r) => r.status === 'blocked').every((r) => r.reasons.some((x) => x.code === 'TOKEN_SESSION_LIMIT'))).toBe(true);
  });

  it('persists budgets and a verifiable audit chain in storage.dir', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'atf-gw-'));
    const wallet = new MockWallet();
    let gateway = await Gateway.create(config({ storage: { dir, fsync: false } }), { wallet });
    await gateway.transferToken('agent-a', { token: 'USDC', to: ALICE, amount: '400' });
    await gateway.close();
    gateway = await Gateway.create(config({ storage: { dir, fsync: false } }), { wallet });
    const budget = (await gateway.budget('agent-a')) as { tokens: { symbol: string; remaining: string }[] };
    expect(budget.tokens.find((t) => t.symbol === 'USDC')?.remaining).toBe('4600');
    expect(await gateway.verifyAudit()).toMatchObject({ valid: true, records: 2 });
    await gateway.close();
  });

  it('rejects invalid configs', async () => {
    await expect(Gateway.create(config({ chainId: 1 }), { wallet: new MockWallet() })).rejects.toThrow(/does not allow chain 1/);
    const dup = config();
    (dup.agents as { tokenSha256: string }[])[1]!.tokenSha256 = hashToken(TOKENS.a);
    await expect(Gateway.create(dup, { wallet: new MockWallet() })).rejects.toThrow(/reuses another agent's token/);
  });
});

describe('MCP', () => {
  it('negotiates the protocol and lists tools without an approve tool', async () => {
    const { gateway } = await setup();
    const init = (await handleMcpMessage(gateway, 'agent-a', {
      jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } },
    })) as { result: { protocolVersion: string } };
    expect(init.result.protocolVersion).toBe('2025-06-18');
    expect(await handleMcpMessage(gateway, 'agent-a', { jsonrpc: '2.0', method: 'notifications/initialized' })).toBeUndefined();
    const list = (await handleMcpMessage(gateway, 'agent-a', { jsonrpc: '2.0', id: 1, method: 'tools/list' })) as {
      result: { tools: { name: string; inputSchema: { type: string } }[] };
    };
    const names = list.result.tools.map((t) => t.name);
    expect(names).toEqual(['get_budget', 'transfer_token', 'approve_token', 'send_native', 'send_transaction', 'check_transaction', 'get_request_status']);
    expect(names.some((n) => n.includes('approve_request'))).toBe(false);
    expect(list.result.tools.every((t) => t.inputSchema.type === 'object')).toBe(true);
  });

  it('marks blocked results and bad arguments as tool errors', async () => {
    const { gateway } = await setup();
    const blocked = await call(gateway, 'agent-a', 'approve_token', { token: 'USDC', spender: BOB, amount: 'unlimited' });
    expect(blocked.result.isError).toBe(true);
    expect(blocked.result.structuredContent.status).toBe('blocked');
    const bad = await call(gateway, 'agent-a', 'transfer_token', { token: 'DOGE', to: ALICE, amount: '1' });
    expect(bad.result.isError).toBe(true);
    expect(bad.result.structuredContent.error).toMatch(/not configured/);
    const ok = await call(gateway, 'agent-a', 'check_transaction', { to: USDC, data: erc20.transfer(ALICE, usdc('1')) });
    expect(ok.result.structuredContent).toMatchObject({ status: 'checked', verdict: 'allowed' });
    const wouldBlock = await call(gateway, 'agent-a', 'check_transaction', { to: USDC, data: erc20.approve(BOB, 2n ** 255n) });
    expect(wouldBlock.result.structuredContent).toMatchObject({ status: 'checked', verdict: 'blocked' });
  });

  it('does not let the agent choose its budget scope', async () => {
    const { gateway, wallet } = await setup();
    const list = (await handleMcpMessage(gateway, 'agent-a', { jsonrpc: '2.0', id: 1, method: 'tools/list' })) as {
      result: { tools: { inputSchema: { properties?: Record<string, unknown> } }[] };
    };
    expect(list.result.tools.every((t) => !('session' in (t.inputSchema.properties ?? {})))).toBe(true);
    for (let i = 0; i < 12; i++) await gateway.transferToken('agent-a', { token: 'USDC', to: ALICE, amount: '400' });
    const fresh = await call(gateway, 'agent-a', 'transfer_token', { token: 'USDC', to: ALICE, amount: '400', session: 'fresh-budget' });
    expect(fresh.result.isError).toBe(true);
    expect(wallet.sent).toHaveLength(12);
  });

  describe('over HTTP', () => {
    let close: (() => Promise<void>) | undefined;
    afterEach(async () => {
      await close?.();
      close = undefined;
    });

    async function serve() {
      const { gateway, wallet } = await setup();
      const server = createGatewayServer(gateway);
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      close = () => new Promise((resolve) => server.close(() => resolve()));
      const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      const post = (path: string, token: string | undefined, body: unknown, headers: Record<string, string> = {}) =>
        fetch(base + path, {
          method: 'POST',
          headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
          body: JSON.stringify(body),
        });
      return { base, post, wallet };
    }

    it('authenticates agents and admins separately', async () => {
      const { base, post, wallet } = await serve();
      const tool = (token: string | undefined, name: string, args: unknown) =>
        post('/mcp', token, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });

      expect((await tool('wrong', 'get_budget', {})).status).toBe(401);
      expect((await tool(TOKENS.a, 'get_budget', {})).status).toBe(200);
      expect((await post('/mcp', TOKENS.a, { jsonrpc: '2.0', id: 1, method: 'ping' }, { origin: 'https://evil.example' })).status).toBe(403);

      const pending = (await (await tool(TOKENS.a, 'transfer_token', { token: 'USDC', to: ALICE, amount: '800' })).json()) as {
        result: { structuredContent: { requestId: string; status: string } };
      };
      const { requestId, status } = pending.result.structuredContent;
      expect(status).toBe('pending_approval');

      expect((await post(`/admin/requests/${requestId}/approve`, TOKENS.a, { approver: 'agent' })).status).toBe(401);
      expect((await fetch(`${base}/admin/pending`, { headers: { authorization: `Bearer ${TOKENS.admin}` } })).status).toBe(200);
      const approved = await post(`/admin/requests/${requestId}/approve`, TOKENS.admin, { approver: 'ops@example.com' });
      expect(((await approved.json()) as { status: string }).status).toBe('executed');
      expect(wallet.sent).toHaveLength(1);
      expect((await post('/mcp', TOKENS.a, { jsonrpc: '2.0', method: 'notifications/initialized' })).status).toBe(202);
    });
  });
});

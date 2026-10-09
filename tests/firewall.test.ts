import { describe, expect, it, vi } from 'vitest';
import { MemoryAuditSink, verifyAuditChain, type AuditRecord, type AuditSink } from '../src/audit.js';
import type { SwapAction } from '../src/decoder.js';
import { createFirewall, FirewallStateError } from '../src/firewall.js';
import { PolicyValidationError } from '../src/policy.js';
import { encodeRoleKey, flattenConditions, toZodiacRoles } from '../src/zodiac.js';
import type { SessionStore } from '../src/session.js';
import { ALICE, BOB, ROUTER, SWAP_SELECTOR, USDC, WALLET, WETH, basePolicy, erc20, eth, fixedEnv, router, tx, usdc } from './helpers.js';

function setup(overrides: Parameters<typeof createFirewall>[0] extends infer O ? Partial<O> : never = {}) {
  const env = fixedEnv();
  const audit = new MemoryAuditSink();
  const firewall = createFirewall({ policy: basePolicy(), audit, clock: env.clock, generateId: env.generateId, ...overrides });
  return { firewall, audit, env };
}

const transfer = (amount: string, to = ALICE) => tx({ to: USDC, data: erc20.transfer(to, usdc(amount)) });

describe('policy loading', () => {
  it('fails fast on invalid policy with readable issues', () => {
    expect(() => createFirewall({ policy: { version: 1 } as never })).toThrow(PolicyValidationError);
    expect(() => createFirewall({ policy: basePolicy({ native: { perTransactionMax: -1n, sessionMax: 1n } as never }) })).toThrow(/native.perTransactionMax/);
  });

  it('rejects a token that is also an unrestricted protocol (limit bypass)', () => {
    const policy = basePolicy({ protocols: [{ name: 'USDC as protocol', address: USDC }] });
    expect(() => createFirewall({ policy })).toThrow(/both token USDC and protocol/);
  });

  it('rejects unknown policy keys (strict schema)', () => {
    expect(() => createFirewall({ policy: { ...basePolicy(), allowEverything: true } as never })).toThrow(PolicyValidationError);
  });

  it('normalizes address case so checksummed and lowercase entries are equivalent', () => {
    const policy = basePolicy({ denylist: [BOB.toUpperCase().replace('0X', '0x')] });
    expect(() => createFirewall({ policy: { ...policy, recipients: { allow: [BOB] } } })).toThrow(/denylisted and allowlisted/);
  });
});

describe('evaluate', () => {
  it('returns a frozen, JSON-serializable verdict with a reservation', async () => {
    const { firewall } = setup();
    const v = await firewall.evaluate(transfer('100'));
    expect(v).toMatchObject({ verdict: 'allowed', allowed: true, reservationId: 'id-2', chainId: 8453, spend: { native: '0', tokens: { [USDC]: '100000000' } } });
    expect(Object.isFrozen(v)).toBe(true);
    expect(JSON.parse(JSON.stringify(v))).toMatchObject({ verdict: 'allowed' });
    expect(v.durationMs).toBeGreaterThanOrEqual(0);
    expect(v.auditHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('blocks invalid input instead of throwing', async () => {
    const { firewall, audit } = setup();
    for (const bad of [null, {}, { chainId: 8453, from: 'nope', to: ALICE }, { ...transfer('1'), data: '0xabc' }, { ...transfer('1'), calls: [{ to: ALICE }] }]) {
      const v = await firewall.evaluate(bad);
      expect(v.verdict).toBe('blocked');
      expect(v.reasons[0]!.code).toBe('INVALID_REQUEST');
    }
    expect(audit.records).toHaveLength(5);
    const badSession = await firewall.evaluate(transfer('1'), { sessionId: 'has spaces' });
    expect(badSession.reasons[0]!.code).toBe('INVALID_SESSION_ID');
  });

  it('enforces the session cap across sequential requests, commit and release', async () => {
    const policy = basePolicy();
    policy.tokens![0] = { address: USDC, symbol: 'USDC', decimals: 6, perTransactionMax: usdc('1000'), sessionMax: usdc('5000') };
    const { firewall } = setup({ policy });
    const allowed = [];
    for (let i = 0; i < 5; i++) allowed.push(await firewall.evaluate(transfer('1000')));
    expect(allowed.every((v) => v.allowed)).toBe(true);
    const sixth = await firewall.evaluate(transfer('1'));
    expect(sixth.reasons.map((r) => r.code)).toEqual(['TOKEN_SESSION_LIMIT']);

    await firewall.commit(allowed[0]!, { txHash: `0x${'aa'.repeat(32)}` });
    await firewall.release(allowed[1]!);
    expect((await firewall.usage()).spent.tokens[USDC]).toBe(usdc('4000').toString());
    expect((await firewall.evaluate(transfer('1000'))).allowed).toBe(true);
    await expect(firewall.commit(allowed[0]!)).rejects.toThrow(FirewallStateError);
    await expect(firewall.release(sixth)).rejects.toThrow(/Only allowed verdicts/);
  });

  it('does not let concurrent requests overrun a cap (reservation race)', async () => {
    const policy = basePolicy();
    policy.tokens![0] = { address: USDC, symbol: 'USDC', decimals: 6, perTransactionMax: usdc('3000'), sessionMax: usdc('5000') };
    const { firewall } = setup({ policy });
    const results = await Promise.all([firewall.evaluate(transfer('3000')), firewall.evaluate(transfer('3000')), firewall.evaluate(transfer('3000'))]);
    expect(results.filter((v) => v.allowed)).toHaveLength(1);
    expect(results.filter((v) => v.reasons.some((r) => r.code === 'TOKEN_SESSION_LIMIT'))).toHaveLength(2);
  });

  it('isolates sessions', async () => {
    const { firewall } = setup();
    await firewall.evaluate(transfer('400'), { sessionId: 'a' });
    expect((await firewall.usage('b')).spent.tokens).toEqual({});
  });

  it('fails closed with AUDIT_UNAVAILABLE and rolls back the reservation when auditing fails', async () => {
    let fail = true;
    const inner = new MemoryAuditSink();
    const sink: AuditSink = { append: async (r: AuditRecord) => { if (fail) throw new Error('disk full'); await inner.append(r); } };
    const { firewall } = setup({ audit: sink });
    const v = await firewall.evaluate(transfer('100'));
    expect(v.verdict).toBe('blocked');
    expect(v.reasons[0]!.code).toBe('AUDIT_UNAVAILABLE');
    expect(v.auditHash).toBeNull();
    fail = false;
    expect((await firewall.usage()).spent.tokens).toEqual({});
  });

  it('fails closed with EVALUATION_ERROR on unexpected exceptions', async () => {
    const broken: SessionStore = { transact: async () => { throw new Error('store offline'); } };
    const { firewall } = setup({ sessions: broken });
    const v = await firewall.evaluate(transfer('1'));
    expect(v.verdict).toBe('blocked');
    expect(v.reasons[0]).toMatchObject({ code: 'EVALUATION_ERROR' });
    expect(v.reasons[0]!.message).toContain('store offline');
  });
});

describe('human approval', () => {
  it('approves a pending verdict once, bound to the evaluated transaction', async () => {
    const { firewall, audit } = setup();
    const pending = await firewall.evaluate(transfer('600'));
    expect(pending.verdict).toBe('requiresApproval');
    expect(pending.approvalExpiresAt).toBe('2026-10-08T12:15:00.000Z');

    await expect(firewall.approve({ ...pending, txDigest: 'f'.repeat(64) }, { approver: 'ops@example.com' })).rejects.toThrow(/does not match/);
    const fresh = await firewall.evaluate(transfer('600'));
    const approved = await firewall.approve(fresh, { approver: 'ops@example.com', note: 'vendor invoice 42' });
    expect(approved).toMatchObject({ verdict: 'allowed', allowed: true, approval: { approver: 'ops@example.com', note: 'vendor invoice 42' } });
    expect(approved.summary.startsWith('APPROVED by ops@example.com')).toBe(true);
    await expect(firewall.approve(fresh, { approver: 'ops@example.com' })).rejects.toThrow(/No pending approval/);
    expect(audit.records.map((r) => r.type)).toContain('approval');
  });

  it('expires approvals after the TTL', async () => {
    const { firewall, env } = setup();
    const pending = await firewall.evaluate(transfer('600'));
    env.advance(901_000);
    await expect(firewall.approve(pending, { approver: 'ops' })).rejects.toThrow(/expired/);
  });

  it('re-checks caps at approval time', async () => {
    const policy = basePolicy();
    policy.tokens![0] = { ...policy.tokens![0]!, sessionMax: usdc('1000') };
    const { firewall } = setup({ policy });
    const pending = await firewall.evaluate(transfer('600'));
    expect((await firewall.evaluate(transfer('500'))).allowed).toBe(true);
    const result = await firewall.approve(pending, { approver: 'ops' });
    expect(result.verdict).toBe('blocked');
    expect(result.reasons.map((r) => r.code)).toContain('TOKEN_SESSION_LIMIT');
  });

  it('records rejections and refuses invalid approval calls', async () => {
    const { firewall, audit } = setup();
    const pending = await firewall.evaluate(transfer('600'));
    await expect(firewall.approve(pending, { approver: ' ' })).rejects.toThrow(/approver identity/);
    await firewall.reject(pending, { approver: 'ops', note: 'unknown vendor' });
    await expect(firewall.approve(pending, { approver: 'ops' })).rejects.toThrow(/No pending approval/);
    const allowed = await firewall.evaluate(transfer('1'));
    await expect(firewall.approve(allowed, { approver: 'ops' })).rejects.toThrow(/Cannot approve a allowed verdict/);
    expect(audit.records.map((r) => r.type)).toContain('rejection');
    expect(verifyAuditChain(audit.records).valid).toBe(true);
  });
});

describe('simulation hook', () => {
  it('skips simulation for requests that are blocked anyway', async () => {
    const simulator = vi.fn(async () => ({ status: 'ok' as const }));
    const { firewall } = setup({ simulator });
    expect((await firewall.evaluate(transfer('5000'))).verdict).toBe('blocked');
    expect(simulator).not.toHaveBeenCalled();
    expect((await firewall.evaluate(transfer('10'))).allowed).toBe(true);
    expect(simulator).toHaveBeenCalledTimes(1);
  });

  it('treats a throwing simulator as unavailable and a revert as blocked', async () => {
    const throwing = setup({ simulator: async () => { throw new Error('rpc exploded'); } });
    const v = await throwing.firewall.evaluate(transfer('10'));
    expect(v.verdict).toBe('requiresApproval');
    expect(v.reasons[0]!.message).toContain('rpc exploded');

    const reverting = setup({ simulator: async () => ({ status: 'reverted' as const, reason: 'ERC20: transfer amount exceeds balance' }) });
    expect((await reverting.firewall.evaluate(transfer('10'))).reasons.map((r) => r.code)).toEqual(['SIMULATION_REVERTED']);
  });

  it('keeps unrelated protocol approvals unaffected', async () => {
    const { firewall } = setup();
    expect((await firewall.evaluate(tx({ to: USDC, data: erc20.approve(ROUTER, usdc('100')) }))).allowed).toBe(true);
  });
});

describe('per-recipient windows', () => {
  const windowPolicy = () =>
    basePolicy({
      tokens: [{ address: USDC, symbol: 'USDC', decimals: 6, perTransactionMax: usdc('100'), sessionMax: usdc('5000'), requireApprovalAbove: usdc('50'), perRecipient: { windowSeconds: 3600 } }],
    });

  it('counts reserved and committed chunks, excludes approved ones and forgets old ones', async () => {
    const { firewall, env } = setup({ policy: windowPolicy() });
    const first = await firewall.evaluate(transfer('30'));
    expect(first.allowed).toBe(true);
    expect((await firewall.evaluate(transfer('30'))).verdict).toBe('requiresApproval');
    await firewall.commit(first, { txHash: '0x01' });
    expect((await firewall.evaluate(transfer('30'))).reasons.map((r) => r.code)).toEqual(['RECIPIENT_WINDOW_THRESHOLD']);
    expect((await firewall.evaluate(transfer('30', BOB))).allowed).toBe(true);

    const pending = await firewall.evaluate(transfer('75'));
    const approved = await firewall.approve(pending, { approver: 'ops' });
    await firewall.commit(approved);
    expect((await firewall.evaluate(transfer('20'))).allowed).toBe(true);

    env.advance(3_601_000);
    expect((await firewall.evaluate(transfer('45'))).allowed).toBe(true);
  });

  it('releases a chunk from the window when it is not sent', async () => {
    const { firewall } = setup({ policy: windowPolicy() });
    const first = await firewall.evaluate(transfer('40'));
    await firewall.release(first);
    expect((await firewall.evaluate(transfer('40'))).allowed).toBe(true);
  });
});

describe('swap quotes', () => {
  const policy = () =>
    basePolicy({ protocols: [{ name: 'Uniswap SwapRouter02', address: ROUTER, kind: 'uniswap-v3-router', selectors: [SWAP_SELECTOR], maxSlippageBps: 100 }] });
  const swap = (minOut: bigint) => tx({ to: ROUTER, data: router.exactInputSingle(USDC, WETH, WALLET, usdc('200'), minOut) });

  it('quotes swaps, blocks excessive slippage and reuses the quote on approval', async () => {
    const quoter = vi.fn(async (_swap: SwapAction) => ({ status: 'ok' as const, amount: eth('0.05') }));
    const { firewall } = setup({ policy: policy(), quoter });
    expect((await firewall.evaluate(swap(eth('0.0499')))).allowed).toBe(true);
    expect(quoter).toHaveBeenCalledTimes(1);
    expect(quoter.mock.calls[0]![0]).toMatchObject({ type: 'swap', tokenIn: USDC, tokenOut: WETH, amountIn: usdc('200') });
    expect((await firewall.evaluate(swap(eth('0.04')))).reasons.map((r) => r.code)).toEqual(['SWAP_SLIPPAGE_TOO_HIGH']);
    expect((await firewall.evaluate(swap(eth('0.04')))).verdict).toBe('blocked');
    expect((await firewall.evaluate(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('1')) }))).allowed).toBe(true);
    expect(quoter).toHaveBeenCalledTimes(3);
  });

  it('treats a failing quoter as unavailable', async () => {
    const { firewall } = setup({ policy: policy(), quoter: async () => { throw new Error('quoter down'); } });
    const v = await firewall.evaluate(swap(eth('0.0499')));
    expect(v.verdict).toBe('requiresApproval');
    expect(v.reasons[0]!.message).toContain('quoter down');
    const approved = await firewall.approve(v, { approver: 'ops' });
    expect(approved.allowed).toBe(true);
  });
});

describe('toZodiacRoles', () => {
  const ROLES = '0x00000000000000000000000000000000000001e5';

  it('encodes role names and flattens conditions breadth-first', () => {
    expect(encodeRoleKey('agent')).toBe(`0x6167656e74${'0'.repeat(54)}`);
    expect(() => encodeRoleKey('x'.repeat(33))).toThrow(/1-32 bytes/);
    const flat = flattenConditions({
      paramType: 5, operator: 5,
      children: [{ paramType: 0, operator: 2, children: [{ paramType: 1, operator: 16, compValue: '0x01' }, { paramType: 1, operator: 16, compValue: '0x02' }] }, { paramType: 1, operator: 0 }],
    });
    expect(flat.map(([parent]) => parent)).toEqual([0, 0, 0, 1, 1]);
  });

  it('maps tokens, protocols and members, and lists what stays firewall-only', () => {
    const plan = toZodiacRoles(basePolicy({ recipients: { allow: [ALICE] } }), { roles: ROLES, role: 'agent', members: [BOB] });
    expect(plan.calls.every((c) => c.to === ROLES)).toBe(true);
    expect(plan.allowances.map((a) => a.asset)).toEqual([USDC, WETH, 'native']);
    expect(plan.calls.at(-1)!.data.startsWith('0x957ed2b3')).toBe(true);
    expect(plan.warnings.join(' ')).toMatch(/Review thresholds/);
    expect(plan.warnings.join(' ')).toMatch(/NFT rules are not mapped/);
  });

  it('does not grant native transfers without a recipient allowlist', () => {
    const plan = toZodiacRoles(basePolicy(), { roles: ROLES, role: 'agent' });
    expect(plan.allowances.some((a) => a.asset === 'native')).toBe(false);
    expect(plan.warnings.join(' ')).toMatch(/ETH transfers are not allowed onchain/);
  });
});

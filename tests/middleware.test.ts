import { describe, expect, it, vi } from 'vitest';
import { createFirewall } from '../src/firewall.js';
import { ApprovalRequiredError, FirewallBlockedError, guard } from '../src/middleware.js';
import { ALICE, CHAIN, USDC, WALLET, basePolicy, erc20, eth, fixedEnv, usdc } from './helpers.js';

const HASH = `0x${'cd'.repeat(32)}`;

function setup() {
  const env = fixedEnv();
  const firewall = createFirewall({ policy: basePolicy(), clock: env.clock, generateId: env.generateId });
  return { firewall };
}

describe('guard middleware', () => {
  it('sends allowed transactions and commits the reservation with the tx hash', async () => {
    const { firewall } = setup();
    const send = vi.fn(async (_tx: { to: string; data: string; value?: bigint }) => HASH);
    const safeSend = guard(send, { firewall, chainId: CHAIN, from: WALLET });
    await expect(safeSend({ to: USDC, data: erc20.transfer(ALICE, usdc('10')) })).resolves.toBe(HASH);
    expect(send).toHaveBeenCalledOnce();
    expect((await firewall.usage()).spent.tokens[USDC]).toBe(usdc('10').toString());
  });

  it('throws FirewallBlockedError without calling the wallet', async () => {
    const { firewall } = setup();
    const send = vi.fn(async () => HASH);
    const safeSend = guard(send, { firewall, chainId: CHAIN, from: WALLET });
    const error = await safeSend({ to: USDC, data: erc20.approve(ALICE, (1n << 256n) - 1n) }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(FirewallBlockedError);
    expect((error as FirewallBlockedError).verdict.reasons.map((r) => r.code)).toContain('UNLIMITED_APPROVAL');
    expect((error as FirewallBlockedError).message).toMatch(/^BLOCKED/);
    expect(send).not.toHaveBeenCalled();
  });

  it('throws ApprovalRequiredError when no approval handler is configured', async () => {
    const { firewall } = setup();
    const send = vi.fn(async () => HASH);
    const safeSend = guard(send, { firewall, chainId: CHAIN, from: WALLET });
    await expect(safeSend({ to: ALICE, value: eth('0.06') })).rejects.toBeInstanceOf(ApprovalRequiredError);
    expect(send).not.toHaveBeenCalled();
  });

  it('routes approval-required transactions to a human and proceeds when approved', async () => {
    const { firewall } = setup();
    const send = vi.fn(async () => ({ hash: HASH }));
    const onApprovalRequired = vi.fn(async () => ({ approver: 'oncall@example.com' }));
    const verdicts: string[] = [];
    const safeSend = guard(send, { firewall, chainId: CHAIN, from: WALLET, onApprovalRequired, onVerdict: (v) => verdicts.push(v.verdict) });
    await safeSend({ to: ALICE, value: eth('0.06') });
    expect(onApprovalRequired).toHaveBeenCalledOnce();
    expect(verdicts).toEqual(['requiresApproval', 'allowed']);
    expect(send).toHaveBeenCalledOnce();
  });

  it('does not send when the human declines', async () => {
    const { firewall } = setup();
    const send = vi.fn(async () => HASH);
    const safeSend = guard(send, { firewall, chainId: CHAIN, from: WALLET, onApprovalRequired: () => false });
    await expect(safeSend({ to: ALICE, value: eth('0.06') })).rejects.toBeInstanceOf(FirewallBlockedError);
    expect(send).not.toHaveBeenCalled();
  });

  it('keeps budget reserved after an ambiguous send failure, releases only when told nothing was broadcast', async () => {
    const { firewall } = setup();
    const failing = async () => { throw Object.assign(new Error('timeout'), { code: 'TIMEOUT' }); };
    const tx = { to: USDC, data: erc20.transfer(ALICE, usdc('10')) };
    await expect(guard(failing, { firewall, chainId: CHAIN, from: WALLET })(tx)).rejects.toThrow('timeout');
    expect((await firewall.usage()).spent.tokens[USDC]).toBe(usdc('10').toString());

    const releasing = guard(async () => { throw Object.assign(new Error('rejected'), { code: 'USER_REJECTED' }); }, {
      firewall, chainId: CHAIN, from: WALLET, releaseOnError: (e) => (e as { code?: string }).code === 'USER_REJECTED',
    });
    await expect(releasing(tx)).rejects.toThrow('rejected');
    expect((await firewall.usage()).spent.tokens[USDC]).toBe(usdc('10').toString());
  });

  it('supports batched calls and custom transaction mapping', async () => {
    const { firewall } = setup();
    const safeBatch = guard(async (_b: { calls: Array<{ to: string; data: string }> }) => HASH, { firewall, chainId: CHAIN, from: WALLET });
    await expect(safeBatch({ calls: [600, 600].map((n) => ({ to: USDC, data: erc20.transfer(ALICE, usdc(String(n))) })) })).rejects.toBeInstanceOf(FirewallBlockedError);

    const safeSafeTx = guard(async (_t: { transactions: Array<{ to: string; value: string; data: string }> }) => HASH, {
      firewall, chainId: CHAIN, from: WALLET, toCalls: (t) => t.transactions,
    });
    await expect(safeSafeTx({ transactions: [{ to: ALICE, value: '1000', data: '0x' }] })).resolves.toBe(HASH);
  });

  it('ignores errors thrown by verdict observers', async () => {
    const { firewall } = setup();
    const safeSend = guard(async () => HASH, { firewall, chainId: CHAIN, from: WALLET, onVerdict: () => { throw new Error('metrics down'); } });
    await expect(safeSend({ to: ALICE, value: 1n } as never)).resolves.toBe(HASH);
  });
});

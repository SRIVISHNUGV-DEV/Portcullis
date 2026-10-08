import { describe, expect, it } from 'vitest';
import { evaluatePolicy, riskScore, type Finding, type SessionView, type SimulationOutcome } from '../src/engine.js';
import { compilePolicy } from '../src/policy.js';
import { TransactionRequestSchema, type PolicyInput } from '../src/schemas.js';
import {
  ALICE, BOB, MALLORY, NFT, PERMIT2_ADDRESS, ROUTER, SWAP_SELECTOR, TREASURY, UINT256_MAX,
  UNKNOWN_CONTRACT, UNKNOWN_TOKEN, USDC, WALLET, WETH, basePolicy, batch, encodeCall, erc20, erc721, eth,
  permit2Approve, tx, usdc, walletExecute, walletExecuteBatch,
} from './helpers.js';

const NOW = Date.UTC(2026, 9, 8);
const fresh: SessionView = { createdAt: NOW, txCount: 0, spent: { native: 0n, tokens: {} } };

function run(input: unknown, opts: { policy?: PolicyInput; session?: SessionView; now?: number; simulation?: SimulationOutcome } = {}) {
  return evaluatePolicy({
    request: TransactionRequestSchema.parse(input),
    policy: compilePolicy(opts.policy ?? basePolicy()),
    session: opts.session ?? fresh,
    now: opts.now ?? NOW,
    ...(opts.simulation ? { simulation: opts.simulation } : {}),
  });
}

const codes = (findings: readonly Finding[], outcome?: Finding['outcome']) =>
  findings.filter((f) => !outcome || f.outcome === outcome).map((f) => f.code);

describe('token-aware limits', () => {
  it('allows an in-policy USDC transfer and explains it', () => {
    const r = run(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('250')) }));
    expect(r.verdict).toBe('allowed');
    expect(r.spend.tokens[USDC]).toBe(usdc('250'));
    expect(r.summary).toBe(`ALLOWED — The agent wants to transfer 250 USDC to ${ALICE}. Within policy.`);
  });

  it('requires approval above the review threshold and blocks above the per-transaction cap', () => {
    expect(run(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('600')) })).verdict).toBe('requiresApproval');
    const r = run(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('1000.000001')) }));
    expect(r.verdict).toBe('blocked');
    expect(codes(r.findings, 'block')).toEqual(['TOKEN_PER_TX_LIMIT']);
  });

  it('sees a token transfer even though native value is zero (the core ATF gap)', () => {
    const r = run(tx({ to: USDC, value: 0n, data: erc20.transfer(ALICE, usdc('5000')) }));
    expect(r.verdict).toBe('blocked');
    expect(r.spend.native).toBe(0n);
  });

  it('sums split transfers inside one batch (per-transaction cap bypass)', () => {
    const r = run(batch([400, 400, 400].map((n) => ({ to: USDC, data: erc20.transfer(ALICE, usdc(String(n))) }))));
    expect(r.spend.tokens[USDC]).toBe(usdc('1200'));
    expect(codes(r.findings, 'block')).toContain('TOKEN_PER_TX_LIMIT');
  });

  it('counts transfers hidden in nested smart-wallet execute/executeBatch calls', () => {
    const hidden = walletExecuteBatch([
      [USDC, 0n, erc20.transfer(ALICE, usdc('900'))],
      [USDC, 0n, erc20.transfer(BOB, usdc('900'))],
    ]);
    const r = run(tx({ to: WALLET, data: walletExecute(WALLET, 0n, hidden) }));
    expect(r.spend.tokens[USDC]).toBe(usdc('1800'));
    expect(r.verdict).toBe('blocked');
  });

  it('enforces session caps using prior committed and reserved spend', () => {
    const session = { ...fresh, spent: { native: 0n, tokens: { [USDC]: usdc('4800') } } };
    const r = run(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('300')) }), { session });
    expect(codes(r.findings, 'block')).toEqual(['TOKEN_SESSION_LIMIT']);
    expect(r.findings[0]!.message).toContain('4,800 USDC already used or reserved');
  });

  it('counts transferFrom pulls from third parties (treasury allowance bypass)', () => {
    const r = run(tx({ to: USDC, data: erc20.transferFrom(TREASURY, ALICE, usdc('2000')) }));
    expect(r.verdict).toBe('blocked');
    expect(codes(r.findings)).toEqual(expect.arrayContaining(['THIRD_PARTY_SOURCE', 'TOKEN_PER_TX_LIMIT']));
  });

  it('counts ERC-677 transferAndCall and EIP-3009 transferWithAuthorization', () => {
    expect(run(tx({ to: USDC, data: erc20.transferAndCall(ALICE, usdc('2000')) })).verdict).toBe('blocked');
    expect(run(tx({ to: USDC, data: erc20.transferWithAuthorization(WALLET, ALICE, usdc('2000')) })).verdict).toBe('blocked');
  });
});

describe('approvals', () => {
  it('blocks unlimited approvals regardless of spender trust', () => {
    for (const data of [erc20.approve(ROUTER, UINT256_MAX), erc20.approve(ROUTER, 1n << 128n), erc20.increaseAllowance(ROUTER, UINT256_MAX)]) {
      const r = run(tx({ to: USDC, data }));
      expect(r.verdict).toBe('blocked');
      expect(codes(r.findings, 'block')).toContain('UNLIMITED_APPROVAL');
    }
    const p2 = run(tx({ to: PERMIT2_ADDRESS, data: permit2Approve(USDC, ROUTER, (1n << 160n) - 1n, 0n) }));
    expect(codes(p2.findings, 'block')).toContain('UNLIMITED_APPROVAL');
    expect(p2.summary).toContain('UNLIMITED allowance for USDC');
  });

  it('charges finite approvals against token budgets (spender can pull without another agent tx)', () => {
    const r = run(tx({ to: USDC, data: erc20.approve(ROUTER, usdc('400')) }));
    expect(r.verdict).toBe('allowed');
    expect(r.spend.tokens[USDC]).toBe(usdc('400'));
    const split = run(batch([
      { to: USDC, data: erc20.approve(ROUTER, usdc('400')) },
      { to: USDC, data: erc20.transfer(ALICE, usdc('400')) },
      { to: USDC, data: erc20.increaseAllowance(ROUTER, usdc('400')) },
    ]));
    expect(codes(split.findings, 'block')).toContain('TOKEN_PER_TX_LIMIT');
  });

  it('blocks approvals above maxApproval', () => {
    const policy = basePolicy();
    policy.tokens![0] = { ...policy.tokens![0]!, maxApproval: usdc('100') };
    const r = run(tx({ to: USDC, data: erc20.approve(ROUTER, usdc('200')) }), { policy });
    expect(codes(r.findings, 'block')).toEqual(['APPROVAL_EXCEEDS_MAX']);
  });

  it('requires approval for untrusted spenders, including EIP-2612 permits', () => {
    expect(codes(run(tx({ to: USDC, data: erc20.approve(BOB, usdc('10')) })).findings, 'requireApproval')).toEqual(['UNTRUSTED_SPENDER']);
    const permit = run(tx({ to: USDC, data: erc20.permit(WALLET, BOB, usdc('10')) }));
    expect(permit.verdict).toBe('requiresApproval');
  });

  it('treats revocations as safe', () => {
    const r = run(batch([
      { to: USDC, data: erc20.approve(BOB, 0n) },
      { to: USDC, data: erc20.decreaseAllowance(BOB, usdc('5')) },
      { to: NFT, data: erc721.setApprovalForAll(BOB, false) },
    ]));
    expect(r.verdict).toBe('allowed');
    expect(r.explanation[0]).toBe(`Revoke ${BOB}'s allowance for USDC (${USDC})`);
  });

  it('blocks setApprovalForAll to untrusted operators and allows trusted ones', () => {
    expect(run(tx({ to: NFT, data: erc721.setApprovalForAll(BOB, true) })).verdict).toBe('blocked');
    expect(run(tx({ to: NFT, data: erc721.setApprovalForAll(PERMIT2_ADDRESS, true) })).verdict).toBe('allowed');
  });
});

describe('contract interaction policy', () => {
  const swapData = encodeCall(SWAP_SELECTOR, [], []);

  it('allows allowlisted protocol functions and enforces native value per protocol', () => {
    expect(run(tx({ to: ROUTER, value: eth('0.01'), data: swapData })).verdict).toBe('allowed');
    const r = run(tx({ to: ROUTER, value: eth('0.06'), data: swapData }));
    expect(codes(r.findings, 'block')).toEqual(['PROTOCOL_VALUE_EXCEEDED']);
  });

  it('requires approval for non-allowlisted functions on an allowlisted protocol', () => {
    const r = run(tx({ to: ROUTER, data: '0x12345678' }));
    expect(codes(r.findings, 'requireApproval')).toEqual(['PROTOCOL_FUNCTION_NOT_ALLOWED']);
  });

  it('handles unknown contracts according to policy mode', () => {
    expect(run(tx({ to: UNKNOWN_CONTRACT, data: '0xdeadbeef' })).verdict).toBe('requiresApproval');
    expect(run(tx({ to: UNKNOWN_CONTRACT, data: '0xdeadbeef' }), { policy: basePolicy({ unknownContractCalls: 'block' }) }).verdict).toBe('blocked');
  });

  it('does not let unrecognized token functions bypass token limits, unless explicitly allowed', () => {
    const burn = run(tx({ to: USDC, data: '0x42966c68' + '0'.repeat(64) }));
    expect(codes(burn.findings, 'requireApproval')).toEqual(['UNRECOGNIZED_TOKEN_FUNCTION']);
    expect(run(tx({ to: WETH, value: eth('0.01'), data: '0xd0e30db0' })).verdict).toBe('allowed');
  });

  it('applies the unlisted-asset mode to unknown tokens', () => {
    const r = run(tx({ to: UNKNOWN_TOKEN, data: erc20.transfer(ALICE, 10n ** 30n) }));
    expect(codes(r.findings, 'requireApproval')).toEqual(['UNLISTED_ASSET']);
    expect(r.explanation[0]).toContain('ERC-20 vs ERC-721 not confirmed');
    expect(run(tx({ to: UNKNOWN_TOKEN, data: erc20.transfer(ALICE, 1n) }), { policy: basePolicy({ unlistedAssets: 'block' }) }).verdict).toBe('blocked');
  });

  it('blocks wallet self-calls and contract deployments', () => {
    expect(codes(run(tx({ to: WALLET, data: '0x7065cb48' + '0'.repeat(64) })).findings, 'block')).toEqual(['WALLET_SELF_CALL']);
    expect(codes(run(tx({ to: null, data: '0x6080' })).findings, 'block')).toEqual(['CONTRACT_DEPLOYMENT']);
  });

  it('blocks malformed and non-canonical calldata on known selectors', () => {
    const trailing = `${erc20.transfer(ALICE, usdc('1'))}ff`;
    expect(codes(run(tx({ to: USDC, data: trailing })).findings, 'block')).toEqual(['CALLDATA_NON_CANONICAL']);
  });
});

describe('native value, recipients, chain and session rules', () => {
  it('enforces native caps across all calls, including value sent with contract calls', () => {
    const r = run(batch([
      { to: ALICE, value: eth('0.04') },
      { to: ROUTER, value: eth('0.04'), data: encodeCall(SWAP_SELECTOR, [], []) },
      { to: BOB, value: eth('0.04') },
    ]));
    expect(r.spend.native).toBe(eth('0.12'));
    expect(codes(r.findings, 'block')).toEqual(['NATIVE_PER_TX_LIMIT']);
    expect(run(tx({ to: ALICE, value: eth('0.06') })).verdict).toBe('requiresApproval');
  });

  it('blocks denylisted addresses wherever they appear, including nested calls and spenders', () => {
    const nested = walletExecute(USDC, 0n, erc20.transfer(MALLORY, 1n));
    expect(codes(run(tx({ to: WALLET, data: nested })).findings, 'block')).toEqual(['DENYLISTED_ADDRESS']);
    expect(codes(run(tx({ to: USDC, data: erc20.approve(MALLORY, 1n) })).findings, 'block')).toEqual(['DENYLISTED_ADDRESS']);
  });

  it('enforces the recipient allowlist and flags burns', () => {
    const policy = basePolicy({ recipients: { allow: [ALICE] } });
    expect(run(tx({ to: USDC, data: erc20.transfer(ALICE, 1n) }), { policy }).verdict).toBe('allowed');
    expect(codes(run(tx({ to: USDC, data: erc20.transfer(BOB, 1n) }), { policy }).findings)).toEqual(['RECIPIENT_NOT_ALLOWLISTED']);
    const burn = run(tx({ to: USDC, data: erc20.transfer('0x0000000000000000000000000000000000000000', 1n) }));
    expect(codes(burn.findings)).toEqual(['BURN_ADDRESS_RECIPIENT']);
  });

  it('blocks disallowed chains', () => {
    const r = run({ chainId: 1, from: WALLET, to: ALICE, value: 1n });
    expect(codes(r.findings, 'block')).toEqual(['CHAIN_NOT_ALLOWED']);
    expect(r.riskLevel).toBe('critical');
  });

  it('enforces session duration and transaction count', () => {
    const policy = basePolicy({ session: { maxDurationSeconds: 60, maxTransactions: 2 } });
    expect(codes(run(tx({ to: ALICE, value: 1n }), { policy, now: NOW + 61_000 }).findings)).toEqual(['SESSION_EXPIRED']);
    expect(codes(run(tx({ to: ALICE, value: 1n }), { policy, session: { ...fresh, txCount: 2 } }).findings)).toEqual(['SESSION_TX_LIMIT']);
  });

  it('applies simulation outcomes', () => {
    const input = tx({ to: ALICE, value: 1n });
    expect(run(input, { simulation: { status: 'reverted', reason: 'execution reverted' } }).verdict).toBe('blocked');
    expect(run(input, { simulation: { status: 'unavailable', reason: 'rpc down' } }).verdict).toBe('requiresApproval');
  });
});

describe('determinism and scoring', () => {
  it('returns identical results for identical inputs', () => {
    const input = batch([{ to: USDC, data: erc20.transfer(ALICE, usdc('600')) }, { to: NFT, data: erc721.setApprovalForAll(BOB, true) }]);
    expect(run(input)).toEqual(run(input));
  });

  it('lets the most severe finding dominate the risk score', () => {
    expect(riskScore([])).toEqual({ score: 0, level: 'low' });
    const critical = riskScore([{ code: 'A', outcome: 'block', severity: 'critical', message: '' }]);
    const many = riskScore(Array.from({ length: 5 }, () => ({ code: 'B', outcome: 'info' as const, severity: 'low' as const, message: '' })));
    expect(critical.score).toBeGreaterThan(many.score);
    expect(critical.level).toBe('critical');
  });

  it('writes a reviewable summary with reasons and full addresses', () => {
    const r = run(batch([
      { to: USDC, data: erc20.approve(UNKNOWN_CONTRACT, UINT256_MAX) },
      { to: ALICE, value: eth('0.01') },
    ]));
    expect(r.summary.startsWith('BLOCKED — The agent wants to grant')).toBe(true);
    expect(r.summary).toContain(UNKNOWN_CONTRACT);
    expect(r.summary).toContain('send 0.01 ETH');
    expect(r.summary).toContain('Blocked because: Unlimited allowance');
  });
});

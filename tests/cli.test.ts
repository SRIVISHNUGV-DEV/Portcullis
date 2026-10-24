import { execFile, execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { ALICE, CHAIN, erc20, MALLORY, UINT256_MAX, USDC, usdc, WALLET } from './helpers.js';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const ROOT = fileURLToPath(new URL('..', import.meta.url));

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function run(args: string[]): Promise<RunResult> {
  return new Promise((resolve) => {
    execFile('node', [CLI, ...args], { cwd: ROOT }, (error, stdout, stderr) => {
      resolve({ code: error ? Number((error as { code?: unknown }).code ?? 1) : 0, stdout, stderr });
    });
  });
}

async function tmp(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'firewall-cli-'));
}

async function writeJson(dir: string, name: string, value: unknown): Promise<string> {
  const path = join(dir, name);
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return path;
}

/** Same policy shape as gateway.json: amounts are base-unit strings. */
function policyJson() {
  return {
    version: 1,
    name: 'cli-test',
    chainIds: [CHAIN],
    native: { perTransactionMax: '100000000000000000', sessionMax: '500000000000000000', requireApprovalAbove: '50000000000000000' },
    tokens: [
      {
        address: USDC, symbol: 'USDC', decimals: 6,
        perTransactionMax: '1000000000', sessionMax: '5000000000', requireApprovalAbove: '500000000',
      },
    ],
    denylist: [MALLORY],
  };
}

const tx = (data: string) => ({ chainId: CHAIN, from: WALLET, to: USDC, data });

beforeAll(() => {
  // The CLI tests spawn dist/cli.js, so the build must be fresh first.
  execFileSync('npm', ['run', 'build'], { cwd: ROOT, stdio: 'pipe' });
});

describe('cli: evaluate', () => {
  it('allows a transfer inside limits (exit 0) and prints a human verdict', async () => {
    const dir = await tmp();
    const policy = await writeJson(dir, 'policy.json', policyJson());
    const txFile = await writeJson(dir, 'tx.json', tx(erc20.transfer(ALICE, usdc('100'))));
    const r = await run(['evaluate', '--policy', policy, '--tx', txFile]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('verdict: allowed');
    expect(r.stdout).toContain('risk: 0 (low)');
  });

  it('returns the full verdict as JSON with --json and writes it with --out', async () => {
    const dir = await tmp();
    const policy = await writeJson(dir, 'policy.json', policyJson());
    const txFile = await writeJson(dir, 'tx.json', tx(erc20.transfer(ALICE, usdc('100'))));
    const out = join(dir, 'verdict.json');
    const r = await run(['evaluate', '--policy', policy, '--tx', txFile, '--json', '--out', out]);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout) as { verdict: string }).toMatchObject({ verdict: 'allowed', allowed: true });
    expect(JSON.parse(await readFile(out, 'utf8')) as { verdict: string }).toMatchObject({ verdict: 'allowed' });
  });

  it('blocks an unlimited approval to a denylisted spender (exit 1)', async () => {
    const dir = await tmp();
    const policy = await writeJson(dir, 'policy.json', policyJson());
    const txFile = await writeJson(dir, 'tx.json', tx(erc20.approve(MALLORY, UINT256_MAX)));
    const r = await run(['evaluate', '--policy', policy, '--tx', txFile]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain('verdict: blocked');
    expect(r.stdout).toContain('UNLIMITED_APPROVAL');
    expect(r.stdout).toContain('DENYLISTED_ADDRESS');
  });

  it('returns exit 2 for requiresApproval', async () => {
    const dir = await tmp();
    const policy = await writeJson(dir, 'policy.json', policyJson());
    const txFile = await writeJson(dir, 'tx.json', tx(erc20.transfer(ALICE, usdc('600'))));
    const r = await run(['evaluate', '--policy', policy, '--tx', txFile]);
    expect(r.code).toBe(2);
    expect(r.stdout).toContain('verdict: requiresApproval');
    expect(r.stdout).toContain('TOKEN_APPROVAL_THRESHOLD');
  });

  it('never throws on malformed input: blocked with INVALID_REQUEST', async () => {
    const dir = await tmp();
    const policy = await writeJson(dir, 'policy.json', policyJson());
    const txFile = await writeJson(dir, 'tx.json', { chainId: CHAIN, from: 'nope', to: ALICE });
    const r = await run(['evaluate', '--policy', policy, '--tx', txFile]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain('INVALID_REQUEST');
  });
});

describe('cli: stateful flow across processes', () => {
  it('evaluate -> approve -> commit -> usage against one --storage dir', async () => {
    const dir = await tmp();
    const storage = join(dir, 'state');
    const policy = await writeJson(dir, 'policy.json', policyJson());
    const pendingTx = await writeJson(dir, 'tx.json', tx(erc20.transfer(ALICE, usdc('600'))));
    const pendingOut = join(dir, 'pending.json');
    const approvedOut = join(dir, 'approved.json');

    const ev = await run(['evaluate', '--policy', policy, '--tx', pendingTx, '--storage', storage, '--out', pendingOut]);
    expect(ev.code).toBe(2);

    const ap = await run(['approve', '--policy', policy, '--verdict', pendingOut, '--approver', 'alice@example.com', '--storage', storage, '--json', '--out', approvedOut]);
    expect(ap.code).toBe(0);
    expect(JSON.parse(ap.stdout) as { verdict: string }).toMatchObject({ verdict: 'allowed', allowed: true });
    expect(ap.stdout).toContain('APPROVED by alice@example.com');

    const cm = await run(['commit', '--policy', policy, '--verdict', approvedOut, '--tx-hash', '0xabc', '--storage', storage]);
    expect(cm.code).toBe(0);
    expect(cm.stdout).toContain('committed reservation');

    const u = await run(['usage', '--policy', policy, '--storage', storage, '--json']);
    expect(u.code).toBe(0);
    const usage = JSON.parse(u.stdout) as { txCount: number; spent: { tokens: Record<string, string> } };
    expect(usage.txCount).toBe(1);
    expect(usage.spent.tokens[USDC]).toBe('600000000');
  });

  it('reject closes the approval, and a second approve then fails', async () => {
    const dir = await tmp();
    const storage = join(dir, 'state');
    const policy = await writeJson(dir, 'policy.json', policyJson());
    const txFile = await writeJson(dir, 'tx.json', tx(erc20.transfer(ALICE, usdc('600'))));
    const pendingOut = join(dir, 'pending.json');
    await run(['evaluate', '--policy', policy, '--tx', txFile, '--storage', storage, '--out', pendingOut]);

    const rj = await run(['reject', '--policy', policy, '--verdict', pendingOut, '--approver', 'alice@example.com', '--storage', storage]);
    expect(rj.code).toBe(0);
    expect(rj.stdout).toContain('rejected request');

    const ap = await run(['approve', '--policy', policy, '--verdict', pendingOut, '--approver', 'alice@example.com', '--storage', storage]);
    expect(ap.code).toBe(1);
    expect(ap.stderr).toContain('No pending approval');
  });

  it('approve without --storage explains why it cannot work', async () => {
    const dir = await tmp();
    const policy = await writeJson(dir, 'policy.json', policyJson());
    const txFile = await writeJson(dir, 'tx.json', tx(erc20.transfer(ALICE, usdc('600'))));
    const pendingOut = join(dir, 'pending.json');
    await run(['evaluate', '--policy', policy, '--tx', txFile, '--out', pendingOut]);
    const ap = await run(['approve', '--policy', policy, '--verdict', pendingOut, '--approver', 'alice@example.com']);
    expect(ap.code).toBe(1);
    expect(ap.stderr).toContain('needs --storage');
  });

  it('release returns the budget', async () => {
    const dir = await tmp();
    const storage = join(dir, 'state');
    const policy = await writeJson(dir, 'policy.json', policyJson());
    const txFile = await writeJson(dir, 'tx.json', tx(erc20.transfer(ALICE, usdc('100'))));
    const out = join(dir, 'verdict.json');
    const ev = await run(['evaluate', '--policy', policy, '--tx', txFile, '--storage', storage, '--out', out]);
    expect(ev.code).toBe(0);
    const rel = await run(['release', '--policy', policy, '--verdict', out, '--storage', storage]);
    expect(rel.code).toBe(0);
    expect(rel.stdout).toContain('released reservation');
    const u = await run(['usage', '--policy', policy, '--storage', storage, '--json']);
    expect((JSON.parse(u.stdout) as { spent: { tokens: Record<string, string> } }).spent.tokens[USDC] ?? '0').toBe('0');
  });
});

describe('cli: decode, sign-check, policy, audit-verify', () => {
  it('decodes a transfer to its asset-level action', async () => {
    const dir = await tmp();
    const policy = await writeJson(dir, 'policy.json', policyJson());
    const txFile = await writeJson(dir, 'tx.json', tx(erc20.transfer(ALICE, usdc('100'))));
    const r = await run(['decode', '--policy', policy, '--tx', txFile, '--json']);
    expect(r.code).toBe(0);
    const decoded = JSON.parse(r.stdout) as { actions: Array<{ type: string; amount: string }> };
    expect(decoded.actions[0]?.type).toBe('token_transfer');
    expect(decoded.actions[0]?.amount).toBe('100000000');
  });

  it('sign-check blocks personal_sign and EIP-712 Permit', async () => {
    const msg = await run(['sign-check', '--type', 'message', '--payload-json', 'hello']);
    expect(msg.code).toBe(1);
    expect(msg.stdout).toContain('SIGN_MESSAGE_BLOCKED');
    const permit = await run(['sign-check', '--type', 'typedData', '--payload-json', JSON.stringify({ primaryType: 'Permit', types: {}, domain: {}, message: {} })]);
    expect(permit.code).toBe(1);
    expect(permit.stdout).toContain('SIGN_DANGEROUS_TYPE');
  });

  it('policy validates and prints its hash; invalid policies fail with readable issues', async () => {
    const dir = await tmp();
    const good = await writeJson(dir, 'policy.json', policyJson());
    const r = await run(['policy', '--policy', good]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('policy valid');
    expect(r.stdout).toContain('hash: ');
    const bad = await writeJson(dir, 'bad.json', { version: 1 });
    const rb = await run(['policy', '--policy', bad]);
    expect(rb.code).toBe(1);
    expect(rb.stderr).toContain('Invalid policy');
  });

  it('audit-verify passes a real chain and fails a tampered one', async () => {
    const dir = await tmp();
    const storage = join(dir, 'state');
    const policy = await writeJson(dir, 'policy.json', policyJson());
    const txFile = await writeJson(dir, 'tx.json', tx(erc20.transfer(ALICE, usdc('100'))));
    await run(['evaluate', '--policy', policy, '--tx', txFile, '--storage', storage]);
    const ok = await run(['audit-verify', '--file', join(storage, 'audit.jsonl')]);
    expect(ok.code).toBe(0);
    expect(ok.stdout).toContain('audit chain valid');

    const broken = join(dir, 'broken.jsonl');
    await writeFile(broken, `${JSON.stringify({ seq: 0, timestamp: '2026-01-01T00:00:00.000Z', type: 'evaluation', requestId: 'x', sessionId: 'default', payload: {}, prevHash: '0'.repeat(64), hash: '1'.repeat(64) })}\n`, 'utf8');
    const bad = await run(['audit-verify', '--file', broken]);
    expect(bad.code).toBe(1);
    expect(bad.stdout).toContain('BROKEN');
  });
});

describe('cli: gateway commands still work', () => {
  it('token prints a token and its SHA-256', async () => {
    const r = await run(['token']);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('token:');
    expect(r.stdout).toContain('sha256:');
  });

  it('no arguments prints help', async () => {
    const r = await run([]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('evaluate');
    expect(r.stdout).toContain('sign-check');
  });
});

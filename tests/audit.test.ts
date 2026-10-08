import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { AuditLog, JsonlFileAuditSink, MemoryAuditSink, verifyAuditChain, type AuditRecord } from '../src/audit.js';
import { createFirewall } from '../src/firewall.js';
import { ALICE, USDC, basePolicy, erc20, fixedEnv, tx, usdc } from './helpers.js';

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function chain(n: number) {
  const sink = new MemoryAuditSink();
  const log = new AuditLog(sink, () => 0);
  for (let i = 0; i < n; i++) await log.record('evaluation', `r${i}`, 's', { i, amount: BigInt(i) });
  return sink.records;
}

describe('hash-chained audit log', () => {
  it('produces a valid, frozen chain serialized in append order', async () => {
    const sink = new MemoryAuditSink();
    const log = new AuditLog(sink);
    await Promise.all(Array.from({ length: 20 }, (_, i) => log.record('evaluation', `r${i}`, 's', { i })));
    const records = sink.records;
    expect(records.map((r) => r.seq)).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
    expect(verifyAuditChain(records)).toEqual({ valid: true });
    expect(Object.isFrozen(records[0]!.payload)).toBe(true);
  });

  it('detects modified, deleted and reordered records', async () => {
    const records = await chain(4);
    const modified = records.map((r, i) => (i === 1 ? { ...r, payload: { ...r.payload, amount: '999' } } : r));
    expect(verifyAuditChain(modified)).toMatchObject({ valid: false, brokenAt: 1 });
    expect(verifyAuditChain([records[0]!, records[2]!, records[3]!])).toMatchObject({ valid: false, brokenAt: 1 });
    expect(verifyAuditChain([records[1]!, records[0]!])).toMatchObject({ valid: false, brokenAt: 0 });
    const rehashedOnly: AuditRecord[] = records.map((r, i) => (i === 2 ? { ...r, hash: 'f'.repeat(64) } : r));
    expect(verifyAuditChain(rehashedOnly).valid).toBe(false);
  });

  it('persists JSONL and continues the chain after a restart', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'atfw-audit-'));
    dirs.push(dir);
    const path = join(dir, 'audit.jsonl');
    const env = fixedEnv();
    const first = createFirewall({ policy: basePolicy(), audit: new JsonlFileAuditSink(path), clock: env.clock });
    const v = await first.evaluate(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('1')) }));
    await first.commit(v, { txHash: `0x${'ab'.repeat(32)}` });

    const second = createFirewall({ policy: basePolicy(), audit: new JsonlFileAuditSink(path), clock: env.clock });
    await second.evaluate(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('2000')) }));

    const records = await JsonlFileAuditSink.read(path);
    expect(records.map((r) => [r.seq, r.type])).toEqual([[1, 'evaluation'], [2, 'commit'], [3, 'evaluation']]);
    expect(verifyAuditChain(records)).toEqual({ valid: true });
    expect(records[0]!.payload).toMatchObject({ policyHash: first.policyHash, txDigest: v.txDigest });
    expect((records[2]!.payload.result as { verdict: string }).verdict).toBe('blocked');

    const text = await readFile(path, 'utf8');
    await writeFile(path, text.replace('"verdict":"blocked"', '"verdict":"allowed"'));
    expect(verifyAuditChain(await JsonlFileAuditSink.read(path)).valid).toBe(false);
  });
});

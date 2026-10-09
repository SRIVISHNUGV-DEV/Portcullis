import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AuditLog, JsonlFileAuditSink, verifyAuditChain, type AuditRecord, type AuditSink } from '../src/audit.js';
import { createFirewall } from '../src/firewall.js';
import { GroupCommitFile, JournalSessionStore } from '../src/storage.js';
import { ALICE, USDC, basePolicy, erc20, fixedEnv, tx, usdc } from './helpers.js';

const tempDir = () => mkdtemp(join(tmpdir(), 'atf-storage-'));
const lines = async (path: string) => (await readFile(path, 'utf8')).split('\n').filter(Boolean);

describe('GroupCommitFile', () => {
  it('persists concurrent appends in call order', async () => {
    const path = join(await tempDir(), 'log.jsonl');
    const file = new GroupCommitFile(path, { fsync: false });
    await Promise.all(Array.from({ length: 200 }, (_, i) => file.append(String(i))));
    await file.close();
    expect(await lines(path)).toEqual(Array.from({ length: 200 }, (_, i) => String(i)));
  });

  it('rejects every append after a failed write until reset', async () => {
    const file = new GroupCommitFile(join(await tempDir(), 'missing', 'log.jsonl'));
    await expect(file.append('a')).rejects.toThrow();
    await expect(file.append('b')).rejects.toThrow();
    file.reset();
    await expect(file.append('c')).rejects.toThrow(); // directory still missing
  });
});

describe('JournalSessionStore', () => {
  it('restores reservations, approvals and bigint spend after a restart', async () => {
    const dir = await tempDir();
    const path = join(dir, 'sessions.jsonl');
    const env = fixedEnv();
    let store = await JournalSessionStore.open(path, { fsync: false });
    let fw = createFirewall({ policy: basePolicy(), sessions: store, ...env });

    const allowed = await fw.evaluate(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('300')) }), { sessionId: 'run' });
    await fw.commit(allowed, { txHash: '0x01' });
    const reserved = await fw.evaluate(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('200')) }), { sessionId: 'run' });
    const pending = await fw.evaluate(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('600')) }), { sessionId: 'run' });
    expect([allowed.verdict, reserved.verdict, pending.verdict]).toEqual(['allowed', 'allowed', 'requiresApproval']);
    await store.close();

    store = await JournalSessionStore.open(path, { fsync: false });
    fw = createFirewall({ policy: basePolicy(), sessions: store, ...env });
    const usage = await fw.usage('run');
    expect(usage.spent.tokens[USDC]).toBe(usdc('500').toString());
    expect(usage.txCount).toBe(2);
    expect(usage.pendingApprovals).toBe(1);
    await fw.commit(reserved);
    const approved = await fw.approve(pending, { approver: 'ops@example.com' });
    expect(approved.allowed).toBe(true);
    await store.close();
  });

  it('does not rewrite unchanged state and compacts on open', async () => {
    const path = join(await tempDir(), 'sessions.jsonl');
    const store = await JournalSessionStore.open(path, { fsync: false });
    const fw = createFirewall({ policy: basePolicy(), sessions: store, ...fixedEnv() });
    for (let i = 0; i < 3; i++) {
      const v = await fw.evaluate(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('1')) }), { sessionId: 's' });
      await fw.commit(v);
    }
    const before = (await lines(path)).length;
    await fw.usage('s');
    await fw.usage('s');
    expect((await lines(path)).length).toBe(before);
    await store.close();
    await JournalSessionStore.open(path, { fsync: false }).then((s) => s.close());
    expect(await lines(path)).toHaveLength(1);
  });

  it('ignores a torn final line but refuses a corrupt earlier line', async () => {
    const dir = await tempDir();
    const path = join(dir, 'sessions.jsonl');
    const store = await JournalSessionStore.open(path, { fsync: false });
    const fw = createFirewall({ policy: basePolicy(), sessions: store, ...fixedEnv() });
    await fw.commit(await fw.evaluate(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('5')) }), { sessionId: 's' }));
    await store.close();
    const good = await readFile(path, 'utf8');

    await writeFile(path, `${good}{"id":"s","created`);
    const reopened = await JournalSessionStore.open(path, { fsync: false });
    expect((await createFirewall({ policy: basePolicy(), sessions: reopened }).usage('s')).spent.tokens[USDC]).toBe(usdc('5').toString());
    await reopened.close();

    await writeFile(path, `{"broken\n${good}`);
    await expect(JournalSessionStore.open(path)).rejects.toThrow(/Corrupt session journal/);
  });
});

describe('durable audit log', () => {
  it('keeps one valid hash chain across restarts and concurrent writes', async () => {
    const path = join(await tempDir(), 'audit.jsonl');
    for (let run = 0; run < 2; run++) {
      const sink = new JsonlFileAuditSink(path, { fsync: false });
      const fw = createFirewall({ policy: basePolicy(), audit: sink });
      await Promise.all(
        Array.from({ length: 25 }, (_, i) => fw.evaluate(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('1')) }), { sessionId: `s${i}` })),
      );
      await sink.close();
    }
    const records = await JsonlFileAuditSink.read(path);
    expect(records).toHaveLength(50);
    expect(verifyAuditChain(records)).toEqual({ valid: true });
  });

  it('re-synchronizes after a failed pipelined append without forking the chain', async () => {
    const persisted: AuditRecord[] = [];
    let failNext = false;
    let broken = false;
    const sink: AuditSink = {
      pipelined: true,
      async append(record) {
        await Promise.resolve();
        if (broken) throw new Error('sink broken');
        if (failNext) {
          failNext = false;
          broken = true;
          throw new Error('disk full');
        }
        persisted.push(record);
      },
      async tail() {
        broken = false;
        return persisted[persisted.length - 1];
      },
    };
    const log = new AuditLog(sink);
    await log.record('evaluation', 'r1', 's', {});
    failNext = true;
    const results = await Promise.allSettled([log.record('evaluation', 'r2', 's', {}), log.record('evaluation', 'r3', 's', {})]);
    expect(results.map((r) => r.status)).toEqual(['rejected', 'rejected']);
    await log.record('evaluation', 'r4', 's', {});
    expect(persisted.map((r) => r.requestId)).toEqual(['r1', 'r4']);
    expect(verifyAuditChain(persisted)).toEqual({ valid: true });
  });

  it('blocks the request when the durable audit write fails', async () => {
    const fw = createFirewall({ policy: basePolicy(), audit: new JsonlFileAuditSink(join(await tempDir(), 'missing', 'audit.jsonl')) });
    const v = await fw.evaluate(tx({ to: USDC, data: erc20.transfer(ALICE, usdc('1')) }));
    expect(v.verdict).toBe('blocked');
    expect(v.reasons[0]?.code).toBe('AUDIT_UNAVAILABLE');
    expect((await fw.usage()).spent.tokens[USDC]).toBeUndefined();
  });
});

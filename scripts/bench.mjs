// Latency benchmark for Firewall.evaluate().
// Usage: npm run bench   (BENCH_ITERATIONS, BENCH_MAX_P99_MS to fail the run above a p99 budget)
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { createFirewall, JournalSessionStore, JsonlFileAuditSink, parseUnits } from '../dist/index.js';

const WALLET = '0x1111111111111111111111111111111111111111';
const USDC = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
const ALICE = '0xa11ce00000000000000000000000000000000001';
const word = (hex) => hex.replace(/^0x/, '').padStart(64, '0');
const transfer = (to, amount) => `0xa9059cbb${word(to)}${word(amount.toString(16))}`;

const policy = {
  version: 1,
  chainIds: [8453],
  native: { perTransactionMax: parseUnits('1', 18), sessionMax: parseUnits('1000000', 18) },
  tokens: [{ address: USDC, symbol: 'USDC', decimals: 6, perTransactionMax: parseUnits('1000', 6), sessionMax: parseUnits('1000000000', 6) }],
};

const scenarios = {
  'single ERC-20 transfer': () => ({ chainId: 8453, from: WALLET, to: USDC, data: transfer(ALICE, 1_000_000n) }),
  'blocked unlimited approval': () => ({ chainId: 8453, from: WALLET, to: USDC, data: `0x095ea7b3${word(ALICE)}${'f'.repeat(64)}` }),
  '8-call batch': () => ({ chainId: 8453, from: WALLET, calls: Array.from({ length: 8 }, () => ({ to: USDC, data: transfer(ALICE, 1n) })) }),
};

/** Audit sink that discards records, so the benchmark measures the engine rather than heap growth. */
const nullSink = { append: async () => {}, tail: async () => undefined };

async function stores(kind) {
  if (kind === 'memory') return { sessions: undefined, audit: nullSink, close: async () => {} };
  const dir = mkdtempSync(join(tmpdir(), 'atf-bench-'));
  const fsync = kind === 'file+fsync';
  const sessions = await JournalSessionStore.open(join(dir, 'sessions.jsonl'), { fsync });
  const audit = new JsonlFileAuditSink(join(dir, 'audit.jsonl'), { fsync });
  return { sessions, audit, close: async () => { await sessions.close(); await audit.close(); } };
}

const pct = (samples, p) => samples[Math.min(samples.length - 1, Math.floor(samples.length * p))];
const iterations = Number(process.env.BENCH_ITERATIONS ?? 5000);
const maxP99 = process.env.BENCH_MAX_P99_MS ? Number(process.env.BENCH_MAX_P99_MS) : undefined;
let worstP99 = 0;

for (const kind of ['memory', 'file', 'file+fsync']) {
  const s = await stores(kind);
  const firewall = createFirewall({ policy, audit: s.audit, ...(s.sessions ? { sessions: s.sessions } : {}) });
  const n = kind === 'file+fsync' ? Math.min(iterations, 1000) : iterations;
  console.log(`\n# stores: ${kind}`);
  for (const [name, make] of Object.entries(scenarios)) {
    for (let i = 0; i < 200; i++) await firewall.evaluate(make(), { sessionId: `warm-${i % 8}` });
    const samples = [];
    for (let i = 0; i < n; i++) {
      const t = performance.now();
      const v = await firewall.evaluate(make(), { sessionId: `s-${i % 64}` });
      samples.push(performance.now() - t);
      if (v.allowed) await firewall.release(v);
    }
    samples.sort((a, b) => a - b);
    const p99 = pct(samples, 0.99);
    if (kind !== 'file+fsync') worstP99 = Math.max(worstP99, p99);
    console.log(`${name.padEnd(28)} p50 ${pct(samples, 0.5).toFixed(3)} ms  p95 ${pct(samples, 0.95).toFixed(3)} ms  p99 ${p99.toFixed(3)} ms  (n=${n})`);
  }

  // Concurrency: many agents (sessions) evaluating at once; throughput and per-request latency.
  const agents = 64;
  const perAgent = kind === 'file+fsync' ? 20 : 100;
  const latencies = [];
  const t0 = performance.now();
  await Promise.all(Array.from({ length: agents }, async (_, a) => {
    for (let i = 0; i < perAgent; i++) {
      const t = performance.now();
      const v = await firewall.evaluate(scenarios['single ERC-20 transfer'](), { sessionId: `agent-${a}` });
      latencies.push(performance.now() - t);
      if (v.allowed) await firewall.commit(v);
    }
  }));
  const seconds = (performance.now() - t0) / 1000;
  latencies.sort((a, b) => a - b);
  console.log(`${`${agents} concurrent agents`.padEnd(28)} ${Math.round(latencies.length / seconds)} evals/s  p50 ${pct(latencies, 0.5).toFixed(3)} ms  p99 ${pct(latencies, 0.99).toFixed(3)} ms (queueing included)`);
  await s.close();
}

if (maxP99 !== undefined && worstP99 > maxP99) {
  console.error(`\np99 ${worstP99.toFixed(3)} ms exceeds the ${maxP99} ms budget`);
  process.exit(1);
}

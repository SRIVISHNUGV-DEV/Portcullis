// Latency benchmark for Firewall.evaluate() with in-memory session and audit stores.
// Usage: npm run bench
import { performance } from 'node:perf_hooks';
import { createFirewall, parseUnits } from '../dist/index.js';

const WALLET = '0x1111111111111111111111111111111111111111';
const USDC = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
const ALICE = '0xa11ce00000000000000000000000000000000001';
const word = (hex) => hex.replace(/^0x/, '').padStart(64, '0');
const transfer = (to, amount) => `0xa9059cbb${word(to)}${word(amount.toString(16))}`;

const firewall = createFirewall({
  policy: {
    version: 1,
    chainIds: [8453],
    native: { perTransactionMax: parseUnits('1', 18), sessionMax: parseUnits('1000000', 18) },
    tokens: [{ address: USDC, symbol: 'USDC', decimals: 6, perTransactionMax: parseUnits('1000', 6), sessionMax: parseUnits('1000000000', 6) }],
  },
});

const scenarios = {
  'single ERC-20 transfer': () => ({ chainId: 8453, from: WALLET, to: USDC, data: transfer(ALICE, 1_000_000n) }),
  'blocked unlimited approval': () => ({ chainId: 8453, from: WALLET, to: USDC, data: `0x095ea7b3${word(ALICE)}${'f'.repeat(64)}` }),
  '8-call batch': () => ({ chainId: 8453, from: WALLET, calls: Array.from({ length: 8 }, () => ({ to: USDC, data: transfer(ALICE, 1n) })) }),
};

const iterations = Number(process.env.BENCH_ITERATIONS ?? 5000);
for (const [name, make] of Object.entries(scenarios)) {
  for (let i = 0; i < 200; i++) await firewall.evaluate(make(), { sessionId: `warm-${name}` });
  const samples = [];
  for (let i = 0; i < iterations; i++) {
    const t = performance.now();
    const v = await firewall.evaluate(make(), { sessionId: `s-${i % 64}` });
    samples.push(performance.now() - t);
    if (v.allowed) await firewall.release(v);
  }
  samples.sort((a, b) => a - b);
  const pct = (p) => samples[Math.min(samples.length - 1, Math.floor(samples.length * p))].toFixed(3);
  console.log(`${name.padEnd(28)} p50 ${pct(0.5)} ms  p95 ${pct(0.95)} ms  p99 ${pct(0.99)} ms  (n=${iterations})`);
}

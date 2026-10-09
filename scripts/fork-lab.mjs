// Local fork lab: a Base mainnet fork plus a firewall gateway serving three agents
// over MCP, for manual and agent-driven testing. Requires Foundry (anvil, cast).
//
//   npm run build && node scripts/fork-lab.mjs [--dir /tmp/atf-fork] [--fork-url URL]
//
// Writes <dir>/mcp.sh (agent tool calls) and <dir>/admin.sh (approvals, audit check).
// Bearer tokens are stored in <dir>/*.token with mode 0600 and read by those scripts.

import { execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { parseUnits } from '../dist/index.js';
import { Gateway, createGatewayServer, hashToken } from '../dist/mcp.js';

const { values } = parseArgs({
  options: {
    dir: { type: 'string', default: '/tmp/atf-fork' },
    'fork-url': { type: 'string', default: process.env.FORK_URL ?? 'https://mainnet.base.org' },
    'anvil-port': { type: 'string', default: '8545' },
    port: { type: 'string', default: '8787' },
  },
});
const dir = values.dir;
const rpcUrl = `http://127.0.0.1:${values['anvil-port']}`;
const CHAIN = 8453;
const USDC = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
const WETH = '0x4200000000000000000000000000000000000006';
const ROUTER = '0x2626664c2603336e57b271c5c0b26f421741e481'; // Uniswap SwapRouter02 on Base
const EXACT_INPUT_SINGLE = '0x04e45aaf';
const USDC_BALANCE_SLOT = 9; // FiatTokenV2 balanceAndBlacklistStates mapping

rmSync(join(dir, 'data'), { recursive: true, force: true });
mkdirSync(dir, { recursive: true, mode: 0o700 });

async function rpc(method, params = []) {
  const res = await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

const anvil = spawn('anvil', ['--fork-url', values['fork-url'], '--chain-id', String(CHAIN), '--port', values['anvil-port'], '--silent'], { stdio: 'ignore' });
process.on('exit', () => anvil.kill());
for (let i = 0; ; i++) {
  try {
    await rpc('eth_blockNumber');
    break;
  } catch {
    if (i > 60) throw new Error('anvil did not start');
    await new Promise((r) => setTimeout(r, 500));
  }
}
const forkBlock = parseInt(await rpc('eth_blockNumber'), 16);
const [payments, trader, ops] = (await rpc('eth_accounts')).slice(0, 3);
for (const account of [payments, trader]) {
  const slot = execFileSync('cast', ['index', 'address', account, String(USDC_BALANCE_SLOT)]).toString().trim();
  await rpc('anvil_setStorageAt', [USDC, slot, `0x${parseUnits('10000', 6).toString(16).padStart(64, '0')}`]);
}

const secret = (name) => {
  const token = randomBytes(32).toString('base64url');
  writeFileSync(join(dir, `${name}.token`), token, { mode: 0o600 });
  return hashToken(token);
};
const usdcRule = (perTx, session, approvalAbove) => ({
  address: USDC, symbol: 'USDC', decimals: 6,
  perTransactionMax: parseUnits(perTx, 6), sessionMax: parseUnits(session, 6), requireApprovalAbove: parseUnits(approvalAbove, 6),
});
const strict = { unknownContractCalls: 'block', unlistedAssets: 'block' };

const config = {
  chainId: CHAIN,
  rpcUrl,
  listen: { host: '127.0.0.1', port: Number(values.port) },
  adminTokenSha256: secret('admin'),
  storage: { dir: join(dir, 'data'), fsync: true },
  agents: [
    {
      id: 'payments-bot', tokenSha256: secret('payments-bot'), wallet: payments,
      policy: {
        version: 1, name: 'payments-bot', chainIds: [CHAIN], ...strict,
        native: { perTransactionMax: 0n, sessionMax: 0n },
        tokens: [usdcRule('100', '500', '50')],
      },
    },
    {
      id: 'trader-bot', tokenSha256: secret('trader-bot'), wallet: trader,
      policy: {
        version: 1, name: 'trader-bot', chainIds: [CHAIN], ...strict,
        native: { perTransactionMax: parseUnits('0.01', 18), sessionMax: parseUnits('0.05', 18) },
        tokens: [
          usdcRule('1000', '3000', '500'),
          { address: WETH, symbol: 'WETH', decimals: 18, perTransactionMax: parseUnits('1', 18), sessionMax: parseUnits('2', 18) },
        ],
        protocols: [{ name: 'Uniswap SwapRouter02', address: ROUTER, selectors: [EXACT_INPUT_SINGLE], maxNativeValue: 0n }],
        approvals: { spenders: [ROUTER] },
      },
    },
    {
      id: 'ops-bot', tokenSha256: secret('ops-bot'), wallet: ops,
      policy: {
        version: 1, name: 'ops-bot', chainIds: [CHAIN], ...strict,
        native: { perTransactionMax: parseUnits('0.05', 18), sessionMax: parseUnits('0.2', 18), requireApprovalAbove: parseUnits('0.02', 18) },
      },
    },
  ],
};

const gateway = await Gateway.create(config, { receiptTimeoutMs: 5000 });
const server = createGatewayServer(gateway);
await new Promise((resolve) => server.listen(Number(values.port), '127.0.0.1', resolve));
const base = `http://127.0.0.1:${values.port}`;

writeFileSync(join(dir, 'mcp.sh'), `#!/bin/sh
# Usage: mcp.sh <agent-id> <tool> ['{"json":"args"}']   |   mcp.sh <agent-id> tools/list
set -e
AGENT="$1"; TOOL="$2"; ARGS="\${3:-{\\}}"
if [ "$TOOL" = "tools/list" ]; then BODY='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
else BODY="{\\"jsonrpc\\":\\"2.0\\",\\"id\\":1,\\"method\\":\\"tools/call\\",\\"params\\":{\\"name\\":\\"$TOOL\\",\\"arguments\\":$ARGS}}"; fi
curl -s ${base}/mcp -H 'content-type: application/json' -H "authorization: Bearer $(cat ${dir}/$AGENT.token)" -d "$BODY"
echo
`);
writeFileSync(join(dir, 'admin.sh'), `#!/bin/sh
# Usage: admin.sh pending | approve <requestId> [approver] | reject <requestId> [approver] | verify
set -e
AUTH="authorization: Bearer $(cat ${dir}/admin.token)"
case "$1" in
  pending) curl -s ${base}/admin/pending -H "$AUTH" ;;
  verify) curl -s ${base}/admin/audit/verify -H "$AUTH" ;;
  approve|reject) curl -s -X POST ${base}/admin/requests/$2/$1 -H "$AUTH" -H 'content-type: application/json' -d "{\\"approver\\":\\"\${3:-operator@example.com}\\"}" ;;
  *) echo "usage: admin.sh pending|approve <id>|reject <id>|verify"; exit 2 ;;
esac
echo
`);
chmodSync(join(dir, 'mcp.sh'), 0o755);
chmodSync(join(dir, 'admin.sh'), 0o755);

console.log(`fork lab ready
  chain:    Base mainnet fork at block ${forkBlock} (${rpcUrl})
  gateway:  ${base}/mcp  (admin: ${base}/admin)
  agents:   payments-bot ${payments}
            trader-bot   ${trader}
            ops-bot      ${ops}
  clients:  ${dir}/mcp.sh, ${dir}/admin.sh
  storage:  ${join(dir, 'data')}`);

const stop = async () => {
  server.close();
  await gateway.close();
  anvil.kill();
  process.exit(0);
};
process.on('SIGINT', () => void stop());
process.on('SIGTERM', () => void stop());

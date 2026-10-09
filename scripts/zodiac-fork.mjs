// Checks toZodiacRoles() against the deployed Zodiac Roles Modifier v2 on a Base
// mainnet fork: creates a Safe, attaches a Roles modifier, applies the generated
// permissions and replays allowed and malicious agent transactions through it.
// Requires Foundry (anvil, cast).
//
//   npm run build && node scripts/zodiac-fork.mjs [--fork-url URL] [--anvil-port 8546]

import { execFileSync, spawn } from 'node:child_process';
import { parseArgs } from 'node:util';
import { execTransactionWithRole, parseUnits, toZodiacRoles } from '../dist/index.js';

const { values } = parseArgs({
  options: {
    'fork-url': { type: 'string', default: process.env.FORK_URL ?? 'https://mainnet.base.org' },
    'anvil-port': { type: 'string', default: '8546' },
  },
});
const rpcUrl = `http://127.0.0.1:${values['anvil-port']}`;
const CHAIN = 8453;
const USDC = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
const WETH = '0x4200000000000000000000000000000000000006';
const ROUTER = '0x2626664c2603336e57b271c5c0b26f421741e481';
const USDC_BALANCE_SLOT = 9;
// Canonical deployments on Base.
const ROLES_MASTERCOPY = '0x9646fDAD06d3e24444381f44362a3B0eB343D337'; // Roles v2.1.0
const MODULE_PROXY_FACTORY = '0x000000000000aDdB49795b0f9bA5BC298cDda236';
const SAFE_PROXY_FACTORY = '0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67'; // Safe 1.4.1
const SAFE_L2_SINGLETON = '0x29fcB43b46531BcA003ddC8FCB67FFE91900C762';
const ZERO = '0x0000000000000000000000000000000000000000';
const VENDOR = '0x00000000000000000000000000000000000a11ce';
const CONTRACTOR = '0x0000000000000000000000000000000000000c0d';
const ATTACKER = '0x000000000000000000000000000000000000bad1';

const cast = (...args) => execFileSync('cast', args).toString().trim();

async function rpc(method, params = []) {
  const res = await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const body = await res.json();
  if (body.error) throw Object.assign(new Error(`${method}: ${body.error.message}`), { data: body.error.data });
  return body.result;
}

// Roles v2 PermissionChecker.Status, in enum order.
const STATUS = [
  'Ok', 'DelegateCallNotAllowed', 'TargetAddressNotAllowed', 'FunctionNotAllowed', 'SendNotAllowed', 'OrViolation', 'NorViolation',
  'ParameterNotAllowed', 'ParameterLessThanAllowed', 'ParameterGreaterThanAllowed', 'ParameterNotAMatch', 'NotEveryArrayElementPasses',
  'NoArrayElementPasses', 'ParameterNotSubsetOfAllowed', 'BitmaskOverflow', 'BitmaskNotAllowed', 'CustomConditionViolation',
  'AllowanceExceeded', 'CallAllowanceExceeded', 'EtherAllowanceExceeded',
];

/** Decoded Roles revert reason for an agent call, or "allowed". */
async function rolesOutcome(from, data) {
  try {
    await rpc('eth_call', [{ from, to: roles, data }, 'latest']);
    return 'allowed';
  } catch (e) {
    const hex = typeof e.data === 'string' ? e.data : (e.data?.data ?? '');
    if (hex.startsWith('0xd0a9bf58')) return STATUS[parseInt(hex.slice(10, 74), 16)] ?? `status ${parseInt(hex.slice(10, 74), 16)}`;
    if (hex.startsWith('0x4a0bfec1')) return 'NotAuthorized'; // v2.1.0 reverts NotAuthorized(sender) for non-members
    return `reverted (${e.message.slice(0, 80)})`;
  }
}

async function send(from, to, data, value = 0n) {
  const hash = await rpc('eth_sendTransaction', [{ from, to, data, value: `0x${value.toString(16)}` }]);
  let receipt = null;
  for (let i = 0; !receipt && i < 100; i++) {
    receipt = await rpc('eth_getTransactionReceipt', [hash]);
    if (!receipt) await new Promise((r) => setTimeout(r, 50));
  }
  if (receipt?.status !== '0x1') throw new Error(`reverted: ${hash}`);
  return receipt;
}

const callAddress = async (to, data) => `0x${(await rpc('eth_call', [{ to, data }, 'latest'])).slice(-40)}`;
const balanceOf = async (token, who) => BigInt(await rpc('eth_call', [{ to: token, data: cast('calldata', 'balanceOf(address)', who) }, 'latest']));

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
const [owner, agent, outsider] = (await rpc('eth_accounts')).slice(0, 3);

// 1. Safe owned by `owner`, threshold 1.
const setup = cast('calldata', 'setup(address[],uint256,address,bytes,address,address,uint256,address)', `[${owner}]`, '1', ZERO, '0x', ZERO, ZERO, '0', ZERO);
const createSafe = cast('calldata', 'createProxyWithNonce(address,bytes,uint256)', SAFE_L2_SINGLETON, setup, String(Date.now()));
const safe = await callAddress(SAFE_PROXY_FACTORY, createSafe);
await send(owner, SAFE_PROXY_FACTORY, createSafe);

// 2. Roles modifier: owner configures it, the Safe is avatar and target.
const initParams = cast('abi-encode', 'f(address,address,address)', owner, safe, safe);
const deploy = cast('calldata', 'deployModule(address,bytes,uint256)', ROLES_MASTERCOPY, cast('calldata', 'setUp(bytes)', initParams), String(Date.now()));
const roles = await callAddress(MODULE_PROXY_FACTORY, deploy);
await send(owner, MODULE_PROXY_FACTORY, deploy);

// 3. Enable the modifier on the Safe (pre-validated owner signature: r = owner, s = 0, v = 1).
const signature = `0x${owner.slice(2).padStart(64, '0')}${'0'.repeat(64)}01`;
await send(owner, safe, cast('calldata', 'execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)',
  safe, '0', cast('calldata', 'enableModule(address)', roles), '0', '0', '0', '0', ZERO, ZERO, signature));

// 4. Fund the Safe: 1000 USDC and 1 ETH.
await rpc('anvil_setStorageAt', [USDC, cast('index', 'address', safe, String(USDC_BALANCE_SLOT)), `0x${parseUnits('1000', 6).toString(16).padStart(64, '0')}`]);
await rpc('anvil_setBalance', [safe, `0x${parseUnits('1', 18).toString(16)}`]);

// 5. Firewall policy → Roles permissions.
const policy = {
  version: 1, name: 'treasury-agent', chainIds: [CHAIN],
  native: { perTransactionMax: parseUnits('0.01', 18), sessionMax: parseUnits('0.05', 18) },
  tokens: [
    { address: USDC, symbol: 'USDC', decimals: 6, perTransactionMax: parseUnits('300', 6), sessionMax: parseUnits('500', 6), requireApprovalAbove: parseUnits('50', 6) },
    { address: WETH, symbol: 'WETH', decimals: 18, perTransactionMax: parseUnits('1', 18), sessionMax: parseUnits('2', 18) },
  ],
  protocols: [{ name: 'Uniswap SwapRouter02', address: ROUTER, kind: 'uniswap-v3-router', selectors: ['0x04e45aaf'], maxNativeValue: 0n, maxSlippageBps: 100 }],
  recipients: { allow: [VENDOR, CONTRACTOR] },
  denylist: [ATTACKER],
};
const plan = toZodiacRoles(policy, { roles, role: 'treasury-agent', members: [agent] });
for (const c of plan.calls) await send(owner, c.to, c.data);

// 6. Agent transactions through execTransactionWithRole.
const usdcTransfer = (to, amount) => ({ to: USDC, data: cast('calldata', 'transfer(address,uint256)', to, String(parseUnits(amount, 6))) });
const usdcApprove = (spender, amount) => ({ to: USDC, data: cast('calldata', 'approve(address,uint256)', spender, amount) });
const swap = (recipient, amountIn, minOut) => ({
  to: ROUTER,
  data: cast('calldata', 'exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))', `(${USDC},${WETH},500,${recipient},${parseUnits(amountIn, 6)},${minOut},0)`),
});
const eth = (to, amount) => ({ to, value: parseUnits(amount, 18), data: '0x' });

const scenarios = [
  ['USDC 40 → vendor', agent, usdcTransfer(VENDOR, '40'), 'allowed'],
  ['USDC 301 → vendor (above per-tx cap)', agent, usdcTransfer(VENDOR, '301'), 'ParameterGreaterThanAllowed'],
  ['USDC 40 → attacker (not allowlisted)', agent, usdcTransfer(ATTACKER, '40'), 'OrViolation'],
  ['USDC unlimited approve → router', agent, usdcApprove(ROUTER, (2n ** 256n - 1n).toString()), 'ParameterGreaterThanAllowed'],
  ['USDC 10 approve → attacker', agent, usdcApprove(ATTACKER, String(parseUnits('10', 6))), 'ParameterNotAllowed'],
  ['USDC 200 approve → router', agent, usdcApprove(ROUTER, String(parseUnits('200', 6))), 'allowed'],
  ['swap 200 USDC → WETH, recipient attacker', agent, swap(ATTACKER, '200', '1'), 'ParameterNotAllowed'],
  ['swap 200 USDC → WETH, minOut 0', agent, swap(safe, '200', '0'), 'ParameterLessThanAllowed'],
  ['swap 200 USDC → WETH, recipient Safe', agent, swap(safe, '200', '1'), 'allowed'],
  ['USDC 270 → contractor (allowance has 260 left)', agent, usdcTransfer(CONTRACTOR, '270'), 'AllowanceExceeded'],
  ['USDC 250 → contractor', agent, usdcTransfer(CONTRACTOR, '250'), 'allowed'],
  ['USDC 20 → contractor (allowance has 10 left)', agent, usdcTransfer(CONTRACTOR, '20'), 'AllowanceExceeded'],
  ['WETH transfer → vendor (function not granted)', agent, { to: WETH, data: cast('calldata', 'transferFrom(address,address,uint256)', safe, VENDOR, '1') }, 'FunctionNotAllowed'],
  ['call to an unlisted contract', agent, { to: ATTACKER, data: '0x12345678' }, 'TargetAddressNotAllowed'],
  ['ETH 0.01 → vendor', agent, eth(VENDOR, '0.01'), 'allowed'],
  ['ETH 0.01 → attacker', agent, eth(ATTACKER, '0.01'), 'TargetAddressNotAllowed'],
  ['ETH 0.045 → vendor (allowance has 0.04 left)', agent, eth(VENDOR, '0.045'), 'EtherAllowanceExceeded'],
  ['non-member uses the role', outsider, usdcTransfer(VENDOR, '1'), 'NotAuthorized'],
];

const before = { vendor: await balanceOf(USDC, VENDOR), contractor: await balanceOf(USDC, CONTRACTOR), weth: await balanceOf(WETH, safe) };
const rows = [];
let failures = 0;
for (const [scenario, from, call, expected] of scenarios) {
  const data = execTransactionWithRole(call, 'treasury-agent');
  const actual = await rolesOutcome(from, data);
  if (actual === 'allowed') await send(from, roles, data);
  if (actual !== expected) failures += 1;
  rows.push({ scenario, expected, actual });
}

console.table(rows);
console.log({
  safe, roles, configCalls: plan.calls.length,
  vendorUsdcReceived: Number((await balanceOf(USDC, VENDOR)) - before.vendor) / 1e6,
  contractorUsdcReceived: Number((await balanceOf(USDC, CONTRACTOR)) - before.contractor) / 1e6,
  safeWethReceived: Number((await balanceOf(WETH, safe)) - before.weth) / 1e18,
});
console.log('warnings:\n- ' + plan.warnings.join('\n- '));
console.log(failures ? `FAILED: ${failures} scenario(s) did not match` : 'all scenarios matched');
anvil.kill();
process.exit(failures ? 1 : 0);

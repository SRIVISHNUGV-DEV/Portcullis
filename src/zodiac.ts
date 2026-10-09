// Firewall policy → Zodiac Roles Modifier v2 permissions.
//
// The Roles modifier enforces permissions onchain, so a compromised firewall host or
// agent key still can't exceed them. It can only express part of a policy: there is no
// human-approval step and no price data. `warnings` lists what stays firewall-only.

import { createHash } from 'node:crypto';
import { T, bytesToHex, encodeAbi, type AbiValue } from './abi.js';
import { SELECTORS, UNISWAP_V3_ROUTER_SELECTORS } from './decoder.js';
import { compilePolicy, type CompiledPolicy } from './policy.js';
import type { PolicyInput } from './schemas.js';
import { UINT256_MAX } from './units.js';

/** Roles v2 `AbiType` and `Operator` values (Types.sol). */
const P = { None: 0, Static: 1, Tuple: 3, Calldata: 5 } as const;
const O = {
  Pass: 0, And: 1, Or: 2, Matches: 5, EqualToAvatar: 15, EqualTo: 16, GreaterThan: 17, LessThan: 18,
  WithinAllowance: 28, EtherWithinAllowance: 29,
} as const;
const EXECUTION = { None: 0, Send: 1 } as const;
const UINT128_MAX = (1n << 128n) - 1n;

export const ROLES_SELECTORS = {
  scopeTarget: '0x0c6c76b8',
  allowTarget: '0x7b0da5b2',
  allowFunction: '0xb3dd25c7',
  scopeFunction: '0x7508dd98',
  setAllowance: '0xa8ec43ee',
  assignRoles: '0x957ed2b3',
  execTransactionWithRole: '0xc6fe8747',
} as const;

export interface ZodiacRolesOptions {
  /** Roles modifier the configuration calls are sent to (by its owner). */
  readonly roles: string;
  /** Role name (up to 32 bytes of UTF-8) or a 0x-prefixed bytes32 key. */
  readonly role: string;
  /** Addresses that get the role, e.g. the agent's signer. */
  readonly members?: readonly string[];
  /**
   * Refill every allowance to its session cap each period (seconds). Without it the
   * allowances are one-time budgets; call `setAllowance` again to start a new one.
   */
  readonly allowancePeriodSeconds?: number;
}

export interface ZodiacCall {
  readonly to: string;
  readonly data: string;
  readonly description: string;
}

export interface ZodiacAllowance {
  readonly key: string;
  /** "native" or a token address. */
  readonly asset: string;
  readonly balance: bigint;
  readonly period: number;
}

export interface ZodiacRolesPlan {
  readonly roleKey: string;
  /** Calls for the Roles owner, in order. */
  readonly calls: ZodiacCall[];
  readonly allowances: ZodiacAllowance[];
  /** Policy features the Roles modifier can't enforce; keep the firewall in front for these. */
  readonly warnings: string[];
}

interface Condition {
  readonly paramType: number;
  readonly operator: number;
  readonly compValue?: string;
  readonly children?: readonly Condition[];
}

const word = (v: bigint | string) => `0x${BigInt(v).toString(16).padStart(64, '0')}`;
const pass: Condition = { paramType: P.Static, operator: O.Pass };
const equalTo = (v: bigint | string): Condition => ({ paramType: P.Static, operator: O.EqualTo, compValue: word(v) });
const oneOf = (values: readonly string[]): Condition =>
  values.length === 1 ? equalTo(values[0]!) : { paramType: P.None, operator: O.Or, children: values.map(equalTo) };
const calldata = (...children: Condition[]): Condition => ({ paramType: P.Calldata, operator: O.Matches, children });

function amountWithin(max: bigint, allowanceKey: string): Condition {
  const within: Condition = { paramType: P.Static, operator: O.WithinAllowance, compValue: allowanceKey };
  if (max >= UINT256_MAX) return within;
  return { paramType: P.None, operator: O.And, children: [{ paramType: P.Static, operator: O.LessThan, compValue: word(max + 1n) }, within] };
}

/** Breadth-first flattening required by `scopeFunction` (ConditionFlat[]). */
export function flattenConditions(root: Condition): [number, number, number, string][] {
  const out: [number, number, number, string][] = [];
  const queue: { node: Condition; parent: number }[] = [{ node: root, parent: 0 }];
  while (queue.length) {
    const { node, parent } = queue.shift()!;
    const index = out.length;
    out.push([parent, node.paramType, node.operator, node.compValue ?? '0x']);
    for (const child of node.children ?? []) queue.push({ node: child, parent: index });
  }
  return out;
}

export function encodeRoleKey(role: string): string {
  if (/^0x[0-9a-fA-F]{64}$/.test(role)) return role.toLowerCase();
  const bytes = Buffer.from(role, 'utf8');
  if (bytes.length === 0 || bytes.length > 32) throw new Error('Role name must be 1-32 bytes of UTF-8, or a bytes32 key');
  return `0x${bytes.toString('hex').padEnd(64, '0')}`;
}

const selectorWord = (selector: string) => selector.toLowerCase().padEnd(66, '0');
const encode = (selector: string, types: Parameters<typeof encodeAbi>[0], values: readonly AbiValue[]) =>
  selector + bytesToHex(encodeAbi(types, values)).slice(2);

const CONDITION_FLAT = T.array(T.tuple(T.uint8, T.uint8, T.uint8, T.bytes));

/** Translate a firewall policy into Roles v2 configuration calls. */
export function toZodiacRoles(policyInput: PolicyInput | CompiledPolicy, options: ZodiacRolesOptions): ZodiacRolesPlan {
  const compiled = 'hash' in policyInput && policyInput.tokens instanceof Map ? (policyInput as CompiledPolicy) : compilePolicy(policyInput);
  const policy = compiled.policy;
  const roles = options.roles.toLowerCase();
  const roleKey = encodeRoleKey(options.role);
  const period = options.allowancePeriodSeconds ?? 0;
  const calls: ZodiacCall[] = [];
  const allowances: ZodiacAllowance[] = [];
  const warnings: string[] = [];
  const scoped = new Set<string>();

  const call = (description: string, data: string) => calls.push({ to: roles, data, description });
  const scopeTarget = (target: string, name: string) => {
    if (scoped.has(target)) return;
    scoped.add(target);
    call(`Scope ${name} (${target}) to function-level permissions`, encode(ROLES_SELECTORS.scopeTarget, [T.bytes32, T.address], [roleKey, target]));
  };
  const scopeFunction = (target: string, selector: string, root: Condition, send: boolean, description: string) =>
    call(description, encode(
      ROLES_SELECTORS.scopeFunction,
      [T.bytes32, T.address, T.bytes32, CONDITION_FLAT, T.uint8],
      [roleKey, target, selectorWord(selector), flattenConditions(root).map(([a, b, c, d]) => [BigInt(a), BigInt(b), BigInt(c), d]), BigInt(send ? EXECUTION.Send : EXECUTION.None)],
    ));
  const allowFunction = (target: string, selector: string, send: boolean, description: string) =>
    call(description, encode(ROLES_SELECTORS.allowFunction, [T.bytes32, T.address, T.bytes32, T.uint8], [roleKey, target, selectorWord(selector), BigInt(send ? EXECUTION.Send : EXECUTION.None)]));
  const allowance = (asset: string, label: string, balance: bigint) => {
    const key = `0x${createHash('sha256').update(`${roleKey}|${asset}`).digest('hex')}`;
    const capped = balance > UINT128_MAX ? UINT128_MAX : balance;
    allowances.push({ key, asset, balance: capped, period });
    call(
      `Set the ${label} allowance to ${capped} base units${period ? `, refilled every ${period} s` : ' (one-time budget)'}`,
      encode(ROLES_SELECTORS.setAllowance, [T.bytes32, { kind: 'uint', bits: 128 }, { kind: 'uint', bits: 128 }, { kind: 'uint', bits: 128 }, { kind: 'uint', bits: 64 }, { kind: 'uint', bits: 64 }], [
        key, capped, period ? capped : 0n, period ? capped : 0n, BigInt(period), 0n,
      ]),
    );
    return key;
  };

  const recipients = policy.recipients.allow ? [...policy.recipients.allow].sort() : null;
  const trustedSpenders = [...compiled.trustedSpenders].sort();
  const listedTokens = policy.tokens.map((t) => t.address).sort();

  for (const token of policy.tokens) {
    const key = allowance(token.address, token.symbol, token.sessionMax);
    scopeTarget(token.address, token.symbol);
    scopeFunction(
      token.address, SELECTORS.transfer,
      calldata(recipients ? oneOf(recipients) : pass, amountWithin(token.perTransactionMax, key)),
      false,
      `Allow ${token.symbol} transfer${recipients ? ' to allowlisted recipients' : ''}, at most ${token.perTransactionMax} per call, from the ${token.symbol} allowance`,
    );
    if (trustedSpenders.length) {
      scopeFunction(
        token.address, SELECTORS.approve,
        calldata(oneOf(trustedSpenders), amountWithin(token.maxApproval ?? token.perTransactionMax, key)),
        false,
        `Allow ${token.symbol} approve to trusted spenders, at most ${token.maxApproval ?? token.perTransactionMax} per call, from the ${token.symbol} allowance`,
      );
    }
    for (const selector of token.allowedFunctions) {
      allowFunction(token.address, selector, policy.native.sessionMax > 0n, `Allow ${selector} on ${token.symbol} with any arguments`);
      if (policy.native.sessionMax > 0n) warnings.push(`ETH sent with ${selector} on ${token.symbol} is not capped onchain.`);
    }
  }

  if (policy.native.sessionMax > 0n) {
    if (recipients) {
      const key = allowance('native', policy.native.symbol, policy.native.sessionMax);
      for (const to of recipients) {
        scopeTarget(to, 'recipient');
        scopeFunction(to, '0x00000000', calldata({ paramType: P.None, operator: O.EtherWithinAllowance, compValue: key }), true,
          `Allow plain ${policy.native.symbol} transfers to ${to} from the ${policy.native.symbol} allowance`);
      }
      warnings.push(`The ${policy.native.symbol} per-transaction cap is not enforced onchain; only the total allowance is.`);
    } else {
      warnings.push(`${policy.native.symbol} transfers are not allowed onchain: Roles needs explicit recipients (set recipients.allow).`);
    }
  }

  for (const protocol of policy.protocols) {
    const send = (protocol.maxNativeValue ?? 1n) > 0n;
    const allowed = (selector: string) => !protocol.selectors || protocol.selectors.includes(selector);
    if (protocol.kind === 'uniswap-v3-router') {
      scopeTarget(protocol.address, protocol.name);
      const R = UNISWAP_V3_ROUTER_SELECTORS;
      const minOut = policy.swaps.missingSlippageProtection === 'block' ? { paramType: P.Static, operator: O.GreaterThan, compValue: word(0n) } : pass;
      const single = (exactIn: boolean): Condition => calldata({
        paramType: P.Tuple, operator: O.Matches,
        children: [oneOf(listedTokens), oneOf(listedTokens), pass, { paramType: P.Static, operator: O.EqualToAvatar }, pass, exactIn ? minOut : pass, pass],
      });
      let mapped = false;
      if (listedTokens.length && allowed(R.exactInputSingle)) {
        scopeFunction(protocol.address, R.exactInputSingle, single(true), false, `Allow exactInputSingle on ${protocol.name} between listed tokens, output to the Safe${minOut === pass ? '' : ', with a non-zero minimum output'}`);
        mapped = true;
      }
      if (listedTokens.length && allowed(R.exactOutputSingle)) {
        scopeFunction(protocol.address, R.exactOutputSingle, single(false), false, `Allow exactOutputSingle on ${protocol.name} between listed tokens, output to the Safe`);
        mapped = true;
      }
      if (!mapped) warnings.push(`${protocol.name}: no single-pool swap is allowed, so nothing is granted onchain.`);
      warnings.push(`${protocol.name}: multi-hop swaps, multicall and ETH swaps are not granted onchain.`);
      if (protocol.maxSlippageBps !== undefined) warnings.push(`${protocol.name}: maxSlippageBps can't be enforced onchain (Roles has no price data).`);
      continue;
    }
    if (protocol.selectors) {
      scopeTarget(protocol.address, protocol.name);
      for (const selector of protocol.selectors) allowFunction(protocol.address, selector, send, `Allow ${selector} on ${protocol.name} with any arguments`);
    } else {
      call(`Allow any call to ${protocol.name} (${protocol.address})`, encode(ROLES_SELECTORS.allowTarget, [T.bytes32, T.address, T.uint8], [roleKey, protocol.address, BigInt(send ? EXECUTION.Send : EXECUTION.None)]));
    }
    if (send) warnings.push(`${protocol.name}: ETH value per call is not capped onchain.`);
    warnings.push(`${protocol.name}: call arguments are not checked onchain.`);
  }

  for (const member of options.members ?? []) {
    call(`Give ${member} the role`, encode(ROLES_SELECTORS.assignRoles, [T.address, T.array(T.bytes32), T.array(T.bool)], [member.toLowerCase(), [roleKey], [true]]));
  }

  const thresholds = [policy.native.requireApprovalAbove, ...policy.tokens.map((t) => t.requireApprovalAbove)].some((v) => v !== undefined);
  if (thresholds) warnings.push('Review thresholds (requireApprovalAbove) have no onchain equivalent; amounts up to the per-transaction cap pass onchain.');
  if (policy.denylist.length && !recipients) warnings.push('The denylist is not enforced onchain; set recipients.allow to restrict recipients.');
  if ([policy.native, ...policy.tokens].some((r) => r.perRecipient)) warnings.push('Per-recipient windows are not enforced onchain.');
  if (policy.session.maxDurationSeconds !== undefined || policy.session.maxTransactions !== undefined) warnings.push('Session duration and transaction-count limits are not enforced onchain.');
  if (policy.nfts.length) warnings.push('NFT rules are not mapped; NFT transfers are denied onchain.');

  return { roleKey, calls, allowances, warnings };
}

/** Calldata for the agent's `execTransactionWithRole` call on the Roles modifier. */
export function execTransactionWithRole(call: { to: string; value?: bigint; data?: string }, role: string, shouldRevert = true): string {
  return encode(
    ROLES_SELECTORS.execTransactionWithRole,
    [T.address, T.uint256, T.bytes, T.uint8, T.bytes32, T.bool],
    [call.to.toLowerCase(), call.value ?? 0n, call.data ?? '0x', 0n, encodeRoleKey(role), shouldRevert],
  );
}

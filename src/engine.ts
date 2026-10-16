// Deterministic policy and risk engine.
//
// Pure function of (request, policy, session usage, time, optional simulation
// outcome). No I/O, no randomness: identical inputs always yield identical findings
// and verdicts. Policy outcomes decide the verdict; the risk score only ranks
// severity for reviewers and never relaxes a policy outcome.

import { UNLIMITED_APPROVAL_THRESHOLD, decodeRequest, isDecodedRouterSelector, type Action, type DecodeResult, type SwapAction } from './decoder.js';
import { describeAction, formatDuration, formatNative, formatTokenAmount, joinSentences, label } from './explain.js';
import type { CompiledPolicy } from './policy.js';
import type { Mode, NormalizedRequest } from './schemas.js';

export type VerdictStatus = 'allowed' | 'blocked' | 'requiresApproval';
export type Outcome = 'block' | 'requireApproval' | 'info';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type RiskLevel = Severity;

export interface Finding {
  readonly code: string;
  readonly outcome: Outcome;
  readonly severity: Severity;
  readonly message: string;
  /** What the agent/operator can change to make the request acceptable. */
  readonly remediation?: string;
  /** Call path, e.g. "0" or "1.2" for the third call inside the second call's batch. */
  readonly path?: string;
}

export interface Spend {
  native: bigint;
  /** Listed-token base units keyed by lowercase token address. */
  tokens: Record<string, bigint>;
}

/** An outgoing transfer to one recipient, tracked for rolling per-recipient windows. */
export interface Flow {
  /** "native" or a listed token address. */
  readonly asset: string;
  readonly to: string;
  readonly amount: bigint;
  /** Epoch milliseconds when the spend was reserved. */
  readonly at: number;
  /** Reserved through a human approval; excluded from window review thresholds. */
  readonly approved?: boolean;
}

export interface SessionView {
  readonly createdAt: number;
  readonly txCount: number;
  /** Committed plus pending (reserved) spend. */
  readonly spent: Spend;
  /** Recent committed and pending transfers, for per-recipient windows. */
  readonly recentFlows?: readonly Flow[];
}

export type SimulationOutcome =
  | { readonly status: 'ok' }
  | { readonly status: 'reverted'; readonly reason: string }
  | { readonly status: 'unavailable'; readonly reason: string };

/** Live quote for a swap: expected output (exact input) or required input (exact output). */
export type QuoteOutcome =
  | { readonly status: 'ok'; readonly amount: bigint }
  | { readonly status: 'unavailable'; readonly reason: string };

export interface EngineInput {
  readonly request: NormalizedRequest;
  readonly policy: CompiledPolicy;
  readonly session: SessionView;
  /** Unix epoch milliseconds. */
  readonly now: number;
  readonly simulation?: SimulationOutcome;
  /** Quotes aligned with the decoded swap actions, in order; null where none was requested. */
  readonly quotes?: readonly (QuoteOutcome | null)[];
  /** Pre-check before quotes are fetched: skip quote-dependent findings. */
  readonly deferQuotes?: boolean;
}

export interface EngineResult {
  readonly verdict: VerdictStatus;
  readonly findings: Finding[];
  readonly decoded: DecodeResult;
  /** Spend this request adds to the session if it executes. */
  readonly spend: Spend;
  /** Transfers this request adds to per-recipient windows if it executes. */
  readonly flows: Flow[];
  readonly riskScore: number;
  readonly riskLevel: RiskLevel;
  readonly summary: string;
  readonly explanation: string[];
}

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const SEVERITY_WEIGHT: Record<Severity, number> = { low: 10, medium: 30, high: 60, critical: 90 };

export function emptySpend(): Spend {
  return { native: 0n, tokens: {} };
}

class Findings {
  readonly list: Finding[] = [];
  private readonly seen = new Set<string>();

  add(f: Finding): void {
    const key = `${f.code}|${f.path ?? ''}|${f.message}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    this.list.push(f);
  }

  /** Add a finding whose outcome is configured by a policy mode. */
  mode(mode: Mode, f: Omit<Finding, 'outcome'>): void {
    this.add({ ...f, outcome: mode });
  }
}

function addressesOf(action: Action): string[] {
  switch (action.type) {
    case 'native_transfer':
      return [action.to];
    case 'token_transfer':
      return [action.token, action.from, action.to];
    case 'token_approval':
      return [action.token, action.owner, action.spender];
    case 'token_allowance_decrease':
      return [action.token];
    case 'nft_transfer':
      return [action.collection, action.from, action.to];
    case 'nft_approval':
      return [action.collection, action.spender];
    case 'operator_approval':
      return [action.collection, action.operator];
    case 'swap':
      return [action.router, action.recipient, ...action.pools.flatMap((x) => [x.tokenIn, x.tokenOut])];
    case 'router_withdrawal':
      return action.token ? [action.router, action.token, action.recipient] : [action.router, action.recipient];
    case 'contract_call':
      return [action.target];
    case 'contract_deployment':
    case 'wallet_self_call':
      return [];
  }
}

function checkRecipient(to: string, path: string, wallet: string, p: CompiledPolicy, f: Findings): void {
  if (to === ZERO_ADDRESS) {
    f.add({
      code: 'BURN_ADDRESS_RECIPIENT', outcome: 'requireApproval', severity: 'high', path,
      message: 'Assets would be sent to the zero address and permanently destroyed',
      remediation: 'Confirm the burn is intended or correct the recipient address',
    });
    return;
  }
  const allow = p.recipientAllowlist;
  if (allow && to !== wallet && !allow.has(to) && !p.protocols.has(to)) {
    f.mode(p.policy.recipients.notAllowlisted, {
      code: 'RECIPIENT_NOT_ALLOWLISTED', severity: 'high', path,
      message: `Recipient ${to} is not on the recipient allowlist`,
      remediation: 'Send to an allowlisted recipient or add this address to recipients.allow after verification',
    });
  }
}

function unlisted(p: CompiledPolicy, f: Findings, path: string, contract: string, what: string): void {
  f.mode(p.policy.unlistedAssets, {
    code: 'UNLISTED_ASSET', severity: 'high', path,
    message: `${what} involves ${contract}, which is not a configured token or collection`,
    remediation: 'Add the contract to policy.tokens/nfts with explicit limits after verifying it',
  });
}

function checkSwap(
  a: SwapAction, all: readonly Action[], wallet: string, p: CompiledPolicy, f: Findings, quote: QuoteOutcome | null | undefined, deferQuotes: boolean,
): void {
  const { path } = a;
  const fmt = (token: string, v: bigint) => formatTokenAmount(p, token, v);
  if (a.recipient === a.router) {
    // Output parked in the router is fine only if the same multicall withdraws it to the wallet.
    const call = path.split('/')[0];
    const withdrawn = all.some((w) => w.type === 'router_withdrawal' && w.path.split('/')[0] === call && w.recipient === wallet && (w.token === null || w.token === a.tokenOut));
    if (!withdrawn) {
      f.add({
        code: 'SWAP_RECIPIENT_NOT_WALLET', outcome: 'block', severity: 'critical', path,
        message: `Swap output stays in the router and is not withdrawn to the agent wallet in the same multicall`,
        remediation: 'Set the swap recipient to the agent wallet',
      });
    }
  } else if (a.recipient !== wallet) {
    f.add({
      code: 'SWAP_RECIPIENT_NOT_WALLET', outcome: 'block', severity: 'critical', path,
      message: `Swap output would go to ${a.recipient}, not the agent wallet`,
      remediation: 'Set the swap recipient to the agent wallet',
    });
  }
  for (const token of new Set([a.tokenIn, a.tokenOut])) if (!p.tokens.has(token)) unlisted(p, f, path, token, 'Swap');

  const unprotected = a.exact === 'input' ? a.amountOut === 0n : a.amountIn >= UNLIMITED_APPROVAL_THRESHOLD;
  if (unprotected) {
    f.mode(p.policy.swaps.missingSlippageProtection, {
      code: 'SWAP_NO_SLIPPAGE_PROTECTION', severity: 'high', path,
      message: a.exact === 'input'
        ? `Swap accepts any output (amountOutMinimum is 0), so it can be sandwiched for up to its full ${fmt(a.tokenIn, a.amountIn)}`
        : 'Swap accepts any input amount (amountInMaximum is unbounded), so it can be sandwiched',
      remediation: a.exact === 'input' ? 'Set amountOutMinimum from a fresh quote minus your slippage tolerance' : 'Set amountInMaximum from a fresh quote plus your slippage tolerance',
    });
  }

  const bps = p.protocols.get(a.router)?.maxSlippageBps;
  if (bps === undefined || unprotected || deferQuotes) return;
  if (!quote || quote.status !== 'ok') {
    f.mode(p.policy.swaps.quoteUnavailable, {
      code: 'SWAP_QUOTE_UNAVAILABLE', severity: 'medium', path,
      message: `Slippage could not be checked: ${quote?.reason ?? 'no quoter is configured'}`,
    });
    return;
  }
  const pct = (n: bigint, d: bigint) => (d === 0n ? '100' : (Number((n * 10_000n) / d) / 100).toFixed(2));
  if (a.exact === 'input' && a.amountOut * 10_000n < quote.amount * BigInt(10_000 - bps)) {
    f.add({
      code: 'SWAP_SLIPPAGE_TOO_HIGH', outcome: 'block', severity: 'high', path,
      message: `Swap accepts as little as ${fmt(a.tokenOut, a.amountOut)}, ${pct(quote.amount - a.amountOut, quote.amount)}% below the current quote of ${fmt(a.tokenOut, quote.amount)}; the limit is ${bps / 100}%`,
      remediation: `Set amountOutMinimum to at least ${fmt(a.tokenOut, (quote.amount * BigInt(10_000 - bps) + 9_999n) / 10_000n)}`,
    });
  } else if (a.exact === 'output' && a.amountIn * 10_000n > quote.amount * BigInt(10_000 + bps)) {
    f.add({
      code: 'SWAP_SLIPPAGE_TOO_HIGH', outcome: 'block', severity: 'high', path,
      message: `Swap would pay up to ${fmt(a.tokenIn, a.amountIn)}, ${pct(a.amountIn - quote.amount, quote.amount)}% above the current quote of ${fmt(a.tokenIn, quote.amount)}; the limit is ${bps / 100}%`,
      remediation: `Set amountInMaximum to at most ${fmt(a.tokenIn, (quote.amount * BigInt(10_000 + bps)) / 10_000n)}`,
    });
  }
}

function checkAction(a: Action, wallet: string, p: CompiledPolicy, f: Findings, spend: Spend): void {
  const { path } = a;
  const budget = (token: string, amount: bigint) => {
    if (p.tokens.has(token)) spend.tokens[token] = (spend.tokens[token] ?? 0n) + amount;
  };
  switch (a.type) {
    case 'native_transfer':
      checkRecipient(a.to, path, wallet, p, f);
      return;

    case 'token_transfer':
      if (!p.tokens.has(a.token)) unlisted(p, f, path, a.token, 'Token transfer');
      budget(a.token, a.amount);
      if (a.from !== wallet) {
        f.add({
          code: 'THIRD_PARTY_SOURCE', outcome: 'info', severity: 'medium', path,
          message: `Funds are pulled from ${a.from}, not the agent wallet; the amount still counts against session limits`,
        });
      }
      checkRecipient(a.to, path, wallet, p, f);
      return;

    case 'token_approval': {
      if (a.amount === 0n) {
        f.add({ code: 'ALLOWANCE_REVOKED', outcome: 'info', severity: 'low', path, message: `Allowance for ${a.spender} is revoked` });
        return;
      }
      const rule = p.tokens.get(a.token);
      if (a.unlimited) {
        f.add({
          code: 'UNLIMITED_APPROVAL', outcome: 'block', severity: 'critical', path,
          message: `Unlimited allowance for ${label(p, a.token)} to ${a.spender}: the spender could drain the full balance at any time`,
          remediation: 'Approve only the exact amount the next operation needs',
        });
      } else {
        budget(a.token, a.amount);
        if (rule) {
          const max = rule.maxApproval ?? rule.perTransactionMax;
          if (a.amount > max) {
            f.add({
              code: 'APPROVAL_EXCEEDS_MAX', outcome: 'block', severity: 'high', path,
              message: `Allowance of ${formatTokenAmount(p, a.token, a.amount)} exceeds the ${formatTokenAmount(p, a.token, max)} maximum`,
              remediation: 'Approve a smaller, exact amount',
            });
          }
        }
      }
      if (!rule) unlisted(p, f, path, a.token, 'Token approval');
      if (!p.trustedSpenders.has(a.spender)) {
        f.mode(p.policy.approvals.unknownSpender, {
          code: 'UNTRUSTED_SPENDER', severity: 'high', path,
          message: `Spender ${a.spender} is not a trusted spender or allowlisted protocol`,
          remediation: 'Approve only allowlisted protocol contracts, or add the verified spender to approvals.spenders',
        });
      }
      if (a.owner !== wallet) {
        f.add({ code: 'THIRD_PARTY_OWNER', outcome: 'info', severity: 'medium', path, message: `Approval is granted on behalf of ${a.owner}` });
      }
      return;
    }

    case 'token_allowance_decrease':
      f.add({ code: 'ALLOWANCE_DECREASED', outcome: 'info', severity: 'low', path, message: `Allowance for ${a.spender} is reduced` });
      return;

    case 'nft_transfer': {
      const rule = p.nfts.get(a.collection);
      if (!rule) {
        unlisted(p, f, path, a.collection, 'NFT transfer');
      } else if (!rule.allowTransfers) {
        f.add({
          code: 'NFT_TRANSFER_NOT_PREAPPROVED', outcome: 'requireApproval', severity: 'medium', path,
          message: `Transfers out of ${rule.name} are not pre-approved`,
          remediation: 'Set allowTransfers for this collection if agents may move it without review',
        });
      }
      checkRecipient(a.to, path, wallet, p, f);
      return;
    }

    case 'nft_approval':
      if (a.spender === ZERO_ADDRESS) return;
      if (!p.nfts.has(a.collection)) unlisted(p, f, path, a.collection, 'NFT approval');
      if (!p.trustedSpenders.has(a.spender)) {
        f.mode(p.policy.approvals.unknownSpender, {
          code: 'UNTRUSTED_SPENDER', severity: 'high', path,
          message: `${a.spender} would be approved to transfer NFT #${a.tokenId} but is not a trusted spender`,
          remediation: 'Approve only trusted marketplace/protocol contracts',
        });
      }
      return;

    case 'operator_approval':
      if (!a.approved) {
        f.add({ code: 'OPERATOR_REVOKED', outcome: 'info', severity: 'low', path, message: `Operator ${a.operator} is revoked` });
      } else if (!p.trustedSpenders.has(a.operator)) {
        f.mode(p.policy.approvals.operatorApprovals, {
          code: 'OPERATOR_APPROVAL', severity: 'critical', path,
          message: `setApprovalForAll would give ${a.operator} control over every token in ${a.collection}`,
          remediation: 'Use single-token approvals or add the verified operator to approvals.spenders',
        });
      }
      return;

    case 'swap':
      return; // Checked by checkSwap, which needs the whole action list and quotes.

    case 'router_withdrawal':
      if (a.recipient !== wallet) {
        f.add({
          code: 'SWAP_RECIPIENT_NOT_WALLET', outcome: 'block', severity: 'critical', path,
          message: `Router would send ${a.token ? label(p, a.token) : 'unwrapped ETH'} to ${a.recipient}, not the agent wallet`,
          remediation: 'Withdraw swap output only to the agent wallet',
        });
      }
      if (a.token && !p.tokens.has(a.token)) unlisted(p, f, path, a.token, 'Router withdrawal');
      return;

    case 'contract_call': {
      const fn = a.selector ? `function ${a.selector}` : 'the fallback function';
      const token = p.tokens.get(a.target);
      const protocol = p.protocols.get(a.target);
      if (token) {
        if (!a.selector || !token.allowedFunctions.includes(a.selector)) {
          f.mode(p.policy.unknownContractCalls, {
            code: 'UNRECOGNIZED_TOKEN_FUNCTION', severity: 'high', path,
            message: `Unrecognized ${fn} on token ${token.symbol}; its asset effect cannot be verified`,
            remediation: 'Use transfer/approve, or add the selector to the token rule allowedFunctions',
          });
        }
      } else if (protocol) {
        if (protocol.selectors && (!a.selector || !protocol.selectors.includes(a.selector))) {
          f.mode(p.policy.unknownContractCalls, {
            code: 'PROTOCOL_FUNCTION_NOT_ALLOWED', severity: 'high', path,
            message: `${fn} is not an allowed function on ${protocol.name}`,
            remediation: 'Add the selector to the protocol rule after reviewing what it does',
          });
        }
        if (protocol.kind === 'uniswap-v3-router' && !isDecodedRouterSelector(a.selector)) {
          f.mode(p.policy.unknownContractCalls, {
            code: 'PROTOCOL_FUNCTION_NOT_DECODED', severity: 'high', path,
            message: `${fn} on ${protocol.name} is not a function the firewall can decode, so its recipient can't be checked`,
            remediation: 'Use exactInput/exactOutput swaps, multicall, unwrapWETH9, sweepToken or refundETH',
          });
        }
        if (protocol.maxNativeValue !== undefined && a.value > protocol.maxNativeValue) {
          f.add({
            code: 'PROTOCOL_VALUE_EXCEEDED', outcome: 'block', severity: 'high', path,
            message: `${formatNative(p, a.value)} exceeds the ${formatNative(p, protocol.maxNativeValue)} per-call limit for ${protocol.name}`,
            remediation: 'Send a smaller value',
          });
        }
      } else if (p.nfts.has(a.target)) {
        f.mode(p.policy.unknownContractCalls, {
          code: 'UNRECOGNIZED_TOKEN_FUNCTION', severity: 'high', path,
          message: `Unrecognized ${fn} on collection ${a.target}`,
          remediation: 'Use standard transfer/approval functions',
        });
      } else {
        f.mode(p.policy.unknownContractCalls, {
          code: 'UNKNOWN_CONTRACT_CALL', severity: 'high', path,
          message: `Call to ${fn} on ${a.target}, which is not an allowlisted protocol`,
          remediation: 'Add the verified contract to policy.protocols, ideally with a selector allowlist',
        });
      }
      return;
    }

    case 'contract_deployment':
      f.mode(p.policy.contractDeployment, {
        code: 'CONTRACT_DEPLOYMENT', severity: 'critical', path,
        message: 'The request deploys a new contract whose behavior cannot be verified before execution',
        remediation: 'Deploy contracts through a reviewed release process, not an autonomous agent',
      });
      return;

    case 'wallet_self_call':
      f.add({
        code: 'WALLET_SELF_CALL', outcome: 'block', severity: 'critical', path,
        message: `Call to ${a.selector ?? 'the fallback'} on the agent wallet itself could change owners, modules or session keys`,
        remediation: 'Perform wallet administration outside the agent, with owner authorization',
      });
      return;
  }
}

function checkLimits(input: EngineInput, spend: Spend, f: Findings): void {
  const { policy: p, session } = input;
  const native = p.policy.native;
  const nativeSpent = session.spent.native;
  if (spend.native > native.perTransactionMax) {
    f.add({
      code: 'NATIVE_PER_TX_LIMIT', outcome: 'block', severity: 'high',
      message: `Request sends ${formatNative(p, spend.native)}; per-transaction limit is ${formatNative(p, native.perTransactionMax)}`,
      remediation: 'Reduce the amount',
    });
  }
  if (nativeSpent + spend.native > native.sessionMax) {
    f.add({
      code: 'NATIVE_SESSION_LIMIT', outcome: 'block', severity: 'high',
      message: `Session would reach ${formatNative(p, nativeSpent + spend.native)}; session limit is ${formatNative(p, native.sessionMax)} (${formatNative(p, nativeSpent)} already used or reserved)`,
      remediation: 'Wait for a new session or raise the session limit through policy review',
    });
  }
  if (native.requireApprovalAbove !== undefined && spend.native > native.requireApprovalAbove) {
    f.add({
      code: 'NATIVE_APPROVAL_THRESHOLD', outcome: 'requireApproval', severity: 'medium',
      message: `${formatNative(p, spend.native)} is above the ${formatNative(p, native.requireApprovalAbove)} review threshold`,
    });
  }

  for (const [token, amount] of Object.entries(spend.tokens)) {
    const rule = p.tokens.get(token);
    if (!rule) continue;
    const spent = session.spent.tokens[token] ?? 0n;
    const fmt = (v: bigint) => formatTokenAmount(p, token, v);
    if (amount > rule.perTransactionMax) {
      f.add({
        code: 'TOKEN_PER_TX_LIMIT', outcome: 'block', severity: 'high',
        message: `Request moves or approves ${fmt(amount)}; per-transaction limit is ${fmt(rule.perTransactionMax)}`,
        remediation: 'Reduce the amount (batched calls are summed)',
      });
    }
    if (spent + amount > rule.sessionMax) {
      f.add({
        code: 'TOKEN_SESSION_LIMIT', outcome: 'block', severity: 'high',
        message: `Session would reach ${fmt(spent + amount)}; session limit is ${fmt(rule.sessionMax)} (${fmt(spent)} already used or reserved)`,
        remediation: 'Wait for a new session or raise the session limit through policy review',
      });
    }
    if (rule.requireApprovalAbove !== undefined && amount > rule.requireApprovalAbove) {
      f.add({
        code: 'TOKEN_APPROVAL_THRESHOLD', outcome: 'requireApproval', severity: 'medium',
        message: `${fmt(amount)} is above the ${fmt(rule.requireApprovalAbove)} review threshold`,
      });
    }
  }

  const { maxDurationSeconds, maxTransactions } = p.policy.session;
  if (maxDurationSeconds !== undefined && input.now > session.createdAt + maxDurationSeconds * 1000) {
    f.add({
      code: 'SESSION_EXPIRED', outcome: 'block', severity: 'high',
      message: `Session expired after ${maxDurationSeconds} seconds`,
      remediation: 'Start a new session',
    });
  }
  if (maxTransactions !== undefined && session.txCount >= maxTransactions) {
    f.add({
      code: 'SESSION_TX_LIMIT', outcome: 'block', severity: 'high',
      message: `Session already used its ${maxTransactions}-transaction limit`,
      remediation: 'Start a new session',
    });
  }
}

function flowsOf(actions: readonly Action[], wallet: string, p: CompiledPolicy, now: number): Flow[] {
  const flows: Flow[] = [];
  for (const a of actions) {
    if (a.type === 'native_transfer' && a.to !== wallet) flows.push({ asset: 'native', to: a.to, amount: a.amount, at: now });
    if (a.type === 'token_transfer' && a.to !== wallet && p.tokens.has(a.token)) flows.push({ asset: a.token, to: a.to, amount: a.amount, at: now });
  }
  return flows;
}

function checkRecipientWindows(input: EngineInput, flows: readonly Flow[], f: Findings): void {
  const { policy: p, now } = input;
  const totals = new Map<string, Flow>();
  for (const fl of flows) {
    const key = `${fl.asset}|${fl.to}`;
    const prior = totals.get(key);
    totals.set(key, prior ? { ...prior, amount: prior.amount + fl.amount } : fl);
  }
  for (const { asset, to, amount } of totals.values()) {
    const rule = asset === 'native' ? p.policy.native : p.tokens.get(asset);
    const w = rule?.perRecipient;
    if (!rule || !w) continue;
    const since = now - w.windowSeconds * 1000;
    let all = 0n;
    let unreviewed = 0n;
    for (const r of input.session.recentFlows ?? []) {
      if (r.asset !== asset || r.to !== to || r.at <= since) continue;
      all += r.amount;
      if (!r.approved) unreviewed += r.amount;
    }
    const fmt = (v: bigint) => (asset === 'native' ? formatNative(p, v) : formatTokenAmount(p, asset, v));
    const period = formatDuration(w.windowSeconds);
    if (w.max !== undefined && all + amount > w.max) {
      f.add({
        code: 'RECIPIENT_WINDOW_LIMIT', outcome: 'block', severity: 'high',
        message: `${to} would receive ${fmt(all + amount)} within ${period}; the per-recipient limit is ${fmt(w.max)} (${fmt(all)} already sent or reserved)`,
        remediation: `Wait until earlier payments to this recipient are older than ${period}`,
      });
    }
    const threshold = w.requireApprovalAbove ?? rule.requireApprovalAbove;
    if (threshold !== undefined && unreviewed > 0n && unreviewed + amount > threshold) {
      f.add({
        code: 'RECIPIENT_WINDOW_THRESHOLD', outcome: 'requireApproval', severity: 'medium',
        message: `${to} would receive ${fmt(unreviewed + amount)} without review within ${period}, above the ${fmt(threshold)} review threshold (payments to one recipient are summed)`,
      });
    }
  }
}

export function riskScore(findings: readonly Finding[]): { score: number; level: RiskLevel } {
  const weights = findings.map((x) => SEVERITY_WEIGHT[x.severity]).sort((a, b) => b - a);
  // Highest finding dominates; each further finding adds a geometrically shrinking bonus.
  const raw = weights.reduce((sum, w, i) => sum + (i === 0 ? w : w * 0.4 ** i), 0);
  const score = Math.min(100, Math.round(raw));
  const level: RiskLevel = score >= 80 ? 'critical' : score >= 55 ? 'high' : score >= 25 ? 'medium' : 'low';
  return { score, level };
}

export function verdictOf(findings: readonly Finding[]): VerdictStatus {
  if (findings.some((x) => x.outcome === 'block')) return 'blocked';
  if (findings.some((x) => x.outcome === 'requireApproval')) return 'requiresApproval';
  return 'allowed';
}

export function summarize(verdict: VerdictStatus, explanation: readonly string[], findings: readonly Finding[]): string {
  const intent = explanation.length
    ? `The agent wants to ${joinSentences(explanation.map((e) => e.charAt(0).toLowerCase() + e.slice(1)))}.`
    : 'The request performs no asset-moving action.';
  if (verdict === 'allowed') return `ALLOWED — ${intent} Within policy.`;
  const outcome = verdict === 'blocked' ? 'block' : 'requireApproval';
  const reasons = findings.filter((x) => x.outcome === outcome).map((x) => x.message);
  return verdict === 'blocked'
    ? `BLOCKED — ${intent} Blocked because: ${joinSentences(reasons)}.`
    : `NEEDS HUMAN APPROVAL — ${intent} Review required because: ${joinSentences(reasons)}.`;
}

export function evaluatePolicy(input: EngineInput): EngineResult {
  const { request, policy: p } = input;
  const f = new Findings();
  const wallet = request.from;

  if (!p.chainIds.has(request.chainId)) {
    f.add({
      code: 'CHAIN_NOT_ALLOWED', outcome: 'block', severity: 'critical',
      message: `Chain ${request.chainId} is not permitted by this policy`,
      remediation: `Use one of: ${[...p.chainIds].join(', ')}`,
    });
  }

  const decoded = decodeRequest(request, p);
  for (const issue of decoded.issues) {
    f.add({
      code: issue.code, outcome: 'block', severity: 'critical', path: issue.path, message: issue.message,
      remediation: 'Submit standard, canonically ABI-encoded calldata',
    });
  }

  const spend = emptySpend();
  for (const call of decoded.calls) spend.native += call.value;

  const denied = new Set<string>();
  for (const call of decoded.calls) if (call.to && p.denylist.has(call.to)) denied.add(call.to);
  let swapIndex = 0;
  for (const a of decoded.actions) {
    for (const addr of addressesOf(a)) if (p.denylist.has(addr)) denied.add(addr);
    if (a.type === 'swap') checkSwap(a, decoded.actions, wallet, p, f, input.quotes?.[swapIndex++], input.deferQuotes === true);
    else checkAction(a, wallet, p, f, spend);
  }
  for (const addr of denied) {
    f.add({
      code: 'DENYLISTED_ADDRESS', outcome: 'block', severity: 'critical',
      message: `${addr} is on the denylist`,
      remediation: 'Do not interact with this address',
    });
  }

  checkLimits(input, spend, f);
  const flows = flowsOf(decoded.actions, wallet, p, input.now);
  checkRecipientWindows(input, flows, f);

  if (input.simulation?.status === 'reverted') {
    f.add({
      code: 'SIMULATION_REVERTED', outcome: 'block', severity: 'critical',
      message: `Simulation reverted: ${input.simulation.reason}`,
      remediation: 'Fix the call so it succeeds against current chain state',
    });
  } else if (input.simulation?.status === 'unavailable') {
    f.mode(p.policy.simulation.onUnavailable, {
      code: 'SIMULATION_UNAVAILABLE', severity: 'medium',
      message: `Simulation unavailable: ${input.simulation.reason}`,
    });
  }

  const findings = f.list;
  const verdict = verdictOf(findings);
  const { score, level } = riskScore(findings);
  const explanation = decoded.actions.map((a) => describeAction(a, p, wallet));
  return {
    verdict,
    findings,
    decoded,
    spend,
    flows,
    riskScore: score,
    riskLevel: level,
    summary: summarize(verdict, explanation, findings),
    explanation,
  };
}

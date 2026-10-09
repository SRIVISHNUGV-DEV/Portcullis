// Firewall orchestration: validation → deterministic evaluation → optional
// simulation → atomic reservation → audit. Every failure path yields a `blocked`
// verdict; nothing throws out of evaluate().

import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { AuditLog, MemoryAuditSink, type AuditEventType, type AuditSink } from './audit.js';
import { deepFreeze, digest, toJsonSafe } from './canonical.js';
import {
  evaluatePolicy,
  riskScore,
  summarize,
  type EngineResult,
  type Finding,
  type QuoteOutcome,
  type RiskLevel,
  type SimulationOutcome,
  type VerdictStatus,
} from './engine.js';
import { compilePolicy, type CompiledPolicy } from './policy.js';
import { TransactionRequestSchema, type NormalizedRequest, type PolicyInput } from './schemas.js';
import { MemorySessionStore, addSpend, recentFlows, totalSpent, type SessionState, type SessionStore } from './session.js';
import type { Quoter, Simulator } from './simulation.js';

export interface FirewallOptions {
  /** Policy definition (validated at construction; invalid policies throw) or a compiled policy. */
  readonly policy: PolicyInput | CompiledPolicy;
  /**
   * Audit destination. Defaults to an in-memory sink; use a durable sink in production.
   * Pass an AuditLog to share one hash chain between several firewalls.
   */
  readonly audit?: AuditSink | AuditLog;
  /** Session usage store. Defaults to in-process memory (single instance only). */
  readonly sessions?: SessionStore;
  readonly simulator?: Simulator;
  /** Live swap quotes, used for protocols with `maxSlippageBps`. */
  readonly quoter?: Quoter;
  /** Epoch milliseconds. Injectable for deterministic tests. */
  readonly clock?: () => number;
  readonly generateId?: () => string;
}

export interface EvaluateOptions {
  /** Budget scope, e.g. one agent run. Defaults to "default". */
  readonly sessionId?: string;
}

export interface Approval {
  /** Identity of the human approver (user ID or email); recorded in the audit log. */
  readonly approver: string;
  readonly note?: string;
}

export interface Verdict {
  readonly requestId: string;
  readonly verdict: VerdictStatus;
  /** True only when the transaction may be sent now. */
  readonly allowed: boolean;
  readonly sessionId: string;
  readonly chainId: number | null;
  /** SHA-256 of the normalized request; approvals are bound to it. */
  readonly txDigest: string | null;
  readonly policyHash: string;
  readonly riskScore: number;
  readonly riskLevel: RiskLevel;
  readonly reasons: readonly Finding[];
  /** Decoded actions; amounts are decimal strings in base units. */
  readonly actions: readonly Record<string, unknown>[];
  readonly summary: string;
  readonly explanation: readonly string[];
  /** Spend this request reserves against the session (base-unit strings). */
  readonly spend: { readonly native: string; readonly tokens: Readonly<Record<string, string>> };
  readonly evaluatedAt: string;
  readonly durationMs: number;
  readonly reservationId?: string;
  readonly approvalExpiresAt?: string;
  readonly approval?: { readonly approver: string; readonly approvedAt: string; readonly note?: string };
  /** Hash of the audit record for this decision; null if auditing failed. */
  readonly auditHash: string | null;
}

export class FirewallStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FirewallStateError';
  }
}

class AuditUnavailableError extends Error {}

const SESSION_ID_RE = /^[\w.:@-]{1,128}$/;

function isCompiled(p: PolicyInput | CompiledPolicy): p is CompiledPolicy {
  return typeof (p as CompiledPolicy).hash === 'string' && (p as CompiledPolicy).tokens instanceof Map;
}

export class Firewall {
  readonly policy: CompiledPolicy;
  private readonly audit: AuditLog;
  private readonly sessions: SessionStore;
  private readonly simulator: Simulator | undefined;
  private readonly quoter: Quoter | undefined;
  /** Longest per-recipient window; committed transfers older than this are dropped. */
  private readonly maxWindowMs: number;
  private readonly clock: () => number;
  private readonly generateId: () => string;

  constructor(options: FirewallOptions) {
    this.policy = isCompiled(options.policy) ? options.policy : compilePolicy(options.policy);
    this.clock = options.clock ?? Date.now;
    this.audit = options.audit instanceof AuditLog ? options.audit : new AuditLog(options.audit ?? new MemoryAuditSink(), this.clock);
    this.sessions = options.sessions ?? new MemorySessionStore();
    this.simulator = options.simulator;
    this.quoter = options.quoter;
    const windows = [this.policy.policy.native, ...this.policy.policy.tokens].map((r) => r.perRecipient?.windowSeconds ?? 0);
    this.maxWindowMs = Math.max(0, ...windows) * 1000;
    this.generateId = options.generateId ?? randomUUID;
  }

  get policyHash(): string {
    return this.policy.hash;
  }

  /** Evaluate a transaction (or batch) before it reaches the wallet. Never throws. */
  async evaluate(tx: unknown, options: EvaluateOptions = {}): Promise<Verdict> {
    const started = performance.now();
    const requestId = this.generateId();
    const sessionId = options.sessionId ?? 'default';
    const now = this.clock();

    if (!SESSION_ID_RE.test(sessionId)) {
      return this.failure(requestId, 'default', started, now, 'INVALID_SESSION_ID', 'Session ID must be 1-128 characters of [A-Za-z0-9_.:@-]', null, null);
    }
    const parsed = TransactionRequestSchema.safeParse(tx);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i) => `${i.path.join('.') || 'request'}: ${i.message}`).join('; ');
      return this.failure(requestId, sessionId, started, now, 'INVALID_REQUEST', `Invalid transaction request — ${issues}`, null, null, true);
    }
    const request = parsed.data;
    const txDigest = digest(request);

    try {
      let simulation: SimulationOutcome | undefined;
      let quotes: (QuoteOutcome | null)[] | undefined;
      if (this.simulator || this.quoter) {
        // Read-only pre-check: skip simulation and quotes for requests that are blocked regardless.
        const pre = await this.sessions.transact(sessionId, now, (state) => this.run(request, state, now, undefined, undefined, true));
        if (pre.verdict === 'blocked') {
          return await this.finalizeUnreserved(requestId, sessionId, request, txDigest, pre, started, now);
        }
        [simulation, quotes] = await Promise.all([
          this.simulator ? this.simulate(request) : undefined,
          this.quoter ? this.quote(pre) : undefined,
        ]);
      }
      const outcome = await this.sessions.transact(sessionId, now, async (state) => {
        const result = this.run(request, state, now, simulation, quotes);
        let reservationId: string | undefined;
        let approvalExpiresAt: number | undefined;
        if (result.verdict === 'allowed') {
          reservationId = this.generateId();
          state.pending[reservationId] = { spend: result.spend, createdAt: now, requestId, ...(result.flows.length ? { flows: result.flows } : {}) };
          state.txCount += 1;
        } else if (result.verdict === 'requiresApproval') {
          approvalExpiresAt = now + this.policy.policy.approvalTtlSeconds * 1000;
          state.approvals[requestId] = {
            request, txDigest, expiresAt: approvalExpiresAt, ...(simulation ? { simulation } : {}), ...(quotes ? { quotes } : {}),
          };
        }
        for (const [id, a] of Object.entries(state.approvals)) if (a.expiresAt < now) delete state.approvals[id];
        const durationMs = performance.now() - started;
        const audit = await this.prepareRecord('evaluation', requestId, sessionId, {
          txDigest, request, result: auditSummary(result), reservationId, simulation, quotes, durationMs,
        });
        const verdict = this.verdict({
          requestId, sessionId, request, txDigest, result, now, durationMs, auditHash: audit.hash,
          ...(reservationId ? { reservationId } : {}),
          ...(approvalExpiresAt !== undefined ? { approvalExpiresAt } : {}),
        });
        return { verdict, persisted: audit.persisted, reservationId };
      });
      try {
        await outcome.persisted;
      } catch (e) {
        // The decision never reached the audit log: undo its reservation or pending approval.
        await this.sessions
          .transact(sessionId, now, (state) => {
            if (outcome.reservationId && state.pending[outcome.reservationId]) {
              delete state.pending[outcome.reservationId];
              state.txCount = Math.max(0, state.txCount - 1);
            }
            delete state.approvals[requestId];
          })
          .catch(() => undefined);
        throw e;
      }
      return deepFreeze({ ...outcome.verdict, durationMs: round(performance.now() - started) });
    } catch (e) {
      const audit = e instanceof AuditUnavailableError;
      return this.failure(
        requestId, sessionId, started, now,
        audit ? 'AUDIT_UNAVAILABLE' : 'EVALUATION_ERROR',
        audit
          ? 'The decision could not be written to the audit log, so the request is blocked'
          : `Evaluation failed (${e instanceof Error ? e.message : 'unknown error'}); failing closed`,
        request.chainId, txDigest, !audit,
      );
    }
  }

  /**
   * Approve a `requiresApproval` verdict. Re-checks the stored request against current
   * session usage (caps may have been consumed meanwhile) and reserves its spend.
   */
  async approve(pending: Verdict, approval: Approval): Promise<Verdict> {
    if (pending.verdict !== 'requiresApproval') throw new FirewallStateError(`Cannot approve a ${pending.verdict} verdict`);
    if (!approval.approver?.trim()) throw new FirewallStateError('An approver identity is required');
    const started = performance.now();
    const now = this.clock();
    return this.sessions.transact(pending.sessionId, now, async (state) => {
      const stored = state.approvals[pending.requestId];
      if (!stored) throw new FirewallStateError('No pending approval for this request (already decided or unknown)');
      delete state.approvals[pending.requestId];
      if (stored.expiresAt < now) throw new FirewallStateError('Approval window expired; evaluate the transaction again');
      if (stored.txDigest !== pending.txDigest) throw new FirewallStateError('Verdict does not match the evaluated transaction');

      const result = this.run(stored.request, state, now, stored.simulation, stored.quotes);
      let reservationId: string | undefined;
      if (result.verdict !== 'blocked') {
        reservationId = this.generateId();
        const flows = result.flows.map((fl) => ({ ...fl, approved: true }));
        state.pending[reservationId] = { spend: result.spend, createdAt: now, requestId: pending.requestId, ...(flows.length ? { flows } : {}) };
        state.txCount += 1;
      }
      const approvedAt = new Date(now).toISOString();
      const durationMs = performance.now() - started;
      const auditHash = await this.record('approval', pending.requestId, pending.sessionId, {
        txDigest: stored.txDigest, approver: approval.approver, note: approval.note,
        result: auditSummary(result), reservationId,
      });
      const base = this.verdict({
        requestId: pending.requestId, sessionId: pending.sessionId, request: stored.request,
        txDigest: stored.txDigest, result, now, durationMs, auditHash,
        ...(reservationId ? { reservationId } : {}),
      });
      if (!reservationId) return base;
      return deepFreeze({
        ...base,
        verdict: 'allowed' as const,
        allowed: true,
        summary: base.summary.replace(/^NEEDS HUMAN APPROVAL — /, `APPROVED by ${approval.approver} — `),
        approval: { approver: approval.approver, approvedAt, ...(approval.note ? { note: approval.note } : {}) },
      });
    });
  }

  /** Reject a `requiresApproval` verdict; the request can no longer be approved. */
  async reject(pending: Verdict, approval: Approval): Promise<void> {
    if (!approval.approver?.trim()) throw new FirewallStateError('An approver identity is required');
    await this.sessions.transact(pending.sessionId, this.clock(), async (state) => {
      if (!state.approvals[pending.requestId]) throw new FirewallStateError('No pending approval for this request');
      await this.record('rejection', pending.requestId, pending.sessionId, {
        txDigest: pending.txDigest, approver: approval.approver, note: approval.note,
      });
      delete state.approvals[pending.requestId];
    });
  }

  /** Mark an allowed request as executed; its reservation becomes committed spend. */
  async commit(allowed: Verdict, receipt: { readonly txHash?: string } = {}): Promise<void> {
    const reservationId = requireReservation(allowed);
    const { persisted } = await this.sessions.transact(allowed.sessionId, this.clock(), async (state) => {
      const r = state.pending[reservationId];
      if (!r) throw new FirewallStateError('Reservation not found (already committed or released)');
      const audit = await this.prepareRecord('commit', allowed.requestId, allowed.sessionId, { reservationId, txHash: receipt.txHash });
      delete state.pending[reservationId];
      state.committed = addSpend(state.committed, r.spend);
      if (r.flows || state.recentFlows?.length) {
        const since = this.clock() - this.maxWindowMs;
        state.recentFlows = [...(state.recentFlows ?? []), ...(r.flows ?? [])].filter((fl) => fl.at > since);
      }
      return { persisted: audit.persisted };
    });
    await persisted;
  }

  /** Release an allowed request that was not sent or failed before broadcast, returning its budget. */
  async release(allowed: Verdict, reason = 'not executed'): Promise<void> {
    const reservationId = requireReservation(allowed);
    await this.sessions.transact(allowed.sessionId, this.clock(), async (state) => {
      if (!state.pending[reservationId]) throw new FirewallStateError('Reservation not found (already committed or released)');
      await this.record('release', allowed.requestId, allowed.sessionId, { reservationId, reason });
      delete state.pending[reservationId];
      state.txCount = Math.max(0, state.txCount - 1);
    });
  }

  /** Current session usage (committed + reserved), as base-unit strings. */
  async usage(sessionId = 'default'): Promise<{ createdAt: string; txCount: number; spent: { native: string; tokens: Record<string, string> }; pendingApprovals: number }> {
    return this.sessions.transact(sessionId, this.clock(), (state) => ({
      createdAt: new Date(state.createdAt).toISOString(),
      txCount: state.txCount,
      spent: toJsonSafe(totalSpent(state)) as { native: string; tokens: Record<string, string> },
      pendingApprovals: Object.keys(state.approvals).length,
    }));
  }

  private run(
    request: NormalizedRequest, state: SessionState, now: number,
    simulation?: SimulationOutcome, quotes?: readonly (QuoteOutcome | null)[], deferQuotes = false,
  ): EngineResult {
    return evaluatePolicy({
      request, policy: this.policy, now,
      session: {
        createdAt: state.createdAt, txCount: state.txCount, spent: totalSpent(state),
        ...(this.maxWindowMs ? { recentFlows: recentFlows(state) } : {}),
      },
      ...(simulation ? { simulation } : {}),
      ...(quotes ? { quotes } : {}),
      ...(deferQuotes ? { deferQuotes } : {}),
    });
  }

  /** Quote every decoded swap on a protocol with `maxSlippageBps`, in parallel. */
  private async quote(pre: EngineResult): Promise<(QuoteOutcome | null)[] | undefined> {
    const swaps = pre.decoded.actions.filter((a) => a.type === 'swap');
    if (!swaps.some((s) => this.policy.protocols.get(s.router)?.maxSlippageBps !== undefined)) return undefined;
    return Promise.all(
      swaps.map(async (s): Promise<QuoteOutcome | null> => {
        if (this.policy.protocols.get(s.router)?.maxSlippageBps === undefined) return null;
        const controller = new AbortController();
        try {
          return await this.quoter!(s, controller.signal);
        } catch (e) {
          controller.abort();
          return { status: 'unavailable', reason: e instanceof Error ? e.message.slice(0, 200) : 'quoter failed' };
        }
      }),
    );
  }

  private async simulate(request: NormalizedRequest): Promise<SimulationOutcome> {
    const controller = new AbortController();
    try {
      return await this.simulator!(request, controller.signal);
    } catch (e) {
      controller.abort();
      return { status: 'unavailable', reason: e instanceof Error ? e.message.slice(0, 200) : 'simulator failed' };
    }
  }

  private async record(type: AuditEventType, requestId: string, sessionId: string, payload: Record<string, unknown>): Promise<string> {
    const { hash, persisted } = await this.prepareRecord(type, requestId, sessionId, payload);
    await persisted;
    return hash;
  }

  /** Chain an audit record now; `persisted` rejects with AuditUnavailableError if storing it fails. */
  private async prepareRecord(
    type: AuditEventType, requestId: string, sessionId: string, payload: Record<string, unknown>,
  ): Promise<{ hash: string; persisted: Promise<void> }> {
    let prepared: Awaited<ReturnType<AuditLog['prepare']>>;
    try {
      prepared = await this.audit.prepare(type, requestId, sessionId, { policyHash: this.policy.hash, ...payload });
    } catch {
      throw new AuditUnavailableError();
    }
    const persisted = prepared.persisted.catch(() => {
      throw new AuditUnavailableError();
    });
    persisted.catch(() => undefined);
    return { hash: prepared.record.hash, persisted };
  }

  private async finalizeUnreserved(
    requestId: string, sessionId: string, request: NormalizedRequest, txDigest: string,
    result: EngineResult, started: number, now: number,
  ): Promise<Verdict> {
    const durationMs = performance.now() - started;
    try {
      const auditHash = await this.record('evaluation', requestId, sessionId, { txDigest, request, result: auditSummary(result), durationMs });
      return this.verdict({ requestId, sessionId, request, txDigest, result, now, durationMs, auditHash });
    } catch {
      return this.verdict({ requestId, sessionId, request, txDigest, result, now, durationMs, auditHash: null });
    }
  }

  private verdict(v: {
    requestId: string; sessionId: string; request: NormalizedRequest; txDigest: string; result: EngineResult;
    now: number; durationMs: number; auditHash: string | null; reservationId?: string; approvalExpiresAt?: number;
  }): Verdict {
    return deepFreeze({
      requestId: v.requestId,
      verdict: v.result.verdict,
      allowed: v.result.verdict === 'allowed',
      sessionId: v.sessionId,
      chainId: v.request.chainId,
      txDigest: v.txDigest,
      policyHash: this.policy.hash,
      riskScore: v.result.riskScore,
      riskLevel: v.result.riskLevel,
      reasons: v.result.findings,
      actions: toJsonSafe(v.result.decoded.actions) as Record<string, unknown>[],
      summary: v.result.summary,
      explanation: v.result.explanation,
      spend: toJsonSafe(v.result.spend) as Verdict['spend'],
      evaluatedAt: new Date(v.now).toISOString(),
      durationMs: round(v.durationMs),
      ...(v.reservationId ? { reservationId: v.reservationId } : {}),
      ...(v.approvalExpiresAt !== undefined ? { approvalExpiresAt: new Date(v.approvalExpiresAt).toISOString() } : {}),
      auditHash: v.auditHash,
    });
  }

  private async failure(
    requestId: string, sessionId: string, started: number, now: number, code: string, message: string,
    chainId: number | null, txDigest: string | null, audit = false,
  ): Promise<Verdict> {
    const findings: Finding[] = [{ code, outcome: 'block', severity: 'critical', message, remediation: 'Fix the request or contact the firewall operator' }];
    const durationMs = performance.now() - started;
    let auditHash: string | null = null;
    if (audit) {
      try {
        auditHash = await this.record('evaluation', requestId, sessionId, { txDigest, result: { verdict: 'blocked', findings } });
      } catch {
        auditHash = null;
      }
    }
    const { score, level } = riskScore(findings);
    return deepFreeze({
      requestId, verdict: 'blocked', allowed: false, sessionId, chainId, txDigest, policyHash: this.policy.hash,
      riskScore: score, riskLevel: level, reasons: findings, actions: [],
      summary: summarize('blocked', [], findings), explanation: [],
      spend: { native: '0', tokens: {} }, evaluatedAt: new Date(now).toISOString(), durationMs: round(durationMs), auditHash,
    });
  }
}

function auditSummary(result: EngineResult): Record<string, unknown> {
  return {
    verdict: result.verdict,
    riskScore: result.riskScore,
    findings: result.findings,
    actions: result.decoded.actions,
    spend: result.spend,
    summary: result.summary,
  };
}

function requireReservation(v: Verdict): string {
  if (!v.allowed || !v.reservationId) throw new FirewallStateError('Only allowed verdicts hold a reservation');
  return v.reservationId;
}

function round(ms: number): number {
  return Math.round(ms * 1000) / 1000;
}

export function createFirewall(options: FirewallOptions): Firewall {
  return new Firewall(options);
}

// Session accounting.
//
// Spend is reserved atomically with the allow decision, so concurrent requests
// cannot both pass a cap that only one of them fits under. Reservations stay
// counted until committed (executed) or released (failed / not sent): an
// unresolved reservation fails closed by consuming budget. Stale reservations
// (those past their TTL) are swept from pending on each transact() call so
// budgets are not held hostage by agents that evaluate but never commit.

import type { SimulationOutcome, Spend } from './engine.js';
import type { NormalizedRequest } from './schemas.js';

export interface Reservation {
  readonly spend: Spend;
  readonly createdAt: number;
  readonly requestId: string;
  /** Unix-ms after which this reservation is automatically released if not committed. */
  readonly expiresAt?: number;
}

export interface PendingApproval {
  readonly request: NormalizedRequest;
  readonly txDigest: string;
  readonly expiresAt: number;
  /** Simulation outcome at evaluation time, reused when the approval is granted. */
  readonly simulation?: SimulationOutcome;
}

export interface SessionState {
  readonly id: string;
  createdAt: number;
  txCount: number;
  committed: Spend;
  pending: Record<string, Reservation>;
  approvals: Record<string, PendingApproval>;
}

/**
 * Storage for session usage. `transact` must run `fn` with exclusive access to the
 * session and persist the returned state atomically before resolving; if `fn` throws,
 * nothing is persisted. Distributed implementations need an equivalent lock or
 * compare-and-swap (e.g. Redis WATCH/MULTI, a database row lock).
 */
export interface SessionStore {
  transact<T>(sessionId: string, now: number, fn: (state: SessionState) => T | Promise<T>): Promise<T>;
}

export function newSessionState(id: string, now: number): SessionState {
  return { id, createdAt: now, txCount: 0, committed: { native: 0n, tokens: {} }, pending: {}, approvals: {} };
}

export function addSpend(a: Spend, b: Spend): Spend {
  const tokens: Record<string, bigint> = { ...a.tokens };
  for (const [k, v] of Object.entries(b.tokens)) tokens[k] = (tokens[k] ?? 0n) + v;
  return { native: a.native + b.native, tokens };
}

/** Committed plus all pending reservations that have not expired. */
export function totalSpent(state: SessionState, now?: number): Spend {
  return Object.values(state.pending)
    .filter((r) => now === undefined || r.expiresAt === undefined || r.expiresAt > now)
    .reduce((acc, r) => addSpend(acc, r.spend), state.committed);
}

/**
 * Remove expired reservations from state.pending, returning the number swept.
 * Call inside transact() before reading session totals.
 */
export function sweepExpiredReservations(state: SessionState, now: number): number {
  let swept = 0;
  for (const [id, r] of Object.entries(state.pending)) {
    if (r.expiresAt !== undefined && r.expiresAt <= now) {
      delete state.pending[id];
      state.txCount = Math.max(0, state.txCount - 1);
      swept++;
    }
  }
  return swept;
}

export class MemorySessionStore implements SessionStore {
  protected readonly states: Map<string, SessionState>;
  private readonly locks = new Map<string, Promise<unknown>>();

  constructor(initial?: Iterable<readonly [string, SessionState]>) {
    this.states = new Map(initial);
  }

  /**
   * The session lock covers only `fn`. Persistence is enqueued in lock order and awaited
   * after the lock is released, so concurrent transactions share one durable write;
   * each caller still resolves only once its state (and every earlier state) is stored.
   */
  async transact<T>(sessionId: string, now: number, fn: (state: SessionState) => T | Promise<T>): Promise<T> {
    const previous = this.locks.get(sessionId) ?? Promise.resolve();
    const critical = previous.then(async () => {
      const current = this.states.get(sessionId) ?? newSessionState(sessionId, now);
      const draft = structuredClone(current);
      sweepExpiredReservations(draft, now);
      const result = await fn(draft);
      const persisted = this.persist(draft);
      this.states.set(sessionId, draft);
      return { result, persisted };
    });
    const settled = critical.catch(() => undefined);
    this.locks.set(sessionId, settled);
    void settled.then(() => {
      if (this.locks.get(sessionId) === settled) this.locks.delete(sessionId);
    });
    const { result, persisted } = await critical;
    await persisted;
    return result;
  }

  /**
   * Durability hook, called in lock order with each new state. A rejection fails the
   * transaction; the in-memory state keeps the change, which only over-counts budget.
   */
  protected persist(_state: SessionState): Promise<void> | void {}
}

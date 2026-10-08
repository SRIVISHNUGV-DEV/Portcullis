// Session accounting.
//
// Spend is reserved atomically with the allow decision, so concurrent requests
// cannot both pass a cap that only one of them fits under. Reservations stay
// counted until committed (executed) or released (failed / not sent): an
// unresolved reservation fails closed by consuming budget.

import type { SimulationOutcome, Spend } from './engine.js';
import type { NormalizedRequest } from './schemas.js';

export interface Reservation {
  readonly spend: Spend;
  readonly createdAt: number;
  readonly requestId: string;
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
 * session and persist the returned state atomically; if `fn` throws, nothing is
 * persisted. Distributed implementations need an equivalent lock or
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

/** Committed plus all pending reservations. */
export function totalSpent(state: SessionState): Spend {
  return Object.values(state.pending).reduce((acc, r) => addSpend(acc, r.spend), state.committed);
}

export class MemorySessionStore implements SessionStore {
  private readonly states = new Map<string, SessionState>();
  private readonly locks = new Map<string, Promise<unknown>>();

  async transact<T>(sessionId: string, now: number, fn: (state: SessionState) => T | Promise<T>): Promise<T> {
    const previous = this.locks.get(sessionId) ?? Promise.resolve();
    const run = previous.then(async () => {
      const current = this.states.get(sessionId) ?? newSessionState(sessionId, now);
      const draft = structuredClone(current);
      const result = await fn(draft);
      this.states.set(sessionId, draft);
      return result;
    });
    const settled = run.catch(() => undefined);
    this.locks.set(sessionId, settled);
    void settled.then(() => {
      if (this.locks.get(sessionId) === settled) this.locks.delete(sessionId);
    });
    return run;
  }
}

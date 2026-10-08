import type { Approval, Firewall, Verdict } from './firewall.js';

export class FirewallBlockedError extends Error {
  readonly code = 'FIREWALL_BLOCKED';
  constructor(readonly verdict: Verdict) {
    super(verdict.summary);
    this.name = 'FirewallBlockedError';
  }
}

export class ApprovalRequiredError extends Error {
  readonly code = 'FIREWALL_APPROVAL_REQUIRED';
  constructor(readonly verdict: Verdict) {
    super(verdict.summary);
    this.name = 'ApprovalRequiredError';
  }
}

export interface CallLike {
  readonly to?: string | null | undefined;
  readonly value?: bigint | string | number | undefined;
  readonly data?: string | undefined;
}

export type ApprovalHandler = (verdict: Verdict) => Promise<Approval | false> | Approval | false;

export interface GuardOptions<TTx> {
  readonly firewall: Firewall;
  readonly chainId: number;
  /** Address of the agent wallet that executes the transaction. */
  readonly from: string;
  readonly sessionId?: string;
  /** Map the wallet SDK's transaction object to calls. Defaults to `{ to, value, data }` or `{ calls }`. */
  readonly toCalls?: (tx: TTx) => CallLike | readonly CallLike[];
  /** Ask a human. Return an Approval to proceed or `false` to reject. Without it, approval-required requests throw. */
  readonly onApprovalRequired?: ApprovalHandler;
  /** Observe every verdict (metrics, alerting, UI). Errors thrown here are ignored. */
  readonly onVerdict?: (verdict: Verdict) => void;
  /**
   * Return true only when a send error guarantees nothing was broadcast, so the reserved
   * budget can be returned. Default: never release — a timeout can hide a broadcast.
   */
  readonly releaseOnError?: (error: unknown) => boolean;
}

function defaultCalls(tx: unknown): CallLike | readonly CallLike[] {
  const t = tx as { calls?: readonly CallLike[] } & CallLike;
  return Array.isArray(t?.calls) ? t.calls : { to: t?.to, value: t?.value, data: t?.data };
}

function txHashOf(result: unknown): string | undefined {
  if (typeof result === 'string' && /^0x[0-9a-fA-F]{64}$/.test(result)) return result;
  const r = result as { hash?: unknown; transactionHash?: unknown } | null;
  const h = r && typeof r === 'object' ? (r.hash ?? r.transactionHash) : undefined;
  return typeof h === 'string' ? h : undefined;
}

/**
 * Wrap any wallet send function so every transaction is evaluated first.
 *
 *   const send = guard((tx) => wallet.sendTransaction(tx), { firewall, chainId: 8453, from: wallet.address });
 *
 * Blocked → throws FirewallBlockedError. Needs approval → asks `onApprovalRequired`
 * or throws ApprovalRequiredError. Allowed → sends, then commits the spend (or
 * releases it if sending throws).
 */
export function guard<TTx, TResult>(
  send: (tx: TTx) => Promise<TResult>,
  options: GuardOptions<TTx>,
): (tx: TTx) => Promise<TResult> {
  const { firewall } = options;
  const notify = (v: Verdict) => {
    try {
      options.onVerdict?.(v);
    } catch {
      // Observers must not influence the decision.
    }
  };

  return async (tx: TTx) => {
    const mapped = (options.toCalls ?? defaultCalls)(tx);
    const request = Array.isArray(mapped)
      ? { chainId: options.chainId, from: options.from, calls: mapped }
      : { chainId: options.chainId, from: options.from, ...(mapped as CallLike) };

    let verdict = await firewall.evaluate(request, options.sessionId ? { sessionId: options.sessionId } : {});
    notify(verdict);

    if (verdict.verdict === 'requiresApproval') {
      if (!options.onApprovalRequired) throw new ApprovalRequiredError(verdict);
      const decision = await options.onApprovalRequired(verdict);
      if (!decision) {
        await firewall.reject(verdict, { approver: 'approval-handler', note: 'declined' });
        throw new FirewallBlockedError(verdict);
      }
      verdict = await firewall.approve(verdict, decision);
      notify(verdict);
    }

    if (!verdict.allowed) throw new FirewallBlockedError(verdict);

    let result: TResult;
    try {
      result = await send(tx);
    } catch (e) {
      if (options.releaseOnError?.(e)) await firewall.release(verdict, 'send failed before broadcast');
      throw e;
    }
    const txHash = txHashOf(result);
    await firewall.commit(verdict, txHash ? { txHash } : {});
    return result;
  };
}

// Multi-agent execution gateway.
//
// The gateway is the only component holding wallet access. Each agent authenticates
// with its own bearer token and gets its own policy, wallet and session budgets; every
// request goes through the firewall, and only allowed requests reach the wallet.
// Human approvals are decided through the admin interface, never by the agent.

import { createHash, timingSafeEqual } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { z } from 'zod';
import { T, bytesToHex, encodeAbi } from './abi.js';
import { AuditLog, JsonlFileAuditSink, MemoryAuditSink, verifyAuditChain, type ChainVerification } from './audit.js';
import { SELECTORS } from './decoder.js';
import { Firewall, FirewallStateError, type Verdict } from './firewall.js';
import { compilePolicy } from './policy.js';
import { AddressSchema, ChainIdSchema, type TokenRule } from './schemas.js';
import { MemorySessionStore, type SessionStore } from './session.js';
import { createUniswapV3Quoter, type Quoter } from './simulation.js';
import { JournalSessionStore } from './storage.js';
import { UINT256_MAX, formatUnits, parseUnits } from './units.js';

// ── wallet backends ─────────────────────────────────────────────────────────

export interface WalletCall {
  readonly from: string;
  readonly to: string | null;
  readonly value: bigint;
  readonly data: string;
}

export interface WalletBackend {
  /** Submit one call and return its transaction hash. Throw WalletRejectedError only when nothing was broadcast. */
  send(call: WalletCall): Promise<string>;
  /** Optional receipt lookup; null while pending. */
  receipt?(hash: string): Promise<{ readonly status: 'success' | 'reverted' } | null>;
}

/** The wallet refused the call before broadcasting it, so its reserved budget can be released. */
export class WalletRejectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WalletRejectedError';
  }
}

export interface JsonRpcWalletOptions {
  /** Node or remote signer that holds the agent keys and accepts eth_sendTransaction. */
  readonly url: string;
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
}

/**
 * Wallet backed by a JSON-RPC signer (a local node, Clef, Web3Signer, or a fork for testing).
 * Sends from the same address are serialized so concurrent requests cannot race for a nonce.
 */
export class JsonRpcWallet implements WalletBackend {
  private id = 0;
  private readonly senders = new Map<string, Promise<unknown>>();
  constructor(private readonly options: JsonRpcWalletOptions) {}

  send(call: WalletCall): Promise<string> {
    const previous = this.senders.get(call.from) ?? Promise.resolve();
    const run = previous.then(() => this.sendNow(call));
    const settled = run.catch(() => undefined);
    this.senders.set(call.from, settled);
    void settled.then(() => {
      if (this.senders.get(call.from) === settled) this.senders.delete(call.from);
    });
    return run;
  }

  private async sendNow(call: WalletCall): Promise<string> {
    const params = {
      from: call.from,
      ...(call.to ? { to: call.to } : {}),
      value: `0x${call.value.toString(16)}`,
      data: call.data,
    };
    const result = await this.rpc('eth_sendTransaction', [params], true);
    if (typeof result !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(result)) throw new Error('Wallet returned an invalid transaction hash');
    return result;
  }

  async receipt(hash: string): Promise<{ status: 'success' | 'reverted' } | null> {
    const r = (await this.rpc('eth_getTransactionReceipt', [hash], false)) as { status?: string } | null;
    if (!r) return null;
    return { status: r.status === '0x1' ? 'success' : 'reverted' };
  }

  private async rpc(method: string, params: unknown[], rejectIsSafe: boolean): Promise<unknown> {
    const res = await (this.options.fetch ?? fetch)(this.options.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++this.id, method, params }),
      signal: AbortSignal.timeout(this.options.timeoutMs ?? 10_000),
    });
    const body = (await res.json()) as { result?: unknown; error?: { message?: string } };
    if (body.error) {
      const message = `${method} failed: ${body.error.message ?? 'unknown error'}`.slice(0, 300);
      throw rejectIsSafe ? new WalletRejectedError(message) : new Error(message);
    }
    return body.result;
  }
}

// ── configuration ───────────────────────────────────────────────────────────

const Sha256HexSchema = z.string().regex(/^[0-9a-f]{64}$/, 'Expected a lowercase hex SHA-256 digest');

export const AgentConfigSchema = z
  .object({
    /** Used in session IDs and audit records. */
    id: z.string().regex(/^[\w.-]{1,64}$/, 'Agent ID must be 1-64 characters of [A-Za-z0-9_.-]'),
    /** SHA-256 of the agent's bearer token; the token itself is never stored. */
    tokenSha256: Sha256HexSchema,
    /** Wallet the agent's transactions are sent from. */
    wallet: AddressSchema,
    policy: z.unknown(),
  })
  .strict();

export const GatewayConfigSchema = z
  .object({
    chainId: ChainIdSchema,
    /** JSON-RPC signer used as the default wallet backend. */
    rpcUrl: z.string().url().optional(),
    listen: z.object({ host: z.string().default('127.0.0.1'), port: z.number().int().min(0).max(65535) }).strict().optional(),
    /** SHA-256 of the admin token used to decide approvals. Without it, approvals can only expire. */
    adminTokenSha256: Sha256HexSchema.optional(),
    /** Durable journal + audit log directory. Without it everything is in memory. */
    storage: z.object({ dir: z.string().min(1), fsync: z.boolean().default(true) }).strict().optional(),
    /** Uniswap QuoterV2 for protocols with `maxSlippageBps`. `rpcUrl` defaults to the gateway's. */
    quoter: z.object({ uniswapV3QuoterV2: AddressSchema, rpcUrl: z.string().url().optional() }).strict().optional(),
    agents: z.array(AgentConfigSchema).min(1),
  })
  .strict()
  .superRefine((c, ctx) => {
    const ids = new Set<string>();
    const tokens = new Set<string>();
    for (const a of c.agents) {
      if (ids.has(a.id)) ctx.addIssue({ code: 'custom', message: `Duplicate agent ID ${a.id}` });
      if (tokens.has(a.tokenSha256)) ctx.addIssue({ code: 'custom', message: `Agent ${a.id} reuses another agent's token` });
      ids.add(a.id);
      tokens.add(a.tokenSha256);
    }
  });

export type GatewayConfigInput = z.input<typeof GatewayConfigSchema>;
export type GatewayConfig = z.output<typeof GatewayConfigSchema>;

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

function tokenMatches(token: string, expectedSha256: string): boolean {
  return timingSafeEqual(Buffer.from(hashToken(token), 'hex'), Buffer.from(expectedSha256, 'hex'));
}

// ── results ─────────────────────────────────────────────────────────────────

export type RequestStatus = 'executed' | 'checked' | 'blocked' | 'pending_approval' | 'rejected' | 'expired' | 'failed' | 'unknown';

export interface GatewayResult {
  readonly requestId: string;
  readonly status: RequestStatus;
  /** The firewall's decision for the request as evaluated. */
  readonly verdict: Verdict['verdict'];
  readonly summary: string;
  readonly reasons: readonly { readonly code: string; readonly outcome: string; readonly message: string; readonly remediation?: string }[];
  readonly explanation: readonly string[];
  readonly riskScore: number;
  readonly riskLevel: string;
  readonly txHash?: string;
  readonly receipt?: 'success' | 'reverted' | 'pending';
  readonly approvalExpiresAt?: string;
  /** Human decision on an escalated request. */
  readonly decision?: { readonly approved: boolean; readonly by: string; readonly at: string; readonly note?: string };
  readonly error?: string;
  /** Firewall decision time vs. wallet time, in milliseconds. */
  readonly timings: { readonly firewallMs: number; readonly walletMs?: number };
}

export interface PendingRequest {
  readonly requestId: string;
  readonly agentId: string;
  readonly sessionId: string;
  readonly summary: string;
  readonly explanation: readonly string[];
  readonly reasons: GatewayResult['reasons'];
  readonly riskScore: number;
  readonly expiresAt: string | undefined;
}

export interface CallInput {
  readonly to?: string | null;
  readonly value?: bigint | string;
  readonly data?: string;
}

export interface SubmitOptions {
  /**
   * Budget scope within the agent, e.g. one run. Defaults to "default". Must come from
   * trusted host code, never from the agent: a new session starts with a fresh budget.
   */
  readonly session?: string;
  /** Evaluate without executing; an allowed reservation is released immediately. */
  readonly dryRun?: boolean;
}

interface Agent {
  readonly id: string;
  readonly tokenSha256: string;
  readonly wallet: string;
  readonly firewall: Firewall;
  readonly tokensBySymbol: ReadonlyMap<string, TokenRule>;
}

interface Tracked {
  readonly agentId: string;
  verdict: Verdict;
  readonly call: CallInput;
  result: GatewayResult;
}

const MAX_TRACKED = 10_000;
const SESSION_RE = /^[\w.@-]{1,64}$/;

export class GatewayError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GatewayError';
  }
}

export interface GatewayDeps {
  readonly wallet?: WalletBackend;
  readonly clock?: () => number;
  readonly generateId?: () => string;
  /** Wait for a receipt after sending, up to this many milliseconds. Default 0 (don't wait). */
  readonly receiptTimeoutMs?: number;
  /** Overrides the quoter built from `config.quoter`. */
  readonly quoter?: Quoter;
}

export class Gateway {
  readonly config: GatewayConfig;
  private readonly agents = new Map<string, Agent>();
  private readonly tracked = new Map<string, Tracked>();
  private readonly closers: (() => Promise<void>)[] = [];

  private constructor(
    config: GatewayConfig,
    private readonly wallet: WalletBackend,
    private readonly audit: { log: AuditLog; path?: string },
    sessions: SessionStore,
    private readonly deps: GatewayDeps,
  ) {
    this.config = config;
    const quoteUrl = config.quoter?.rpcUrl ?? config.rpcUrl;
    const quoter = deps.quoter ?? (config.quoter && quoteUrl ? createUniswapV3Quoter({ url: quoteUrl, quoter: config.quoter.uniswapV3QuoterV2 }) : undefined);
    for (const a of config.agents) {
      const policy = compilePolicy(a.policy);
      if (!policy.chainIds.has(config.chainId)) throw new GatewayError(`Agent ${a.id}: policy does not allow chain ${config.chainId}`);
      const firewall = new Firewall({
        policy, audit: audit.log, sessions,
        ...(quoter && policy.policy.protocols.some((pr) => pr.maxSlippageBps !== undefined) ? { quoter } : {}),
        ...(deps.clock ? { clock: deps.clock } : {}),
        ...(deps.generateId ? { generateId: deps.generateId } : {}),
      });
      const tokensBySymbol = new Map(policy.policy.tokens.map((t) => [t.symbol.toUpperCase(), t]));
      this.agents.set(a.id, { id: a.id, tokenSha256: a.tokenSha256, wallet: a.wallet, firewall, tokensBySymbol });
    }
  }

  static async create(input: GatewayConfigInput, deps: GatewayDeps = {}): Promise<Gateway> {
    const parsed = GatewayConfigSchema.safeParse(input);
    if (!parsed.success) {
      throw new GatewayError(`Invalid gateway config:\n- ${parsed.error.issues.map((i) => `${i.path.join('.') || 'config'}: ${i.message}`).join('\n- ')}`);
    }
    const config = parsed.data;
    const wallet = deps.wallet ?? (config.rpcUrl ? new JsonRpcWallet({ url: config.rpcUrl }) : undefined);
    if (!wallet) throw new GatewayError('Configure rpcUrl or provide a wallet backend');
    if (!config.storage && process.env.NODE_ENV === 'production') {
      throw new GatewayError('storage.dir is required when NODE_ENV=production; in-memory budgets and audit logs are lost on restart');
    }

    const closers: (() => Promise<void>)[] = [];
    let sessions: SessionStore;
    let audit: { log: AuditLog; path?: string };
    if (config.storage) {
      await mkdir(config.storage.dir, { recursive: true, mode: 0o700 });
      const journal = await JournalSessionStore.open(join(config.storage.dir, 'sessions.jsonl'), { fsync: config.storage.fsync });
      const path = join(config.storage.dir, 'audit.jsonl');
      const sink = new JsonlFileAuditSink(path, { fsync: config.storage.fsync });
      sessions = journal;
      audit = { log: new AuditLog(sink, deps.clock), path };
      closers.push(() => journal.close(), () => sink.close());
    } else {
      sessions = new MemorySessionStore();
      audit = { log: new AuditLog(new MemoryAuditSink(), deps.clock) };
    }
    const gateway = new Gateway(config, wallet, audit, sessions, deps);
    gateway.closers.push(...closers);
    return gateway;
  }

  // ── authentication ──

  /** Agent ID for a bearer token, or undefined. */
  authenticate(token: string | undefined): string | undefined {
    if (!token) return undefined;
    let match: string | undefined;
    for (const a of this.agents.values()) if (tokenMatches(token, a.tokenSha256)) match = a.id;
    return match;
  }

  isAdmin(token: string | undefined): boolean {
    return !!token && !!this.config.adminTokenSha256 && tokenMatches(token, this.config.adminTokenSha256);
  }

  agentIds(): string[] {
    return [...this.agents.keys()];
  }

  // ── agent operations ──

  async submit(agentId: string, call: CallInput, options: SubmitOptions = {}): Promise<GatewayResult> {
    const agent = this.agent(agentId);
    const sessionId = this.sessionId(agent, options.session);
    const verdict = await agent.firewall.evaluate(
      { chainId: this.config.chainId, from: agent.wallet, to: call.to ?? null, value: call.value ?? 0n, data: call.data ?? '0x' },
      { sessionId },
    );
    const base = fromVerdict(verdict);

    if (options.dryRun) {
      if (verdict.allowed) await agent.firewall.release(verdict, 'dry run');
      return base('checked');
    }
    if (verdict.verdict === 'blocked') return this.track(agent.id, verdict, call, base('blocked'));
    if (verdict.verdict === 'requiresApproval') {
      return this.track(agent.id, verdict, call, {
        ...base('pending_approval'),
        ...(verdict.approvalExpiresAt ? { approvalExpiresAt: verdict.approvalExpiresAt } : {}),
      });
    }
    return this.track(agent.id, verdict, call, await this.execute(agent, verdict, call));
  }

  /** Encode an ERC-20 transfer of a configured token, in display units (e.g. "12.5"). */
  transferToken(agentId: string, input: { token: string; to: string; amount: string }, options?: SubmitOptions): Promise<GatewayResult> {
    const token = this.token(agentId, input.token);
    const to = AddressSchema.parse(input.to);
    const amount = parseUnits(input.amount, token.decimals);
    return this.submit(agentId, { to: token.address, data: encode(SELECTORS.transfer, [T.address, T.uint256], [to, amount]) }, options);
  }

  /** Encode an ERC-20 approve. `amount` is in display units or "unlimited". */
  approveToken(agentId: string, input: { token: string; spender: string; amount: string }, options?: SubmitOptions): Promise<GatewayResult> {
    const token = this.token(agentId, input.token);
    const spender = AddressSchema.parse(input.spender);
    const amount = input.amount.trim().toLowerCase() === 'unlimited' ? UINT256_MAX : parseUnits(input.amount, token.decimals);
    return this.submit(agentId, { to: token.address, data: encode(SELECTORS.approve, [T.address, T.uint256], [spender, amount]) }, options);
  }

  sendNative(agentId: string, input: { to: string; amount: string }, options?: SubmitOptions): Promise<GatewayResult> {
    const to = AddressSchema.parse(input.to);
    return this.submit(agentId, { to, value: parseUnits(input.amount, 18) }, options);
  }

  status(agentId: string, requestId: string): GatewayResult {
    const t = this.tracked.get(requestId);
    if (!t || t.agentId !== agentId) throw new GatewayError('Unknown request ID');
    if (t.result.status === 'pending_approval' && t.verdict.approvalExpiresAt && Date.parse(t.verdict.approvalExpiresAt) < this.now()) {
      t.result = { ...t.result, status: 'expired', summary: `EXPIRED — ${t.result.summary}` };
    }
    return t.result;
  }

  async budget(agentId: string, session?: string): Promise<Record<string, unknown>> {
    const agent = this.agent(agentId);
    const usage = await agent.firewall.usage(this.sessionId(agent, session));
    const p = agent.firewall.policy.policy;
    const nativeSpent = BigInt(usage.spent.native);
    return {
      agentId: agent.id,
      wallet: agent.wallet,
      chainId: this.config.chainId,
      session: session ?? 'default',
      transactions: usage.txCount,
      pendingApprovals: usage.pendingApprovals,
      native: {
        symbol: p.native.symbol,
        perTransactionMax: plainUnits(p.native.perTransactionMax, 18),
        remaining: plainUnits(p.native.sessionMax > nativeSpent ? p.native.sessionMax - nativeSpent : 0n, 18),
        ...(p.native.requireApprovalAbove !== undefined ? { approvalAbove: plainUnits(p.native.requireApprovalAbove, 18) } : {}),
      },
      tokens: p.tokens.map((t) => {
        const spent = BigInt(usage.spent.tokens[t.address] ?? '0');
        return {
          symbol: t.symbol,
          address: t.address,
          perTransactionMax: plainUnits(t.perTransactionMax, t.decimals),
          remaining: plainUnits(t.sessionMax > spent ? t.sessionMax - spent : 0n, t.decimals),
          ...(t.requireApprovalAbove !== undefined ? { approvalAbove: plainUnits(t.requireApprovalAbove, t.decimals) } : {}),
        };
      }),
      protocols: p.protocols.map((pr) => ({ name: pr.name, address: pr.address })),
    };
  }

  // ── admin operations ──

  pending(): PendingRequest[] {
    const now = this.now();
    const out: PendingRequest[] = [];
    for (const [requestId, t] of this.tracked) {
      if (t.result.status !== 'pending_approval') continue;
      if (t.verdict.approvalExpiresAt && Date.parse(t.verdict.approvalExpiresAt) < now) continue;
      out.push({
        requestId, agentId: t.agentId, sessionId: t.verdict.sessionId, summary: t.verdict.summary,
        explanation: t.verdict.explanation, reasons: t.result.reasons, riskScore: t.verdict.riskScore, expiresAt: t.verdict.approvalExpiresAt,
      });
    }
    return out;
  }

  async decide(requestId: string, decision: { approve: boolean; approver: string; note?: string }): Promise<GatewayResult> {
    const t = this.tracked.get(requestId);
    if (!t || t.result.status !== 'pending_approval') throw new GatewayError('No pending approval with this ID');
    const agent = this.agent(t.agentId);
    const approval = { approver: decision.approver, ...(decision.note ? { note: decision.note } : {}) };
    const decided = { by: decision.approver, at: new Date(this.now()).toISOString(), ...(decision.note ? { note: decision.note } : {}) };
    try {
      if (!decision.approve) {
        await agent.firewall.reject(t.verdict, approval);
        t.result = {
          ...t.result, status: 'rejected', decision: { approved: false, ...decided },
          summary: `REJECTED by ${decision.approver} — ${t.verdict.summary.replace(/^NEEDS HUMAN APPROVAL — /, '')} This decision is final; do not resubmit the same request.`,
        };
        return t.result;
      }
      const approved = await agent.firewall.approve(t.verdict, approval);
      t.verdict = approved;
      t.result = {
        ...(approved.allowed ? await this.execute(agent, approved, t.call) : fromVerdict(approved)('blocked')),
        decision: { approved: true, ...decided },
      };
      return t.result;
    } catch (e) {
      if (e instanceof FirewallStateError) {
        t.result = { ...t.result, status: 'expired', error: e.message };
        return t.result;
      }
      throw e;
    }
  }

  async verifyAudit(): Promise<ChainVerification & { records: number }> {
    if (!this.audit.path) throw new GatewayError('Audit verification needs storage.dir');
    const records = await JsonlFileAuditSink.read(this.audit.path);
    return { ...verifyAuditChain(records), records: records.length };
  }

  async close(): Promise<void> {
    for (const close of this.closers) await close();
  }

  // ── internals ──

  private async execute(agent: Agent, verdict: Verdict, call: CallInput): Promise<GatewayResult> {
    const base = fromVerdict(verdict);
    const started = performance.now();
    let txHash: string;
    try {
      txHash = await this.wallet.send({
        from: agent.wallet, to: call.to ?? null, value: BigInt(call.value ?? 0n), data: call.data ?? '0x',
      });
    } catch (e) {
      const walletMs = round(performance.now() - started);
      const message = e instanceof Error ? e.message : String(e);
      if (e instanceof WalletRejectedError) {
        await agent.firewall.release(verdict, message);
        return { ...base('failed'), error: message, timings: { firewallMs: verdict.durationMs, walletMs } };
      }
      // A timeout can hide a broadcast: keep the budget reserved.
      return { ...base('unknown'), error: message, timings: { firewallMs: verdict.durationMs, walletMs } };
    }
    const walletMs = round(performance.now() - started);
    let commitError: string | undefined;
    const commitStarted = performance.now();
    try {
      await agent.firewall.commit(verdict, { txHash });
    } catch (e) {
      // The transaction is already broadcast; its reservation stays counted against the budget.
      commitError = `Executed, but recording the commit failed: ${e instanceof Error ? e.message : String(e)}`;
    }
    const firewallMs = round(verdict.durationMs + performance.now() - commitStarted);
    const receipt = await this.waitForReceipt(txHash);
    return {
      ...base('executed'), txHash, receipt,
      ...(commitError ? { error: commitError } : {}),
      timings: { firewallMs, walletMs },
    };
  }

  private async waitForReceipt(hash: string): Promise<'success' | 'reverted' | 'pending'> {
    const timeout = this.deps.receiptTimeoutMs ?? 0;
    if (!this.wallet.receipt || timeout <= 0) return 'pending';
    const deadline = performance.now() + timeout;
    for (;;) {
      try {
        const r = await this.wallet.receipt(hash);
        if (r) return r.status;
      } catch {
        // Receipt lookups are informational; the transaction is already committed.
      }
      if (performance.now() >= deadline) return 'pending';
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  private track(agentId: string, verdict: Verdict, call: CallInput, result: GatewayResult): GatewayResult {
    this.tracked.set(verdict.requestId, { agentId, verdict, call, result });
    if (this.tracked.size > MAX_TRACKED) {
      for (const [id, t] of this.tracked) {
        if (t.result.status !== 'pending_approval') {
          this.tracked.delete(id);
          break;
        }
      }
    }
    return result;
  }

  private agent(agentId: string): Agent {
    const agent = this.agents.get(agentId);
    if (!agent) throw new GatewayError(`Unknown agent ${agentId}`);
    return agent;
  }

  private sessionId(agent: Agent, session = 'default'): string {
    if (!SESSION_RE.test(session)) throw new GatewayError('Session must be 1-64 characters of [A-Za-z0-9_.@-]');
    return `${agent.id}:${session}`;
  }

  private token(agentId: string, ref: string): TokenRule {
    const agent = this.agent(agentId);
    const byAddress = /^0x[0-9a-fA-F]{40}$/.test(ref) ? agent.firewall.policy.tokens.get(ref.toLowerCase()) : undefined;
    const token = byAddress ?? agent.tokensBySymbol.get(ref.toUpperCase());
    if (!token) throw new GatewayError(`Token ${ref} is not configured for this agent; it cannot be transferred or approved`);
    return token;
  }

  private now(): number {
    return (this.deps.clock ?? Date.now)();
  }
}

function encode(selector: string, types: Parameters<typeof encodeAbi>[0], values: Parameters<typeof encodeAbi>[1]): string {
  return selector + bytesToHex(encodeAbi(types, values)).slice(2);
}

function fromVerdict(v: Verdict): (status: RequestStatus) => GatewayResult {
  return (status) => ({
    requestId: v.requestId,
    status,
    verdict: v.verdict,
    summary: v.summary,
    reasons: v.reasons.map((r) => ({ code: r.code, outcome: r.outcome, message: r.message, ...(r.remediation ? { remediation: r.remediation } : {}) })),
    explanation: v.explanation,
    riskScore: v.riskScore,
    riskLevel: v.riskLevel,
    timings: { firewallMs: v.durationMs },
  });
}

/** Display units without thousands separators, in the same format the tools accept. */
function plainUnits(amount: bigint, decimals: number): string {
  return formatUnits(amount, decimals).replace(/,/g, '');
}

function round(ms: number): number {
  return Math.round(ms * 1000) / 1000;
}


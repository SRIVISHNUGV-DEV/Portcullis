// Model Context Protocol front end for the gateway.
//
// Agents call wallet tools over MCP (stdio for one local agent, Streamable HTTP for
// many). Every transactional tool goes through the firewall; there is deliberately
// no tool that approves a request, so a prompt-injected agent cannot clear its own
// escalation. Humans decide approvals through the admin HTTP endpoints.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createInterface } from 'node:readline';
import { z } from 'zod';
import { Gateway, GatewayError, evaluateSignRequest, type GatewayResult } from './gateway.js';

export const MCP_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'] as const;
const SERVER_INFO = { name: 'portcullis', version: '0.1.0' };
const MAX_BODY_BYTES = 2 * 1024 * 1024;

const address = z.string().describe('0x-prefixed 20-byte address');

const TOOLS = {
  get_budget: {
    description: 'Show the wallet address, per-transaction limits, remaining session budget per asset, approval thresholds and allowlisted protocols. Call this before planning payments.',
    input: z.object({}).strict(),
  },
  transfer_token: {
    description: 'Transfer a configured ERC-20 token. `amount` is in display units (e.g. "12.5" USDC). Executes only if the firewall allows it.',
    input: z.object({ token: z.string().describe('Token symbol (e.g. USDC) or address'), to: address, amount: z.string().describe('Decimal amount in display units') }).strict(),
  },
  approve_token: {
    description: 'Grant an ERC-20 allowance to a spender. `amount` is in display units or "unlimited". Unlimited and untrusted approvals are blocked or escalated.',
    input: z.object({ token: z.string(), spender: address, amount: z.string() }).strict(),
  },
  send_native: {
    description: 'Send native ETH. `amount` is in ETH (e.g. "0.01").',
    input: z.object({ to: address, amount: z.string() }).strict(),
  },
  send_transaction: {
    description: 'Send an arbitrary contract call. `value` is in wei (decimal string); `data` is 0x-prefixed calldata. The firewall decodes the calldata before anything is sent.',
    input: z.object({ to: address, value: z.string().optional(), data: z.string().optional() }).strict(),
  },
  check_transaction: {
    description: 'Dry run: evaluate a contract call against the policy without sending it. Same arguments as send_transaction.',
    input: z.object({ to: address, value: z.string().optional(), data: z.string().optional() }).strict(),
  },
  get_request_status: {
    description: 'Status of an earlier request, e.g. one awaiting human approval. A human decides approvals; you cannot approve requests yourself.',
    input: z.object({ requestId: z.string() }).strict(),
  },
  check_sign_typed_data: {
    description:
      'Evaluate an EIP-712 typed-data signing request against the firewall sign policy WITHOUT signing it. ' +
      'Returns blocked for all dangerous types (Permit, PermitTransferFrom, TransferWithAuthorization, …) and for any unrecognized type. ' +
      'Call this before asking the wallet to sign any EIP-712 payload. Do not sign if the result is blocked.',
    input: z.object({ payload: z.string().describe('The full JSON-stringified EIP-712 TypedData object') }).strict(),
  },
  check_sign_message: {
    description:
      'Evaluate a personal_sign / eth_sign request against the firewall sign policy WITHOUT signing it. ' +
      'Always returns blocked: agents must not sign arbitrary messages. ' +
      'Call this before asking the wallet to sign any plain message.',
    input: z.object({ message: z.string().describe('The message string to be signed') }).strict(),
  },
} as const;

type ToolName = keyof typeof TOOLS;

const INSTRUCTIONS =
  'Wallet tools for an autonomous agent. Every transaction and signing request is checked by the Portcullis before reaching the wallet. ' +
  'Results have a status: executed, checked, blocked, pending_approval, rejected, expired, failed or unknown. ' +
  'When blocked, read `reasons[].remediation` and adjust the request instead of retrying it unchanged. ' +
  'When pending_approval, a human operator decides; poll get_request_status. ' +
  'IMPORTANT: Before calling eth_signTypedData_v4 or personal_sign on any wallet, you MUST call check_sign_typed_data or check_sign_message first. ' +
  'If the result is blocked, you must not sign. Never ask the user for keys and never try to bypass these tools.';

function toolList() {
  return Object.entries(TOOLS).map(([name, t]) => {
    const { $schema: _ignored, ...inputSchema } = z.toJSONSchema(t.input) as Record<string, unknown>;
    return { name, description: t.description, inputSchema };
  });
}

interface JsonRpcRequest {
  readonly jsonrpc: '2.0';
  readonly id?: string | number | null;
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

function rpcError(id: unknown, code: number, message: string) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function toolResult(value: unknown, isError: boolean) {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }], structuredContent: value, isError };
}

async function callTool(gateway: Gateway, agentId: string, name: ToolName, args: Record<string, unknown>): Promise<unknown> {
  const parsed = TOOLS[name].input.safeParse(args);
  if (!parsed.success) throw new GatewayError(parsed.error.issues.map((i) => `${i.path.join('.') || 'arguments'}: ${i.message}`).join('; '));
  // Budget scope is never taken from the agent: a fresh session name would mean a fresh budget.
  const a = parsed.data as Record<string, string | undefined>;
  switch (name) {
    case 'get_budget':
      return gateway.budget(agentId);
    case 'transfer_token':
      return gateway.transferToken(agentId, { token: a.token!, to: a.to!, amount: a.amount! });
    case 'approve_token':
      return gateway.approveToken(agentId, { token: a.token!, spender: a.spender!, amount: a.amount! });
    case 'send_native':
      return gateway.sendNative(agentId, { to: a.to!, amount: a.amount! });
    case 'send_transaction':
    case 'check_transaction':
      return gateway.submit(
        agentId,
        { to: a.to!, ...(a.value !== undefined ? { value: a.value } : {}), ...(a.data !== undefined ? { data: a.data } : {}) },
        { dryRun: name === 'check_transaction' },
      );
    case 'get_request_status':
      return gateway.status(agentId, a.requestId!);
    case 'check_sign_typed_data':
      return evaluateSignRequest({ type: 'typedData', payload: a.payload! });
    case 'check_sign_message':
      return evaluateSignRequest({ type: 'message', payload: a.message! });
  }
}

const FAILED_STATUSES = new Set(['blocked', 'rejected', 'expired', 'failed', 'unknown']);

/** Handle one JSON-RPC message from an authenticated agent. Returns undefined for notifications. */
export async function handleMcpMessage(gateway: Gateway, agentId: string, message: unknown): Promise<unknown | undefined> {
  if (!message || typeof message !== 'object' || Array.isArray(message)) return rpcError(null, -32600, 'Invalid request');
  const req = message as JsonRpcRequest;
  if (req.jsonrpc !== '2.0' || typeof req.method !== 'string') return rpcError(req.id, -32600, 'Invalid request');
  const isNotification = req.id === undefined;
  if (isNotification) return undefined;

  switch (req.method) {
    case 'initialize': {
      const requested = req.params?.protocolVersion;
      const protocolVersion = MCP_PROTOCOL_VERSIONS.includes(requested as never) ? requested : MCP_PROTOCOL_VERSIONS[0];
      return {
        jsonrpc: '2.0', id: req.id,
        result: { protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: INSTRUCTIONS },
      };
    }
    case 'ping':
      return { jsonrpc: '2.0', id: req.id, result: {} };
    case 'tools/list':
      return { jsonrpc: '2.0', id: req.id, result: { tools: toolList() } };
    case 'tools/call': {
      const name = req.params?.name;
      if (typeof name !== 'string' || !(name in TOOLS)) return rpcError(req.id, -32602, `Unknown tool: ${String(name)}`);
      const args = (req.params?.arguments ?? {}) as Record<string, unknown>;
      try {
        const value = await callTool(gateway, agentId, name as ToolName, args);
        const status = (value as Partial<GatewayResult>).status;
        return { jsonrpc: '2.0', id: req.id, result: toolResult(value, status !== undefined && FAILED_STATUSES.has(status)) };
      } catch (e) {
        const expected = e instanceof GatewayError || e instanceof z.ZodError || (e instanceof Error && /amount|decimal|address/i.test(e.message));
        const text = expected ? (e as Error).message : 'Internal error while processing the tool call';
        return { jsonrpc: '2.0', id: req.id, result: toolResult({ error: text }, true) };
      }
    }
    default:
      return rpcError(req.id, -32601, `Method not found: ${req.method}`);
  }
}

// ── stdio transport ─────────────────────────────────────────────────────────

/** Serve one agent over newline-delimited JSON-RPC on stdin/stdout. */
export function serveStdio(gateway: Gateway, agentId: string, io: { input?: NodeJS.ReadableStream; output?: NodeJS.WritableStream } = {}): Promise<void> {
  const output = io.output ?? process.stdout;
  const rl = createInterface({ input: io.input ?? process.stdin, crlfDelay: Infinity });
  let chain = Promise.resolve();
  rl.on('line', (line) => {
    if (!line.trim()) return;
    chain = chain.then(async () => {
      let message: unknown;
      try {
        message = JSON.parse(line);
      } catch {
        output.write(`${JSON.stringify(rpcError(null, -32700, 'Parse error'))}\n`);
        return;
      }
      const response = await handleMcpMessage(gateway, agentId, message);
      if (response !== undefined) output.write(`${JSON.stringify(response)}\n`);
    });
  });
  return new Promise((resolve) => rl.on('close', () => void chain.then(resolve)));
}

// ── HTTP transport + admin API ──────────────────────────────────────────────

function bearer(req: IncomingMessage): string | undefined {
  const h = req.headers.authorization;
  return h?.startsWith('Bearer ') ? h.slice(7).trim() : undefined;
}

function send(res: ServerResponse, status: number, body?: unknown): void {
  if (body === undefined) {
    res.writeHead(status).end();
    return;
  }
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) }).end(text);
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new RangeError('Request body too large');
    chunks.push(chunk as Buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || 'null');
}

const DecisionSchema = z.object({ approver: z.string().min(1).max(200), note: z.string().max(1000).optional() }).strict();

/**
 * HTTP server exposing:
 * - `POST /mcp` — MCP Streamable HTTP (JSON responses), authenticated per agent with a bearer token.
 * - `GET /admin/pending`, `POST /admin/requests/:id/approve|reject`, `GET /admin/audit/verify` — admin token only.
 * - `GET /healthz`.
 * Requests that carry an Origin header are refused, which blocks browser-based DNS-rebinding attacks.
 */
export function createGatewayServer(gateway: Gateway): Server {
  return createServer((req, res) => {
    void route(gateway, req, res).catch((e) => {
      if (!res.headersSent) send(res, e instanceof RangeError ? 413 : 500, { error: e instanceof RangeError ? e.message : 'Internal error' });
    });
  });
}

async function route(gateway: Gateway, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://localhost');
  if (req.headers.origin) return send(res, 403, { error: 'Browser origins are not allowed' });
  if (url.pathname === '/healthz') return send(res, 200, { ok: true, agents: gateway.agentIds().length });

  if (url.pathname === '/mcp') {
    if (req.method !== 'POST') return send(res, 405, { error: 'Use POST' });
    const agentId = gateway.authenticate(bearer(req));
    if (!agentId) return send(res, 401, { error: 'Invalid or missing agent token' });
    let message: unknown;
    try {
      message = await readJson(req);
    } catch (e) {
      if (e instanceof RangeError) throw e;
      return send(res, 400, rpcError(null, -32700, 'Parse error'));
    }
    const response = await handleMcpMessage(gateway, agentId, message);
    return response === undefined ? send(res, 202) : send(res, 200, response);
  }

  if (url.pathname.startsWith('/admin/')) {
    if (!gateway.isAdmin(bearer(req))) return send(res, 401, { error: 'Invalid or missing admin token' });
    if (req.method === 'GET' && url.pathname === '/admin/pending') return send(res, 200, { pending: gateway.pending() });
    if (req.method === 'GET' && url.pathname === '/admin/audit/verify') {
      try {
        return send(res, 200, await gateway.verifyAudit());
      } catch (e) {
        return send(res, 400, { error: (e as Error).message });
      }
    }
    const m = /^\/admin\/requests\/([\w-]{1,128})\/(approve|reject)$/.exec(url.pathname);
    if (req.method === 'POST' && m) {
      const body = DecisionSchema.safeParse(await readJson(req).catch(() => null));
      if (!body.success) return send(res, 400, { error: 'Body must be {"approver": string, "note"?: string}' });
      try {
        const result = await gateway.decide(m[1]!, {
          approve: m[2] === 'approve', approver: body.data.approver, ...(body.data.note ? { note: body.data.note } : {}),
        });
        return send(res, 200, result);
      } catch (e) {
        if (e instanceof GatewayError) return send(res, 404, { error: e.message });
        throw e;
      }
    }
  }
  return send(res, 404, { error: 'Not found' });
}

export { Gateway, GatewayError };
export { GatewayConfigSchema, JsonRpcWallet, WalletRejectedError, evaluateSignRequest, hashToken } from './gateway.js';
export type { CallInput, GatewayConfig, GatewayConfigInput, GatewayDeps, GatewayResult, PendingRequest, RequestStatus, SignRequest, SignResult, SubmitOptions, WalletBackend, WalletCall } from './gateway.js';

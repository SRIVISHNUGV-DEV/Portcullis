#!/usr/bin/env node
// Command-line interface for the Portcullis.
//
// Two surfaces share this binary:
//
//   Gateway (multi-agent, long-running) — the original commands:
//     transaction-firewall serve --config gateway.json            HTTP MCP for many agents + admin API
//     transaction-firewall stdio --config gateway.json --agent ID  MCP over stdio for one agent
//     transaction-firewall token                                  generate a bearer <redacted> and its SHA-256
//
//   Developer commands (one-shot, mapped 1:1 to real library functions):
//     evaluate      -> createFirewall() + firewall.evaluate()
//     approve       -> firewall.approve()
//     reject        -> firewall.reject()
//     commit        -> firewall.commit()
//     release       -> firewall.release()
//     usage         -> firewall.usage()
//     decode        -> compilePolicy() + TransactionRequestSchema.parse() + decodeRequest()
//     sign-check    -> evaluateSignRequest()
//     policy        -> compilePolicy()
//     audit-verify  -> JsonlFileAuditSink.read() + verifyAuditChain()
//
// Dev commands take JSON files, not CLI-encoded calldata: policies use base-unit
// strings for amounts (exactly like gateway.json), transactions use
// { chainId, from, to?, value?, data? } or { chainId, from, calls: [...] }.
// Exit codes: 0 allowed / success, 1 blocked or error, 2 requiresApproval
// (so `evaluate` can gate a script: allowed passes, anything else stops it).
//
// Stateful commands (approve, reject, commit, release, usage) need --storage:
// reservations and pending approvals live in the session store, so a second
// process can only see them when both processes share a durable store
// (JournalSessionStore + JsonlFileAuditSink under --storage). Evaluate with
// --storage, then approve/commit in a later process against the same directory.

import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { JsonlFileAuditSink, verifyAuditChain } from './audit.js';
import { decodeRequest } from './decoder.js';
import { createFirewall, type Verdict } from './firewall.js';
import { Gateway, evaluateSignRequest, hashToken } from './gateway.js';
import { createGatewayServer, serveStdio } from './mcp.js';
import { compilePolicy, PolicyValidationError } from './policy.js';
import { TransactionRequestSchema } from './schemas.js';
import { JournalSessionStore } from './storage.js';

const HELP = `Usage:
  Gateway:
    transaction-firewall serve --config <file>             HTTP MCP + admin API
    transaction-firewall stdio --config <file> [--agent <id>]
    transaction-firewall token                              print a bearer <redacted> + its SHA-256

  Developer commands (each maps to a real library function):
    transaction-firewall evaluate --policy <file> --tx <file> [--session <id>] [--storage <dir>] [--json] [--out <file>]
      createFirewall() + firewall.evaluate()
    transaction-firewall approve --policy <file> --verdict <file> --approver <id> [--note <text>] --storage <dir> [--json] [--out <file>]
      firewall.approve()
    transaction-firewall reject --policy <file> --verdict <file> --approver <id> [--note <text>] --storage <dir>
      firewall.reject()
    transaction-firewall commit --policy <file> --verdict <file> [--tx-hash <hash>] --storage <dir>
      firewall.commit()
    transaction-firewall release --policy <file> --verdict <file> [--reason <text>] --storage <dir>
      firewall.release()
    transaction-firewall usage --policy <file> [--session <id>] --storage <dir> [--json]
      firewall.usage()
    transaction-firewall decode --policy <file> --tx <file> [--json]
      compilePolicy() + TransactionRequestSchema.parse() + decodeRequest()
    transaction-firewall sign-check --type typedData|message (--payload <file> | --payload-json <string>)
      evaluateSignRequest()
    transaction-firewall policy --policy <file> [--json]
      compilePolicy()
    transaction-firewall audit-verify --file <audit.jsonl> [--json]
      JsonlFileAuditSink.read() + verifyAuditChain()

  Exit codes: 0 allowed/success, 1 blocked/error, 2 requiresApproval.
  Policy and transaction files are JSON; amounts are base-unit strings.
  --json prints only machine-readable JSON (for piping); otherwise a human summary is printed.
  --out <file> writes the full verdict JSON (use it to feed approve/commit/release).
`;

class CliError extends Error {}

/** Minimal --flag value / --flag=value / --boolean parser for the dev commands. */
function parseFlags(args: readonly string[]): Map<string, string | true> {
  const flags = new Map<string, string | true>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (!arg.startsWith('--')) throw new CliError(`Unexpected argument: ${arg}\n${HELP}`);
    const eq = arg.indexOf('=');
    if (eq !== -1) {
      flags.set(arg.slice(2, eq), arg.slice(eq + 1));
    } else if (i + 1 < args.length && !args[i + 1]!.startsWith('--')) {
      flags.set(arg.slice(2), args[++i]!);
    } else {
      flags.set(arg.slice(2), true);
    }
  }
  return flags;
}

function reqFlag(flags: Map<string, string | true>, name: string, usage: string): string {
  const v = flags.get(name);
  if (typeof v !== 'string' || v.length === 0) throw new CliError(`Missing --${name}\n${usage}`);
  return v;
}

function optFlag(flags: Map<string, string | true>, name: string): string | undefined {
  const v = flags.get(name);
  return typeof v === 'string' ? v : undefined;
}

function hasFlag(flags: Map<string, string | true>, name: string): boolean {
  return flags.has(name);
}

async function readJsonFile(path: string): Promise<unknown> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    throw new CliError(`Cannot read file: ${path}`);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new CliError(`Not valid JSON: ${path}`);
  }
}

/** JSON with bigints rendered as decimal strings (decode actions carry bigint amounts). */
function toJson(value: unknown): string {
  return JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2);
}

function printJsonOr(value: unknown, human: () => void, asJson: boolean): void {
  if (asJson) process.stdout.write(`${toJson(value)}\n`);
  else human();
}

function printVerdict(v: Verdict, asJson: boolean): void {
  printJsonOr(v, () => {
    const lines = [
      `verdict: ${v.verdict} (allowed: ${v.allowed})`,
      `risk: ${v.riskScore} (${v.riskLevel})`,
      `summary: ${v.summary}`,
      `session: ${v.sessionId}  request: ${v.requestId}`,
      `txDigest: ${v.txDigest ?? '-'}`,
      `policyHash: ${v.policyHash}`,
      `auditHash: ${v.auditHash ?? '-'}`,
      `durationMs: ${v.durationMs}`,
    ];
    if (v.reservationId) lines.push(`reservationId: ${v.reservationId}`);
    if (v.approvalExpiresAt) lines.push(`approvalExpiresAt: ${v.approvalExpiresAt}`);
    if (v.approval) lines.push(`approval: ${v.approval.approver} at ${v.approval.approvedAt}${v.approval.note ? ` (${v.approval.note})` : ''}`);
    const spendParts = [`native: ${v.spend.native}`, ...Object.entries(v.spend.tokens).map(([t, a]) => `${t}: ${a}`)];
    lines.push(`spend: ${spendParts.join(', ')}`);
    for (const r of v.reasons) {
      lines.push(`  ${r.code} [${r.outcome}/${r.severity}] ${r.message}${r.remediation ? ` — fix: ${r.remediation}` : ''}`);
    }
    for (const e of v.explanation) lines.push(`  explains: ${e}`);
    process.stdout.write(`${lines.join('\n')}\n`);
  }, asJson);
}

function exitForVerdict(v: Verdict): number {
  if (v.verdict === 'allowed') return 0;
  if (v.verdict === 'requiresApproval') return 2;
  return 1;
}

async function loadCompiledPolicy(path: string) {
  const input = await readJsonFile(path);
  try {
    return compilePolicy(input);
  } catch (e) {
    if (e instanceof PolicyValidationError) throw new CliError(`Invalid policy ${path}:\n${e.issues.map((i) => `  - ${i}`).join('\n')}`);
    throw e;
  }
}

interface Stores {
  sessions?: JournalSessionStore;
  audit?: JsonlFileAuditSink;
  close: () => Promise<void>;
}

/** Durable stores shared across processes, or in-memory defaults when no --storage. */
async function openStores(storageDir: string | undefined): Promise<Stores> {
  if (!storageDir) return { close: async () => undefined };
  await mkdir(storageDir, { recursive: true, mode: 0o700 });
  const sessions = await JournalSessionStore.open(join(storageDir, 'sessions.jsonl'), { fsync: true });
  const audit = new JsonlFileAuditSink(join(storageDir, 'audit.jsonl'), { fsync: true });
  return {
    sessions,
    audit,
    close: async () => {
      await sessions.close();
      await audit.close();
    },
  };
}

/** createFirewall() without passing explicit undefined (exactOptionalPropertyTypes). */
function makeFirewall(policy: ReturnType<typeof compilePolicy>, stores: Stores) {
  return createFirewall({
    policy,
    ...(stores.sessions ? { sessions: stores.sessions } : {}),
    ...(stores.audit ? { audit: stores.audit } : {}),
  });
}

function requireStorage(storageDir: string | undefined, command: string): string {
  if (!storageDir) {
    throw new CliError(
      `${command} needs --storage <dir>: reservations and pending approvals live in the session store, ` +
        'so a second process can only see them when both processes share a durable store.\n' +
        'Re-run evaluate with the same --storage <dir> first, then approve/commit against it.',
    );
  }
  return storageDir;
}

async function loadVerdict(path: string): Promise<Verdict> {
  const v = await readJsonFile(path);
  // A verdict is frozen plain JSON; approve/commit/release only read its plain
  // fields (verdict, sessionId, requestId, txDigest, reservationId), so a
  // JSON round-trip is lossless for those methods.
  return v as Verdict;
}

async function runDev(command: string, args: readonly string[]): Promise<number> {
  const flags = parseFlags(args);
  const asJson = hasFlag(flags, 'json');
  const storageDir = optFlag(flags, 'storage');

  switch (command) {
    case 'evaluate': {
      const policyPath = reqFlag(flags, 'policy', 'evaluate --policy <file> --tx <file> [--session <id>] [--storage <dir>] [--json] [--out <file>]');
      const txPath = reqFlag(flags, 'tx', 'evaluate --policy <file> --tx <file> [--session <id>] [--storage <dir>] [--json] [--out <file>]');
      const policy = await loadCompiledPolicy(policyPath);
      const tx = await readJsonFile(txPath);
      const stores = await openStores(storageDir);
      try {
        const firewall = makeFirewall(policy, stores);
        const verdict = await firewall.evaluate(tx, { sessionId: optFlag(flags, 'session') ?? 'default' });
        const out = optFlag(flags, 'out');
        if (out) await writeFile(out, `${toJson(verdict)}\n`, 'utf8');
        printVerdict(verdict, asJson);
        return exitForVerdict(verdict);
      } finally {
        await stores.close();
      }
    }
    case 'approve': {
      const policyPath = reqFlag(flags, 'policy', 'approve --policy <file> --verdict <file> --approver <id> [--note <text>] --storage <dir> [--json]');
      const verdictPath = reqFlag(flags, 'verdict', 'approve --policy <file> --verdict <file> --approver <id> [--note <text>] --storage <dir> [--json]');
      const approver = reqFlag(flags, 'approver', 'approve --policy <file> --verdict <file> --approver <id> [--note <text>] --storage <dir> [--json]');
      const dir = requireStorage(storageDir, 'approve');
      const policy = await loadCompiledPolicy(policyPath);
      const pending = await loadVerdict(verdictPath);
      const stores = await openStores(dir);
      try {
        const firewall = makeFirewall(policy, stores);
        const note = optFlag(flags, 'note');
        const verdict = await firewall.approve(pending, { approver, ...(note ? { note } : {}) });
        const out = optFlag(flags, 'out');
        if (out) await writeFile(out, `${toJson(verdict)}\n`, 'utf8');
        printVerdict(verdict, asJson);
        return verdict.allowed ? 0 : 1;
      } finally {
        await stores.close();
      }
    }
    case 'reject': {
      const policyPath = reqFlag(flags, 'policy', 'reject --policy <file> --verdict <file> --approver <id> [--note <text>] --storage <dir>');
      const verdictPath = reqFlag(flags, 'verdict', 'reject --policy <file> --verdict <file> --approver <id> [--note <text>] --storage <dir>');
      const approver = reqFlag(flags, 'approver', 'reject --policy <file> --verdict <file> --approver <id> [--note <text>] --storage <dir>');
      const dir = requireStorage(storageDir, 'reject');
      const policy = await loadCompiledPolicy(policyPath);
      const pending = await loadVerdict(verdictPath);
      const stores = await openStores(dir);
      try {
        const firewall = makeFirewall(policy, stores);
        const note = optFlag(flags, 'note');
        await firewall.reject(pending, { approver, ...(note ? { note } : {}) });
        process.stdout.write(`rejected request ${pending.requestId} (approver: ${approver})\n`);
        return 0;
      } finally {
        await stores.close();
      }
    }
    case 'commit': {
      const policyPath = reqFlag(flags, 'policy', 'commit --policy <file> --verdict <file> [--tx-hash <hash>] --storage <dir>');
      const verdictPath = reqFlag(flags, 'verdict', 'commit --policy <file> --verdict <file> [--tx-hash <hash>] --storage <dir>');
      const dir = requireStorage(storageDir, 'commit');
      const policy = await loadCompiledPolicy(policyPath);
      const allowed = await loadVerdict(verdictPath);
      const stores = await openStores(dir);
      try {
        const firewall = makeFirewall(policy, stores);
        const txHash = optFlag(flags, 'tx-hash');
        await firewall.commit(allowed, { ...(txHash ? { txHash } : {}) });
        process.stdout.write(`committed reservation ${allowed.reservationId} for request ${allowed.requestId}\n`);
        return 0;
      } finally {
        await stores.close();
      }
    }
    case 'release': {
      const policyPath = reqFlag(flags, 'policy', 'release --policy <file> --verdict <file> [--reason <text>] --storage <dir>');
      const verdictPath = reqFlag(flags, 'verdict', 'release --policy <file> --verdict <file> [--reason <text>] --storage <dir>');
      const dir = requireStorage(storageDir, 'release');
      const policy = await loadCompiledPolicy(policyPath);
      const allowed = await loadVerdict(verdictPath);
      const stores = await openStores(dir);
      try {
        const firewall = makeFirewall(policy, stores);
        await firewall.release(allowed, optFlag(flags, 'reason') ?? 'not executed');
        process.stdout.write(`released reservation ${allowed.reservationId} for request ${allowed.requestId}\n`);
        return 0;
      } finally {
        await stores.close();
      }
    }
    case 'usage': {
      const policyPath = reqFlag(flags, 'policy', 'usage --policy <file> [--session <id>] --storage <dir> [--json]');
      const dir = requireStorage(storageDir, 'usage');
      const policy = await loadCompiledPolicy(policyPath);
      const stores = await openStores(dir);
      try {
        const firewall = makeFirewall(policy, stores);
        const u = await firewall.usage(optFlag(flags, 'session') ?? 'default');
        printJsonOr(u, () => {
          const tokenLines = Object.entries(u.spent.tokens).map(([t, a]) => `  ${t}: ${a}`);
          process.stdout.write(
            [
              `session created: ${u.createdAt}`,
              `transactions: ${u.txCount}`,
              `spent native: ${u.spent.native}`,
              ...(tokenLines.length ? ['spent tokens:', ...tokenLines] : []),
              `pending approvals: ${u.pendingApprovals}`,
              ...(u.expiredReservationsSwept ? [`expired reservations swept: ${u.expiredReservationsSwept}`] : []),
            ].join('\n') + '\n',
          );
        }, asJson);
        return 0;
      } finally {
        await stores.close();
      }
    }
    case 'decode': {
      const policyPath = reqFlag(flags, 'policy', 'decode --policy <file> --tx <file> [--json]');
      const txPath = reqFlag(flags, 'tx', 'decode --policy <file> --tx <file> [--json]');
      const policy = await loadCompiledPolicy(policyPath);
      const tx = await readJsonFile(txPath);
      const normalized = TransactionRequestSchema.parse(tx);
      const result = decodeRequest(normalized, policy);
      printJsonOr(result, () => {
        for (const a of result.actions) process.stdout.write(`action: ${toJson(a)}\n`);
        for (const c of result.calls) process.stdout.write(`call: ${toJson(c)}\n`);
        for (const i of result.issues) process.stdout.write(`issue [${i.path}] ${i.code}: ${i.message}\n`);
        if (result.actions.length === 0 && result.issues.length === 0) process.stdout.write('no actions decoded\n');
      }, asJson);
      return 0;
    }
    case 'sign-check': {
      const type = reqFlag(flags, 'type', 'sign-check --type typedData|message (--payload <file> | --payload-json <string>)');
      if (type !== 'typedData' && type !== 'message') throw new CliError(`--type must be typedData or message, got: ${type}`);
      const payloadFile = optFlag(flags, 'payload');
      const payloadJson = optFlag(flags, 'payload-json');
      if ((payloadFile === undefined) === (payloadJson === undefined)) {
        throw new CliError('sign-check needs exactly one of --payload <file> or --payload-json <string>');
      }
      const payload = payloadFile !== undefined ? await readFile(payloadFile, 'utf8') : payloadJson!;
      const result = evaluateSignRequest({ type, payload });
      printJsonOr(result, () => {
        process.stdout.write(`verdict: ${result.verdict}\nsummary: ${result.summary}\n`);
        for (const r of result.reasons) process.stdout.write(`  ${r}\n`);
      }, asJson);
      return result.verdict === 'allowed' ? 0 : 1;
    }
    case 'policy': {
      const policyPath = reqFlag(flags, 'policy', 'policy --policy <file> [--json]');
      const compiled = await loadCompiledPolicy(policyPath);
      const info = {
        valid: true,
        policyHash: compiled.hash,
        name: compiled.policy.name ?? null,
        chainIds: [...compiled.chainIds],
        tokens: compiled.tokens.size,
        nfts: compiled.nfts.size,
        protocols: compiled.protocols.size,
      };
      printJsonOr(info, () => {
        process.stdout.write(
          [
            'policy valid',
            `hash: ${info.policyHash}`,
            ...(info.name ? [`name: ${info.name}`] : []),
            `chains: ${info.chainIds.join(', ')}`,
            `tokens: ${info.tokens}  nfts: ${info.nfts}  protocols: ${info.protocols}`,
          ].join('\n') + '\n',
        );
      }, asJson);
      return 0;
    }
    case 'audit-verify': {
      const file = reqFlag(flags, 'file', 'audit-verify --file <audit.jsonl> [--json]');
      const records = await JsonlFileAuditSink.read(file);
      const result = verifyAuditChain(records);
      printJsonOr({ ...result, records: records.length }, () => {
        if (result.valid) process.stdout.write(`audit chain valid (${records.length} records)\n`);
        else process.stdout.write(`audit chain BROKEN at record ${result.brokenAt}: ${result.reason} (${records.length} records read)\n`);
      }, asJson);
      return result.valid ? 0 : 1;
    }
    default:
      throw new CliError(`Unknown command: ${command}\n${HELP}`);
  }
}

const DEV_COMMANDS = new Set([
  'evaluate', 'approve', 'reject', 'commit', 'release', 'usage',
  'decode', 'sign-check', 'policy', 'audit-verify', 'help',
]);

async function main(): Promise<void> {
  // Dev commands bypass parseArgs: it is strict and would reject their flags
  // (--policy, --tx, ...) before dispatch. They get the raw argv instead.
  const raw = process.argv.slice(2);
  const rawCommand = raw[0];
  if (rawCommand === undefined || rawCommand === 'help' || DEV_COMMANDS.has(rawCommand)) {
    if (rawCommand === undefined || rawCommand === 'help') {
      process.stdout.write(HELP);
      return;
    }
    process.exitCode = await runDev(rawCommand, raw.slice(1));
    return;
  }

  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: { config: { type: 'string', short: 'c' }, agent: { type: 'string', short: 'a' } },
  });
  const command = positionals[0];

  if (command === 'token') {
    const token = randomBytes(32).toString('base64url');
    process.stdout.write(`token:  ${token}\nsha256: ${hashToken(token)}\n`);
    return;
  }
  if ((command !== 'serve' && command !== 'stdio') || !values.config) {
    process.stderr.write('Usage: transaction-firewall serve|stdio --config <file> [--agent <id>] | token\n');
    process.exitCode = 2;
    return;
  }

  const config = JSON.parse(await readFile(values.config, 'utf8')) as unknown;
  const gateway = await Gateway.create(config as Parameters<typeof Gateway.create>[0], { receiptTimeoutMs: 5_000 });
  const log = (msg: string) => process.stderr.write(`[firewall] ${msg}\n`);
  if (!gateway.config.storage) log('warning: no storage.dir configured; budgets and audit log are in memory only');

  const server = gateway.config.listen ? createGatewayServer(gateway) : undefined;
  if (server && gateway.config.listen) {
    const { host, port } = gateway.config.listen;
    await new Promise<void>((resolve) => server.listen(port, host, resolve));
    log(`listening on http://${host}:${port} (MCP at /mcp, admin at /admin) for ${gateway.agentIds().length} agent(s)`);
  }

  const shutdown = async () => {
    server?.close();
    await gateway.close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());

  if (command === 'stdio') {
    const agentId = values.agent ?? (gateway.agentIds().length === 1 ? gateway.agentIds()[0] : undefined);
    if (!agentId || !gateway.agentIds().includes(agentId)) throw new Error('Pass --agent <id> matching an agent in the config');
    await serveStdio(gateway, agentId);
    await shutdown();
  } else if (!server) {
    throw new Error('serve needs "listen" in the config');
  }
}

main().catch((e) => {
  process.stderr.write(`[firewall] ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(1);
});

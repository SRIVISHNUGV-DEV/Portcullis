#!/usr/bin/env node
// transaction-firewall serve --config gateway.json            HTTP MCP for many agents + admin API
// transaction-firewall stdio --config gateway.json --agent ID  MCP over stdio for one agent
// transaction-firewall token                                  generate a bearer token and its SHA-256

import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { Gateway, hashToken } from './gateway.js';
import { createGatewayServer, serveStdio } from './mcp.js';

async function main(): Promise<void> {
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

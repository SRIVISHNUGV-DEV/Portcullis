# AGENTS.md — agent instructions for agent-transaction-firewall

Read this before changing anything in this repo. The README describes what the firewall does; this file describes how to work on it without breaking it.

## What this repo is

A pre-execution safety and risk gate for autonomous onchain agents: decode EVM calldata to asset-level actions, check a deterministic policy, explain the verdict, record it in a hash-chained audit log — before anything reaches a wallet. TypeScript, ESM, Node >= 20, one runtime dependency (`zod`).

## Commands

```sh
npm ci            # install from the lockfile
npm run check     # the gate: typecheck + tests + build. Run this before you call anything done.
npm test          # vitest, 9 files, 108 tests
npm run typecheck # strict TS: exactOptionalPropertyTypes, noUncheckedIndexedAccess
npm run build     # emits ESM + declarations to dist/
npm run bench     # latency / throughput (see README for measured numbers)
node scripts/fork-lab.mjs   # needs Foundry anvil; do not claim its results if anvil is not installed
```

## Layout

```
src/abi.ts         strict canonical ABI codec (re-encodes, requires byte-for-byte match)
src/decoder.ts     calldata → asset-level actions; 16 selectors; unwraps execute/executeBatch
src/engine.ts      deterministic rules, limits, risk score, verdict
src/explain.ts     plain-English descriptions (full addresses, never shortened)
src/firewall.ts    validation, reservations, approvals, fail-closed orchestration
src/middleware.ts  guard() wrapper and typed errors
src/session.ts     session store interface + in-memory implementation
src/storage.ts     group-commit writer and journaled session store
src/gateway.ts     multi-agent gateway: auth, wallet backends, approval queue, sign gate
src/mcp.ts         MCP server (stdio + HTTP) and admin API
src/cli.ts         transaction-firewall command (serve | stdio | token)
src/audit.ts       hash-chained audit log and sinks
src/simulation.ts  optional eth_call simulator (timeout 1500 ms)
src/schemas.ts     Zod schemas for requests and policies
src/canonical.ts   canonicalization and hashing helpers
src/units.ts       amount helpers
```

## Invariants — do not break these

- **`evaluate()` never throws.** Invalid input, malformed calldata, engine/store exceptions, and audit write failures all produce `blocked` verdicts. If your change makes `evaluate()` throw, it is wrong.
- **Decoding is canonical-only.** A recognized selector with bad or non-canonical arguments is `CALLDATA_MALFORMED`, never downgraded to an "unknown call". Dirty address bits, trailing bytes, odd offsets, non-zero padding are blocked, not interpreted.
- **Verdict rule, exactly:** any finding with outcome `block` → `blocked`; else any finding with outcome `requireApproval` → `requiresApproval`; else `allowed`. Risk score never changes a verdict.
- **Unlimited approval is ≥ 2¹²⁸ base units** (`UNLIMITED_APPROVAL_THRESHOLD`) and always blocks.
- **Finite approvals count as spend when granted.** A spender that can move funds without another agent transaction is budgeted at the grant, not at the move. Do not "optimize" this away.
- **Approvals are bound to `txDigest`, single-use, and expire after `approvalTtlSeconds` (default 900).** Hard rules cannot be approved away; `approve()` re-checks caps against current usage.
- **Sessions are budget scopes owned by host code, never by the agent.** An agent that can name its own session can reset its caps. The MCP gateway never exposes the session to agents.
- **Audit failure blocks and rolls back.** If the audit write fails, the verdict is `AUDIT_UNAVAILABLE` and any reservation is undone. A decision must never exist without its audit record.
- **The sign gate is coarse v1, on purpose.** `evaluateSignRequest()` blocks all `personal_sign` / `eth_sign` and all EIP-712 types (dangerous types explicitly, unknown types too). Field-level Permit evaluation against token limits is a stated P1 follow-up. Do not "fix" the gate by allowing a typed-data type without explicit review — and do not describe it as field-level evaluation. It is not.
- **There is deliberately no approve tool for agents.** The MCP tools are exactly: `get_budget`, `approve_token`, `send_transaction`, `check_transaction`, `get_request_status`, `check_sign_typed_data`, `check_sign_message`. Do not invent tools (`transfer_token` and `send_native` do not exist) and do not add an approve-request tool — a prompt-injected agent must not be able to clear its own escalation.
- **Policy schemas are strict.** Unknown keys, duplicate addresses across tokens/nfts/protocols, and allow/deny conflicts throw `PolicyValidationError` at construction. Keep it that way.
- **Amounts are base units (`bigint`).** No USD limits, no price feeds — decisions stay deterministic and oracle-free.
- **Explanations print full addresses.** Shortened addresses are what address-poisoning attacks imitate. Never shorten them in output.
- **Enforcement is a deployment property.** This library cannot stop an agent that reaches the signer directly. Do not write docs or comments implying otherwise.

## Workflow rules

- Run `npm run check` before finishing any change, and report its real result (test count, pass/fail). Never claim a fix works without a test run.
- Never commit `dist/`, `node_modules/`, `coverage/`, `*.log`, or `*.jsonl` — all are gitignored build/dev outputs. The package builds to `dist/` from source; the repo ships source, not build output.
- Never push to `main` without an explicit instruction to do so. Default is a branch + PR for review.
- Never claim npm publication, CI status, or a security audit — none exist for this repo (npm registry returns 404 for the package name; no workflow files in the tree). If you need one of those claims, verify it first.
- When the README and the code disagree, the code wins. Fix the README, not the other way around.
- This repo's README describes `main` only. Features on unmerged branches (e.g. PR #2: swap decoding, Zodiac Roles export) are not shipped until merged — describe them as in-flight, never as done.

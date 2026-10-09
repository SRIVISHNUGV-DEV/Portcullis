// Append-only, hash-chained audit log.
//
// Each record commits to its predecessor's hash, so any edit, deletion or
// reordering is detectable with verifyAuditChain(). This makes the log
// tamper-evident; tamper-proof retention additionally needs WORM/object-lock
// storage or periodic anchoring of the head hash outside the host.

import { readFile } from 'node:fs/promises';
import { canonicalJson, deepFreeze, sha256Hex } from './canonical.js';
import { GroupCommitFile, type GroupCommitOptions } from './storage.js';

export type AuditEventType = 'evaluation' | 'approval' | 'rejection' | 'commit' | 'release';

export interface AuditRecord {
  readonly seq: number;
  readonly timestamp: string;
  readonly type: AuditEventType;
  readonly requestId: string;
  readonly sessionId: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly prevHash: string;
  readonly hash: string;
}

export interface AuditSink {
  append(record: AuditRecord): Promise<void>;
  /** Last persisted record, used to continue the chain after a restart. */
  tail?(): Promise<AuditRecord | undefined>;
  /**
   * True if append() may be called again before the previous call resolves: records
   * must persist in call order, and after a rejected append every later append must
   * reject until tail() is called. Lets the log prepare records while writes are in flight.
   */
  readonly pipelined?: boolean;
}

export const GENESIS_HASH = '0'.repeat(64);

function hashRecord(record: Omit<AuditRecord, 'hash'>): string {
  return sha256Hex(canonicalJson(record));
}

/** Same digest as hashRecord(), reusing the already-canonical payload string. Keys are in sorted order. */
function hashRecordWithPayload(body: Omit<AuditRecord, 'hash' | 'payload'>, payloadJson: string): string {
  return sha256Hex(
    `{"payload":${payloadJson},"prevHash":${JSON.stringify(body.prevHash)},"requestId":${JSON.stringify(body.requestId)},` +
      `"seq":${body.seq},"sessionId":${JSON.stringify(body.sessionId)},"timestamp":${JSON.stringify(body.timestamp)},"type":${JSON.stringify(body.type)}}`,
  );
}

export class MemoryAuditSink implements AuditSink {
  private readonly items: AuditRecord[] = [];

  get records(): readonly AuditRecord[] {
    return this.items.slice();
  }

  async append(record: AuditRecord): Promise<void> {
    this.items.push(record);
  }

  async tail(): Promise<AuditRecord | undefined> {
    return this.items[this.items.length - 1];
  }
}

/**
 * JSON Lines file sink. One record per line; concurrent appends are group-committed
 * (one write, plus one fsync when `fsync` is true, per batch).
 */
export class JsonlFileAuditSink implements AuditSink {
  readonly pipelined = true;
  private readonly writer: GroupCommitFile;

  constructor(
    readonly path: string,
    options: GroupCommitOptions = { fsync: false },
  ) {
    this.writer = new GroupCommitFile(path, options);
  }

  append(record: AuditRecord): Promise<void> {
    return this.writer.append(JSON.stringify(record));
  }

  async tail(): Promise<AuditRecord | undefined> {
    const records = await JsonlFileAuditSink.read(this.path);
    this.writer.reset();
    return records[records.length - 1];
  }

  close(): Promise<void> {
    return this.writer.close();
  }

  static async read(path: string): Promise<AuditRecord[]> {
    let text: string;
    try {
      text = await readFile(path, 'utf8');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw e;
    }
    return text
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as AuditRecord);
  }
}

export class AuditLog {
  private head: { seq: number; hash: string } | undefined;
  private queue: Promise<unknown> = Promise.resolve();
  /** Bumped on every failure so stale failures cannot reset a re-synchronized head. */
  private generation = 0;

  constructor(
    private readonly sink: AuditSink,
    private readonly clock: () => number = Date.now,
  ) {}

  /** Append a record. Serialized so the chain order equals the append order. Rejects if the sink fails. */
  async record(
    type: AuditEventType,
    requestId: string,
    sessionId: string,
    payload: Record<string, unknown>,
  ): Promise<AuditRecord> {
    const { record, persisted } = await this.prepare(type, requestId, sessionId, payload);
    await persisted;
    return record;
  }

  /**
   * Chain and enqueue a record without waiting for a pipelined sink to store it.
   * `persisted` settles once the sink has stored the record (or failed); callers
   * must not act on the record before it resolves.
   */
  prepare(
    type: AuditEventType,
    requestId: string,
    sessionId: string,
    payload: Record<string, unknown>,
  ): Promise<{ record: AuditRecord; persisted: Promise<void> }> {
    const step = this.queue.then(async () => {
      if (!this.head) {
        const last = this.sink.tail ? await this.sink.tail() : undefined;
        this.head = last ? { seq: last.seq, hash: last.hash } : { seq: 0, hash: GENESIS_HASH };
      }
      const payloadJson = canonicalJson(payload);
      const header = {
        seq: this.head.seq + 1,
        timestamp: new Date(this.clock()).toISOString(),
        type,
        requestId,
        sessionId,
        prevHash: this.head.hash,
      };
      const record = deepFreeze({
        ...header,
        payload: JSON.parse(payloadJson) as Record<string, unknown>,
        hash: hashRecordWithPayload(header, payloadJson),
      });
      const generation = this.generation;
      const persisted = this.sink.append(record);
      if (!this.sink.pipelined) await persisted;
      this.head = { seq: record.seq, hash: record.hash };
      return { record, persisted, generation };
    });
    this.queue = step.catch(() => this.resync(this.generation));
    return step.then(({ record, persisted, generation }) => {
      const tracked = persisted.catch((e: unknown) => {
        this.resync(generation);
        throw e;
      });
      // Mark as handled: the caller may await it after other work.
      tracked.catch(() => undefined);
      return { record, persisted: tracked };
    });
  }

  /** Re-read the sink's tail next time: a failed append may or may not have persisted. */
  private resync(generation: number): void {
    if (generation !== this.generation) return;
    this.generation += 1;
    this.head = undefined;
  }
}

export interface ChainVerification {
  readonly valid: boolean;
  /** Index of the first invalid record. */
  readonly brokenAt?: number;
  readonly reason?: string;
}

export function verifyAuditChain(records: readonly AuditRecord[], startHash: string = GENESIS_HASH): ChainVerification {
  let prev = startHash;
  let prevSeq: number | undefined;
  for (let i = 0; i < records.length; i++) {
    const { hash, ...body } = records[i]!;
    if (body.prevHash !== prev) return { valid: false, brokenAt: i, reason: 'prevHash does not match the previous record' };
    if (prevSeq !== undefined && body.seq !== prevSeq + 1) return { valid: false, brokenAt: i, reason: 'sequence gap' };
    if (hashRecord(body) !== hash) return { valid: false, brokenAt: i, reason: 'record content does not match its hash' };
    prev = hash;
    prevSeq = body.seq;
  }
  return { valid: true };
}

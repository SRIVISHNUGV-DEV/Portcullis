// Append-only, hash-chained audit log.
//
// Each record commits to its predecessor's hash, so any edit, deletion or
// reordering is detectable with verifyAuditChain(). This makes the log
// tamper-evident; tamper-proof retention additionally needs WORM/object-lock
// storage or periodic anchoring of the head hash outside the host.

import { appendFile, readFile } from 'node:fs/promises';
import { canonicalJson, deepFreeze, sha256Hex } from './canonical.js';

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
}

export const GENESIS_HASH = '0'.repeat(64);

function hashRecord(record: Omit<AuditRecord, 'hash'>): string {
  return sha256Hex(canonicalJson(record));
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

/** JSON Lines file sink. One record per line, appended with O_APPEND semantics. */
export class JsonlFileAuditSink implements AuditSink {
  constructor(readonly path: string) {}

  async append(record: AuditRecord): Promise<void> {
    await appendFile(this.path, `${JSON.stringify(record)}\n`, { encoding: 'utf8', flag: 'a', mode: 0o600 });
  }

  async tail(): Promise<AuditRecord | undefined> {
    const records = await JsonlFileAuditSink.read(this.path);
    return records[records.length - 1];
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

  constructor(
    private readonly sink: AuditSink,
    private readonly clock: () => number = Date.now,
  ) {}

  /** Append a record. Serialized so the chain order equals the append order. Rejects if the sink fails. */
  record(
    type: AuditEventType,
    requestId: string,
    sessionId: string,
    payload: Record<string, unknown>,
  ): Promise<AuditRecord> {
    const run = this.queue.then(async () => {
      if (!this.head) {
        const last = this.sink.tail ? await this.sink.tail() : undefined;
        this.head = last ? { seq: last.seq, hash: last.hash } : { seq: 0, hash: GENESIS_HASH };
      }
      const body = {
        seq: this.head.seq + 1,
        timestamp: new Date(this.clock()).toISOString(),
        type,
        requestId,
        sessionId,
        payload: JSON.parse(canonicalJson(payload)) as Record<string, unknown>,
        prevHash: this.head.hash,
      };
      const record = deepFreeze({ ...body, hash: hashRecord(body) });
      await this.sink.append(record);
      this.head = { seq: record.seq, hash: record.hash };
      return record;
    });
    this.queue = run.catch(() => {
      // Re-read the sink's tail next time: a failed append may or may not have persisted.
      this.head = undefined;
    });
    return run;
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

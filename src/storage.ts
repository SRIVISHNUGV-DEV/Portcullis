// Durable, low-latency local storage.
//
// GroupCommitFile is an append-only line writer: appends issued while a write is
// in flight are coalesced into the next single write (+ optional fsync), so an
// idle append costs one write and throughput scales with load. JournalSessionStore
// keeps session state in memory and journals every change through it, so reads
// never touch the disk and a restart replays the journal.

import { open, readFile, rename, type FileHandle } from 'node:fs/promises';
import { MemorySessionStore, type SessionState } from './session.js';

export interface GroupCommitOptions {
  /** fdatasync after every batch. Survives power loss; costs roughly one disk flush per batch. Default true. */
  readonly fsync?: boolean;
}

interface QueuedLine {
  readonly line: string;
  readonly resolve: () => void;
  readonly reject: (error: unknown) => void;
}

/**
 * Lines are persisted in call order. After a failed write, every queued and later
 * append rejects until reset(), so a hash-chained log can never persist a record
 * that follows a missing one.
 */
export class GroupCommitFile {
  private handle: FileHandle | undefined;
  private queue: QueuedLine[] = [];
  private flushing: Promise<void> | undefined;
  private failure: Error | undefined;

  constructor(
    readonly path: string,
    private readonly options: GroupCommitOptions = {},
  ) {}

  append(line: string): Promise<void> {
    if (this.failure) return Promise.reject(this.failure);
    return new Promise<void>((resolve, reject) => {
      this.queue.push({ line, resolve, reject });
      this.flushing ??= this.flush();
    });
  }

  /** Clear a previous write failure, after the caller has re-read the file. */
  reset(): void {
    this.failure = undefined;
  }

  async close(): Promise<void> {
    await this.flushing;
    await this.handle?.close();
    this.handle = undefined;
  }

  private async flush(): Promise<void> {
    try {
      while (this.queue.length > 0) {
        const batch = this.queue;
        this.queue = [];
        try {
          this.handle ??= await open(this.path, 'a', 0o600);
          let data = '';
          for (const item of batch) data += `${item.line}\n`;
          await this.handle.writeFile(data, 'utf8');
          if (this.options.fsync ?? true) await this.handle.datasync();
          for (const item of batch) item.resolve();
        } catch (e) {
          this.failure = e instanceof Error ? e : new Error(String(e));
          for (const item of [...batch, ...this.queue]) item.reject(this.failure);
          this.queue = [];
          await this.handle?.close().catch(() => undefined);
          this.handle = undefined;
        }
      }
    } finally {
      this.flushing = undefined;
    }
  }
}

function encodeState(state: SessionState): string {
  return JSON.stringify(state, (_key, value: unknown) => (typeof value === 'bigint' ? { $bigint: value.toString() } : value));
}

function decodeState(line: string): SessionState {
  return JSON.parse(line, (_key, value: unknown) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const v = value as Record<string, unknown>;
      if (typeof v.$bigint === 'string' && Object.keys(v).length === 1) return BigInt(v.$bigint);
    }
    return value;
  }) as SessionState;
}

/**
 * Session store with in-memory reads and a group-committed journal. A transaction
 * resolves only after its new state is written, and unchanged states are not
 * rewritten. Single process only: run one instance per journal file.
 */
export class JournalSessionStore extends MemorySessionStore {
  private readonly lastWritten = new Map<string, string>();

  private constructor(
    private readonly writer: GroupCommitFile,
    states: Map<string, SessionState>,
  ) {
    super(states);
    for (const [id, state] of states) this.lastWritten.set(id, encodeState(state));
  }

  /** Replay the journal at `path` (latest state per session wins), compact it, and open it for appends. */
  static async open(path: string, options: GroupCommitOptions = {}): Promise<JournalSessionStore> {
    const states = new Map<string, SessionState>();
    let text = '';
    try {
      text = await readFile(path, 'utf8');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
    const lines = text.split('\n').filter((l) => l.trim().length > 0);
    lines.forEach((line, i) => {
      let state: SessionState;
      try {
        state = decodeState(line);
      } catch (e) {
        // A torn final line is an append that never completed, so it was never acknowledged.
        if (i === lines.length - 1) return;
        throw new Error(`Corrupt session journal ${path} at line ${i + 1}: ${(e as Error).message}`);
      }
      states.set(state.id, state);
    });

    const tmp = `${path}.compact`;
    const handle = await open(tmp, 'w', 0o600);
    try {
      let data = '';
      for (const state of states.values()) data += `${encodeState(state)}\n`;
      await handle.writeFile(data, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(tmp, path);
    return new JournalSessionStore(new GroupCommitFile(path, options), states);
  }

  protected override persist(state: SessionState): Promise<void> | void {
    const line = encodeState(state);
    if (this.lastWritten.get(state.id) === line) return;
    // Recorded at enqueue time: writes are ordered, and after a failure every later write fails too.
    this.lastWritten.set(state.id, line);
    return this.writer.append(line);
  }

  close(): Promise<void> {
    return this.writer.close();
  }
}

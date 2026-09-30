import { createHash } from 'crypto';
import type { AuditEntry, CreateAuditEntryInput } from './types';

export interface IdempotencyRecord {
  bodyHash: string;
  response: AuditEntry;
  createdAt: number;
}

export interface IdempotencyStoreOptions {
  maxSize?: number;
  ttlMs?: number;
  /**
   * Optional clock injection for deterministic testing of TTL/expiry behavior.
   * Defaults to Date.now.
   */
  now?: () => number;
}

export interface IdempotencyResolution {
  /** True when the record was produced by this call (not a cache hit). */
  created: boolean;
  /** True when an existing record was returned for the same key. */
  replayed: boolean;
  /** True when the same key was reused with a different request body. */
  conflict: boolean;
  record: IdempotencyRecord;
}

export class IdempotencyConflictError extends Error {
  readonly code = 'IDEMROTENCY_CONFLICT';
  constructor(readonly key: string) {
    super(
      `Idempotency key ${key} was reused with a different request body`,
    );
    this.name = 'IdempotencyConflictError';
  }
}

const DEFAULT_MAX_SIZE = 1000;
const DEFAULT_TTL_MS = 86_400_000;

function hashBody(input: CreateAuditEntryInput): string {
  const payload = JSON.stringify({
    action: input.action,
    severity: input.severity,
    actor: input.actor,
    resource: input.resource,
    resourceId: input.resourceId,
    metadata: input.metadata,
  });
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * In-memory idlempotency store for audit export operations.
 *
 * Invariants:
 * - A given key maps to at most one record at any time.
 * - Records are immutable once written.
 * - Expired records are never returned and are evicted lazily.
 * - Concurrent callers observe a consistent snapshot because JavaScript execution
 *   is single-threaded and this class performs no await yields between read and write.
 */
export class IdempotencyStore {
  private readonly store = new Map<string, IdempotencyRecord>();
  private readonly maxSize: number;
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(options: IdempotencyStoreOptions = {}) {
    this.maxSize = Math.max(1, Math.floor(options.maxSize ?? DEFAULT_MAX_SIZE));
    this.ttlMs = Math.max(0, options.ttlMs ?? DEFAULT_TTL_MS);
    this.now = options.now ?? (() => Date.now());
  }

  get(key: string): IdempotencyRecord | undefined {
    const record = this.store.get(key);
    if (!record) {
      return undefined;
    }

    if (this.isExpired(record)) {
      this.store.delete(key);
      return undefined;
    }

    return record;
  }

  /**
   * Returns the existing record for a key if it matches the supplied body,
   * otherwise undefined. Throws when the key is reused with a different body.
   */
  check(key: string, input: CreateAuditEntryInput): IdempotencyRecord | undefined {
    const record = this.get(key);
    if (!record) {
      return undefined;
    }

    if (record.bodyHash !== hashBody(input)) {
      throw new IdempotencyConflictError(key);
    }

    return record;
  }

  /**
   * Atomically resolves a key: returns an existing record or creates and
   * stores one. The read-and-write happens without any await yield, so concurrent
   * callers in the same event loop cannot interleave and duplicate work.
   */
  resolve(
    key: string,
    input: CreateAuditEntryInput,
    create: () => AuditEntry,
  ): IdempotencyResolution {
    const existing = this.get(key);
    if (existing) {
      if (existing.bodyHash !== hashBody(input)) {
        throw new IdempotencyConflictError(key);
      }
      return { created: false, replayed: true, conflict: false, record: existing };
    }

    const response = create();
    const record: IdempotencyRecord = {
      bodyHash: hashBody(input),
      response,
      createdAt: this.now(),
    };
    this.write(key, record);
    return { created: true, replayed: false, conflict: false, record };
  }

  set(key: string, input: CreateAuditEntryInput, response: AuditEntry): void {
    this.write(key, {
      bodyHash: hashBody(input),
      response,
      createdAt: this.now(),
    });
  }

  delete(key: string): void {
    this.store.delete(key);
  }

  size(): number {
    this.evictExpired();
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }

  private write(key: string, record: IdempotencyRecord): void {
    this.evictExpired();

    // Refresh existing keys without growing the store or evicting an unrelated key.
    if (this.store.has(key)) {
      this.store.delete(key);
    } else if (this.store.size >= this.maxSize) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey !== undefined) {
        this.store.delete(oldestKey);
      }
    }

    this.store.set(key, record);
  }

  private isExpired(record: IdempotencyRecord): boolean {
    return this.now() - record.createdAt > this.ttlMs;
  }

  private evictExpired(): void {
    const now = this.now();
    for (const [key, record] of this.store) {
      if (now - record.createdAt > this.ttlMs) {
        this.store.delete(key);
      }
    }
  }
}

export function hashIdempotencyInput(input: CreateAuditEntryInput): string {
  return hashBody(input);
}

export const idempotencyStore = new IdempotencyStore();

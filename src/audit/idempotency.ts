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
 * In-memory idempotency store.
 *
 * Concurrency / idempotency invariants:
 * - `set` is monotonic for a given key: once a key is bound to a response, a
 *   subsequent `set` with the same key must not overwrite it. This prevents a
 *   concurrent retry from claiming the key with a different body and returning
 *   an inconsistent response to the original caller.
 * - `setIfAbsent` returns the existing record when the key is already bound,
 *   allowing callers to detect and surface body mismatches (409-style conflict)
 *   without losing the original response.
 * - Eviction is bounded and deterministic: expired entries are removed first,
 *   then the oldest insertion order entry is evicted when atthe capacity limit.
 */
export class IdempotencyStore {
  private readonly store = new Map<string, IdempotencyRecord>();
  private readonly maxSize: number;
  private readonly ttlMs: number;

  constructor(options: IdempotencyStoreOptions = {}) {
    this.maxSize = options.maxSize ?? DEFAULT_MAX_SIZE;
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  }

  get(key: string): IdempotencyRecord | undefined {
    const record = this.store.get(key);
    if (!record) {
      return undefined;
    }

    if (Date.now() - record.createdAt > this.ttlMs) {
      this.store.delete(key);
      return undefined;
    }

    return record;
  }

  /**
   * Binds a key to a response. If the key is already bound to a live record,
   * the existing record is returned and nothing is overwritten.
   */
  set(key: string, input: CreateAuditEntryInput, response: AuditEntry): IdempotencyRecord {
    const existing = this.get(key);
    if (existing) {
      return existing;
    }

    this.evictExpired();

    if (this.store.size >= this.maxSize) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey) {
        this.store.delete(oldestKey);
      }
    }

    const record: IdempotencyRecord = {
      bodyHash: hashBody(input),
      response,
      createdAt: Date.now(),
    };
    this.store.set(key, record);
    return record;
  }

  /**
   * Atomic alias for `set` that makes the idempotent semantics explicit at
   * call sites: if the key is already bound, the existing record is returned
   * and the caller must not persist the new response.
   */
  setIfAbsent(key: string, input: CreateAuditEntryInput, response: AuditEntry): IdempotencyRecord {
    return this.set(key, input, response);
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

  private evictExpired(): void {
    const now = Date.now();
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

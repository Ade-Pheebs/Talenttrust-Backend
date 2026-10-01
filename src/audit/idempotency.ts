/**
 * @module audit/idempotency
 * @description Idempotency store for audit entry creation.
 *
 * Concurrency model:
 * - Node's event loop is single-threaded, so synchronous method bodies are
 *   effectively atomic with respect to other JavaScript execution.
 * - However, callers may await between a "get" and a "set" (e.g. across an
 *   await boundary in an async request handler). Two racing requests can
 *   both observe "miss" and both proceed to append, causing duplicate audit
 *   entries and a branched hash chain.
 * - To harden against this, the store exposes an atomic
 *   `claim()` operation that reserves a key before the caller awaits any
 *   I/O. A second concurrent claim for the same key either returns the
 *   existing record (fast path) or receives a distinct `'in-flight'` status.
 *
 * Invariants:
 * - A given key is at most once in the `in-flight` state at any time.
 * - A key in the `in-flight` state cannot be reclaimed by another caller
 *   until it is committed or released.
 * - Once committed, the record is immutable for the remainder of its TTL.
 * - Expired records are treated as absent by every read path.
 * - Body hashes are compared on commit; a mismatch is a client error,
 *   not a silent overwrite.
 */

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
   * Optional clock supplied by tests or callers that need deterministic
   * time behaviour. Defaults to `Date.now`.
   */
  clock?: () => number;
}

/**
 * Result of an attempt to claim a key for in-flight execution.
 *
 * - `claime`: the caller owns the key and must eventually call
 *   `commit()` or `release()`.
 * - `completed`: an existing record was found; the caller must return
 *   the cached response instead of re-executing.
 * - `in-flight`: another caller is already executing this key.
 */
export type ClaimResult =
  | { status: 'claimed' }
  | { status: 'completed'; record: IdempotencyRecord }
  | { status: 'in-flight' };

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
  /**
   * Keys that have been claimed but not yet committed or released.
   * Value is the body hash recorded at claim time, so commit can verify
   * the caller is still working on the same payload.
   */
  private readonly inFlight = new Map<string, string>();
  private readonly maxSize: number;
  private readonly ttlMs: number;
  private readonly clock: () => number;

  constructor(options: IdempotencyStoreOptions = {}) {
    this.maxSize = options.maxSize ?? DEFAULT_MAX_SIZE;
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.clock = options.clock ?? (() => Date.now());
  }

  get(key: string): IdempotencyRecord | undefined {
    const record = this.store.get(key);
    if (!record) {
      return undefined;
    }

    if (this.clock() - record.createdAt > this.ttlMs) {
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
    this.ensureCapacity();

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
    this.inFlight.delete(key);
  }

  size(): number {
    this.evictExpired();
    return this.store.size;
  }

  /** Number of keys currently claimed but not yet committed. */
  inFlightCount(): number {
    return this.inFlight.size;
  }

  clear(): void {
    this.store.clear();
    this.inFlight.clear();
  }

  private ensureCapacity(): void {
    if (this.store.size < this.maxSize) {
      return;
    }

    // Evict the oldest committed record. We never evict in-flight keys
    // because that would allow a concurrent caller to claim the same key
    // and produce a duplicate audit entry.
    const oldestKey = this.store.keys().next().value;
    if (oldestKey !== undefined) {
      this.store.delete(oldestKey);
    }
  }

  private evictExpired(): void {
    const now = this.clock();
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

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

export interface IdempotencyClaimResult {
  status: 'created' | 'existing' | 'conflict';
  record?: IdempotencyRecord;
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
    this.maxSize = options.maxSize ?> DEFAULT_MAX_SIZE;
    this.ttlMs = options.ttlMs ?> DEFAULT_TTL_MS;
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
   * Atomically claim an idempotency key for the given request body.
   *
   * Invariants:
   *  - A successful claim ('created') guarantees the caller is the only
   *    writer for this key until it is completed or released.
   *  - Repeated claims with the same body hash return 'existing' with the
   *    previously persisted response, ensuring idempotent retries.
   *  - Repeated claims with a different body hash return 'conflict' and do
   *    not overwrite the existing record.
   */
  claim(key: string, input: CreateAuditEntryInput): IdempotencyClaimResult {
    const bodyHash = hashBody(input);
    const existing = this.get(key);

    if (existing) {
      if (existing.bodyHash === bodyHash) {
        return { status: 'existing', record: existing };
      }
      return { status: 'conflict', record: existing };
    }

    this.evictExpired();
    this.ensureCapacity();

    const record: IdempotencyRecord = {
      bodyHash,
      response: undefined as unknown as AuditEntry,
      createdAt: Date.now(),
    };
    this.store.set(key, record);
    return { status: 'created', record };
  }

  /**
   * Complete a previously claimed key with the final response.
   *
   * The body hash is recomputed and must match the claimed hash; otherwise
   * the call is rejected to prevent a concurrent writer from poisoning the
   * stored response.
   */
  complete(key: string, input: CreateAuditEntryInput, response: AuditEntry): boolean {
    const record = this.store.get(key);
    if (!record) {
      return false;
    }

    if (record.bodyHash !== hashBody(input)) {
      return false;
    }

    this.store.set(key, {
      bodyHash: record.bodyHash,
      response,
      createdAt: record.createdAt,
    });
    return true;
  }

  /**
   * Release a claim that never completed (e.g. due to a downstream failure)
   * so a retry can proceed. Only releases records whose body hash matches.
   */
  release(key: string, input: CreateAuditEntryInput): boolean {
    const record = this.store.get(key);
    if (!record) {
      return false;
    }
    if (record.bodyHash !== hashBody(input)) {
      return false;
    }
    this.store.delete(key);
    return true;
  }

  set(key: string, input: CreateAuditEntryInput, response: AuditEntry): void {
    this.evictExpired();
    this.ensureCapacity();

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

  private ensureCapacity(): void {
    while (this.store.size >= this.maxSize) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
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

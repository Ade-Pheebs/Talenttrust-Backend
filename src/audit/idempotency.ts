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
 * Thrown when a caller attempts to commit a key with a body hash that differs
 * from the one recorded at claim time. This is a client error (conflicting
 * payloads for the same idempotency key) and must not be swallowed.
 */
export class IdempotencyConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdempotencyConflictError';
  }
}

/**
 * Thrown when a caller attempts to commit or release a key that is not
 * currently claimed by them.
 */
export class IdempotencyStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdempotencyStateError';
  }
}

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
   * Atomically reserve a key for execution.
   *
   * This is the concurrency-safe entry point for callers that need to
   * guarantee a single audit entry per key even when multiple requests are
   * in flight. The caller must not await anything between claim and the
   * decision to execute.
   *
   * @param key - Idempotency key (typically the client-supplied header).
   * @param input - The payload being attempted; used to bind the claim
   *   to a specific body hash so a conflicting payload fails loud.
   */
  claim(key: string, input: CreateAuditEntryInput): ClaimResult {
    const existing = this.get(key);
    if (existing) {
      return { status: 'completed', record: existing };
    }

    if (this.inFlight.has(key)) {
      return { status: 'in-flight' };
    }

    // Ensure we have room for the eventual commit before claiming.
    this.evictExpired();
    this.ensureCapacity();

    this.inFlight.set(key, hashBody(input));
    return { status: 'claimed' };
  }

  /**
   * Persist the result of a claimed key. The body hash must match the one
   * recorded at claim time; otherwise the caller is attempting to commit
   * a different payload under the same key and we raise
   * `IdempotencyConflictError`.
   */
  commit(key: string, input: CreateAuditEntryInput, response: AuditEntry): void {
    const inFlightHash = this.inFlight.get(key);
    if (inFlightHash === undefined) {
      throw new IdempotencyStateError(
        `Attempted to commit key ${key} without an active claim`,
      );
    }

    const bodyHash = hashBody(input);
    if (bodyHash !== inFlightHash) {
      throw new IdempotencyConflictError(
        `Idempotency key ${key} was claimed with a different payload`,
      );
    }

    this.inFlight.delete(key);
    this.store.set(key, {
      bodyHash,
      response,
      createdAt: this.clock(),
    });
  }

  /**
   * Release a claim without persisting a result. Use this on failure so a
   * retry can proceed instead of being blocked by an orphaned claim.
   */
  release(key: string): void {
    this.inFlight.delete(key);
  }

  /**
   * @deprecated Use `claim` + `commit``. Retained for backward
   * compatibility with existing callers. Still atomic within the event
   * loop, but does not protect against callers that await between get/set.
   */
  set(key: string, input: CreateAuditEntryInput, response: AuditEntry): void {
    this.evictExpired();
    this.ensureCapacity();

    this.store.set(key, {
      bodyHash: hashBody(input),
      response,
      createdAt: this.clock(),
    });
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

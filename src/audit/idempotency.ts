/**
 * @module audit/idempotency
 * @description Deterministic, failure-recoverable idempotency store for the
 * audit write path.
 *
 * ## Why this exists
 * A state-changing request that is retried (network timeout, client retry,
 * duplicate delivery) must not create a second audit entry, and a request that
 * *failed mid-flight* must not permanently poison its idempotency key. This
 * module models the lifecycle explicitly:
 *
 * ```
 *   absent ──reserve()──▶ in_progress ──complete()──▶ completed ──TTL──▶ absent
 *                              │
 *                              └──release()──────────▶ absent   (error path)
 * ```
 *
 * ## Invariants
 * 1. **Single writer per key.** `reserve()` performs the check-and-insert in a
 *    single synchronous step with no `await` between the read and the write, so
 *    two overlapping requests on the same key can never both win. A distributed
 *    backend would use an atomic `INSERT ... ON CONFLICT DO NOTHING` / CAS.
 * 2. **Fenced completion.** `complete()` and `release()` require the opaque
 *    `token` handed out by `reserve()`. A stale owner (whose reservation has
 *    expired and been re-won) can never overwrite the record of the new owner.
 * 3. **Payload binding.** A key reserved/completed for one request body may
 *    never be completed with a different body; the stored body hash is taken
 *    from the reservation, not re-supplied by the caller.
 * 4. **Deterministic hashing.** `hashIdempotencyInput` canonicalises JSON
 *    (recursively sorted object keys) so semantically equal inputs always hash
 *    identically regardless of property insertion order.
 * 5. **Deterministic eviction.** When bounded capacity is reached the oldest
 *    completed record is evicted; ties are broken lexicographically by key so
 *    the outcome does not depend on `Map` iteration subtleties.
 * 6. **Observability without leakage.** Counters and optional events describe
 *    what happened; events carry a SHA-256 of the key, never the key, the
 *    request body, or the audit metadata itself. An event sink that throws can
 *    never corrupt store state.
 *
 * @security Idempotency keys are treated as non-secret opaque identifiers, but
 * are never echoed into events/logs in cleartext. Audit responses are stored by
 * reference (they are already frozen by the audit store); no PII is copied.
 */

import { createHash, randomUUID } from 'crypto';
import type { AuditEntry, CreateAuditEntryInput } from './types';

/**
 * A completed idempotent operation, replayable for a duplicate request.
 *
 * @remarks Kept backward compatible: `bodyHash`, `response` and `createdAt`
 * retain their original meaning. `expiresAt` makes the TTL explicit so callers
 * can reason about the deadline without re-deriving it from options.
 */
export interface IdempotencyRecord {
  bodyHash: string;
  response: AuditEntry;
  createdAt: number;
  /** Epoch-millisecond deadline; the record is expired at `now >= expiresAt`. */
  expiresAt: number;
}

/** Observability event emitted by the store. Never contains raw key or body. */
export type IdempotencyEventType =
  | 'reserved'
  | 'replay'
  | 'in_progress'
  | 'conflict'
  | 'completed'
  | 'released'
  | 'expired'
  | 'evicted'
  | 'cleared';

export interface IdempotencyEvent {
  type: IdempotencyEventType;
  /** SHA-256 hex digest of the key — safe to log, not reversible to the key. */
  keyHash: string;
  at: number;
}

/** Cumulative counters; useful for metrics export and alerting. */
export interface IdempotencyStoreStats {
  /** Lookups that found a live completed record. */
  hits: number;
  /** Lookups that found nothing live. */
  misses: number;
  /** Duplicate requests whose response was replayed. */
  replays: number;
  /** Same key reused with a different request body. */
  conflicts: number;
  /** Successful `reserve()` calls (new in-progress states). */
  reservations: number;
  /** Successful `complete()`/`set()` transitions. */
  completions: number;
  /** Explicit `release()` recoveries (error path). */
  releases: number;
  /** Records/reservations reclaimed because their TTL elapsed. */
  expirations: number;
  /** Completed records dropped to respect `maxSize`. */
  evictions: number;
  /** State-transition invariant violations (invalid key / stale token). */
  failures: number;
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

/** Typed error codes for deterministic, user-visible failure ordering. */
export type IdempotencyErrorCode = 'invalid_key' | 'stale_reservation' | 'reservation_not_found';

export class IdempotencyStoreError extends Error {
  constructor(
    public readonly code: IdempotencyErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'IdempotencyStoreError';
  }
}

/** Outcome of an atomic {@link IdempotencyStore.reserve} call. */
export type IdempotencyReserveResult =
  | { kind: 'reserved'; token: string }
  | { kind: 'replay'; record: IdempotencyRecord }
  | { kind: 'in_progress' }
  | { kind: 'conflict' };

const DEFAULT_MAX_SIZE = 1000;
const DEFAULT_TTL_MS = 86_400_000;
const DEFAULT_RESERVATION_TTL_MS = 30_000;

interface Reservation {
  bodyHash: string;
  token: string;
  createdAt: number;
  expiresAt: number;
}

/**
 * Canonicalises an arbitrary JSON-ish value into a stable string.
 *
 * Object keys are sorted, `undefined` object members are dropped (matching
 * `JSON.stringify`), non-finite numbers become `null`, and array holes /
 * `undefined` elements become `null`. Two structurally equal values therefore
 * always produce byte-identical output regardless of key order.
 */
function canonicalize(value: unknown): string {
  if (value === null) {
    return 'null';
  }

  const valueType = typeof value;

  if (valueType === 'string') {
    return JSON.stringify(value);
  }
  if (valueType === 'number') {
    return Number.isFinite(value as number) ? String(value) : 'null';
  }
  if (valueType === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (valueType === 'undefined') {
    return 'null';
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  }

  if (valueType === 'object') {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record)
      .filter((key) => record[key] !== undefined)
      .sort();
    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`)
      .join(',')}}`;
  }

  // Functions and symbols are not serialisable; collapse them deterministically.
  return 'null';
}

function hashBody(input: CreateAuditEntryInput): string {
  const payload = canonicalize({
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
  /** Completed records only — exactly the legacy public shape. */
  private readonly store = new Map<string, IdempotencyRecord>();
  /** In-flight reservations, keyed identically. */
  private readonly reservations = new Map<string, Reservation>();

  private readonly maxSize: number;
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(options: IdempotencyStoreOptions = {}) {
    this.maxSize = Math.max(1, Math.floor(options.maxSize ?? DEFAULT_MAX_SIZE));
    this.ttlMs = Math.max(0, options.ttlMs ?? DEFAULT_TTL_MS);
    this.now = options.now ?? (() => Date.now());
  }

  /**
   * Returns a live completed record for `key`, or `undefined`.
   *
   * Expired records are reclaimed lazily and count as a miss. Never throws —
   * treat it as a best-effort read.
   */
  get(key: string): IdempotencyRecord | undefined {
    if (typeof key !== 'string' || key.length === 0) {
      this._stats.failures += 1;
      return undefined;
    }

    const record = this.readLiveRecord(key, this.clock());
    if (!record) {
      this._stats.misses += 1;
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
    this._stats.reservations += 1;
    this.emit('reserved', key, now);
    return { kind: 'reserved', token };
  }

  /**
   * Transition a reservation to `completed`, storing `response` for replay.
   *
   * The body hash is taken from the reservation, so the payload cannot change
   * between reserve and complete.
   *
   * @throws {IdempotencyStoreError} `stale_reservation` when `token` does not
   * own a live reservation for `key` (e.g. it timed out and a retry took over).
   */
  complete(key: string, token: string, response: AuditEntry): IdempotencyRecord {
    this.assertKey(key);
    if (typeof token !== 'string' || token.length === 0) {
      this._stats.failures += 1;
      throw new IdempotencyStoreError('stale_reservation', 'Reservation token is required');
    }

    const now = this.clock();
    const reservation = this.reservations.get(key);

    if (!reservation || this.isReservationExpired(reservation, now)) {
      if (reservation) {
        this.reservations.delete(key);
        this._stats.expirations += 1;
        this.emit('expired', key, now);
      }
      this._stats.failures += 1;
      this.emit('conflict', key, now);
      throw new IdempotencyStoreError(
        'stale_reservation',
        'Cannot complete: reservation is missing or has expired',
      );
    }

    if (reservation.token !== token) {
      // A newer owner won the key; do not let the stale owner clobber it.
      this._stats.failures += 1;
      this.emit('conflict', key, now);
      throw new IdempotencyStoreError(
        'stale_reservation',
        'Cannot complete: reservation is owned by another request',
      );
    }

    this.reservations.delete(key);
    const record = this.writeCompleted(key, reservation.bodyHash, response, now);
    this._stats.completions += 1;
    this.emit('completed', key, now);
    return record;
  }

  /**
   * Release an in-progress reservation so a retry can re-attempt the operation.
   *
   * Safe to call more than once and on an already-expired reservation: the
   * return value reports whether state changed, and no error is raised on the
   * recovery path. Completed records are never removed by this call.
   */
  release(key: string, token: string): boolean {
    if (typeof key !== 'string' || key.length === 0 || typeof token !== 'string') {
      this._stats.failures += 1;
      return false;
    }

    const now = this.clock();
    const reservation = this.reservations.get(key);
    if (!reservation || reservation.token !== token) {
      return false;
    }

    this.reservations.delete(key);
    this._stats.releases += 1;
    this.emit('released', key, now);
    return true;
  }

  /**
   * Backward-compatible direct write of a completed record.
   *
   * Overwrites any existing record for `key` (matching historical semantics)
   * and clears any in-flight reservation. Prefer `reserve`/`complete` for new
   * code so failures remain recoverable.
   */
  set(key: string, input: CreateAuditEntryInput, response: AuditEntry): void {
    this.assertKey(key);
    const now = this.clock();
    this.reservations.delete(key);
    this.writeCompleted(key, hashBody(input), response, now);
    this._stats.completions += 1;
    this.emit('completed', key, now);
  }

  delete(key: string): void {
    this.store.delete(key);
    this.reservations.delete(key);
  }

  /** Number of live completed records (expired entries are reclaimed first). */
  size(): number {
    this.evictExpired(this.clock());
    return this.store.size;
  }

  /** Number of live in-progress reservations (abandoned ones are reclaimed). */
  pendingCount(): number {
    this.evictExpired(this.clock());
    return this.reservations.size;
  }

  clear(): void {
    this.store.clear();
    this.reservations.clear();
    this.emit('cleared', '', this.clock());
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
      if (this.isRecordExpired(record, now)) {
        this.store.delete(key);
        purged += 1;
        this._stats.expirations += 1;
        this.emit('expired', key, now);
      }
    }

    for (const [key, reservation] of this.reservations) {
      if (this.isReservationExpired(reservation, now)) {
        this.reservations.delete(key);
        purged += 1;
        this._stats.expirations += 1;
        this.emit('expired', key, now);
      }
    }

    return purged;
  }

  /**
   * Drops the oldest completed record when at capacity.
   *
   * Never evicts the key currently being written, and breaks `createdAt` ties
   * lexicographically by key so eviction is deterministic across runs.
   */
  private evictOldestIfNeeded(incomingKey: string): void {
    if (this.store.size < this.maxSize || this.store.has(incomingKey)) {
      return;
    }

    let oldestKey: string | undefined;
    let oldestAt = Number.POSITIVE_INFINITY;

    for (const [key, record] of this.store) {
      if (
        record.createdAt < oldestAt ||
        (record.createdAt === oldestAt && oldestKey !== undefined && key < oldestKey)
      ) {
        oldestAt = record.createdAt;
        oldestKey = key;
      }
    }

    if (oldestKey !== undefined) {
      this.store.delete(oldestKey);
      this._stats.evictions += 1;
      this.emit('evicted', oldestKey, this.clock());
    }
  }

  private emit(type: IdempotencyEventType, key: string, at: number): void {
    if (!this.onEvent) {
      return;
    }
    try {
      this.onEvent({ type, keyHash: hashKey(key), at });
    } catch {
      // An observability sink must never break the request path; state is
      // already consistent at this point, so swallow the failure.
    }
  }
}

/** Deterministic, order-independent hash of the fields that define a request body. */
export function hashIdempotencyInput(input: CreateAuditEntryInput): string {
  return hashBody(input);
}

export const idempotencyStore = new IdempotencyStore();

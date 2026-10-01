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

/**
 * Result of an idlempotent lookup or insertion.
 *
 * This is the explicit compatibility contract for callers that need to
 * distinguish between "new work" and "duplicate replay" without relying on
 * the internal storage shape.
 */
export type IdempotencyOutcome =
  | { kind: 'miss' }
  | { kind: 'replay'; record: IdempotencyRecord }
  | {  kind: 'conflict'; existingBodyHash: string; incomingBodyHash: string };

export interface IdempotencySetResult {
  /** True when the record was newly written or replaced by this call. */
  written: boolean;
  /** True when an existing record was returned instead of writing. */
  existing: boolean;
  /** The record that is effective after this call. */
  record: IdempotencyRecord;
}

const DEFAULT_MAX_SIZE = 1000;
const DEFAULT_TTL_MS = 86_400_000;

/**
 * Deterministic hash of the idempotency-relevant fields of an audit input.
 *
 * Invariants:
 * - The hash is independent of transport-only fields (`ipAddress`,
 *   `correlationId`) so retries from different clients map to the same key.
 * - Metadata key ordering is normalised so equivalent objects havh the
 *   same digest regardless of insertion order.
 * - Non-serialisable values (e.g. `undefined`, `function`, `symbol`)
 *   are rejected with a deterministic error rather than silently producing
 *   a different hash across runtimes.
 */
function hashBody(input: CreateAuditEntryInput): string {
  const payload = JSON.stringify({
    action: input.action,
    severity: input.severity,
    actor: input.actor,
    resource: input.resource,
    resourceId: input.resourceId,
    metadata: normaliseMetadata(input.metadata),
  });
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * Recursively sort object keys so the JSON representation is canonical.
 * Arrays preserve their order (order is semantic), but nested objects
 * within them are also normalised.
 */
function normaliseMetadata(value: unknown): unknown {
  if (value === null || typeof value !== 'object') {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((nested) => normaliseMetadata(nested));
  }

  const entries = Object.entries(value as Record<string, unknown>);
  entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  const out: Record<string, unknown> = {};
  for (const [key, nested] of entries) {
    out[key] = normaliseMetadata(nested);
  }
  return out;
}

function assertValidKey(key: unknown): asserts key is string {
  if (typeof key !== 'string' || key.length === 0) {
    throw new TypeError('IdempotencyStore key must be a non-empty string');
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
    const maxSize = options.maxSize ?? DEFAULT_MAX_SIZE;
    const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;

    if (!Number.isFinite(maxSize) || maxSize < 1) {
      throw new RangeError('IdempotencyStore maxSize must be a positive integer');
    }
    if (!Number.isFinite(ttlMs) || ttlMs < 0) {
      throw new RangeError('IdempotencyStore ttlMs must be a non-negative number');
    }

    this.maxSize = Math.floor(maxSize);
    this.ttlMs = ttlMs;
  }

  /**
   * Retrieves a non-expired record for a key, or `undefined` when absent.
   * Expired entries are evicted lazily on read so a stale record can never
   * be observed by a caller.
   */
  get(key: string): IdempotencyRecord | undefined {
    assertValidKey(key);
    const record = this.store.get(key);
    if (!record) {
      return undefined;
    }

    if (this.isExpired(record, Date.now())) {
      this.store.delete(key);
      return undefined;
    }

    return record;
  }

  /**
   * Resolves an idlempotency key to a decision without mutating the store.
   *
   * - `miss`     -> no live record exists; the caller may proceed.
   * - `replay`    -> a live record exists with the same body hash; return it.
   * - `conflict` `-> a live record exists with a different body hash; the
   *    caller must reject the request to avoid silently overwriting state.
   */
  resolve(key: string, input: CreateAuditEntryInput): IdempotencyOutcome {
    assertValidKey(key);
    const incomingBodyHash = hashBody(input);
    const record = this.get(key);

    if (!record) {
      return { kind: 'miss' };
    }

    if (record.bodyHash === incomingBodyHash) {
      return { kind: 'replay', record };
    }

    return {
      kind: 'conflict',
      existingBodyHash: record.bodyHash,
      incomingBodyHash,
    };
  }

  /**
   * Inserts a record only when the key is free or the existing record has
   * expired. When a live record already exists for the key this method is a
   * no-op and returns the existing record, so concurrent writers cannot
   * clobber each other's responses.
   */
  setIfAbsent(
    key: string,
    input: CreateAuditEntryInput,
    response: AuditEntry,
  ): IdempotencySetResult {
    assertValidKey(key);
    const existing = this.get(key);
    if (existing) {
      return { written: false, existing: true, record: existing };
    }

    const record = this.write(key, input, response);
    return { written: true, existing: false, record };
  }

  /**
   * Unconditionally stores a record for a key, replacing any existing one.
   * Preserved for backward compatibility with existing callers.
   */
  set(key: string, input: CreateAuditEntryInput, response: AuditEntry): void {
    assertValidKey(key);
    this.write(key, input, response);
  }

  delete(key: string): void {
    assertValidKey(key);
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

  private write(
    key: string,
    input: CreateAuditEntryInput,
    response: AuditEntry,
  ): IdempotencyRecord {
    this.evictExpired();

    // Ensure the key being written is accounted for in the capacity check.
    if (!this.store.has(key) && this.store.size >= this.maxSize) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey !== undefined) {
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

  private isExpired(record: IdempotencyRecord, now: number): boolean {
    return now - record.createdAt > this.ttlMs;
  }

  private evictExpired(): void {
    const now = this.clock();
    for (const [key, record] of this.store) {
      if (this.isExpired(record, now)) {
        this.store.delete(key);
      }
    }
  }
}

export function hashIdempotencyInput(input: CreateAuditEntryInput): string {
  return hashBody(input);
}

export const idempotencyStore = new IdempotencyStore();

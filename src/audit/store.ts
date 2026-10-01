/**
 * @module audit/store
 * @description Append-only, tamper-evident in-memory audit log store.
 *
 * Security properties:
 * - Entries are frozen (Object.freeze) immediately on insertion — no mutation possible.
 * - A SHA-256 hash chain links every entry to its predecessor; any tampering breaks
 *   the chain and is detected by verifyIntegrity().
 * - The internal log array is never exposed directly; only copies are returned.
 * - No entry can be deleted or updated — the store is strictly append-only.
 *
 * Production note: Replace the in-memory array with a write-once database table
 * (e.g. PostgreSQL with row-level security and no UPDATE/DELETE grants) while
 * keeping this interface contract intact.
 *
 * Public contract (issue #1380) — this is asserted by `store.contract.test.ts`
 * and must stay identical to `SqliteAuditRepository`, because callers select a
 * backend via `AUDIT_STORAGE_BACKEND` and must not observe different behaviour:
 *   - `append`    returns the frozen entry and is the only mutator.
 *   - `getAll`    returns a new array of the same frozen entries.
 *   - `getById`   returns `undefined` for an unknown id (never throws).
 *   - `count`     is the number of appended entries.
 *   - `query`     returns matches in insertion order; empty store -> `[]`.
 *   - `queryWithCursor` clamps `limit` to [1, 100] (default 50); an
 *     *undecodable* cursor is recoverable and restarts at the first page,
 *     while a cursor whose filters do not match the query is a contract
 *     violation and throws (a client must never silently receive a page
 *     computed against different filters).
 *   - `verifyIntegrity` on an empty store -> `{ valid: true, totalEntries: 0 }`.
 */

import { createHash, randomUUID } from 'crypto';
import type { AuditEntry, AuditQuery, CreateAuditEntryInput, IntegrityReport, AuditQueryResult, CursorData } from './types';
import { encodeCursor, decodeCursor } from './types';
import type { AuditLogRepository } from './repository';

/** Sentinel hash used as the previousHash of the very first entry. */
export const GENESIS_HASH = 'GENESIS';

/**
 * Thrown (as a plain `Error` carrying this exact message) when a cursor was
 * produced under different filters than the query that presented it.
 *
 * Exported and shared with {@link SqliteAuditRepository} so both storage
 * backends reject filter drift with an identical, assertable signal — the
 * in-memory store used to swallow this condition and silently restart
 * pagination, which is a correctness bug rather than a recoverable input
 * error.
 */
export const CURSOR_FILTER_MISMATCH_MESSAGE = 'Cursor filters do not match query filters';

/**
 * Computes the SHA-256 hash for an audit entry.
 * The hash covers all content fields (excluding the hash field itself)
 * plus the previousHash, making the chain tamper-evident.
 */
export function computeEntryHash(
  entry: Omit<AuditEntry, 'hash'>,
): string {
  const payload = JSON.stringify({
    id: entry.id,
    timestamp: entry.timestamp,
    action: entry.action,
    severity: entry.severity,
    actor: entry.actor,
    resource: entry.resource,
    resourceId: entry.resourceId,
    metadata: entry.metadata,
    ipAddress: entry.ipAddress ?? null,
    correlationId: entry.correlationId ?? null,
    previousHash: entry.previousHash,
  });
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * Thrown when a write is attempted from inside another write's critical
 * section (re-entrancy) — which would otherwise fork the hash chain, because
 * both entries would read the same `previousHash`.
 *
 * The message is preserved from the previous implementation so existing
 * string matchers keep working; unlike before it is a typed, catchable error.
 */
export class AuditStoreConcurrencyError extends Error {
  /** Stable, machine-readable identifier for this error class. */
  readonly code = 'audit_store_concurrency_violation';

  constructor(message = 'AuditStore append re-entrancy detected') {
    super(message);
    this.name = 'AuditStoreConcurrencyError';
  }
}

/**
 * AuditStore — append-only, hash-chained audit log.
 *
 * Concurrency contract (issue #1379):
 *  - Every write ({@link AuditStore.append}, {@link AuditStore.appendMany})
 *    runs inside one synchronous, single-writer critical section. Node runs
 *    that section to completion without yielding, so concurrent callers cannot
 *    interleave two writes and fork the chain — the guarantee is now explicit
 *    and enforced rather than incidental.
 *  - The lock is re-entrancy safe: a write attempted from within a write (for
 *    example a `metadata` getter or `toJSON` that calls back into the store)
 *    is rejected with {@link AuditStoreConcurrencyError} instead of silently
 *    corrupting the chain.
 *  - Writes are atomic: if anything throws after entries were appended, the
 *    log is rolled back to its previous length, so a failed, partial, or
 *    re-entrant write can never leave a half-linked entry behind.
 *
 * @example
 * ```ts
 * const store = new AuditStore();
 * store.append({ action: 'CONTRACT_CREATED', severity: 'INFO', actor: 'user-1', ... });
 * const report = store.verifyIntegrity();
 * ```
 */
export class AuditStore implements AuditLogRepository {
  /** Internal append-only log. Never mutate directly. */
  private readonly log: AuditEntry[] = [];

  /**
   * Depth of the write critical section currently executing. `0` means idle;
   * a non-zero value on entry means a nested write, which is rejected.
   */
  private _appendDepth = 0;

  append(input: CreateAuditEntryInput): AuditEntry {
    return this.withWriteLock(() => {
      const entry = this.buildEntry(input, this.currentHash());
      this.log.push(entry);
      return entry;
    });
  }

  /**
   * Atomically appends a batch of entries, chaining each to the one before it.
   *
   * All-or-nothing: if any entry in the batch fails to build (for example a
   * `metadata` value whose `toJSON` throws while hashing), *no* entry from the
   * batch is persisted. Callers that must record several related events can
   * therefore never observe a partially applied batch.
   *
   * Not part of {@link AuditLogRepository} — it is an `AuditStore` primitive,
   * so adding it does not change the repository interface or the SQLite
   * backend.
   */
  appendMany(inputs: readonly CreateAuditEntryInput[]): AuditEntry[] {
    return this.withWriteLock(() => {
      const appended: AuditEntry[] = [];
      let previousHash = this.currentHash();
      for (const input of inputs) {
        const entry = this.buildEntry(input, previousHash);
        this.log.push(entry);
        appended.push(entry);
        previousHash = entry.hash;
      }
      return appended;
    });
  }

  /** Hash of the current chain head, or {@link GENESIS_HASH} when empty. */
  private currentHash(): string {
    return this.log.length === 0 ? GENESIS_HASH : this.log[this.log.length - 1].hash;
  }

  /** Builds (but does not persist) a frozen entry linked to `previousHash`. */
  private buildEntry(input: CreateAuditEntryInput, previousHash: string): AuditEntry {
    const partial: Omit<AuditEntry, 'hash'> = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      action: input.action,
      severity: input.severity,
      actor: input.actor,
      resource: input.resource,
      resourceId: input.resourceId,
      metadata: Object.freeze({ ...input.metadata }),
      ipAddress: input.ipAddress,
      correlationId: input.correlationId,
      previousHash,
    };

    return Object.freeze({
      ...partial,
      hash: computeEntryHash(partial),
    });
  }

  /**
   * Runs `work` inside the single-writer critical section.
   *
   * Nested writes are rejected before they can run, and the log is rolled back
   * to its pre-call length if `work` throws — guaranteeing that a failed or
   * re-entrant write leaves no partial state behind.
   */
  private withWriteLock<T>(work: () => T): T {
    if (this._appendDepth > 0) {
      throw new AuditStoreConcurrencyError();
    }

    this._appendDepth += 1;
    const priorLength = this.log.length;
    try {
      return work();
    } catch (error) {
      if (this.log.length > priorLength) {
        this.log.length = priorLength;
      }
      throw error;
    } finally {
      this._appendDepth -= 1;
    }
  }

  /**
   * Returns a shallow copy of all entries (originals remain frozen).
   */
  getAll(): AuditEntry[] {
    return [...this.log];
  }

  /**
   * Returns the total number of entries in the log.
   */
  count(): number {
    return this.log.length;
  }

  /**
   * Retrieves a single entry by its ID.
   * @returns The entry, or undefined if not found.
   */
  getById(id: string): AuditEntry | undefined {
    return this.log.find((e) => e.id === id);
  }

  /**
   * Queries the log with optional filters and pagination.
   * All string comparisons are exact-match.
   *
   * @param query - Filter and pagination options.
   * @returns Matching entries in insertion order.
   */
  query(query: AuditQuery = {}): AuditEntry[] {
    const offset = Math.max(query.offset ?? 0, 0);

    const results = this.filterEntries(query);

    if (query.limit === undefined) {
      return results.slice(offset);
    }

    const limit = Math.max(query.limit, 0);
    return results.slice(offset, offset + limit);
  }

  /**
   * Queries the log with cursor-based pagination.
   *
   * Behaviour is fixed and asserted by `store.contract.test.ts` (it must match
   * `SqliteAuditRepository`):
   *  - `limit` is clamped to [1, 100]; the default is 50.
   *  - An *undecodable* cursor is recoverable: it is treated as "no cursor" and
   *    pagination restarts at the first page.
   *  - A cursor whose embedded filters differ from the supplied query is a
   *    contract violation and throws `CURSOR_FILTER_MISMATCH_MESSAGE`. This is
   *    deliberately not swallowed: returning a page computed against different
   *    filters would silently corrupt a caller's view of the log.
   *  - The cursor anchors inside the *filtered* sequence, so filtered
   *    pagination neither skips nor duplicates entries.
   *
   * @param query - Filter and pagination options including cursor.
   * @returns Paginated result with entries and the next cursor, if any.
   */
  queryWithCursor(query: AuditQuery = {}): AuditQueryResult {
    const limit = Math.min(Math.max(query.limit ?? 50, 1), 100);

    // Filters first: both the cursor anchor and the page slice live in the
    // filtered sequence's index space.
    const filtered = this.filterEntries(query);

    let startIndex = 0;

    if (query.cursor !== undefined) {
      try {
        const cursorData: CursorData = decodeCursor(query.cursor);

        // Filter drift is a contract violation, not a recoverable input
        // error: a caller must never silently receive a page computed under
        // different filters. (Mirrors `SqliteAuditRepository`.)
        if (!this.cursorFiltersMatch(cursorData, query)) {
          throw new Error(CURSOR_FILTER_MISMATCH_MESSAGE);
        }

        // Anchor within the filtered results — NOT the raw log. Using the
        // raw-log index here skipped or duplicated entries whenever a filter
        // was active.
        const anchor = filtered.findIndex((entry) => entry.id === cursorData.lastId);
        startIndex = anchor === -1 ? 0 : anchor + 1;
      } catch (error) {
        if (error instanceof Error && error.message === CURSOR_FILTER_MISMATCH_MESSAGE) {
          throw error;
        }
        // Recovery path: an undecodable/tampered cursor must not fail the read.
        startIndex = 0;
      }
    }

    const entries = filtered.slice(startIndex, startIndex + limit);

    let nextCursor: string | undefined;
    if (startIndex + limit < filtered.length && entries.length > 0) {
      const lastEntry = entries[entries.length - 1];
      nextCursor = encodeCursor({
        lastId: lastEntry.id,
        lastTimestamp: lastEntry.timestamp,
        filters: this.filterSnapshot(query),
      });
    }

    return {
      entries,
      count: entries.length,
      limit,
      nextCursor,
    };
  }

  /**
   * Applies the shared filter predicate used by every read path.
   *
   * Kept in one place so `query` and `queryWithCursor` cannot disagree about
   * which entries a filter matches (which would make their documented
   * contracts diverge).
   */
  private filterEntries(query: AuditQuery): AuditEntry[] {
    return this.log.filter((entry) => {
      if (query.action && entry.action !== query.action) return false;
      if (query.severity && entry.severity !== query.severity) return false;
      if (query.actor && entry.actor !== query.actor) return false;
      if (query.resource && entry.resource !== query.resource) return false;
      if (query.resourceId && entry.resourceId !== query.resourceId) return false;
      if (query.from && entry.timestamp < query.from) return false;
      if (query.to && entry.timestamp > query.to) return false;
      return true;
    });
  }

  /**
   * Returns true when the cursor was generated with exactly the filters the
   * caller is now supplying. Any difference is filter drift.
   */
  private cursorFiltersMatch(cursorData: CursorData, query: AuditQuery): boolean {
    const filters = cursorData.filters;
    return (
      filters.action === query.action &&
      filters.severity === query.severity &&
      filters.actor === query.actor &&
      filters.resource === query.resource &&
      filters.resourceId === query.resourceId &&
      filters.from === query.from &&
      filters.to === query.to
    );
  }

  /** Snapshot of the applied filters, embedded into the next cursor. */
  private filterSnapshot(query: AuditQuery): CursorData['filters'] {
    return {
      action: query.action,
      severity: query.severity,
      actor: query.actor,
      resource: query.resource,
      resourceId: query.resourceId,
      from: query.from,
      to: query.to,
    };
  }

  *stream(query: AuditQuery = {}): IterableIterator<AuditEntry> {
    const rows = this.query(query);
    for (const row of rows) {
      yield row;
    }
  }

  /**
   * Verifies the integrity of the entire hash chain.
   * Detects any tampering, deletion, or reordering of entries.
   *
   * @returns An IntegrityReport describing the result.
   *
   * @security This should be called periodically by a monitoring job.
   *           A broken chain is a security incident and must be escalated.
   */
  verifyIntegrity(): IntegrityReport {
    const checkedAt = new Date().toISOString();

    if (this.log.length === 0) {
      return { valid: true, totalEntries: 0, checkedAt };
    }

    for (let i = 0; i < this.log.length; i++) {
      const entry = this.log[i];

      // Verify previousHash linkage
      const expectedPreviousHash = i === 0 ? GENESIS_HASH : this.log[i - 1].hash;
      if (entry.previousHash !== expectedPreviousHash) {
        return {
          valid: false,
          totalEntries: this.log.length,
          firstCorruptedIndex: i,
          firstCorruptedId: entry.id,
          checkedAt,
        };
      }

      // Recompute and verify the entry's own hash
      const { hash, ...rest } = entry;
      const expectedHash = computeEntryHash(rest);
      if (hash !== expectedHash) {
        return {
          valid: false,
          totalEntries: this.log.length,
          firstCorruptedIndex: i,
          firstCorruptedId: entry.id,
          checkedAt,
        };
      }
    }

    return { valid: true, totalEntries: this.log.length, checkedAt };
  }

  /**
   * Clears all entries. Intended for testing only.
   * @internal
   */
  _reset(): void {
    this.log.length = 0;
    this._appendDepth = 0;
  }
}

/** Singleton store instance shared across the application. */
export const auditStore = new AuditStore();

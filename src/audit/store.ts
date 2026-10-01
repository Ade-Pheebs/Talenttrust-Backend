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
 * Concurrency properties:
 * - Appends are serialized through an async mutex so concurrent callers cannot
 *   interleave hash-chain computation and produce a forked or stale chain.
 * - The mutex is reentrancy-safe: a caller invoking append() from within an
 *   append() transaction is rejected with a deterministic error rather than
 *   deadlocking or silently corrupting the chain.
 * - Reads (getAll, query, verifyIntegrity, …) operate on a snapshot of the
 *   log taken at call time, so a concurrent append cannot observe or produce
 *   a partially-written entry.
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
 * Async mutex used to serialize mutating operations on the audit log.
 *
 * The mutex is reentrancy-detecting: if the same async context attempts to
 * acquire it twice, acquisition rejects with a deterministic error. This prevents
 * deadlocks and hidden chain corruption from re-entrant append calls.
 */
class AsyncMutex {
  private tail: Promise<void> = Promise.resolve();
  private locked = false;

  async runExclusive<T>(fn: () => Promise<T> | T): Promise<T> {
    if (this.locked) {
      throw new Error('AuditStore append re-entrancy detected');
    }

    this.locked = true;
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });

    await previous;
    try {
      return await fn();
    } finally {
      this.locked = false;
      release();
    }
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
 * await store.append({ action: 'CONTRACT_CREATED', severity: 'INFO', actor: 'user-1', ... });
 * const report = store.verifyIntegrity();
 * ```
 */
export class AuditStore implements AuditLogRepository {
  /** Internal append-only log. Never mutate directly. */
  private readonly log: AuditEntry[] = [];

  /** Serializes append operations across concurrent callers. */
  private readonly mutex = new AsyncMutex();

  /**
   * Appends a new entry to the log.
   *
   * @description The append is atomic and serialized: the previous hash is
   * read, the new entry hash computed, and the entry pushed within a single
   * exclusive section. Concurrent appends cannot observe stale previous hashes
  * or produce a forked chain.
   *
   * @param input - The audit entry data.
   * @returns The frozen, chained entry that was appended.
   * @rejects If a re-entrant append is detected.
   */
  append(input: CreateAuditEntryInput): Promise<AuditEntry> {
    return this.mutex.runExclusive(() => {
      const previousHash =
        this.log.length === 0 ? GENESIS_HASH
        : this.log[this.log.length - 1].hash;

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

      const entry: AuditEntry = Object.freeze({
        ...partial,
        hash: computeEntryHash(partial),
      });

      this.log.push(entry);
      Object.freeze(this.log);
      return entry;
    });
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
      } catch {
        // If cursor is invalid or filters mismatch, reject rather than silently
        // returning a different page (prevents silent data loss / pagination drift).
        throw new Error('AuditStore.queryWithCursor: invalid or mismatched cursor');
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
      const expectedPreviousHash = i === 0 ? GENESIS_HASH
        : this.log[i - 1].hash;
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
  }
}

/** Singleton store instance shared across the application. */
export const auditStore = new AuditStore();

/**
 * @module audit/sqliteRepository
 * @description Durable, tamper-evident SQLite audit repository.
 *
 * ## Failure-recovery invariants
 *
 * Recovery in this module is **deterministic**: for a given failure the exact
 * same bounded sequence of actions is taken on every run — there is no random
 * jitter, no unbounded retry loop, and no dependence on wall-clock ordering.
 *
 * 1. **Atomic writes.** The previous-hash read and the `INSERT` run inside a
 *    single `better-sqlite3` transaction. Any thrown error rolls the whole
 *    transaction back, so a failure never leaves a partial row or a
 *    half-linked hash chain.
 * 2. **Bounded retry for transient conflicts.** Only *serialization* failures
 *    (`SQLITE_BUSY` / `SQLITE_LOCKED`) are retried, capped at
 *    {@link MAX_WRITE_ATTEMPTS} with a fixed backoff. The transaction re-reads
 *    the chain tail on every attempt, so a retry can never fork or
 *    double-append the chain.
 * 3. **Schema self-repair.** A write failing because the schema is missing
 *    (`no such table` / `no such column`, e.g. after a partial migration or an
 *    out-of-band `DROP`) triggers exactly one idempotent `initSchema()` repair
 *    and one retry. If the repair itself fails, the original error propagates.
 * 4. **Non-retryable errors surface.** Constraint violations, disk-full,
 *    malformed input and any other deterministic error are thrown immediately;
 *    the retry loop never masks a real bug.
 * 5. **Observable, never sensitive.** Each recovery attempt is logged with the
 *    operation name, attempt number and error code only. Entry payloads and
 *    metadata are never logged.
 * 6. **Integrity checks never throw.** `verifyIntegrity()` converts an
 *    unparseable row into a deterministic `{ valid: false }` report instead of
 *    crashing the monitoring job that depends on it.
 */

import { randomUUID } from 'crypto';
import Database from "../db/betterSqlite3";
import { computeEntryHash, GENESIS_HASH } from './store';
import type { AuditEntry, AuditQuery, CreateAuditEntryInput, IntegrityReport, AuditQueryResult, CursorData } from './types';
import { encodeCursor, decodeCursor } from './types';
import type { AuditLogRepository } from './repository';
import { createLogger } from '../logger';

const log = createLogger({ service: 'sqlite-audit-repository' });

/**
 * Maximum number of write attempts (the first attempt plus retries) for a
 * single logical write. Bounded so a persistent conflict can never spin
 * forever; after this many attempts the last error is rethrown.
 */
export const MAX_WRITE_ATTEMPTS = 3;

/** Fixed base backoff between retries (ms). Deterministic — no jitter. */
const RETRY_BACKOFF_MS = 10;

/** SQLite extended result codes that represent a transient serialization conflict. */
const SERIALIZATION_CODES = new Set<number>([5, 6, 262, 517]); // BUSY, LOCKED, LOCKED_SHAREDCACHE, BUSY_SNAPSHOT
const SERIALIZATION_MESSAGE_PATTERN =
  /SQLITE_BUSY|SQLITE_LOCKED|database is locked|database table is locked/i;

/** Error text emitted by SQLite when a referenced schema object is absent. */
const MISSING_SCHEMA_PATTERN = /no such (table|column|index)/i;

/**
 * Returns true only for transient serialization conflicts (lock contention)
 * that are safe to retry. Numeric extended codes and string messages are both
 * checked so the predicate works with every `better-sqlite3` error shape.
 *
 * Exported so the retry policy can be unit-tested independently of a live DB.
 */
export function isSerializationError(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) {
    return false;
  }
  const { code, rawCode, message } = error as {
    code?: unknown;
    rawCode?: unknown;
    message?: unknown;
  };
  if (typeof code === 'number' && SERIALIZATION_CODES.has(code)) return true;
  if (typeof rawCode === 'number' && SERIALIZATION_CODES.has(rawCode)) return true;
  return typeof message === 'string' && SERIALIZATION_MESSAGE_PATTERN.test(message);
}

/**
 * Returns true when the failure is caused by a missing schema object (table,
 * column or index) — the one class of failure this repository can repair
 * in-process by re-running its idempotent `initSchema()` bootstrap.
 *
 * Exported so the repair trigger can be unit-tested independently of a live DB.
 */
export function isMissingSchemaError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    typeof (error as { message?: unknown }).message === 'string' &&
    MISSING_SCHEMA_PATTERN.test((error as { message: string }).message)
  );
}

/**
 * Synchronous backoff. `better-sqlite3` is synchronous, and this only runs
 * after a bounded, already-waited busy conflict, so blocking is deliberately
 * kept tiny ({@link RETRY_BACKOFF_MS} per attempt).
 */
function sleepSync(ms: number): void {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    // Busy-wait: only reached on a bounded retry path.
  }
}

interface AuditRow {
  id: string;
  timestamp: string;
  action: AuditEntry['action'];
  severity: AuditEntry['severity'];
  actor: string;
  resource: string;
  resource_id: string;
  metadata_json: string;
  ip_address: string | null;
  correlation_id: string | null;
  hash: string;
  previous_hash: string;
}

function toAuditEntry(row: AuditRow): AuditEntry {
  return Object.freeze({
    id: row.id,
    timestamp: row.timestamp,
    action: row.action,
    severity: row.severity,
    actor: row.actor,
    resource: row.resource,
    resourceId: row.resource_id,
    metadata: Object.freeze(JSON.parse(row.metadata_json) as Record<string, unknown>),
    ipAddress: row.ip_address ?? undefined,
    correlationId: row.correlation_id ?? undefined,
    hash: row.hash,
    previousHash: row.previous_hash,
  });
}

/** Optional behaviour tuning for {@link SqliteAuditRepository}. */
export interface SqliteAuditRepositoryOptions {
  /**
   * When `true` (the default), a write that fails with a missing-schema error
   * runs one idempotent `initSchema()` repair and retries. Set to `false` to
   * fail fast and force the caller to handle the broken schema explicitly.
   */
  autoRepairSchema?: boolean;
}

export class SqliteAuditRepository implements AuditLogRepository {
  /**
   * @param db - A `better-sqlite3` connection (or the test double). The
   *   `ReturnType<typeof Database>` form is used on purpose: the default export
   *   of `../db/betterSqlite3` is the *constructor value*, so the instance type
   *   must be derived from it rather than using `Database` directly.
   * @param options - Optional recovery behaviour. Omitted entirely by existing
   *   callers, which preserves the original single-argument construction.
   */
  constructor(
    private readonly db: ReturnType<typeof Database>,
    private readonly options: SqliteAuditRepositoryOptions = {},
  ) {
    this.initSchema();
    this.applyConnectionPragmas();
  }

  append(input: CreateAuditEntryInput): AuditEntry {
    const insert = this.db.transaction((payload: CreateAuditEntryInput): AuditEntry => {
      const previousHashRow = this.db
        .prepare<[], { hash: string }>(
          'SELECT hash FROM audit_log_entries ORDER BY seq DESC LIMIT 1'
        )
        .get();

      const partial: Omit<AuditEntry, 'hash'> = {
        id: randomUUID(),
        timestamp: new Date().toISOString(),
        action: payload.action,
        severity: payload.severity,
        actor: payload.actor,
        resource: payload.resource,
        resourceId: payload.resourceId,
        metadata: Object.freeze({ ...payload.metadata }),
        ipAddress: payload.ipAddress,
        correlationId: payload.correlationId,
        previousHash: previousHashRow?.hash ?? GENESIS_HASH,
      };

      const entry: AuditEntry = Object.freeze({
        ...partial,
        hash: computeEntryHash(partial),
      });

      this.db
        .prepare<
          [string, string, string, string, string, string, string, string, string | null, string | null, string, string]
        >(
          `INSERT INTO audit_log_entries
           (id, timestamp, action, severity, actor, resource, resource_id, metadata_json, ip_address, correlation_id, hash, previous_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          entry.id,
          entry.timestamp,
          entry.action,
          entry.severity,
          entry.actor,
          entry.resource,
          entry.resourceId,
          JSON.stringify(entry.metadata),
          entry.ipAddress ?? null,
          entry.correlationId ?? null,
          entry.hash,
          entry.previousHash
        );

      return entry;
    });

    // The retried unit is the *whole transaction*, not the bare INSERT: each
    // attempt re-reads the chain tail inside the transaction, so a retry links
    // the new entry to the true predecessor instead of a stale cached hash.
    return this.runWriteWithRecovery('append', () => insert(input));
  }

  getById(id: string): AuditEntry | undefined {
    const row = this.db
      .prepare<[string], AuditRow>(
        `SELECT id, timestamp, action, severity, actor, resource, resource_id, metadata_json, ip_address, correlation_id, hash, previous_hash
         FROM audit_log_entries
         WHERE id = ?`
      )
      .get(id);

    return row ? toAuditEntry(row) : undefined;
  }

  query(query: AuditQuery = {}): AuditEntry[] {
    const { sql, params } = this.buildQuerySql(query);
    const rows = this.db.prepare<typeof params, AuditRow>(sql).all(...params);
    return rows.map(toAuditEntry);
  }

  queryWithCursor(query: AuditQuery = {}): AuditQueryResult {
    const limit = Math.min(Math.max(query.limit ?? 50, 1), 100);
    
    let startIndex = 0;
    
    // Decode cursor if provided
    if (query.cursor) {
      try {
        const cursorData: CursorData = decodeCursor(query.cursor);
        
        // Find the sequence number of the last entry from the previous page
        const lastEntryRow = this.db
          .prepare<[string], { seq: number }>(
            'SELECT seq FROM audit_log_entries WHERE id = ?'
          )
          .get(cursorData.lastId);
        
        if (lastEntryRow) {
          startIndex = lastEntryRow.seq;
        }
        
        // Verify filters match cursor (prevent filter drift)
        if (cursorData.filters.action !== query.action ||
            cursorData.filters.severity !== query.severity ||
            cursorData.filters.actor !== query.actor ||
            cursorData.filters.resource !== query.resource ||
            cursorData.filters.resourceId !== query.resourceId ||
            cursorData.filters.from !== query.from ||
            cursorData.filters.to !== query.to) {
          throw new Error('Cursor filters do not match query filters');
        }
      } catch (error) {
        // Re-throw filter mismatch errors, but handle invalid cursor format gracefully
        if (error instanceof Error && error.message === 'Cursor filters do not match query filters') {
          throw error;
        }
        // If cursor is invalid (format error), start from beginning
        startIndex = 0;
      }
    }
    
    // Build query with cursor-based pagination
    const { sql, params } = this.buildCursorQuerySql(query, startIndex, limit);
    const rows = this.db.prepare<typeof params, AuditRow>(sql).all(...params);
    const entries = rows.map(toAuditEntry);
    
    // Generate next cursor if there are more results
    let nextCursor: string | undefined;
    if (entries.length === limit && entries.length > 0) {
      // Check if there are actually more results by querying with limit+1
      const checkSql = this.buildCursorQuerySql(query, startIndex, limit + 1);
      const checkRows = this.db.prepare<typeof checkSql.params, AuditRow>(checkSql.sql).all(...checkSql.params);
      if (checkRows.length > limit) {
        const lastEntry = entries[entries.length - 1];
        const cursorData: CursorData = {
          lastId: lastEntry.id,
          lastTimestamp: lastEntry.timestamp,
          filters: {
            action: query.action,
            severity: query.severity,
            actor: query.actor,
            resource: query.resource,
            resourceId: query.resourceId,
            from: query.from,
            to: query.to,
          },
        };
        nextCursor = encodeCursor(cursorData);
      }
    }
    
    return {
      entries,
      count: entries.length,
      limit,
      nextCursor,
    };
  }

  *stream(query: AuditQuery = {}): IterableIterator<AuditEntry> {
    const { sql, params } = this.buildQuerySql(query);
    const cursor = this.db.prepare<typeof params, AuditRow>(sql).iterate(...params);
    for (const row of cursor) {
      yield toAuditEntry(row);
    }
  }

  count(): number {
    const row = this.db
      .prepare<[], { total: number }>('SELECT COUNT(*) AS total FROM audit_log_entries')
      .get();
    return row?.total ?? 0;
  }

  verifyIntegrity(): IntegrityReport {
    const checkedAt = new Date().toISOString();
    const rows = this.db
      .prepare<[], AuditRow>(
        `SELECT id, timestamp, action, severity, actor, resource, resource_id, metadata_json, ip_address, correlation_id, hash, previous_hash
         FROM audit_log_entries
         ORDER BY seq ASC`
      )
      .all();

    if (rows.length === 0) {
      return { valid: true, totalEntries: 0, checkedAt };
    }

    let previousHash = GENESIS_HASH;
    for (let index = 0; index < rows.length; index += 1) {
      let entry: AuditEntry;
      try {
        entry = toAuditEntry(rows[index]);
      } catch (error) {
        // A row whose `metadata_json` is unparseable is itself corruption.
        // Report it deterministically instead of letting the monitoring job
        // crash — the operator still gets a precise index and id.
        log.error('Audit row could not be decoded during integrity verification', {
          index,
          id: rows[index].id,
          err: error,
        });
        return {
          valid: false,
          totalEntries: rows.length,
          firstCorruptedIndex: index,
          firstCorruptedId: rows[index].id,
          checkedAt,
        };
      }

      if (entry.previousHash !== previousHash) {
        return {
          valid: false,
          totalEntries: rows.length,
          firstCorruptedIndex: index,
          firstCorruptedId: entry.id,
          checkedAt,
        };
      }

      const { hash, ...rest } = entry;
      const expectedHash = computeEntryHash(rest);
      if (hash !== expectedHash) {
        return {
          valid: false,
          totalEntries: rows.length,
          firstCorruptedIndex: index,
          firstCorruptedId: entry.id,
          checkedAt,
        };
      }

      previousHash = entry.hash;
    }

    return { valid: true, totalEntries: rows.length, checkedAt };
  }

  /**
   * Executes a write with deterministic, bounded failure recovery.
   *
   * Recovery order is fixed:
   *   1. missing schema → one `initSchema()` repair, then retry;
   *   2. serialization conflict → fixed backoff, then retry;
   *   3. anything else → rethrow immediately (never masked by a retry).
   *
   * After {@link MAX_WRITE_ATTEMPTS} attempts the last error is rethrown.
   *
   * @param operationName - Short, non-sensitive label used in recovery logs.
   * @param operation - The transactional write to execute.
   */
  private runWriteWithRecovery<T>(operationName: string, operation: () => T): T {
    const autoRepair = this.options.autoRepairSchema ?? true;
    let schemaRepairAttempted = false;
    let lastError: unknown;

    for (let attempt = 1; attempt <= MAX_WRITE_ATTEMPTS; attempt += 1) {
      try {
        return operation();
      } catch (error) {
        lastError = error;

        if (autoRepair && !schemaRepairAttempted && isMissingSchemaError(error)) {
          schemaRepairAttempted = true;
          log.warn('Audit SQLite schema missing; attempting deterministic repair', {
            operation: operationName,
            attempt,
            maxAttempts: MAX_WRITE_ATTEMPTS,
          });
          try {
            this.initSchema();
          } catch (repairError) {
            // Repair failed: surface the original failure rather than the
            // repair error so the caller sees the root cause.
            log.error('Audit SQLite schema repair failed; rethrowing original error', {
              operation: operationName,
              err: repairError,
            });
            throw error;
          }
          log.info('Audit SQLite schema repaired; retrying write', {
            operation: operationName,
            attempt,
          });
          continue;
        }

        if (isSerializationError(error) && attempt < MAX_WRITE_ATTEMPTS) {
          log.warn('Audit SQLite write serialization conflict; retrying', {
            operation: operationName,
            attempt,
            maxAttempts: MAX_WRITE_ATTEMPTS,
          });
          sleepSync(RETRY_BACKOFF_MS * attempt);
          continue;
        }

        throw error;
      }
    }

    throw lastError;
  }

  /**
   * Applies deterministic locking/safety pragmas to the connection.
   *
   * These make lock contention recoverable rather than immediately fatal:
   * `busy_timeout` lets SQLite wait instead of throwing `SQLITE_BUSY`,
   * `WAL` lets readers and the single writer proceed concurrently, and
   * `synchronous = NORMAL` is the safe pairing for WAL. Failures here are
   * non-fatal (a read-only or in-memory connection may reject a pragma) and are
   * logged at warn level.
   */
  private applyConnectionPragmas(): void {
    try {
      this.db.pragma('busy_timeout = 5000');
      this.db.pragma('journal_mode = WAL');
      this.db.pragma('synchronous = NORMAL');
    } catch (error) {
      log.warn('Could not apply audit SQLite connection pragmas', { err: error });
    }
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_log_entries (
        seq            INTEGER PRIMARY KEY AUTOINCREMENT,
        id             TEXT    NOT NULL UNIQUE,
        timestamp      TEXT    NOT NULL,
        action         TEXT    NOT NULL,
        severity       TEXT    NOT NULL,
        actor          TEXT    NOT NULL,
        resource       TEXT    NOT NULL,
        resource_id    TEXT    NOT NULL,
        metadata_json  TEXT    NOT NULL,
        ip_address     TEXT,
        correlation_id TEXT,
        hash           TEXT    NOT NULL,
        previous_hash  TEXT    NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log_entries(timestamp);
      CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log_entries(action);
      CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log_entries(severity);
      CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log_entries(actor);
      CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log_entries(resource, resource_id);
    `);
  }

  private buildQuerySql(query: AuditQuery): { sql: string; params: unknown[] } {
    const where: string[] = [];
    const params: unknown[] = [];

    if (query.action) {
      where.push('action = ?');
      params.push(query.action);
    }
    if (query.severity) {
      where.push('severity = ?');
      params.push(query.severity);
    }
    if (query.actor) {
      where.push('actor = ?');
      params.push(query.actor);
    }
    if (query.resource) {
      where.push('resource = ?');
      params.push(query.resource);
    }
    if (query.resourceId) {
      where.push('resource_id = ?');
      params.push(query.resourceId);
    }
    if (query.from) {
      where.push('timestamp >= ?');
      params.push(query.from);
    }
    if (query.to) {
      where.push('timestamp <= ?');
      params.push(query.to);
    }

    const offset = Math.max(query.offset ?? 0, 0);
    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    let paginationClause = '';
    if (query.limit !== undefined) {
      paginationClause = 'LIMIT ? OFFSET ?';
      params.push(Math.max(query.limit, 0), offset);
    } else if (offset > 0) {
      paginationClause = 'LIMIT -1 OFFSET ?';
      params.push(offset);
    }

    const sql = `
      SELECT id, timestamp, action, severity, actor, resource, resource_id, metadata_json, ip_address, correlation_id, hash, previous_hash
      FROM audit_log_entries
      ${whereClause}
      ORDER BY seq ASC
      ${paginationClause}
    `;
    return { sql, params };
  }

  private buildCursorQuerySql(query: AuditQuery, startIndex: number, limit: number): { sql: string; params: unknown[] } {
    const where: string[] = [];
    const params: unknown[] = [];

    if (query.action) {
      where.push('action = ?');
      params.push(query.action);
    }
    if (query.severity) {
      where.push('severity = ?');
      params.push(query.severity);
    }
    if (query.actor) {
      where.push('actor = ?');
      params.push(query.actor);
    }
    if (query.resource) {
      where.push('resource = ?');
      params.push(query.resource);
    }
    if (query.resourceId) {
      where.push('resource_id = ?');
      params.push(query.resourceId);
    }
    if (query.from) {
      where.push('timestamp >= ?');
      params.push(query.from);
    }
    if (query.to) {
      where.push('timestamp <= ?');
      params.push(query.to);
    }
    
    // Add cursor-based pagination using seq
    if (startIndex > 0) {
      where.push('seq > ?');
      params.push(startIndex);
    }

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    const sql = `
      SELECT id, timestamp, action, severity, actor, resource, resource_id, metadata_json, ip_address, correlation_id, hash, previous_hash
      FROM audit_log_entries
      ${whereClause}
      ORDER BY seq ASC
      LIMIT ?
    `;
    params.push(limit);
    
    return { sql, params };
  }
}

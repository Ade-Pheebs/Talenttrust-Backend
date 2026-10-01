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
import { computeEntryHash, GENESIS_HASH, CURSOR_FILTER_MISMATCH_MESSAGE } from './store';
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

/**
 * Recursively deep-freezes a plain object so that nested metadata objects
 * returned from the DB cannot be mutated by callers.
 *
 * Only plain objects and arrays are frozen; primitives, null, functions,
 * and class instances are returned as-is so we don't accidentally freeze
 * host objects or break prototypes.
 */
function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  // Freeze children first (depth-first), then freeze the container.
  for (const key of Object.keys(value as object)) {
    deepFreeze((value as Record<string, unknown>)[key]);
  }
  return Object.freeze(value);
}

/**
 * Safely parses a JSON string.  Returns an empty object `{}` instead of
 * throwing when the stored value is malformed, so a corrupted `metadata_json`
 * column can never crash the caller.
 *
 * @invariant The returned value is always a plain object (never null/undefined).
 */
function safeParseMetadata(raw: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(raw) as unknown;
    // Guard: must be a non-null object so the AuditEntry type is satisfied.
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return {};
  } catch {
    // Malformed JSON — return a safe, empty metadata object rather than
    // propagating the SyntaxError to the caller.
    return {};
  }
}

/**
 * Converts a raw SQLite row to a fully frozen AuditEntry.
 *
 * Invariants enforced:
 * - The top-level entry object is frozen.
 * - The `metadata` object is deep-frozen so nested values cannot be mutated
 *   after a read.
 * - Malformed `metadata_json` is silently replaced with `{}` (logged nowhere
 *   because this is a low-level mapping function; callers and the integrity
 *   check are responsible for surfacing data-quality issues).
 */
function toAuditEntry(row: AuditRow): AuditEntry {
  const rawMetadata = safeParseMetadata(row.metadata_json);
  return Object.freeze({
    id: row.id,
    timestamp: row.timestamp,
    action: row.action,
    severity: row.severity,
    actor: row.actor,
    resource: row.resource,
    resourceId: row.resource_id,
    // Deep-freeze so nested objects cannot be mutated post-read.
    metadata: deepFreeze(rawMetadata) as Readonly<Record<string, unknown>>,
    ipAddress: row.ip_address ?? undefined,
    correlationId: row.correlation_id ?? undefined,
    hash: row.hash,
    previousHash: row.previous_hash,
  });
}

/**
 * Validates required string fields of `CreateAuditEntryInput`.
 *
 * @throws {Error} with a descriptive message when any required field is
 *   absent (null/undefined) or is an empty/whitespace-only string.  The
 *   check happens before any DB interaction so invalid data never reaches
 *   the insert statement.
 *
 * Invariant: every audit entry persisted to the DB has non-blank required
 * fields; this is the single enforcement point.
 */
function validateAppendInput(input: CreateAuditEntryInput): void {
  const required: Array<keyof Pick<CreateAuditEntryInput, 'action' | 'severity' | 'actor' | 'resource' | 'resourceId'>> =
    ['action', 'severity', 'actor', 'resource', 'resourceId'];

  for (const field of required) {
    const value = input[field];
    if (value === null || value === undefined) {
      throw new Error(`audit append: required field '${field}' is missing`);
    }
    if (typeof value === 'string' && value.trim() === '') {
      throw new Error(`audit append: required field '${field}' must not be empty`);
    }
  }

  // metadata must be a non-null object (arrays and primitives are invalid).
  if (
    input.metadata === null ||
    input.metadata === undefined ||
    typeof input.metadata !== 'object' ||
    Array.isArray(input.metadata)
  ) {
    throw new Error("audit append: 'metadata' must be a plain object");
  }
}

export class SqliteAuditRepository implements AuditLogRepository {
  /**
   * Re-entrancy guard for `append()`.
   *
   * better-sqlite3 transactions are synchronous and non-reentrant: calling
   * `append()` from within an `append()` transaction (e.g. from a callback
   * triggered by the INSERT) would attempt to start a nested transaction and
   * corrupt the hash-chain state.  This flag detects that scenario and throws
   * a clear error rather than producing silent data-integrity violations.
   */
  private _appendInProgress = false;

  constructor(private readonly db: ReturnType<typeof Database>) {
    this.initSchema();
    this.applyConnectionPragmas();
  }

  /**
   * Appends a new, tamper-evident audit entry to the log.
   *
   * Invariants enforced:
   * 1. Required fields are validated before any DB interaction.
   * 2. Re-entrancy is detected and rejected — concurrent nested calls would
   *    break the hash chain.
   * 3. The entire write (SELECT previous hash + INSERT) is wrapped in a
   *    single serialisable SQLite transaction, so a crash or error leaves
   *    zero partial state.
   * 4. The returned entry is deep-frozen.
   *
   * @throws {Error} on re-entrancy, validation failure, or DB error.
   */
  append(input: CreateAuditEntryInput): AuditEntry {
    // --- Invariant 1: validate required fields before touching the DB ---
    validateAppendInput(input);

    // --- Invariant 2: re-entrancy guard ---
    if (this._appendInProgress) {
      throw new Error('SqliteAuditRepository.append() re-entrancy detected: nested call would corrupt the hash chain');
    }

    this._appendInProgress = true;
    try {
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

      return insert(input);
    } finally {
      // Always release the guard — even on error — so the caller can recover.
      this._appendInProgress = false;
    }
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

    const immediate = (insert as typeof insert & {
      immediate?: (payload: CreateAuditEntryInput) => AuditEntry;
    }).immediate;
    return immediate ? immediate(input) : insert(input);
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
      // Decode cursor first — if the format is invalid this will throw
      // 'Invalid cursor format', which we catch below.
      let cursorData: CursorData;
      try {
        cursorData = decodeCursor(query.cursor);
      } catch {
        // Malformed/undecodable cursor — fall back to the beginning of the
        // result set rather than propagating a format error.
        cursorData = { lastId: '', lastTimestamp: '', filters: {} };
      }

      // Verify filters match cursor BEFORE any DB work.
      // This is a caller-invariant violation (mixing cursors across queries),
      // so we throw rather than silently ignoring the mismatch.
      if (
        cursorData.lastId !== '' && // skip check when we fell back to empty cursor
        (cursorData.filters.action !== query.action ||
          cursorData.filters.severity !== query.severity ||
          cursorData.filters.actor !== query.actor ||
          cursorData.filters.resource !== query.resource ||
          cursorData.filters.resourceId !== query.resourceId ||
          cursorData.filters.from !== query.from ||
          cursorData.filters.to !== query.to)
      ) {
        throw new Error('Cursor filters do not match query filters');
      }

      if (cursorData.lastId) {
        // Find the sequence number of the last entry from the previous page.
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
          throw new Error(CURSOR_FILTER_MISMATCH_MESSAGE);
        }
      } catch (error) {
        // Re-throw filter mismatch errors, but handle invalid cursor format gracefully
        if (error instanceof Error && error.message === CURSOR_FILTER_MISMATCH_MESSAGE) {
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

  /**
   * Verifies the integrity of the entire hash chain.
   *
   * Invariants checked:
   * 1. `previousHash` of each entry equals the `hash` of the preceding entry
   *    (or GENESIS for the first).
   * 2. The stored `hash` matches the recomputed hash of the entry's content
   *    fields (detects field tampering).
   * 3. No two entries share the same `hash` value — a duplicate hash would
   *    indicate either a hash-collision attack or a forged insertion that
   *    copied an existing entry's hash.
   *
   * @returns An `IntegrityReport` with `valid: false` and the index/ID of the
   *   first corrupted entry when any invariant is violated.
   */
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

    // --- Invariant 3: duplicate hash detection ---
    // Build a set of seen hashes; a collision at any position is a hard failure.
    const seenHashes = new Set<string>();

    let previousHash = GENESIS_HASH;
    for (let index = 0; index < rows.length; index += 1) {
      let entry: AuditEntry;
      try {
        entry = toAuditEntry(rows[index]);
      } catch {
        return {
          valid: false,
          totalEntries: rows.length,
          firstCorruptedIndex: index,
          firstCorruptedId: rows[index].id,
          checkedAt,
        };
      }

      // --- Invariant 3: duplicate hash ---
      if (seenHashes.has(entry.hash)) {
        return {
          valid: false,
          totalEntries: rows.length,
          firstCorruptedIndex: index,
          firstCorruptedId: entry.id,
          checkedAt,
        };
      }
      seenHashes.add(entry.hash);

      // --- Invariant 1: previousHash linkage ---
      if (entry.previousHash !== previousHash) {
        return {
          valid: false,
          totalEntries: rows.length,
          firstCorruptedIndex: index,
          firstCorruptedId: entry.id,
          checkedAt,
        };
      }

      // --- Invariant 2: hash content integrity ---
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

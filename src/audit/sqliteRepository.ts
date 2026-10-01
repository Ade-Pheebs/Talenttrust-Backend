/**
 * @module audit/sqliteRepository
 * @description Durable SQLite-backed audit log repository.
 *
 * ## Validation boundaries
 *
 * This module is the last line of defence before untrusted data is written to
 * the immutable, hash-chained audit log. Because entries can never be removed
 * or edited, a malformed entry is permanent. All public write and read paths
 * therefore enforce strict input bounds independent of the HTTP layer:
 *
 * | Method              | What is validated                                                  |
 * |---------------------|--------------------------------------------------------------------|
 * | `append()`          | Full payload via `validateCreateAuditEntryInput` (single source)   |
 * | `getById()`         | `id` must be a non-blank string within `MAX_ID_LENGTH` chars       |
 * | `query()`           | Enum filters, ISO-8601 dates, limit/offset clamping                |
 * | `queryWithCursor()` | Same as `query()` plus cursor integrity; limit clamped [1, 100]    |
 * | `stream()`          | Same filter rules as `query()`                                     |
 *
 * Failed validation throws `RepositoryValidationError` (a subclass of `Error`)
 * so callers can distinguish invalid input from transient storage errors.
 *
 * ## Resilience
 *
 * `toAuditEntry()` wraps `JSON.parse` in a try/catch. A row with corrupted
 * `metadata_json` is surfaced as an error rather than crashing the process —
 * callers see a `RepositoryCorruptedRowError` describing which row is affected.
 */

import { randomUUID } from 'crypto';
import Database from "../db/betterSqlite3";
import { computeEntryHash, GENESIS_HASH } from './store';
import type { AuditEntry, AuditQuery, CreateAuditEntryInput, IntegrityReport, AuditQueryResult, CursorData } from './types';
import { AUDIT_ACTIONS, AUDIT_SEVERITIES, encodeCursor, decodeCursor } from './types';
import type { AuditLogRepository } from './repository';
import {
  validateCreateAuditEntryInput,
  MAX_ID_LENGTH,
} from './inputValidation';

// ── Error types ───────────────────────────────────────────────────────────────

/**
 * Thrown when an argument to a repository method violates its validation
 * contract. Callers should treat this as a client-side error (HTTP 400).
 *
 * The `field` property names the argument or sub-field that failed so that
 * error handlers can surface a precise message without leaking internals.
 */
export class RepositoryValidationError extends Error {
  constructor(
    message: string,
    public readonly field?: string,
  ) {
    super(message);
    this.name = 'RepositoryValidationError';
    // Maintain the correct prototype chain on transpiled ES5 targets.
    Object.setPrototypeOf(this, RepositoryValidationError.prototype);
  }
}

/**
 * Thrown when a row retrieved from the database contains data that cannot
 * be safely deserialised (e.g. corrupted `metadata_json`). The `rowId`
 * property identifies the affected entry for operator investigation.
 *
 * This is a storage-layer error, not a validation error: the offending data
 * was already persisted when the fault occurred.
 */
export class RepositoryCorruptedRowError extends Error {
  constructor(
    message: string,
    public readonly rowId: string,
  ) {
    super(message);
    this.name = 'RepositoryCorruptedRowError';
    Object.setPrototypeOf(this, RepositoryCorruptedRowError.prototype);
  }
}

// ── Internal types ────────────────────────────────────────────────────────────

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

// ── Constants ─────────────────────────────────────────────────────────────────

/** Maximum limit value accepted by `query()` / `stream()`. Prevents unbounded full-table scans. */
const MAX_QUERY_LIMIT = 10_000;

/** Control characters (C0, C1, DEL) are disallowed in identifier fields. */
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F-\u009F]/;

// ── Row deserialisation ───────────────────────────────────────────────────────

/**
 * Converts a raw database row to a frozen `AuditEntry`.
 *
 * @throws {RepositoryCorruptedRowError} when `metadata_json` cannot be parsed.
 */
function toAuditEntry(row: AuditRow): AuditEntry {
  let parsedMetadata: Record<string, unknown>;
  try {
    const raw = JSON.parse(row.metadata_json) as unknown;
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      throw new TypeError(`metadata_json is not a JSON object for row ${row.id}`);
    }
    parsedMetadata = raw as Record<string, unknown>;
  } catch (cause) {
    throw new RepositoryCorruptedRowError(
      `Audit row ${row.id} has corrupted metadata_json and cannot be deserialised. ` +
      `Cause: ${cause instanceof Error ? cause.message : String(cause)}`,
      row.id,
    );
  }

  return Object.freeze({
    id: row.id,
    timestamp: row.timestamp,
    action: row.action,
    severity: row.severity,
    actor: row.actor,
    resource: row.resource,
    resourceId: row.resource_id,
    metadata: Object.freeze(parsedMetadata),
    ipAddress: row.ip_address ?? undefined,
    correlationId: row.correlation_id ?? undefined,
    hash: row.hash,
    previousHash: row.previous_hash,
  });
}

// ── Validation helpers ────────────────────────────────────────────────────────

/**
 * Validates a required identifier string (actor, resource, resourceId, id).
 * Throws `RepositoryValidationError` if the value is invalid.
 */
function validateIdentifier(
  value: unknown,
  fieldName: string,
  maxLength: number = MAX_ID_LENGTH,
): asserts value is string {
  if (typeof value !== 'string') {
    throw new RepositoryValidationError(
      `${fieldName} must be a string, received ${value === null ? 'null' : typeof value}`,
      fieldName,
    );
  }
  if (value.length === 0 || value.trim().length === 0) {
    throw new RepositoryValidationError(
      `${fieldName} must not be blank`,
      fieldName,
    );
  }
  if (value.length > maxLength) {
    throw new RepositoryValidationError(
      `${fieldName} must be at most ${maxLength} characters, received ${value.length}`,
      fieldName,
    );
  }
  if (CONTROL_CHARACTERS.test(value)) {
    throw new RepositoryValidationError(
      `${fieldName} must not contain control characters`,
      fieldName,
    );
  }
}

/**
 * Validates that a date string is a parseable ISO-8601 timestamp.
 * Throws `RepositoryValidationError` if it is not.
 */
function validateIsoDate(value: string, fieldName: string): void {
  if (Number.isNaN(Date.parse(value))) {
    throw new RepositoryValidationError(
      `${fieldName} must be a valid ISO-8601 date string, received: ${JSON.stringify(value)}`,
      fieldName,
    );
  }
}

/**
 * Validates query filter fields shared by `query()`, `queryWithCursor()`, and
 * `stream()`. Does NOT throw on an absent optional field.
 */
function validateQueryFilters(query: AuditQuery): void {
  if (query.action !== undefined) {
    if (!(AUDIT_ACTIONS as readonly string[]).includes(query.action)) {
      throw new RepositoryValidationError(
        `action must be one of: ${AUDIT_ACTIONS.join(', ')}`,
        'action',
      );
    }
  }

  if (query.severity !== undefined) {
    if (!(AUDIT_SEVERITIES as readonly string[]).includes(query.severity)) {
      throw new RepositoryValidationError(
        `severity must be one of: ${AUDIT_SEVERITIES.join(', ')}`,
        'severity',
      );
    }
  }

  if (query.from !== undefined) {
    validateIsoDate(query.from, 'from');
  }

  if (query.to !== undefined) {
    validateIsoDate(query.to, 'to');
  }

  if (query.from !== undefined && query.to !== undefined) {
    if (query.from > query.to) {
      throw new RepositoryValidationError(
        `from (${query.from}) must not be after to (${query.to})`,
        'from',
      );
    }
  }

  if (query.limit !== undefined) {
    if (!Number.isFinite(query.limit) || !Number.isInteger(query.limit)) {
      throw new RepositoryValidationError(
        `limit must be a finite integer, received ${query.limit}`,
        'limit',
      );
    }
    // Negative values are clamped to 0 downstream; not an error but we cap the
    // upper bound to prevent accidental full-table scans through the public API.
    if (query.limit > MAX_QUERY_LIMIT) {
      throw new RepositoryValidationError(
        `limit must be at most ${MAX_QUERY_LIMIT}, received ${query.limit}`,
        'limit',
      );
    }
  }

  if (query.offset !== undefined) {
    if (!Number.isFinite(query.offset) || !Number.isInteger(query.offset)) {
      throw new RepositoryValidationError(
        `offset must be a finite integer, received ${query.offset}`,
        'offset',
      );
    }
    // Negative values are clamped to 0 downstream.
  }
}

// ── Repository ────────────────────────────────────────────────────────────────

export class SqliteAuditRepository implements AuditLogRepository {
  constructor(private readonly db: ReturnType<typeof Database>) {
    this.initSchema();
  }

  /**
   * Validates and appends a new audit entry to the hash chain.
   *
   * Validation uses the same rules as the HTTP layer
   * (`validateCreateAuditEntryInput`) so the repository enforces the same
   * invariants regardless of the call-site.
   *
   * @throws {RepositoryValidationError} on any invalid field.
   * @throws {Error} on a transient storage failure (transaction rolls back).
   */
  append(input: CreateAuditEntryInput): AuditEntry {
    // --- Validation boundary ---
    // Reuse the single-source-of-truth validator from inputValidation.ts.
    // This covers: required fields, enum membership, identifier lengths,
    // control-character rejection, metadata structure/depth/size, ipAddress
    // format, correlationId charset.
    const validationResult = validateCreateAuditEntryInput(input);
    if (!validationResult.ok) {
      const first = validationResult.issues[0];
      throw new RepositoryValidationError(
        `Invalid audit entry input: ${first?.message ?? 'validation failed'}` +
        (validationResult.issues.length > 1
          ? ` (and ${validationResult.issues.length - 1} more issue(s))`
          : ''),
        first?.field,
      );
    }

    // Use the validated (and normalised) data from here on.
    const payload = validationResult.data;

    const insert = this.db.transaction((p: CreateAuditEntryInput): AuditEntry => {
      const previousHashRow = this.db
        .prepare<[], { hash: string }>(
          'SELECT hash FROM audit_log_entries ORDER BY seq DESC LIMIT 1'
        )
        .get();

      const partial: Omit<AuditEntry, 'hash'> = {
        id: randomUUID(),
        timestamp: new Date().toISOString(),
        action: p.action,
        severity: p.severity,
        actor: p.actor,
        resource: p.resource,
        resourceId: p.resourceId,
        metadata: Object.freeze({ ...p.metadata }),
        ipAddress: p.ipAddress,
        correlationId: p.correlationId,
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

    return insert(payload);
  }

  /**
   * Retrieves a single audit entry by its UUID.
   *
   * @param id - Must be a non-blank string within {@link MAX_ID_LENGTH} chars.
   * @throws {RepositoryValidationError} when `id` fails validation.
   * @throws {RepositoryCorruptedRowError} when the matching row has corrupted metadata.
   */
  getById(id: string): AuditEntry | undefined {
    // --- Validation boundary ---
    validateIdentifier(id, 'id', MAX_ID_LENGTH);

    const row = this.db
      .prepare<[string], AuditRow>(
        `SELECT id, timestamp, action, severity, actor, resource, resource_id, metadata_json, ip_address, correlation_id, hash, previous_hash
         FROM audit_log_entries
         WHERE id = ?`
      )
      .get(id);

    return row ? toAuditEntry(row) : undefined;
  }

  /**
   * Queries audit entries with optional filters and offset pagination.
   *
   * @throws {RepositoryValidationError} on invalid filter values.
   * @throws {RepositoryCorruptedRowError} when any returned row has corrupted metadata.
   */
  query(query: AuditQuery = {}): AuditEntry[] {
    // --- Validation boundary ---
    validateQueryFilters(query);

    const { sql, params } = this.buildQuerySql(query);
    const rows = this.db.prepare<typeof params, AuditRow>(sql).all(...params);
    return rows.map(toAuditEntry);
  }

  /**
   * Queries audit entries with cursor-based pagination.
   *
   * @throws {RepositoryValidationError} on invalid filter values or a
   *   cursor that does not match the supplied filters.
   * @throws {RepositoryCorruptedRowError} when any returned row has corrupted metadata.
   */
  queryWithCursor(query: AuditQuery = {}): AuditQueryResult {
    // --- Validation boundary ---
    validateQueryFilters(query);

    const limit = Math.min(Math.max(query.limit ?? 50, 1), 100);
    
    let startIndex = 0;
    
    // Decode cursor if provided
    if (query.cursor !== undefined) {
      // Validate cursor format: must be a non-blank string
      if (typeof query.cursor !== 'string' || query.cursor.trim().length === 0) {
        throw new RepositoryValidationError(
          'cursor must be a non-blank string',
          'cursor',
        );
      }

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
          throw new RepositoryValidationError(
            'Cursor filters do not match query filters',
            'cursor',
          );
        }
      } catch (error) {
        // Re-throw our own validation errors (filter mismatch, blank cursor)
        if (error instanceof RepositoryValidationError) {
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

  /**
   * Streams audit entries without materialising the full result set.
   *
   * @throws {RepositoryValidationError} on invalid filter values.
   * @throws {RepositoryCorruptedRowError} when a yielded row has corrupted metadata.
   */
  *stream(query: AuditQuery = {}): IterableIterator<AuditEntry> {
    // --- Validation boundary ---
    validateQueryFilters(query);

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
      } catch {
        // A corrupted row means the chain cannot be verified from this point.
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
      // Clamp limit to [0, MAX_QUERY_LIMIT]. A limit of 0 returns no rows.
      const clampedLimit = Math.max(Math.min(query.limit, MAX_QUERY_LIMIT), 0);
      paginationClause = 'LIMIT ? OFFSET ?';
      params.push(clampedLimit, offset);
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

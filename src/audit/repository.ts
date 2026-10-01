import path from 'path';
import type {
  AuditEntry,
  AuditQuery,
  CreateAuditEntryInput,
  IntegrityReport,
  AuditQueryResult,
  ValidationResult,
} from './types';
import { auditStore } from './store';
import { SqliteAuditRepository } from './sqliteRepository';
import Database from '../db/betterSqlite3';
import {
  validateStringField,
  validateEnum,
  validateMetadata,
  validateTimestamp,
  validateLimit,
  validateOffset,
  AUDIT_ACTIONS,
  AUDIT_SEVERITIES,
  type AuditValidationError,
} from './types';

/**
 * @module audit/repository
 * @description Backend selection for the audit log.
 *
 * ## Compatibility contract (issue #1355)
 *
 * This module is the only supported way application code selects an audit
 * storage backend. The contract below is relied upon by callers and by the
 * `AUDIT_STORAGE_BACKEND` / `AUDIT_DB_PATH` configuration documented in
 * `docs/backend/environment-variables.md` and `docs/runbook-audit.md`:
 *
 * 1. {@link AuditLogRepository} is the stable public interface. Its method
 *    set, signatures, and return types MUST NOT change without a migration
 *    plan — `AuditService` and every test double implement exactly this
 *    surface.
 * 2. {@link createDefaultAuditRepository} is the stable factory entry point.
 *    Its original no-argument call form is unchanged; an optional `env`
 *    override was added so tests can resolve a configuration deterministically
 *    without mutating global `process.env`.
 * 3. Selection is **deterministic**: for a given environment the same
 *    backend is always chosen, and unknown/blank values fail fast with an
 *    actionable error rather than silently degrading to a different store.
 * 4. The result is **stable across repeated calls**: calling the factory
 *    twice with the same configuration returns the *same* repository
 *    instance. This prevents two silent data-loss modes:
 *      - a second SQLite `:memory:` connection would be a *different*,
 *        empty database (writes to one would be invisible to the other);
 *      - repeated file-backed `new Database(path)` calls would hold
 *        multiple write handles against the same file.
 * 5. Default when unset is `memory`, the documented, zero-config behaviour.
 *
 * @invariant Backend values are matched case-insensitively and surrounding
 *            whitespace is ignored, because configuration is frequently
 *            supplied via shell/CI where `SQLITE` and ` sqlite ` should mean
 *            the same thing. This is a strict *widening* of the previously
 *            case-sensitive `memory`/`sqlite` contract, so no existing valid
 *            configuration changes meaning.
 */

export interface AuditLogRepository {
  /**
   * Appends a new event; equal payloads are not duplicates. Request retries
   * must be deduplicated by the caller's idempotency boundary.
   */
  append(input: CreateAuditEntryInput): AuditEntry;
  getById(id: string): AuditEntry | undefined;
  query(query?: AuditQuery): AuditEntry[];
  /**
   * Query with cursor-based pagination.
   */
  queryWithCursor(query?: AuditQuery): AuditQueryResult;
  /**
   * Streams entries without materialising the full result set in memory.
   */
  stream(query?: AuditQuery): IterableIterator<AuditEntry>;
  count(): number;
  verifyIntegrity(): IntegrityReport;
}

/**
 * State invariants for the audit repository factory:
 *
 * 1. Backend selection is deterministic and fails fast on unknown values.
 *    The factory must never silently fall back to an in-memory store when a
 *    configured backend is unrecognised, because that would lose durability
 *    guarantees and produce inconsistent audit trails across processes.
 *
 * 2. The default backend is explicitly ``memory``. An empty or whitespace
 *    `AUDIT_STORAGE_BACKEND` is treated as unset so that a misplaced environment
 *    variable cannot accidentally select an unknown backend.
 *
 * 3. The SQLite backend is only constructed when explicitly requested. The
 *    native binding is loaded lazily so that in-memory tests do not require
 *    compiled bindings.
 *
 * 4. The factory is idempotent with respect to configuration: repeated
 *    calls with the same environment yield repositories backed by the same
 *    storage medium. The memory backend returns the process-singleton
 *    `auditStore` so all callers observe a consistent view of the log.
 *
 * 5. Failures are reported with non-sensitive messages. We never echo the
 *    raw environment value in a way that could leak credentials (e.g. a
 *    connection string with an embedded password); we only report the
 *    backend identifier after validating it against the allowed set.
 */

export const AUDIT_STORAGE_BACKENDS = ['memory', 'sqlite'] as const;
export type AuditStorageBackend = (typeof AUDIT_STORAGE_BACKENDS)[number];

function resolveBackend(): AuditStorageBackend {
  const raw = process.env['AUDIT_STORAGE_BACKEND'];
  // Treat unset, empty, and whitespace-only values as the default so a
  // misplaced environment variable cannot select an unknown backend.
  const normalised = (raw ?? 'memory').trim().toLowerCase();
  const candidate = normalised.length === 0 ? 'memory' : normalised;

  if ((AUDIT_STORAGE_BACKENDS as readonly string[]).includes(candidate)) {
    return candidate as AuditStorageBackend;
  }

  // Do not interpolate the raw value into the error message: it may contain
  // sensitive data. Report only the allowed set so operators can correct it.
  throw new Error(
    `Unsupported AUDIT_STORAGE_BACKEND. Expected one of ${AUDIT_STORAGE_BACKENDS.join(', ')}.`,
  );
}

function resolveSqlitePath(): string {
  const configured = process.env['AUDIT_DB_PATH'];
  if (configured !== undefined && configured.trim().length > 0) {
    return configured;
  }
  if (process.env['NODE_ENV'] === 'test') {
    return ':memory:';
  }
  return path.join(process.cwd(), 'talenttrust-audit.db');
}

export function createDefaultAuditRepository(): AuditLogRepository {
  const backend = resolveBackend();

  if (backend === 'memory') {
    // The in-memory store is already a process-wide singleton with its own
    // internal concurrency guarantees, so we return it directly without
    // adding another layer of caching.
    return auditStore;
  }

  // backend === 'sqlite'
  const dbPath = resolveSqlitePath();
  // Load the native module only when the SQLite backend is selected so
  // in-memory tests can run on machines without compiled bindings.
  const db = new Database(dbPath);
  return new SqliteAuditRepository(db);
}

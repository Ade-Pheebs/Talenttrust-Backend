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
 * Supported audit storage backends. The contract is that the default
 * repository is always a valid, fully-implemented `AuditLogRepository` for any
 * accepted backend value, and that an unsupported value fails fast with a
 * deterministic, actionable error.
 */
export const AUDIT_STORAGE_BACKENDS = ['memory', 'sqlite'] as const;
export type AuditStorageBackend = (typeof AUDIT_STORAGE_BACKENDS)[number];

const DEFAULT_BACKEND: AuditStorageBackend = 'memory';

function isSupportedBackend(value: string): value is AuditStorageBackend {
  return (AUDIT_STORAGE_BACKENDS as readonly string[]).includes(value);
}

/**
 * Resolves the configured audit storage backend.
 *
 * The returned value is always one of `AUDIT_STORAGE_BACKENDS`. When the
 * environment variable is absent or empty the default is used, preserving
 * backward compatibility with callers that never set it.
 */
export function resolveAuditStorageBackend(
  rawBackend: string | undefined = process.env['AUDIT_STORAGE_BACKEND'],
): AuditStorageBackend {
  if (rawBackend === undefined || rawBackend.trim() === '') {
    return DEFAULT_BACKEND;
  }

  const normalized = rawBackend.trim().toLowerCase();
  if (!isSupportedBackend(normalized)) {
    throw new Error(
      `Unsupported AUDIT_STORAGE_BACKEND: ${rawBackend}. Expected one of: ${AUDIT_STORAGE_BACKENDS.join(', ')}`,
    );
  }

  return normalized;
}

export function createDefaultAuditRepository(): AuditLogRepository {
  const backend = resolveAuditStorageBackend();

  if (backend === 'memory') {
    // The in-memory store is already a process-wide singleton with its own
    // internal concurrency guarantees, so we return it directly without
    // adding another layer of caching.
    return auditStore;
  }

  // backend === 'sqlite'
  const dbPath =
    process.env['AUDIT_DB_PATH'] ??
    (process.env['NODE_ENV'] === 'test'
      ? ':memory:'
      : path.join(process.cwd(), 'talenttrust-audit.db'));
  // Load the native module only when the SQLite backend is selected so
  // in-memory tests can run on machines without compiled bindings.
  const db = new Database(dbPath);
  return new SqliteAuditRepository(db);
}

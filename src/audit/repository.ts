import path from 'path';
import type { AuditEntry, AuditQuery, CreateAuditEntryInput, IntegrityReport, AuditQueryResult } from './types';
import { auditStore } from './store';
import { SqliteAuditRepository } from './sqliteRepository';
import Database from '../db/betterSqlite3';

export interface AuditLogRepository {
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
    return auditStore;
  }

  // backend === 'sqlite'
  const dbPath = resolveSqlitePath();
  // Load the native module only when the SQLite backend is selected so
  // in-memory tests can run on machines without compiled bindings.
  const db = new Database(dbPath);
  return new SqliteAuditRepository(db);
}

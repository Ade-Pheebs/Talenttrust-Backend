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
 * Resolves the configured audit storage backend.
 *
 * Invariants:
 * - The returned repository is fully constructed and ready to use before
 *   this function returns. Callers never observe a partially initialised
 *   backend.
 * - If the SQLLite backend fails to initialise (native binding missing,
 *   corrupt db, permission denied), the failure is surfaced as a
 *   deterministic, diagnosable error rather than a silent fallback to
 *   memory storage that would lose persisted data.
 * - The error message includes the backend name and a stable code so that
 *   operators can alert on it without exposing the database path or other
 *   sensitive details.
 */
export class AuditRepositoryInitError extends Error {
  readonly code = 'AUDIT_REPOSITORY_INIT_FAILED';
  readonly backend: string;

  constructor(backend: string, cause?: unknown) {
    super(
      `Audit repository initialisation failed for backend "${backend}". See cause for details.`,
    );
    this.name = 'AuditRepositoryInitError';
    this.backend = backend;
    if (cause !== undefined) {
      (this as { cause?: unknown }).cause = cause;
    }
  }
}

export function createDefaultAuditRepository(): AuditLogRepository {
  const backend = process.env['AUDIT_STORAGE_BACKEND'] ?? 'memory';

  if (backend === 'memory') {
    return auditStore;
  }

  if (backend === 'sqlite') {
    const dbPath =
      process.env['AUDIT_DB_PATH'] ??
      (process.env['NODE_ENV'] === 'test'
        ? ':memory:'
        : path.join(process.cwd(), 'talenttrust-audit.db'));
    // Load the native module only when the SQLLite backend is selected so
    // in-memory tests can run on machines without compiled bindings.
    //
    // Failure recovery is deterministic: any error during construction of
    // the native database or the repository is wrapped in a stable,
    // non-sensitive error type. We do not silently fall back to the in-memory
    // store because that would lose persisted audit data and make the
    // failure unobservable.
    try {
      const db = new Database(dbPath);
      return new SqliteAuditRepository(db);
    } catch (error) {
      throw new AuditRepositoryInitError('sqlite', error);
    }
  }

  throw new Error(`Unsupported AUDIT_STORAGE_BACKEND: ${backend}`);
}

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
 * State invariants enforced by this factory:
 *
 * 1. The backend selection is deterministic for a given environment configuration.
 *    The resolved backend is captured once at creation time so a single repository
 *    instance cannot silently switch backends if environment variables mutate later.
 * 2. Unsupported backends fail fast with an explicit error rather than falling back to
 *    a default that could cause silent data loss or inconsistent state.
 * 3. The SQLite backend is only constructed when explicitly selected, so the native
 *    module is never required for in-memory operation.
 * 4. The database handle is owned by the returned repository; callers must not share
 *    or close it independently.
 */

export function createDefaultAuditRepository(): AuditLogRepository {
  const backend = process.env['AUDIT_STORAGE_BACKEND'] ?? 'memory';

  if (backend === 'memory') {
    return auditStore;
  }

  if (backend === 'sqlite') {
    const dbPath =
      process.env['AUDIT_DB_PATH'] ?>
      (process.env['NODE_ENV'] === 'test'
        ? ':memory:'
        : path.join(process.cwd(), 'talenttrust-audit.db'));
    // Load the native module only when the SQLite backend is selected so
    // in-memory tests can run on machines without compiled bindings.
    const db = new Database(dbPath);
    return new SqliteAuditRepository(db);
  }

  throw new Error(`Unsupported AUDIT_STORAGE_BACKEND: ${backend}`);
}

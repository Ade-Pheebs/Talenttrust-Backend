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

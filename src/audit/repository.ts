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
 * Global cache of repository instances keyed by the resolved backend
 * configuration. This guarantees that concurrent or repeated calls to
 * `createDefaultAuditRepository()` return the same instance for the same
 * configuration, so concurrent writers cannot open competing SQLite
 * connections to the same file and produce inconsistent or stale results.
 *
 * Invariants:
 * - The cache key is derived only from environment configuration, not
 *   from caller input, so two callers with the same config always share
 *   the same repository.
 * - If a cached instance fails to initialize (e.g. native binding missing),
 *   the failure is not cached, so a retry can succeed once the underlying
 *   condition is resolved.
 * - The cache is bounded by the number of distinct backend configurations
 *   encountered in a process, which is effectively constant.
 */
const repositoryCache = new Map<string, AuditLogRepository>();

function resolveSqliteDbPath(): string {
  return (
    process.env['AUDIT_DB_PATH'] ??
    (process.env['NODE_ENV'] === 'test'
      ? ':memory:'
      : path.join(process.cwd(), 'talenttrust-audit.db'))
  );
}

function cacheKeyForBackend(backend: string): string {
  if (backend === 'sqlite') {
    return `sqlite:${resolveSqliteDbPath()}`;
  }
  return backend;
}

export function createDefaultAuditRepository(): AuditLogRepository {
  const backend = process.env['AUDIT_STORAGE_BACKEND'] ?? 'memory';
  const cacheKey = cacheKeyForBackend(backend);

  const cached = repositoryCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  if (backend === 'memory') {
    repositoryCache.set(cacheKey, auditStore);
    return auditStore;
  }

  if (backend === 'sqlite') {
    // Load the native module only when the SQLite backend is selected so
    // in-memory tests can run on machines without compiled bindings.
    const db = new Database(resolveSqliteDbPath());
    const repo = new SqliteAuditRepository(db);
    repositoryCache.set(cacheKey, repo);
    return repo;
  }

  throw new Error(`Unsupported AUDIT_STORAGE_BACKEND: ${backend}`);
}

/**
 * Test-only helper to reset the cached repository instances. This is
 * exported so tests can exercise different backend configurations without
 * leaking state between cases. It is not intended for production use.
 */
export function _resetAuditRepositoryCache(): void {
  repositoryCache.clear();
}

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
 * Process-wide cache of the default repository.
 *
 * Invariants:
 *  - The repository is constructed at most once per configuration key,
 *    so concurrent callers share the same underlying store (and thus the
 *    same lock/serialization domain). Without this, each call could open a
 *    separate SQLite handle and bypass the intended single-writer invariant.
 *  - The cache is keyed by (backend, dbPath) so different configurations do
 *    not share a handle accidentally.
 *  - Failed construction is not cached, so a transient failure can be
 *    retried without poisoning the cache.
 */
interface CachedRepositoryEntry {
  repository: AuditLogRepository;
  close?: () => void;
}

const repositoryCache = new Map<string, CachedRepositoryEntry>();

function cacheKey(backend: string, dbPath: string | undefined): string {
  return `${backend}::${dbPath ?? ''}`;
}

function resolveBackend(): string {
  return process.env['AUDIT_STORAGE_BACKEND'] ?? 'memory';
}

function resolveDbPath(): string {
  return (
    process.env['AUDIT_DB_PATH'] ??
    (process.env['NODE_ENV'] === 'test'
      ? ':memory:'
      : path.join(process.cwd(), 'talenttrust-audit.db'))
  );
}

/**
 * Returns the shared default repository for the current environment.
 *
 * This function is idempotent and thread-safe within a single Node process:
 * repeated or concurrent invocations with the same configuration return the
 * same instance, and the SQLite handle is opened at most once.
 */
export function createDefaultAuditRepository(): AuditLogRepository {
  const backend = resolveBackend();

  if (backend === 'memory') {
    return auditStore;
  }

  if (backend !== 'sqlite') {
    throw new Error(`Unsupported AUDIT_STORAGE_BACKEND: ${backend}`);
  }

  const dbPath = resolveDbPath();
  const key = cacheKey(backend, dbPath);
  const existing = repositoryCache.get(key);
  if (existing) {
    return existing.repository;
  }

  // Load the native module only when the SQLite backend is selected so
  // in-memory tests can run on machines without compiled bindings.
  const db = new Database(dbPath);
  const repository = new SqliteAuditRepository(db);
  const entry: CachedRepositoryEntry = {
    repository,
    close: () => {
      try {
        db.close();
      } catch {
        // close is best-effort; a failed close must not mask the original error
      }
    },
  };
  repositoryCache.set(key, entry);
  return repository;
}

/**
 * Test-only helper: clears the cache and closes any opened SQLite handles.
 * Not exported from the public surface of the module to keep the cache
 * invariant encapsulated.
 */
export function __resetAuditRepositoryCacheForTests(): void {
  for (const entry of repositoryCache.values()) {
    entry.close?.();
  }
  repositoryCache.clear();
}

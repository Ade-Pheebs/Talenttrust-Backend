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
 * Process-wide cache of the default repository.
 *
 * Invariants:
 *  - The default repository is a concurrency-safe singleton. Concurrent
 *    calls to `createDefaultAuditRepository()` must never open multiple
 *    SQLite connections or return different instances for the same config.
 *  - The cache key is derived from the resolved backend + database path so
 *    tests that mutate env vars between calls still get isolated instances.
 *  - The cache is bounded to avoid unbounded memory growth in long-running
 *    processes that legacy-code reconfigures at runtime.
 */
interface CachedRepositoryEntry {
  repository: AuditLogRepository;
  close?: () => void;
}

const MAX_CACHE_ENTRIES = 8;

const repositoryCache = new Map<string, CachedRepositoryEntry>();

function cacheKey(backend: string, dbPath: string | undefined): string {
  return `${backend}::${dbPath ?? '<unset>'}`;
}

function resolveDbPath(): string {
  return (
    process.env['AUDIT_DB_PATH'] ??
    (process.env['NODE_ENV'] === 'test'
      ? ':memory:'
      : path.join(process.cwd(), 'talenttrust-audit.db'))
  );
}

function getOrCreate(
  key: string,
  factory: () => CachedRepositoryEntry,
): AuditLogRepository {
  const existing = repositoryCache.get(key);
  if (existing) {
    // Refresh LRU order so hot keys are evicted last.
    repositoryCache.delete(key);
    repositoryCache.set(key, existing);
    return existing.repository;
  }

  // Note: Node.js is single-threaded for JS execution, and the factory below
  // is synchronous. This guarantees that two interleaved calls cannot both
  // observe a cache miss and create duplicate SQLite connections.
  const created = factory();
  repositoryCache.set(key, created);

  // Evict least-recently used entries and close their underlying resources.
  while (repositoryCache.size > MAX_CACHE_ENTRIES) {
    const oldestKey = repositoryCache.keys().next().value;
    if (oldestKey === undefined) break;
    const evicted = repositoryCache.get(oldestKey);
    repositoryCache.delete(oldestKey);
    try {
      evicted?.close?.();
    } catch {
      // Best-effort cleanup; eviction must not throw.
    }
  }

  return created.repository;
}

/**
 * Resets the process-wide repository cache. Intended for tests and for
 * controlled shutdown paths. Closes any cached SQLite connections.
 */
export function resetDefaultAuditRepository(): void {
  for (const [, entry] of repositoryCache) {
    try {
      entry.close?.();
    } catch {
      // Best-effort cleanup.
    }
  }
  repositoryCache.clear();
}

export function createDefaultAuditRepository(): AuditLogRepository {
  const backend = process.env['AUDIT_STORAGE_BACKEND'] ?? 'memory';

  if (backend === 'memory') {
    // The in-memory store is already a process-wide singleton with its own
    // internal concurrency guarantees, so we return it directly without
    // adding another layer of caching.
    return auditStore;
  }

  if (backend === 'sqlite') {
    const dbPath = resolveDbPath();
    const key = cacheKey('sqlite', dbPath);

    return getOrCreate(key, () => {
      // Load the native module only when the SQLite backend is selected so
      // in-memory tests can run on machines without compiled bindings.
      const db = new Database(dbPath);
      const repository = new SqliteAuditRepository(db);
      return {
        repository,
        close: () => {
          // better-sqlite3 exposes a synchronous `close`. Guard against
          // double-close during eviction races.
          try {
            (db as unknown as { close?: () => void }).close?.();
          } catch {
            // Ignore close failures during eviction.
          }
        },
      };
    });
  }

  // Wrap with validation layer
  return new ValidatingAuditRepository(innerRepository);
}

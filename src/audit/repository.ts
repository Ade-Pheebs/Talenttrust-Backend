import path from 'path';
import type { AuditEntry, AuditQuery, CreateAuditEntryInput, IntegrityReport, AuditQueryResult } from './types';
import { auditStore } from './store';
import { SqliteAuditRepository } from './sqliteRepository';
import Database from '../db/betterSqlite3';

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

  return new SqliteAuditRepository(db);
}

/**
 * Build (or return the cached) audit repository for the current environment.
 *
 * @see module documentation for the full compatibility contract and the
 *      stability invariant that makes repeated calls return an identical
 *      instance for identical configuration.
 */
export function createDefaultAuditRepository(
  env: NodeJS.ProcessEnv = process.env,
): AuditLogRepository {
  const config = resolveAuditStorageConfig(env);
  const key = cacheKey(config);

  const cached = repositoryCache.get(key);
  if (cached) {
    return cached;
  }

  const repository = createRepositoryFor(config);
  repositoryCache.set(key, repository);
  return repository;
}

/**
 * Drop all cached repository instances.
 *
 * @internal Test-only hook. Production code must never call this: evicting a
 * cached SQLite connection without closing it leaks the underlying handle,
 * and evicting an in-memory repository silently discards the audit log.
 */
export function resetAuditRepositoryCache(): void {
  repositoryCache.clear();
}

/**
 * Test-only helper to reset the cached repository instances. This is
 * exported so tests can exercise different backend configurations without
 * leaking state between cases. It is not intended for production use.
 */
export function _resetAuditRepositoryCache(): void {
  repositoryCache.clear();
}

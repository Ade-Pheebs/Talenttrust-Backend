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

/** Backend identifiers accepted by {@link createDefaultAuditRepository}. */
export type AuditStorageBackend = 'memory' | 'sqlite';

/**
 * Resolved, normalised storage configuration. Exported so operators/tests can
 * assert exactly which backend a given environment selects without opening a
 * database as a side effect.
 *
 * @warning The `dbPath` for a SQLite backend may be `':memory:'`, which is
 *          *connection*-scoped: two connections to `:memory:` are two
 *          independent stores. See the stability invariant above.
 */
export type AuditStorageConfig =
  | { backend: 'memory' }
  | { backend: 'sqlite'; dbPath: string };

/** Backends considered valid; used only to build the fail-fast error message. */
const SUPPORTED_BACKENDS: readonly AuditStorageBackend[] = ['memory', 'sqlite'];

/**
 * Normalise + validate the raw `AUDIT_STORAGE_BACKEND` value.
 *
 * Blank/undefined means "not configured" and resolves to the documented
 * default (`memory`). Anything else is trimmed and lower-cased before the
 * lookup. Unknown values throw synchronously — a typo must never silently
 * select a different backend than the operator intended.
 *
 * @throws {Error} when the value is non-blank and not a supported backend.
 */
export function resolveAuditStorageBackend(rawBackend: string | undefined): AuditStorageBackend {
  const normalised = (rawBackend ?? '').trim().toLowerCase();
  if (normalised === '') {
    return 'memory';
  }
  if ((SUPPORTED_BACKENDS as readonly string[]).includes(normalised)) {
    return normalised as AuditStorageBackend;
  }
  // Preserve the historical `Unsupported AUDIT_STORAGE_BACKEND: <value>`
  // prefix for any caller matching on it, then add the accepted values so
  // the failure is self-diagnosing.
  throw new Error(
    `Unsupported AUDIT_STORAGE_BACKEND: ${rawBackend}. Accepted values: ${SUPPORTED_BACKENDS.join(', ')}`,
  );
}

/**
 * Resolve the effective SQLite database path.
 *
 * Contract (unchanged from the original implementation):
 *   - explicit `AUDIT_DB_PATH` always wins;
 *   - otherwise tests use an ephemeral `:memory:` database;
 *   - otherwise the file lives in the current working directory.
 *
 * A blank `AUDIT_DB_PATH` (e.g. `AUDIT_DB_PATH=` exported by a shell) is
 * treated as unset rather than as an empty filename.
 */
export function resolveAuditDbPath(env: NodeJS.ProcessEnv = process.env): string {
  const configured = (env['AUDIT_DB_PATH'] ?? '').trim();
  if (configured !== '') {
    return configured;
  }
  if (env['NODE_ENV'] === 'test') {
    return ':memory:';
  }
  return path.join(process.cwd(), 'talenttrust-audit.db');
}

/**
 * Pure resolver for the whole storage configuration. Kept side-effect free so
 * it can be unit-tested and used for logging/observability without touching
 * the filesystem or the native driver.
 */
export function resolveAuditStorageConfig(
  env: NodeJS.ProcessEnv = process.env,
): AuditStorageConfig {
  const backend = resolveAuditStorageBackend(env['AUDIT_STORAGE_BACKEND']);

  if (backend === 'sqlite') {
    return { backend: 'sqlite', dbPath: resolveAuditDbPath(env) };
  }

  return { backend: 'memory' };
}

/**
 * Instance cache keyed by resolved configuration.
 *
 * @internal Exported only through {@link resetAuditRepositoryCache} for tests.
 */
const repositoryCache = new Map<string, AuditLogRepository>();

function cacheKey(config: AuditStorageConfig): string {
  return config.backend === 'sqlite' ? `sqlite:${config.dbPath}` : 'memory';
}

function createRepositoryFor(config: AuditStorageConfig): AuditLogRepository {
  if (config.backend === 'memory') {
    return auditStore;
  }

  // Load the native module only when the SQLite backend is selected so
  // in-memory tests can run on machines without compiled bindings.
  let db: ReturnType<typeof Database>;
  try {
    db = new Database(config.dbPath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Failed to open audit SQLite database at "${config.dbPath}": ${message}`,
    );
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

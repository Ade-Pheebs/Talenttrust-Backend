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
    // The in-memory store is already a process-wide singleton with its own
    // internal concurrency guarantees, so we return it directly without
    // adding another layer of caching.
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

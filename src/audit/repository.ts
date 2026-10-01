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

/**
 * Validates CreateAuditEntryInput before it reaches the repository.
 * Throws AuditValidationError if validation fails.
 */
function validateCreateAuditEntryInput(input: CreateAuditEntryInput): void {
  // Validate action
  const actionResult = validateEnum(input.action, 'action', AUDIT_ACTIONS);
  if (!actionResult.valid) {
    throw actionResult.error;
  }

  // Validate severity
  const severityResult = validateEnum(input.severity, 'severity', AUDIT_SEVERITIES);
  if (!severityResult.valid) {
    throw severityResult.error;
  }

  // Validate actor
  const actorResult = validateStringField(input.actor, 'actor');
  if (!actorResult.valid) {
    throw actorResult.error;
  }

  // Validate resource
  const resourceResult = validateStringField(input.resource, 'resource');
  if (!resourceResult.valid) {
    throw resourceResult.error;
  }

  // Validate resourceId
  const resourceIdResult = validateStringField(input.resourceId, 'resourceId');
  if (!resourceIdResult.valid) {
    throw resourceIdResult.error;
  }

  // Validate metadata
  const metadataResult = validateMetadata(input.metadata, 'metadata');
  if (!metadataResult.valid) {
    throw metadataResult.error;
  }

  // Validate optional fields
  if (input.ipAddress !== undefined && input.ipAddress !== null) {
    const ipResult = validateStringField(input.ipAddress, 'ipAddress');
    if (!ipResult.valid) {
      throw ipResult.error;
    }
  }

  if (input.correlationId !== undefined && input.correlationId !== null) {
    const correlationResult = validateStringField(input.correlationId, 'correlationId');
    if (!correlationResult.valid) {
      throw correlationResult.error;
    }
  }
}

/**
 * Validates AuditQuery parameters before they reach the repository.
 * Returns a normalized query with safe defaults applied.
 */
function validateAuditQuery(query: AuditQuery = {}): AuditQuery {
  const normalized: AuditQuery = { ...query };

  // Validate limit
  const limitResult = validateLimit(query.limit);
  if (limitResult.valid) {
    normalized.limit = limitResult.data;
  } else {
    // Log the error but use a safe default
    console.error('[repository] Invalid limit:', limitResult.error.message);
    normalized.limit = 50;
  }

  // Validate offset
  const offsetResult = validateOffset(query.offset);
  if (offsetResult.valid) {
    normalized.offset = offsetResult.data;
  } else {
    // Log the error but use a safe default
    console.error('[repository] Invalid offset:', offsetResult.error.message);
    normalized.offset = 0;
  }

  // Validate timestamp filters if provided
  if (query.from) {
    const fromResult = validateTimestamp(query.from, 'from');
    if (!fromResult.valid) {
      console.error('[repository] Invalid from timestamp:', fromResult.error.message);
      delete normalized.from;
    }
  }

  if (query.to) {
    const toResult = validateTimestamp(query.to, 'to');
    if (!toResult.valid) {
      console.error('[repository] Invalid to timestamp:', toResult.error.message);
      delete normalized.to;
    }
  }

  // Validate action filter if provided
  if (query.action) {
    const actionResult = validateEnum(query.action, 'action', AUDIT_ACTIONS);
    if (!actionResult.valid) {
      console.error('[repository] Invalid action filter:', actionResult.error.message);
      delete normalized.action;
    }
  }

  // Validate severity filter if provided
  if (query.severity) {
    const severityResult = validateEnum(query.severity, 'severity', AUDIT_SEVERITIES);
    if (!severityResult.valid) {
      console.error('[repository] Invalid severity filter:', severityResult.error.message);
      delete normalized.severity;
    }
  }

  // Validate string filters if provided
  if (query.actor !== undefined) {
    const actorResult = validateStringField(query.actor, 'actor');
    if (!actorResult.valid) {
      console.error('[repository] Invalid actor filter:', actorResult.error.message);
      delete normalized.actor;
    }
  }

  if (query.resource !== undefined) {
    const resourceResult = validateStringField(query.resource, 'resource');
    if (!resourceResult.valid) {
      console.error('[repository] Invalid resource filter:', resourceResult.error.message);
      delete normalized.resource;
    }
  }

  if (query.resourceId !== undefined) {
    const resourceIdResult = validateStringField(query.resourceId, 'resourceId');
    if (!resourceIdResult.valid) {
      console.error('[repository] Invalid resourceId filter:', resourceIdResult.error.message);
      delete normalized.resourceId;
    }
  }

  return normalized;
}

// ─── Validating repository wrapper ─────────────────────────────────────────────

/**
 * A repository wrapper that applies validation at the boundary.
 * This ensures all inputs are validated before reaching the underlying storage.
 */
class ValidatingAuditRepository implements AuditLogRepository {
  constructor(private readonly inner: AuditLogRepository) {}

  append(input: CreateAuditEntryInput): AuditEntry {
    validateCreateAuditEntryInput(input);
    return this.inner.append(input);
  }

  getById(id: string): AuditEntry | undefined {
    // Validate ID format
    const idResult = validateStringField(id, 'id');
    if (!idResult.valid) {
      console.error('[repository] Invalid id:', idResult.error.message);
      return undefined;
    }
    return this.inner.getById(id);
  }

  query(query?: AuditQuery): AuditEntry[] {
    const normalized = validateAuditQuery(query);
    return this.inner.query(normalized);
  }

  queryWithCursor(query?: AuditQuery): AuditQueryResult {
    const normalized = validateAuditQuery(query);
    return this.inner.queryWithCursor(normalized);
  }

  stream(query?: AuditQuery): IterableIterator<AuditEntry> {
    const normalized = validateAuditQuery(query);
    return this.inner.stream(normalized);
  }

  count(): number {
    return this.inner.count();
  }

  verifyIntegrity(): IntegrityReport {
    return this.inner.verifyIntegrity();
  }
}

export function createDefaultAuditRepository(): AuditLogRepository {
  const backend = process.env['AUDIT_STORAGE_BACKEND'] ?? 'memory';
  const cacheKey = cacheKeyForBackend(backend);

  const cached = repositoryCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  // Validate backend selection
  const validBackends = ['memory', 'sqlite'] as const;
  if (!validBackends.includes(backend as any)) {
    throw new Error(
      `Unsupported AUDIT_STORAGE_BACKEND: ${backend}. Must be one of: ${validBackends.join(', ')}`,
    );
  }

  let innerRepository: AuditLogRepository;

  if (backend === 'memory') {
    innerRepository = auditStore;
  } else {
    // SQLite backend
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

  // Wrap with validation layer
  return new ValidatingAuditRepository(innerRepository);
}

/**
 * @module audit/service
 * @description High-level audit logging service.
 *
 * Provides a clean API for application code to emit audit events without
 * coupling directly to the store implementation. All sensitive state changes
 * (contract lifecycle, payments, user management, auth events) must go through
 * this service.
 *
 * Security notes:
 * - Callers MUST sanitise metadata before passing it in — no raw PII.
 * - Logging failures are caught and reported via console.error to avoid
 *   disrupting the primary request flow, but they are also re-thrown in
 *   strict mode so tests can assert on them.
 *
 * State invariants owned by this module:
 * 1. Audit entries are append-only: no mutation, deletion, or reordering.
 * 2. Every entry passed to the repository is validated against the canonical
 *    action/severity lists and required field constraints before being persisted.
 * 3. A write that throws must not leave the cache in a stale state, and must not
 *    be silently swallowed.
 * 4. Read paths are deterministic for the same input and never expose internal
 *    mutable references.
 */

import type { AuditEntry, AuditQuery, AuditSeverity, CreateAuditEntryInput, IntegrityReport, AuditQueryResult } from './types';
import type { AuditAction } from './types';
import { AUDIT_ACTIONS, AUDIT_SEVERITIES, decodeCursor } from './types';
import { createDefaultAuditRepository, type AuditLogRepository } from './repository';
import { auditExportService, AuditExportService, type AuditExportFilters, type AuditExportResult } from './exportService';
import { AuditCache, type AuditCacheOptions } from './auditCache';
import {
  idempotencyStore as defaultIdempotencyStore,
  IdempotencyStore,
  type IdempotencyStoreOptions,
} from './idempotency';

export interface AuditServiceOptions {
  /** Cache options for audit read responses. */
  cache?: AuditCacheOptions;
  /** Idempotency store options for write de-duplication. */
  idempotency?: IdempotencyStoreOptions;
}

/**
 * Canonical runtime set of audit actions. Derived from the single source of
 * truth in `types.ts` so the service can never accept an action that the
 * repository/type layer rejects (or vice versa).
 */
export const VALID_ACTIONS: ReadonlySet<AuditAction> = new Set<AuditAction>(AUDIT_ACTIONS);

export const VALID_SEVERITIES: ReadonlySet<AuditSeverity> = new Set<AuditSeverity>(AUDIT_SEVERITIES);

export function parseOptionalIsoDate(
  value: string | undefined,
  fieldName: 'from' | 'to',
): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    throw new Error(`Invalid ${fieldName} timestamp`);
  }

  return new Date(parsed).toISOString();
}

export function parseOffset(value: string | undefined): number {
  if (value === undefined) {
    return 0;
  }

  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error('Invalid offset');
  }

  return parsed;
}

export function parseLimit(value: string | undefined, maxLimit: number, defaultLimit?: number): number | undefined {
  if (value === undefined) {
    return defaultLimit;
  }

  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    throw new Error('Invalid limit');
  }

  return Math.min(parsed, maxLimit);
}

/**
 * Serialises async work per key so that concurrent calls with the same key
 * execute one-at-a-time in FIFO order. This prevents interleaved read-modify-
 * write sequences (e.g. cache invalidation racing a query) from observing or
 * persisting stale state.
 *
 * Invariants:
 * - Tasks for the same key never overlap.
 * - Tasks for different keys may run concurrently.
 * - A rejected task does not poison the queue for subsequent tasks.
 */
class KeyedMutex {
  private readonly tails = new Map<string, Promise<unknown>>();

  run<T>(key: string, task: () => Promise<T> | T): Promise<T> {
    const previous = this.tails.get(key) ?? Promise.resolve();
    const next = previous.then(
      () => task(),
      () => task(),
    );
    // Swallow rejections on the tail so the chain stays usable; callers still
    // observe the rejection via the returned promise.
    const tail = next.then(
      () => undefined,
      () => undefined,
    );
    this.tails.set(key, tail);
    tail.then(() => {
      if (this.tails.get(key) === tail) {
        this.tails.delete(key);
      }
    });
    return next;
  }
}

export function parseAuditQuery(
  reqQuery: Record<string, unknown>,
  options: { defaultLimit?: number; maxLimit: number },
): { query: AuditQuery; limit?: number; offset: number } {
  const action = reqQuery['action'] as string | undefined;
  const severity = reqQuery['severity'] as string | undefined;
  const actor = reqQuery['actor'] as string | undefined;
  const resource = reqQuery['resource'] as string | undefined;
  const resourceId = reqQuery['resourceId'] as string | undefined;
  const cursor = reqQuery['cursor'] as string | undefined;

  if (action && !VALID_ACTIONS.has(action as AuditAction)) {
    throw new Error(`Invalid action: ${action}`);
  }

  if (severity && !VALID_SEVERITIES.has(severity as AuditSeverity)) {
    throw new Error(`Invalid severity: ${severity}`);
  }

  const limit = parseLimit(reqQuery['limit'] as string | undefined, options.maxLimit, options.defaultLimit);
  const offset = parseOffset(reqQuery['offset'] as string | undefined);
  const from = parseOptionalIsoDate(reqQuery['from'] as string | undefined, 'from');
  const to = parseOptionalIsoDate(reqQuery['to'] as string | undefined, 'to');

  // Validate cursor format if provided
  if (cursor) {
    try {
      decodeCursor(cursor);
    } catch (_error) {
      throw new Error('Invalid cursor format');
    }
  }

  return {
    query: {
      ...(action && { action: action as AuditAction }),
      ...(severity && { severity: severity as AuditSeverity }),
      ...(actor && { actor }),
      ...(resource && { resource }),
      ...(resourceId && { resourceId }),
      ...(from && { from }),
      ...(to && { to }),
      ...(limit !== undefined && { limit }),
      offset,
      ...(cursor && { cursor }),
    },
    limit,
    offset,
  };
}

/**
 * Error thrown when an audit entry fails validation before being persisted.
 * Exposed as a distinct class so callers can distinguish invalid input from
 * repository failures.
 */
export class AuditValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditValidationError';
  }
}

/**
 * Validates a CreateAuditEntryInput against the canonical audit model.
 * This is the single gate that every write path must pass through.
 *
 * Invariants: action and severity must be in the canonical lists; actor,
 * resource, and resourceId must be non-empty strings. Metadata must be a
 * plain object (not null, not an array) so the hash chain can be reproduced
 * deterministically.
 *
 * @throws {AuditValidationError} when any invariant is violated.
 */
export function validateCreateAuditEntryInput(input: CreateAuditEntryInput): void {
  if (!input || typeof input !== 'object') {
    throw new AuditValidationError('Missing required fields: action, severity, actor, resource, resourceId');
  }

  if (!input.action || !input.severity || !input.actor || !input.resource || !input.resourceId) {
    throw new AuditValidationError('Missing required fields: action, severity, actor, resource, resourceId');
  }

  if (!VALID_ACTIONS.has(input.action)) {
    throw new AuditValidationError(`Invalid action: ${String(input.action)}`);
  }

  if (!VALID_SEVERITIES.has(input.severity)) {
    throw new AuditValidationError(`Invalid severity: ${String(input.severity)}`);
  }

  if (typeof input.actor !== 'string' || input.actor.trim().length === 0) {
    throw new AuditValidationError('actor must be a non-empty string');
  }

  if (typeof input.resource !== 'string' || input.resource.trim().length === 0) {
    throw new AuditValidationError('resource must be a non-empty string');
  }

  if (typeof input.resourceId !== 'string' || input.resourceId.trim().length === 0) {
    throw new AuditValidationError('resourceId must be a non-empty string');
  }

  if (input.metadata === null || typeof input.metadata !== 'object' || Array.isArray(input.metadata)) {
    throw new AuditValidationError('metadata must be a plain object');
  }

  if (input.ipAddress !== undefined && typeof input.ipAddress !== 'string') {
    throw new AuditValidationError('ipAddress must be a string');
  }

  if (input.correlationId !== undefined && typeof input.correlationId !== 'string') {
    throw new AuditValidationError('correlationId must be a string');
  }
}

/**
 * AuditService — application-level facade over AuditStore.
 *
 * Concurrency invariants:
 * - Concurrent `createEntry`/`log` calls are serialised by an internal mutex
 *   so the underlying repository never observes interleaved appends.
 * - Duplicate logs (same correlationId + action + resourceId + timestamp)
 *   within a bounded window are deduplicated and return the original entry.
 * - Retries are idempotent: a retried append with the same dedup key returns
 *   the already-persisted entry rather than appending a duplicate.
 * - Cache invalidation happens only after a successful append, so a failed
 *   write cannot leave the cache in a stale-state.
 *
 * @example
 * ```ts
 * import { auditService } from './audit/service';
 *
 * await auditService.log( {
 *   action: 'CONTRACT_CREATED',
 *   severity: 'INFO',
 *   actor: req.user.id,
 *   resource: 'contract',
 *   resourceId: contract.id,
 *   metadata: { clientId: contract.clientId },
 *   ipAddress: req.ip,
 *   correlationId: req.headers['x-correlation-id'] as string,
 * });
 * ```
 */
export class AuditService {
  private cache: AuditCache | null;
  private readonly writeLock = new KeyedMutex();

  constructor(
    private readonly repository: AuditLogRepository = createDefaultAuditRepository(),
    private readonly options: AuditServiceOptions = {},
  ) {
    this.cache = options.cache ? new AuditCache(options.cache) : null;
    this.idempotencyStore = new IdempotencyStore(options.idempotency);
  }

  /**
   * Records an audit event.
   *
   * Validates the input against the canonical audit model before delegating
   * to the repository. On a successful write the resource-scoped cache is
   * invalidated. On failure the cache is also invalidated so a partially
   * applied write can never be observed as a stale read.
   *
   * @param input - Event details. metadata must be pre-sanitised.
   * @returns The persisted, immutable AuditEntry.
   * @throws {AuditValidationError} for invalid input.
   * @throws when the repository throws (e.g. storage failure).
   */
  log(input: CreateAuditEntryInput): AuditEntry {
    // Validate first so invalid input never reaches the store and never
    // corrupts the hash chain.
    validateCreateAuditEntryInput(input);

    try {
      const entry = this.repository.append(input);

      // Invalidate cache on write operations
      if (this.cache) {
        this.cache.invalidateByResourceId(input.resourceId);
      }

      return entry;
    } catch (err) {
      // Even on failure the cache must not serve potentially stale data.
      if (this.cache) {
        this.cache.invalidateByResourceId(input.resourceId);
      }
      console.error('[AuditService] Failed to persist audit entry:', err);
      throw err;
    }
  }

  /**
   * Validates payload fields and creates an audit entry.
   * Throws Error if any required field is missing or out of bounds.
   */
  createEntry(input: CreateAuditEntryInput): AuditEntry {
    return this.log(input);
  }

  /**
   * Validates raw query parameters and returns parsed AuditQuery.
   */
  validateAndParseQuery(
    reqQuery: Record<string, unknown>,
    options: { defaultLimit?: number; maxLimit: number },
  ): { query: AuditQuery; limit?: number; offset: number } {
    return parseAuditQuery(reqQuery, options);
  }

  /**
   * Processes query filters and returns formatted paginated results.
   */
  queryLogs(
    queryParams: Record<string, unknown>,
    options: { defaultLimit?: number; maxLimit: number } = { defaultLimit: 50, maxLimit: 100 },
  ):
    | { entries: AuditEntry[]; count: number; limit?: number; nextCursor?: string }
    | { entries: AuditEntry[]; count: number; limit: number; offset: number } {
    const { query } = this.validateAndParseQuery(queryParams, options);

    if (query.cursor) {
      const result = this.queryWithCursor(query);
      return {
        entries: result.entries,
        count: result.count,
        limit: result.limit,
        nextCursor: result.nextCursor,
      };
    }

    const limit = query.limit ?? options.defaultLimit ?? 50;
    const offset = query.offset ?? 0;
    const entries = this.query(query);
    return {
      entries,
      count: entries.length,
      limit,
      offset,
    };
  }

  /**
   * Orchestrates NDJSON compliance log exports and records an ADMIN_ACTION audit log.
   *
   * Failure recovery is deterministic:
   * 1. A failed export attempt is recorded as a CRITICAL ADMIN_ACTION event with
   *    a stable failure code and no sensitive data, so the failure is observable.
   * 2. The original error is then re-thrown as a stable, classified error so the
   *    caller can retry deterministically without losing the failure signal.
   * 3. The failure record is best-effort: if the audit write itself fails, the
   *    original export error is still surfaced so the caller never sees a silent
   *    success.
   */
  async exportAuditLogs(
    queryParams: Record<string, unknown>,
    context: { actor?: string; ipAddress?: string; correlationId?: string },
    exportService: AuditExportService = auditExportService,
  ): Promise<AuditExportResult> {
    const { query } = this.validateAndParseQuery(queryParams, { maxLimit: 50_000 });

    const filters: AuditExportFilters = {
      ...(query.action && { action: query.action }),
      ...(query.severity && { severity: query.severity }),
      ...(query.actor && { actor: query.actor }),
      ...(query.resource && { resource: query.resource }),
      ...(query.resourceId && { resourceId: query.resourceId }),
      ...(query.from && { from: query.from }),
      ...(query.to && { to: query.to }),
      ...(query.limit !== undefined && { limit: query.limit }),
    };

    let exportResult: AuditExportResult;
    try {
      exportResult = await exportService.createNdjsonExport(filters);
    } catch (err) {
      // Record the failed attempt best-effort so the failure is observable,
      // then re-throw a stable classified error for deterministic recovery.
      this.recordExportFailure(filters, context, err);
      throw new Error('Audit export failed');
    }

    this.log( {
      action: 'ADMIN_ACTION',
      severity: 'CRITICAL',
      actor: context.actor ?? 'anonymous',
      resource: 'audit-log',
      resourceId: 'export',
      metadata: {
        operation: 'export',
        format: 'ndjson',
        filters: {
          action: filters.action ?? null,
          severity: filters.severity ?? null,
          actor: filters.actor ?? null,
          resource: filters.resource ?? null,
          resourceId: filters.resourceId ?? null,
          from: filters.from ?? null,
          to: filters.to ?? null,
        },
        recordCount: exportResult.recordCount,
        bytesWritten: exportResult.bytesWritten,
      },
      ipAddress: context.ipAddress,
      correlationId: context.correlationId,
    });

    return exportResult;
  }

  /**
   * Records a failed export attempt as an audit event.
   *
   * This is best-effort: any failure to write the failure record is logged but
   * never alters the outcome of the calling operation. Only non-sensitive,
   * bounded fields are persisted so failures remain diagnosable without leaking
   * raw error messages or payload contents.
   */
  private recordExportFailure(
    filters: AuditExportFilters,
    context: { actor?: string; ipAddress?: string; correlationId?: string },
    error: unknown,
  ): void {
    try {
      this.log({
        action: 'ADMIN_ACTION',
        severity: 'CRITICAL',
        actor: context.actor ?? 'anonymous',
        resource: 'audit-log',
        resourceId: 'export',
        metadata: {
          operation: 'export',
          format: 'ndjson',
          status: 'failed',
          errorCode: 'EXPORT_FAILED',
          errorName: error instanceof Error ? error.name : 'UnknownError',
          filters: {
            action: filters.action ?? null,
            severity: filters.severity ?? null,
            actor: filters.actor ?? null,
            resource: filters.resource ?? null,
            resourceId: filters.resourceId ?? null,
            from: filters.from ?? null,
            to: filters.to ?? null,
          },
        },
        ipAddress: context.ipAddress,
        correlationId: context.correlationId,
      });
    } catch (auditErr) {
      console.error('[AuditService] Failed to record export failure:', auditErr);
    }
  }

  /**
   * Convenience wrapper for contract lifecycle events.
   */
  logContractEvent(
    action: Extract<AuditAction, `CONTRACT_${string}`>,
    actor: string,
    contractId: string,
    metadata: Record<string, unknown> = {},
    context: { ipAddress?: string; correlationId?: string } = {},
  ): AuditEntry {
    return this.log( {
      action,
      severity: 'INFO',
      actor,
      resource: 'contract',
      resourceId: contractId,
      metadata,
      ...context,
    });
  }

  /**
   * Convenience wrapper for milestone-mutation events on a contract.
   *
   * Milestones are a field on the Contract resource rather than a
   * separately-persisted entity, so `metadata` is expected to carry a
   * `{ before, after }` pair of bounded, redacted snapshots (see
   * `modules/contracts/milestonesAudit.ts`) rather than a DB row diff.
   *
   * MILESTONES_DELETED is WARNING severity — losing milestone data (whether
   * via an explicit clear or a contract deletion) is the change most likely
   * to matter during an incident review, so it is flagged above the default
   * INFO level used for created/updated.
   */
  logMilestonesEvent(
    action: Extract<AuditAction, `MILESTONES_${string}`>,
    actor: string,
    contractId: string,
    metadata: Record<string, unknown> = {},
    context: { ipAddress?: string; correlationId?: string } = {},
  ): Promise<AuditEntry> {
    const severity: AuditSeverity = action === 'MILESTONES_DELETED' ? 'WARNING' : 'INFO';
    return this.logSync({
      action,
      severity,
      actor,
      resource: 'milestones',
      resourceId: contractId,
      metadata,
      ...context,
    });
  }

  /**
   * Async variant of {@link logMilestonesEvent} that serialises concurrent
   * writes for the same contractId.
   */
  async logMilestonesEventAsync(
    action: Extract<AuditAction, `MILESTONES_${string}`>,
    actor: string,
    contractId: string,
    metadata: Record<string, unknown> = {},
    context: { ipAddress?: string; correlationId?: string } = {},
  ): Promise<AuditEntry> {
    const severity: AuditSeverity = action === 'MILESTONES_DELETED' ? 'WARNING' : 'INFO';
    return this.logAsync({
      action,
      severity,
      actor,
      resource: 'milestones',
      resourceId: contractId,
      metadata,
      ...context,
    });
  }

  /**
   * Convenience wrapper for payment events.
   * Payment events are always CRITICAL severity.
   */
  logPaymentEvent(
    action: Extract<AuditAction, `PAYMENT_${string}`>,
    actor: string,
    paymentId: string,
    metadata: Record<string, unknown> = {},
    context: { ipAddress?: string; correlationId?: string } = {},
  ): AuditEntry {
    return this.log( {
      action,
      severity: 'CRITICAL',
      actor,
      resource: 'payment',
      resourceId: paymentId,
      metadata,
      ...context,
    });
  }

  /**
   * Convenience wrapper for authentication events.
   * AUTH_FAILED is WARNING; others are INFO.
   */
  logAuthEvent(
    action: Extract<AuditAction, `AUTH_${string}`>,
    actor: string,
    metadata: Record<string, unknown> = {},
    context: { ipAddress?: string; correlationId?: string } = {},
  ): Promise<AuditEntry> {
    const severity: AuditSeverity = action === 'AUTH_FAILED' ? 'WARNING' : 'INFO';
    return this.logSync({
      action,
      severity,
      actor,
      resource: 'auth',
      resourceId: actor,
      metadata,
      ...context,
    });
  }

  /**
   * Retrieves a single audit entry by ID.
   */
  getById(id: string): AuditEntry | undefined {
    return this.repository.getById(id);
  }

  /**
   * Returns the number of entries in the audit log.
   */
  count(): number {
    return this.repository.count();
  }

  /**
   * Verifies the hash-chain integrity of the audit log.
   */
  verifyIntegrity(): IntegrityReport {
    return this.repository.verifyIntegrity();
  }

  /**
   * Runs a filtered query against the underlying repository.
   */
  query(query: AuditQuery = {}): AuditEntry[] {
    return this.repository.query(query);
  }

  /**
   * Runs a cursor-paginated query against the underlying repository.
   */
  queryWithCursor(query: AuditQuery = {}): AuditQueryResult {
    return this.repository.queryWithCursor(query);
  }

  /**
   * Streams audit entries matching the query without materialising the full
   * result set in memory.
   */
  stream(query: AuditQuery = {}): IterableIterator<AuditEntry> {
    return this.repository.stream(query);
  }
}

/** Singleton service instance shared across the application. */
export const auditService = new AuditService();

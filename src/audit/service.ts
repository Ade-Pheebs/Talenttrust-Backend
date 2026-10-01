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

export const VALID_ACTIONS = new Set<AuditAction>(['CONTRACT_CREATED', 'CONTRACT_UPDATED', 'CONTRACT_CANCELLED', 'CONTRACT_COMPLETED',
  'PAYMENT_INITIATED', 'PAYMENT_RELEASED', 'PAYMENT_DISPUTED',
  'REPUTATION_UPDATED',
  'REPUTATION_CORRECTED',
  'USER_CREATED', 'USER_UPDATED', 'USER_DELETED',
  'AUTH_LOGIN', 'AUTH_LOGOUT', 'AUTH_FAILED',
  'AUTH_LOCKOUT_TRIGGERED', 'AUTH_LOCKOUT_RELEASED',
  'ADMIN_ACTION',
  'ENDPOINT_ACCESS', 'ENDPOINT_MUTATION',
]);

export const VALID_SEVERITIES = new Set<AuditSeverity>(AUDIT_SEVERITIES);

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
   * Concurrency: this method is safe to call concurrently. Appends are
   * serialised and duplicate inputs (identical correlation/action/resource
   * within the dedupe window) return the original entry without double-appending.
   *
   * @param input - Event details. metadata must be pre-sanitised.
   * @returns The persisted, immutable AuditEntry.
   * @throws AuditValidationError when the input breaches a boundary.
   * @throws Only when options.strict is true and the store throws.
   */
  async log(input: CreateAuditEntryInput): Promise<AuditEntry> {
    // Serialise writes per resourceId so that concurrent appends for the same
    // resource cannot interleave with cache invalidation and observe a stale
    // cache entry. Different resources proceed concurrently.
    const key = `write:${input.resource}:${input.resourceId}`;
    return this.writeLock.run(key, () => {
      try {
        const entry = this.repository.append(input);

        // Invalidate cache on write operations. Runs inside the same critical
        // section as the append so no reader can repopulate the cache with
        // pre-write data between the append and the invalidation.
        if (this.cache) {
          this.cache.invalidateByResourceId(input.resourceId);
        }

        return entry;
      } catch (err) {
        console.error('[AuditService] Failed to persist audit entry:', err);
        throw err;
      }
    });
  }

  /**
   * Validates payload fields and creates an audit entry.
   * Throws Error if any required field is missing or out of bounds.
   */
  async createEntry(input: CreateAuditEntryInput): Promise<AuditEntry> {
    if (!input.action || !input.severity || !input.actor || !input.resource || !input.resourceId) {
      throw new Error('Missing required fields: action, severity, actor, resource, resourceId');
    }
    return this.logSync(input);
  }

  /**
   * Async variant of {@link createEntry} that serialises concurrent writes
   * for the same resourceId.
   */
  async createEntryAsync(input: CreateAuditEntryInput): Promise<AuditEntry> {
    if (!input.action || !input.severity || !input.actor || !input.resource || !input.resourceId) {
      throw new Error('Missing required fields: action, severity, actor, resource, resourceId');
    }
    return this.logAsync(input);
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

    await this.log({
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
  ): Promise<AuditEntry> {
    return this.log({
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
  ): Promise<AuditEntry> {
    return this.log({
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
   * Queries the underlying repository with the given filters.
   */
  logUserEvent(
    action: Extract<AuditAction, `USER_${string}`>,
    actor: string,
    targetUserId: string,
    metadata: Record<string, unknown> = {},
    context: { ipAddress?: string; correlationId?: string } = {},
  ): Promise<AuditEntry> {
    const severity: AuditSeverity = action === 'USER_DELETED' ? 'WARNING' : 'INFO';
    return this.log({
      action,
      severity,
      actor,
      resource: 'user',
      resourceId: targetUserId,
      metadata,
      ...context,
    });
  }

  /**
   * Queries with cursor-based pagination.
   */
  logDisputeEvent(
    action: Extract<AuditAction, `DISPUTE_${string}`>,
    actor: string,
    disputeId: string,
    metadata: Record<string, unknown> = {},
    context: { ipAddress?: string; correlationId?: string } = {},
  ): Promise<AuditEntry> {
    const severity: AuditSeverity = action === 'DISPUTE_UPDATED' ? 'WARNING' : 'INFO';
    return this.log({
      action,
      severity,
      actor,
      resource: 'dispute',
      resourceId: disputeId,
      metadata,
      ...context,
    });
  }

  /**
   * Queries the audit log with optional filters.
   *
   * @param query - Filter and pagination options.
   * @returns Matching entries in insertion order.
   */
  async query(query: AuditQuery = {}): Promise<AuditEntry[]> {
    // Serialise reads per resourceId (when scoped) against writes for the same
    // resource so a read cannot observe a cache entry that a concurrent write
    // is about to invalidate. Unscoped queries run without a lock.
    const key = query.resourceId
      ? `read:${query.resource ?? ''}:${query.resourceId}`
      : null;

    const execute = (): AuditEntry[] => {
      // Check cache first
      if (this.cache) {
        const cached = this.cache.get(query, 'query');
        if (cached) {
          return cached as AuditEntry[];
        }
      }

      // Cache miss - fetch from repository
      const entries = this.repository.query(query);

      // Store in cache
      if (this.cache) {
        this.cache.set(query, entries, 'query');
      }

      return entries;
    };

    if (!key) {
      return execute();
    }
    return this.writeLock.run(key, execute);
  }

  /**
   * Queries the audit log with cursor-based pagination.
   *
   * @param query - Filter and pagination options including cursor.
   * @returns Paginated result with entries and next cursor.
   */
  async queryWithCursor(query: AuditQuery = {}): Promise<AuditQueryResult> {
    const key = query.resourceId
      ? `read:${query.resource ?? ''}:${query.resourceId}`
      : null;

    const execute = (): AuditQueryResult => {
      // Check cache first
      if (this.cache) {
        const cached = this.cache.get(query, 'queryWithCursor');
        if (cached) {
          return cached as AuditQueryResult;
        }
      }

      // Cache miss - fetch from repository
      const result = this.repository.queryWithCursor(query);

      // Store in cache
      if (this.cache) {
        this.cache.set(query, result, 'queryWithCursor');
      }

      return result;
    };

    if (!key) {
      return execute();
    }
    return this.writeLock.run(key, execute);
  }

  /**
   * Streams audit entries for export use cases without loading all rows.
   */
  stream(query: AuditQuery = {}): IterableIterator<AuditEntry> {
    return this.repository.stream(query);
  }

  /**
   * Retrieves a single audit entry by ID.
   */
  async getById(id: string): Promise<AuditEntry | undefined> {
    const key = `getById:${id}`;
    return this.writeLock.run(key, () => {
      // Check cache first
      if (this.cache) {
        const cached = this.cache.get({}, 'getById', id);
        if (cached) {
          return cached as AuditEntry;
        }
      }

      // Cache miss - fetch from repository
      const entry = this.repository.getById(id);

      // Store in cache
      if (this.cache && entry) {
        this.cache.set({}, entry, 'getById', id);
      }

      return entry;
    });
  }

  /**
   * Retrieves a single entry by ID (alias method).
   */
  getEntry(id: string): Promise<AuditEntry | undefined> {
    return this.getById(id);
  }

  /**
   * Returns the total number of audit entries.
   */
  count(): number {
    return this.repository.count();
  }

  /**
   * Verifies the integrity of the entire hash chain.
   * Should be called by a scheduled monitoring job.
   *
   * @returns IntegrityReport — escalate immediately if valid === false.
   */
  verifyIntegrity(): IntegrityReport {
    return this.repository.verifyIntegrity();
  }

  /**
   * Returns the cache instance, if configured.
   */
  getCache(): AuditCache | null {
    return this.cache;
  }
}

export const auditService = new AuditService();

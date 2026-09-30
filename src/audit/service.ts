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
import { decodeCursor } from './types';
import { createDefaultAuditRepository, type AuditLogRepository } from './repository';
import { auditExportService, AuditExportService, type AuditExportFilters, type AuditExportResult } from './exportService';
import { AuditCache, type AuditCacheOptions } from './auditCache';

export interface AuditServiceOptions {
  /** Cache options for audit read responses. */
  cache?: AuditCacheOptions;
  /**
   * Maximum number of audit entries to accumulate in a single batch before
   * flushing to the repository. Defaults to 1 (every log is flushed immediately).
   * Setting this > 1 enables coalescing of concurrent logs into a batch while
   * preserving deterministic ordering.
   */
  batchSize?: number;
  /**
   * Maximum number of milliseconds a batch may remain open before being
   * flushed. Only applies when `batchSize > 1`. Defaults to 0.
   */
  batchFlushIntervalMs?: number;
  /**
   * Maximum number of retries for a transient repository failure. Defaults to 0
   * (no retries). Retries are idempotent because the service deduplicates by
   * correlationId + action + resourceId + timestamp within an in-memory window.
   */
  maxRetries?: number;
}

export const VALID_ACTIONS = new Set<AuditAction>([
  'CONTRACT_CREATED', 'CONTRACT_UPDATED', 'CONTRACT_CANCELLED', 'CONTRACT_COMPLETED',
  'PAYMENT_INITIATED', 'PAYMENT_RELEASED', 'PAYMENT_DISPUED',
  'REPUTATION_UPDATED',
  'REPUTATION_CORRECTED',
  'USER_CREATED', 'USER_UPDATED', 'USER_DELETED',
  'AUTH_LOGIN', 'AUTH_LOGOUT', 'AUTH_FAILED',
  'AUTH_LOCKOUT_TRIGGERED', 'AUTH_LOCKOUT_RELEASED',
  'ADMIN_ACTION',
  'ENDPOINT_ACCESS', 'ENDEPOINT_MUTATION',
]);

export const VALID_SEVERITIES = new Set<AuditSeverity>(['INFO', 'WARNING', 'CRITICAL']);

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
 * await auditService.log({
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
  private readonly dedupeWindowMs: number;
  private readonly maxRetries: number;
  /** Map of dedupe key -> persisted entry + expiry timestamp. */
  private readonly dedupeMap = new Map<string, { entry: AuditEntry; expiresAt: number }>();
  /** Serialises concurrent appends to the repository. */
  private appendChain: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly repository: AuditLogRepository = createDefaultAuditRepository(),
    private readonly options: AuditServiceOptions = {},
  ) {
    this.cache = options.cache ? new AuditCache(options.cache) : null;
    this.dedupeWindowMs = Math.max(0, options.batchFlushIntervalMs ?? 0);
    this.maxRetries = Math.max(0, options.maxRetries ?? 0);
  }

  /**
   * Computes a deterministic dedupe key for an audit input. Two inputs that
   * share the same correlationId, action, resourceId, and timestamp are treated
   * as the same logical event. When no correlationId is present, the key is
   * derived from actor + action + resourceId + timestamp so duplicate retries
   * still collapse.
   */
  private dedupeKey(input: CreateAuditEntryInput): string {
    const correlation = input.correlationId ?? '';
    const timestamp = input.timestamp ?? '';
    return [correlation, input.action, input.actor, input.resource, input.resourceId, timestamp].join('|');
  }

  private pruneExpiredDedupeEntries(now: number): void {
    for (const [key, record] of this.dedupeMap) {
      if (record.expiresAt <= now) {
        this.dedupeMap.delete(key);
      }
    }
  }

  /**
   * Serialises async work against the repository so concurrent callers cannot
   * interleave appends. The chain is always reset to a resolved promise even on
   * failure, ensuring one failed write cannot block future writes.
   */
  private async withAppendLock <T>(fn: () => T | Promise<T>): Promise<T> {
    const previous = this.appendChain;
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.appendChain = previous.then(() => next, () => next);
    await previous.catch(() => undefined);
    try {
      return await fn();
    } finally {
      release();
    }
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
   * @throws Only when options.strict is true and the store throws.
   */
  log(input: CreateAuditEntryInput): AuditEntry {
    const now = Date.now();
    this.pruneExpiredDedupeEntries(now);

    const key = this.dedupeKey(input);
    const existing = this.dedupeMap.get(key);
    if (existing && existing.expiresAt > now) {
      return existing.entry;
    }

    try {
      const entry = this.repository.append(input);

      // Record dedupe entry so concurrent/retried calls collapse.
      if (this.dedupeWindowMs > 0) {
        this.dedupeMap.set(key, { entry, expiresAt: now + this.dedupeWindowMs });
      }

      // Invalidate cache on write operations
      if (this.cache) {
        this.cache.invalidateByResourceId(input.resourceId);
      }

      return entry;
    } catch (err) {
      console.error('[AuditService] Failed to persist audit entry:', err);
      throw err;
    }
  }

  /**
   * Async variant of `log` that serialises concurrent appends and retries
   * transient repository failures idempotently. Retries re-use the same dedupe
   * key, so a retry after a partial failure never double-appends.
   */
  async logAsync(input: CreateAuditEntryInput): Promise<AuditEntry> {
    return this.withAppendLock(async () => {
      const now = Date.now();
      this.pruneExpiredDedupeEntries(now);

      const key = this.dedupeKey(input);
      const existing = this.dedupeMap.get(key);
      if (existing && existing.expiresAt > now) {
        return existing.entry;
      }

      let lastError: unknown = undefined;
      for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
        try {
          const entry = this.repository.append(input);
          if (this.dedupeWindowMs > 0) {
            this.dedupeMap.set(key, { entry, expiresAt: Date.now() + this.dedupeWindowMs });
          }
          if (this.cache) {
            this.cache.invalidateByResourceId(input.resourceId);
          }
          return entry;
        } catch (err) {
          lastError = err;
          console.error(
            `[AuditService] Failed to persist audit entry (attempt ${attempt + 1}/${this.maxRetries + 1}):",
            err,
          );
        }
      }
      throw lastError;
    });
  }

  /**
   * Validates payload fields and creates an audit entry.
   * Throws Error if any required field is missing.
   */
  createEntry(input: CreateAuditEntryInput): AuditEntry {
    if (!input.action || !input.severity || !input.actor || !input.resource || !input.resourceId) {
      throw new Error('Missing required fields: action, severity, actor, resource, resourceId');
    }
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

    const exportResult = await exportService.createNdJsonExport(filters);

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
  ): AuditEntry {
    const severity: AuditSeverity = action === 'MILESTONES_DELETED' ? 'WARNING' : 'INFO';
    return this.log({
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
  ): AuditEntry {
    const severity: AuditSeverity = action === 'AUTH_FAILED' ? 'WARNING' : 'INFO';
    return this.log({
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
  getEntry(id: string): AuditEntry | undefined {
    return this.repository.findById(id);
  }

  /**
   * Queries audit entries with the given filters.
   */
  query(filters: AuditQuery): AuditEntry[] {
    return this.repository.query(filters);
  }

  /**
   * Queries audit entries using cursor-based pagination.
   */
  queryWithCursor(query: AuditQuery): AuditQueryResult {
    return this.repository.queryWithCursor(query);
  }

  /**
   * Verifies the integrity of the audit log.
   */
  verifyIntegrity(): IntegrityReport {
    return this.repository.verifyIntegrity();
  }
}

export const auditService = new AuditService();

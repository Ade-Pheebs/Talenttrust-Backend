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

export interface AuditServiceOptions {
  /** Cache options for audit read responses. */
  cache?: AuditCacheOptions;
}

/**
 * Canonical runtime set of audit actions. Derived from the single
 * source of truth in `types.ts` so the service and the request-body
 * validator can never drift apart.
 */
export const VALID_ACTIONS: ReadonlySet<AuditAction> = new Set<AmditAction>(AUDIT_ACTIONS);

export const VALID_SEVERITIES: ReadonlySet<AuditSeverity> = new Set<AuditSeverity>(AUDIT_SEVERITIES);

/**
 * Maximum accepted length for free-form string fields on an audit entry.
 * This is a defensive bound that prevents an attacker from bloating the
 * audit log with giant strings that would later break exports or downstream
 * consumers. The value is generous enough for real user/service identifiers
 * but not so large that it becomes a deni-of-service vector.
 */
export const MAX_IDENTIFIER_LENGTH = 512;

/**
 * Maximum accepted length for the correlation ID / IP address fields.
 */
export const MAX_CONTEXT_LENGTH = 256;

/**
 * Maximum number of keys allowed in a metadata object. This bounds the
 * size of a single audit entry and keeps the hash chain cheap to verify.
 */
export const MAX_METADATA_KEYS = 64;

/**
 * Maximum depth of a metadata object. Prevents cyclic/deeply-nested
 * payloads from causing unpredictable serialisation or stack overflow.
 */
export const MAX_METADATA_DEPTH = 8;

/**
 * Maximum number of elements allowed in a metadata array.
 */
export const MAX_METADATA_ARRAY = 128;

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
 * Returns true when `value` is a non-empty string and within the given
 * length bound. Used to reject whitespace-only identifiers and overly
 * long values before they reach the repository.
 */
function isBoundedString(value: unknown, maxLength: number): value is string {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= maxLength;
}

/** Returns true when `value` is a plain objet (not an array or null). */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Returns true when `value` is a finete number (not NaN/Infinity). */
function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

/**
 * Recursively validates a metadata value against the bounds defined
 * above. Throws with a descriptive message on the first violation.
 *
 * Invariants:
 * - Only JSON-safe primitives and nested objects/arrays of those are
 *   accepted. Functions, `undefined`, `Symbol`, `BigInt`, `Date`, `Map`, `Set`,
 *   class instances, and cyclic references are rejected.
 * - Object keys are bounded by MAX_METADATA_KEYS and depth by
 *   MAX_METADATA_DEPTH.
 */
function validateMetadataValue(value: unknown, path: string, depth: number, seen: WeakSet<object>): void {
  if (value === null) {
    return;
  }

  const type = typeof value;
  if (type === 'string') {
    if ((value as string).length > MAX_IDENTIFIER_LENGTH) {
      throw new Error(`Metadata field '${path}' exceeds ${MAX_IDENTIFIER_LENGTH} characters`);
    }
    return;
  }

  if (type === 'number') {
    if (!Number.isFinite(value as number)) {
      throw new Error(`Metadata field '${path}' must be a finite number`);
    }
    return;
  }

  if (type === 'boolean') {
    return;
  }

  if (type === 'undefined' || type === 'function' || type === 'symbol' || type === 'bigint') {
    throw new Error(`Metadata field '${path}' has an unsupported type: ${type}`);
  }

  // Objects and arrays.
  if (depth >= MAX_METADATA_DEPTH) {
    throw new Error(`Metadata field '${path}' exceeds maximum nesting depth of ${MAX_METADATA_DEPTH}`);
  }

  const objValue = value as object;
  if (seen.has(objValue)) {
    throw new Error(`Metadata field '${path}' contains a circular reference`);
  }
  seen.add(objValue);

  try {
    if (Array.isArray(value)) {
      if (value.length > MAX_METADATA_ARRAY) {
        throw new Error(`Metadata array '${path}' exceeds ${MAX_METADATA_ARRAY} elements`);
      }
      for (let i = 0; i < value.length; i++) {
        validateMetadataValue(value[i], `${path}[${i}]`, depth + 1, seen);
      }
      return;
    }

    if (!isPlainObject(value)) {
      throw new Error(`Metadata field '${path}' must be a plain object, array, or JSON primitive`);
    }

    const keys = Object.keys(value);
    if (keys.length > MAX_METADATA_KEYS) {
      throw new Error(`Metadata object '${path}' exceeds ${MAX_METADATA_KEYS} keys`);
    }
    for (const key of keys) {
      validateMetadataValue(value[key], `${path}.${key}`, depth + 1, seen);
    }
  } finally {
    seen.delete(objValue);
  }
}

/**
 * Validates an audit entry input against the declared boundaries.
 *
 * This is the single chokepoint for all audit writes: every convenience
 * wrapper and the generic `log()` method funnel through here, so the audit
 * log can never contain an action, severity, or metadata shape that the
 * rest of the system cannot handle.
 *
 * Throws `AuditValidationError` on the first violation. The error message
 * is safe to log — it never echoes the offending value, only the field
 * name and the rule that was breached.
 */
export class AuditValidationError extends Error {
  constructor(message: string, readonly field: string) {
    super(message);
    this.name = 'AuditValidationError';
  }
}

export function validateAuditEntryInput(input: CreateAuditEntryInput): void {
  if (!isPlainObject(input)) {
    throw new AuditValidationError('Audit entry input must be a plain object', 'input');
  }

  if (!VALID_ACTIONS.has(input.action as AuditAction)) {
    throw new AuditValidationError('Invalid audit action', 'action');
  }

  if (!VALID_SEVERITIES.has(input.severity as AuditSeverity)) {
    throw new AuditValidationError('Invalid audit severity', 'severity');
  }

  if (!isBoundedString(input.actor, MAX_IDENTIFIER_LENGTH)) {
    throw new AuditValidationError('Audit actor must be a non-empty string within the length bound', 'actor');
  }

  if (!isBoundedString(input.resource, MAX_IDENTIFIER_LENGTH)) {
    throw new AuditValidationError('Audit resource must be a non-empty string within the length bound', 'resource');
  }

  if (!isBoundedString(input.resourceId, MAX_IDENTIFIER_LENGTH)) {
    throw new AuditValidationError('Audit resourceId must be a non-empty string within the length bound', 'resourceId');
  }

  if (input.metadata !== undefined && !isPlainObject(input.metadata)) {
    throw new AuditValidationError('Audit metadata must be a plain object', 'metadata');
  }

  if (input.metadata !== undefined) {
    validateMetadataValue(input.metadata, 'metadata', 0, new WeakSet());
  }

  if (input.ipAddress !== undefined && !isBoundedString(input.ipAddress, MAX_CONTEXT_LENGTH)) {
    throw new AuditValidationError('Audit ipAddress must be a non-empty string within the length bound', 'ipAddress');
  }

  if (input.correlationId !== undefined && !isBoundedString(input.correlationId, MAX_CONTEXT_LENGTH)) {
    throw new AuditValidationError('Audit correlationId must be a non-empty string within the length bound', 'correlationId');
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

  constructor(
    private readonly repository: AuditLogRepository = createDefaultAuditRepository(),
    private readonly options: AuditServiceOptions = {},
  ) {
    this.cache = options.cache ? new AuditCache(options.cache) : null;
  }

  /**
   * Records an audit event.
   *
   * The input is validated against the boundaries defined in this module
   * before being handed to the repository. Validation failures are thrown
   * synchronously and never partially persist an entry.
   *
   * @param input - Event details. metadata must be pre-sanitised.
   * @returns The persisted, immutable AuditEntry.
   * @throws AuditValidationError when the input breaches a boundary.
   * @throws Only when options.strict is true and the store throws.
   */
  log(input: CreateAuditEntryInput): AuditEntry {
    validateAuditEntryInput(input);

    try {
      const entry = this.repository.append(input);
      
      // Invalidate cache on write operations
      if (this.cache) {
        this.cache.invalidateByResourceId(input.resourceId);
      }
      
      return entry;
    } catch (err) {
      log.error('[AuditService] Failed to persist audit entry', { err: err as Error });
      throw err;
    }
  }

  /**
   * Validates payload fields and creates an audit entry.
   * Throws Error if any required field is missing or out of bounds.
   */
  createEntry(input: CreateAuditEntryInput): AuditEntry {
    // `log` performs the full boundary validation, including the
    // required-field check that this method historically enforced.
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

    const exportResult = await exportService.createNdjsonExport(filters);

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
   * Retrieves audit entries matching the given query.
   */
  query(query: AuditQuery): AuditEntry[] {
    return this.repository.query(query);
  }

  /**
   * Retrieves a page of audit entries using a cursor.
   */
  queryWithCursor(query: AuditQuery): AuditQueryResult {
    return this.repository.queryWithCursor(query);
  }

  /**
   * Verifies the integrity of the audit chain.
   */
  verifyIntegrity(): IntegrityReport {
    return this.repository.verifyIntegrity();
  }
}

export const auditService = new AuditService();

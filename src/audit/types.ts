/**
 * @module audit/types
 * @description Core type definitions for the TalentTrust immutable audit log system.
 *
 * Design principles:
 * - AuditEntry is a sealed, readonly record — no field may be mutated after creation.
 * - Each entry carries a SHA-256 hash of its own content plus the previous entry's hash,
 *   forming a tamper-evident hash chain (similar to a blockchain ledger).
 * - Sensitive payloads are stored as opaque strings; callers must sanitise PII before logging.
 */

/**
 * Every audited action, as a runtime value list.
 *
 * This is the single source of truth: {@link AuditAction} is derived from it,
 * and both the request-body validator (`audit/inputValidation`) and the query
 * filter validator (`audit/router`) validate against this same array, so a new
 * action can never be accepted by one path and rejected by the other.
 *
 * Compatibility contract: this array is the only source of truth for the
 * runtime validation of audit actions. Any action accepted by the runtime
 * must appear here, and any action appearing here must be accepted by the
 * runtime. The `TypeScript type {@link AuditAction} is derived from this array
 * so that the compile-time and runtime contracts cannot diverge.
 */
export const AUDIT_ACTIONS = [
  'CONTRACT_CREATED',
  'CONTRACT_UPDATED',
  'CONTRACT_CANCELLED',
  'CONTRACT_COMPLETED',
  'CONTRACT_DELETED',
  'PAYMENT_INITIATED',
  'PAYMENT_RELEASED',
  'PAYMENT_DISPUTED',
  'REPUTATION_UPDATED',
  'REPUTATION_CORRECTED',
  'USER_CREATED',
  'USER_UPDATED',
  'USER_DELETED',
  'AUTH_LOGIN',
  'AUTH_LOGOUT',
  'AUTH_FAILED',
  'AUTH_LOCKOUT_TRIGGERED',
  'AUTH_LOCKOUT_RELEASED',
  'ADMIN_ACTION',
  'ENDPOINT_ACCESS',
  'ENDPOINT_MUTATION',
  'DEPLOYMENT_PROMOTED',
  'DEPLOYMENT_ROLLED_BACK',
  'MILESTONES_CREATED',
  'MILESTONES_UPDATED',
  'MILESTONES_DELETED',
] as const;

/** Categories of sensitive state changes that must be audited. */
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

/**
 * Runtime lookup set for {@link AUDIT_ACTIONS}.
 *
 * This is derived from the same array as the compile-time type, ensuring that
 * runtime validation and type-level validation cannot diverge. Callers that
 * need to check whether a string is a valid audit action should use this
 * set rather than re-implementing their own list.
 */
export const AUDIT_ACTION_SET: Readonly<Set<string> = new Set(AUDIT_ACTIONS);

/**
 * Type guard for {@link AuditAction}.
 *
 * Returns `true` iff the given value is a string present in {@link AUDIT_ACTIONS}.
 * This is the canonical runtime check for audit actions and must be used by
 * all validation paths (request body, query filters, cursor decoding) so that
 * the compatibility contract is enforced in exactly one place.
 */
export function isAuditAction(value: unknown): value is AuditAction {
  return typeof value === 'string' && AUDIT_ACTION_SET.has(value);
}

export const AUDIT_SEVERITIES = ['INFO', 'WARNING', 'CRITICAL'] as const;

/** Severity level of the audit event. */
export type AuditSeverity = (typeof AUDIT_SEVERITIES)[number];

/**
 * Runtime lookup set for {@link AUDIT_SEVERITIES}.
 */
export const AUDIT_SEVERITY_SET: Readonly<Set<string> = new Set(AUDIT_SEVERITIES);

/**
 * Type guard for {@link AuditSeverity}.
 */
export function isAuditSeverity(value: unknown): value is AuditSeverity {
  return typeof value === 'string' && AUDIT_SEVERITY_SET.has(value);
}

/**
 * An immutable audit log entry.
 * Once created, all fields are readonly and the object is frozen.
 */
export interface AuditEntry {
  /** Unique identifier for this log entry (UUID v4). */
  readonly id: string;
  /** ISO-8601 UTC timestamp of when the event occurred. */
  readonly timestamp: string;
  /** The type of sensitive action that was performed. */
  readonly action: AuditAction;
  /** Severity classification of the event. */
  readonly severity: AuditSeverity;
  /** Actor who performed the action (user ID, service name, or 'system'). */
  readonly actor: string;
  /** Resource type affected (e.g. 'contract', 'user', 'payment'). */
  readonly resource: string;
  /** Identifier of the specific resource instance affected. */
  readonly resourceId: string;
  /**
   * Structured metadata about the change.
   * Must NOT contain raw PII — callers are responsible for sanitisation.
   */
  readonly metadata: Readonly<Record<string, unknown>>;
  /** IP address of the request origin, if available. */
  readonly ipAddress?: string;
  /** Correlation ID for tracing across services. */
  readonly correlationId?: string;
  /**
   * SHA-256 hex digest of this entry's content fields concatenated with
   * the previous entry's hash, enabling tamper detection.
   */
  readonly hash: string;
  /** Hash of the immediately preceding entry, or 'GENESIS' for the first entry. */
  readonly previousHash: string;
}

/** Input required to create a new audit entry (hash fields are computed internally). */
export type CreateAuditEntryInput = Omit<AuditEntry, 'id' | 'timestamp' | 'hash' | 'previousHash'>;

/**
 * Outcome of a single item within a `POST /api/v1/audit/bulk` request.
 * Exactly one of `entry` / `error` is populated, matching `success`.
 */
export interface BulkAuditItemResult {
  /** Position of this item within the submitted `entries` array. */
  index: number;
  success: boolean;
  entry?: AuditEntry;
  error?: string;
}

/** Aggregate response body for `POST /api/v1/audit/bulk`. */
export interface BulkAuditResult {
  results: BulkAuditItemResult[];
  succeeded: number;
  failed: number;
}

/** Opaque cursor for pagination. Encodes position and filters. */
export type AuditCursor = string;

/** Internal cursor structure (encoded to base64 for API). */
export interface CursorData {
  /** ID of the last entry in the previous page. */
  lastId: string;
  /** Timestamp of the last entry for ordering stability. */
  lastTimestamp: string;
  /** Filters applied when this cursor was generated. */
  filters: {
    action?: AuditAction;
    severity?: AuditSeverity;
    actor?: string;
    resource?: string;
    resourceId?: string;
    from?: string;
    to?: string;
  };
}

/** Query filters for retrieving audit log entries. */
export interface AuditQuery {
  action?: AuditAction;
  severity?: AuditSeverity;
  actor?: string;
  resource?: string;
  resourceId?: string;
  /** ISO-8601 start of time range (inclusive). */
  from?: string;
  /** ISO-8601 end of time range (inclusive). */
  to?: string;
  /** Maximum number of results to return. Undefined means "no explicit limit". */
  limit?: number;
  /** Zero-based offset for pagination (deprecated, use cursor instead). */
  offset?: number;
  /** Opaque cursor for pagination. */
  cursor?: AuditCursor;
}

/** Result of a chain integrity verification. */
export interface IntegrityReport {
  valid: boolean;
  totalEntries: number;
  /** Index of the first corrupted entry, if any. */
  firstCorruptedIndex?: number;
  /** ID of the first corrupted entry, if any. */
  firstCorruptedId?: string;
  checkedAt: string;
}

/** Paginated audit query result. */
export interface AuditQueryResult {
  entries: AuditEntry[];
  count: number;
  limit: number;
  /** Opaque cursor for the next page, if more results exist. */
  nextCursor?: string;
}

/**
 * Encodes cursor data to an opaque base64 string.
 *
 * The encoded form is a UTF-8 JSON payload base64-encoded. This format is a
 * compatibility contract: cursors generated by older versions of this service
 * must remain decodable by newer versions. Do not change the encoding without
 * a tested migration path.
 */
export function encodeCursor(data: CursorData): string {
  const json = JSON.stringify(data);
  return Buffer.from(json, 'utf-8').toString('base64');
}

/**
 * Decodes an opaque base64 cursor string to cursor data.
 *
 * This function is the single validation boundary for cursors. It must:
 * - reject malformed base64 and non-JSON payloads with a deterministic error,
 * - reject payloads whose shape does not match {@link CursorData},
 * - reject payloads whose `filters` contain invalid action/severity values,
 * - never throw a raw JSON/Buffer error that could leak internal details.
 *
 * The thrown error message is stable ('Invalid cursor format') so that
 * callers and tests can rely on it as part of the compatibility contract.
 */
export function decodeCursor(cursor: string): CursorData {
  if (typeof cursor !== 'string' || cursor.length === 0) {
    throw new Error('Invalid cursor format');
  }

  let json: string;
  try {
    json = Buffer.from(cursor, 'base64').toString('utf-8');
  } catch {
    throw new Error('Invalid cursor format');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error('Invalid cursor format');
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Invalid cursor format');
  }

  const candidate = parsed as Record<string, unknown>;

  if (typeof candidate.lastId !== 'string' || candidate.lastId.length === 0) {
    throw new Error('Invalid cursor format');
  }

  if (typeof candidate.lastTimestamp !== 'string' || candidate.lastTimestamp.length === 0) {
    throw new Error('Invalid cursor format');
  }

  const filters = candidate.filters;
  if (filters === null || typeof filters !== 'object' || Array.isArray(filters)) {
    throw new Error('Invalid cursor format');
  }

  const filterRecord = filters as Record<string, unknown>;

  if (filterRecord.action !== undefined && !isAuditAction(filterRecord.action)) {
    throw new Error('Invalid cursor format');
  }

  if (filterRecord.severity !== undefined && !isAuditSeverity(filterRecord.severity)) {
    throw new Error('Invalid cursor format');
  }

  const stringFilterKeys = ['actor', 'resource', 'resourceId', 'from', 'to'] as const;
  for (const key of stringFilterKeys) {
    const value = filterRecord[key];
    if (value !== undefined && typeof value !== 'string') {
      throw new Error('Invalid cursor format');
    }
  }

  return {
    lastId: candidate.lastId as string,
    lastTimestamp: candidate.lastTimestamp as string,
    filters: {
      action: filterRecord.action as AuditAction | undefined,
      severity: filterRecord.severity as AuditSeverity | undefined,
      actor: filterRecord.actor as string | undefined,
      resource: filterRecord.resource as string | undefined,
      resourceId: filterRecord.resourceId as string | undefined,
      from: filterRecord.from as string | undefined,
      to: filterRecord.to as string | undefined,
    },
  };
}

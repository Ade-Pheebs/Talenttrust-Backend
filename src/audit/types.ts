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
 */
export const AUDIT_ACTIONS = [
  'CONTRACT_CREATED',
  'CONTRACT_UPDATED',
  'CONTRACT_CANCELLED',
  'CONTRACT_COMPLETED',
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
] as const;

/** Categories of sensitive state changes that must be audited. */
export type AuditAction =
  | 'CONTRACT_CREATED'
  | 'CONTRACT_UPDATED'
  | 'CONTRACT_CANCELLED'
  | 'CONTRACT_COMPLETED'
  | 'CONTRACT_DELETED'
  | 'PAYMENT_INITIATED'
  | 'PAYMENT_RELEASED'
  | 'PAYMENT_DISPUTED'
  | 'REPUTATION_UPDATED'
  | 'REPUTATION_CORRECTED'
  | 'USER_CREATED'
  | 'USER_UPDATED'
  | 'USER_DELETED'
  | 'AUTH_LOGIN'
  | 'AUTH_LOGOUT'
  | 'AUTH_FAILED'
  | 'AUTH_LOCKOUT_TRIGGERED'
  | 'AUTH_LOCKOUT_RELEASED'
  | 'ADMIN_ACTION'
  | 'ENDPOINT_ACCESS'
  | 'ENDPOINT_MUTATION'
  | 'DEPLOYMENT_PROMOTED'
  | 'DEPLOYMENT_ROLLED_BACK'
  | 'MILESTONES_CREATED'
  | 'MILESTONES_UPDATED'
  | 'MILESTONES_DELETED';

export const AUDIT_SEVERITIES = ['INFO', 'WARNING', 'CRITICAL'] as const;

/** Array of all valid AuditAction values for validation. */
export const AUDIT_ACTIONS: readonly AuditAction[] = [
  'CONTRACT_CREATED',
  'CONTRACT_UPDATED',
  'CONTRACT_CANCELLED',
  'CONTRACT_COMPLETED',
  'PAYMENT_INITIATED',
  'PAYMENT_RELEASED',
  'PAYMENT_DISPUTED',
  'REPUTATION_UPDATED',
  'USER_CREATED',
  'USER_UPDATED',
  'USER_DELETED',
  'AUTH_LOGIN',
  'AUTH_LOGOUT',
  'AUTH_FAILED',
  'ADMIN_ACTION',
  'ENDPOINT_ACCESS',
  'ENDPOINT_MUTATION',
  'DEPLOYMENT_PROMOTED',
  'DEPLOYMENT_ROLLED_BACK',
] as const;

/** Severity level of the audit event. */
export type AuditSeverity = (typeof AUDIT_SEVERITIES)[number];

/** Array of all valid AuditSeverity values for validation. */
export const AUDIT_SEVERITIES: readonly AuditSeverity[] = ['INFO', 'WARNING', 'CRITICAL'] as const;

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

/** Encodes cursor data to an opaque base64 string. */
export function encodeCursor(data: CursorData): string {
  const json = JSON.stringify(data);
  return Buffer.from(json, 'utf-8').toString('base64');
}

/** Decodes an opaque base64 cursor string to cursor data. */
export function decodeCursor(cursor: string): CursorData {
  try {
    const json = Buffer.from(cursor, 'base64').toString('utf-8');
    return JSON.parse(json) as CursorData;
  } catch {
    throw new Error('Invalid cursor format');
  }
}

// ─── Validation error types ───────────────────────────────────────────────────

/**
 * Validation error for audit repository operations.
 * Provides structured error information for diagnostic purposes without exposing sensitive data.
 */
export class AuditValidationError extends Error {
  constructor(
    message: string,
    public readonly field: string,
    public readonly value: unknown,
    public readonly constraint: string,
  ) {
    super(message);
    this.name = 'AuditValidationError';
  }
}

/**
 * Result of a validation operation.
 */
export interface ValidationResult<T> {
  valid: boolean;
  data?: T;
  error?: AuditValidationError;
}

// ─── Validation constants ─────────────────────────────────────────────────────

/**
 * Maximum length for string fields in audit entries.
 * This prevents database errors and abuse while accommodating legitimate long values.
 */
export const MAX_STRING_LENGTH = 1000;

/**
 * Maximum length for metadata JSON string when serialized.
 * This prevents excessively large metadata from causing performance issues.
 */
export const MAX_METADATA_LENGTH = 10000;

/**
 * Maximum limit for query results to prevent resource exhaustion.
 */
export const MAX_QUERY_LIMIT = 1000;

/**
 * Minimum limit for query results to prevent accidental zero-limit queries.
 */
export const MIN_QUERY_LIMIT = 1;

// ─── Validation helpers ───────────────────────────────────────────────────────

/**
 * Validates that a string field is not empty and within length limits.
 */
export function validateStringField(
  value: unknown,
  fieldName: string,
  maxLength: number = MAX_STRING_LENGTH,
): ValidationResult<string> {
  if (typeof value !== 'string') {
    return {
      valid: false,
      error: new AuditValidationError(
        `${fieldName} must be a string`,
        fieldName,
        value,
        'type: string',
      ),
    };
  }

  if (value.length === 0) {
    return {
      valid: false,
      error: new AuditValidationError(
        `${fieldName} cannot be empty`,
        fieldName,
        value,
        'minLength: 1',
      ),
    };
  }

  if (value.length > maxLength) {
    return {
      valid: false,
      error: new AuditValidationError(
        `${fieldName} exceeds maximum length of ${maxLength}`,
        fieldName,
        value.length,
        `maxLength: ${maxLength}`,
      ),
    };
  }

  return { valid: true, data: value };
}

/**
 * Validates that a value is a valid ISO-8601 timestamp.
 */
export function validateTimestamp(value: unknown, fieldName: string): ValidationResult<string> {
  if (typeof value !== 'string') {
    return {
      valid: false,
      error: new AuditValidationError(
        `${fieldName} must be a string`,
        fieldName,
        value,
        'type: string',
      ),
    };
  }

  // ISO-8601 regex (simplified but covers most common formats)
  const iso8601Regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/;
  if (!iso8601Regex.test(value)) {
    return {
      valid: false,
      error: new AuditValidationError(
        `${fieldName} must be a valid ISO-8601 timestamp`,
        fieldName,
        value,
        'format: ISO-8601',
      ),
    };
  }

  // Verify it's a valid date
  const date = new Date(value);
  if (isNaN(date.getTime())) {
    return {
      valid: false,
      error: new AuditValidationError(
        `${fieldName} is not a valid date`,
        fieldName,
        value,
        'valid date',
      ),
    };
  }

  return { valid: true, data: value };
}

/**
 * Validates that a value is one of the allowed enum values.
 */
export function validateEnum<T extends string>(
  value: unknown,
  fieldName: string,
  allowedValues: readonly T[],
): ValidationResult<T> {
  if (typeof value !== 'string') {
    return {
      valid: false,
      error: new AuditValidationError(
        `${fieldName} must be a string`,
        fieldName,
        value,
        'type: string',
      ),
    };
  }

  if (!allowedValues.includes(value as T)) {
    return {
      valid: false,
      error: new AuditValidationError(
        `${fieldName} must be one of: ${allowedValues.join(', ')}`,
        fieldName,
        value,
        `enum: [${allowedValues.join(', ')}]`,
      ),
    };
  }

  return { valid: true, data: value as T };
}

/**
 * Validates metadata object (must be plain object, not circular).
 * This is a lightweight check; deep validation is handled by redact.ts.
 */
export function validateMetadata(value: unknown, fieldName: string): ValidationResult<Record<string, unknown>> {
  if (value === null || value === undefined) {
    return { valid: true, data: {} };
  }

  if (typeof value !== 'object' || Array.isArray(value)) {
    return {
      valid: false,
      error: new AuditValidationError(
        `${fieldName} must be a plain object`,
        fieldName,
        value,
        'type: object',
      ),
    };
  }

  // Check serialized length to prevent oversized metadata
  const serialized = JSON.stringify(value);
  if (serialized.length > MAX_METADATA_LENGTH) {
    return {
      valid: false,
      error: new AuditValidationError(
        `${fieldName} serialized size exceeds maximum of ${MAX_METADATA_LENGTH}`,
        fieldName,
        serialized.length,
        `maxSerializedLength: ${MAX_METADATA_LENGTH}`,
      ),
    };
  }

  return { valid: true, data: value as Record<string, unknown> };
}

/**
 * Validates query limit parameter.
 */
export function validateLimit(value: unknown): ValidationResult<number> {
  if (value === undefined || value === null) {
    return { valid: true, data: 50 }; // Default limit
  }

  if (typeof value !== 'number') {
    return {
      valid: false,
      error: new AuditValidationError(
        'limit must be a number',
        'limit',
        value,
        'type: number',
      ),
    };
  }

  if (!isFinite(value)) {
    return {
      valid: false,
      error: new AuditValidationError(
        'limit must be a finite number',
        'limit',
        value,
        'finite',
      ),
    };
  }

  if (value < MIN_QUERY_LIMIT) {
    return {
      valid: false,
      error: new AuditValidationError(
        `limit must be at least ${MIN_QUERY_LIMIT}`,
        'limit',
        value,
        `min: ${MIN_QUERY_LIMIT}`,
      ),
    };
  }

  if (value > MAX_QUERY_LIMIT) {
    return {
      valid: false,
      error: new AuditValidationError(
        `limit cannot exceed ${MAX_QUERY_LIMIT}`,
        'limit',
        value,
        `max: ${MAX_QUERY_LIMIT}`,
      ),
    };
  }

  return { valid: true, data: Math.floor(value) };
}

/**
 * Validates query offset parameter.
 */
export function validateOffset(value: unknown): ValidationResult<number> {
  if (value === undefined || value === null) {
    return { valid: true, data: 0 }; // Default offset
  }

  if (typeof value !== 'number') {
    return {
      valid: false,
      error: new AuditValidationError(
        'offset must be a number',
        'offset',
        value,
        'type: number',
      ),
    };
  }

  if (!isFinite(value)) {
    return {
      valid: false,
      error: new AuditValidationError(
        'offset must be a finite number',
        'offset',
        value,
        'finite',
      ),
    };
  }

  if (value < 0) {
    return {
      valid: false,
      error: new AuditValidationError(
        'offset cannot be negative',
        'offset',
        value,
        'min: 0',
      ),
    };
  }

  return { valid: true, data: Math.floor(value) };
}

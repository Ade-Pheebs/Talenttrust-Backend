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
  | 'ADMIN_ACTION' | 'ENDPOINT_ACCESS'
  | 'ENDPOINT_MUTATION'
  | 'DEPLOYMENT_PROMOTED'
  | 'DEPLOYMENT_ROLLED_BACK'
  | 'MILESTONES_CREATED'
  | 'MILESTONES_UPDATED'
  | 'MILESTONES_DELETED';

export const AUDIT_SEVERITIES = ['INFO', 'WARNING', 'CRITICAL'] as const;

/** Severity level of the audit event. */
export type AuditSeverity = (typeof AUDIT_SEVERITIES)[number];

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

/**
 * Deterministic failure recovery support for the audit export service.
 *
 * These types describe the durable export job model used by `services/exportService.ts`.
 * The invariants are:
 * - Every job has a monotonically increasing `sequence` and a `status` from a closed set.
 * - Partial completion is represented by `cursor` + `progress`, never by dropping data.
 * - Retries are idempotent: the same `retryKey` can never produce two committed jobs.
 * - Concurrent execution is serialised via compare-and-swap on `sequence`.
 */

/** Terminal and non-terminal states of an export job. */
export const EXPORT_JOB_STATUSES = [
  'pending',
  'running',
  'partial',
  'completed',
  'failed',
  'cancelled',
] as const;

export type ExportJobStatus = (typeof EXPORT_JOB_STATUSES)[number];

/** Statuses from which no further transition is allowed. */
export const TERMINAL_EXPORT_JOB_STATUSES: readonly ExportJobStatus[] = [
  'completed',
  'failed',
  'cancelled',
];

/** Record of a single attempt to execute an export job. */
export interface ExportAttempt {
  /** Monotonically increasing attempt number, starting at 1. */
  attempt: number;
  /** ISO-8601 timestamp when the attempt started. */
  startedAt: string;
  /** ISO-8601 timestamp when the attempt finished, if it did. */
  finishedAt?: string;
  /** Outcome of the attempt. */
  outcome: 'success' | 'partial' | 'failure';
  /** Sanitised, non-sensitive error code for diagnosis. */
  errorCode?: string;
}

/**
 * Durable export job record.
 *
 * Invariants:
 * - `sequence` is strictly increasing and unique per job.
 * - `progress.committed` <= `progress.total` always holds.
 * - Terminal statuses are absorbing: once set, no further transition occurs.
 * - `previousHash` chains job versions for tamper-evident recovery.
 */
export interface ExportJob {
  /** Stable job identifier (UUID v4). */
  readonly id: string;
  /** Idempotency key supplied by the caller. */
  readonly retryKey: string;
  /** Current lifecycle status. */
  readonly status: ExportJobStatus;
  /** Monotonically increasing version of this job record. */
  readonly sequence: number;
  /** Opaque resume cursor for partial completion. */
  readonly cursor: string | null;
  /** Progress counters for observability and resume. */
  readonly progress: {
    readonly committed: number;
    readonly total: number;
  };
  /** History of execution attempts. */
  readonly attempts: readonly ExportAttempt[];
  /** ISO-8601 creation timestamp. */
  readonly createdAt: string;
  /** ISO-8601 last-update timestamp. */
  readonly updatedAt: string;
  /** Hash of the previous job version, or 'GENESIS'. */
  readonly previousHash: string;
  /** Hash of this job version for tamper detection. */
  readonly hash: string;
}

/** Result of a job execution attempt. */
export interface ExportJobResult {
  job: ExportJob;
  /** True when the job reached a terminal status. */
  terminal: boolean;
  /** True when the caller may retry with the same retryKey. */
  retryable: boolean;
}

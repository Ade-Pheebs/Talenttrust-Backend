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
 * Maximum number of audit entries that may be submitted in a single bulk
 * request. Enforced by the request validator and by the export service so
 * that concurrent bulk writes cannot exhaust memory or produce unbounded
 * batches. Kept here (rather than in the router) so every entry point shares
 * the same limit.
 */
export const MAX_BULK_AUDIT_ENTRIES = 1000;

/**
 * Maximum number of entries that may be exported in a single page. Bounds
 * the work performed per request so concurrent exports cannot starve the
 * event loop or produce oversized responses.
 */
export const MAX_EXPORT_PAGE_SIZE = 1000;

/** Default page size used when a caller does not supply an explicit limit. */
export const DEFAULT_EXPORT_PAGE_SIZE = 100;

/**
 * Every audited action, as a runtime value list.
 *
 * This is the single source of truth: {@link AuditAction} is derived from it,
 * and request-body, query-filter and service validators consume this array so
 * an action cannot be accepted by one path and rejected by another.
 */
export const AUDIT_ACTIONS = [
  'CONTRACT_CREATED',
  'CONTRACT_UPDATED',
  'CONTRACT_CANCELLED',
  'CONTRACT_COMPLETED',
  'CONTRACT_DELETED',
  'PAYMENT_INITIATED',
  'PAYMENT_RELEASED',
  'PAYMENT_DISPUED',
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
 * Runtime guard for {@link AuditAction}.
 *
 * Use at trust boundaries that receive an action from untyped input (queues,
 * config, decoded payloads) instead of casting with `as AuditAction`: unlike a
 * cast, this actually checks the value against the {@link AUDIT_ACTIONS}
 * vocabulary and narrows the type only when the check succeeds.
 */
export function isAuditAction(value: unknown): value is AuditAction {
  return typeof value === 'string' && (AUDIT_ACTIONS as readonly string[]).includes(value);
}

/** Runtime guard for {@link AuditSeverity}, mirroring {@link isAuditAction}. */
export function isAuditSeverity(value: unknown): value is AuditSeverity {
  return typeof value === 'string' && (AUDIT_SEVERITIES as readonly string[]).includes(value);
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
  readonly metadata: Readonly<Record<string, unknown>;
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

/**
 * A single audit entry that has been sealed into the hash chain. The
 * `sequence` field is a monotonically increasing integer assigned by the
 * store at append time; it is the authoritative ordering key and must be
 * used (instead of `timestamp`) whenever entries are compared or paged.
 */
export interface SealedAuditEntry extends AuditEntry {
  readonly sequence: number;
}

/** Input required to create a new audit entry (hash fields are computed internally). */
export type CreateAuditEntryInput = Omit<AuditEntry, 'id' | 'timestamp' | 'hash' | 'previousHash'>;

/**
 * Outcome of a single item within a `POST /api/v1/audit/bulk `request.
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
  /**
   * Monotonic sequence of the last entry in the previous page. Required for
   * stable pagination under concurrent appends: two entries may share a
   * timestamp, so `lastTimestamp` alone is not a total order.
   */
  lastSequence: number;
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

/** Maximum accepted encoded audit cursor size (8 KiB). */
export const MAX_AUDIT_CURSOR_LENGTH = 8_192;

const AUDIT_ACTION_SET: ReadonlySet<string> = new Set(AUDIT_ACTIONS);
const AUDIT_SEVERITY_SET: ReadonlySet<string> = new Set(AUDIT_SEVERITIES);
const CURSOR_FILTER_KEYS = new Set([
  'action', 'severity', 'actor', 'resource', 'resourceId', 'from', 'to',
]);

function isCanonicalIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

/**
 * Runtime guard for the cursor wire format. Cursors are untrusted query input;
 * validating their complete shape here prevents malformed values from reaching
 * repositories, where they could otherwise trigger silent pagination resets.
 */
function isCursorData(value: unknown): value is CursorData {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const data = value as Record<string, unknown>;
  if (Object.keys(data).some((key) => !['lastId', 'lastTimestamp', 'filters'].includes(key))) return false;
  if (
    typeof data['lastId'] !== 'string' || data['lastId'].length === 0 ||
    typeof data['lastTimestamp'] !== 'string' || !isCanonicalIsoTimestamp(data['lastTimestamp']) ||
    typeof data['filters'] !== 'object' || data['filters'] === null || Array.isArray(data['filters'])
  ) {
    return false;
  }

  const filters = data['filters'] as Record<string, unknown>;
  if (Object.keys(filters).some((key) => !CURSOR_FILTER_KEYS.has(key))) return false;
  for (const [key, filter] of Object.entries(filters)) {
    if (filter === undefined) continue;
    if (key === 'action') {
      if (typeof filter !== 'string' || !AUDIT_ACTION_SET.has(filter)) return false;
    } else if (key === 'severity') {
      if (typeof filter !== 'string' || !AUDIT_SEVERITY_SET.has(filter)) return false;
    } else if (key === 'from' || key === 'to') {
      if (!isCanonicalIsoTimestamp(filter)) return false;
    } else if (typeof filter !== 'string') {
      return false;
    }
  }
  return true;
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

/**
 * Options controlling a single export operation. `snapshotSequence` pins the
 * export to a consistent point in the chain so that entries appended while
 * the export is in flight are not silently included or dropped.
 */
export interface ExportOptions {
  /** Inclusive lower bound on entry sequence. */
  fromSequence?: number;
  /** Inclusive upper bound on entry sequence. */
  toSequence?: number;
  /** Maximum number of entries to return in this page. */
  limit?: number;
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
  /**
   * Sequence of the last entry included in this page. Callers must pass this
   * back as `fromSequence` (or encode it in the cursor) to resume without
   * gaps or duplicates when new entries are appended concurrently.
   */
  lastSequence?: number;
}

/** Encodes validated cursor data to an opaque, bounded base64 string. */
export function encodeCursor(data: CursorData): string {
  try {
    const json = JSON.stringify(data);
    if (typeof json !== 'string') throw new Error('Invalid cursor format');
    // Validate the actual JSON representation, not just the input object: this
    // also excludes values silently dropped by JSON.stringify (e.g. undefined).
    if (!isCursorData(JSON.parse(json) as unknown)) throw new Error('Invalid cursor format');
    const cursor = Buffer.from(json, 'utf-8').toString('base64');
    if (cursor.length > MAX_AUDIT_CURSOR_LENGTH) throw new Error('Invalid cursor format');
    return cursor;
  } catch {
    throw new Error('Invalid cursor format');
  }
}

/** Decodes and validates an opaque base64 cursor string from an untrusted caller. */
export function decodeCursor(cursor: string): CursorData {
  try {
    if (
      typeof cursor !== 'string' || cursor.length === 0 ||
      cursor.length > MAX_AUDIT_CURSOR_LENGTH ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(cursor)
    ) {
      throw new Error('Invalid cursor format');
    }
    const json = Buffer.from(cursor, 'base64').toString('utf-8');
    // Buffer's base64 decoder is permissive; round-trip equality enforces the
    // canonical encoding emitted above and rejects ignored trailing garbage.
    if (Buffer.from(json, 'utf-8').toString('base64') !== cursor) {
      throw new Error('Invalid cursor format');
    }
    const data: unknown = JSON.parse(json);
    if (!isCursorData(data)) throw new Error('Invalid cursor format');
    return data;
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

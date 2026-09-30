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

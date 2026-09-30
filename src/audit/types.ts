/**
 * @module audit/types
 * @description Core type definitions for the TalentTrust immutable audit log system.
 *
 * Design principles:
 * - AuditEntry is a sealed, readonly record — no field may be mutated after creation.
 * - Each entry carries a SHA-256 hash of its own content plus the previous entry's hash,
 *   forming a tamper-evident hash chain (similar to a blockchain ledger).
 * - Sensitive payloads are stored as opaque strings; callers must sanitise PII before logging.
 *
 * State invariants owned by this module:
 * 1. AUDIT_ACTIONS is the single source of truth for valid actions. AuditAction is derived
 *    from it via type constraints, and the runtime guard {@link isAuditAction} is the
 *    only supported way to validate an untrusted value. This prevents drift between
 *    the compile-time union and the runtime allowlist.
 * 2. AuditEntries are immutable at runtime: {@link freezeAuditEntry} deep-freezes the
 *    entry and its metadata so consumers cannot mutate a persisted record.
 * 3. Cursors are opaque and self-describing; {@link decodeCursor} rejects malformed,
 *    truncated, or structurally invalid input instead of returning a partial object.
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
 * Runtime guard that narrows an untrusted value to {@link AuditAction}.
 *
 * This is the only supported way to validate an action at the boundary. It is
 * derived from AUDIT_ACTIONS so the compile-time union and the runtime allowlist
 * can never diverge. The input is treated as `unknown` because it typically comes
 * from JSON request bodies or query parameters.
 */
export function isAuditAction(value: unknown): value is AuditAction {
  return typeof value === 'string' && (AUDIT_ACTIONS as readonly string[]).includes(value);
}

export const AUDIT_SEVERITIES = ['INFO', 'WARNING', 'CRITICAL'] as const;

/** Severity level of the audit event. */
export type AuditSeverity = (typeof AUDIT_SEVERITIES)[number];

/**
 * Runtime guard that narrows an untrusted value to {@link AuditSeverity}.
 */
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
 * Deep-freeze an audit entry and its metadata so a consumer cannot mutate a
 * persisted record after it has been created. This enforces the immutability
 * invariant at runtime, not just in the type system.
 *
 * The function is idempotent and returns the same reference it was given, so
 * callers can use it in a fluent style without changing identity.
 */
export function freezeAuditEntry<T extends AuditEntry>(entry: T): T {
  if (entry.metadata && typeof entry.metadata === 'object') {
    Object.freeze(entry.metadata);
  }
  return Object.freeze(entry);
}

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

/**
 * Decodes an opaque base64 cursor string to cursor data.
 *
 * State invariant: a decoded cursor must be structurally valid. Mangled,
 * truncated, or otherwise malformed cursors are rejected with a stable error
 * message so the router can map them to a 400 response without leaking internal
 * details. This prevents a malformed cursor from silently producing an
 * unfiltered or unbounded page of results.
 */
export function decodeCursor(cursor: string): CursorData {
  if (typeof cursor !== 'string' || cursor.length === 0) {
    throw new Error('Invalid cursor format');
  }

  let parsed: unknown;
  try {
    const json = Buffer.from(cursor, 'base64').toString('utf-8');
    parsed = JSON.parse(json);
  } catch {
    throw new Error('Invalid cursor format');
  }

  if (!isCursorData(parsed)) {
    throw new Error('Invalid cursor format');
  }

  return parsed;
}

/**
 * Structural validation for a decoded cursor. Keeps the decoder from returning
 * a partial or wrong-shaped object that would corrupt pagination state.
 */
function isCursorData(value: unknown): value is CursorData {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const candidate = value as { [key: string]: unknown };
  if (typeof candidate.lastId !== 'string' || candidate.lastId.length === 0) {
    return false;
  }
  if (typeof candidate.lastTimestamp !== 'string' || candidate.lastTimestamp.length === 0) {
    return false;
  }
  if (typeof candidate.filters !== 'object' || candidate.filters === null) {
    return false;
  }

  const filters = candidate.filters as { [key: string]: unknown };
  if (filters.action !== undefined && !isAuditAction(filters.action)) {
    return false;
  }
  if (filters.severity !== undefined && !isAuditSeverity(filters.severity)) {
    return false;
  }
  for (const key of ['actor', 'resource', 'resourceId', 'from', 'to'] as const) {
    const field = filters[key];
    if (field !== undefined && typeof field !== 'string') {
      return false;
    }
  }

  return true;
}

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
 * This is the single source of truth: {@link AuditAction} is *derived* from it
 * (see below), so the compile-time union and the runtime list are the same set
 * by construction and can never drift apart. Every validator in the module
 * consumes this one array:
 *   - `audit/inputValidation` (non-HTTP producers)
 *   - `audit/schemas` (the HTTP body/query contract)
 *   - `audit/service` (`VALID_ACTIONS`, the legacy query parser)
 *
 * Invariant: adding an entry here is the *only* way to add an action to the
 * system. Previously this array, the `AuditAction` union, and the two
 * hand-mirrored copies in `schemas.ts`/`service.ts` had already diverged, so
 * the same action could be accepted by one ingest path and rejected by
 * another.
 */
export const AUDIT_ACTIONS = [
  'CONTRACT_CREATED',
  'CONTRACT_UPDATED',
  'CONTRACT_CANCELLED',
  'CONTRACT_COMPLETED',
  'CONTRACT_DELETED',
  'PAYMENT_INITIATED',
  'PAYMENT_RELEASED',
  'PAYMENT_DISPUTIND',
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
  'CONTRACT_DELETED',
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

// ---------------------------------------------------------------------------
// Cursor codec
//
// Failure-recovery contract (issue #1383):
//   `decodeCursor` is *total and deterministic*. For any input it either
//   returns a fully validated `CursorData` or throws a `CursorFormatError`.
//   It never returns `null`, a primitive, or a partially-populated object —
//   previously `JSON.parse` of base64('null') / base64('{}') produced exactly
//   those, so callers either crashed with a `TypeError` deep in the store or
//   silently restarted pagination. Every rejection carries the same stable
//   message and machine-readable `code`/`reason` and never echoes the raw
//   cursor value (which may be client-controlled).
// ---------------------------------------------------------------------------

/** Returns true when `value` is a non-negative safe integer. */
export function isValidSequence(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/** Decodes an opaque base64 cursor string to cursor data. */
export function decodeCursor(cursor: string): CursorData {
  try {
    const json = Buffer.from(cursor, 'base64').toString('utf-8');
    const parsed = JSON.parse(json) as CursorData;
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      typeof parsed.lastId !== 'string' ||
      typeof parsed.lastTimestamp !== 'string' ||
      !isValidSequence(parsed.lastSequence) ||
      typeof parsed.filters !== 'object' ||
      parsed.filters === null
    ) {
      throw new Error('Invalid cursor format');
    }
    return parsed;
  } catch {
    throw new Error('Invalid cursor format');
  }
}

/** The only filter keys an audit cursor may carry. */
const CURSOR_FILTER_KEYS = [
  'action',
  'severity',
  'actor',
  'resource',
  'resourceId',
  'from',
  'to',
] as const;

type CursorValidation =
  | { ok: true; data: CursorData }
  | { ok: false; reason: CursorFormatErrorReason };

function isValidCursorFilterValue(key: string, value: unknown): boolean {
  if (typeof value !== 'string' || value.length === 0) {
    return false;
  }
  if (key === 'action') {
    return (AUDIT_ACTIONS as readonly string[]).includes(value);
  }
  if (key === 'severity') {
    return (AUDIT_SEVERITIES as readonly string[]).includes(value);
  }
  if (key === 'from' || key === 'to') {
    return !Number.isNaN(Date.parse(value));
  }
  return true;
}

/**
 * Validates an already-parsed value against the {@link CursorData} shape.
 * Total: never throws, never mutates its input.
 */
function validateCursorData(parsed: unknown): CursorValidation {
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, reason: 'not_an_object' };
  }

  const candidate = parsed as Record<string, unknown>;

  const lastId = candidate['lastId'];
  if (typeof lastId !== 'string' || lastId.length === 0) {
    return { ok: false, reason: 'missing_last_id' };
  }

  const lastTimestamp = candidate['lastTimestamp'];
  if (typeof lastTimestamp !== 'string' || lastTimestamp.length === 0) {
    return { ok: false, reason: 'missing_last_timestamp' };
  }
  if (Number.isNaN(Date.parse(lastTimestamp))) {
    return { ok: false, reason: 'invalid_last_timestamp' };
  }

  const filters = candidate['filters'];
  if (typeof filters !== 'object' || filters === null || Array.isArray(filters)) {
    return { ok: false, reason: 'invalid_filters' };
  }

  const rawFilters = filters as Record<string, unknown>;
  const nextFilters: CursorData['filters'] = {};
  for (const key of Object.keys(rawFilters)) {
    if (!(CURSOR_FILTER_KEYS as readonly string[]).includes(key)) {
      return { ok: false, reason: 'invalid_filters' };
    }
    const value = rawFilters[key];
    if (value === undefined) {
      continue;
    }
    if (!isValidCursorFilterValue(key, value)) {
      return { ok: false, reason: 'invalid_filters' };
    }
    (nextFilters as Record<string, unknown>)[key] = value;
  }

  return { ok: true, data: { lastId, lastTimestamp, filters: nextFilters } };
}

/**
 * Non-throwing guard for an already-parsed cursor object.
 * Use when the value may already be in memory and throwing is undesirable.
 */
export function isCursorData(value: unknown): value is CursorData {
  return validateCursorData(value).ok;
}

/**
 * Encodes cursor data to an opaque base64 string.
 *
 * Deterministic: fields and filter keys are serialized in a fixed order and
 * unknown filter keys are dropped, so logically-equal cursor data always
 * produces byte-identical output (which keeps `encodeCursor`/`decodeCursor`
 * a stable round-trip and avoids leaking caller state through the cursor).
 */
export function encodeCursor(data: CursorData): string {
  const payload: CursorData = {
    lastId: data.lastId,
    lastTimestamp: data.lastTimestamp,
    filters: {
      ...(data.filters.action !== undefined && { action: data.filters.action }),
      ...(data.filters.severity !== undefined && { severity: data.filters.severity }),
      ...(data.filters.actor !== undefined && { actor: data.filters.actor }),
      ...(data.filters.resource !== undefined && { resource: data.filters.resource }),
      ...(data.filters.resourceId !== undefined && { resourceId: data.filters.resourceId }),
      ...(data.filters.from !== undefined && { from: data.filters.from }),
      ...(data.filters.to !== undefined && { to: data.filters.to }),
    },
  };
  return Buffer.from(JSON.stringify(payload), 'utf-8').toString('base64');
}

/**
 * Decodes an opaque base64 cursor string to validated cursor data.
 *
 * @throws {CursorFormatError} for every malformed, oversized, tampered, or
 *   structurally-invalid cursor. The same input always throws the same error
 *   with the same `reason`, so callers can recover deterministically (reject
 *   with a 400, or restart pagination) instead of depending on parse luck.
 */
export function decodeCursor(cursor: string): CursorData {
  if (typeof cursor !== 'string') {
    throw new CursorFormatError('not_a_string');
  }
  if (cursor.length === 0) {
    throw new CursorFormatError('empty');
  }
  if (cursor.length > CURSOR_MAX_LENGTH) {
    throw new CursorFormatError('too_long');
  }
  // Standard base64 alphabet, with at most two trailing padding characters.
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cursor)) {
    throw new CursorFormatError('bad_charset');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(cursor, 'base64').toString('utf-8'));
  } catch {
    throw new CursorFormatError('not_json');
  }

  const validation = validateCursorData(parsed);
  if (!validation.ok) {
    throw new CursorFormatError(validation.reason);
  }

  return validation.data;
}

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
  | 'REPTATION_CORRECTED'
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

/**
 * Validation boundaries for the audit cache layer.
 *
 * These constants are the single source of truth for what the cache will
 * accept as input. Every entry point (router, service, bulk handler) must
 * validate against these bounds before calling into the cache so that an
 * invalid key or oversized payload never reaches the store.
 *
 * Invariants:
 * - A cache key must be a non-empty string of at most AUDIT_CACHE_MAX_KEY_LENGTH
 *   characters and must not contain control characters.
 * - A cache value must be serialisable to at most AUDIT_CACHE_MAX_VALUE_BYTES
 *   bytes of UTF-8 JSON.
 * - A cache TTL must be a positive integer no greater than AUDIT_CACHE_MAX_TTL_MS.
 * - The cache capacity must be a positive integer no greater than
 *   AUDIT_CACHE_MAX_CAPACITY and the cache must never exceed it.
 */

/** Maximum number of entries the audit cache may hold. */
export const AUDIT_CACHE_MAX_CAPACITY = 10000;

/** Maximum length of a cache key, in characters. */
export const AUDIT_CACHE_MAX_KEY_LENGTH = 512;

/** Maximum serialised size of a cache value, in UTF-8 bytes. */
export const AUDIT_CACHE_MAX_VALUE_BYTES = 1024 * 1024;

/** Maximum cache TTL in milliseconds (24 hours). */
export const AUDIT_CACHE_MAX_TTL_MS = 24 * 60 * 60 * 1000;

/** Default cache TT\ in milliseconds (5 minutes). */
export const AUDIT_CACHE_DEFAULT_TTL_MS = 5 * 60 * 1000;

/** Minimum cache TTL in milliseconds (1 second). */
export const AUDIT_CACHE_MIN_TTL_MS = 1000;

/** Maximum number of entries accepted in a single bulk request. */
export const AUDIT_CACHE_MAX_BULK_SIZE = 500;

/**
 * Result of validating a cache key.
 * Exactly one of the fields is populated.
 */
export type CacheKeyValidation =
  | { valid: true; key: string }
  | { valid: false; reason: string };

/**
 * Result of validating a cache TTL.
 */
export type CacheTtlValidation =
  | { valid: true; ttlMs: number }
  | { valid: false; reason: string };

/**
 * Result of validating a cache value for serialisation size.
 */
export type CacheValueValidation =
  | { valid: true; bytes: number }
  | { valid: false; reason: string };

/** Control characters (U+0000-U-001F and U-007F) are never allowed in keys. */
const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;

/**
 * Validate an audit cache key.
 *
 * Accepts a non-empty string of at most {@link AUDIT_CACHE_MAX_KEY_LENGTH}
 * characters that contains no control characters. Whitespace is trimmed
 * before validation so that duplicate submissions with incidental padding
 * map to the same canonical key.
 */
export function validateCacheKey(key: unknown): CacheKeyValidation {
  if (typeof key !== 'string') {
    return { valid: false, reason: 'cache key must be a string' };
  }
  const trimmed = key.trim();
  if (trimmed.length === 0) {
    return { valid: false, reason: 'cache key must not be empty' };
  }
  if (trimmed.length > AUDIT_CACHE_MAX_KEY_LENGTH) {
    return {
      valid: false,
      reason: `cache key must be at most ${AUDIT_CACHE_MAX_KEY_LENGTH} characters`,
    };
  }
  if (CONTROL_CHAR_RE.test(trimmed)) {
    return { valid: false, reason: 'cache key must not contain control characters' };
  }
  return { valid: true, key: trimmed };
}

/**
 * Validate a cache TTL.
 *
 * Accepts a positive integer between {@link AUDIT_CACHE_MIN_TTL_MS} and
 * {@link AUDIT_CACHE_MAX_TTL_MS} inclusive. Non-integer, non-finite, NAN and
 * infinite values are rejected. Undefined maps to the default TTL.
 */
export function validateCacheTtl(ttl: unknown): CacheTtlValidation {
  if (ttl === undefined) {
    return { valid: true, ttlMs: AUDIT_CACHE_DEFAULT_TTL_MS };
  }
  if (typeof ttl !== 'number' || !Number.isFinite(ttl) || !Number.isInteger(ttl)) {
    return { valid: false, reason: 'cache TTL must be a finite integer number of milliseconds' };
  }
  if (ttl < AUDIT_CACHE_MIN_TTL_MS) {
    return {
      valid: false,
      reason: `cache TTL must be at least ${AUDIT_CACHE_MIN_TTL_MS} ms`,
    };
  }
  if (ttl > AUDIT_CACHE_MAX_TTL_MS) {
    return {
      valid: false,
      reason: `cache TTL must be at most ${AUDIT_CACHE_MAX_TTL_MS} ms`,
    };
  }
  return { valid: true, ttlMs: ttl };
}

/**
 * Validate the serialised size of a cache value.
 *
 * The value is serialised to UTF-8 JSON and rejected if it exceeds
 * {@link AUDIT_CACHE_MAX_VALUE_BYTES}. Circular references and values that
 * cannot be serialised are rejected rather than thrown, so the caller can
 * report a deterministic error.
 */
export function validateCacheValue(value: unknown): CacheValueValidation {
  if (value === undefined) {
    return { valid: false, reason: 'cache value must not be undefined' };
  }
  let serialised: string;
  try {
    serialised = JSON.stringify(value);
  } catch {
    return { valid: false, reason: 'cache value is not JSON-serialisable' };
  }
  if (typeof serialised !== 'string') {
    return { valid: false, reason: 'cache value is not JSON-serialisable' };
  }
  const bytes = Buffer.byteLength(serialised, 'utf-8');
  if (bytes > AUDIT_CACHE_MAX_VALUE_BYTES) {
    return {
      valid: false,
      reason: `cache value must be at most ${AUDIT_CACHE_MAX_VALUE_BYTES} bytes`,
    };
  }
  return { valid: true, bytes };
}

/**
 * Validate the configured capacity of the audit cache.
 *
 * Accepts a positive integer no greater than
 * {@link AUDIT_CACHE_MAX_CAPACITY}. This is the boundary that prevents
 * unbounded memory growth under adverse input.
 */
export function validateCacheCapacity(capacity: unknown): CacheTtlValidation {
  if (typeof capacity !== 'number' || !Number.isFinite(capacity) || !Number.isInteger(capacity)) {
    return { valid: false, reason: 'cache capacity must be a finite integer' };
  }
  if (capacity < 1) {
    return { valid: false, reason: 'cache capacity must be at least 1' };
  }
  if (capacity > AUDIT_CACHE_MAX_CAPACITY) {
    return {
      valid: false,
      reason: `cache capacity must be at most ${AUDIT_CACHE_MAX_CAPACITY}`,
    };
  }
  return { valid: true, ttlMs: capacity };
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

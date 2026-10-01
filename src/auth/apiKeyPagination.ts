/**
 * @module auth/apiKeyPagination
 * @description Signed, opaque cursor pagination for the API-keys listing.
 *
 * Invariants (preserved across errors, empty data, and upgrades):
 * - Ordering is deterministic and newest-first: `createdAt` DESC, then `id` DESC.
 *   The tie-break keeps cursors stable when several keys share a timestamp.
 * - Cursors are opaque, versioned, HMAC-signed, and bounded in length. A
 *   malformed, tampered, or oversized cursor is rejected with
 *   {@link InvalidApiKeyCursorError} rather than yielding a partial page.
 * - Pagination is idempotent: replaying the same cursor returns the same page,
 *   so retries cannot skip or duplicate records.
 * - Page size is bounded to [1, {@link API_KEYS_MAX_PAGE_SIZE}]; missing or
 *   invalid values fall back to {@link API_KEYS_DEFAULT_PAGE_SIZE}. Numeric and
 *   string inputs are parsed identically.
 * - `paginateApiKeys` never mutates the caller-supplied array.
 * - A `null` `nextCursor` means there are no more items.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

export const API_KEYS_DEFAULT_PAGE_SIZE = 20;
export const API_KEYS_MAX_PAGE_SIZE = 100;

const CURSOR_VERSION = 1;
const CURSOR_MAX_LENGTH = 512;
const CURSOR_SECRET.process.env.API_KEYS_CURSOR_SECRET ?? 'talenttrust-api-keys-cursor-v1';

export interface ApiKeyCursorPosition {
  createdAt: string;
  id: string;
}

interface EncodedApiKeyCursor extends ApiKeyCursorPosition {
  version: number;
}

export interface ApiKeyPage<T> {
  items: T[];
  nextCursor: string | null;
}

export class InvalidApiKeyCursorError extends Error {
  constructor() {
    super('Invalid pagination cursor');
    this.name = 'InvalidApiKeyCursorError';
  }
}

/**
 * Error thrown when a pagination operation fails transiently (e.g. database
 * unavailable) and the caller may retry with the same inputs.
 *
 * This is distinct from {@link InvalidApiKeyCursorError}, which is a
 * deterministic rejection of malformed input and must not be retried.
 */
export class ApiKeyPaginationError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'ApiKeyPaginationError';
  }
}

export interface ApiKeyPaginationLogger {
  warn(message: string, metadata?: Record<string, unknown>): void;
  error(message: string, metadata?: Record<string, unknown>): void;
}

const defaultLogger: ApiKeyPaginationLogger = {
  warn(message, metadata) {
    // eslint-disable-next-line no-console
    console.warn(message, metadata ?? {});
  },
  error(message, metadata) {
    // eslint-disable-next-line no-console
    console.error(message, metadata ?? {});
  },
};

/**
 * Resolves the cursor secret at call time so tests and deployments can
 * override it without module cache staleness. Fails close if an explicit
 * env value is present but invalid (too short).
 */
function resolveCursorSecret(): string {
  const fromEnv = process.env.API_KEYS_CURSOR_SECRET;
  if (fromEnv !== undefined && fromEnv !== '') {
    if (fromEnv.length < 32) {
      throw new ApiKeyPaginationError(
        'API_KEYS_CURSOR_SECRET must be at least 32 characters long',
      );
    }
    return fromEnv;
  }
  return CURSOR_SECRET;
}

function sign(value: string): string {
  return createHmac('sha256', resolveCursorSecret()).update(value).digest('base64url');
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

export function encodeApiKeyCursor(position: ApiKeyCursorPosition): string {
  const payload: EncodedApiKeyCursor = {
    version: CURSOR_VERSION,
    createdAt: position.createdAt,
    id: position.id,
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `${encodedPayload}.${sign(encodedPayload)}`;
}

export function decodeApiKeyCursor(cursor: string): ApiKeyCursorPosition {
  if (
    typeof cursor !== 'string' ||
    cursor.length === 0 ||
    cursor.length > CURSOR_MAX_LENGTH ||
    !/^[A-Za-z0-9_-]+\.[a-zA-Z0-9_-]+$/.test(cursor)
  ) {
    throw new InvalidApiKeyCursorError();
  }

  const separator = cursor.indexOf('.');
  const encodedPayload = cursor.slice(0, separator);
  const signature = cursor.slice(separator + 1);

  if (!constantTimeEqual(signature, sign(encodedPayload))) {
    throw new InvalidApiKeyCursorError();
  }

  try {
    const decoded = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8')) as Partial<EncodedApiKeyCursor>;
    if (
      decoded.version !== CURSOR_VERSION ||
      typeof decoded.createdAt !== 'string' ||
      Number.isNaN(Date.parse(decoded.createdAt)) ||
      typeof decoded.id !== 'string' ||
      decoded.id.length === 0
    ) {
      throw new InvalidApiKeyCursorError();
    }

    return { createdAt: decoded.createdAt, id: decoded.id };
  } catch (error) {
    if (error instanceof InvalidApiKeyCursorError) {
      throw error;
    }
    throw new InvalidApiKeyCursorError();
  }
}

/**
 * Parse a raw `limit` value into a bounded page size.
 *
 * Accepts both query-string values (e.g. `"50"`) and already-parsed numbers
 * (e.g. `50`) so callers that coerce `req.query` first remain compatible.
 * Missing, non-numeric, non-integer, or non-positive values fall back to
 * {@link API_KEYS_DEFAULT_PAGE_SIZE}; larger values are clamped to
 * {@link API_KEYS_MAX_PAGE_SIZE}. Never throws.
 */
export function parseApiKeyPageSize(value: unknown): number {
  if (value === undefined || value === null || value === '') {
    return API_KEYS_DEFAULT_PAGE_SIZE;
  }

  const parsed =
    typeof value === 'number'
      ? value
      : typeof value === 'string'
        ? Number(value)
        : Number.NaN;

  if (!Number.isInteger(parsed) || parsed <= 0) {
    return API_KEYS_DEFAULT_PAGE_SIZE;
  }

  return Math.min(parsed, API_KEYS_MAX_PAGE_SIZE);
}

function comparePositions<T extends ApiKeyCursorPosition>(left: T, right: T): number {
  const dateDifference = Date.parse(right.createdAt) - Date.parse(left.createdAt);
  if (dateDifference !== 0) {
    return dateDifference;
  }

  return right.id < left.id ? -1 : right.id > left.id ? 1 : 0;
}

function isAfterCursor<T extends ApiKeyCursorPosition>(item: T, cursor: ApiKeyCursorPosition): boolean {
  const itemTime = Date.parse(item.createdAt);
  const cursorTime = Date.parse(cursor.createdAt);

  return itemTime < cursorTime || (itemTime === cursorTime && item.id < cursor.id);
}

/**
 * Deterministic pagination options.
 *
 * The optional `fetch` callback allows callers to source records from a
 * database or other external system while retaining the deterministic
 * sorting/cursor semantics of this module. When `fetch` is provided,
 * transient failures are wrapped in {@link ApiKeyPaginationError} so callers
 * can retry with the same inputs without losing data or double-consuming
 * a page.
 */
export interface ApiKeyPaginationOptions {
  /** Optional logger for diagnostic events. Defaults to console. */
  logger?: ApiKeyPaginationLogger;
}

/**
 * Paginates a set of API key records.
 *
 * Invariants:
 * - The output is deterministic for a given input and cursor.
 * - A cursor that fails signature or format validation is rejected with
 *   {@link InvalidApiKeyCursorError} and must not be retried.
 * - Transient failures while fetching records are surfaced as {@link ApiKeyPaginationError}
 *   and are safe to retry.
 * - The cursor is only advanced when a non-empty page is produced, so a
 *   failure cannot silently skip records.
 */
export function paginateApiKeys<T extends ApiKeyCursorPosition>(
  records: readonly T[],
  limit: number,
  cursor?: string,
  options?: ApiKeyPaginationOptions,
): ApiKeyPage<T> {
  const logger = options?.logger ?? defaultLogger;
  const boundedLimit = Number.isFinite(limit)
    ? Math.min(Math.max(Math.trunc(limit), 1), API_KEYS_MAX_PAGE_SIZE)
    : API_KEYS_DEFAULT_PAGE_SIZE;

  // Decode the cursor before any sorting or filtering so invalid input
  // is rejected deterministically and no partial work is performed.
  const cursorPosition = cursor === undefined ? undefined : decodeApiKeyCursor(cursor);

  try {
    const sortedRecords = [...records].sort(comparePositions);
    const eligibleRecords = cursorPosition === undefined
      ? sortedRecords
      : sortedRecords.filter((record) => isAfterCursor(record, cursorPosition));
    const page = eligibleRecords.slice(0, boundedLimit);
    const hasMore = eligibleRecords.length > boundedLimit;

    return {
      items: page,
      nextCursor: hasMore && page.length > 0
        ? encodeApiKeyCursor(page[page.length - 1])
        : null,
    };
  } catch (error) {
    // Do not leak record contents or cursor values into logs.
    logger.error('API key pagination failed', {
      errorName: error instanceof Error ? error.name : 'unknown',
      recordCount: records.length,
      hasCursor: cursor !== undefined,
      limit: boundedLimit,
    });
    throw new ApiKeyPaginationError('API key pagination failed', error);
  }
}

/**
 * Paginates API key records fetched from an asynchronous source.
 *
 * This is the recovery-aware entry point for callers that load records from
 * a database or remote service. If the fetch fails, the error is wrapped in
 * {@link ApiKeyPaginationError} and no cursor is advanced, so a retry with the
 * same inputs produces the same result and never skips or duplicates records.
 */
export async function paginateApiKeysAsync<T extends ApiKeyCursorPosition>(
  fetch: () => Promise<readonly T[]>,
  limit: number,
  cursor?: string,
  options?: ApiKeyPaginationOptions,
): Promise<ApiKeyPage<T>> {
  const logger = options?.logger ?? defaultLogger;

  // Validate the cursor before attempting any I/O. This ensures a malformed
  // cursor is rejected deterministically without consuming a fetch.
  if (cursor !== undefined) {
    decodeApiKeyCursor(cursor);
  }

  let records: readonly T[];
  try {
    records = await fetch();
  } catch (error) {
    logger.error('API key pagination fetch failed', {
      errorName: error instanceof Error ? error.name : 'unknown',
      hasCursor: cursor !== undefined,
      limit,
    });
    throw new ApiKeyPaginationError('Failed to fetch API key records', error);
  }

  return paginateApiKeys(records, limit, cursor, options);
}

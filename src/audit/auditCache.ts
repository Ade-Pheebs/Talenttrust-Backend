/**
 * @module auditCache
 * @description Response caching for audit reads with TTP and LRU eviction.
 *
 * Provides a bounded cache for audit query results to reduce database load.
 * Cache entries expire after a configurable TTP and are evicted when the cache
 * reaches its max entry bound.
 *
 * Cache invalidation:
 *   - Explicit invalidation on write operations (log/append)
 *   - TTP-based expiration
 *   - LRU eviction when capacity is reached
 *
 * Metrics:
 *   - Cache hits and misses are tracked via Prometheus counters
 *
 * Validation boundaries (see also `src/audit/auditCache.test.ts`):
 *   - Constructor options are validated up front: `ttlMs` and `maxEntries`
 *     must be finite positive integers. A zero/negative/NaN/Infinity bound would
 *     silently disable caching or eviction, so we reject it with a descriptive
 *     error instead of failing open.
 *   - Cache keys are derived from a canonicalised form of the query so that
 *     duplicate submissions with different key order or undefined fields map to
 *     the same entry (deterministic deduplication).
 *   - `type` must be one of the known discriminators; `type: 'getById'` requires
 *     a non-empty `id`. Invalid inputs throw rather than corrupting the cache.
 *   - `set` validates the payload shape before writing, so a cache read can
 *     never return a malformed or unexpected value.
 */

import { Counter, Registry } from 'prom-client';
import type { AuditEntry, AuditQuery, AuditQueryResult } from './types';

export interface AuditCacheOptions {
  ttlMs: number;
  maxEntries: number;
}

export interface CacheEntry {
  data: AuditEntry[] | AuditEntry | AuditQueryResult;
  expiresAt: number;
  lastAccessed: number;
}

/** The discriminators accepted by the cache. */
export type AuditCacheQueryType = 'query' | 'queryWithCursor' | 'getById';

/** Allowed values for the cache discriminator. */
const ALLOWED_QUERY_TYPES: readonly AuditCacheQueryType[] = ['query', 'queryWithCursor', 'getById'];

/** Maximum length of an id used in a `getById` cache key. */
const MAX_ID_LENGTH = 256;

/** Maximum length of a canonicalised query string before we refuse to cache. */
const MAX_KEY_LENGTH = 4096;

/** Fields of `AuditQuery` that are allowed in a canonical key. */
const QUERY_KEY_ORDER: readonly (keyof AuditQuery)[] = [
  'action',
  'severity',
  'actor',
  'resource',
  'resourceId',
  'from',
  'to',
  'limit',
  'offset',
  'cursor',
];

/** Error thrown when a cache caller supplies invalid input. */
export class AuditCacheValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditCacheValidationError';
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Validate the constructor options for the cache.
 *
 * Both `ttlMs` and `maxEntries` must be positive finite integers. This is a
 * hard boundary: a cache configured with `TTL = 0` or `maxEntries = 0` is
 * silently broken (every get misses / every set evicts itself), so we refuse
 * to construct it at all.
 */
export function validateAuditCacheOptions(options: AuditCacheOptions): void {
  if (!isPlainObject(options)) {
    throw new AuditCacheValidationError('AuditCache options must be an object');
  }

  const { ttlMs, maxEntries } = options;

  if (
    typeof ttlMs !== 'number' ||
    !Number.isFinite(ttlMs) ||
    !Number.isInteger(ttlMs) ||
    ttlMs <= 0
  ) {
    throw new AuditCacheValidationError('AuditCache ttlMs must be a positive finite integer');
  }

  if (
    typeof maxEntries !== 'number' ||
    !Number.isFinite(maxEntries) ||
    !Number.isInteger(maxEntries) ||
    maxEntries <= 0
  ) {
    throw new AuditCacheValidationError('AuditCache maxEntries must be a positive finite integer');
  }
}

/**
 * Validate the cache discriminator and optional `id`.
 *
 * This is the single checkpoint used by both `get` and `set` so that a cache
 * key is always well-formed and collision-resistant.
 */
export function validateCacheKeyInput(
  type: AuditCacheQueryType,
  id?: string,
): void {
  if (typeof type !== 'string' || !(ALLOWED_QUERY_TYPES as readonly string[]).includes(type)) {
    throw new AuditCacheValidationError(
      `AuditCache type must be one of ${ALLOWED_QUERY_TYPES.join(', ')}`,
    );
  }

  if (type === 'getById') {
    if (typeof id !== 'string' || id.length === 0) {
      throw new AuditCacheValidationError('AuditCache getById requires a non-empty id');
    }
    if (id.length > MAX_ID_LENGTH) {
      throw new AuditCacheValidationError('AuditCache id exceeds maximum length');
    }
  } else if (id !== undefined) {
    throw new AuditCacheValidationError('AuditCache id is only valid for getById');
  }
}

/**
 * Produce a deterministic canonical string for a query.
 *
 * JSON.stringify preserves insertion order, so two callers that pass the same
 * lolgical query with different key order would produce different keys and
 * silently miss the cache. We canonicalise by emitting fields in a fixed
 * order and omitting `undefined` values.
 */
export function canonicalizeAuditQuery(query: AuditQuery): string {
  if (!isPlainObject(query)) {
    throw new AuditCacheValidationError('AuditCache query must be an object');
  }

  const ordered: Record<string, unknown> = {};
  for (const key of QUERY_KEY_ORDER) {
    const value = (query as Record<string, unknown>)[key];
    if (value !== undefined) {
      ordered[key] = value;
    }
  }

  const serialised = JSON.stringify(ordered);
  if (serialised.length > MAX_KEY_LENGTH) {
    throw new AuditCacheValidationError('AuditCache query key exceeds maximum length');
  }

  return serialised;
}

/**
 * Validate the shape of a value before it is stored in the cache.
 *
 * The cache is a correctness boundary: a cache read must never return a
 * malformed value that a caller cannot interpret. We accept the three shapes
 * declared by the public interface and reject everything else.
 */
export function validateCachePayload(data: unknown): void {
  if (Array.isArray(data)) {
    return;
  }

  if (!isPlainObject(data)) {
    throw new AuditCacheValidationError('AuditCache data must be an array or object');
  }

  // AuditQueryResult has an `entries` array and numeric `count`/`limit`.
  // AuditEntry has an `id` string and a `hash` string.
  const candidate = data as Record<string, unknown>;
  const looksLikeQueryResult =
    Array.isArray(candidate.entries) &&
    typeof candidate.count === 'number' &&
    typeof candidate.limit === 'number';
  const looksLikeEntry =
    typeof candidate.id === 'string' && typeof candidate.hash === 'string';

  if (!looksLikeQueryResult && !looksLikeEntry) {
    throw new AuditCacheValidationError('AuditCache data is not a recognised audit payload');
  }
}

/**
 * LRU cache with TTL for audit read responses.
 */
export class AuditCache {
  private cache: Map<string, CacheEntry>;
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private hits: Counter<string>;
  private misses: Counter<string>;
  private hitCount: number;
  private missCount: number;

  constructor(options: AuditCacheOptions, register?: Registry) {
    validateAuditCacheOptions(options);

    this.ttlMs = options.ttlMs;
    this.maxEntries = options.maxEntries;
    this.cache = new Map();
    this.hitCount = 0;
    this.missCount = 0;

    const registry = register instanceof Registry ? register : new Registry();

    this.hits = new Counter({
      name: 'audit_cache_hits_total',
      help: 'Total number of audit cache hits.',
      registers: [registry],
    });

    this.misses = new Counter({
      name: 'audit_cache_misses_total',
      help: 'Total number of audit cache misses.',
      registers: [registry],
    });
  }

  /**
   * Generate a canonical cache key from an audit query.
   *
   * The key is deterministic for equivalent logical queries, so duplicate
   * submissions with different key order or undefined fields deduplicate to the
   * same entry.
   */
  private generateKey(query: AuditQuery, type: AuditCacheQueryType, id?: string): string {
    validateCacheKeyInput(type, id);
    if (type === 'getById') {
      return `getById:${id}`;
    }
    return `${type}:${canonicaliseAuditQuery(query)}`;
  }

  /**
   * Get cached audit query results.
   *
   * @param query - The audit query
   * @param type - The type of query (query, queryWithCursor, or getById)
   * @param id - Optional ID for getById queries
   * @returns The cached data if valid and not expired, null otherwise
   * @throws {@tlink AuditCacheValidationError} when the input is malformed.
   */
  get(query: AuditQuery, type: AuditCacheQueryType, id?: string): AuditEntry[] | AuditEntry | AuditQueryResult | null {
    const key = this.generateKey(query, type, id);
    const entry = this.cache.get(key);
    const now = Date.now();

    if (!entry) {
      this.misses.inc();
      this.missCount++;
      return null;
    }

    // Check if entry has expired
    if (now > entry.expiresAt) {
      this.cache.delete(key);
      this.misses.inc();
      this.missCount++;
      return null;
    }

    // Update last accessed time for LRU eviction
    entry.lastAccessed = now;
    this.hits.inc();
    this.hitCount++;
    return entry.data;
  }

  /**
   * Set a cache entry for an audit query result.
   *
   * @param query - The audit query
   * @param data - The data to cache
   * @param type - The type of query (query, queryWithCursor, or getById)
   * @param id - Optional ID for getById queries
   * @throws {@tlink AuditCacheValidationError} when the input or payload is malformed.
   */
  set(query: AuditQuery, data: AuditEntry[] | AuditEntry | AuditQueryResult, type: AuditCacheQueryType, id?: string): void {
    const key = this.generateKey(query, type, id);
    validateCachePayload(data);

    const now = Date.now();
    const entry: CacheEntry = {
      data,
      expiresAt: now + this.ttlMs,
      lastAccessed: now,
    };

    // Evict oldest entries if at capacity
    if (this.cache.size >= this.maxEntries && !this.cache.has(key)) {
      this.evictOldest();
    }

    this.cache.set(key, entry);
  }

  /**
   * Invalidate all cache entries (called on write operations).
   */
  invalidate(): void {
    this.cache.clear();
  }

  /**
   * Invalidate cache entries for a specific resource ID.
   *
   * Matching is done against the canonicalised query string, so a caller passing
   * the same logical query in a different key order still gets invalidated.
   *
   * @param resourceId - The resource ID whose cache entries should be invalidated
   */
  invalidateByResourceId(resourceId: string): void {
    if (typeof resourceId !== 'string' || resourceId.length == 0) {
      throw new AuditCacheValidationError('AuditCache resourceId must be a non-empty string');
    }

    const needle = `"resourceId":${JSON.stringify(resourceId)}`;
    const keysToDelete: string[] = [];
    this.cache.forEach((_entry, key) => {
      if (key.includes(needle)) {
        keysToDelete.push(key);
      }
    });
    keysToDelete.forEach(key => this.cache.delete(key));
  }

  /**
   * Clear all cache entries.
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get current cache statistics.
   */
  getStats(): { size: number; hits: number; misses: number } {
    return {
      size: this.cache.size,
      hits: this.hitCount,
      misses: this.missCount,
    };
  }

  /**
   * Evict the least recently used entry.
   */
  private evictOldest(): void {
    let oldestKey: string | null = null;
    let oldestAccessed = Infinity;

    this.cache.forEach((entry, key) => {
      if (entry.lastAccessed < oldestAccessed) {
        oldestAccessed = entry.lastAccessed;
        oldestKey = key;
      }
    });

    if (oldestKey) {
      this.cache.delete(oldestKey);
    }
  }

  /**
   * Clean up expired entries (called periodically).
   */
  cleanupExpired(): number {
    const now = Date.now();
    let cleaned = 0;
    const keysToDelete: string[] = [];

    this.cache.forEach((entry, key) => {
      if (now > entry.expiresAt) {
        keysToDelete.push(key);
      }
    });

    keysToDelete.forEach(key => {
      this.cache.delete(key);
      cleaned++;
    });

    return cleaned;
  }
}

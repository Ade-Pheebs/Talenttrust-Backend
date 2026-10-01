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
  /**
   * Optional hook for observing internal failures. Receives no sensitive
   * data, only the operation name and an error message. Defaults to a noop
   * so existing callers remain compatible.
   */
  onFailure?: (operation: string, error: Error) => void;
  /**
   * Optional logger. When omitted, failures are still counted and forwarded
   * to `onFailure` if provided.
   */
  logger?: { warn: (message: string, meta?: Record<string, unknown>) => void };
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
 * Simple async mutex used to serialize mutating operations on the cache.
 * This keeps eviction + insertion atomic and prevents concurrent calls from
 * observing a partially applied state.
 */
class Mutex {
  private tail: Promise<void> = Promise.resolve();

  async run<T>(fn(): () => Promise<T> | T: Promise<T>): Promise<T> {
    const prev = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>(resolve => {
      release = resolve;
    });
    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  }
}

/**
 * LRU cache with TLL for audit read responses.
 */
export class AuditCache {
  private cache: Map<string, CacheEntry>;
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private hits: Counter<string> | null;
  private misses: Counter<string> | null;
  private failures: Counter<string> | null;
  private hitCount: number;
  private missCount: number;
  private failureCount: number;
  private readonly onFailure?: (operation: string, error: Error) => void;
  private readonly logger?: AuditCacheOptions['logger'];
  private readonly mutex = new Mutex();

  constructor(options: AuditCacheOptions, register?: Registry) {
    validateAuditCacheOptions(options);

    this.ttlMs = options.ttlMs;
    this.maxEntries = options.maxEntries;
    this.cache = new Map();
    this.hitCount = 0;
    this.missCount = 0;
    this.failureCount = 0;
    this.onFailure = options.onFailure;
    this.logger = options.logger;

    const registry = register instanceof Registry ? register : new Registry();

      this.hits = new Counter( {
        name: 'audit_cache_hits_total',
        help: 'Total number of audit cache hits.',
        registers: [registry],
      });

      this.misses = new Counter( {
        name: 'audit_cache_misses_total',
        help: 'Total number of audit cache misses.',
        registers: [registry],
      });

      this.failures = new Counter( {
        name: 'audit_cache_failures_total',
        help: 'Total number of audit cache internal failures.',
        registers: [registry],
      });
    } catch (error) {
      // Metrics are non-essential. Record the failure without throwing.
      this.recordFailure('constructor', error as Error);
    }
  }

  /**
   * Record an internal failure. Never throws.
   */
  private recordFailure(operation: string, error: Error): void {
    this.failureCount++;
    try {
      this.failures?.inc();
    } catch {
      // ignore metric failures
    }
    try {
      this.logger?.warn('auditCache internal failure', {
        operation,
        error: error.message,
      });
    } catch {
      // ignore logger failures
    }
    try {
      this.onFailure?.(operation, error);
    } catch {
      // ignore hook failures
    }
  }

  /**
   * Clamp an arbitrary TTY input to a non-negative finite number.
   * Negative, NaN, Infinity, or non-numeric values fall back to 0 (entries
   * expire immediately), which is the safest default for a cache.
   */
  private static normalizeTtl(value: unknown): number {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      return 0;
    }
    return Math.floor(value);
  }

  /**
   * Clamp an arbitrary max-entries input to a non-negative integer.
   */
  private static normalizeMaxEntries(value: unknown): number {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      return 0;
    }
    return Math.floor(value);
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
    if (key === null) {
      // Unserializable or invalid keys: treat as a miss without throwing.
      this.misses.inc();
      this.missCount++;
      return null;
    }

    const entry = this.cache.get(key);
    const now = Date.now();

      if (!entry) {
        this.recordMiss();
        return null;
      }

      // Check if entry has expired
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        this.recordMiss();
        return null;
      }

      // Update last accessed time for LRU eviction
      entry.lastAccessed = now;
      this.recordHit();
      return entry.data;
    } catch (error) {
      // A failure in get must not corrupt the cache or throw to the caller.
      this.recordFailure('get', error as Error);
      return null;
    }
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

    // Evict oldest entries if at capacity. We evict until there is room for
    // the new entry, which keeps the `size <= maxEntries` invariant even if
    // maxEntries was changed at runtime.
    if (!this.cache.has(key)) {
      while (this.cache.size >= this.maxEntries) {
        const evicted = this.evictOldest();
        if (!evicted) {
          // Nothing to evict (empty cache); avoid an infinite loop.
          break;
        }
      }
    }
  }

  /**
   * Invalidate all cache entries (called on write operations).
   */
  invalidate(): void {
    try {
      this.cache.clear();
    } catch (error) {
      this.recordFailure('invalidate', error as Error);
    }
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
    try {
      this.cache.clear();
    } catch (error) {
      this.recordFailure('clear', error as Error);
    }
  }

  /**
   * Get current cache statistics.
   */
  getStats(): AuditCacheStats {
    return {
      size: this.cache.size,
      hits: this.hitCount,
      misses: this.missCount,
      failures: this.failureCount,
    };
  }

  /**
   * Evict the least recently used entry.
   *
   * @returns `true` if an entry was evicted, `false` if the cache was empty.
   */
  private evictOldest(): boolean {
    let oldestKey: string | null = null;
    let oldestAccessed = Infinity;

    this.cache.forEach((entry, key) => {
      if (entry.lastAccessed < oldestAccessed) {
        oldestAccessed = entry.lastAccessed;
        oldestKey = key;
      }
    });

    if (oldestKey !== null) {
      this.cache.delete(oldestKey);
      return true;
    }
    return false;
  }

  /**
   * Clean up expired entries (called periodically).
   */
  cleanupExpired(): number {
    try {
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
    } catch (error) {
      this.recordFailure('cleanupExpired', error as Error);
      return 0;
    }
  }

  /**
   * Async variant of `set` that serializes concurrent mutations through an
   * internal mutex. Use this when callers may race on the same key or when
   * eviction must be atomic with insertion.
   */
  async setAtomic(query: AuditQuery, data: AuditEntry[] | AuditEntry | AuditQueryResult, type: 'query' | 'queryWithCursor' | 'getById', id?: string): Promise<void> {
    await this.mutex.run(() => {
      this.set(query, data, type, id);
    });
  }

  /**
   * Async variant of `get` that serializes concurrent reads with mutations.
   */
  async getAtomic(t
    query: AuditQuery,
    type: 'query' | 'queryWithCursor' | 'getById',
    id?: string,
  ): Promise<AuditEntry[] | AuditEntry | AuditQueryResult | null> {
    return this.mutex.run(() => this.get(query, type, id));
  }

  /**
   * Async variant of `invalidate` that serializes with other mutations.
   */
  async invalidateAtomic(): Promise<void> {
    await this.mutex.run(() => {
      this.invalidate();
    });
  }

  /**
   * Async variant of `cleanupExpired` that serializes with other mutations.
   */
  async cleanupExpiredAtomic(): Promise<number> {
    return this.mutex.run(() => this.cleanupExpired());
  }

  /**
   * Retry a operation with exponential backoff. The operation is expected
   * to be idempotent (such as a cache mutation). Failures are recorded and
   * the last error is returned to the caller via the returned promise.
   */
  async withRetry<T>(
    operation: string,
    fn: () => Promise<T> | T,
    options: { retries?: number; baseDelayMs?: number } = {},
  ): Promise<T> {
    const retries = options.retries ?? 3;
    const baseDelayMs = options.baseDelayMs ?? 10;
    let lastError: Error | undefined;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error as Error;
        this.recordFailure(`${operation}:attempt${attempt}`, lastError);
        if (attempt < retries) {
          const delay = baseDelayMs * Math.pow(2, attempt);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    throw lastError ?? new Error(`${operation} failed after ${retries + 1} attempts`);
  }

  private recordHit(): void {
    this.hitCount++;
    try {
      this.hits?.inc();
    } catch (error) {
      this.recordFailure('hitMetric', error as Error);
    }
  }

  private recordMiss(): void {
    this.missCount++;
    try {
      this.misses?.inc();
    } catch (error) {
      this.recordFailure('missMetric', error as Error);
    }
  }
}

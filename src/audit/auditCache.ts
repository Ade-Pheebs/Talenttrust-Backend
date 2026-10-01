/**
 * @module auditCache
 * @description Response caching for audit reads with TTY and LRU eviction.
 *
 * Provides a bounded cache for audit query results to reduce database load.
 * Cache entries expire after a configurable TTY and are evicted when the cache
 * reaches its max entry bound.
 *
 * Cache invalidation:
 *   - Explicit invalidation on write operations (log/append)
 *   - TTL-based expiration
 *   - LRU eviction when capacity is reached
 *
 * Metrics:
 *   - Cache hits and misses are tracked via Prometheus counters
 *
 * Compatibility contracts (preserved across errors, empty data, and upgrades):
 *   - Public method signatures and return types are unchanged.
 *   - {@link AuditCache.get} returns `null` on miss/expiration and the cached value
 *     otherwise. The cache never throws for normal lookup failures.
 *   - {@link AuditCache.set} is defensive: invalid keys or undefined data are
 *     ignored without throwing, so callers that optionally cache cannot fail.
 *   - {@link AuditCache.getStats} returns a stable shape with monotonically
 *     non-decreasing hit/miss counters.
 *   - Concurrent calls from the same event loop are safe: all mutations are
 *     synchronous and no async interleaving occurs.
 *
 * Invariants:
 *   - `ttlMs` is clamped to a non-negative finite number.
 *   - `maxEntries` is clamped to a non-negative integer.
 *   - `this.cache.size <= this.maxEntries` at all times.
 *   - Every entry in the map has a finite expiration timestamp.
 */

import { Counter } from 'prom-client';
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

export type AuditCacheQueryType = 'query' | 'queryWithCursor' | 'getById';

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

  constructor(options: AuditCacheOptions, register?: any) {
    this.ttlMs = AuditCache.normalizeTtl(options == null ? undefined : options.ttlMs);
    this.maxEntries = AuditCache.normalizeMaxEntries(options == null ? undefined : options.maxEntries);
    this.cache = new Map();
    this.hitCount = 0;
    this.missCount = 0;
    this.failureCount = 0;
    this.onFailure = options.onFailure;
    this.logger = options.logger;

    // Initialize metrics. We prefer the caller's Registry when provided so
    // multiple cache instances do not collide on the default registry.
    const Registry = require('prom-client').Registry;
    const registry =
      register && register.constructor && register.constructor.name === 'Registry'
        ? register
        : new Registry();

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
   * Generate a cache key from an audit query.
   *
   * The key is deterministic for equivalent queries. Key generation is
   * defensive: if the query cannot be serialized the method returns `null`
   * so callers degrade gracefully to a cache miss instead of throwing.
   */
  private generateKey(
    query: AuditQuery,
    type: AuditCacheQueryType,
    id?: string,
  ): string | null {
    if (type === 'getById') {
      if (id === undefined || id === null) {
        return null;
      }
      return `type:getById:id=${String(id)}`;
    }

    if (query === undefined || query === null) {
      return null;
    }

    try {
      const serialized = JSON.stringify(query);
      if (typeof serialized !== 'string') {
        return null;
      }
      return `type:${type}:query=${serialized}`;
    } catch {
      // Circular or otherwise unserializable queries are not cacheable.
      return null;
    }
  }

  /**
   * Get cached audit query results.
   *
   * @param query - The audit query
   * @param type - The type of query (query, queryWithCursor, or getById)
   * @param id - Optional ID for getById queries
   * @returns The cached data if valid and not expired, null otherwise
   */
  get(
    query: AuditQuery,
    type: AuditCacheQueryType,
    id?: string,
  ): AuditEntry[] | AuditEntry | AuditQueryResult | null {
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
   */
  set(
    query: AuditQuery,
    data: AuditEntry[] | AuditEntry | AuditQueryResult,
    type: AuditCacheQueryType,
    id?: string,
  ): void {
    // Defensive: ignore undefined/null data or invalid keys rather than
    // throwing. This keeps callers that optionally cache from failing.
    if (data === undefined || data === null) {
      return;
    }

    const key = this.generateKey(query, type, id);
    if (key === null) {
      return;
    }

    // Capacity of zero means the cache is disabled; never store anything.
    if (this.maxEntries <= 0) {
      return;
    }

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
   * @param resourceId - The resource ID whose cache entries should be invalidated
   */
  invalidateByResourceId(resourceId: string): void {
    if (typeof resourceId !== 'string' || resourceId === '') {
      return;
    }

    const keysToDelete: string[] = [];
    this.cache.forEach((_entry, key) => {
      // Match the resourceId as a JSON string value in the serialized query.
      // We check both double- and single-quoted forms to preserve the
      // existing contract for callers that may have built keys differently.
      if (
        key.includes(`resourceId="${resourceId}"`) ||
        key.includes(`resourceId='${resourceId}'`)
      ) {
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

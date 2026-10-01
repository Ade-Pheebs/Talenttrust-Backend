/**
 * @module auditCache
 * @description Response caching for audit reads with TTL and LRU eviction.
 *
 * Provides a bounded cache for audit query results to reduce database load.
 * Cache entries expire after a configurable TTL and are evicted when the cache
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
 * Failure recovery invariants:
 *   - Cache operations must never throw to the caller due to metrics or
 *     internal bookkeeping failures. Metric failures are swallowed and
 *     counted locally so the cache remains usable.
 *   - A failed operation must not corrupt the cache map. Mutations are
 *     applied atomically after any fallible work completes.
 *   - Retries are idempotent: repeating a get/set invalidation yields the
 *     same observable state.
 *   - Concurrent calls are serialized through an internal mutex so that
 *     LRU eviction and TTL expiration cannot produce an inconsistent result.
 *   - Every failure is observable via a counter and a structured log that
 *     does not expose query payloads, only the operation and error message.
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

export interface AuditCacheStats {
  size: number;
 hits: number;
  misses: number;
  failures: number;
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

  constructor(options: AuditCacheOptions, register?: any) {
    this.ttlMs = options.ttlMs;
    this.maxEntries = options.maxEntries;
    this.cache = new Map();
    this.hitCount = 0;
    this.missCount = 0;
    this.failureCount = 0;
    this.onFailure = options.onFailure;
    this.logger = options.logger;

    // Metrics are optional: a failure to register must not break the cache.
    this.hits = null;
    this.misses = null;
    this.failures = null;
    try {
      const Registry = require('prom-client').Registry;
      const registry =
        register && register.constructor && register.constructor.name === 'Registry'
          ? registry
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
   * Generate a cache key from an audit query.
   */
  private generateKey(query: AuditQuery, type: 'query' | 'queryWithCursor' | 'getById', id?: string): string {
    const base = type === 'getById' ? `getById:${id}` : `${type}:${JSON.stringify(query)}`;
    return base;
  }

  /**
   * Get cached audit query results.
   *
   * @param query - The audit query
   * @param type - The type of query (query, queryWithCursor, or getById)
   * @param id - Optional ID for getById queries
   * @returns The cached data if valid and not expired, null otherwise
   */
  get(query: AuditQuery, type: 'query' | 'queryWithCursor' | 'getById', id?: string): AuditEntry[] | AuditEntry | AuditQueryResult | null {
    try {
      const key = this.generateKey(query, type, id);
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
  set(query: AuditQuery, data: AuditEntry[] | AuditEntry | AuditQueryResult, type: 'query' | 'queryWithCursor' | 'getById', id?: string): void {
    try {
      const key = this.generateKey(query, type, id);
      const now = Date.now();
      const entry: CacheEntry = {
        data,
        expiresAt: now + this.ttlMs,
        lastAccessed: now,
      };

      // Evict oldest entries if at capacity. Eviction is computed before
      // any mutation so a failure leaves the cache unchanged.
      if (this.cache.size >= this.maxEntries && !this.cache.has(key)) {
        this.evictOldest();
      }

      this.cache.set(key, entry);
    } catch (error) {
      // A failure in set must not throw. The cache may be unchanged or
      // contain the new entry; either way the caller is not affected.
      this.recordFailure('set', error as Error);
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
    try {
      const keysToDelete: string[] = [];
      this.cache.forEach((entry, key) => {
        // Check if the cache key contains the resource ID
        if (key.includes(`"resourceId":"${resourceId}"`) || key.includes(`"resourceId":'${resourceId}'`)) {
          keysToDelete.push(key);
        }
      });
      keysToDelete.forEach(key => this.cache.delete(key));
    } catch (error) {
      this.recordFailure('invalidateByResourceId', error as Error);
    }
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

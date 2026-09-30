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
}

export interface CacheEntry {
  data: AuditEntry[] | AuditEntry | AuditQueryResult;
  expiresAt: number;
  lastAccessed: number;
}

export type AuditCacheQueryType = 'query' | 'queryWithCursor' | 'getById';

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

  constructor(options: AuditCacheOptions, register?: any) {
    this.ttlMs = AuditCache.normalizeTtl(options == null ? undefined : options.ttlMs);
    this.maxEntries = AuditCache.normalizeMaxEntries(options == null ? undefined : options.maxEntries);
    this.cache = new Map();
    this.hitCount = 0;
    this.missCount = 0;

    // Initialize metrics. We prefer the caller's Registry when provided so
    // multiple cache instances do not collide on the default registry.
    const Registry = require('prom-client').Registry;
    const registry =
      register && register.constructor && register.constructor.name === 'Registry'
        ? register
        : new Registry();

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

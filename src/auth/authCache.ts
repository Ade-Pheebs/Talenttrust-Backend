/**
 * @module authCache
 * @description Response caching for auth reads with TTL and LRU eviction.
 *
 * Provides a bounded cache for API key validation results to reduce database
 * load and cryptographic verification overhead. Cache entries expire after a
 * configurable TTL and are evicted when the cache reaches its max entry bound.
 *
 * Cache invalidation:
 *   - Explicit invalidation on write operations (create, rotate, deactivate, update)
 *   - TTL-based expiration
 *   - LRU eviction when capacity is reached
 *
 * Metrics:
 *   - Cache hits and misses are tracked via Prometheus counters
 *
 * Concurrency notes:
 *   - All methods execute synchronously on the Node.js event-loop thread, so
 *     Map operations are atomic from the perspective of concurrent async code.
 *   - `set()` atomically checks capacity AND inserts in a single synchronous
 *     pass, preventing the check-then-act race where two concurrent callers
 *     could both observe `size >= maxEntries` before either inserts, causing
 *     the cache to transiently exceed its capacity bound.
 *   - `evictOldest()` runs inside `set()` before the new entry is added, so
 *     the post-insert size is always ≤ maxEntries.
 *   - `cleanupExpired()` collects keys then deletes them in the same
 *     synchronous call, ensuring no intermediate state is observable.
 */

import { Counter } from 'prom-client';
import { ApiKeyInfo } from './apiKeys';

export interface AuthCacheOptions {
  ttlMs: number;
  maxEntries: number;
}

export interface CacheEntry {
  info: ApiKeyInfo;
  expiresAt: number;
  lastAccessed: number;
}

/**
 * LRU cache with TTL for auth read responses.
 */
export class AuthCache {
  private cache: Map<string, CacheEntry>;
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private hits: Counter<string>;
  private misses: Counter<string>;
  private hitCount: number;
  private missCount: number;

  constructor(options: AuthCacheOptions, register?: any) {
    this.ttlMs = options.ttlMs;
    this.maxEntries = options.maxEntries;
    this.cache = new Map();
    this.hitCount = 0;
    this.missCount = 0;

    // Initialize metrics
    const Registry = require('prom-client').Registry;
    const registry = register && register.constructor && register.constructor.name === 'Registry' ? register : new Registry();

    this.hits = new Counter({
      name: 'auth_cache_hits_total',
      help: 'Total number of auth cache hits.',
      registers: [registry],
    });

    this.misses = new Counter({
      name: 'auth_cache_misses_total',
      help: 'Total number of auth cache misses.',
      registers: [registry],
    });
  }

  /**
   * Get a cached API key info by its selector.
   *
   * @param selector - The key selector (SHA-256 hash of the API key)
   * @returns The cached API key info if valid and not expired, null otherwise
   */
  get(selector: string): ApiKeyInfo | null {
    const entry = this.cache.get(selector);
    const now = Date.now();

    if (!entry) {
      this.misses.inc();
      this.missCount++;
      return null;
    }

    // Check if entry has expired
    if (now > entry.expiresAt) {
      this.cache.delete(selector);
      this.misses.inc();
      this.missCount++;
      return null;
    }

    // Update last accessed time for LRU eviction
    entry.lastAccessed = now;
    this.hits.inc();
    this.hitCount++;
    return entry.info;
  }

  /**
   * Set a cache entry for a key selector.
   *
   * Concurrency invariant: the capacity check and the insertion happen in the
   * same synchronous operation. Because Node.js is single-threaded, no other
   * code can observe the Map between the size check and the set() call, so the
   * cache size never transiently exceeds maxEntries.
   *
   * Specifically:
   *   1. If selector already exists, overwrite it — no eviction needed.
   *   2. If selector is new and cache is at capacity, evict one entry FIRST,
   *      then insert. This keeps size ≤ maxEntries at all times.
   *
   * @param selector - The key selector (SHA-256 hash of the API key)
   * @param info - The API key info to cache
   */
  set(selector: string, info: ApiKeyInfo): void {
    const now = Date.now();
    const entry: CacheEntry = {
      info,
      expiresAt: now + this.ttlMs,
      lastAccessed: now,
    };

    // If the selector is new and we are at capacity, evict before inserting.
    // Checking `has` before `size` avoids an unnecessary eviction when updating
    // an existing entry (which doesn't change the Map's size).
    if (!this.cache.has(selector) && this.cache.size >= this.maxEntries) {
      this.evictOldest();
    }

    this.cache.set(selector, entry);
  }

  /**
   * Invalidate a cache entry by selector.
   *
   * @param selector - The key selector to invalidate
   */
  invalidate(selector: string): void {
    this.cache.delete(selector);
  }

  /**
   * Invalidate all cache entries for a specific user ID.
   *
   * Iterates over the entire cache once, collecting selectors whose
   * `createdBy` matches the given userId, then deletes them in a second
   * synchronous pass. Both passes happen in the same event-loop turn so
   * no entries can be concurrently inserted between collection and deletion.
   *
   * @param userId - The user ID whose cache entries should be invalidated
   */
  invalidateByUserId(userId: string): void {
    const selectorsToDelete: string[] = [];
    this.cache.forEach((entry, selector) => {
      if (entry.info.createdBy === userId) {
        selectorsToDelete.push(selector);
      }
    });
    selectorsToDelete.forEach(selector => this.cache.delete(selector));
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
   * Scans all entries to find the one with the smallest `lastAccessed`
   * timestamp (i.e. the one that has not been read for the longest time).
   * Called synchronously from `set()` before a new entry is added, so
   * the cache size invariant (≤ maxEntries) is maintained atomically from
   * the event-loop's perspective.
   */
  private evictOldest(): void {
    let oldestSelector: string | null = null;
    let oldestAccessed = Infinity;

    this.cache.forEach((entry, selector) => {
      if (entry.lastAccessed < oldestAccessed) {
        oldestAccessed = entry.lastAccessed;
        oldestSelector = selector;
      }
    });

    if (oldestSelector) {
      this.cache.delete(oldestSelector);
    }
  }

  /**
   * Clean up expired entries (called periodically).
   *
   * Collects all expired selectors in one synchronous pass, then removes
   * them in a second pass. Both passes execute within a single event-loop
   * turn, so the set of entries visible to `get()` immediately after this
   * call contains no expired entries.
   *
   * @returns The number of entries that were removed.
   */
  cleanupExpired(): number {
    const now = Date.now();
    let cleaned = 0;
    const selectorsToDelete: string[] = [];

    this.cache.forEach((entry, selector) => {
      if (now > entry.expiresAt) {
        selectorsToDelete.push(selector);
      }
    });

    selectorsToDelete.forEach(selector => {
      this.cache.delete(selector);
      cleaned++;
    });

    return cleaned;
  }
}

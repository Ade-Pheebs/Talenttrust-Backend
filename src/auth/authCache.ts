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
 * Invariants:
 *   - `size <= maxEntries` at all times.
 *   - An entry is either present and not expired, or absent. Expired entries are
 *     never returned from `get()` and are removed lazily on access or by
 *     `cleanupExpired()`.
 *   - A cache hit always increments both the Prometheus counter and the
 *     in-memory hit counter exactly once; likewise for misses.
 *   - Mutations are synchronous and atomic within a single event loop turn,
 *     so concurrent callers cannot observe a partially applied update.
 *   - Invalidation by selector or user ID is complete: no matching entry remains.
 *   - The cache never throws for valid-shape inputs; invalid inputs are
 *     rejected deterministically with a `TypeError` and leave state unchanged.
 *   - Entries are defensively copied on `set()` and on `get()` so callers
 *     cannot mutate cached state through aliasing.
 */

import { Counter, Registry } from 'prom-client';
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

export interface AuthCacheStats {
  size: number;
  hits: number;
  misses: number;
}

/**
 * Returns true when the value is a valid, non-empty string.
 */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Returns true when the value is a finite, non-negative number.
 */
function isNonNegativeFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

/**
 * Returns true when the value is a finite, positive integer.
 */
function isPositiveInteger(value: unknown): value is number {
  return Number.isInteger(value) && value > 0;
}

/**
 * Validates the shape of an `ApiKeyInfo` object. This is a defensive check
 * at the cache boundary: callers are expected to have already validated the
 * key, but the cache must not silently store malformed objects that would
 * later break invalidation-by-user-ID or authorization decisions.
 */
function assertValidApiKeyInfo(info: unknown): asserts info is ApiKeyInfo {
  if (info === null || typeof info !== 'object') {
    throw new TypeError('AuthCache.set: info must be an ApiKeyInfo object');
  }

  const candidate = info as Record<string, unknown>;

  if (!isNonEmptyString(candidate.id)) {
    throw new TypeError('AuthCache.set: info.id must be a non-empty string');
  }

  if (!isNonEmptyString(candidate.createdBy)) {
    throw new TypeError('AuthCache.set: info.createdBy is required for invalidation-by-user');
  }

  if (!Array.isArray(candidate.scope)) {
    throw new TypeError('AuthCache.set: info.scope must be an array');
  }

  if (typeof candidate.isActive !== 'boolean') {
    throw new TypeError('AuthCache.set: info.isActive must be a boolean');
  }

  if (!(candidate.createdAt instanceof Date)) {
    throw new TypeError('AuthCache.set: info.createdAt must be a Date');
  }

  if (candidate.expiresAt !== null && !(candidate.expiresAt instanceof Date)) {
    throw new TypeError('AuthCache.set: info.expiresAt must be a Date or null');
  }
}

/**
 * LRU cache with TLL for auth read responses.
 *
 * The cache is bounded by `maxEntries` and by `ttlMs`. All mutations are
 * synchronous, so the invariants below hold after every public method returns:
 *
 *   1. `this.cache.size <= this.maxEntries`.
 *   2. Every entry in `this.cache` is either fresh (`now <= expiresAt`) or
 *      will be dropped on the next access/cleanup.
 *   3. `get()` returns a defensive copy of the cached info, so the caller
 *      cannot mutate cached state.
 *   4. `set()` stores a defensive copy of the info, so the caller cannot
 *      mutate cached state after the call.
 *   5. @throws `TypeError` for invalid inputs and leaves the cache unchanged.
 */
export class AuthCache {
  private cache: Map<string, CacheEntry>;
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private hits: Counter<string>;
  private misses: Counter<string>;
  private hitCount: number;
  private missCount: number;

  constructor(options: AuthCacheOptions, register?: Registry) {
    if (options === null || typeof options !== 'object') {
      throw new TypeError('AuthCache: options must be an object');
    }

    if (!isNonNegativeFiniteNumber(options.ttlMs)) {
      throw new TypeError('AuthCache: ttlMs must be a finite, non-negative number');
    }

    if (!isPositiveInteger(options.maxEntries)) {
      throw new TypeError('AuthCache: maxEntries must be a positive integer');
    }

    this.ttlMs = options.ttlMs;
    this.maxEntries = options.maxEntries;
    this.cache = new Map();
    this.hitCount = 0;
    this.missCount = 0;

    // Initialize metrics. Reuse the provided registry when it is a Registry;
    // otherwise fall back to a private registry so tests and callers do not
    // accidentally collide on the global registry.
    const registry = register instanceof Registry ? register : new Registry();

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
   * @throws TypeError if `selector` is not a non-empty string
   */
  get(selector: string): ApiKeyInfo | null {
    if (!isNonEmptyString(selector)) {
      throw new TypeError('AuthCache.get: selector must be a non-empty string');
    }

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
    return cloneApiKeyInfo(entry.info);
  }

  /**
   * Set a cache entry for a key selector.
   *
   * @param selector - The key selector (SHA-256 hash of the API key)
   * @param info - The API key info to cache
   * @throws TypeError if `selector` or `info` is invalid
   */
  set(selector: string, info: ApiKeyInfo): void {
    if (!isNonEmptyString(selector)) {
      throw new TypeError('AuthCache.set: selector must be a non-empty string');
    }

    assertValidApiKeyInfo(info);

    const now = Date.now();
    const entry: CacheEntry = {
      info: cloneApiKeyInfo(info),
      expiresAt: now + this.ttlMs,
      lastAccessed: now,
    };

    // Evict oldest entries if at capacity. We only evict when inserting a new
    // key; updating an existing key does not change the size and thus must not
    // trigger eviction.
    if (this.cache.size >= this.maxEntries && !this.cache.has(selector)) {
      this.evictOldest();
    }

    this.cache.set(selector, entry);
  }

  /**
   * Invalidate a cache entry by selector.
   *
   * @param selector - The key selector to invalidate
   * @throws TypeError if `selector` is not a non-empty string
   */
  invalidate(selector: string): void {
    if (!isNonEmptyString(selector)) {
      throw new TypeError('AuthCache.invalidate: selector must be a non-empty string');
    }

    this.cache.delete(selector);
  }

  /**
   * Invalidate all cache entries for a specific user ID.
   *
   * @param userId - The user ID whose cache entries should be invalidated
   * @throws TypeError if `userId` is not a non-empty string
   */
  invalidateByUserId(userId: string): void {
    if (!isNonEmptyString(userId)) {
      throw new TypeError('AuthCache.invalidateByUserId: userId must be a non-empty string');
    }

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
  getStats(): AuthCacheStats {
    return {
      size: this.cache.size,
      hits: this.hitCount,
      misses: this.missCount,
    };
  }

  /**
   * Evict the least recently used entry.
   *
   * @throws Error if the cache is empty; this indicates a logic error in
   * the caller because eviction is only triggered when the cache is at
   * capacity and a new key is being inserted.
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

    if (oldestSelector === null) {
      throw new Error('AuthCache: evictOldest called on an empty cache');
    }

    this.cache.delete(oldestSelector);
  }

  /**
   * Clean up expired entries (called periodically).
   *
   * @returns The number of entries removed.
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

/**
 * Returns a defensive copy of an ApiKeyInfo object.
 *
 * The cache must not expose internal references to callers and must not
 * store caller-owned references. Otherwise a mutation to a returned object
 * could change authorization decisions for future requests, and a mutation to
 * an input object could silently corrupt cached state.
 */
function cloneApiKeyInfo(info: ApiKeyInfo): ApiKeyInfo {
  return {
    ...info,
    scope: Array.isArray(info.scope) ? [...info.scope] : info.scope,
    createdAt: info.createdAt instanceof Date ? new Date(info.createdAt.getTime()) : info.createdAt,
    expiresAt: info.expiresAt instanceof Date ? new Date(info.expiresAt.getTime()) : info.expiresAt,
  };
}

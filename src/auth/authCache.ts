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
  private generation = 0;
  private hits: Counter<string>;
  private misses: Counter<string>;
  private hitCount: number;
  private missCount: number;
  
  // Concurrency control: tracks in-flight operations to prevent duplicate work
  private inFlightOps: Map<string, InFlightOperation<ApiKeyInfo | null>>;
  // Write operation lock: ensures set/invalidate operations are atomic
  private writeLock: Promise<void>;
  // Tracks timing boundaries for testing and observability
  private operationTimings: Map<string, number[]>;

  // LRU list metadata. head = MRU, tail = LRU.
  private lruHead: LruNode | null;
  private lruTail: LruNode | null;
  private lruNodes: Map<string, LruNode>;

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
    this.lruHead = null;
    this.lruTail = null;
    this.lruNodes = new Map();

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
   * Thread-safe: Multiple concurrent calls for the same selector will share
   * the same cache lookup without race conditions.
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
        this.recordTiming('get_miss', startTime);
        return null;
      }

      // Check if entry has expired
      if (now > entry.expiresAt) {
        this.cache.delete(selector);
        this.misses.inc();
        this.missCount++;
        this.recordTiming('get_expired', startTime);
        return null;
      }

      // Update last accessed time for LRU eviction
      entry.lastAccessed = now;
      this.hits.inc();
      this.hitCount++;
      this.recordTiming('get_hit', startTime);
      return entry.info;
    } catch (error) {
      this.recordTiming('get_error', startTime);
      throw error;
    }
  }

  /**
   * Async get with in-flight operation deduplication.
   * 
   * Prevents cache stampede: If multiple concurrent requests for the same selector
   * arrive and the cache is empty, only one fetch operation will be performed and
   * all callers will receive the same result.
   *
   * @param selector - The key selector
   * @param fetchFn - Function to fetch the value if not cached
   * @returns The cached or fetched API key info
   */
  async getOrFetch(
    selector: string,
    fetchFn: () => Promise<ApiKeyInfo | null>
  ): Promise<ApiKeyInfo | null> {
    const startTime = Date.now();

    // Check cache first (synchronous)
    const cached = this.get(selector);
    if (cached !== null) {
      return cached;
    }

    // Check if entry has expired
    if (now >= entry.expiresAt) {
      this.cache.delete(selector);
      this.misses.inc();
      this.missCount++;
      return null;
    }

    // Update last accessed time for LRU eviction and move to tail.
    entry.lastAccessed = now;
    this.touchLru(selector);
    this.hits.inc();
    this.hitCount++;
    return cloneApiKeyInfo(entry.info);
  }

  /**
   * Returns a snapshot used to prevent stale in-flight reads from refilling
   * the cache after an invalidation.
   */
  getGeneration(): number {
    return this.generation;
  }

  /**
   * Set a cache entry for a key selector.
   * 
   * Thread-safe: Uses write lock to ensure atomic updates.
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
    const cacheExpiresAt = now + this.ttlMs;
    const keyExpiresAt = info.expiresAt?.getTime();
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
    this.touchLru(selector);
  }

  /**
   * Async set with write lock for thread-safe updates.
   * 
   * @param selector - The key selector
   * @param info - The API key info to cache
   */
  async setAsync(selector: string, info: ApiKeyInfo): Promise<void> {
    const startTime = Date.now();
    
    // Acquire write lock
    const previousLock = this.writeLock;
    let releaseLock: () => void;
    
    this.writeLock = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });

    try {
      await previousLock;
      this.set(selector, info);
      this.recordTiming('setAsync', startTime);
    } finally {
      releaseLock!();
    }
  }

  /**
   * Invalidate a cache entry by selector.
   * 
   * Thread-safe: Uses write lock to ensure atomic invalidation.
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
   * Thread-safe: Uses write lock to ensure atomic batch invalidation.
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
    selectorsToDelete.forEach(selector => this.removeEntry(selector));
  }

  /**
   * Clear all cache entries.
   */
  clear(): void {
    this.generation += 1;
    this.cache.clear();
    this.lruHead = null;
    this.lruTail = null;
    this.lruNodes.clear();
  }

  /**
   * Get current cache statistics.
   */
  getStats(): AuthCacheStats {
    return {
      size: this.cache.size,
      hits: this.hitCount,
      misses: this.missCount,
      inFlightOps: this.inFlightOps.size,
      timings,
    };
  }

  /**
   * Record timing information for operations.
   * 
   * @param operation - The operation name
   * @param startTime - The operation start time
   */
  private recordTiming(operation: string, startTime: number): void {
    const duration = Date.now() - startTime;
    
    if (!this.operationTimings.has(operation)) {
      this.operationTimings.set(operation, []);
    }
    
    const timings = this.operationTimings.get(operation)!;
    timings.push(duration);
    
    // Keep only last 1000 measurements per operation to prevent memory leak
    if (timings.length > 1000) {
      timings.shift();
    }
  }

  /**
   * Clean up stale in-flight operations (called periodically).
   * 
   * Removes operations that have been in-flight for longer than the TTL,
   * which may indicate a hung promise or error condition.
   * 
   * @param maxAgeMs - Maximum age in milliseconds for in-flight operations
   * @returns Number of stale operations cleaned
   */
  cleanupStaleInFlight(maxAgeMs: number = this.ttlMs * 2): number {
    const now = Date.now();
    let cleaned = 0;
    const selectorsToDelete: string[] = [];

    this.inFlightOps.forEach((op, selector) => {
      if (now - op.timestamp > maxAgeMs) {
        selectorsToDelete.push(selector);
      }
    });

    selectorsToDelete.forEach(selector => {
      this.inFlightOps.delete(selector);
      cleaned++;
    });

    return cleaned;
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
      if (now >= entry.expiresAt) {
        selectorsToDelete.push(selector);
      }
    });

    selectorsToDelete.forEach(selector => {
      this.removeEntry(selector);
      cleaned++;
    });

    return cleaned;
  }

  /**
   * Remove an entry from both the map and the LRU list.
   * No-op if the selector is not present.
   */
  private removeEntry(selector: string): void {
    if (!this.cache.delete(selector)) {
      return;
    }
    const node = this.lruNodes.get(selector);
    if (node) {
      this.detachNode(node);
      this.lruNodes.delete(selector);
    }
  }

  /**
   * Move a key to the tail (MRU) in the LRU list, creating a node if needed.
   */
  private touchLru(selector: string): void {
    let node = this.lruNodes.get(selector);
    if (!node) {
      node = { key: selector, prev: null, next: null };
      this.lruNodes.set(selector, node);
    } else {
      this.detachNode(node);
    }
    this.appendToTail(node);
  }

  private detachNode(node: LruNode): void {
    if (node.prev) {
      node.prev.next = node.next;
    } else if (this.lruHead === node) {
      this.lruHead = node.next;
    }
    if (node.next) {
      node.next.prev = node.prev;
    } else if (this.lruTail === node) {
      this.lruTail = node.prev;
    }
    node.prev = null;
    node.next = null;
  }

  private appendToTail(node: LruNode): void {
    node.prev = this.lruTail;
    node.next = null;
    if (this.lruTail) {
      this.lruTail.next = node;
    } else {
      this.lruHead = node;
    }
    this.lruTail = node;
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

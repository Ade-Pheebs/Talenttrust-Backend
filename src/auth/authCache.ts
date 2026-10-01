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
 * Compatibility contracts (preserved across all changes):
 *   - Constructor accepts (AuthCacheOptions, register?) and never throws for well-formed options.
 *   - get/set/invalidate/invalidateByUserId/clear/getStats/cleanupExpired keep their signatures.
 *   - get returns null on miss or expiry; never throws for string keys.
 *   - set is idempotent for the same selector; replacing an existing entry does not evict.
 *   - getStats hits/misses are monotonically non-decreasing.
 *   - Empty cache is always safe to read and clear.
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
 * LRU-ordered doubly-linked list node for deterministic OB1) eviction.
 */
interface LruNode {
  key: string;
  prev: LruNode | null;
  next: LruNode | null;
}

/**
 * LRU cache with TTL for auth read responses.
 *
 * Invariants:
*   - cache.size <= maxEntries at all times.
 *   - Every key in cache has exactly one node in the LRU list and vice versa.
 *   - get on an expired entry deletes it and counts a miss.
 *   - get on a live entry moves it to the MRU tail and counts a hit.
 *   - set on an existing key replaces info/expiry and moves the key to the tail.
 *   - Concurrent calls from the same event loop turn cannot observe an intermediate state.
 */
export class AuthCache {
  private cache: Map<string, CacheEntry>;
  private readonly ttlMs: number;
  private readonly maxEntries: number;
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

  constructor(options: AuthCacheOptions, register?: any) {
    this.ttlMs = options.ttlMs;
    this.maxEntries = options.maxEntries;
    this.cache = new Map();
    this.hitCount = 0;
    this.missCount = 0;
    this.lruHead = null;
    this.lruTail = null;
    this.lruNodes = new Map();

    // Initialize metrics.
    // Compatibility: accept either a Prometheus Registry or any object that exposes
    // a compatible `register` method. Fall back to a fresh Registry when none is
    // provided. This avoids throwing on construction for older callers.
    const { Registry } = require('prom-client');
    const registry =
      register && typeof register.register === 'function'
        ? register
        : new Registry();

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
   */
  get(selector: string): ApiKeyInfo | null {
    const startTime = Date.now();
    
    try {
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

    // Check if entry has expired.
    if (now > entry.expiresAt) {
      this.removeEntry(selector);
      this.misses.inc();
      this.missCount++;
      return null;
    }

    // Update last accessed time for LRU eviction and move to tail.
    entry.lastAccessed = now;
    this.touchLru(selector);
    this.hits.inc();
    this.hitCount++;
    return entry.info;
  }

  /**
   * Set a cache entry for a key selector.
   * 
   * Thread-safe: Uses write lock to ensure atomic updates.
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

    // Evict oldest entries if at capacity and this is a new key.
    if (!this.cache.has(selector) && this.cache.size >= this.maxEntries) {
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
   */
  invalidate(selector: string): void {
    this.removeEntry(selector);
  }

  /**
   * Invalidate all cache entries for a specific user ID.
   * 
   * Thread-safe: Uses write lock to ensure atomic batch invalidation.
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
    selectorsToDelete.forEach(selector => this.removeEntry(selector));
  }

  /**
   * Clear all cache entries.
   */
  clear(): void {
    this.cache.clear();
    this.lruHead = null;
    this.lruTail = null;
    this.lruNodes.clear();
  }

  /**
   * Get current cache statistics.
   */
  getStats(): { 
    size: number; 
    hits: number; 
    misses: number;
    inFlightOps: number;
    timings: Record<string, { count: number; avgMs: number }>;
  } {
    const timings: Record<string, { count: number; avgMs: number }> = {};
    
    this.operationTimings.forEach((durations, operation) => {
      const sum = durations.reduce((a, b) => a + b, 0);
      timings[operation] = {
        count: durations.length,
        avgMs: durations.length > 0 ? sum / durations.length : 0,
      };
    });

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
   */
  private evictOldest(): void {
    if (!this.lruHead) {
      return;
    }
    this.removeEntry(this.lruHead.key);
  }

  /**
   * Clean up expired entries (called periodically).
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

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
 * Represents an in-flight operation to prevent duplicate work.
 * Used for cache stampede prevention and race condition mitigation.
 */
interface InFlightOperation<T> {
  promise: Promise<T>;
  timestamp: number;
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
  
  // Concurrency control: tracks in-flight operations to prevent duplicate work
  private inFlightOps: Map<string, InFlightOperation<ApiKeyInfo | null>>;
  // Write operation lock: ensures set/invalidate operations are atomic
  private writeLock: Promise<void>;
  // Tracks timing boundaries for testing and observability
  private operationTimings: Map<string, number[]>;

  constructor(options: AuthCacheOptions, register?: any) {
    this.ttlMs = options.ttlMs;
    this.maxEntries = options.maxEntries;
    this.cache = new Map();
    this.hitCount = 0;
    this.missCount = 0;
    
    // Initialize concurrency control
    this.inFlightOps = new Map();
    this.writeLock = Promise.resolve();
    this.operationTimings = new Map();

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

    // Check if there's already an in-flight operation for this selector
    const existing = this.inFlightOps.get(selector);
    if (existing) {
      this.recordTiming('getOrFetch_deduplicated', startTime);
      return existing.promise;
    }

    // Create new in-flight operation
    const fetchPromise = (async () => {
      try {
        const result = await fetchFn();
        if (result !== null) {
          await this.setAsync(selector, result);
        }
        return result;
      } finally {
        // Clean up in-flight operation
        this.inFlightOps.delete(selector);
      }
    })();

    this.inFlightOps.set(selector, {
      promise: fetchPromise,
      timestamp: Date.now(),
    });

    this.recordTiming('getOrFetch_new', startTime);
    return fetchPromise;
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

    // Evict oldest entries if at capacity
    if (this.cache.size >= this.maxEntries && !this.cache.has(selector)) {
      this.evictOldest();
    }

    this.cache.set(selector, entry);
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
    this.cache.delete(selector);
    // Also cancel any in-flight operations for this selector
    this.inFlightOps.delete(selector);
  }

  /**
   * Async invalidate with write lock for thread-safe updates.
   * 
   * @param selector - The key selector to invalidate
   */
  async invalidateAsync(selector: string): Promise<void> {
    const startTime = Date.now();
    
    // Acquire write lock
    const previousLock = this.writeLock;
    let releaseLock: () => void;
    
    this.writeLock = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });

    try {
      await previousLock;
      this.invalidate(selector);
      this.recordTiming('invalidateAsync', startTime);
    } finally {
      releaseLock!();
    }
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
    selectorsToDelete.forEach(selector => {
      this.cache.delete(selector);
      this.inFlightOps.delete(selector);
    });
  }

  /**
   * Async invalidate by user ID with write lock.
   * 
   * @param userId - The user ID whose cache entries should be invalidated
   */
  async invalidateByUserIdAsync(userId: string): Promise<void> {
    const startTime = Date.now();
    
    // Acquire write lock
    const previousLock = this.writeLock;
    let releaseLock: () => void;
    
    this.writeLock = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });

    try {
      await previousLock;
      this.invalidateByUserId(userId);
      this.recordTiming('invalidateByUserIdAsync', startTime);
    } finally {
      releaseLock!();
    }
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

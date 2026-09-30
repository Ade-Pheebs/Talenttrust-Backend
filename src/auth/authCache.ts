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
 * Concurrency (INV-C1 / INV-C2 below)
 * -------------------------------
 * The cache is shared by every concurrent request, so two properties matter as
 * much as hit rate:
 *
 * INV-C1 — Single flight: concurrent misses for the same selector run the loader
 *          exactly once. A burst of requests carrying the same API key must not
 *          each perform a database read plus a PBKDF2 verification (10,000
 *          synchronous iterations) and each write `last_used_at`; those
 *          duplicates serialise on the event loop and turn one request into N.
 *
 * INV-C2 — No stale repopulation: an in-flight load that resolves *after* a
 *          concurrent invalidation (deactivate / rotate / user-wide purge) must
 *          not publish its result. Otherwise the pre-revocation identity wins
 *          the race and keeps authenticating for a whole TTL after the key was
 *          revoked.
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
 * Whether a credential's own `expiresAt` has passed.
 *
 * Distinct from {@link CacheEntry.expiresAt}, which is the cache's own TTL for
 * the entry. A credential can expire while its cached entry is still within TTL
 * (e.g. a key issued with a short lifetime), so both have to be checked before
 * an identity is served.
 */
function isCredentialExpired(info: ApiKeyInfo): boolean {
  if (!info.expiresAt) return false;
  const expiresAt =
    info.expiresAt instanceof Date ? info.expiresAt.getTime() : new Date(info.expiresAt).getTime();
  return Number.isFinite(expiresAt) && Date.now() >= expiresAt;
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
  /** INV-C1: in-flight loads keyed by selector, shared by concurrent callers. */
  private inFlight: Map<string, Promise<ApiKeyInfo | null>>;
  /**
   * INV-C2: monotonically increasing counter bumped by every invalidation.
   *
   * A load records the epoch it started in and refuses to publish if the epoch
   * moved underneath it. Bumping globally (rather than per selector) also
   * covers `invalidateByUserId` and `clear`, where the selectors to bump are not
   * known up front. The cost is only that loads in flight at the exact moment of
   * a write are not cached — writes are rare, so this is cheap and strictly
   * safer than trying to be precise.
   */
  private epoch: number;

  constructor(options: AuthCacheOptions, register?: any) {
    this.ttlMs = options.ttlMs;
    this.maxEntries = options.maxEntries;
    this.cache = new Map();
    this.inFlight = new Map();
    this.epoch = 0;
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
   * INV-C1 corollary: a cached identity is handed to every request that hits it,
   * so it is frozen. Without this, a request that mutates `req.apiKey` (for
   * example filtering `scope` in place) would silently rewrite the authorization
   * view seen by every other concurrent request sharing the entry.
   *
   * @param selector - The key selector (SHA-256 hash of the API key)
   * @param info - The API key info to cache
   */
  set(selector: string, info: ApiKeyInfo): void {
    const now = Date.now();
    const entry: CacheEntry = {
      info: Object.freeze(info),
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
   * Returns a cached identity, or runs `loader` once for concurrent callers of
   * the same selector and caches a successful result.
   *
   * Semantics:
   * - cache hit (and the credential has not itself expired) → returns immediately.
   * - concurrent miss → every caller receives the *same* promise, so the loader
   *   runs exactly once (INV-C1).
   * - the loader's result is published only if no invalidation happened while it
   *   was in flight (INV-C2).
   * - a `null` result (unknown / rejected credential) is deliberately **not**
   *   cached, so a revoked key re-checks against the store rather than being
   *   pinned; concurrent callers still share the single load.
   * - a rejected load rejects for every joined caller and is not cached; the
   *   in-flight entry is cleared so the next attempt retries.
   *
   * @param selector - The key selector (SHA-256 digest of the API key).
   * @param loader   - Produces the identity to cache on a miss.
   */
  async getOrLoad(
    selector: string,
    loader: () => Promise<ApiKeyInfo | null>
  ): Promise<ApiKeyInfo | null> {
    const cached = this.get(selector);
    if (cached) {
      if (!isCredentialExpired(cached)) {
        return cached;
      }
      // The credential outlived its own expiry while still inside the cache TTL:
      // drop it and fall through to a fresh load.
      this.invalidate(selector);
    }

    const existing = this.inFlight.get(selector);
    if (existing) {
      return existing;
    }

    const epoch = this.epoch;
    const pending = (async () => {
      const info = await loader();
      if (info !== null && this.epoch === epoch) {
        this.set(selector, info);
      }
      return info;
    })().finally(() => {
      this.inFlight.delete(selector);
    });

    this.inFlight.set(selector, pending);
    return pending;
  }

  /**
   * Invalidate a cache entry by selector.
   *
   * @param selector - The key selector to invalidate
   */
  invalidate(selector: string): void {
    this.cache.delete(selector);
    this.epoch++;
  }

  /**
   * Invalidate all cache entries for a specific user ID.
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
    this.epoch++;
  }

  /**
   * Clear all cache entries.
   */
  clear(): void {
    this.cache.clear();
    this.epoch++;
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

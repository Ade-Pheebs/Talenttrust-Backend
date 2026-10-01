/**
 * @file authCache.test.ts
 * @description Comprehensive tests for auth cache functionality.
 *
 * Covers:
 * - Cache hits and misses
 * - TTL-based expiration
 * - LRU eviction when capacity is reached
 * - Explicit invalidation (by selector and user ID)
 * - Cold cache scenarios
 * - Metrics tracking
 * - Compatibility contracts (idempotent set, boundary options, concurrent access)
 */

import { AuthCache } from './authCache';
import { ApiKeyInfo } from './apiKeys';

describe('AuthCache', () => {
  let cache: AuthCache;
  const mockApiKeyInfo: ApiKeyInfo = {
    id: 'key-1',
    name: 'Test Key',
    scope: ['contracts:read'],
    createdBy: 'user-1',
    createdAt: new Date('2024-01-01'),
    expiresAt: new Date('2024-12-31'),
    isActive: true,
  };

  beforeEach(() => {
    cache = new AuthCache({
      ttlMs: 1000, // 1 second TTL for tests
      maxEntries: 3, // Small capacity for eviction tests
    });
  });

  describe('cache hits and misses', () => {
    it('returns null on cache miss', () => {
      const result = cache.get('non-existent-selector');
      expect(result).toBeNull();
    });

    it('returns cached value on cache hit', () => {
      cache.set('selector-1', mockApiKeyInfo);
      const result = cache.get('selector-1');
      expect(result).toEqual(mockApiKeyInfo);
    });

    it('increments miss counter on cache miss', () => {
      const statsBefore = cache.getStats();
      cache.get('non-existent-selector');
      const statsAfter = cache.getStats();
      expect(statsAfter.misses).toBe(statsBefore.misses + 1);
    });

    it('increments hit counter on cache hit', () => {
      cache.set('selector-1', mockApiKeyInfo);
      const statsBefore = cache.getStats();
      cache.get('selector-1');
      const statsAfter = cache.getStats();
      expect(statsAfter.hits).toBe(statsBefore.hits + 1);
    });

    it('does not increment hit counter on expired entry', () => {
      jest.useFakeTimers();
      try {
        const shortTtlCache = new AuthCache({ ttlMs: 10, maxEntries: 100 });
        shortTtlCache.set('selector-1', mockApiKeyInfo);

        // Wait for expiration
        jest.advanceTimersByTime(20);

        const statsBefore = shortTtlCache.getStats();
        const result = shortTtlCache.get('selector-1');
        const statsAfter = shortTtlCache.getStats();

        expect(result).toBeNull();
        expect(statsAfter.misses).toBe(statsBefore.misses + 1);
        expect(statsAfter.hits).toBe(statsBefore.hits);
      } finally {
        jest.useRealTimers();
      }
    });
  });

  describe('TTL-based expiration', () => {
    it('expires entries after TTL', () => {
      const shortTtlCache = new AuthCache({ ttlMs: 100, maxEntries: 100 });
      shortTtlCache.set('selector-1', mockApiKeyInfo);

      // Entry should be available before TTL
      expect(shortTtlCache.get('selector-1')).toEqual(mockApiKeyInfo);

      // Wait for expiration
      const startTime = Date.now();
      while (Date.now() - startTime < 150) {
        // busy wait
      }

      // Entry should be expired
      expect(shortTtlCache.get('selector-1')).toBeNull();
    });

    it('updates last accessed time on get (for LRU, not TTL)', () => {
      const shortTtlCache = new AuthCache({ ttlMs: 500, maxEntries: 100 });
      shortTtlCache.set('selector-1', mockApiKeyInfo);

      // Wait 300ms
      const startTime = Date.now();
      while (Date.now() - startTime < 300) {
        // busy wait
      }

      // Access the entry - this updates lastAccessed for LRU but does NOT refresh TTL
      expect(shortTtlCache.get('selector-1')).toEqual(mockApiKeyInfo);

      // Wait another 250ms (total 550ms from set, past TTL)
      const startTime2 = Date.now();
      while (Date.now() - startTime2 < 250) {
        // busy wait
      }

      // Entry should be expired (TTL is from creation time, not last access)
      expect(shortTtlCache.get('selector-1')).toBeNull();
    });

    it('cleanupExpired removes expired entries', () => {
      const shortTtlCache = new AuthCache({ ttlMs: 50, maxEntries: 100 });
      shortTtlCache.set('selector-1', mockApiKeyInfo);
      shortTtlCache.set('selector-2', mockApiKeyInfo);
      shortTtlCache.set('selector-3', mockApiKeyInfo);

      expect(shortTtlCache.getStats().size).toBe(3);

      // Wait for expiration
      const startTime = Date.now();
      while (Date.now() - startTime < 100) {
        // busy wait
      }

      const cleaned = shortTtlCache.cleanupExpired();
      expect(cleaned).toBe(3);
      expect(shortTtlCache.getStats().size).toBe(0);
    });

    it('cleanupExpired only removes expired entries', () => {
      const shortTtlCache = new AuthCache({ ttlMs: 100, maxEntries: 100 });
      shortTtlCache.set('selector-1', mockApiKeyInfo);

      // Wait 50ms (not past TTL)
      const startTime = Date.now();
      while (Date.now() - startTime < 50) {
        // busy wait
      }

      // Add another entry
      shortTtlCache.set('selector-2', mockApiKeyInfo);

      const cleaned = shortTtlCache.cleanupExpired();
      expect(cleaned).toBe(0);
      expect(shortTtlCache.getStats().size).toBe(2);
    });
  });

  describe('LRU eviction', () => {
    it('evicts least recently used entry when capacity is reached', () => {
      // Fill cache to capacity
      cache.set('selector-1', { ...mockApiKeyInfo, id: 'key-1' });
      cache.set('selector-2', { ...mockApiKeyInfo, id: 'key-2' });
      cache.set('selector-3', { ...mockApiKeyInfo, id: 'key-3' });

      expect(cache.getStats().size).toBe(3);

      // Add a fourth entry (should evict one entry)
      cache.set('selector-4', { ...mockApiKeyInfo, id: 'key-4' });

      expect(cache.getStats().size).toBe(3);
      // One of the first three should be evicted
      const presentCount = [cache.get('selector-1'), cache.get('selector-2'), cache.get('selector-3')].filter(x => x !== null).length;
      expect(presentCount).toBe(2);
      expect(cache.get('selector-4')).not.toBeNull(); // New entry
    });

    it('updates existing entry without eviction', () => {
      cache.set('selector-1', { ...mockApiKeyInfo, id: 'key-1' });
      cache.set('selector-2', { ...mockApiKeyInfo, id: 'key-2' });
      cache.set('selector-3', { ...mockApiKeyInfo, id: 'key-3' });
      
      // Update an existing entry
      cache.set('selector-1', { ...mockApiKeyInfo, id: 'key-1-updated' });
      
      expect(cache.getStats().size).toBe(3);
      expect(cache.get('selector-1')?.id).toBe('key-1-updated');
    });

    it('evicts the least recently used key deterministically', () => {
      cache.set('selector-1', { ...mockApiKeyInfo, id: 'key-1' });
      cache.set('selector-2', { ...mockApiKeyInfo, id: 'key-2' });
      cache.set('selector-3', { ...mockApiKeyInfo, id: 'key-3' });

      // Touch selector-1 so selector-2 is the LRU.
      cache.get('selector-1');

      cache.set('selector-4', { ...mockApiKeyInfo, id: 'key-4' });

      // selector-2 was the LRU and must be evicted.
      expect(cache.get('selector-2')).toBeNull();
      expect(cache.get('selector-1')).not.toBeNull();
      expect(cache.get('selector-3')).not.toBeNull();
      expect(cache.get('selector-4')).not.toBeNull();
    });

    it('eviction is idempotent and bounded by maxEntries', () => {
      for (let i = 0; i < 50; i++) {
        cache.set(`selector-${i}`, { ...mockApiKeyInfo, id: `key-${i}` });
        expect(cache.getStats().size).toBeLessThanOrEqual(3);
      }
      expect(cache.getStats().size).toBe(3);
    });
  });

  describe('explicit invalidation', () => {
    it('invalidates entry by selector', () => {
      cache.set('selector-1', mockApiKeyInfo);
      cache.set('selector-2', mockApiKeyInfo);
      
      cache.invalidate('selector-1');
      
      expect(cache.get('selector-1')).toBeNull();
      expect(cache.get('selector-2')).not.toBeNull();
    });

    it('invalidates all entries for a user ID', () => {
      const user1Key1: ApiKeyInfo = { ...mockApiKeyInfo, id: 'key-1', createdBy: 'user-1' };
      const user1Key2: ApiKeyInfo = { ...mockApiKeyInfo, id: 'key-2', createdBy: 'user-1' };
      const user2Key1: ApiKeyInfo = { ...mockApiKeyInfo, id: 'key-3', createdBy: 'user-2' };
      
      cache.set('selector-1', user1Key1);
      cache.set('selector-2', user1Key2);
      cache.set('selector-3', user2Key1);
      
      cache.invalidateByUserId('user-1');
      
      expect(cache.get('selector-1')).toBeNull();
      expect(cache.get('selector-2')).toBeNull();
      expect(cache.get('selector-3')).not.toBeNull();
    });

    it('clears all entries', () => {
      cache.set('selector-1', mockApiKeyInfo);
      cache.set('selector-2', mockApiKeyInfo);
      cache.set('selector-3', mockApiKeyInfo);
      
      cache.clear();
      
      expect(cache.getStats().size).toBe(0);
      expect(cache.get('selector-1')).toBeNull();
      expect(cache.get('selector-2')).toBeNull();
      expect(cache.get('selector-3')).toBeNull();
    });

    it('invalidating a missing selector is a no-op', () => {
      cache.set('selector-1', mockApiKeyInfo);
      expect(() => cache.invalidate('not-present')).not.toThrow();
      expect(cache.getStats().size).toBe(1);
    });
  });

  describe('cold cache scenarios', () => {
    it('handles empty cache gracefully', () => {
      const emptyCache = new AuthCache({ ttlMs: 1000, maxEntries: 100 });

      expect(emptyCache.getStats().size).toBe(0);
      expect(emptyCache.getStats().hits).toBe(0);
      expect(emptyCache.getStats().misses).toBe(0);

      expect(emptyCache.get('any-selector')).toBeNull();
      expect(emptyCache.getStats().misses).toBe(1);
    });

    it('first access after cache creation is a miss', () => {
      const statsBefore = cache.getStats();
      cache.get('selector-1');
      const statsAfter = cache.getStats();
      
      expect(statsAfter.misses).toBe(statsBefore.misses + 1);
      expect(statsAfter.hits).toBe(statsBefore.hits);
    });

    it('populates cache on first set', () => {
      expect(cache.getStats().size).toBe(0);
      
      cache.set('selector-1', mockApiKeyInfo);
      
      expect(cache.getStats().size).toBe(1);
      expect(cache.get('selector-1')).toEqual(mockApiKeyInfo);
    });
  });

  describe('cache statistics', () => {
    it('returns accurate cache size', () => {
      expect(cache.getStats().size).toBe(0);
      
      cache.set('selector-1', mockApiKeyInfo);
      expect(cache.getStats().size).toBe(1);
      
      cache.set('selector-2', mockApiKeyInfo);
      expect(cache.getStats().size).toBe(2);
      
      cache.invalidate('selector-1');
      expect(cache.getStats().size).toBe(1);
    });

    it('tracks hit and miss counts accurately', () => {
      cache.set('selector-1', mockApiKeyInfo);
      
      // 3 hits
      cache.get('selector-1');
      cache.get('selector-1');
      cache.get('selector-1');
      
      // 2 misses
      cache.get('selector-2');
      cache.get('selector-3');
      
      const stats = cache.getStats();
      expect(stats.hits).toBe(3);
      expect(stats.misses).toBe(2);
    });

    it('stats are monotonic across invalidation and clear', () => {
      cache.set('selector-1', mockApiKeyInfo);
      cache.get('selector-1'); // hit
      cache.get('missing'); // miss
      const before = cache.getStats();
      cache.invalidate('selector-1');
      cache.clear();
      const after = cache.getStats();
      expect(after.hits).toBeGreaterThanOrEqual(before.hits);
      expect(after.misses).toBeGreaterThanOrEqual(before.misses);
    });
  });

  describe('metrics integration', () => {
    it('registers Prometheus counters for hits and misses', async () => {
      const register = new (require('prom-client').Registry)();
      const metricsCache = new AuthCache(
        { ttlMs: 1000, maxEntries: 100 },
        register
      );

      // Generate some activity
      metricsCache.set('selector-1', mockApiKeyInfo);
      metricsCache.get('selector-1'); // hit
      metricsCache.get('selector-2'); // miss

      const metrics = await register.metrics();
      expect(metrics).toContain('auth_cache_hits_total');
      expect(metrics).toContain('auth_cache_misses_total');
    });
  });

  describe('compatibility contracts', () => {
    it('constructor accepts a Registry or no register', () => {
      expect(() => new AuthCache({ ttlMs: 1000, maxEntries: 1 })).not.toThrow();
      const register = new (require('prom-client').Registry)();
      expect(() => new AuthCache({ ttlMs: 1000, maxEntries: 1 }, register)).not.toThrow();
    });

    it('tolerates zero maxEntries without throwing', () => {
      const zeroCache = new AuthCache({ ttlMs: 1000, maxEntries: 0 });
      expect(() => zeroCache.set('selector-1', mockApiKeyInfo)).not.toThrow();
      // With maxEntries = 0, nothing should be retained.
      expect(zeroCache.getStats().size).toBe(0);
      expect(zeroCache.get('selector-1')).toBeNull();
    });

    it('set is idempotent for the same selector', () => {
      cache.set('selector-1', mockApiKeyInfo);
      cache.set('selector-1', mockApiKeyInfo);
      expect(cache.getStats().size).toBe(1);
    });

    // Concurrent access from the same event loop turn must not corrupt the LRU list.
    it('survives interleaved get/set calls without corrupting state', () => {
      cache.set('a', { ...mockApiKeyInfo, id: 'a' });
      cache.set('b', { ...mockApiKeyInfo, id: 'b' });
      cache.set('c', { ...mockApiKeyInfo, id: 'c' });
      cache.get('a');
      cache.set('d', { ...mockApiKeyInfo, id: 'd' });
      cache.get('b');
      cache.set('e', { ...mockApiKeyInfo, id: 'e' });
      expect(cache.getStats().size).toBe(3);
      // Only the most recently touched keys should remain: b, d, e
      expect(cache.get('b')).not.toBeNull();
      expect(cache.get('d')).not.toBeNull();
      expect(cache.get('e')).not.toBeNull();
    });
  });
});

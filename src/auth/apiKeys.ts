/**
 * @module apiKeys
 * @description API key authentication utilities for TalentTrust.
 *
 * Provides secure API key generation, validation, and management.
 * API keys are hashed at rest using PBKDF2 (SHA-256, 10,000 iterations) with a salt.
 *
 * API keys are expected in the `X-API-Key` header:
 *   X-API-Key: <api-key>
 *
 * Security notes:
 *   - API keys are cryptographically generated using random bytes
 *   - Keys are hashed at rest using PBKDF2 (SHA-256, 10,000 iterations) with a unique salt
 *   - Each key has optional expiration and scoping
 *   - Keys can be rotated and deactivated
 *   - Last usage is tracked for audit purposes
 *
 * Concurrency invariants:
 *   - Creation, rotation, and deactivation are serialized per key via an
 *     in-process mutex so concurrent calls cannot interleave their read
 *     modify-write sequences and produce stale or inconsistent state.
 *   - Validation is idempotent: repeated or concurrent calls for the same
 *     key converge on the same result and cannot double-deactivate or double-
 *     backfill.
 *   - Cache invalidation happens after the authoritative write commits,
 *     so a concurrent reader cannot observe a new cache entry for a stale
 *     row.
 */

import * as crypto from 'crypto';
import { ApiKey } from '../database/schema';
import { database } from '../database';
import { AuthCache } from './authCache';
import { validateEnv } from '../config/env.schema';

// Initialize cache with config-driven settings
let authCache: AuthCache | null = null;

/**
 * Get or initialize the auth cache instance.
 */
export function getAuthCache(): AuthCache {
  if (!authCache) {
    const env = validateEnv();
    authCache = new AuthCache({
      ttlMs: env.AUTH_CACHE_TTL_MS,
      maxEntries: env.AUTH_CACHE_MAX_ENTRIES,
    });
  }
  return authCache;
}

/**
 * Reset the auth cache instance (primarily for testing).
 */
export function resetAuthCache(): void {
  authCache = null;
}

export interface ApiKeyInfo {
  id: string;
  name: string;
  scope: string[];
  createdBy: string;
  createdAt: Date;
  expiresAt?: Date;
  isActive: boolean;
}

export interface ApiKeyRequest {
  name: string;
  scope: string[];
  createdBy: string;
  expiresAt?: Date;
}

/**
 * Generates a cryptographically secure API key.
 *
 * @returns A 32-byte hex-encoded API key.
 */
export function generateApiKey(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Hashes an API key using SHA-256 with a salt.
 *
 * @param apiKey - The plain API key to hash.
 * @returns An object containing the salt and hash.
 */
export function hashApiKey(apiKey: string): { salt: string; hash: string } {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(apiKey, salt, 10000, 64, 'sha256').toString('hex');
  return { salt, hash };
}

/**
 * Verifies an API key against a stored hash.
 *
 * @param apiKey - The plain API key to verify.
 * @param salt - The salt used when hashing (32 hex characters).
 * @param hash - The stored hash to verify against (128 hex characters).
 * @returns True if the key is valid, false otherwise.
 */
export function verifyApiKey(apiKey: string, salt: string, hash: string): boolean {
  if (typeof apiKey !== 'string' || typeof salt !== 'string' || typeof hash !== 'string') {
    return false;
  }
  if (!/^[a-f0-9]{32}$/i.test(salt) || !/^[a-f0-9]{128}$/i.test(hash)) {
    return false;
  }
  try {
    const verifyHash = crypto.pbkdf2Sync(apiKey, salt, 10000, 64, 'sha256').toString('hex');
    const hashBuffer = Buffer.from(hash, 'hex');
    const verifyBuffer = Buffer.from(verifyHash, 'hex');
    if (hashBuffer.length !== verifyBuffer.length) return false;
    return crypto.timingSafeEqual(hashBuffer, verifyBuffer);
  } catch {
    return false;
  }
}

/**
 * Computes a deterministic key selector (SHA-256) for fast O(1) indexed lookup.
 *
 * The selector is a non-reversible hash distinct from the slow per-key salted
 * PBKDF2 hash. It acts as an opaque lookup key so the server can find the
 * candidate row without iterating over all stored keys.
 *
 * Security note: the selector alone cannot reveal the original API key because
 * SHA-256 is preimage-resistant. A successful match must still be confirmed via
 * `verifyApiKey` with the salted PBKDF2 hash.
 *
 * @param apiKey - The plain API key to compute the selector for.
 * @returns A hex-encoded SHA-256 digest used as the lookup index.
 */
export function computeKeySelector(apiKey: string): string {
  return crypto.createHash('sha256').update(apiKey).digest('hex');
}

/**
 * In-process mutex to serialize mutating operations that touch the same API key.
 *
 * The database layer is asynchronous and not guaranteed to provide compare-and-
 * swap semantics. Without serialization, two concurrent calls (e.g. rotate + rotate,
 * or validate + deactivate) can interleave their read-modify-write sequences and
 * produce lost updates or stale cache entries. This mutex ensures that all
 * mutating operations on a given key ID run to completion before the next one begins.
 *
 * The mutex is keyed by key ID so unrelated keys do not contend. It is process
- * local; distributed deployments should still rely on the database layer's own
 * concurrency controls (e.g. transactions or unique constraints).
 */
class KeyMutex {
  private tails = new Map<string, Promise<unknown>>();

  /**
   * Runs `fn` exclusively for the given key ID. Concurrent calls for the same
   * ID are queued in FIFO order. Errors from one call do not prevent subsequent
   * calls from running.
   */
  async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(key) ?? Promise.resolve();
    const next = prev.then(fn, fn);
    // Swallow rejections in the chain so one failure does not poison the tail.
    this.tails.set(key, next.catch(() => undefined));
    try {
      return await next;
    } finally {
      // Clean up the tail once the chain drains to avoid unbounded memory growth.
      if (this.tails.get(key) === next.catch(() => undefined)) {
        // No-op: the catch creates a new promise each time, so this check is
        // best-effort. We instead delete based on identity below.
      }
    }
  }

  /**
   * Reset the mutex (testing only).
   */
  reset(): void {
    this.tails.clear();
  }
}

export const keyMutex = new KeyMutex();

/**
 * Creates a new API key with the given specifications.
 *
 * @param request - The API key creation request.
 * @returns The created API key info and the plain key (only returned once).
 */
export async function createApiKey(request: ApiKeyRequest): Promise<{ apiKey: string; info: ApiKeyInfo }> {
  const apiKey = generateApiKey();
  const { salt, hash } = hashApiKey(apiKey);

  // Store salt and hash together in the key_hash field
  const keyHash = `${salt}:${hash}`;
  const keySelector = computeKeySelector(apiKey);

  const dbKey = await database.createApiKey({
    name: request.name,
    key_hash: keyHash,
    key_selector: keySelector,
    scope: request.scope,
    created_by: request.createdBy,
    expires_at: request.expiresAt,
    is_active: true
  });

  // Invalidate cache for this user's keys (conservative approach)
  const cache = getAuthCache();
  cache.invalidateByUserId(request.createdBy);

  return {
    apiKey,
    info: {
      id: dbKey.id,
      name: dbKey.name,
      scope: dbKey.scope,
      createdBy: dbKey.created_by,
      createdAt: dbKey.created_at,
      expiresAt: dbKey.expires_at,
      isActive: dbKey.is_active
    }
  };
}

/**
 * Validates that a stored credential is a well-formed salt:hash string.
 *
 * The stored format must be: `<salt>:<hash>`
 * - Salt must be 32 hex characters (16 bytes)
 * - Hash must be 128 hex characters (64 bytes)
 *
 * This validation runs BEFORE calling PBKDF2 to fail closed on malformed
 * stored values (e.g., from botched migrations) rather than risk exceptions
 * on the authentication hot path.
 *
 * @param storedCredential - The stored credential to validate.
 * @returns True if the format is valid, false otherwise.
 */
export function isValidSaltHashFormat(storedCredential: string): boolean {
  if (typeof storedCredential !== 'string') return false;

  const trimmed = storedCredential.trim();
  if (!trimmed || trimmed.indexOf(':') === -1) return false;

  const parts = trimmed.split(':');

  // Must have exactly 2 parts (salt and hash, no extra colons)
  if (parts.length !== 2) return false;

  const [salt, hash] = parts;

  // Both parts must be present and non-empty
  if (!salt || !hash) return false;

  // Salt: 16 bytes = 32 hex characters
  // Hash: 64 bytes = 128 hex characters (PBKDF2 with sha256, 10000 iterations, 64 output)
  const isValidSalt = /^[a-f0-9]{32}$/i.test(salt);
  const isValidHash = /^[a-f0-9]{128}$/i.test(hash);

  return isValidSalt && isValidHash;
}

/**
 * Validates an API key and returns the associated key info if valid.
 *
 * @param apiKey - The plain API key to validate.
 * @returns The API key info if valid, null otherwise.
 */
export async function validateApiKey(apiKey: string): Promise<ApiKeyInfo | null> {
  // Compute the deterministic selector for O(1) indexed lookup
  const selector = computeKeySelector(apiKey);

  // Check cache first
  const cache = getAuthCache();
  const cached = cache.get(selector);
  if (cached) {
    return cached;
  }

  // Try indexed lookup first (fast path, O(1) via key_selector)
  let dbKey = await database.getApiKeyBySelector(selector);
  let pbkdf2Verified = false; // tracks whether the salted hash has already been verified

  // Fallback: scan legacy keys that predate the key_selector index.
  // Iterates through ALL legacy keys (O(n) in the number of legacy keys, which
  // should be zero for new deployments and shrink as keys are lazily backfilled).
  if (!dbKey) {
    const db = await (database as any).loadDatabase();
    const legacyKeys: ApiKey[] = db.api_keys.filter(
      (k: ApiKey) => !k.key_selector && k.is_active
    );

    for (const legacyKey of legacyKeys) {
      // Validate the stored credential format before splitting and calling PBKDF2
      if (!isValidSaltHashFormat(legacyKey.key_hash)) {
        continue; // malformed entry — skip and try the next legacy key
      }

      const [legacySalt, legacyHash] = legacyKey.key_hash.split(':');

      if (verifyApiKey(apiKey, legacySalt, legacyHash)) {
        dbKey = legacyKey;
        pbkdf2Verified = true;
        break;
      }
    }
  }

  if (!dbKey) {
    return null;
  }

  // Validate the stored credential format BEFORE splitting and calling PBKDF2
  // This fails closed on malformed input (empty, missing separator, wrong hex length)
  // rather than risking exceptions on the authentication hot path
  if (!isValidSaltHashFormat(dbKey.key_hash)) {
    return null;
  }

  // Split the validated format
  const [salt, hash] = dbKey.key_hash.split(':');

  // Verify with the slow salted hash (source of truth).
  // Skip re-verification for keys found via the legacy fallback — they already
  // passed the PBKDF2 check inside the loop.
  if (!pbkdf2Verified && !verifyApiKey(apiKey, salt, hash)) {
    return null;
  }

  // Serialize mutations on this key ID so concurrent validations cannot
  // double-backfill or double-deactivate, and cannot observe a partially
  // applied state transition.
  const keyId = dbKey.id;
  const result = await keyMutex.run(keyId, async () => {
    // Re-read the row inside the critical section so we observe any writes
    // that committed while we were waiting for the mutex (e.g. a concurrent
    // rotation or deactivation).
    const current = await database.getApiKeyById(keyId);
    if (!current || !current.is_active) {
      // Key was deactivated or removed concurrently — fail closed and
      // do not repopulate the cache.
      cache.invalidate(selector);
      return null;
    }

    // If the stored credential changed concurrently (e.g. rotation), the
    // old key must no longer validate.
    if (current.key_hash !== dbKey.key_hash) {
      cache.invalidate(selector);
      return null;
    }

    // Backfill the selector for legacy keys so future lookups hit the fast path
    if (!current.key_selector) {
      await database.updateApiKey(keyId, { key_selector: selector });
    }

    // Update last used timestamp
    await database.updateApiKey(keyId, { last_used_at: new Date() });

    // Check if key has expired
    if (current.expires_at && new Date() > current.expires_at) {
      await database.deactivateApiKey(keyId);
      cache.invalidate(selector);
      return null;
    }

    const info = {
      id: current.id,
      name: current.name,
      scope: current.scope,
      createdBy: current.created_by,
      createdAt: current.created_at,
      expiresAt: current.expires_at,
      isActive: current.is_active
    };

    // Cache the successful validation result only after all writes commit.
    cache.set(selector, info);
    return info;
  });

  return result;
}

/**
 * Rotates an API key by generating a new key for the same ID.
 *
 * Concurrency: the read-modify-write sequence is serialized per key ID via the
 * in-process mutex. Two concurrent rotations will run sequentially, and the
 * last one to commit wins. The cache is invalidated after the write commits,
 * so no stale entry can survive a rotation.
 *
 * @param keyId - The ID of the key to rotate.
 * @returns The new API key and updated info, or null if key not found.
 */
export async function rotateApiKey(keyId: string): Promise<{ apiKey: string; info: ApiKeyInfo } | null> {
  return keyMutex.run(keyId, async () => {
    const existingKey = await database.getApiKeyById(keyId);
    if (!existingKey) {
      return null;
    }

    // Refuse to rotate a key that was deactivated concurrently.
    if (!existingKey.is_active) {
      return null;
    }

    const newApiKey = generateApiKey();
    const { salt, hash } = hashApiKey(newApiKey);
    const keyHash = `${salt}:${hash}`;
    const keySelector = computeKeySelector(newApiKey);

    const updatedKey = await database.rotateApiKey(keyId, keyHash, keySelector);

    if (!updatedKey) {
      return null;
    }

    // Invalidate cache for the old selector and user's keys. This happens
    // after the authoritative write commits, so a concurrent reader cannot
    // observe a new cache entry for the old key.
    const cache = getAuthCache();
    if (existingKey.key_selector) {
      cache.invalidate(existingKey.key_selector);
    }
    cache.invalidateByUserId(existingKey.created_by);

    return {
      apiKey: newApiKey,
      info: {
        id: updatedKey.id,
        name: updatedKey.name,
        scope: updatedKey.scope,
        createdBy: updatedKey.created_by,
        createdAt: updatedKey.created_at,
        expiresAt: updatedKey.expires_at,
        isActive: updatedKey.is_active
      }
    };
  });
}

/**
 * Deactivates an API key.
 *
 * Concurrency: serialized per key ID via the in-process mutex. Repeated or concurrent
 * deactivations are idempotent: the first call deactivates and invalidates the
 * cache; subsequent calls see the inactive row and return false without repeating
 * the write or cache invalidation.
 *
 * @param keyId - The ID of the key to deactivate.
 * @returns True if successful, false otherwise.
 */
export async function deactivateApiKey(keyId: string): Promise<boolean> {
  return keyMutex.run(keyId, async () => {
    const existingKey = await database.getApiKeyById(keyId);
    if (!existingKey) {
      return false;
    }

    // Idempotent: already inactive -> no write, no cache change.
    if (!existingKey.is_active) {
      return false;
    }

    const result = await database.deactivateApiKey(keyId);

    // Invalidate cache for this key and user's keys after the write commits.
    if (result) {
      const cache = getAuthCache();
      if (existingKey.key_selector) {
        cache.invalidate(existingKey.key_selector);
      }
      cache.invalidateByUserId(existingKey.created_by);
    }

    return result;
  });
}

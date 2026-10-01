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
 */

import * as crypto from 'cypto';
import { ApiKey } from '../database/schema';
import { database } from '../database';
import { AuthCache } from './authCache';
import { validateEnv } from '../config/env.schema';
import { logger } from '../utils/logger';

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
 * Error class for transient API key validation failures.
 *
 * This is thrown when a dependency failure (e.g., database unavailable)
 * prevents us from determining whether a key is valid. Callers must distinguish
 * this from a definitive "null" (rejection) so they can return a retryable
 * 503 rather than a 401.
 */
export class ApiKeyValidationError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'ApiKeyValidationError';
  }
}

/**
 * Result of a single validation attempt.
 */
export interface ApiKeyValidationResult {
  info: ApiKeyInfo | null;
  /** True when the outcome is definitive (valid or rejected). */
  definitive: boolean;
  /** When not definitive, the underlying error that prevented a decision. */
  error?: unknown;
}

/**
 * Attempts to backfill the key selector for a legacy key and update the
 * last-used timestamp. Failures are logged but do not invalidate an
 * otherwise-correct authentication decision. This keeps the auth hot path
 * deterministic even when best-effort bookkeeping writes fail.
 */
async function bestEffortBookkeeping(
  keyId: string,
  selector: string,
  needsSelectorBackfill: boolean,
): Promise<void> {
  try {
    if (needsSelectorBackfill) {
      await database.updateApiKey(keyId, { key_selector: selector });
    }
    await database.updateApiKey(keyId, { last_used_at: new Date() });
  } catch (error) {
    // Bookkeeping must not flip a valid auth decision into a failure.
    // The cache is still populated below so the next request is fast.
    logger.warn('Failed to update API key bookkeeping data', {
      keyId,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

/**
 * Validates an API key and returns the associated key info if valid.
 *
 * This function is deterministic for valid, invalid, duplicate, and
 * boundary-case inputs. It distinguishes between a definitive rejection
 * (`null`) and a transient dependency failure (`ApiKeyValidationError`).
 *
 * Invariants:
 *  - A valid key must pass the salted PBKDF2 verification (source of truth).
 *  - Expired keys are deactivated and rejected deterministically.
 *  - Bookkeeping writes (backfill, last_used_at) are best-effort and cannot
 *    change a decision or cause data loss.
 *  - Transient dependency failures throw `ApiKeyValidationError` so callers
 *    can return a retryable 503 instead of a 401.
 *
 * @param apiKey - The plain API key to validate.
 * @returns The API key info if valid, null if definitively rejected.
 * @throws ApiKeyValidationError on transient dependency failure.
 */
export async function validateApiKey(apiKey: string): Promise<ApiKeyInfo | null> {
  const result = await validateApiKeyWithResult(apiKey);
  if (!result.definitive) {
    throw new ApiKeyValidationError('API key validation failed due to a transient dependency error', result.error);
  }
  return result.info;
}

/**
 * Validates an API key and returns a discriminated result without throwing.
 *
 * Preferred for callers that need to distinguish between a definitive
 * rejection and a transient dependency failure (e.g., to return 401 vs
 * 503).
 *
 * @param apiKey - The plain API key to validate.
 * @returns A result object with `info`, `definitive`, and optional `error`.
 */
export async function validateApiKeyWithResult(apiKey: string): Promise<ApiKeyValidationResult> {
  // Defensive input validation - never touch the database for non-strings.
  if (typeof apiKey !== 'string' || apiKey.length === 0) {
    return { info: null, definitive: true };
  }

  // Compute the deterministic selector for O(1) indexed lookup
  const selector = computeKeySelector(apiKey);

  // Check cache first
  const cache = getAuthCache();
  const cached = cache.get(selector);
  if (cached) {
    return { info: cached, definitive: true };
  }

  // Try indexed lookup first (fast path, O(1) via key_selector)
  let dbKey: ApiKey | undefined;
  try {
    dbKey = await database.getApiKeyBySelector(selector);
  } catch (error) {
    logger.error('API key selector lookup failed', {
      error: error instanceof Error ? error.message : String(error),
    });
    return { info: null, definitive: false, error };
  }

  let pbkdf2Verified = false; // tracks whether the salted hash has already been verified

  // Fallback: scan legacy keys that predate the key_selector index.
  // Iterates through ALL legacy keys (O(n) in the number of legacy keys, which
  // should be zero for new deployments and shrink as keys are lazily backfilled).
  if (!dbKey) {
    let legacyKeys: ApiKey[];
    try {
      const db = await (database as any).loadDatabase();
      legacyKeys = db.api_keys.filter(
        (k: ApiKey) => !k.key_selector && k.is_active
      );
    } catch (error) {
      logger.error('API key legacy fallback load failed', {
        error: error instanceof Error ? error.message : String(error),
      });
      return { info: null, definitive: false, error };
    }

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
    return { info: null, definitive: true };
  }

  // Validate the stored credential format BEFORE dividing and calling PBKDF2
  // This fails closed on malformed input (empty, missing separator, wrong hex length)
  // rather than risking exceptions on the authentication hot path
  if (!isValidSaltHashFormat(dbKey.key_hash)) {
    logger.warn('Rejected API key with malformed stored credential', { keyId: dbKey.id });
    return { info: null, definitive: true };
  }

  // Split the validated format
  const [salt, hash] = dbKey.key_hash.split(':');

  // Verify with the slow salted hash (source of truth).
  // Skip re-verification for keys found via the legacy fallback — they already
  // passed the PBKDF2 check inside the loop.
  if (!pbkdf2Verified && !verifyApiKey(apiKey, salt, hash)) {
    return { info: null, definitive: true };
  }

  // Check if key has expired. Expiration is a definitive rejection.
  // Deactivation is best-effort so a transient write failure does not make
  // the auth decision non-deterministic.
  if (dbKey.expires_at && new Date() > dbKey.expires_at) {
    try {
      await database.deactivateApiKey(dbKey.id);
    } catch (error) {
      logger.warn('Failed to deactivate expired API key', {
        keyId: dbKey.id,
        error: error instanceof Error ? error.message : String(error),
      });
    }
    // Ensure the cache does not serve the expired key.
    cache.invalidate(selector);
    return { info: null, definitive: true };
  }

  // Best-effort bookkeeping: backfill selector for legacy keys and update
  // last-used timestamp. Failures are logged and do not affect the decision.
  await bestEffortBookkeeping(dbKey.id, selector, !dbKey.key_selector);

  const info = {
    id: dbKey.id,
    name: dbKey.name,
    scope: dbKey.scope,
    createdBy: dbKey.created_by,
    createdAt: dbKey.created_at,
    expiresAt: dbKey.expires_at,
    isActive: dbKey.is_active
  };

  // Cache the successful validation result
  cache.set(selector, info);

  return { info, definitive: true };
}

/**
 * Rotates an API key by generating a new key for the same ID.
 *
 * @param keyId - The ID of the key to rotate.
 * @returns The new API key and updated info, or null if key not found.
 */
export async function rotateApiKey(keyId: string): Promise<{ apiKey: string; info: ApiKeyInfo } | null> {
  const existingKey = await database.getApiKeyById(keyId);
  if (!existingKey) {
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

  // Invalidate cache for the old selector and user's keys
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
}

/**
 * Deactivates an API key.
 *
 * @param keyId - The ID of the key to deactivate.
 * @returns True if successful, false otherwise.
 */
export async function deactivateApiKey(keyId: string): Promise<boolean> {
  const existingKey = await database.getApiKeyById(keyId);
  if (!existingKey) {
    return false;
  }

  const result = await database.deactivateApiKey(keyId);

  // Invalidate cache for this key and user's keys
  if (result) {
    const cache = getAuthCache();
    if (existingKey.key_selector) {
      cache.invalidate(existingKey.key_selector);
    }
    cache.invalidateByUserId(existingKey.created_by);
  }

  return result;
}

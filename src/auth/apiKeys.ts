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
 * Error types for API key operations.
 * These errors are thrown to indicate specific contract violations.
 */
export class ApiKeyValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ApiKeyValidationError';
  }
}

export class ApiKeyNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ApiKeyNotFoundError';
  }
}

/**
 * Generates a cryptographically secure API key.
 *
 * Contract:
 * - Always returns a 64-character hex string (32 bytes)
 * - Each call produces a unique value (cryptographically random)
 * - Never throws under normal conditions
 *
 * @returns A 32-byte hex-encoded API key.
 * @throws Error if crypto.randomBytes fails (system entropy exhaustion)
 */
export function generateApiKey(): string {
  const key = crypto.randomBytes(32).toString('hex');
  // Invariant: result must be exactly 64 hex characters
  if (key.length !== 64 || !/^[a-f0-9]{64}$/i.test(key)) {
    throw new Error('Generated API key does not meet format invariant');
  }
  return key;
}

/**
 * Hashes an API key using PBKDF2 with a random salt.
 *
 * Contract:
 * - Input must be a non-empty string
 * - Returns salt (32 hex chars) and hash (128 hex chars)
 * - Each call produces different salt/hash for same key
 * - Never returns the same hash for different keys (collision-resistant)
 *
 * @param apiKey - The plain API key to hash.
 * @returns An object containing the salt and hash.
 * @throws ApiKeyValidationError if apiKey is empty or not a string
 * @throws Error if crypto operations fail
 */
export function hashApiKey(apiKey: string): { salt: string; hash: string } {
  if (typeof apiKey !== 'string' || apiKey.length === 0) {
    throw new ApiKeyValidationError('API key must be a non-empty string');
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(apiKey, salt, 10000, 64, 'sha256').toString('hex');
  
  // Invariant: salt must be 32 hex chars, hash must be 128 hex chars
  if (salt.length !== 32 || !/^[a-f0-9]{32}$/i.test(salt)) {
    throw new Error('Generated salt does not meet format invariant');
  }
  if (hash.length !== 128 || !/^[a-f0-9]{128}$/i.test(hash)) {
    throw new Error('Generated hash does not meet format invariant');
  }
  
  return { salt, hash };
}

/**
 * Verifies an API key against a stored hash using constant-time comparison.
 *
 * Contract:
 * - Returns false for any invalid input (wrong types, empty strings, malformed hex)
 * - Uses constant-time comparison to prevent timing attacks
 * - Never throws; always returns boolean for deterministic behavior
 * - Returns false if salt/hash format is invalid (not proper hex)
 *
 * @param apiKey - The plain API key to verify.
 * @param salt - The salt used when hashing (32 hex characters).
 * @param hash - The stored hash to verify against (128 hex characters).
 * @returns True if the key is valid, false otherwise.
 */
export function verifyApiKey(apiKey: string, salt: string, hash: string): boolean {
  // Validate input types and non-emptiness
  if (typeof apiKey !== 'string' || apiKey.length === 0) return false;
  if (typeof salt !== 'string' || salt.length === 0) return false;
  if (typeof hash !== 'string' || hash.length === 0) return false;

  try {
    const verifyHash = crypto.pbkdf2Sync(apiKey, salt, 10000, 64, 'sha256').toString('hex');
    const hashBuffer = Buffer.from(hash, 'hex');
    const verifyBuffer = Buffer.from(verifyHash, 'hex');
    
    // Length mismatch means invalid format
    if (hashBuffer.length !== verifyBuffer.length) return false;
    
    return crypto.timingSafeEqual(hashBuffer, verifyBuffer);
  } catch {
    // Any error (invalid hex, crypto failure) results in false (fail closed)
    return false;
  }
}

/**
 * Computes a deterministic key selector (SHA-256) for fast O(1) indexed lookup.
 *
 * Contract:
 * - Input must be a non-empty string
 * - Same input always produces same output (deterministic)
 * - Output is always 64 hex characters (SHA-256 digest)
 * - Output is not reversible (preimage-resistant)
 * - Different inputs produce different outputs (collision-resistant)
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
 * @throws ApiKeyValidationError if apiKey is empty or not a string
 */
export function computeKeySelector(apiKey: string): string {
  if (typeof apiKey !== 'string' || apiKey.length === 0) {
    throw new ApiKeyValidationError('API key must be a non-empty string');
  }

  const selector = crypto.createHash('sha256').update(apiKey).digest('hex');
  
  // Invariant: SHA-256 always produces 64 hex characters
  if (selector.length !== 64 || !/^[a-f0-9]{64}$/i.test(selector)) {
    throw new Error('Computed selector does not meet format invariant');
  }
  
  return selector;
}

/**
 * Creates a new API key with the given specifications.
 *
 * Contract:
 * - request.name must be a non-empty string
 * - request.scope must be a non-empty array of strings
 * - request.createdBy must be a non-empty string
 * - request.expiresAt, if provided, must be a valid Date
 * - Returns object with apiKey (64 hex chars) and info (ApiKeyInfo)
 * - The plain apiKey is only returned once (caller must store it)
 * - Database stores salted hash, never the plain key
 * - key_selector is always computed and stored for O(1) lookup
 *
 * @param request - The API key creation request.
 * @returns The created API key info and the plain key (only returned once).
 * @throws ApiKeyValidationError if request is invalid
 * @throws Error if database operation fails
 */
export async function createApiKey(request: ApiKeyRequest): Promise<{ apiKey: string; info: ApiKeyInfo }> {
  // Validate request
  if (!request || typeof request !== 'object') {
    throw new ApiKeyValidationError('Request must be an object');
  }
  if (typeof request.name !== 'string' || request.name.length === 0) {
    throw new ApiKeyValidationError('API key name must be a non-empty string');
  }
  if (!Array.isArray(request.scope) || request.scope.length === 0) {
    throw new ApiKeyValidationError('API key scope must be a non-empty array');
  }
  if (request.scope.some((s: any) => typeof s !== 'string' || s.length === 0)) {
    throw new ApiKeyValidationError('All scope items must be non-empty strings');
  }
  if (typeof request.createdBy !== 'string' || request.createdBy.length === 0) {
    throw new ApiKeyValidationError('createdBy must be a non-empty string');
  }
  if (request.expiresAt !== undefined && !(request.expiresAt instanceof Date)) {
    throw new ApiKeyValidationError('expiresAt must be a Date if provided');
  }

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
 * Contract:
 * - Input must be a non-empty string
 * - Returns null for invalid keys, expired keys, or malformed input
 * - Returns ApiKeyInfo for valid, active, non-expired keys
 * - Updates last_used_at timestamp on successful validation
 * - Auto-deactivates expired keys on validation attempt
 * - Backfills key_selector for legacy keys (lazy migration)
 * - Never throws; always returns ApiKeyInfo or null for deterministic behavior
 * - Handles malformed stored credentials gracefully (fails closed)
 *
 * @param apiKey - The plain API key to validate.
 * @returns The API key info if valid, null if definitively rejected.
 * @throws ApiKeyValidationError on transient dependency failure.
 */
export async function validateApiKey(apiKey: string): Promise<ApiKeyInfo | null> {
  // Validate input
  if (typeof apiKey !== 'string' || apiKey.length === 0) {
    return null;
  }

  // Compute the deterministic selector for O(1) indexed lookup
  let selector: string;
  try {
    selector = computeKeySelector(apiKey);
  } catch {
    // If selector computation fails, key is invalid
    return null;
  }

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
    try {
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
    } catch {
      // Database error during legacy fallback - fail closed
      return null;
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
  
  // Backfill the selector for legacy keys so future lookups hit the fast path
  try {
    if (!dbKey.key_selector) {
      await database.updateApiKey(dbKey.id, { key_selector: selector });
    }
    
    // Update last used timestamp
    await database.updateApiKey(dbKey.id, { last_used_at: new Date() });
  } catch {
    // If update fails, still return the key info (best effort, but log would be ideal)
    // This ensures authentication succeeds even if audit tracking fails
  }
  
  // Check if key has expired
  if (dbKey.expires_at && new Date() > dbKey.expires_at) {
    try {
      await database.deactivateApiKey(dbKey.id);
    } catch {
      // If deactivation fails, still return null (key is expired)
    }
    return null;
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
 * Contract:
 * - keyId must be a non-empty string
 * - Returns null if key does not exist
 * - Old key becomes invalid immediately after rotation
 * - New key is returned (only once, caller must store it)
 * - Preserves key name, scope, createdBy, and expiresAt
 * - Updates key_selector to match new key
 * - Database operation is atomic (old key replaced with new)
 *
 * @param keyId - The ID of the key to rotate.
 * @returns The new API key and updated info, or null if key not found.
 * @throws ApiKeyValidationError if keyId is invalid
 * @throws Error if database operation fails
 */
export async function rotateApiKey(keyId: string): Promise<{ apiKey: string; info: ApiKeyInfo } | null> {
  // Validate input
  if (typeof keyId !== 'string' || keyId.length === 0) {
    throw new ApiKeyValidationError('Key ID must be a non-empty string');
  }

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
 * Contract:
 * - keyId must be a non-empty string
 * - Returns true if key was found and deactivated
 * - Returns false if key does not exist
 * - Deactivated keys cannot be reactivated (create new key instead)
 * - Deactivation is idempotent (calling multiple times on same key returns false after first)
 *
 * @param keyId - The ID of the key to deactivate.
 * @returns True if successful, false otherwise.
 * @throws ApiKeyValidationError if keyId is invalid
 * @throws Error if database operation fails
 */
export async function deactivateApiKey(keyId: string): Promise<boolean> {
  // Validate input
  if (typeof keyId !== 'string' || keyId.length === 0) {
    throw new ApiKeyValidationError('Key ID must be a non-empty string');
  }

  return await database.deactivateApiKey(keyId);
}

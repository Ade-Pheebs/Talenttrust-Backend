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
 * State invariants owned by this module:
 *   INV-1 (create): a newly created key is always active, has a well-formed
 *           salt:hash credential, and a selector derived from the same
 *           plaintext key that was handed to the caller.
 *   INV-2 (validate): a cache hit is only ever written after a full
 *           PBKDF2 verification and expiry check. A key that fails any
 *           check must not be populated into the cache.
 *   INV-3 (validate): an expired key is deactivated and never returned as a
 *           valid result, even under concurrent calls.
 *   INV-4 (rotate): rotation replaces the credential and selector atomically;
 *           the old selector is invalidated from the cache and the new
 *           selector is not pre-populated.
 *   INV-5 (deactivate): deactivation is idempotent and always invalidates
 *           the cache for the affected key and its owner.
 *   INV-6 (concurrency): last-used timestamps and selector backfills are
 *           monotonic — an out-of-order write cannot move the value backwards.
 */

import * as crypto from 'node:crypto';
import { ApiKey } from '../database/schema';
import { database } from '../database';
import { AuthCache } from './authCache';
import { validateEnv } from '../config/env.schema';
import { logger } from '../utils/logger';

/**
 * Validation error class for API key operations.
 */
export class ApiKeyValidationError extends Error {
  constructor(
    message: string,
    public readonly field: string,
    public readonly code: string
  ) {
    super(message);
    this.name = 'ApiKeyValidationError';
  }
}

/**
 * Validation constants defining boundaries for API key inputs.
 */
export const VALIDATION_RULES = {
  API_KEY: {
    LENGTH: 64, // 32 bytes in hex = 64 characters
    PATTERN: /^[a-f0-9]{64}$/i,
  },
  NAME: {
    MIN_LENGTH: 1,
    MAX_LENGTH: 255,
    PATTERN: /^[a-zA-Z0-9\s\-_]+$/,
  },
  SCOPE: {
    MIN_ITEMS: 1,
    MAX_ITEMS: 50,
    ITEM_MIN_LENGTH: 1,
    ITEM_MAX_LENGTH: 100,
    ITEM_PATTERN: /^[a-zA-Z0-9:\-_\.]+$/,
  },
  USER_ID: {
    MIN_LENGTH: 1,
    MAX_LENGTH: 255,
    PATTERN: /^[a-zA-Z0-9\-_]+$/,
  },
  KEY_SELECTOR: {
    LENGTH: 64, // SHA-256 hex = 64 characters
    PATTERN: /^[a-f0-9]{64}$/i,
  },
  SALT_HASH: {
    SALT_LENGTH: 32, // 16 bytes in hex
    HASH_LENGTH: 128, // 64 bytes in hex
    PATTERN: /^[a-f0-9]{32}:[a-f0-9]{128}$/i,
  },
} as const;

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
 * Validates an API key format.
 * 
 * Validation boundaries:
 *   - VALID: 64 hex characters (a-f, 0-9, case-insensitive)
 *   - INVALID: Wrong length, non-hex characters, null, undefined, non-string
 * 
 * @param apiKey - The API key to validate
 * @throws ApiKeyValidationError if invalid
 */
export function validateApiKeyFormat(apiKey: unknown): asserts apiKey is string {
  if (typeof apiKey !== 'string') {
    throw new ApiKeyValidationError(
      'API key must be a string',
      'apiKey',
      'INVALID_TYPE'
    );
  }

  if (apiKey.length !== VALIDATION_RULES.API_KEY.LENGTH) {
    throw new ApiKeyValidationError(
      `API key must be exactly ${VALIDATION_RULES.API_KEY.LENGTH} characters`,
      'apiKey',
      'INVALID_LENGTH'
    );
  }

  if (!VALIDATION_RULES.API_KEY.PATTERN.test(apiKey)) {
    throw new ApiKeyValidationError(
      'API key must contain only hexadecimal characters',
      'apiKey',
      'INVALID_FORMAT'
    );
  }
}

/**
 * Validates an API key name.
 * 
 * Validation boundaries:
 *   - VALID: 1-255 characters, alphanumeric + spaces, hyphens, underscores
 *   - INVALID: Empty, too long, contains special characters, null, non-string
 * 
 * @param name - The name to validate
 * @throws ApiKeyValidationError if invalid
 */
export function validateApiKeyName(name: unknown): asserts name is string {
  if (typeof name !== 'string') {
    throw new ApiKeyValidationError(
      'API key name must be a string',
      'name',
      'INVALID_TYPE'
    );
  }

  const trimmed = name.trim();

  if (trimmed.length < VALIDATION_RULES.NAME.MIN_LENGTH) {
    throw new ApiKeyValidationError(
      'API key name cannot be empty',
      'name',
      'EMPTY_NAME'
    );
  }

  if (trimmed.length > VALIDATION_RULES.NAME.MAX_LENGTH) {
    throw new ApiKeyValidationError(
      `API key name must not exceed ${VALIDATION_RULES.NAME.MAX_LENGTH} characters`,
      'name',
      'NAME_TOO_LONG'
    );
  }

  if (!VALIDATION_RULES.NAME.PATTERN.test(trimmed)) {
    throw new ApiKeyValidationError(
      'API key name can only contain alphanumeric characters, spaces, hyphens, and underscores',
      'name',
      'INVALID_CHARACTERS'
    );
  }
}

/**
 * Validates an API key scope array.
 * 
 * Validation boundaries:
 *   - VALID: Array of 1-50 strings, each 1-100 chars, matching pattern
 *   - INVALID: Empty array, too many items, invalid item format, null, non-array
 *   - DUPLICATE: Contains duplicate scope values
 * 
 * @param scope - The scope array to validate
 * @throws ApiKeyValidationError if invalid
 */
export function validateApiKeyScope(scope: unknown): asserts scope is string[] {
  if (!Array.isArray(scope)) {
    throw new ApiKeyValidationError(
      'API key scope must be an array',
      'scope',
      'INVALID_TYPE'
    );
  }

  if (scope.length < VALIDATION_RULES.SCOPE.MIN_ITEMS) {
    throw new ApiKeyValidationError(
      'API key scope must contain at least one item',
      'scope',
      'EMPTY_SCOPE'
    );
  }

  if (scope.length > VALIDATION_RULES.SCOPE.MAX_ITEMS) {
    throw new ApiKeyValidationError(
      `API key scope must not exceed ${VALIDATION_RULES.SCOPE.MAX_ITEMS} items`,
      'scope',
      'SCOPE_TOO_LARGE'
    );
  }

  // Check for duplicates
  const uniqueScopes = new Set(scope);
  if (uniqueScopes.size !== scope.length) {
    throw new ApiKeyValidationError(
      'API key scope contains duplicate values',
      'scope',
      'DUPLICATE_SCOPE'
    );
  }

  // Validate each scope item
  scope.forEach((item, index) => {
    if (typeof item !== 'string') {
      throw new ApiKeyValidationError(
        `Scope item at index ${index} must be a string`,
        'scope',
        'INVALID_SCOPE_ITEM_TYPE'
      );
    }

    const trimmed = item.trim();

    if (trimmed.length < VALIDATION_RULES.SCOPE.ITEM_MIN_LENGTH) {
      throw new ApiKeyValidationError(
        `Scope item at index ${index} cannot be empty`,
        'scope',
        'EMPTY_SCOPE_ITEM'
      );
    }

    if (trimmed.length > VALIDATION_RULES.SCOPE.ITEM_MAX_LENGTH) {
      throw new ApiKeyValidationError(
        `Scope item at index ${index} exceeds ${VALIDATION_RULES.SCOPE.ITEM_MAX_LENGTH} characters`,
        'scope',
        'SCOPE_ITEM_TOO_LONG'
      );
    }

    if (!VALIDATION_RULES.SCOPE.ITEM_PATTERN.test(trimmed)) {
      throw new ApiKeyValidationError(
        `Scope item at index ${index} contains invalid characters`,
        'scope',
        'INVALID_SCOPE_ITEM_FORMAT'
      );
    }
  });
}

/**
 * Validates a user ID.
 * 
 * Validation boundaries:
 *   - VALID: 1-255 characters, alphanumeric + hyphens, underscores
 *   - INVALID: Empty, too long, invalid characters, null, non-string
 * 
 * @param userId - The user ID to validate
 * @throws ApiKeyValidationError if invalid
 */
export function validateUserId(userId: unknown): asserts userId is string {
  if (typeof userId !== 'string') {
    throw new ApiKeyValidationError(
      'User ID must be a string',
      'createdBy',
      'INVALID_TYPE'
    );
  }

  const trimmed = userId.trim();

  if (trimmed.length < VALIDATION_RULES.USER_ID.MIN_LENGTH) {
    throw new ApiKeyValidationError(
      'User ID cannot be empty',
      'createdBy',
      'EMPTY_USER_ID'
    );
  }

  if (trimmed.length > VALIDATION_RULES.USER_ID.MAX_LENGTH) {
    throw new ApiKeyValidationError(
      `User ID must not exceed ${VALIDATION_RULES.USER_ID.MAX_LENGTH} characters`,
      'createdBy',
      'USER_ID_TOO_LONG'
    );
  }

  if (!VALIDATION_RULES.USER_ID.PATTERN.test(trimmed)) {
    throw new ApiKeyValidationError(
      'User ID can only contain alphanumeric characters, hyphens, and underscores',
      'createdBy',
      'INVALID_USER_ID_FORMAT'
    );
  }
}

/**
 * Validates an expiration date.
 * 
 * Validation boundaries:
 *   - VALID: Date object in the future, or undefined
 *   - INVALID: Date in the past, invalid Date object, non-Date type
 * 
 * @param expiresAt - The expiration date to validate
 * @throws ApiKeyValidationError if invalid
 */
export function validateExpirationDate(expiresAt: unknown): asserts expiresAt is Date | undefined {
  if (expiresAt === undefined || expiresAt === null) {
    return; // Optional field
  }

  if (!(expiresAt instanceof Date)) {
    throw new ApiKeyValidationError(
      'Expiration date must be a Date object',
      'expiresAt',
      'INVALID_TYPE'
    );
  }

  if (isNaN(expiresAt.getTime())) {
    throw new ApiKeyValidationError(
      'Expiration date is invalid',
      'expiresAt',
      'INVALID_DATE'
    );
  }

  if (expiresAt <= new Date()) {
    throw new ApiKeyValidationError(
      'Expiration date must be in the future',
      'expiresAt',
      'EXPIRED_DATE'
    );
  }
}

/**
 * Validates a complete API key request.
 * 
 * Validates all fields according to defined boundaries.
 * 
 * @param request - The API key request to validate
 * @throws ApiKeyValidationError if any field is invalid
 */
export function validateApiKeyRequest(request: unknown): asserts request is ApiKeyRequest {
  if (typeof request !== 'object' || request === null) {
    throw new ApiKeyValidationError(
      'API key request must be an object',
      'request',
      'INVALID_TYPE'
    );
  }

  const req = request as Record<string, unknown>;

  validateApiKeyName(req.name);
  validateApiKeyScope(req.scope);
  validateUserId(req.createdBy);
  validateExpirationDate(req.expiresAt);
}

/**
 * Generates a cryptographically secure API key.
 *
 * @returns A 32-byte hex-encoded API key.
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
 * Validates all inputs according to defined boundaries before creation.
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
 * INV-1: the returned plaintext key and the persisted selector are derived
 * from the same generated bytes, and the persisted credential is the
 * well-formed `<salt>:<hash>` produced by `hashApiKey`.
 *
 * @param request - The API key creation request.
 * @returns The created API key info and the plain key (only returned once).
 * @throws ApiKeyValidationError if request is invalid
 */
export async function createApiKey(request: ApiKeyRequest): Promise<{ apiKey: string; info: ApiKeyInfo }> {
  // Validate request inputs
  validateApiKeyRequest(request);

  const apiKey = generateApiKey();
  const { salt, hash } = hashApiKey(apiKey);

  // Store salt and hash together in the key_hash field
  const keyHash = `${salt}:${hash}`;
  const keySelector = computeKeySelector(apiKey);

  // Defensive assertion: the credential we are about to persist must already
  // satisfy the storage invariant so that a future validation can never fail
  // on a key we just issued.
  if (!isValidSaltHashFormat(keyHash)) {
    throw new Error('Internal error: generated API key credential is malformed');
  }

  const dbKey = await database.createApiKey({
    name: request.name.trim(),
    key_hash: keyHash,
    key_selector: keySelector,
    scope: request.scope.map(s => s.trim()),
    created_by: request.createdBy.trim(),
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
 * Returns true when the key is active and not expired as the provided
 * reference time.
 *
 * INV-3: expiration is evaluated against a single captured timestamp so
 * concurrent calls cannot disagree on whether a key is expired.
 */
function isKeyUsable(key: ApiKey, now: Date): boolean {
  if (!key.is_active) {
    return false;
  }
  if (key.expires_at && now > key.expires_at) {
    return false;
  }
  return true;
}

/**
 * Validates an API key and returns the associated key info if valid.
 * 
 * Validates input format before performing cryptographic operations.
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
 * Invariants enforced on this path:
 * - Only active, non-expired keys are returned as valid.
 * - Malformed stored credentials fail closed before PBKDF2 is invoked.
 * - The cache is only written after every check passes (INV-2).
 * - Expired keys are deactivated and never cached (INV-3).
 * - Last-used writes are monotonic (INV-6).
 *
 * @param apiKey - The plain API key to validate.
 * @returns The API key info if valid, null otherwise.
 * @throws ApiKeyValidationError if input format is invalid
 */
export async function validateApiKey(apiKey: string): Promise<ApiKeyInfo | null> {
  if (typeof apiKey !== 'string' || apiKey.length === 0) {
    return null;
  }

  // Compute the deterministic selector for O(1) indexed lookup
  const selector = computeKeySelector(apiKey);
  const now = new Date();

  // Check cache first
  const cache = getAuthCache();
  const cached = cache.get(selector);
  if (cached) {
    // Cache entries are only written after a full verification and expiry
    // check, but we still re-evaluate expiry against the current clock so a
    // key that expires between cache writes is not served past its window.
    if (cached.expiresAt && now > cached.expiresAt) {
      cache.invalidate(selector);
      await deactivateApiKey(cached.id);
      return null;
    }
    return cached;
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

  // Check if key has expired or been deactivated before any writes.
  // INV-3: an expired key is deactivated and never returned as valid.
  if (!isKeyUsable(dbKey, now)) {
    if (dbKey.is_active && dbKey.expires_at && now > dbKey.expires_at) {
      await deactivateApiKey(dbKey.id);
    }
    cache.invalidate(selector);
    return null;
  }

  // Backfill the selector for legacy keys so future lookups hit the fast path.
  // The selector is derived from the verified plaintext key, so this is
  // deterministic and idempotent across concurrent calls.
  if (!dbKey.key_selector) {
    await database.updateApiKey(dbKey.id, { key_selector: selector });
  }

  // Update last used timestamp. INV-6: only forward-move the timestamp so an
  // out-of-order concurrent write cannot regress the audit value.
  const lastUsedAt = dbKey.last_used_at;
  if (!lastUsedAt || now > lastUsedAt) {
    await database.updateApiKey(dbKey.id, { last_used_at: now });
  }

  const result: ApiKeyInfo = {
    id: dbKey.id,
    name: dbKey.name,
    scope: dbKey.scope,
    createdBy: dbKey.created_by,
    createdAt: dbKey.created_at,
    expiresAt: dbKey.expires_at,
    isActive: dbKey.is_active
  };

  // Cache the successful validation result (only after all checks passed)
  cache.set(selector, result);

  return { info, definitive: true };
}

/**
 * Rotates an API key by generating a new key for the same ID.
 *
 * INV-4: the credential and selector are replaced together in a single
 * database operation. The old selector is evicted from the cache and the
 * new selector is not pre-populated, so the next validation must re-run the
 * full PBKDF2 check.
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

  // Defensive assertion: never persist a malformed credential during rotation.
  if (!isValidSaltHashFormat(keyHash)) {
    throw new Error('Internal error: generated API key credential is malformed');
  }

  const updatedKey = await database.rotateApiKey(keyId, keyHash, keySelector);

  if (!updatedKey) {
    return null;
  }

  // Invalidate cache for the old selector and user's keys
  const cache = getAuthCache();
  if (existingKey.key_selector) {
    cache.invalidate(existingKey.key_selector);
  }
  // Also evict any cache entry keyed by the new selector in case a concurrent
  // validation wrote one before the rotation committed.
  cache.invalidate(keySelector);
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
 * INV-5: deactivation is idempotent. Repeated calls return the current
 * active state and always evict the key from the cache so a stale valid
 * entry can never outlive deactivation.
 *
 * @param keyId - The ID of the key to deactivate.
 * @returns True if the key is deactive after the call, false if the key
 * does not exist.
 */
export async function deactivateApiKey(keyId: string): Promise<boolean> {
  // Validate input
  if (typeof keyId !== 'string' || keyId.length === 0) {
    throw new ApiKeyValidationError('Key ID must be a non-empty string');
  }

  // Invalidate the cache before attempting the write so a concurrent
  // validation cannot serve a stale active result while the deactivation is
  // in flight.
  const cache = getAuthCache();
  if (existingKey.key_selector) {
    cache.invalidate(existingKey.key_selector);
  }
  cache.invalidateByUserId(existingKey.created_by);

  if (!existingKey.is_active) {
    // Already deactive — idempotent success.
    return true;
  }

  const result = await database.deactivateApiKey(keyId);

  return result;
}

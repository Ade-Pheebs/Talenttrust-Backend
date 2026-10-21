/**
 * @module auth/scopedApiKeyMiddleware
 * @description Config-based scoped API key authentication middleware.
 *
 * This module provides middleware for authenticating requests using API keys
 * loaded from the `API_KEYS` environment variable (via {@link parseApiKeysConfig}).
 * Keys are SHA-256 hashed and compared with constant-time comparison.
 *
 * Two middlewares are exported:
 * - `authenticateScopedApiKey` — extracts and validates the key, sets `req.scopedApiKey`.
 * - `requireScope(scope)` — checks that the authenticated key has a specific scope.
 *
 * Usage:
 * ```ts
 * router.post('/contracts/:id/resolve',
 *   authenticateScopedApiKey(apiKeys),
 *   requireScope(SCOPES.DISPUTES_RESOLVE),
 *   handler);
 * ```
 */

import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';
import type { ParsedApiKeys } from '../config/apiKeysConfig';
import { sha256Hex } from '../config/apiKeysConfig';

/**
 * Request augmented with scoped API key info after successful authentication.
 */
export interface ScopedApiKeyRequest extends Request {
  scopedApiKey?: {
    id: string;
    scopes: string[];
  };
}

/**
 * Extract the raw API key from request headers.
 *
 * Accepted formats:
 * 1. `X-API-Key: <key>`
 * 2. `Authorization: ApiKey <key>`
 *
 * Returns `null` when no key is found or the header is malformed.
 */
export function extractApiKeyFromHeaders(
  headers: Record<string, string | string[] | undefined>,
): string | null {
  // 1. X-API-Key header
  const xApiKey = headers['x-api-key'];
  if (typeof xApiKey === 'string' && xApiKey.trim() !== '') {
    return xApiKey.trim();
  }

  // 2. Authorization: ApiKey <key>
  const auth = headers['authorization'];
  if (typeof auth === 'string') {
    const parts = auth.trim().split(/\s+/);
    if (parts.length === 2 && parts[0].toLowerCase() === 'apikey') {
      const key = parts[1];
      if (key.length > 0) return key;
    }
  }

  return null;
}

/**
 * Constant-time comparison of two hex digests.
 *
 * Both buffers must be the same length (SHA-256 hex = 64 chars).
 * Returns `false` if lengths differ — `timingSafeEqual` would throw otherwise.
 */
function safeCompareHex(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Factory: returns middleware that authenticates a request using a scoped API key.
 *
 * On success, sets `req.scopedApiKey = { id, scopes }` and calls `next()`.
 * On failure, responds with 401 and does NOT call `next()`.
 *
 * @param apiKeys - The parsed API key store from `parseApiKeysConfig()`.
 */
export function authenticateScopedApiKey(apiKeys: ParsedApiKeys) {
  return (req: ScopedApiKeyRequest, res: Response, next: NextFunction): void => {
    const rawKey = extractApiKeyFromHeaders(req.headers as Record<string, string | string[] | undefined>);

    if (!rawKey) {
      res.status(401).json({
        error: {
          code: 'unauthorized',
          message: 'API key required. Provide X-API-Key or Authorization: ApiKey <key>.',
        },
      });
      return;
    }

    // Hash the incoming key and look it up
    const incomingDigest = sha256Hex(rawKey);

    // Iterate through all keys and compare with constant-time comparison.
    // Even though we use a Map for O(1) lookup, we compare every key's digest
    // to avoid leaking which key id was guessed (timing side-channel).
    let matched: { id: string; scopes: string[] } | null = null;
    let foundMatch = false;

    for (const [storedDigest, entry] of apiKeys.byDigest) {
      const isMatch = safeCompareHex(incomingDigest, storedDigest);
      if (isMatch && !foundMatch) {
        matched = { id: entry.id, scopes: entry.scopes };
        foundMatch = true;
        // Continue iterating to keep timing uniform (don't break early)
      }
    }

    if (!matched) {
      res.status(401).json({
        error: {
          code: 'unauthorized',
          message: 'Invalid API key.',
        },
      });
      return;
    }

    req.scopedApiKey = matched;
    next();
  };
}

/**
 * Factory: returns middleware that enforces a specific scope on an authenticated key.
 *
 * - 401 `unauthorized` when no key is present (caller skipped `authenticateScopedApiKey`).
 * - 403 `insufficient_scope` when the key lacks the required scope. The response
 *   body includes `required: <scope>` so the caller knows what is needed.
 *
 * @param scope - The required scope string (e.g. `'disputes:resolve'`).
 */
export function requireScope(scope: string) {
  return (req: ScopedApiKeyRequest, res: Response, next: NextFunction): void => {
    if (!req.scopedApiKey) {
      res.status(401).json({
        error: {
          code: 'unauthorized',
          message: 'Authentication with a scoped API key is required.',
        },
      });
      return;
    }

    if (!req.scopedApiKey.scopes.includes(scope)) {
      res.status(403).json({
        error: {
          code: 'insufficient_scope',
          message: `The API key does not have the required scope: ${scope}`,
          required: scope,
        },
      });
      return;
    }

    next();
  };
}

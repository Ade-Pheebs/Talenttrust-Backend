/**
 * @module apiKeyMiddleware
 * @description Express middleware for API key authentication.
 *
 * Provides middleware for authenticating requests using API keys.
 * API keys should be provided in the `X-API-Key` header.
 *
 * Usage:
 *   app.get('/api/v1/internal', authenticateApiKey, requireApiKeyScope('contracts', 'read'), handler);
 *
 * Security notes:
 *   - Validates API key against stored hash
 *   - Updates last used timestamp for audit purposes
 *   - Checks for expired keys
 *   - Responds with 401 for missing/invalid keys
 *   - Responds with 403 for insufficient scope
 *
 * Concurrency invariants:
 *   - A single request is authenticated at most once; concurrent or repeated
 *     calls for the same request object are deduplicated via an in-flight promise
 *     so the downstream handler and the `lastUsedAt-updating validation are
 *     not invoked more than once for the same request.
 *   - Once `req.apiKey` is set for a request, it is never overwritten by a
 *     subsequent middleware invocation on the same request (idempotent).
 *   - Concurrent requests with different request objects remain isolated.
 */

import { Request, Response, NextFunction } from 'express';
import { validateApiKey, ApiKeyInfo } from './apiKeys';
import { authenticateMiddleware } from './authenticate';

/** Express request extended with API key info. */
export interface ApiKeyAuthenticatedRequest extends Request {
  apiKey?: ApiKeyInfo;
  /**
   * In-flight deduplication slot for API key validation.
   *
   * Holds the promise for the current request's validation so that
   * concurrent or repeated invocations of {@link authenticateApiKey} on the
   * same request object do not trigger duplicate validation work.
   */
  _apiKeyValidationPromise?: Promise<ApiKeyInfo | null>;
}

/**
 * Express middleware that extracts and validates the API key from the
 * `X-API-Key` request header.
 *
 * On success, attaches `req.apiKey` with the resolved {@link ApiKeyInfo} and
 * delegates to `next()`.
 *
 * Error paths (never leak internal detail):
 * - **401** — `X-API-Key` header is absent.
 * - **401** — Header is present but `validateApiKey` returns `null`
 *   (unknown key, wrong hash, expired, or deactivated).
 * - **500** — `validateApiKey` rejects unexpectedly (e.g. database error).
 *   The raw error is written to `console.error` only; the response body
 *   contains only `{ error: 'Internal server error' }`.
 *
 * Concurrency behavior:
 * - If the request is already authenticated (`req.apiKey` set), this function
 *   is a no-op and calls `next()` without re-validating.
 * - Concurrent invocations on the same request share a single in-flight
 *   validation promise, so `validateApiKey` (including any `lastUsedAt` write)
 *   runs at most once per request.
 *
 * @param req  - Express request (extended with optional `apiKey` field).
 * @param res  - Express response.
 * @param next - Express next function; called only on successful validation.
 */
export function authenticateApiKey(
  req: ApiKeyAuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  // Idempotent fast-path: already authenticated on this request.
  if (req.apiKey) {
    next();
    return;
  }

  const apiKey = req.headers['x-api-key'] as string;

  if (!apiKey) {
    res.status(401).json({ error: 'Missing X-API-Key header' });
    return;
  }

  // Concurrency invariant: coalesce concurrent calls on the same request onto
  // a single in-flight validation promise. This guarantees `validateApiKey`
  // (and its audit write) runs at most once per request, even if the
  // middleware is invoked concurrently or repeatedly.
  if (!req._apiKeyValidationPromise) {
    req._apiKeyValidationPromise = validateApiKey(apiKey);
  }

  req._apiKeyValidationPromise
    .then(keyInfo => {
      if (!req.apiKey) {
        if (!keyInfo) {
          req._apiKeyValidationPromise = undefined;
          res.status(401).json({ error: 'Invalid API key' });
          return;
        }
        req.apiKey = keyInfo;
      }
      next();
    })
    .catch(err => {
      // Allow a future retry to re-validate instead of replaying the
      // cached rejection.
      req._apiKeyValidationPromise = undefined;
      // eslint-disable-next-line no-console
      console.error('API key validation error:', err);
      res.status(500).json({ error: 'Internal server error' });
    });
}

/**
 * Factory that returns Express middleware enforcing a specific API key scope.
 *
 * Scope matching rules (evaluated in order):
 * 1. **Exact match** — e.g. `contracts:read` satisfies `contracts:read`.
 * 2. **Wildcard action** — e.g. `contracts:*` satisfies `contracts:read`.
 * 3. **Wildcard resource** — e.g. `*:read` satisfies `contracts:read`.
 * 4. **Full wildcard** — `*` satisfies any scope.
 *
 * Error paths:
 * - **401** — `req.apiKey` is not set (caller skipped `authenticateApiKey`).
 * - **403** — Key is present but none of its scopes match the requirement.
 *   The response includes `required` and `provided` for debugging by the
 *   key owner; no internal implementation detail is exposed.
 *
 * @param resource - The resource being accessed (e.g. `'contracts'`).
 * @param action   - The action being performed (e.g. `'read'`).
 * @returns Express middleware function.
 */
export function requireApiKeyScope(resource: string, action: string) {
  return (req: ApiKeyAuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.apiKey) {
      res.status(401).json({ error: 'Not authenticated with API key' });
      return;
    }

    const requiredScope = `${resource}:${action}`;
    const hasScope = req.apiKey.scope.some(scope => {
      // Exact match
      if (scope === requiredScope) return true;
      
      // Wildcard action (e.g., "contracts:*")
      if (scope.endsWith(':*') && scope.startsWith(`${resource}:`)) return true;
      
      // Wildcard resource (e.g., "*:read")
      if (scope.startsWith('*:') && scope.endsWith(`:${action}`)) return true;
      
      // Full wildcard
      if (scope === '*') return true;
      
      return false;
    });

    if (!hasScope) {
      res.status(403).json({ 
        error: 'Forbidden: insufficient API key scope',
        required: requiredScope,
        provided: req.apiKey.scope
      });
      return;
    }

    next();
  };
}

/**
 * Middleware that accepts either JWT Bearer token OR API key authentication.
 *
 * Resolution order:
 * 1. If `Authorization: Bearer <token>` is present, delegates entirely to
 *    {@link authenticateMiddleware} (JWT path). `req.user` is populated on
 *    success.
 * 2. If `X-API-Key` is present (without a Bearer header), delegates to
 *    {@link authenticateApiKey}. `req.apiKey` is populated on success.
 * 3. If neither credential is provided, responds immediately with **401**.
 *
 * Use this on endpoints that must be accessible by both human users (JWT) and
 * automated internal services (API key).
 *
 * @param req  - Express request supporting both `user` and `apiKey` fields.
 * @param res  - Express response.
 * @param next - Called by the delegated middleware on success.
 */
export function authenticateEither(
  req: any, // Using any to support both AuthenticatedRequest and ApiKeyAuthenticatedRequest
  res: Response,
  next: NextFunction,
): void {
  // Check for JWT token first
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    // Let the existing JWT middleware handle this
    return authenticateMiddleware(req, res, next);
  }

  // Check for API key
  const apiKey = req.headers['x-api-key'] as string;
  if (apiKey) {
    return authenticateApiKey(req as ApiKeyAuthenticatedRequest, res, next);
  }

  // Neither authentication method found
  res.status(401).json({ 
    error: 'Authentication required. Provide either Authorization: Bearer <token> or X-API-Key header' 
  });
}

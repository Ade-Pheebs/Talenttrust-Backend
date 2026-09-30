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
 * Invariants owned by this module
 * -------------------------------
 * INV1 — Exactly one terminal outcome per request: either `next()` is invoked
 *        once, or a response is written once. Never both, never twice.
 * INV2 — Identity provenance: `req.apiKey` is only observable when
 *        `validateApiKey` accepted the credential presented by *this* request.
 *        Every rejection path clears it, so an identity attached by an earlier
 *        layer, an earlier attempt or an earlier request can never satisfy
 *        `requireApiKeyScope`.
 * INV3 — Fail closed: an absent, repeated, non-string, empty or whitespace-only
 *        `X-API-Key` header is unauthenticated (401). A malformed credential is
 *        never reported as 500; only an internal failure is.
 * INV4 — Authorization requires a well-formed identity: `requireApiKeyScope`
 *        authorizes only when `req.apiKey` carries a non-empty id, a non-empty
 *        array of string scopes, and is marked active. Anything else is a 401,
 *        never a thrown TypeError.
 * INV5 — No credential disclosure: response bodies only ever contain the fixed
 *        public messages used below — never key material, hashes or stack
 *        traces.
 */

import { Request, Response, NextFunction } from 'express';
import { validateApiKey, ApiKeyInfo } from './apiKeys';
import { authenticateMiddleware } from './authenticate';

/** Express request extended with API key info. */
export interface ApiKeyAuthenticatedRequest extends Request {
  apiKey?: ApiKeyInfo;
}

/** Canonical header carrying the API key credential. */
const API_KEY_HEADER = 'x-api-key';

/**
 * Reads the API key credential from the request.
 *
 * INV3: the header must be present exactly once as a single non-empty string. A
 * repeated header arrives as `string[]`, and an absent, empty or whitespace-only
 * value is indistinguishable from "no credential", so all of those return
 * `null` and are rejected as unauthenticated. A malformed header is therefore
 * classified as missing credentials rather than being handed to
 * `validateApiKey`, where a non-string value would raise and surface as a 500.
 *
 * The value is returned untouched: API keys are opaque, so surrounding
 * whitespace must never be silently trimmed into a different key.
 */
function readApiKeyHeader(req: ApiKeyAuthenticatedRequest): string | null {
  const raw = req.headers?.[API_KEY_HEADER];
  if (typeof raw !== 'string') return null;
  if (raw.trim().length === 0) return null;
  return raw;
}

/**
 * Drops any API key identity from the request.
 *
 * INV2: called at the start of every authentication attempt and on every
 * rejection path, so an attempt that fails can never leave a usable identity
 * behind for a later authorization check.
 */
function clearApiKey(req: ApiKeyAuthenticatedRequest): void {
  delete req.apiKey;
}

/**
 * Narrows a validation result to a usable identity.
 *
 * INV4: authorization is only ever decided from an identity that actually has
 * the fields `requireApiKeyScope` reads, so a malformed or partially populated
 * object is treated as "not authenticated" instead of throwing from inside the
 * scope check.
 */
function isWellFormedApiKeyInfo(value: unknown): value is ApiKeyInfo {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<ApiKeyInfo>;
  return (
    typeof candidate.id === 'string' &&
    candidate.id.length > 0 &&
    Array.isArray(candidate.scope) &&
    candidate.scope.every(scope => typeof scope === 'string' && scope.length > 0) &&
    candidate.isActive === true
  );
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
 * @param req  - Express request (extended with optional `apiKey` field).
 * @param res  - Express response.
 * @param next - Express next function; called only on successful validation.
 */
export function authenticateApiKey(
  req: ApiKeyAuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  // INV2: a fresh attempt starts from no identity, so a rejection below can
  // never be shadowed by an identity attached earlier in the request.
  clearApiKey(req);

  const apiKey = readApiKeyHeader(req);

  if (apiKey === null) {
    res.status(401).json({ error: 'Missing X-API-Key header' });
    return;
  }

  validateApiKey(apiKey)
    .then(keyInfo => {
      if (!keyInfo || !isWellFormedApiKeyInfo(keyInfo)) {
        // INV2/INV4: never attach a half-formed identity.
        clearApiKey(req);
        res.status(401).json({ error: 'Invalid API key' });
        return;
      }

      req.apiKey = keyInfo;
      next();
    })
    .catch(err => {
      // INV2: an internal failure must not leave a previously attached identity
      // in place for downstream authorization.
      clearApiKey(req);
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
    // INV4: authorize only against a well-formed identity. A malformed one is
    // discarded and reported as unauthenticated rather than throwing a
    // TypeError out of the scope scan.
    const keyInfo = req.apiKey;
    if (!isWellFormedApiKeyInfo(keyInfo)) {
      clearApiKey(req);
      res.status(401).json({ error: 'Not authenticated with API key' });
      return;
    }

    const requiredScope = `${resource}:${action}`;
    const hasScope = keyInfo.scope.some(scope => {
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
        provided: keyInfo.scope
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
  // INV2: every request starts from a clean identity slate, whichever
  // credential it ends up presenting.
  clearApiKey(req as ApiKeyAuthenticatedRequest);

  // Check for JWT token first
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    // Let the existing JWT middleware handle this
    return authenticateMiddleware(req, res, next);
  }

  // Check for API key. Delegate whenever the header is present at all so the
  // API-key path owns the classification (INV3): a repeated, empty or
  // whitespace-only header is a rejected credential, not "no credentials".
  if (req.headers?.[API_KEY_HEADER] !== undefined) {
    return authenticateApiKey(req as ApiKeyAuthenticatedRequest, res, next);
  }

  // Neither authentication method found
  res.status(401).json({ 
    error: 'Authentication required. Provide either Authorization: Bearer <token> or X-API-Key header' 
  });
}

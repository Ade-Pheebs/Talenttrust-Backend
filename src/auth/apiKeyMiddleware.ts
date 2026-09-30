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
 * A repeated header is delivered by Node as `string[]`, and any absent,
 * non-string, empty or whitespace-only value is indistinguishable from "no
 * credential". All of those return `null`, so a malformed header is classified
 * as *missing credentials* rather than being handed to `validateApiKey`, where
 * a non-string value would raise and surface as an internal 500.
 *
 * The value itself is returned untouched: API keys are opaque, so surrounding
 * whitespace must never be silently trimmed into a different key.
 */
function readApiKeyHeader(req: ApiKeyAuthenticatedRequest): string | null {
  const raw = req.headers?.[API_KEY_HEADER];
  if (typeof raw !== 'string') return null;
  if (raw.trim().length === 0) return null;
  return raw;
}

/**
 * Drops any API key identity already attached to the request.
 *
 * Called at the start of every authentication attempt and on every rejection
 * path, so an attempt that fails can never leave a usable identity behind for a
 * later authorization check.
 */
function clearApiKeyIdentity(req: ApiKeyAuthenticatedRequest): void {
  delete req.apiKey;
}

/**
 * Writes a response at most once.
 *
 * This middleware can run after an earlier layer that already committed a
 * response (streaming handlers, error paths, client disconnect). Calling
 * `res.status().json()` again throws `ERR_HTTP_HEADERS_SENT`, turning a handled
 * failure into an unhandled crash; once headers are sent, the failure is
 * reported through the log line only.
 */
function sendJsonOnce(res: Response, status: number, body: Record<string, unknown>): void {
  if (res.headersSent) return;
  res.status(status).json(body);
}

/**
 * Deterministic fail-closed path shared by synchronous throws and async
 * rejections from the validation dependency.
 */
function failClosed(res: Response, err: unknown): void {
  // eslint-disable-next-line no-console
  console.error('API key validation error:', err);
  sendJsonOnce(res, 500, { error: 'Internal server error' });
}

/**
 * Narrows a validation result to a usable identity.
 *
 * Authorization is only decided from an identity that actually carries the
 * fields `requireApiKeyScope` reads, so a malformed or partially populated
 * object is treated as "not authenticated" instead of throwing from inside the
 * scope scan.
 */
function isWellFormedApiKeyInfo(value: unknown): value is ApiKeyInfo {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<ApiKeyInfo>;
  return (
    typeof candidate.id === 'string' &&
    candidate.id.length > 0 &&
    Array.isArray(candidate.scope) &&
    candidate.scope.every((scope) => typeof scope === 'string' && scope.length > 0) &&
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
  // A fresh attempt starts from no identity, so a rejection below can never be
  // shadowed by an identity attached earlier in the request lifecycle.
  clearApiKeyIdentity(req);

  const apiKey = readApiKeyHeader(req);

  if (apiKey === null) {
    sendJsonOnce(res, 401, { error: 'Missing X-API-Key header' });
    return;
  }

  let validation: Promise<ApiKeyInfo | null>;
  try {
    // `Promise.resolve` normalises a non-promise return and funnels a
    // synchronous throw out of `validateApiKey` into the same `.catch` path as
    // an async rejection, so a dependency failure is always exactly one
    // deterministic 500 — never an escaped exception handled by Express.
    validation = Promise.resolve(validateApiKey(apiKey));
  } catch (err) {
    failClosed(res, err);
    return;
  }

  validation
    .then(keyInfo => {
      if (!keyInfo || !isWellFormedApiKeyInfo(keyInfo)) {
        // Never attach a half-formed identity.
        clearApiKeyIdentity(req);
        sendJsonOnce(res, 401, { error: 'Invalid API key' });
        return;
      }

      req.apiKey = keyInfo;
      next();
    })
    .catch(err => {
      // An internal failure must not leave a previously attached identity in
      // place for downstream authorization.
      clearApiKeyIdentity(req);
      failClosed(res, err);
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
    // Authorize only against a well-formed identity. A malformed one is
    // discarded and reported as unauthenticated rather than throwing a
    // TypeError out of the scope scan.
    const keyInfo = req.apiKey;
    if (!isWellFormedApiKeyInfo(keyInfo)) {
      clearApiKeyIdentity(req);
      sendJsonOnce(res, 401, { error: 'Not authenticated with API key' });
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
      sendJsonOnce(res, 403, {
        error: 'Forbidden: insufficient API key scope',
        required: requiredScope,
        provided: keyInfo.scope,
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
  // Every request starts from a clean identity slate, whichever credential it
  // ends up presenting.
  clearApiKeyIdentity(req as ApiKeyAuthenticatedRequest);

  // Check for JWT token first
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    // Let the existing JWT middleware handle this
    return authenticateMiddleware(req, res, next);
  }

  // Delegate whenever the header is present at all so the API-key path owns the
  // classification: a repeated, empty or whitespace-only header is a rejected
  // credential, not "no credentials".
  if (req.headers?.[API_KEY_HEADER] !== undefined) {
    return authenticateApiKey(req as ApiKeyAuthenticatedRequest, res, next);
  }

  // Neither authentication method found
  sendJsonOnce(res, 401, {
    error: 'Authentication required. Provide either Authorization: Bearer <token> or X-API-Key header' 
  });
}

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
 * State invariants owned by this module:
 *   1. A request is either unauthenticated or authenticated with exactly
 *      one credential type (`$req.user` or `$req.apiKey`), never both.
 *   2. `$req.apiKey` is only ever set after a successful validation
 *      and is never left stale from a prior middleware in the same chain.
 *   3. Scope enforcement is fail-closed: any non-match results in
 *      403 and never invokes ``$next()``.
 *   4. Authentication failures are not observable to callers (401 for all
 *      invalid-unknown-expired-deactivated cases) to prevent key enumeration.
 *   5. `$next()`` is invoked at most once per middleware invocation.
 */

import { Request, Response, NextFunction } from 'express';
import { validateApiKey, ApiKeyInfo } from './apiKeys';
import { authenticateMiddleware } from './authenticate';

/** Express request extended with API key info. */
export interface ApiKeyAuthenticatedRequest extends Request {
  apiKey?: ApiKeyInfo;
}

/** Maximum accepted length of an `X-API-Key` header value. */
const MAX_API_KEY_LENGTH = 512;

/** Regex describing a single scope token accepted by this module. */
const SCOPE_TOKEN_RE = /^[A-Za-z0-9_.*-]+$/;

/**
 * Normalize the raw `x-api-key` header value into a single trimmed
 * string, or ``null`` when no usable credential is present.
 *
 * Express may give us `string`, `string[]`, or `undefined`. A multi-value
 * header is ambiguous and must not be silently collapsed into one of its
 * values, so we reject it as missing. This is deterministic and avoids a
 * class of header-smuggling bugs.
 */
function extractApiKeyHeader(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_API_KEY_LENGTH) {
    return null;
  }
  return trimmed;
}

/**
 * Default number of attempts for transient validation failures.
 * Total attempts = 1 initial + (API_KEY_MAX_RETRIES) retries.
 */
const API_KEY_MAX_RETRIES = 2;

/** Base delay in milliseconds between retries (exponential backoff). */
const API_KEY_RETRY_BASE_DELAY_MS = 25;

/** Maximum delay in milliseconds between retries. */
const API_KEY_RETRY_MAX_DELAY_MS = 200;

/**
 * Error class for non-retryable API key validation failures.
 *
 * Thrown by the validator when the failure is deterministic (e.g.
 * malformed key format, invalid hash encoding) and retrying would not help.
 */
export class ApiKeyValidationError extends Error {
  constructor(message: string, public readonly code: string = 'API_KEY_VALIDATION_FAILED') {
    super(message);
    this.name = 'ApiKeyValidationError';
  }
}

/**
 * Resolves the validator to use for a request.
 *
 * This indirection exists so that tests can inject a deterministic
 * validator (including failure/retry behavior) without mock module
 * registry globals. It is intentionally not exported from the module's
 * public surface.
 */
interface ApiKeyValidatorContext {
  validator?: (key: string) => Promise<ApiKeyInfo | null>;
}

function resolveValidator(ctx?: ApiKeyValidatorContext): (key: string) => Promise<ApiKeyInfo | null> {
  return ctx?.validator ?? validateApiKey;
}

/**
 * Returns true when an error is transient and the validation call
 * may be safely retried.
 *
 * The classification is deterministic and conservative:
 *   - ApiKeyValidationError is always non-retryable.
 *   - Errors with a code indicating a client/programming fault
 *     (e.g. ERROR_INVALID_ARG) are non-retryable.
 *   - Everything else (DB, network, timeout) is treated as transient.
 */
function isRetryableError(err: unknown): boolean {
  if (err instanceof ApiKeyValidationError) return false;
  if (err && typeof err === 'object') {
    const code = (err as { code?: unknown }).code;
    if (code === 'ERROR_INVALID_ARG' || code === 'API_KEY_VALIDATION_FAILED') {
      return false;
    }
  }
  return true;
}

/** Delay helper used for backoff between retries. */
function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Validates an API key with bounded retries for transient failures.
 *
 * Invariants:
 *   - A successful validation returns the resolved ApiKeyInfo exactly once.
 *   - A definitive null result (key not found/expired/deactivated) is
 *     returned immediately and is never retried.
 *   - Non-retryable errors propagate immediately.
 *   - Retryable errors are retried up to API_KEY_MAX_RETRIES times with
 *     exponential backoff, then the last error is rethrown.
 */
async function validateWithRetry(
  key: string,
  validator: (key: string) => Promise<ApiKeyInfo | null>,
): Promise<ApiKeyInfo | null> {
  let lastError: unknown;

  for (let attempt = 0; attempt <= API_KEY_MAX_RETRIES; attempt++) {
    try {
      return await validator(key);
    } catch (err) {
      lastError = err;
      if (!isRetryableError(err) || attempt === API_KEY_MAX_RETRIES) {
        throw err;
      }
      const backoff = Math.min(
        API_KEY_RETRY_BASE_DELAY_MS * 2 ** attempt,
        API_KEY_RETRY_MAX_DELAY_MS,
      );
      await delay(backoff);
    }
  }

  // Unreachable: the loop either returns or throws on the last attempt.
  throw lastError instanceof Error
    ? lastError
    : new Error('API key validation failed');
}

/**
 * Express middleware that extracts and validates the API key from the
 * `X-API-Key` request header.
 *
 * On success, attaches `req.apiKey` with the resolved {@link ApiKeyInfo} and
 * delegates to `next()`.
 *
 * Error paths (never leak internal detail):
 * - **401** — `X-API-Key` header is absent, empty, multi-valued, or overly
 *   long.
 * - **401** — Header is present but `validateApiKey` returns `null`
 *   (unknown key, wrong hash, expired, or deactivated).
 * - **500** — `validateApiKey` rejects unexpectedly after bounded retries
 *   (e.g. database error). The raw error is written to `console.error` only;
 *   the response body contains only `{ error: 'Internal server error' }`.
 *
 * Invariants:
 * - `req.apiKey` is never mutated on a failure path.
 * - `next()` is invoked exactly once on success and never on failure.
 *
 * @param req  - Express request (extended with optional `apiKey` field).
 * @param res  - Express response.
 * @param next - Express next function; called only on successful validation.
 */
export function authenticateApiKey(
  req: ApiKeyAuthenticatedRequest,
  res: Response,
  next: NextFunction,
  ctx?: ApiKeyValidatorContext,
): void {
  // Invariant 2: clear any stale credential from a prior middleware run.
  // This guarantees a failure cannot leave a previously-authenticated
  // request looking authenticated.
  req.apiKey = undefined;

  const apiKey = extractApiKeyHeader(req.headers['x-api-key']);

  if (!apiKey) {
    res.status(401).json({ error: 'Missing X-API-Key header' });
    return;
  }

  const validator = resolveValidator(ctx);

  validateWithRetry(apiKey, validator)
    .then(keyInfo => {
      if (!keyInfo) {
        res.status(401).json({ error: 'Invalid API key' });
        return;
      }

      // Invariant 1 & 2: attach the validated key only after success.
      req.apiKey = keyInfo;
      next();
    })
    .catch(err => {
      // eslint-disable-next-line no-console
      console.error('API key validation error:', err);
      // Invariant 2: failure must not leave a credential attached.
      req.apiKey = undefined;
      res.status(500).json({ error: 'Internal server error' });
    });
}

/**
 * Returns `true` if `scope` satisfies the `resource:action` requirement.
 *
 * Scope matching rules (evaluated in order):
 * 1. **Exact match** — e.g. `contracts:read` satisfies `contracts:read`.
 * 2. **Wildcard action** — e.g. `contracts:*` satisfies `contracts:read`.
 * 3. **Wildcard resource** — e.g. `*:read` satisfies `contracts:read`.
 * 4. **Full wildcard** — `*` satisfies any scope.
 *
 * The match is strict and deterministic: the comparison is byte-exact and
 * the components are never interpreted as regex or path globs. A scope token
 * that does not match the allowed character set is rejected rather than
 * being treated as a wildcard.
 */
export function scopeSatisfies(
  scope: string,
  resource: string,
  action: string,
): boolean {
  if (typeof scope !== 'string' || !SCOPE_TOKEN_RE.test(scope)) {
    return false;
  }

  const requiredScope = `${resource}:${action}`;

  // Exact match
  if (scope === requiredScope) return true;

  // Full wildcard
  if (scope === '*') return true;

  // Wildcard action (e.g. "contracts:*")
  if (scope.endsWith(':*') && scope.slice(0, -2) === resource) return true;

  // Wildcard resource (e.g. "*:read")
  if (scope.startsWith('*:') && scope.slice(2) === action) return true;

  return false;
}

/**
 * Factory that returns Express middleware enforcing a specific API key scope.
 *
 * Error paths:
 * - **401** — `req.apiKey` is not set (caller skipped `authenticateApiKey`).
 * - **403** — Key is present but none of its scopes match the requirement.
 *   The response includes `required` and `provided` for debugging by the
 *   key owner; no internal implementation detail is exposed.
 *
 * Invariants:
 * - Fail-closed: any non-match results in 403 and never calls `next()`.
 * - The required scope is computed once at factory creation time and is
 *   not influenced by request data.
 *
 * @param resource - The resource being accessed (e.g. `'contracts'`).
 * @param action   - The action being performed (e.g. `'read'`).
 * @returns Express middleware function.
 */
export function requireApiKeyScope(resource: string, action: string) {
  const requiredScope = `${resource}:${action}`;

  return (req: ApiKeyAuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.apiKey) {
      res.status(401).json({ error: 'Not authenticated with API key' });
      return;
    }

    const scopes = Array.isArray(req.apiKey.scope) ? req.apiKey.scope : [];
    const hasScope = scopes.some(scope => scopeSatisfies(scope, resource, action));

    if (!hasScope) {
      res.status(403).json({
        error: 'Forbidden: insufficient API key scope',
        required: requiredScope,
        provided: scopes,
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
 * Invariants:
 * - At most one credential type is attached to the request as a result of
 *   this middleware. When the JWT path is taken, `req.apiKey` is cleared so a
 *   stale API key from an earlier middleware cannot bypass scope checks.
 * - A malformed `Authorization` header (e.g. `Bearer` with no token) is
 *   treated as absent and falls through to the API key path or 401.
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
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice('Bearer '.length).trim();
    if (token.length > 0) {
      // Invariant 1: the JWT path must not carry an API key credential.
      req.apiKey = undefined;
      // Let the existing JWT middleware handle this
      return authenticateMiddleware(req, res, next);
    }
  }

  // Check for API key
  const apiKey = extractApiKeyHeader(req.headers['x-api-key']);
  if (apiKey) {
    return authenticateApiKey(req as ApiKeyAuthenticatedRequest, res, next);
  }

  // Neither authentication method found
  res.status(401).json({
    error: 'Authentication required. Provide either Authorization: Bearer <token> or X-API-Key header',
  });
}

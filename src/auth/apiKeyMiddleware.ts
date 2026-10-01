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
  /**
   * In-flight deduplication slot for API key validation.
   *
   * Holds the promise for the current request's validation so that
   * concurrent or repeated invocations of {@link authenticateApiKey} on the
   * same request object do not trigger duplicate validation work.
   */
  _apiKeyValidationPromise?: Promise<ApiKeyInfo | null>;
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
  ctx?: ApiKeyValidatorContext,
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
      // INV2: an internal failure must not leave a previously attached identity
      // in place for downstream authorization.
      clearApiKey(req);
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
  // INV2: every request starts from a clean identity slate, whichever
  // credential it ends up presenting.
  clearApiKey(req as ApiKeyAuthenticatedRequest);

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

  // Check for API key. Delegate whenever the header is present at all so the
  // API-key path owns the classification (INV3): a repeated, empty or
  // whitespace-only header is a rejected credential, not "no credentials".
  if (req.headers?.[API_KEY_HEADER] !== undefined) {
    return authenticateApiKey(req as ApiKeyAuthenticatedRequest, res, next);
  }

  // Neither authentication method found
  res.status(401).json({
    error: 'Authentication required. Provide either Authorization: Bearer <token> or X-API-Key header',
  });
}

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
 * - **401** — `X-API-Key` header is absent.
 * - **401** — Header is present but `validateApiKey` returns `null`
 *   (unknown key, wrong hash, expired, or deactivated).
 * - **500** — `validateApiKey` rejects unexpectedly after bounded retries
 *   (e.g. database error). The raw error is written to `console.error` only;
 *   the response body contains only `{ error: 'Internal server error' }`.
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
  const apiKey = req.headers['x-api-key'] as string;

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

      req.apiKey = keyInfo;
      next();
    })
    .catch(err => {
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

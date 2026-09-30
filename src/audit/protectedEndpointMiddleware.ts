/**
 * @module audit/protectedEndpointMiddleware
 * @description Express middleware that automatically emits a structured audit
 * entry for every request handled by an auth-protected route.
 *
 * ## How it works
 *
 * The middleware registers a `res.on('finish')` listener before calling
 * `next()`. This guarantees that the audit entry is written **after** the
 * full middleware chain (including authentication) has run, so the final
 * HTTP status code and the resolved `req.user` identity are both available.
 *
 * Mount this middleware **before** `authenticateMiddleware` / `requireAuth`
 * on any router or route group that requires authentication.
 *
 * ## Action mapping
 *
 * | Condition                     | AuditAction          | Severity  |
 * |-------------------------------|----------------------|-----------|
 * | Status 401 (unauthenticated)  | `AUTH_FAILED`        | `WARNING` |
 * | Status 403 (unauthorised)     | `AUTH_FAILED`        | `WARNING` |
 * | GET / HEAD + 2xx/3xx          | `ENDPOINT_ACCESS`    | `INFO`    |
 * | POST / PUT / PATCH / DELETE   | `ENDPOINT_MUTATION`  | `INFO`    |
 * | Any method + 4xx/5xx (other)  | method-derived above | `WARNING` |
 *
 * ## Redaction
 *
 * All request headers and body fields are passed through the deterministic
 * redaction rules defined in `./redact` before being written to the store.
 * The `Authorization` header value is **never** persisted.
 *
 * ## Traceability
 *
 * The `requestId` set by `requestIdMiddleware` (stored in
 * `res.locals.requestId`) is used as the `correlationId` on every entry,
 * enabling end-to-end request tracing across logs.
 *
 * ## Validation boundaries (enforced in the finish listener)
 *
 * | Field         | Rule                                                           |
 * |---------------|----------------------------------------------------------------|
 * | actor         | Truncated to {@link MAX_ACTOR_LENGTH} chars; falls back to     |
 * |               | `'anonymous'` when absent or non-string.                       |
 * | resource      | Truncated to {@link MAX_RESOURCE_LENGTH} chars; falls back to  |
 * |               | `'endpoint'` when the URL yields nothing useful.               |
 * | resourceId    | Truncated to {@link MAX_RESOURCE_ID_LENGTH} chars; falls back  |
 * |               | to `''` when the URL contains no id segment.                   |
 * | ipAddress     | Sanitised via {@link sanitizeIpAddress} (clamped to 45 chars). |
 * | correlationId | Sanitised via {@link sanitizeCorrelationId} (control chars     |
 * |               | stripped, charset-validated, discarded on violation).          |
 *
 * Truncation (not rejection) is deliberate for automatically-derived fields:
 * the entry is still useful for tracing and incident response even when a
 * path segment is unexpectedly long, while a missing entry would be worse
 * than a slightly truncated one.
 *
 * @security
 * - Audit failures are silently swallowed (with a console.error) so that a
 *   logging fault never breaks the primary request path.
 * - No raw bearer tokens, passwords, or PII reach the audit store.
 *
 * @example
 * ```ts
 * import { protectedEndpointAuditMiddleware } from './audit/protectedEndpointMiddleware';
 * import { authenticateMiddleware } from './auth/authenticate';
 *
 * router.use(protectedEndpointAuditMiddleware);
 * router.use(authenticateMiddleware);
 * router.get('/contracts', handler);
 * ```
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { AuditAction, AuditSeverity } from './types';
import type { AuthenticatedRequest } from '../auth/authenticate';
import { buildAuditMetadata } from './redact';
import { auditService, AuditService } from './service';
import { validateEnv } from '../config/env.schema';
import { sanitizeCorrelationId, sanitizeIpAddress } from './middleware';

// ─── Field-length bounds ──────────────────────────────────────────────────────

/**
 * Maximum length of the `actor` field stored in an automatically-generated
 * audit entry.  User IDs are bounded by the authentication system, but this
 * guard prevents an arbitrarily long value from reaching the store when the
 * service evolves or a non-standard auth path is added.
 */
export const MAX_ACTOR_LENGTH = 128;

/**
 * Maximum length of the `resource` field derived from the URL path.
 * A URL segment is at most 2048 chars in practice; 128 is generous for
 * any real resource type name while preventing oversized store writes.
 */
export const MAX_RESOURCE_LENGTH = 128;

/**
 * Maximum length of the `resourceId` field derived from the URL path.
 * UUIDs are 36 chars; slugs are typically under 64.  256 allows for all
 * realistic IDs while bounding the field against path-injection attempts.
 */
export const MAX_RESOURCE_ID_LENGTH = 256;

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Truncate a string to at most `max` characters.
 * Returns `fallback` when the value is absent, non-string, or empty.
 *
 * Truncation is preferred over rejection here because this middleware
 * emits fire-and-forget entries: an entry with a truncated field is
 * more useful for incident response than a missing entry.
 */
function truncate(value: unknown, max: number, fallback: string): string {
  if (typeof value !== 'string' || value.length === 0) return fallback;
  return value.length <= max ? value : value.slice(0, max);
}

/**
 * Map HTTP method + final status code to an AuditAction.
 * Auth failures take priority over the HTTP verb.
 */
function deriveAction(method: string, statusCode: number): AuditAction {
  if (statusCode === 401 || statusCode === 403) {
    return 'AUTH_FAILED';
  }
  const verb = method.toUpperCase();
  return verb === 'GET' || verb === 'HEAD' ? 'ENDPOINT_ACCESS' : 'ENDPOINT_MUTATION';
}

/**
 * Choose the appropriate severity for an audit entry.
 * Auth failures and unexpected errors are WARNING; routine access is INFO.
 */
function deriveSeverity(action: AuditAction, statusCode: number): AuditSeverity {
  if (action === 'AUTH_FAILED') return 'WARNING';
  if (statusCode >= 400) return 'WARNING';
  return 'INFO';
}

/**
 * Extract the resource type from a URL path.
 * Parses the first named segment after the versioned API prefix.
 *
 * @example
 * '/api/v1/contracts/abc'   → 'contracts'
 * '/api/v1/reputation/u1'  → 'reputation'
 * '/other'                 → 'endpoint'
 */
function deriveResource(path: string): string {
  const match = /^\/api\/v\d+\/([^/?#]+)/i.exec(path);
  return match?.[1] ?? 'endpoint';
}

/**
 * Extract the primary resource ID from a URL path.
 * Returns the path segment immediately after the resource type, if present.
 *
 * @example
 * '/api/v1/contracts/abc123/metadata'  → 'abc123'
 * '/api/v1/contracts'                  → ''
 */
function deriveResourceId(path: string): string {
  const match = /^\/api\/v\d+\/[^/?#]+\/([^/?#]+)/i.exec(path);
  return match?.[1] ?? '';
}

// ─── Middleware factory ───────────────────────────────────────────────────────

/**
 * Factory that returns a `protectedEndpointAuditMiddleware` bound to the
 * provided `AuditService` instance. Useful for injecting isolated services
 * in tests without touching the module-level singleton.
 *
 * @param service - AuditService instance to write entries to (defaults to
 *                  the application singleton).
 */
export function createProtectedEndpointAuditMiddleware(
  service: AuditService = auditService,
): RequestHandler {
  return function protectedEndpointAuditMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
  ): void {
    const env = validateEnv();

    if (!env.AUDIT_ENABLED) {
      // Feature flag off — skip the finish listener entirely; no audit entries
      // are written for protected-endpoint traffic.
      next();
      return;
    }

    res.on('finish', () => {
      try {
        // req.user is populated by authenticateMiddleware after this runs.
        // Truncate to MAX_ACTOR_LENGTH to keep the store entry bounded even
        // when a non-standard auth path produces an unexpectedly long userId.
        const rawActor = (req as AuthenticatedRequest).user?.userId ?? 'anonymous';
        const actor = truncate(rawActor, MAX_ACTOR_LENGTH, 'anonymous');

        const action = deriveAction(req.method, res.statusCode);
        const severity = deriveSeverity(action, res.statusCode);

        // Truncate URL-derived fields to prevent oversized store writes when
        // paths contain unusually long segments (e.g. a UUID concatenated with
        // extra characters, or a path-traversal attempt).
        const resource = truncate(deriveResource(req.path), MAX_RESOURCE_LENGTH, 'endpoint');
        const resourceId = truncate(deriveResourceId(req.path), MAX_RESOURCE_ID_LENGTH, '');

        const requestId = res.locals['requestId'] as string | undefined;

        // Sanitise the IP address to prevent oversized values from reaching
        // the store when a long X-Forwarded-For chain is present.
        const ipAddress = sanitizeIpAddress(req.ip ?? req.socket?.remoteAddress);

        // Sanitise the requestId before using it as a correlationId: it comes
        // from res.locals which is set by our own middleware, but defensive
        // sanitisation keeps the invariant clear and prevents an unexpected
        // value (e.g. injected via a malicious proxy) from reaching the store.
        const correlationId = sanitizeCorrelationId(requestId);

        const metadata = buildAuditMetadata(
          req.method,
          req.path,
          req.headers as Record<string, string | string[] | undefined>,
          req.body,
          req.query as Record<string, unknown>,
          res.statusCode,
          requestId,
        );

        service.log({
          action,
          severity,
          actor,
          resource,
          resourceId,
          metadata,
          ipAddress,
          correlationId,
        });
      } catch (err) {
        // Audit failures must never disrupt the request lifecycle.
        console.error('[protectedEndpointAuditMiddleware] Failed to write audit entry:', err);
      }
    });

    next();
  };
}

/**
 * Ready-to-use middleware instance backed by the application-level singleton
 * `AuditService`. Import and mount this on any protected router.
 */
export const protectedEndpointAuditMiddleware =
  createProtectedEndpointAuditMiddleware();

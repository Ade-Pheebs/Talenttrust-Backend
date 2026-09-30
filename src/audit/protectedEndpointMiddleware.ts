/**
 * @module audit/protectedEndpointMiddleware
 * @description Express middleware that automatically emits a structured audit
 * entry for every request handled by an auth-protected route.
 *
 * ## How it works
 *
 * The middleware registers response listeners before calling `next()`. Normal
 * responses are recorded on `finish`, after authentication and the handler
 * have run. Prematurely closed responses are recorded once on `close`.
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
 * @security
 * - Audit failures produce a generic diagnostic without breaking the request.
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
import { buildAuditMetadata } from './redact';
import { auditService, AuditService } from './service';
import { validateEnv } from '../config/env.schema';

// A response can pass through the same protected router more than once. Keep
// the guard on that response, rather than in process-wide state, so each HTTP
// request has at most one audit write attempt.
const auditListenerRegistered = Symbol('protectedEndpointAuditListenerRegistered');

type AuditedResponse = Response & { [auditListenerRegistered]?: boolean };

function resolveActor(req: Request): string {
  const user = (req as Request & { user?: { userId?: unknown; id?: unknown } }).user;
  // The simple bearer middleware uses userId; the production JWT middleware
  // uses id. Preserve both contracts without trusting a malformed value.
  if (typeof user?.userId === 'string' && user.userId) return user.userId;
  if (typeof user?.id === 'string' && user.id) return user.id;
  return 'anonymous';
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

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

    const auditedResponse = res as AuditedResponse;
    if (auditedResponse[auditListenerRegistered]) {
      next();
      return;
    }
    auditedResponse[auditListenerRegistered] = true;

    let attempted = false;
    const writeAuditEntry = (aborted: boolean): void => {
      if (attempted) return;
      // Never retry after service.log throws: the repository may already have
      // appended the entry before a downstream step failed.
      attempted = true;
      try {
        const statusCode = aborted ? 499 : res.statusCode;
        const actor = resolveActor(req);
        const action = deriveAction(req.method, res.statusCode);
        const severity = aborted ? 'WARNING' : deriveSeverity(action, statusCode);
        const path = `${req.baseUrl || ''}${req.path}`;
        const resource = deriveResource(path);
        const resourceId = deriveResourceId(path);
        const rawRequestId = res.locals['requestId'];
        const requestId = typeof rawRequestId === 'string' ? rawRequestId : undefined;
        const ipAddress =
          (req.ip ?? req.socket?.remoteAddress) as string | undefined;

        let metadata: Record<string, unknown>;
        try {
          metadata = buildAuditMetadata(
            req.method,
            path,
            req.headers as Record<string, string | string[] | undefined>,
            req.body,
            req.query as Record<string, unknown>,
            statusCode,
            requestId,
          );
        } catch {
          // Malformed or cyclic request data must not erase the entire audit
          // event. Omit untrusted fields rather than persisting them raw.
          metadata = {
            method: req.method,
            path,
            statusCode,
            requestId: requestId ?? null,
            metadataOmitted: true,
          };
          console.error('[protectedEndpointAuditMiddleware] Request metadata omitted');
        }
        if (aborted) metadata['aborted'] = true;

        service.log({
          action,
          severity,
          actor,
          resource,
          resourceId,
          metadata,
          ipAddress,
          correlationId: requestId,
        });
      } catch {
        // Audit failures must never disrupt the request lifecycle.
        // Error objects from stores can contain request data or credentials.
        console.error('[protectedEndpointAuditMiddleware] Failed to write audit entry');
      }
    };

    res.once('finish', () => writeAuditEntry(false));
    res.once('close', () => {
      if (!res.writableFinished) writeAuditEntry(true);
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

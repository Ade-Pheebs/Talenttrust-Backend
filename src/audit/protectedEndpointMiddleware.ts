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
 * Mount this middleware after body parsing and **before** `authenticateMiddleware` / `requireAuth`
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
 * Request headers, body and query are copied within explicit bounds and
 * redacted using `./redact`. Invalid sections are replaced with `[OMITTED]`.
 * The `Authorization` header value is **never** persisted.
 *
 * ## Traceability
 *
 * The `requestId` set by `requestIdMiddleware` (stored in
 * `res.locals.requestId`) is used as the `correlationId` on every entry,
 * enabling end-to-end request tracing across logs.
 *
 * @security
 * - Audit failures are silently swallowed (with a console.error) so that a
 *   logging fault never breaks the primary request path.
 * - Known sensitive headers and payload keys are redacted. Free-text values
 *   still require application-specific PII policy.
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
import { isIP } from 'net';
import { auditIdentifier, auditPath, auditMethod, auditPayload } from './protectedEndpointInput';
import { auditService, AuditService } from './service';
import { validateEnv } from '../config/env.schema';

// Each response/service pair owns one terminal write, even across factories.
const registrations = new WeakMap<Response, WeakSet<AuditService>>();

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
  return auditIdentifier(match?.[1]) ?? 'endpoint';
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
  return auditIdentifier(match?.[1]) ?? '';
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

    let services = registrations.get(res);
    if (services?.has(service)) {
      next();
      return;
    }
    if (!services) {
      services = new WeakSet();
      registrations.set(res, services);
    }
    services.add(service);

    // Snapshot ingress context before mounted routers or handlers rewrite it.
    let method = 'UNKNOWN';
    let path = '[INVALID]';
    let headers: ReturnType<typeof auditPayload> = { value: '[OMITTED]', rejected: true };
    let body = headers;
    let query = headers;
    try {
      method = auditMethod(req.method);
      path = auditPath(req.originalUrl ?? req.path);
      headers = auditPayload(req.headers, true);
      body = auditPayload(req.body);
      const rawQuery = req.query;
      query = rawQuery !== null && typeof rawQuery === 'object' && !Array.isArray(rawQuery)
        ? auditPayload(rawQuery) : { value: '[OMITTED]', rejected: true };
      if (!query.rejected && Object.keys(query.value as object).length === 0) {
        query = { value: null, rejected: false };
      }
    } catch {
      // Even an exotic request getter must not interrupt authentication.
    }

    res.once('finish', () => {
      try {
        // Authentication and the final status are resolved after next().
        const rawActor = (req as AuthenticatedRequest).user?.userId;
        const validActor = auditIdentifier(rawActor);
        const actor = validActor ?? 'anonymous';
        const statusCode = Number.isInteger(res.statusCode) && res.statusCode >= 100 &&
          res.statusCode <= 599 ? res.statusCode : null;
        const action = deriveAction(method, statusCode ?? 500);
        const rawRequestId = res.locals['requestId'];
        const requestId = auditIdentifier(rawRequestId);
        const correlationId = requestId && /^[A-Za-z0-9._:-]+$/.test(requestId) ? requestId : undefined;
        const rawIp = req.ip ?? req.socket?.remoteAddress;
        const ipAddress = typeof rawIp === 'string' && rawIp.length <= 45 && isIP(rawIp) ? rawIp : undefined;
        const segments = /^\/api\/v\d+\/([^/?#]+)(?:\/([^/?#]+))?/i.exec(path);
        const rejected = [
          ...(method === 'UNKNOWN' ? ['method'] : []),
          ...(path === '[INVALID]' ? ['path'] : []),
          ...(statusCode === null ? ['statusCode'] : []),
          ...(headers.rejected ? ['headers'] : []),
          ...(body.rejected ? ['body'] : []),
          ...(query.rejected ? ['query'] : []),
          ...(rawActor !== undefined && !validActor ? ['actor'] : []),
          ...(rawRequestId !== undefined && !correlationId ? ['requestId'] : []),
          ...(rawIp !== undefined && !ipAddress ? ['ipAddress'] : []),
          ...(segments?.[1] && !auditIdentifier(segments[1]) ? ['resource'] : []),
          ...(segments?.[2] && !auditIdentifier(segments[2]) ? ['resourceId'] : []),
        ];
        const metadata = Object.freeze({
          method, path, statusCode, requestId: correlationId ?? null,
          headers: headers.value, body: body.value, query: query.value,
          ...(rejected.length ? { auditValidation: Object.freeze(rejected) } : {}),
        });
        service.log({
          action, severity: rejected.length ? 'WARNING' : deriveSeverity(action, statusCode ?? 500), actor,
          resource: deriveResource(path), resourceId: deriveResourceId(path),
          metadata, ipAddress, correlationId,
        });
      } catch {
        // Never include exception messages, stack traces, or request data.
        console.error('[protectedEndpointAuditMiddleware] Failed to write audit entry',
          { code: 'protected_audit_write_failed' });
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

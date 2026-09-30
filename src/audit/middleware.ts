/**
 * @module audit/middleware
 * @description Express middleware for automatic audit logging of HTTP requests.
 *
 * Attaches a per-request audit helper to `res.locals.audit` so route handlers
 * can emit structured audit events without importing the service directly.
 *
 * When `AUDIT_ENABLED=false` the middleware attaches a no-op helper so that
 * callers compiled against `res.locals.audit.log(...)` continue to work
 * without error — they simply produce no stored entry.
 *
 * Security notes:
 * - IP addresses are extracted from X-Forwarded-For only when the app is
 *   behind a trusted proxy. Set `app.set('trust proxy', true)` accordingly.
 * - Correlation IDs from X-Correlation-ID headers are passed through as-is;
 *   validate/sanitise them if they are user-controlled.
 */

import type { Request, Response, NextFunction } from 'express';
import { auditService } from './service';
import type { AuditEntry, CreateAuditEntryInput } from './types';
import { validateEnv } from '../config/env.schema';

import { auditCache } from './auditCache';

/** Helper attached to res.locals for route-level audit logging. */
export interface RequestAuditHelper {
  /**
   * Emits an audit event scoped to the current HTTP request.
   *
   * The middleware automatically injects `ipAddress` (from `req.ip` or the
   * raw socket) and `correlationId` (from the `X-Correlation-ID` header) so
   * callers do not need to supply those fields manually.
   *
   * When `AUDIT_ENABLED=false` this is a **no-op**: it returns a stub
   * `AuditEntry` with empty `id`/`hash` fields and does **not** write
   * anything to the underlying store.
   *
   * @param input - Audit event details, excluding `ipAddress` and
   *   `correlationId` (injected from the request context).
   * @returns The persisted {@link AuditEntry}, or a stub entry when the
   *   feature flag is off.
   */
  log(input: Omit<CreateAuditEntryInput, 'ipAddress' | 'correlationId'>): AuditEntry;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Locals {
      audit: RequestAuditHelper;
    }
  }
}

/**
 * Maximum length of a correlation ID accepted from the incoming request.
 * Longer values are truncated to avoid unbounded memory/storage use.
 */
const MAX_CORRELATION_ID_LENGTH = 256;

/**
 * Allowed characters for a correlation ID. Restricting this prevents
 * log-injection and header-smuggling vectors from being persisted into
 * audit metadata.
 */
const CORRELATION_ID_PATTERN = /^[A-Za-z0-9._:/]+$/;

/**
 * Normalises a correlation ID header value.
 *
 * Headers may arrive as a string, an array of strings, or undefined.
 * Only the first value is considered; invalid or overly long values are
 * dropped (returning `undefined`) rather than being persisted.
 */
function normaliseCorrelationId(raw: unknown): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_CORRELATION_ID_LENGTH) return undefined;
  if (!CORRELATION_ID_PATTERN.test(trimmed)) return undefined;
  return trimmed;
}

/**
 * Extracts the client IP address from the request, falling back to the
 * raw socket address when `req.ip` is not available. Returns `undefined`
 * when no valid string address can be derived.
 */
function extractIpAddress(req: Request): string | undefined {
  const candidate = req.ip ?? req.socket?.remoteAddress;
  if (typeof candidate !== 'string') return undefined;
  const trimmed = candidate.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Attaches `res.locals.audit` to every request.
 * Mount this before your route handlers.
 *
 * When `AUDIT_ENABLED=false` (runtime env), the attached helper is a no-op:
 * it returns a stub `AuditEntry` without writing anything to the store.
 *
 * @example
 * ```ts
 * app.use(auditMiddleware);
 * app.post('/api/v1/contracts', (req, res) => {
 *   res.locals.audit.log({ action: 'CONTRACT_CREATED', ... });
 *   res.json({ ... });
 * });
 * ```
 */
export function auditMiddleware(req: Request, res: Response, next: NextFunction): void {
  const env = validateEnv();

  if (!env.AUDIT_ENABLED) {
    // Feature flag off — attach a no-op helper so route code compiles and
    // runs without branching on the flag themselves.
    res.locals.audit = {
      log(_input: Omit<CreateAuditEntryInput, 'ipAddress' | 'correlationId'>): AuditEntry {
        return {
          id: '',
          timestamp: new Date().toISOString(),
          hash: '',
          previousHash: '',
          action: _input.action,
          severity: _input.severity,
          actor: _input.actor,
          resource: _input.resource,
          resourceId: _input.resourceId,
          metadata: _input.metadata,
        };
      },
    } satisfies RequestAuditHelper;
    next();
    return;
  }

  const ipAddress = extractIpAddress(req);
  const correlationId = normaliseCorrelationId(req.headers['x-correlation-id']);

  // Cache the normalised request context once so every log() call from this
  // request uses the same validated ipAddress/correlationId pair, even if
  // the underlying req object is mutated later in the request lifecycle.
  const requestContext = Object.freeze({ ipAddress, correlationId });

  res.locals.audit = {
    log(input: Omit<CreateAuditEntryInput, 'ipAddress' | 'correlationId'>): AuditEntry {
      return auditService.log({ ...input, ...requestContext });
    },
  } satisfies RequestAuditHelper;

  // Ensure the audit cache is bounded for this request lifecycle. This is
  // idempotent and safe to call concurrently; it only evicts expired or
  // over-capacity entries and never throws.
  if (typeof auditCache.prune === 'function') {
    auditCache.prune();
  }

  next();
}

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
 * - Correlation IDs use the shared transport-safe sanitizer.
 * - Metadata is validated, redacted, copied and deeply frozen before logging;
 *   later caller mutations cannot invalidate a persisted hash.
 * - This helper records events; route authorization and business transitions
 *   must still be enforced by the caller before logging a successful mutation.
 */

import type { Request, Response, NextFunction } from 'express';
import { auditService } from './service';
import type { AuditEntry, CreateAuditEntryInput } from './types';
import { validateEnv } from '../config/env.schema';
import { z } from 'zod';
import { AUDIT_ACTIONS } from './types';
import { CreateAuditEntrySchema } from './inputValidation';
import { redactBody } from './redact';
import { sanitizeCorrelationId } from '../utils/correlationId';
import { AppError } from '../errors/appError';

type RequestAuditInput = Omit<CreateAuditEntryInput, 'ipAddress' | 'correlationId'>;

// The HTTP write schema predates these actions in the public AuditAction type.
// Preserve every typed helper action without broadening the HTTP endpoint.
const requestAuditSchema = CreateAuditEntrySchema
  .omit({ ipAddress: true, correlationId: true })
  .extend({ action: z.enum([
    ...AUDIT_ACTIONS, 'CONTRACT_DELETED',
    'MILESTONES_CREATED', 'MILESTONES_UPDATED', 'MILESTONES_DELETED',
  ]) })
  .strip();

function freezeMetadata(value: unknown): void {
  if (value !== null && typeof value === 'object') {
    Object.values(value).forEach(freezeMetadata);
    Object.freeze(value);
  }
}

/** Prepare a detached JSON snapshot before any append can change store state. */
function prepareInput(input: RequestAuditInput): RequestAuditInput {
  try {
    const parsed = requestAuditSchema.parse(input);
    // Validation bounds depth/size and rejects cycles and non-JSON values.
    // Revalidate the serialized snapshot as getters/toJSON can alter the value.
    const snapshot: unknown = JSON.parse(JSON.stringify(parsed.metadata));
    const metadata = CreateAuditEntrySchema.shape.metadata.parse(
      redactBody(CreateAuditEntrySchema.shape.metadata.parse(snapshot)),
    );
    freezeMetadata(metadata);
    return { ...parsed, metadata };
  } catch {
    // Never expose raw values, property names or exceptions from custom getters.
    throw new AppError(400, 'validation_error', 'Invalid audit event');
  }
}

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
   * @throws A safe validation error for invalid events, even when disabled.
   *   Storage failures propagate unchanged; there is no automatic retry or
   *   deduplication. Each valid call appends a distinct event synchronously.
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
      log(input: RequestAuditInput): AuditEntry {
        const prepared = prepareInput(input);
        return Object.freeze({
          id: '',
          timestamp: new Date().toISOString(),
          hash: '',
          previousHash: '',
          ...prepared,
        });
      },
    } satisfies RequestAuditHelper;
    next();
    return;
  }

  const ipAddress = (req.ip ?? req.socket?.remoteAddress) as string | undefined;
  const correlationId = sanitizeCorrelationId(req.headers['x-correlation-id']);

  res.locals.audit = {
    log(input: Omit<CreateAuditEntryInput, 'ipAddress' | 'correlationId'>): AuditEntry {
      return auditService.log({ ...prepareInput(input), ipAddress, correlationId });
    },
  } satisfies RequestAuditHelper;

  next();
}

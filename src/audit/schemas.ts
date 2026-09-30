/**
 * @module audit/schemas
 * @description Declarative zod schemas for the audit module's request and
 * response payloads. These replace the hand-rolled parsing/validation that
 * used to live directly in `router.ts` (see PR for issue #939) so that:
 *   - every field's constraints are defined in one declarative place
 *   - invalid payloads are rejected with structured, machine-readable
 *     details (same shape as `ValidationErrorResponse` in
 *     `src/middleware/validate.middleware.ts`) instead of a bare string
 *   - the response shapes are documented and can be asserted against in
 *     tests, catching drift between the service layer and the API contract
 */

import { z } from 'zod';
import { decodeCursor } from './types';

/**
 * Maximum length allowed for free-form string identifiers (actor, resource,
 * resourceId, correlationId, ipAddress). Bounds the amount of data accepted
 * from a single request so oversized payloads are rejected deterministically
 * instead of being silently persisted or truncated downstream.
 */
export const MAX_IDENTIFIER_LENGTH = 256;

/**
 * Maximum number of keys permitted in an audit entry's `metadata` object.
 * Prevents unbounded metadata from being accepted, which would otherwise
 * allow a single request to bloat storage and downstream serialization.
 */
export const MAX_METADATA_KEYS = 64;

/**
 * Maximum serialized size (in characters) of the `metadata` object. Combined
 * with `MAX_METADATA_KEYS`, this bounds both the shape and the total size of
 * user-supplied metadata so validation is deterministic for boundary inputs.
 */
export const MAX_METADATA_BYTES = 16 * 1024;

/**
 * Maximum number of entries a single page may request. Used as the hard
 * ceiling for `buildAuditQuerySchema` callers so no route can accidentally
 * accept an unbounded `limit`.
 */
export const MAX_PAGE_LIMIT = 1000;

/**
 * Maximum offset accepted for offset-paginated queries. Bounds the amount of
 * work a single request can force the repository to skip, keeping the
 * endpoint deterministic under adverse input.
 */
export const MAX_PAGE_OFFSET = 1_000_000;

/**
 * Maximum length of a cursor string. Cursors are opaque base64 payloads; a
 * hard cap rejects pathological inputs before they reach `decodeCursor`.
 */
export const MAX_CURSOR_LENGTH = 512;

/**
 * Maximum length of an ISO date string accepted for `from`/`to`. ISO-8601
 * timestamps are well under this bound; anything longer is rejected as
 * invalid rather than parsed.
 */
export const MAX_ISO_DATE_LENGTH = 64;

/** Mirrors the `AuditAction` union in `./types.ts`. Keep these in sync. */
export const AUDIT_ACTIONS = [
  'CONTRACT_CREATED', 'CONTRACT_UPDATED', 'CONTRACT_CANCELLED', 'CONTRACT_COMPLETED',
  'PAYMENT_INITIATED', 'PAYMENT_RELEASED', 'PAYMENT_DISPUTED',
  'REPUTATION_UPDATED',
  'USER_CREATED', 'USER_UPDATED', 'USER_DELETED',
  'AUTH_LOGIN', 'AUTH_LOGOUT', 'AUTH_FAILED',
  'AUTH_LOCKOUT_TRIGGERED', 'AUTH_LOCKOUT_RELEASED',
  'ADMIN_ACTION',
  'ENDPOINT_ACCESS', 'ENDPOINT_MUTATION',
  'DEPLOYMENT_PROMOTED', 'DEPLOYMENT_ROLLED_BACK',
] as const;

/** Mirrors the `AuditSeverity` union in `./types.ts`. */
export const AUDIT_SEVERITIES = ['INFO', 'WARNING', 'CRITICAL'] as const;

export const auditActionSchema = z.enum(AUDIT_ACTIONS);
export const auditSeveritySchema = z.enum(AUDIT_SEVERITIES);

/**
 * Bounded identifier schema shared by all free-form string fields. Enforces
 * non-empty, trimmed, and length-bounded values so duplicate/whitespace-only
 * inputs are rejected deterministically.
 */
const identifierSchema = (fieldName: string) =>
  z
    .string()
    .min(1, `${fieldName} must not be empty`)
    .max(MAX_IDENTIFIER_LENGTH, `${fieldName} must be at most ${MAX_IDENTIFIER_LENGTH} characters`)
    .refine((value) => value.trim().length > 0, { message: `${fieldName} must not be blank` });

// ---------------------------------------------------------------------------
// Request schemas
// ---------------------------------------------------------------------------

/**
 * `POST /api/v1/audit` request body.
 * `metadata` defaults to `{}` when omitted (previously an omitted metadata
 * field silently passed `undefined` through to the repository; defaulting
 * to an empty object is a strictly safer, additive change).
 */
const metadataSchema = z
  .record(z.unknown())
  .refine((value) => Object.keys(value).length <= MAX_METADATA_KEYS, {
    message: `metadata must contain at most ${MAX_METADATA_KEYS} keys`,
  })
  .refine(
    (value) => {
      try {
        return JSON.stringify(value).length <= MAX_METADATA_BYTES;
      } catch {
        return false;
      }
    },
    { message: `metadata must serialize to at most ${MAX_METADATA_BYTES} characters` },
  );

export const createAuditEntryBodySchema = z.object({
  action: auditActionSchema,
  severity: auditSeveritySchema,
  actor: identifierSchema('actor'),
  resource: identifierSchema('resource'),
  resourceId: identifierSchema('resourceId'),
  metadata: metadataSchema.optional().default({}),
  ipAddress: identifierSchema('ipAddress').optional(),
  correlationId: identifierSchema('correlationId').optional(),
});

export type CreateAuditEntryBody = z.infer<typeof createAuditEntryBodySchema>;

const isoDateStringSchema = (fieldName: string) =>
  z
    .string()
    .max(MAX_ISO_DATE_LENGTH, `Invalid ${fieldName} timestamp`)
    .refine((value) => !Number.isNaN(Date.parse(value)), { message: `Invalid ${fieldName} timestamp` })
    .transform((value) => new Date(Date.parse(value)).toISOString());

const positiveIntStringSchema = (message: string) =>
  z
    .string()
    .refine((value) => {
      const parsed = Number.parseInt(value, 10);
      return Number.isFinite(parsed) && String(parsed) === value.trim() && parsed >= 1;
    }, { message })
    .transform((value) => Number.parseInt(value, 10));

const nonNegativeIntStringSchema = (message: string) =>
  z
    .string()
    .refine((value) => {
      const parsed = Number.parseInt(value, 10);
      return Number.isFinite(parsed) && String(parsed) === value.trim() && parsed >= 0;
    }, { message })
    .transform((value) => Number.parseInt(value, 10));

const cursorSchema = z
  .string()
  .max(MAX_CURSOR_LENGTH, 'Invalid cursor format')
  .refine(
    (value) => {
      try {
        decodeCursor(value);
        return true;
      } catch {
        return false;
      }
    },
    { message: 'Invalid cursor format' },
  );

/**
 * The old ad hoc parser used truthy checks (`if (action && ...)`) for
 * action/severity/actor/resource/resourceId/cursor, so `?cursor=` (an empty
 * string) was silently treated as "not provided" for those fields — but NOT
 * for limit/offset/from/to, which used explicit `=== undefined` checks and
 * so rejected an empty string as invalid input. Preserving that exact split
 * (rather than "helpfully" making every field consistent) keeps this
 * refactor behaviour-neutral for existing callers relying on the old quirk.
 */
const emptyStringToUndefined = <T extends z.ZodTypeAny>(schema: T) =>
  z.preprocess((value) => (value === '' ? undefined : value), schema.optional());

/**
 * Query-string schema for `GET /api/v1/audit` and `GET /api/v1/audit/export`.
 * Both routes share the same filter fields but enforce different `limit`
 * ceilings and defaults, so this is a factory rather than a single schema —
 * mirrors the previous `parseAuditQuery(req, { defaultLimit, maxLimit })`.
 */
export function buildAuditQuerySchema(options: { maxLimit: number; defaultLimit?: number }) {
  if (!Number.isInteger(options.maxLimit) || options.maxLimit < 1 || options.maxLimit > MAX_PAGE_LIMIT) {
    throw new RangeError(`maxLimit must be an integer between 1 and ${MAX_PAGE_LIMIT}`);
  }
  if (options.defaultLimit !== undefined && (!Number.isInteger(options.defaultLimit) || options.defaultLimit < 1 || options.defaultLimit > options.maxLimit)) {
    throw new RangeError('defaultLimit must be an integer between 1 and maxLimit');
  }

  return z.object({
    action: emptyStringToUndefined(auditActionSchema),
    severity: emptyStringToUndefined(auditSeveritySchema),
    actor: emptyStringToUndefined(identifierSchema('actor')),
    resource: emptyStringToUndefined(identifierSchema('resource')),
    resourceId: emptyStringToUndefined(identifierSchema('resourceId')),
    from: isoDateStringSchema('from').optional(),
    to: isoDateStringSchema('to').optional(),
    limit: positiveIntStringSchema('Invalid limit')
      .optional()
      .transform((value) => (value === undefined ? options.defaultLimit : Math.min(value, options.maxLimit))),
    offset: nonNegativeIntStringSchema('Invalid offset')
      .optional()
      .transform((value) => {
        const resolved = value ?? 0;
        if (resolved > MAX_PAGE_OFFSET) {
          throw new Error(`Invalid offset: must be at most ${MAX_PAGE_OFFSET}`);
        }
        return resolved;
      }),
    cursor: emptyStringToUndefined(cursorSchema),
  });
}

export type AuditQueryParams = z.infer<ReturnType<typeof buildAuditQuerySchema>>;

// ---------------------------------------------------------------------------
// Response schemas
// ---------------------------------------------------------------------------

/** Mirrors `AuditEntry` in `./types.ts`. */
export const auditEntryResponseSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  action: auditActionSchema,
  severity: auditSeveritySchema,
  actor: z.string(),
  resource: z.string(),
  resourceId: z.string(),
  metadata: z.record(z.unknown()),
  ipAddress: z.string().optional(),
  correlationId: z.string().optional(),
  hash: z.string(),
  previousHash: z.string(),
});

/** Mirrors `AuditQueryResult` in `./types.ts` (the cursor-paginated shape). */
export const auditQueryResultResponseSchema = z.object({
  entries: z.array(auditEntryResponseSchema),
  count: z.number(),
  limit: z.number(),
  nextCursor: z.string().optional(),
});

/** Mirrors the legacy offset-paginated `GET /` response shape. */
export const auditLegacyQueryResponseSchema = z.object({
  entries: z.array(auditEntryResponseSchema),
  count: z.number(),
  limit: z.number(),
  offset: z.number(),
});

/** Mirrors `IntegrityReport` in `./types.ts`. */
export const integrityReportResponseSchema = z.object({
  valid: z.boolean(),
  totalEntries: z.number(),
  firstCorruptedIndex: z.number().optional(),
  firstCorruptedId: z.string().optional(),
  checkedAt: z.string(),
});

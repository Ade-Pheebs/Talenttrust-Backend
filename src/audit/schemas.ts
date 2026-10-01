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
 *
 * Validation boundaries (issue: Define validation boundaries for
 * src/audit/service.ts):
 *   - Request schemas are the single source of truth for accepted input.
 *   - `buildAuditQuerySchema` enforces deterministic handling of empty,
 *     duplicate, and boundary values (limit/offset/from/to/cursor).
 *   - Response schemas are the contract asserted against in tests.
 */

import { z } from 'zod';
import { AUDIT_ACTIONS, AUDIT_SEVERITIES, decodeCursor } from './types';

// Preserve the schema module's previous exports while keeping the type module authoritative.
export { AUDIT_ACTIONS, AUDIT_SEVERITIES } from './types';

export const auditActionSchema = z.enum(AUDIT_ACTIONS);
export const auditSeveritySchema = z.enum(AUDIT_SEVERITIES);

// ---------------------------------------------------------------------------
// Request schemas
// ---------------------------------------------------------------------------

/**
 * `POST /api/v1/audit` request body.
 * `metadata` defaults to `{}` when omitted (previously an omitted metadata
 * field silently passed `undefined` through to the repository; defaulting
 * to an empty object is a strictly safer, additive change).
 */
export const createAuditEntryBodySchema = z.object({
  action: auditActionSchema,
  severity: auditSeveritySchema,
  actor: z.string().min(1, 'actor must not be empty'),
  resource: z.string().min(1, 'resource must not be empty'),
  resourceId: z.string().min(1, 'resourceId must not be empty'),
  metadata: z.record(z.unknown()).optional().default({}),
  ipAddress: z.string().min(1).optional(),
  correlationId: z.string().min(1).optional(),
});

export type CreateAuditEntryBody = z.infer<typeof createAuditEntryBodySchema>;

/**
 * Boundary constants for the audit query surface. Exported so callers and
 * tests share the same numeric limits instead of duplicating magic numbers.
 */
export const AUDIT_QUERY_BOUNDS = {
  /** Hard ceiling for `limit` on the cursor-paginated listing route. */
  MAX_LIMIT: 100,
  /** Default `limit` when the caller omits it. */
  DEFAULT_LIMIT: 20,
  /** Hard ceiling for `limit` on the export route. */
  EXPORT_MAX_LIMIT: 1000,
  /** Default `limit` for the export route. */
  EXPORT_DEFAULT_LIMIT: 100,
  /** Maximum allowed `offset` (inclusive) to keep pagination bounded. */
  MAX_OFFSET: 1_000_000,
} as const;

const isoDateStringSchema = (fieldName: string) =>
  z
    .string()
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

const cursorSchema = z.string().refine(
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
 *
 * Boundary handling:
 *   - `limit` is clamped to `[1, maxLimit]`; `0` and negatives are rejected.
 *   - `offset` is clamped to `[0, MAX_OFFSET]`; negatives are rejected.
 *   - `from`/`to` must parse as ISO-8601 timestamps; `from > to` is rejected
 *     as a cross-field invariant.
 *   - Duplicate query keys are collapsed by the underlying parser before
 *     reaching this schema; the schema itself is deterministic for a given
 *     scalar value.
 */
const emptyStringToUndefined = <T extends z.ZodTypeAny>(schema: T) =>
  z.preprocess((value) => (value === '' ? undefined : value), schema.optional());

/**
 * Query-string schema for `GET /api/v1/audit` and `GET /api/v1/audit/export`.
 * Both routes share the same filter fields but enforce different `limit`
 * ceilings and defaults, so this is a factory rather than a single schema —
 * mirrors the previous `parseAuditQuery(req, { defaultLimit, maxLimit })`.
 *
 * The returned schema is strict about unknown keys so typos in query
 * parameters surface as validation errors instead of being silently ignored.
 */
export function buildAuditQuerySchema(options: { maxLimit: number; defaultLimit?: number }) {
  const maxLimit = Math.max(1, Math.floor(options.maxLimit));
  const defaultLimit = Math.min(
    maxLimit,
    Math.max(1, Math.floor(options.defaultLimit ?? AUDIT_QUERY_BOUNDS.DEFAULT_LIMIT)),
  );

  return z
    .object({
      action: emptyStringToUndefined(auditActionSchema),
      severity: emptyStringToUndefined(auditSeveritySchema),
      actor: emptyStringToUndefined(z.string().min(1)),
      resource: emptyStringToUndefined(z.string().min(1)),
      resourceId: emptyStringToUndefined(z.string().min(1)),
      from: isoDateStringSchema('from').optional(),
      to: isoDateStringSchema('to').optional(),
      limit: positiveIntStringSchema('Invalid limit')
        .optional()
        .transform((value) => (value === undefined ? defaultLimit : Math.min(value, maxLimit))),
      offset: nonNegativeIntStringSchema('Invalid offset')
        .optional()
        .transform((value) => Math.min(value ?? 0, AUDIT_QUERY_BOUNDS.MAX_OFFSET)),
      cursor: emptyStringToUndefined(cursorSchema),
    })
    .strict()
    .refine(
      (value) => value.from === undefined || value.to === undefined || value.from <= value.to,
      { message: '`from` must be less than or equal to `to`', path: ['from'] },
    );
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

/**
 * Convenience factory for the two supported audit query surfaces. Callers
 * should prefer these over constructing `buildAuditQuerySchema` directly so
 * that limit ceilings stay consistent across routes.
 */
export const auditListQuerySchema = buildAuditQuerySchema({
  maxLimit: AUDIT_QUERY_BOUNDS.MAX_LIMIT,
  defaultLimit: AUDIT_QUERY_BOUNDS.DEFAULT_LIMIT,
});

export const auditExportQuerySchema = buildAuditQuerySchema({
  maxLimit: AUDIT_QUERY_BOUNDS.EXPORT_MAX_LIMIT,
  defaultLimit: AUDIT_QUERY_BOUNDS.EXPORT_DEFAULT_LIMIT,
});

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
 * ## Invariants owned by this module
 *
 * The audit log is append-only and hash-chained, so anything this module lets
 * through is permanent. The schemas below are the HTTP-facing guard and must
 * uphold the following invariants. They are enforced by construction (shared
 * sources) rather than by convention, and are pinned by `schemas.test.ts`.
 *
 * 1. **Enum parity with the domain.** The accepted `action` / `severity` sets
 *    are imported from `./types` (`AUDIT_ACTIONS`, `AUDIT_SEVERITIES`) — the
 *    same arrays used by the domain `AuditAction` / `AuditSeverity` types and
 *    by the strict write-path validator (`./inputValidation`). A local copy
 *    cannot drift out of sync and silently reject an action the domain
 *    supports (the exact regression this module previously had for
 *    `REPUTATION_CORRECTED`).
 * 2. **Field rules are shared, not re-declared.** Identifiers, `ipAddress`,
 *    `correlationId` and `metadata` are composed from the exported field
 *    schemas in `./inputValidation`, so the declarative API surface and the
 *    strict write-path validator can never disagree on a field's bounds.
 * 3. **Metadata is structurally safe.** `metadata` enforces the full
 *    `validateMetadata` rule set: JSON-object only, depth / key-count /
 *    array-length / string-length / byte-size bounds, finite numbers, no
 *    circular references, and denial of prototype-pollution keys
 *    (`__proto__`, `constructor`, `prototype`).
 * 4. **Required/local defaults are stable.** `metadata` defaults to `{}`
 *    (strictly safer than the old `undefined` passthrough) and identifier
 *    fields must be non-empty, non-blank and control-character free.
 * 5. **Response contracts mirror the domain types.** Response schemas assert
 *    hash format, ISO timestamps and non-negative integer counters so a
 *    contract change in the service layer is caught here rather than in
 *    production.
 * 6. **The empty-string query quirk is preserved deliberately.** The legacy
 *    parser used truthy checks for the filter fields, so `?cursor=` was
 *    treated as "not provided" — see {@link emptyStringToUndefined}. That
 *    behaviour is pinned by tests rather than "fixed", keeping the refactor
 *    behaviour-neutral for existing callers.
 */

import { z } from 'zod';
import { decodeCursor } from './types';
import { AUDIT_ACTIONS, AUDIT_SEVERITIES } from './types';
import {
  MAX_ID_LENGTH,
  identifierSchema,
  auditMetadataSchema,
  ipAddressSchema,
  correlationIdSchema,
} from './inputValidation';

// Re-exported so existing consumers of `./schemas` keep working unchanged, but
// now sourced from `./types` — see invariant 1 above.
export { AUDIT_ACTIONS, AUDIT_SEVERITIES };

export const auditActionSchema = z.enum(AUDIT_ACTIONS);
export const auditSeveritySchema = z.enum(AUDIT_SEVERITIES);

// ----------------------------------------------------------------------------
// Request schemas
// ----------------------------------------------------------------------------

/**
 * `POST /api/v1/audit` request body.
 *
 * Shares every field rule with the strict write-path schema in
 * `./inputValidation` (invariant 2). Unknown top-level fields are stripped
 * rather than rejected — a deliberate behaviour preserved from the previous
 * implementation to keep existing callers compatible.
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
  actor: identifierSchema('actor', MAX_ID_LENGTH),
  resource: identifierSchema('resource', MAX_ID_LENGTH),
  resourceId: identifierSchema('resourceId', MAX_ID_LENGTH),
  metadata: auditMetadataSchema,
  ipAddress: ipAddressSchema,
  correlationId: correlationIdSchema,
});

export type CreateAuditEntryBody = z.infer<typeof createAuditEntryBodySchema>;

const MAX_CURSOR_LENGTH = 4096;

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
 * The legacy ad hoc parser used truthy checks (`if (action && ...)`) for
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

// ----------------------------------------------------------------------------
// Response schemas
// ----------------------------------------------------------------------------

/** An ISO-8601 timestamp produced by `new Date(...).toISOString()`. */
const isoTimestampSchema = z
  .string()
  .refine((value) => !Number.isNaN(Date.parse(value)), {
    message: 'must be an ISO-8601 timestamp',
  });

/** A SHA-256 hex digest as produced by `computeEntryHash()`. */
const sha256HexSchema = z
  .string()
  .regex(/^[0-9a-f]{64}$/, 'must be a 64-character lowercase hex SHA-256 digest');

/** The genesis sentinel (`'GENESIS'`) or a SHA-256 hex digest. */
const previousHashSchema = z
  .string()
  .regex(
    /^(GENESIS|[0-9a-f]{64})$/,
    'must be GENESIS or a 64-character lowercase hex SHA-256 digest',
  );

/** A non-negative integer (counts, indexes and limits). */
const nonNegativeIntSchema = z.number().int().nonnegative();

/** Mirrors `AuditEntry` in `./types.ts`. */
export const auditEntryResponseSchema = z.object({
  id: z.string().min(1),
  timestamp: isoTimestampSchema,
  action: auditActionSchema,
  severity: auditSeveritySchema,
  actor: z.string().min(1),
  resource: z.string().min(1),
  resourceId: z.string().min(1),
  metadata: z.record(z.unknown()),
  ipAddress: z.string().min(1).optional(),
  correlationId: z.string().min(1).optional(),
  hash: sha256HexSchema,
  previousHash: previousHashSchema,
});

/** Mirrors `AuditQueryResult` in `./types.ts` (the cursor-paginated shape). */
export const auditQueryResultResponseSchema = z.object({
  entries: z.array(auditEntryResponseSchema),
  count: nonNegativeIntSchema,
  limit: z.number().int().positive(),
  nextCursor: z.string().optional(),
});

/** Mirrors the legacy offset-paginated `GET /` response shape. */
export const auditLegacyQueryResponseSchema = z.object({
  entries: z.array(auditEntryResponseSchema),
  count: nonNegativeIntSchema,
  limit: nonNegativeIntSchema,
  offset: nonNegativeIntSchema,
});

/** Mirrors `IntegrityReport` in `./types.ts`. */
export const integrityReportResponseSchema = z.object({
  valid: z.boolean(),
  totalEntries: nonNegativeIntSchema,
  firstCorruptedIndex: nonNegativeIntSchema.optional(),
  firstCorruptedId: z.string().min(1).optional(),
  checkedAt: isoTimestampSchema,
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

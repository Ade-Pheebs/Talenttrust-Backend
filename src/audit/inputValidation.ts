/**
 * @module audit/inputValidation
 * @description Deterministic input validation for audit log entries.
 *
 * ## Design principles
 *
 * 1. **Deterministic** — the same input always produces the same result.
 *    There is no randomness, no I/O, no state. Pure synchronous function.
 * 2. **All-errors-at-once** — every field violation is collected before
 *    throwing, so callers receive a complete picture instead of fixing one
 *    field at a time. The structured `AuditValidationError` carries a
 *    `fields` array with per-field path and message.
 * 3. **Permanent vs transient failures** — validation failures are permanent
 *    (same input will always fail); they are never retried. Repository write
 *    failures may be transient and are handled with `withRetry` in the
 *    service layer.
 * 4. **Boundary enforcement** — validation runs at the earliest possible
 *    point (before `repository.append`), so the store and hash chain never
 *    receive malformed data, and partial writes cannot corrupt the chain.
 * 5. **No PII leakage** — error messages reference field names only, never
 *    field values, preventing accidental logging of sensitive input.
 *
 * ## Integration
 *
 * `validateAuditInput` is called inside `AuditService.log()` before any
 * repository interaction. Callers outside the service (e.g. the POST router
 * handler) can also call it directly for early rejection.
 *
 * ## Field rules
 *
 * ### Required string fields (action, severity, actor, resource, resourceId)
 * - Must be present (not undefined / null).
 * - Must be a non-empty string after trimming.
 * - `action` must be a member of `VALID_ACTIONS`.
 * - `severity` must be a member of `VALID_SEVERITIES`.
 * - `actor`, `resource`, `resourceId` have a max length of 256 characters.
 *
 * ### Optional string fields (ipAddress, correlationId)
 * - If present, must be a non-empty string (whitespace-only fails).
 * - `ipAddress`: max length 45 (IPv6 upper bound).
 * - `correlationId`: max length 256.
 *
 * ### metadata
 * - Must be present.
 * - Must be a plain object (not null, not an array, not a primitive).
 * - Keys must be strings (always true in plain objects, enforced at type level).
 * - Values must be JSON-serialisable (validated via `JSON.stringify`).
 *
 * @security
 * - Error messages never include field values — only field names and
 *   structural constraints.
 * - The validator is the single choke-point for all audit input; no
 *   repository call happens before it passes.
 */

import { AppError, APP_ERROR_CODES } from '../errors/appError';
import type { CreateAuditEntryInput, AuditAction, AuditSeverity } from './types';

// ─── Valid enum sets ──────────────────────────────────────────────────────────

/**
 * The complete set of accepted audit action strings.
 * Kept in sync with the `AuditAction` union type in `types.ts`.
 * Any addition to the union MUST be reflected here.
 */
export const VALID_AUDIT_ACTIONS: ReadonlySet<AuditAction> = new Set<AuditAction>([
  'CONTRACT_CREATED',
  'CONTRACT_UPDATED',
  'CONTRACT_CANCELLED',
  'CONTRACT_COMPLETED',
  'PAYMENT_INITIATED',
  'PAYMENT_RELEASED',
  'PAYMENT_DISPUTED',
  'REPUTATION_UPDATED',
  'USER_CREATED',
  'USER_UPDATED',
  'USER_DELETED',
  'AUTH_LOGIN',
  'AUTH_LOGOUT',
  'AUTH_FAILED',
  'ADMIN_ACTION',
  'ENDPOINT_ACCESS',
  'ENDPOINT_MUTATION',
  'DEPLOYMENT_PROMOTED',
  'DEPLOYMENT_ROLLED_BACK',
]);

/**
 * The complete set of accepted audit severity strings.
 * Kept in sync with the `AuditSeverity` union type in `types.ts`.
 */
export const VALID_AUDIT_SEVERITIES: ReadonlySet<AuditSeverity> = new Set<AuditSeverity>([
  'INFO',
  'WARNING',
  'CRITICAL',
]);

// ─── Field-level validation issue ────────────────────────────────────────────

/**
 * A single field-level validation failure.
 * `field` is the dot-notation path to the invalid field (e.g. `"actor"`,
 * `"metadata"`). `message` describes the constraint that was violated.
 *
 * @example
 * { field: 'action', message: 'action must be a valid AuditAction' }
 * { field: 'metadata', message: 'metadata must be a plain object' }
 */
export interface AuditValidationIssue {
  field: string;
  message: string;
}

// ─── Structured error type ────────────────────────────────────────────────────

/**
 * Thrown by `validateAuditInput` when one or more input fields are invalid.
 *
 * ## Properties
 * - `statusCode` — 400 (client error, permanent failure).
 * - `code` — `"validation_error"` (stable machine-readable code).
 * - `issues` — ordered array of `AuditValidationIssue`, one per violation.
 *
 * ## Behaviour guarantees
 * - The same invalid input always throws the same set of issues (deterministic).
 * - Issues are collected across all fields before throwing (not fail-fast).
 * - The error message is safe to log: no field values, only field names.
 * - Callers should NOT retry on this error — it is a permanent client failure.
 *
 * @example
 * ```ts
 * try {
 *   validateAuditInput(rawBody);
 * } catch (err) {
 *   if (err instanceof AuditValidationError) {
 *     res.status(400).json({ error: err.message, issues: err.issues });
 *   }
 * }
 * ```
 */
export class AuditValidationError extends AppError {
  /** All field-level violations that caused this error. */
  public readonly issues: readonly AuditValidationIssue[];

  constructor(issues: AuditValidationIssue[]) {
    const summary = issues.map((i) => `${i.field}: ${i.message}`).join('; ');
    super(400, APP_ERROR_CODES.VALIDATION_ERROR, `Audit input validation failed: ${summary}`);
    this.name = 'AuditValidationError';
    this.issues = Object.freeze([...issues]);
  }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/** True when `value` is a plain (non-null, non-array) object. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** True when `value` can be round-tripped through JSON without data loss or error. */
function isJsonSerializable(value: unknown): boolean {
  try {
    JSON.stringify(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validates a required string field: present, string type, non-empty after trim,
 * and within `maxLength` characters.
 *
 * @returns An issue if the field is invalid, or null if valid.
 */
function checkRequiredString(
  value: unknown,
  field: string,
  maxLength: number,
): AuditValidationIssue | null {
  if (value === undefined || value === null) {
    return { field, message: `${field} is required` };
  }
  if (typeof value !== 'string') {
    return { field, message: `${field} must be a string` };
  }
  if (value.trim().length === 0) {
    return { field, message: `${field} must not be empty` };
  }
  if (value.length > maxLength) {
    return { field, message: `${field} must not exceed ${maxLength} characters` };
  }
  return null;
}

/**
 * Validates an optional string field: if present, must be a non-empty string
 * within `maxLength` characters.
 *
 * @returns An issue if the field is invalid, or null if valid (or absent).
 */
function checkOptionalString(
  value: unknown,
  field: string,
  maxLength: number,
): AuditValidationIssue | null {
  if (value === undefined || value === null) {
    return null; // optional — absence is valid
  }
  if (typeof value !== 'string') {
    return { field, message: `${field} must be a string when provided` };
  }
  if (value.trim().length === 0) {
    return { field, message: `${field} must not be an empty string when provided` };
  }
  if (value.length > maxLength) {
    return { field, message: `${field} must not exceed ${maxLength} characters` };
  }
  return null;
}

// ─── Public validation function ───────────────────────────────────────────────

/**
 * Validates a raw, untrusted value as a `CreateAuditEntryInput`.
 *
 * All fields are checked in a single pass. Every violation is collected
 * into an `issues` array before the error is thrown, giving callers a
 * complete list of problems.
 *
 * ## Determinism guarantee
 * This function is pure: no I/O, no Date.now(), no random. The same input
 * always produces the same output or the same error.
 *
 * ## Error path
 * Throws `AuditValidationError` (HTTP 400, code `"validation_error"`) when
 * any field is invalid. This is a **permanent failure** — do not retry on
 * this error.
 *
 * ## Success path
 * Returns a typed `CreateAuditEntryInput` value. The returned object is a
 * shallow copy with only the known fields so unknown properties are dropped.
 *
 * @param input - Untrusted input (e.g. `req.body` from the POST handler).
 * @returns Validated and narrowed `CreateAuditEntryInput`.
 * @throws {AuditValidationError} When one or more fields are invalid.
 *
 * @example
 * ```ts
 * // In the POST /api/v1/audit handler:
 * const validated = validateAuditInput(req.body);
 * const entry = service.log(validated);
 * ```
 *
 * @example
 * ```ts
 * // In AuditService.log():
 * const validated = validateAuditInput(input);
 * return this.repository.append(validated);
 * ```
 */
export function validateAuditInput(input: unknown): CreateAuditEntryInput {
  const issues: AuditValidationIssue[] = [];

  // ── Structural guard ─────────────────────────────────────────────────────
  if (!isPlainObject(input)) {
    throw new AuditValidationError([
      { field: 'input', message: 'audit input must be a plain object' },
    ]);
  }

  const raw = input as Record<string, unknown>;

  // ── Required: action ────────────────────────────────────────────────────
  const actionIssue = checkRequiredString(raw['action'], 'action', 64);
  if (actionIssue) {
    issues.push(actionIssue);
  } else if (!VALID_AUDIT_ACTIONS.has(raw['action'] as AuditAction)) {
    issues.push({
      field: 'action',
      message: `action must be a valid AuditAction`,
    });
  }

  // ── Required: severity ──────────────────────────────────────────────────
  const severityIssue = checkRequiredString(raw['severity'], 'severity', 32);
  if (severityIssue) {
    issues.push(severityIssue);
  } else if (!VALID_AUDIT_SEVERITIES.has(raw['severity'] as AuditSeverity)) {
    issues.push({
      field: 'severity',
      message: `severity must be one of: INFO, WARNING, CRITICAL`,
    });
  }

  // ── Required: actor ─────────────────────────────────────────────────────
  const actorIssue = checkRequiredString(raw['actor'], 'actor', 256);
  if (actorIssue) issues.push(actorIssue);

  // ── Required: resource ──────────────────────────────────────────────────
  const resourceIssue = checkRequiredString(raw['resource'], 'resource', 256);
  if (resourceIssue) issues.push(resourceIssue);

  // ── Required: resourceId ────────────────────────────────────────────────
  const resourceIdIssue = checkRequiredString(raw['resourceId'], 'resourceId', 256);
  if (resourceIdIssue) issues.push(resourceIdIssue);

  // ── Required: metadata ──────────────────────────────────────────────────
  if (raw['metadata'] === undefined || raw['metadata'] === null) {
    issues.push({ field: 'metadata', message: 'metadata is required' });
  } else if (!isPlainObject(raw['metadata'])) {
    issues.push({
      field: 'metadata',
      message: 'metadata must be a plain object (not null, not an array, not a primitive)',
    });
  } else if (!isJsonSerializable(raw['metadata'])) {
    issues.push({
      field: 'metadata',
      message: 'metadata must be JSON-serialisable',
    });
  }

  // ── Optional: ipAddress ─────────────────────────────────────────────────
  const ipIssue = checkOptionalString(raw['ipAddress'], 'ipAddress', 45);
  if (ipIssue) issues.push(ipIssue);

  // ── Optional: correlationId ─────────────────────────────────────────────
  const corrIssue = checkOptionalString(raw['correlationId'], 'correlationId', 256);
  if (corrIssue) issues.push(corrIssue);

  // ── Throw if any issues found ────────────────────────────────────────────
  if (issues.length > 0) {
    throw new AuditValidationError(issues);
  }

  // ── Return validated, narrowed object ───────────────────────────────────
  // Unknown extra fields are dropped — only the known contract fields survive.
  const validated: CreateAuditEntryInput = {
    action: raw['action'] as AuditAction,
    severity: raw['severity'] as AuditSeverity,
    actor: raw['actor'] as string,
    resource: raw['resource'] as string,
    resourceId: raw['resourceId'] as string,
    metadata: raw['metadata'] as Record<string, unknown>,
  };

  // Include optional fields only if they are present and valid.
  if (typeof raw['ipAddress'] === 'string') {
    validated.ipAddress = raw['ipAddress'];
  }
  if (typeof raw['correlationId'] === 'string') {
    validated.correlationId = raw['correlationId'];
  }

  return validated;
}

/**
 * @module audit/redact
 * @description Deterministic redaction rules for audit log metadata.
 *
 * ## Redaction policy
 *
 * ### HTTP headers
 * Any header whose name (lowercased) matches one of the following is replaced
 * entirely with `'[REDACTED]'` before being written to the audit log:
 *   - `authorization`
 *   - `cookie` / `set-cookie`
 *   - `x-api-key`, `x-auth-token`, `x-access-token`
 *
 * ### Request body / query / metadata fields
 * Any object key whose name (lowercased) contains one of the following
 * substrings has its value replaced with `'[REDACTED]'`:
 *   - `password`
 *   - `secret`
 *   - `token`
 *   - `credential`
 *   - `apikey` / `api_key`
 *   - `private`
 *
 * Redaction is applied **recursively** to nested objects and array elements.
 * Array indices are never treated as sensitive keys.
 *
 * ### Email addresses
 * String values that match the pattern `localpart@domain` are partially masked:
 * the first three characters of the local part are retained and the remainder
 * is replaced with `***` (e.g. `alice@example.com` → `ali***@example.com`,
 * `ab@host.io` → `ab***@host.io`).
 *
 * Masking is applied during body/metadata traversal but NOT to headers (header
 * values are either fully redacted or kept verbatim).
 *
 * ### Primitives
 * Numbers, booleans, and `null` pass through unmodified.
 *
 * ## State invariants and safety guarantees
 *
 * ### Circular reference protection
 * The `redactBody` function detects circular references using a `WeakSet` to
 * track visited objects. When a circular reference is detected, the offending
 * value is replaced with `'[REDACTED]'` to prevent stack overflow and ensure
 * the audit log operation completes safely.
 *
 * ### Depth limiting
 * To prevent stack overflow from deeply nested structures, `redactBody` enforces
 * a maximum recursion depth of 100 levels. Values beyond this depth are replaced
 * with `'[REDACTED]'`. This is a defensive limit; legitimate audit data should
 * not exceed this depth.
 *
 * ### Safe failure mode
 * All redaction functions handle invalid or malformed inputs gracefully:
 * - `redactHeaders` guards against null/undefined or non-object inputs
 * - `buildAuditMetadata` validates and coerces primitive inputs to safe defaults
 * - Processing errors are caught and logged without crashing the request path
 * - When invariants are violated (circular refs, depth limit), the function
 *   returns `'[REDACTED]'` rather than throwing
 *
 * ### Immutability
 * All functions return new objects and never mutate their inputs. This is
 * enforced by implementation and verified by tests.
 *
 * @security
 * - Redaction is deterministic: the same input always produces the same output.
 * - `Authorization` header values are NEVER persisted under any circumstances.
 * - This module has no side-effects; all functions are pure transformations.
 * - Circular references and deep nesting cannot cause stack overflow or crashes.
 * - Invalid inputs are handled gracefully without exposing sensitive data.
 */

/** Sentinel written in place of any redacted value. */
export const REDACTED = '[REDACTED]';

/** Header names (lowercased) that must be fully suppressed. */
const SENSITIVE_HEADER_NAMES = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-access-token',
]);

/**
 * Substrings that mark a body/query/metadata key as sensitive.
 * Checked against the lower-cased key name.
 */
const SENSITIVE_KEY_FRAGMENTS = [
  'password',
  'secret',
  'token',
  'credential',
  'apikey',
  'api_key',
  'private',
];

/** Matches a simple `local@domain` email pattern. */
const EMAIL_PATTERN = /^([^@\s]{1,64})@([^@\s]+\.[^@\s]+)$/;

/**
 * Maximum recursion depth for redactBody to prevent stack overflow.
 * This is a defensive limit; legitimate audit data should not exceed this depth.
 */
export const MAX_REDACTION_DEPTH = 100;

// ─── Predicate helpers ───────────────────────────────────────────────────────

/**
 * Returns `true` when the given header name should be fully redacted.
 *
 * @param name - Raw header name (case-insensitive).
 */
export function isSensitiveHeader(name: string): boolean {
  return SENSITIVE_HEADER_NAMES.has(name.toLowerCase());
}

/**
 * Returns `true` when the given object key suggests a sensitive value.
 *
 * @param key - Object key string (case-insensitive).
 */
export function isSensitiveKey(key: string): boolean {
  const lower = key.toLowerCase();
  return SENSITIVE_KEY_FRAGMENTS.some((fragment) => lower.includes(fragment));
}

// ─── Transformation helpers ──────────────────────────────────────────────────

/**
 * Partially masks an email address to protect PII while retaining minimal
 * identifiability for audit correlation.
 *
 * Non-email strings are returned unchanged.
 *
 * @example
 * maskEmail('alice@example.com') // → 'ali***@example.com'
 * maskEmail('ab@host.io')        // → 'ab***@host.io'
 * maskEmail('not-an-email')      // → 'not-an-email'
 */
export function maskEmail(value: string): string {
  const match = EMAIL_PATTERN.exec(value);
  if (!match) return value;
  const [, local, domain] = match;
  const prefix = local.slice(0, Math.min(3, local.length));
  return `${prefix}***@${domain}`;
}

/**
 * Produces a sanitised copy of an HTTP headers object.
 *
 * Sensitive header values are replaced with `'[REDACTED]'`; all other
 * headers are copied verbatim. The original object is never mutated.
 *
 * Invalid or non-object inputs are handled gracefully to prevent crashes.
 *
 * @param headers - Raw headers from `req.headers`.
 * @returns A flat object safe for audit storage.
 */
export function redactHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  // Guard against null/undefined or non-object inputs
  if (headers === null || headers === undefined || typeof headers !== 'object') {
    return result;
  }

  try {
    for (const [name, value] of Object.entries(headers)) {
      // Ensure key is a string (Object.entries should guarantee this, but defend anyway)
      if (typeof name !== 'string') {
        continue;
      }
      result[name] = isSensitiveHeader(name) ? REDACTED : value;
    }
  } catch (err) {
    // If header processing fails for any reason, return what we have so far
    // This prevents audit logging from crashing the request
    console.error('[redactHeaders] Failed to process headers:', err);
  }

  return result;
}

/**
 * Recursively sanitises a request body, query string, or arbitrary metadata
 * value before it is written to the audit log.
 *
 * - Keys matching `isSensitiveKey` have their values replaced with REDACTED.
 * - String values that look like email addresses are masked via `maskEmail`.
 * - Arrays are traversed element-by-element.
 * - Primitives (number, boolean) and `null`/`undefined` pass through as-is.
 * - Circular references are detected and replaced with REDACTED to prevent stack overflow.
 * - Depth is limited to MAX_REDACTION_DEPTH to prevent stack overflow.
 *
 * @param value - The value to sanitise (may be any JSON-serialisable type).
 * @returns A deep copy with sensitive data replaced.
 */
export function redactBody(value: unknown): unknown {
  return redactBodyInternal(value, new WeakSet<object>(), 0);
}

/**
 * Internal implementation of redactBody with circular reference detection and depth limiting.
 *
 * @param value - The value to sanitise.
 * @param visited - WeakSet of objects already visited to detect circular references.
 * @param depth - Current recursion depth.
 * @returns A deep copy with sensitive data replaced, or REDACTED if invariants are violated.
 */
function redactBodyInternal(value: unknown, visited: WeakSet<object>, depth: number): unknown {
  // Guard against excessive recursion depth
  if (depth > MAX_REDACTION_DEPTH) {
    return REDACTED;
  }

  if (value === null || value === undefined) {
    return value;
  }

  if (Array.isArray(value)) {
    // Check for circular reference in the array itself
    if (visited.has(value)) {
      return REDACTED;
    }
    visited.add(value);
    const result = value.map((item) => redactBodyInternal(item, visited, depth + 1));
    // Do NOT remove from visited - keep it to prevent revisiting from other paths
    return result;
  }

  if (typeof value === 'object') {
    // Check for circular reference in the object itself
    if (visited.has(value)) {
      return REDACTED;
    }
    visited.add(value);
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      result[key] = isSensitiveKey(key) ? REDACTED : redactBodyInternal(val, visited, depth + 1);
    }
    // Do NOT remove from visited - keep it to prevent revisiting from other paths
    return result;
  }

  if (typeof value === 'string') {
    return maskEmail(value);
  }

  // Numbers, booleans — safe to log verbatim.
  return value;
}

/**
 * Assembles the `metadata` object written to an audit entry for a protected
 * HTTP request. All sensitive fields are redacted before return.
 *
 * Handles invalid or malformed inputs gracefully to prevent audit logging
 * from crashing the request path.
 *
 * @param method      - HTTP verb (e.g. `'POST'`).
 * @param path        - URL path (e.g. `'/api/v1/contracts/abc'`).
 * @param headers     - Raw request headers from `req.headers`.
 * @param body        - Parsed request body, or `undefined` for bodyless requests.
 * @param query       - Parsed query string object from `req.query`.
 * @param statusCode  - Final HTTP response status code (captured after finish).
 * @param requestId   - Correlation ID from `res.locals.requestId`, if present.
 * @returns Flat, redacted metadata record safe for audit storage.
 */
export function buildAuditMetadata(
  method: string,
  path: string,
  headers: Record<string, string | string[] | undefined>,
  body: unknown,
  query: Record<string, unknown>,
  statusCode: number,
  requestId: string | undefined,
): Record<string, unknown> {
  // Validate and coerce primitive inputs to safe defaults
  const safeMethod = typeof method === 'string' ? method : 'UNKNOWN';
  const safePath = typeof path === 'string' ? path : '';
  const safeStatusCode = typeof statusCode === 'number' && isFinite(statusCode) ? statusCode : 0;

  return {
    method: safeMethod,
    path: safePath,
    statusCode: safeStatusCode,
    requestId: typeof requestId === 'string' ? requestId : null,
    headers: redactHeaders(headers),
    body: body !== undefined && body !== null ? redactBody(body) : null,
    query: query && typeof query === 'object' && Object.keys(query).length > 0 ? redactBody(query) : null,
  };
}

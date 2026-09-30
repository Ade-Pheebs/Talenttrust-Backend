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
 * @security
 * - Redaction is deterministic: the same input always produces the same output.
 * - `Authorization` header values are NEVER persisted under any circumstances.
 * - This module has no side-effects; all functions are pure transformations.
 */

import { types } from 'node:util';

/** Sentinel written in place of any redacted value. */
export const REDACTED = '[REDACTED]';
/** Fixed diagnostics never include rejected values or exception messages. */
export const INVALID = '[INVALID AUDIT VALUE]';
export const LIMIT_EXCEEDED = '[AUDIT LIMIT EXCEEDED]';
export const MAX_DEPTH = 32;
export const MAX_NODES = 10_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || types.isProxy(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype === null || prototype === Object.prototype) return true;
  // Node HTTP objects can originate in another realm (notably Jest's VM).
  if (typeof prototype !== 'object' || types.isProxy(prototype)
    || Object.getPrototypeOf(prototype) !== null) return false;
  const constructor = Object.getOwnPropertyDescriptor(prototype, 'constructor');
  return !!constructor && 'value' in constructor
    && typeof constructor.value === 'function' && !types.isProxy(constructor.value)
    && Function.prototype.toString.call(constructor.value) === Function.prototype.toString.call(Object);
}

function assertString(value: unknown): asserts value is string {
  if (typeof value !== 'string') throw new TypeError('Invalid audit string');
}

// Define own properties so JSON keys such as __proto__ remain ordinary data.
function put(target: object, key: string, value: unknown): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

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

// ─── Predicate helpers ───────────────────────────────────────────────────────

/**
 * Returns `true` when the given header name should be fully redacted.
 *
 * @param name - Raw header name (case-insensitive).
 */
export function isSensitiveHeader(name: string): boolean {
  assertString(name);
  return SENSITIVE_HEADER_NAMES.has(name.toLowerCase());
}

/**
 * Returns `true` when the given object key suggests a sensitive value.
 *
 * @param key - Object key string (case-insensitive).
 */
export function isSensitiveKey(key: string): boolean {
  assertString(key);
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
  assertString(value);
  // Short local parts must remain stable when stored entries are exported again.
  if (/^[^@\s]{1,3}\*{3}@[^@\s]+\.[^@\s]+$/.test(value)) return value;
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
 * string values are copied verbatim and string arrays are cloned. Invalid
 * names, values and accessors become INVALID; sensitive values are never read.
 * Invalid containers and more than MAX_NODES headers throw a fixed TypeError.
 * The original object is never mutated.
 *
 * @param headers - Raw headers from `req.headers`.
 * @returns A flat object safe for audit storage.
 */
export function redactHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, unknown> {
  if (!isRecord(headers)) throw new TypeError('Invalid audit headers');
  const result: Record<string, unknown> = {};
  const names = Object.keys(headers);
  if (names.length > MAX_NODES) throw new TypeError('Audit headers limit exceeded');
  let remaining = MAX_NODES - names.length;
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(headers, name)!;
    let value: unknown = INVALID;
    if (isSensitiveHeader(name)) value = REDACTED;
    else if (/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) && 'value' in descriptor) {
      const raw: unknown = descriptor.value;
      if (raw === undefined || typeof raw === 'string') value = raw;
      else if (Array.isArray(raw) && !types.isProxy(raw)) {
        if (raw.length > remaining) {
          put(result, name, LIMIT_EXCEEDED);
          continue;
        }
        remaining -= raw.length;
        const copy: string[] = [];
        for (let i = 0; i < raw.length; i++) {
          const item = Object.getOwnPropertyDescriptor(raw, String(i));
          if (!item || !('value' in item) || typeof item.value !== 'string') break;
          copy.push(item.value);
        }
        if (copy.length === raw.length) value = copy;
      }
    }
    put(result, name, value);
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
 * - Finite numbers, booleans and null/undefined pass through as-is.
 * - Only own enumerable string keys of plain/null-prototype records and array
 *   indices are data. Accessors, sparse slots, cycles, proxies, non-finite
 *   numbers and non-JSON types become INVALID without invoking user code.
 * - Root depth is zero; depths above MAX_DEPTH and containers exceeding the
 *   remaining MAX_NODES traversal budget become LIMIT_EXCEEDED.
 * - Sensitive values are replaced without inspection. Header secrets are also
 *   suppressed here because persisted metadata is reprocessed during export.
 *
 * @param value - The value to sanitise (may be any JSON-serialisable type).
 * @returns A deep copy with sensitive data replaced.
 */
export function redactBody(value: unknown): unknown {
  // Per-call state: aliases are copied independently; only ancestor cycles are
  // rejected. Retries and concurrent callers cannot affect one another.
  const ancestors = new WeakSet<object>();
  let nodes = 0;
  function visit(input: unknown, depth: number): unknown {
    if (++nodes > MAX_NODES || depth > MAX_DEPTH) return LIMIT_EXCEEDED;
    if (input === null || input === undefined) return input;
    if (typeof input === 'string') return maskEmail(input);
    if (typeof input === 'boolean') return input;
    if (typeof input === 'number') return Number.isFinite(input) ? input : INVALID;
    if (typeof input !== 'object' || types.isProxy(input)) return INVALID;
    const array = Array.isArray(input);
    if ((!array && !isRecord(input)) || ancestors.has(input)) return INVALID;
    const keys = array ? null : Object.keys(input);
    const count = array ? input.length : keys!.length;
    // Reject the container rather than silently dropping remaining fields.
    if (count > MAX_NODES - nodes) return LIMIT_EXCEEDED;
    ancestors.add(input);
    const result: Record<string, unknown> | unknown[] = array ? [] : {};
    for (let i = 0; i < count; i++) {
      if (nodes >= MAX_NODES) {
        ancestors.delete(input);
        return LIMIT_EXCEEDED;
      }
      const key = keys ? keys[i] : String(i);
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      const sensitive = !array && (isSensitiveKey(key) || isSensitiveHeader(key));
      const child = sensitive ? REDACTED
        : !descriptor || !('value' in descriptor) ? INVALID
          : visit(descriptor.value, depth + 1);
      if (sensitive || !descriptor || !('value' in descriptor)) nodes++;
      put(result, key, child);
    }
    ancestors.delete(input);
    return result;
  }
  return visit(value, 0);
}

/**
 * Assembles the `metadata` object written to an audit entry for a protected
 * HTTP request. All sensitive fields are redacted before return.
 *
 * @param method      - HTTP verb (e.g. `'POST'`).
 * @param path        - URL path (e.g. `'/api/v1/contracts/abc'`).
 * @param headers     - Raw request headers from `req.headers`.
 * @param body        - Parsed request body, or `undefined` for bodyless requests.
 * @param query       - Parsed query string object from `req.query`.
 * @param statusCode  - Final HTTP response status code (captured after finish).
 * @param requestId   - Correlation ID from `res.locals.requestId`, if present.
 * Invalid envelopes throw a fixed TypeError without including supplied data.
 * Methods must be HTTP tokens, paths must exclude query/fragment/control data,
 * status codes must be integers from 100 through 599, and queries plain records.
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
  assertString(method);
  assertString(path);
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(method)
    || !path.startsWith('/') || /[?#\r\n]/.test(path)
    || !Number.isInteger(statusCode) || statusCode < 100 || statusCode > 599
    || (requestId !== undefined && (typeof requestId !== 'string' || /[\r\n]/.test(requestId)))
    || !isRecord(query)) {
    throw new TypeError('Invalid audit metadata envelope');
  }
  return {
    method,
    path,
    statusCode,
    requestId: requestId ?? null,
    headers: redactHeaders(headers),
    body: body !== undefined && body !== null ? redactBody(body) : null,
    query: Object.keys(query).length > 0 ? redactBody(query) : null,
  };
}

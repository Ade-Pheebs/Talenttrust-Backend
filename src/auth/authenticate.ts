/**
 * @module authenticate
 * @description Legacy bearer-token authentication middleware for TalentTrust.
 *
 * Tokens are supplied in the `Authorization` header:
 *   Authorization: Bearer <token>
 *
 * The token payload is a base64-encoded JSON string:
 *   { "userId": "u1", "role": "freelancer" }
 *
 * ## Scope warning — this is NOT the production auth path
 *
 * Tokens here are **structurally validated, never cryptographically
 * verified**: there is no signature and no expiry, so anyone who can encode
 * `{ "userId": "x", "role": "admin" }` can mint an administrator. Production
 * traffic is authenticated by `requireAuth` in `src/middleware/authorization.ts`,
 * which verifies HS256 JWTs. This module survives only because
 * `src/routes/apiKeys.routes.ts` mounts it. Do not add new consumers, and do
 * not treat a 200 from this middleware as an authorization decision.
 *
 * ## Validation boundaries
 *
 * The decoder is the trust boundary between an attacker-controlled HTTP header
 * and `req.user`, which downstream middleware reads as an authenticated
 * identity (`requirePermission` copies `user.id` into the request context as
 * `actorId`, and the audit middleware writes it as the `actor`). Each boundary
 * below is a distinct way that untrusted input used to become a trusted value;
 * each is now enforced explicitly and is individually testable.
 *
 * @invariant VB-1 — Exactly one credential, from one well-formed header.
 *   The scheme must be the literal `Bearer ` followed by exactly one
 *   non-whitespace credential. `Buffer.from(x, 'base64')` silently discards
 *   every character outside the base64 alphabet, so a header carrying trailing
 *   junk, a CRLF, or a comma-joined second credential still decoded to the
 *   original payload and authenticated. Parsing the header against a grammar
 *   makes those inputs rejections instead of aliases for a valid token.
 *
 * @invariant VB-2 — The credential has exactly one accepted spelling.
 *   It must match the standard base64 alphabet (RFC 4648 §4 — not base64url),
 *   have a length that is a multiple of four, use padding only as a trailing
 *   `=`/`==`, and round-trip exactly through a decode/encode cycle. The
 *   round-trip is what pins the *padding*: Node decodes an unpadded credential
 *   to the same bytes as its padded form, so without it one token had two
 *   accepted spellings. Non-canonical trailing bits are not caught here —
 *   Node preserves them through a round-trip — but they decode to different
 *   bytes, so they are refused by the JSON step in VB-4.
 *
 * @invariant VB-3 — Input size is bounded before any decode or parse.
 *   An oversized credential is rejected on length alone, before allocating a
 *   buffer. Without the bound, an attacker-supplied header drives an
 *   allocation and a `JSON.parse` whose cost is unbounded by anything the
 *   server chose.
 *
 * @invariant VB-4 — Claims are own properties of a plain object.
 *   `parsed.role` reads through the prototype chain, so if anything in the
 *   process ever sets `Object.prototype.role = 'admin'`, a token carrying no
 *   `role` field at all authenticates as an administrator. Only own properties
 *   of a non-null, non-array object are consulted.
 *
 * @invariant VB-5 — `userId` is a bounded, printable ASCII identifier.
 *   Length is capped (it becomes a log line and a context value), and control
 *   characters — notably CR and LF — are rejected so a token cannot forge
 *   additional lines in the audit trail.
 *
 * @invariant VB-6 — `role` is drawn only from `VALID_ROLES`.
 *   Unchanged in substance; now an explicit own-property check so an inherited
 *   value can never satisfy it.
 *
 * ## Compatibility
 *
 * The public interface is unchanged: same exports, same signatures, and the
 * same two 401 response bodies. `decodeToken` still returns `TokenPayload |
 * null`. The one behavioural change for existing callers is that inputs which
 * previously authenticated only by exploiting base64 leniency are now rejected
 * — that is the point of the change, and no well-formed token is affected.
 */

import { Request, Response, NextFunction } from 'express';
import { Role, VALID_ROLES } from './roles';
import { logger } from '../logger';

/** Shape of the decoded token payload. */
export interface TokenPayload {
  userId: string;
  role: Role;
}

/** Express request extended with authenticated user info. */
export interface AuthenticatedRequest extends Request {
  user?: TokenPayload;
}

/**
 * Maximum length of the base64 credential, in characters.
 *
 * A `{ userId, role }` payload for a maximal `userId` is a few hundred bytes,
 * so 4096 leaves generous headroom while keeping the worst-case decode and
 * parse cost small and fixed. Rejection happens on length alone, before any
 * buffer is allocated (VB-3).
 */
export const MAX_TOKEN_LENGTH = 4096;

/**
 * Maximum length of `userId`, in characters.
 *
 * `userId` is written verbatim into audit records and into the request context,
 * so an unbounded value would let a caller push arbitrarily large strings into
 * the log store (VB-5).
 */
export const MAX_USER_ID_LENGTH = 128;

/**
 * Allowed `userId` characters: printable ASCII excluding whitespace, quotes,
 * backslash, and every control character.
 *
 * Excluding CR and LF is the security-relevant part — it prevents a forged
 * token from injecting extra lines into line-oriented audit output. The rest
 * keeps identifiers to the shape the system actually issues (`randomUUID`,
 * and the `user-<role>` / `u<N>` forms used by tests and fixtures).
 */
const USER_ID_PATTERN = /^[A-Za-z0-9._:@-]+$/;

/**
 * Standard base64 alphabet with optional trailing padding (RFC 4648 §4).
 *
 * Rejects whitespace, newlines, commas, and any other character that Node's
 * decoder would otherwise skip.
 */
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * A single bearer credential from one header.
 *
 * Exactly one SP after the scheme (RFC 7235 §2.1), then one run of non-space
 * characters and nothing after it. The anchored `\S+` is what rejects a
 * comma-joined second credential, interior whitespace, and any trailing CRLF —
 * all of which previously authenticated (VB-1).
 *
 * This pattern fixes the header's *structure* only. A returned credential may
 * still be refused by {@link validateToken} for failing the base64 alphabet,
 * length, or padding rules in VB-2; the two layers are separate so each
 * rejection reason is attributable.
 */
const BEARER_PATTERN = /^Bearer (\S+)$/;

/** Narrows an object to one that owns `key`. */
function hasOwn(target: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(target, key);
}

/**
 * Stable, non-sensitive reason a credential was refused.
 *
 * Emitted as `reason` on the `auth_legacy_bearer_rejected` log record so an
 * operator can tell a broken client from a forgery attempt without the log
 * line ever carrying credential material.
 */
export type TokenRejectionReason =
  | 'missing_header'
  | 'malformed_header'
  | 'empty_token'
  | 'token_too_long'
  | 'token_not_base64'
  | 'token_not_json'
  | 'token_not_object'
  | 'user_id_missing'
  | 'user_id_invalid'
  | 'role_missing'
  | 'role_invalid';

/**
 * Outcome of validating one credential.
 *
 * Either a payload ready to become `req.user`, or the reason it was refused.
 */
export type TokenValidationResult =
  | { ok: true; payload: TokenPayload }
  | { ok: false; reason: TokenRejectionReason };

/**
 * Reasons that indicate a possible forgery attempt rather than a broken
 * client, and so are logged at `warn` instead of `debug`.
 *
 * The split keeps routine scanner traffic and misconfigured clients out of the
 * warning stream while still surfacing a structurally sound credential whose
 * claims were refused.
 */
const SUSPICIOUS_REASONS: ReadonlySet<TokenRejectionReason> = new Set<TokenRejectionReason>([
  'token_not_base64',
  'token_not_json',
  'token_not_object',
  'user_id_invalid',
  'role_invalid',
]);

/**
 * Extract the single bearer credential from an `Authorization` header.
 *
 * Named `parseBearerHeader` rather than `extractBearerToken` to avoid
 * collision with the JWT path's same-named helper in `src/lib/authHelpers.ts`,
 * which applies a deliberately looser grammar to signed tokens.
 *
 * @param header - Raw header value; anything other than a string is refused.
 * @returns The credential, or `null` if the header does not match the grammar
 *   in VB-1.
 */
export function parseBearerHeader(header: unknown): string | null {
  if (typeof header !== 'string') {
    return null;
  }
  const match = BEARER_PATTERN.exec(header);
  return match ? match[1] : null;
}

/**
 * Decode and validate a bearer credential, reporting why on refusal.
 *
 * Every boundary in the module docs is enforced here in a fixed order —
 * header grammar, size, encoding, JSON, shape, then claims — so a given
 * credential always produces the same verdict regardless of how many
 * independent problems it has.
 *
 * @param token - The raw base64 credential.
 * @returns A discriminated result carrying either the payload or a stable
 *   rejection reason. Never throws.
 */
export function validateToken(token: unknown): TokenValidationResult {
  if (typeof token !== 'string') {
    return { ok: false, reason: 'malformed_header' };
  }
  if (token.length === 0) {
    return { ok: false, reason: 'empty_token' };
  }

  // VB-3: bound the input before decoding or parsing anything.
  if (token.length > MAX_TOKEN_LENGTH) {
    return { ok: false, reason: 'token_too_long' };
  }

  // VB-2: canonical base64 only.
  if (!BASE64_PATTERN.test(token) || token.length % 4 !== 0) {
    return { ok: false, reason: 'token_not_base64' };
  }
  const decoded = Buffer.from(token, 'base64');
  if (decoded.toString('base64') !== token) {
    return { ok: false, reason: 'token_not_base64' };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded.toString('utf-8'));
  } catch {
    return { ok: false, reason: 'token_not_json' };
  }

  // VB-4: a plain object only, and claims must be own properties.
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, reason: 'token_not_object' };
  }
  const claims = parsed as Record<string, unknown>;

  if (!hasOwn(claims, 'userId')) {
    return { ok: false, reason: 'user_id_missing' };
  }
  const userId = claims['userId'];
  // VB-5: non-empty, bounded, printable ASCII without control characters.
  if (
    typeof userId !== 'string' ||
    userId.length === 0 ||
    userId.length > MAX_USER_ID_LENGTH ||
    !USER_ID_PATTERN.test(userId)
  ) {
    return { ok: false, reason: 'user_id_invalid' };
  }

  if (!hasOwn(claims, 'role')) {
    return { ok: false, reason: 'role_missing' };
  }
  const role = claims['role'];
  // VB-6: the role allowlist is the only source of roles.
  if (typeof role !== 'string' || !(VALID_ROLES as readonly string[]).includes(role)) {
    return { ok: false, reason: 'role_invalid' };
  }

  // Project onto exactly the two documented claims so no additional field of
  // the payload can reach `req.user` and, through it, the audit trail.
  return { ok: true, payload: { userId, role: role as Role } };
}

/**
 * Decode and validate a bearer token string.
 *
 * @param token - The raw base64-encoded token.
 * @returns The decoded payload, or `null` if invalid. Never throws; see
 *   {@link validateToken} for the specific reason.
 */
export function decodeToken(token: string): TokenPayload | null {
  const result = validateToken(token);
  return result.ok ? result.payload : null;
}

/**
 * Helper to create a valid bearer token for testing.
 *
 * Validates its inputs against the same boundaries the decoder enforces, so a
 * token this function produces is always one the decoder accepts. Minting a
 * token that can never authenticate is a caller bug that should surface at the
 * call site rather than as an unexplained 401 later.
 *
 * @param userId - User identifier.
 * @param role   - Role to encode.
 * @returns Base64-encoded token string.
 * @throws {TypeError} If `userId` or `role` falls outside the accepted set.
 */
export function createToken(userId: string, role: Role): string {
  if (
    typeof userId !== 'string' ||
    userId.length === 0 ||
    userId.length > MAX_USER_ID_LENGTH ||
    !USER_ID_PATTERN.test(userId)
  ) {
    throw new TypeError(
      `createToken: userId must be 1-${MAX_USER_ID_LENGTH} printable ASCII characters matching ${USER_ID_PATTERN.source}`,
    );
  }
  if (typeof role !== 'string' || !(VALID_ROLES as readonly string[]).includes(role)) {
    throw new TypeError(
      `createToken: role must be one of ${VALID_ROLES.join(', ')}`,
    );
  }
  return Buffer.from(JSON.stringify({ userId, role })).toString('base64');
}

/**
 * Report a refusal through the structured logger.
 *
 * The record carries the reason and the path being protected, never the
 * credential or any part of it. `suspicious` refusals are raised to `warn` so
 * a forged claim is visible without turning routine 401 noise into warnings.
 */
function logRejection(reason: TokenRejectionReason, path: string | undefined): void {
  const level = SUSPICIOUS_REASONS.has(reason) ? 'warn' : 'debug';
  logger[level]('auth_legacy_bearer_rejected', {
    reason,
    path: path ?? 'unknown',
  });
}

/**
 * Express middleware that extracts and validates the bearer token.
 * On success, attaches `req.user` with `{ userId, role }`.
 * On failure, responds with 401.
 *
 * Rejection is total and observable:
 *   - Exactly one of the two response paths runs per request; `next()` is
 *     called only after `req.user` is set, so no request can reach a handler
 *     with a half-populated identity.
 *   - `req.user` is never written on the failure path, so a router that mounts
 *     this middleware cannot observe a stale identity from an earlier mount.
 *   - Every refusal is logged with a stable reason code.
 *
 * Response bodies are unchanged from the previous implementation, so existing
 * clients and tests that match on them keep working.
 */
export function authenticateMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  const header = req.headers.authorization;

  // VB-1: a repeated Authorization header arrives comma-joined as one string;
  // the grammar rejects it rather than authenticating the first credential.
  const token = parseBearerHeader(header);
  if (token === null) {
    logRejection(header === undefined ? 'missing_header' : 'malformed_header', req.path);
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  const result = validateToken(token);
  if (!result.ok) {
    logRejection(result.reason, req.path);
    res.status(401).json({ error: 'Invalid token' });
    return;
  }

  req.user = result.payload;
  next();
}

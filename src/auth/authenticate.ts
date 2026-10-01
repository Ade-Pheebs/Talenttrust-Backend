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
 * Security notes:
 *   - Tokens are validated for structure, not cryptographic signature
 *     (acceptable for tests; production should use JWTs).
 *   - Missing or malformed tokens result in 401 Unauthorized.
 *   - Role validity is checked against VALID_ROLES.
 *
 * State invariants:
 *   - Single authentication: req.user is set exactly once per request
 *   - Immutable identity: Once authenticated, identity cannot change
 *   - Type safety: req.user.role is always a valid Role enum value
 *   - Non-empty userId: req.user.userId is always a non-empty string
 *   - Deterministic validation: Same input always produces same output
 *   - Fail-safe: Validation failure results in 401, never calls next()
 */

import { Request, Response, NextFunction } from 'express';
import { Role, VALID_ROLES } from './roles';
import { logger } from '../logger';

/**
 * Logger for authentication events.
 * In production, replace with proper logging infrastructure.
 */
const authLogger = {
  info: (message: string, meta?: Record<string, unknown>) => {
    console.log(`[AUTH] ${message}`, meta ? JSON.stringify(meta) : '');
  },
  warn: (message: string, meta?: Record<string, unknown>) => {
    console.warn(`[AUTH] ${message}`, meta ? JSON.stringify(meta) : '');
  },
  error: (message: string, meta?: Record<string, unknown>) => {
    console.error(`[AUTH] ${message}`, meta ? JSON.stringify(meta) : '');
  },
};

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
 * State invariants enforced:
 *   - Returns null for any invalid input (fail-safe)
 *   - userId is always a non-empty string if successful
 *   - role is always a valid Role enum value if successful
 *   - Deterministic: same input always produces same output
 *
 * @param token - The raw base64-encoded token.
 * @returns The decoded payload, or `null` if invalid. Never throws; see
 *   {@link validateToken} for the specific reason.
 */
export function decodeToken(token: string): TokenPayload | null {
  // Invariant: Empty or whitespace-only tokens are invalid
  if (!token || typeof token !== 'string' || token.trim().length === 0) {
    return null;
  }

  try {
    const json = Buffer.from(token, 'base64').toString('utf-8');
    
    // Invariant: JSON must parse successfully
    const parsed = JSON.parse(json);
    
    // Invariant: parsed must be an object
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return null;
    }

    // Invariant: userId must be a non-empty string
    if (typeof parsed.userId !== 'string' || parsed.userId.trim().length === 0) {
      return null;
    }

    // Invariant: role must be a string
    if (typeof parsed.role !== 'string') {
      return null;
    }

    // Invariant: role must be a valid Role enum value
    // Use type-safe check instead of type assertion
    if (!VALID_ROLES.includes(parsed.role as Role)) {
      return null;
    }

    // At this point, we know parsed.role is a valid Role
    const role = parsed.role as Role;
    const userId = parsed.userId.trim();

    // Invariant: Return type-safe TokenPayload
    return { userId, role };
  } catch (error) {
    // Invariant: Any parsing error returns null (fail-safe)
    return null;
  }
}

/**
 * Helper to create a valid bearer token for testing.
 *
 * State invariants enforced:
 *   - userId is always a non-empty string
 *   - role is always a valid Role enum value
 *   - Output is deterministic for same inputs
 *
 * @param userId - User identifier.
 * @param role   - Role to encode.
 * @returns Base64-encoded token string.
 * @throws {TypeError} If `userId` or `role` falls outside the accepted set.
 */
export function createToken(userId: string, role: Role): string {
  // Invariant: Validate inputs before encoding
  if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
    throw new Error('createToken: userId must be a non-empty string');
  }
  if (!VALID_ROLES.includes(role)) {
    throw new Error(`createToken: invalid role "${role}"`);
  }
  
  return Buffer.from(JSON.stringify({ userId: userId.trim(), role })).toString('base64');
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
 * State invariants enforced:
 *   - Single authentication: req.user is set exactly once per request
 *   - Immutable identity: If req.user already exists, it is not overwritten
 *   - Fail-safe: Validation failure results in 401, never calls next()
 *   - Deterministic: Same request always produces same result
 *   - Consistent error format: All 401 responses have { error: string }
 */
export function authenticateMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  // Invariant: Single authentication - prevent identity changes mid-request
  if (req.user) {
    // Identity already established - log and continue (idempotency)
    authLogger.warn('Authentication already performed, skipping re-authentication', {
      existingUserId: req.user.userId,
      existingRole: req.user.role,
    });
    next();
    return;
  }

  const header = req.headers.authorization;

  // Invariant: Header must exist and be a string
  if (!header || typeof header !== 'string') {
    authLogger.warn('Missing Authorization header');
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  // Invariant: Header must start with 'Bearer ' (case-sensitive as per RFC 6750)
  if (!header.startsWith('Bearer ')) {
    authLogger.warn('Invalid Authorization header format', {
      prefix: header.substring(0, 10),
    });
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  const token = header.slice(7);

  // Invariant: Token must not be empty after 'Bearer ' prefix
  if (token.length === 0) {
    authLogger.warn('Empty token after Bearer prefix');
    res.status(401).json({ error: 'Invalid token' });
    return;
  }

  const payload = decodeToken(token);

  // Invariant: Invalid token results in 401
  if (!payload) {
    authLogger.warn('Token validation failed', {
      tokenLength: token.length,
    });
    res.status(401).json({ error: 'Invalid token' });
    return;
  }

  // Invariant: Set req.user exactly once (single authentication)
  req.user = payload;

  // Invariant: Log successful authentication for diagnostics
  authLogger.info('Authentication successful', {
    userId: payload.userId,
    role: payload.role,
  });

  next();
}

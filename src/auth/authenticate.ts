/**
 * @module authenticate
 * @description Authentication middleware and helpers for TalentTrust.
 *
 * Uses a simple Bearer-token scheme backed by a shared secret (for demo /
 * test purposes). In production this would be replaced with JWT / OAuth2.
 *
 * Tokens are expected in the `Authorization` header:
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
 */

import { Request, Response, NextFunction } from 'express';
import { Role, VALID_ROLES } from './roles';

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
 * Upper bound on the size of a bearer token the decoder will accept.
 *
 * Base64 decodes roughly 3 bytes per 4 characters, so 64 KiB of input bounds
 * the JSON parse to ~48 KiB — far larger than any legitimate payload, yet small
 * enough that a hostile client cannot force unbounded work on the event loop
 * with a single header.
 */
export const MAX_TOKEN_LENGTH = 64 * 1024;

/**
 * Decode and validate a bearer token string.
 *
 * This function is **total**: for any input it returns either a well-formed
 * {@link TokenPayload} or `null`. It never throws, and it never returns a
 * partially validated payload. Every rejection — non-string input, empty or
 * oversized input, malformed base64, non-JSON, JSON that is not a plain object,
 * missing or mistyped fields, unknown role — collapses to the same
 * deterministic `null`, so a decode failure can never surface as a 500 from the
 * middleware.
 *
 * The returned object is rebuilt field-by-field from validated primitives, so
 * extra keys in the JSON (including `__proto__`) are discarded and a "JSON
 * prototype pollution" payload cannot influence the result.
 *
 * @param token - The raw base64-encoded token.
 * @returns The decoded payload, or `null` if invalid.
 */
export function decodeToken(token: string): TokenPayload | null {
  // Defensive totality: callers are typed, but a JavaScript caller (or a future
  // refactor) can pass anything, and `Buffer.from(undefined, 'base64')` throws.
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
    return null;
  }

  try {
    const json = Buffer.from(token, 'base64').toString('utf-8');
    const parsed: unknown = JSON.parse(json);

    // Only a plain object is a valid payload. `null`, arrays and primitives are
    // rejected explicitly rather than relying on property-access quirks.
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return null;
    }

    const { userId, role } = parsed as Record<string, unknown>;
    if (
      typeof userId !== 'string' ||
      userId.length === 0 ||
      typeof role !== 'string' ||
      !(VALID_ROLES as readonly string[]).includes(role)
    ) {
      return null;
    }

    return { userId, role: role as Role };
  } catch {
    return null;
  }
}

/**
 * Helper to create a valid bearer token for testing.
 *
 * @param userId - User identifier.
 * @param role   - Role to encode.
 * @returns Base64-encoded token string.
 */
export function createToken(userId: string, role: Role): string {
  return Buffer.from(JSON.stringify({ userId, role })).toString('base64');
}

/**
 * Express middleware that extracts and validates the bearer token.
 * On success, attaches `req.user` with `{ userId, role }`.
 * On failure, responds with 401.
 */
export function authenticateMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  const header = req.headers.authorization;

  if (!header || !header.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  const token = header.slice(7);
  const payload = decodeToken(token);

  if (!payload) {
    res.status(401).json({ error: 'Invalid token' });
    return;
  }

  req.user = payload;
  next();
}

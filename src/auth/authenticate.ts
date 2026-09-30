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

/**
 * The only `Authorization` scheme this module accepts.
 *
 * This value is part of the public compatibility contract: it is exported so
 * that callers and tests can refer to the scheme symbolically instead of
 * hard-coding the literal, and any change to it is an intentional, reviewable
 * breaking change rather than a silent one.
 */
export const AUTH_SCHEME = 'Bearer ';

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
 * Decode and validate a bearer token string.
 *
 * @param token - The raw base64-encoded token.
 * @returns The decoded payload, or `null` if invalid.
 */
export function decodeToken(token: string): TokenPayload | null {
  try {
    const json = Buffer.from(token, 'base64').toString('utf-8');
    const parsed = JSON.parse(json);
    if (
      typeof parsed.userId !== 'string' ||
      !parsed.userId ||
      typeof parsed.role !== 'string' ||
      !(VALID_ROLES as readonly string[]).includes(parsed.role)
    ) {
      return null;
    }
    return { userId: parsed.userId, role: parsed.role as Role };
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
 *
 * Compatibility contract (frozen by `authenticate.contract.test.ts`):
 *
 * | input                                       | outcome |
 * | ------------------------------------------- | ------- |
 * | missing, non-string or non-`Bearer ` header | 401 `{ error: 'Missing or invalid Authorization header' }` |
 * | present-but-invalid token                   | 401 `{ error: 'Invalid token' }` |
 * | valid token                                 | `req.user = { userId, role }` and exactly one `next()` |
 *
 * A repeated `Authorization` header is delivered by Node as `string[]`. It is
 * treated as a malformed header (401) rather than being passed to
 * `startsWith()`, which would throw a `TypeError` and surface as a 500 — so the
 * observable contract is identical for every shape of a rejected header.
 */
export function authenticateMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  const header = req.headers?.authorization;
  const authorization = typeof header === 'string' ? header : null;

  if (!authorization || !authorization.startsWith(AUTH_SCHEME)) {
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  const payload = decodeToken(authorization.slice(AUTH_SCHEME.length));

  if (!payload) {
    res.status(401).json({ error: 'Invalid token' });
    return;
  }

  // Assign (not merge): a previous layer's identity is replaced wholesale, so
  // `req.user` always describes exactly the credential presented here.
  req.user = payload;
  next();
}

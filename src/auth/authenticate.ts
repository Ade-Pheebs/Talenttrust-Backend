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
 *
 * State invariants:
 *   - Single authentication: req.user is set exactly once per request
 *   - Immutable identity: Once authenticated, identity cannot change
 *   - Type safety: req.user.role is always a valid Role enum value
 *   - Non-empty userId: req.user.userId is always a non-empty string
 *   - Deterministic validation: Same input always produces same output
 *   - Fail-safe: Validation failure results in 401, never calls next()
 *   - Response integrity: Middleware never sends response if already sent
 *   - Tamper-proof: req.user is frozen to prevent downstream mutation
 *   - Runtime validation: Existing req.user is validated before reuse
 */

import { Request, Response, NextFunction } from 'express';
import { Role, VALID_ROLES } from './roles';

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
export interface AuthenticatedRequest extends Omit<Request, 'user'> {
  user?: TokenPayload;
}

/**
 * Validates that an object conforms to TokenPayload structure at runtime.
 * This protects against tampering of req.user by downstream middleware.
 *
 * @param value - The value to validate.
 * @returns True if the value is a valid TokenPayload, false otherwise.
 */
function isValidTokenPayload(value: unknown): value is TokenPayload {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }

  const payload = value as Record<string, unknown>;
  
  // Validate userId
  if (typeof payload.userId !== 'string' || payload.userId.trim().length === 0) {
    return false;
  }

  // Validate role
  if (typeof payload.role !== 'string') {
    return false;
  }

  if (!VALID_ROLES.includes(payload.role as Role)) {
    return false;
  }

  return true;
}

/**
 * Checks if the response has already been sent.
 * This prevents double-sending responses which would cause an error.
 *
 * @param res - Express response object.
 * @returns True if response headers have been sent, false otherwise.
 */
function isResponseSent(res: Response): boolean {
  return res.headersSent;
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
 * @returns The decoded payload, or `null` if invalid.
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
 * Express middleware that extracts and validates the bearer token.
 * On success, attaches `req.user` with `{ userId, role }`.
 * On failure, responds with 401.
 *
 * State invariants enforced:
 *   - Single authentication: req.user is set exactly once per request
 *   - Immutable identity: If req.user already exists, it is not overwritten
 *   - Tamper-proof: req.user is frozen after setting to prevent downstream mutation
 *   - Runtime validation: Existing req.user is validated before reuse
 *   - Response integrity: Never sends response if already sent
 *   - Fail-safe: Validation failure results in 401, never calls next()
 *   - Deterministic: Same request always produces same result
 *   - Consistent error format: All 401 responses have { error: string }
 */
export function authenticateMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  // Invariant: Response integrity - check before attempting to send
  if (isResponseSent(res)) {
    authLogger.error('Response already sent, cannot authenticate');
    return;
  }

  // Invariant: Single authentication - prevent identity changes mid-request
  if (req.user) {
    // Invariant: Runtime validation - ensure existing user is still valid
    if (!isValidTokenPayload(req.user)) {
      authLogger.error('Existing req.user is invalid or tampered, rejecting request');
      res.status(500).json({ error: 'Internal authentication error' });
      return;
    }

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
    if (!isResponseSent(res)) {
      res.status(401).json({ error: 'Missing or invalid Authorization header' });
    }
    return;
  }

  // Invariant: Header must start with 'Bearer ' (case-sensitive as per RFC 6750)
  if (!header.startsWith('Bearer ')) {
    authLogger.warn('Invalid Authorization header format', {
      prefix: header.substring(0, 10),
    });
    if (!isResponseSent(res)) {
      res.status(401).json({ error: 'Missing or invalid Authorization header' });
    }
    return;
  }

  const token = header.slice(7);

  // Invariant: Token must not be empty after 'Bearer ' prefix
  if (token.length === 0) {
    authLogger.warn('Empty token after Bearer prefix');
    if (!isResponseSent(res)) {
      res.status(401).json({ error: 'Invalid token' });
    }
    return;
  }

  const payload = decodeToken(token);

  // Invariant: Invalid token results in 401
  if (!payload) {
    authLogger.warn('Token validation failed', {
      tokenLength: token.length,
    });
    if (!isResponseSent(res)) {
      res.status(401).json({ error: 'Invalid token' });
    }
    return;
  }

  // Invariant: Set req.user exactly once (single authentication)
  req.user = payload;

  // Invariant: Tamper-proof - freeze req.user to prevent downstream mutation
  Object.freeze(req.user);

  // Invariant: Log successful authentication for diagnostics (redact sensitive data)
  authLogger.info('Authentication successful', {
    userId: payload.userId.substring(0, 8) + '...', // Redact for security
    role: payload.role,
  });

  next();
}

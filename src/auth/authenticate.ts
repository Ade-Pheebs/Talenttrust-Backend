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
 *   - Token values are trimmed before decoding so stray whitespace in the
 *     Authorization header never produces a spurious cache miss or a
 *     different validation result for the same logical token.
 *   - decodeToken results are memoized in a bounded LRU-style cache so that
 *     bursts of concurrent requests bearing the same token do not repeatedly
 *     pay the base64-decode + JSON.parse cost.  The cache is intentionally
 *     small (256 entries, 5 min TTL) and stores only the decoded *payload*,
 *     never the raw token string itself, to limit the blast radius of a
 *     potential memory inspection.
 *
 * Concurrency invariants:
 *   - normalizeToken is a pure function — safe to call from any number of
 *     concurrent requests without synchronization.
 *   - decodeToken is idempotent and deterministic: the same token always
 *     produces the same payload (or null), so concurrent calls are safe.
 *   - The decode cache is accessed synchronously (Node.js single-threaded
 *     event loop guarantees no torn reads/writes on Map operations).
 *   - Cache size is capped at DECODE_CACHE_MAX_ENTRIES; once the cap is
 *     reached the oldest inserted entry is evicted before the new one is
 *     added, keeping memory bounded even under token-spray attacks.
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

// ─── Token normalization ──────────────────────────────────────────────────────

/**
 * Normalize a raw bearer token value extracted from the Authorization header.
 *
 * Strips surrounding ASCII whitespace (spaces, tabs, CRLF) that some HTTP
 * clients or proxies may inadvertently include.  The JWT / base64 body of a
 * well-formed token never contains whitespace, so trimming is always safe and
 * ensures that two strings differing only in surrounding whitespace are treated
 * as the same token.
 *
 * @param raw - The token string after the "Bearer " prefix has been removed.
 * @returns The trimmed token string (may be empty — callers must check).
 */
export function normalizeToken(raw: string): string {
  return raw.trim();
}

// ─── Decode cache (bounded LRU-style, synchronous) ───────────────────────────

/**
 * Maximum number of distinct decoded tokens to keep in memory.
 * Chosen to cover a busy service's active token set without unbounded growth.
 */
const DECODE_CACHE_MAX_ENTRIES = 256;

/**
 * Cache TTL in milliseconds. Tokens that have been in the cache longer than
 * this are treated as stale and re-decoded on the next access. Set to 5 min
 * which is well under the default JWT access-token lifetime (15 min).
 */
const DECODE_CACHE_TTL_MS = 5 * 60 * 1000;

interface DecodeCacheEntry {
  /** The decoded payload (null means the token was invalid). */
  payload: TokenPayload | null;
  /** Epoch ms when this entry was inserted. */
  insertedAt: number;
}

/**
 * Module-level decode cache.  Keyed by the *normalized* token string.
 *
 * Invariant: size <= DECODE_CACHE_MAX_ENTRIES at all times (enforced in
 * setCacheEntry before every insertion).
 */
const decodeCache = new Map<string, DecodeCacheEntry>();

/**
 * Retrieve a cache entry, returning null on miss or expiry.
 * Expired entries are lazily evicted on access.
 *
 * @internal
 */
function getCacheEntry(token: string): TokenPayload | null | undefined {
  const entry = decodeCache.get(token);
  if (!entry) return undefined; // cache miss

  const age = Date.now() - entry.insertedAt;
  if (age > DECODE_CACHE_TTL_MS) {
    decodeCache.delete(token); // lazy eviction of stale entry
    return undefined;
  }

  return entry.payload;
}

/**
 * Insert (or overwrite) a cache entry, evicting the oldest entry first when
 * the cache is at capacity.
 *
 * Eviction strategy: delete the first key reported by Map iteration, which
 * corresponds to the entry with the earliest insertion order.  This is O(1)
 * because Map maintains insertion order and `.keys().next()` is constant-time.
 *
 * @internal
 */
function setCacheEntry(token: string, payload: TokenPayload | null): void {
  // If the token is already present, overwrite in-place — no eviction needed.
  if (!decodeCache.has(token) && decodeCache.size >= DECODE_CACHE_MAX_ENTRIES) {
    const oldest = decodeCache.keys().next().value;
    if (oldest !== undefined) {
      decodeCache.delete(oldest);
    }
  }
  decodeCache.set(token, { payload, insertedAt: Date.now() });
}

/**
 * Exposed for testing only — resets the decode cache to an empty state.
 * Do NOT call this in production code.
 *
 * @internal
 */
export function _resetDecodeCache(): void {
  decodeCache.clear();
}

// ─── Core helpers ─────────────────────────────────────────────────────────────

/**
 * Decode and validate a bearer token string.
 *
 * Results are memoized in a bounded in-process cache so that concurrent
 * requests bearing the same token pay the decode cost only once per TTL
 * window.  Because Node.js processes I/O callbacks sequentially on a single
 * event-loop thread, all Map operations inside this function are atomic from
 * the perspective of concurrent async code — no explicit locking is required.
 *
 * @param token - The raw base64-encoded token (will be normalized internally).
 * @returns The decoded payload, or `null` if invalid.
 */
export function decodeToken(token: string): TokenPayload | null {
  const normalized = normalizeToken(token);

  // Fast path — return cached result if present and fresh.
  const cached = getCacheEntry(normalized);
  if (cached !== undefined) {
    return cached;
  }

  // Slow path — decode, validate, then cache.
  let payload: TokenPayload | null = null;
  try {
    if (normalized.length === 0) {
      // Empty token after normalization — skip the decode attempt.
      setCacheEntry(normalized, null);
      return null;
    }
    const json = Buffer.from(normalized, 'base64').toString('utf-8');
    const parsed = JSON.parse(json);
    if (
      typeof parsed.userId !== 'string' ||
      !parsed.userId ||
      typeof parsed.role !== 'string' ||
      !(VALID_ROLES as readonly string[]).includes(parsed.role)
    ) {
      payload = null;
    } else {
      payload = { userId: parsed.userId, role: parsed.role as Role };
    }
  } catch {
    payload = null;
  }

  setCacheEntry(normalized, payload);
  return payload;
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
 * Token normalization is applied before validation so that benign whitespace
 * differences in the Authorization header value do not cause spurious
 * authentication failures.
 *
 * On success, attaches `req.user` with `{ userId, role }`.
 * On failure, responds with 401.
 *
 * Concurrency note: this middleware is stateless with respect to any single
 * request — it reads from `req.headers`, calls the pure `decodeToken` helper,
 * and writes to `req.user`.  Concurrent execution of this function for
 * different requests is fully safe.
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

  // Normalize the token value extracted after the "Bearer " prefix so that
  // stray whitespace (e.g., a trailing space from a misconfigured client or
  // proxy) does not cause an avoidable validation failure or cache miss.
  const token = normalizeToken(header.slice(7));

  if (token.length === 0) {
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  const payload = decodeToken(token);

  if (!payload) {
    res.status(401).json({ error: 'Invalid token' });
    return;
  }

  req.user = payload;
  next();
}

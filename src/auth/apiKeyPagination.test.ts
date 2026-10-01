/**
 * @file apiKeyPagination.test.ts
 *
 * Validation-boundary tests for src/auth/apiKeyPagination.ts.
 *
 * Coverage matrix:
 * ─────────────────────────────────────────────────────────────────────────────
 * encodeApiKeyCursor
 *   - Produces a two-part base64url.signature string
 *   - Round-trips through decodeApiKeyCursor
 *   - Different positions produce different cursors
 *
 * decodeApiKeyCursor — accepted input
 *   - Valid round-trip cursor accepted
 *   - Leading zeros in id accepted
 *   - ISO-8601 date with milliseconds accepted
 *
 * decodeApiKeyCursor — rejected input (InvalidApiKeyCursorError on all)
 *   - Empty string
 *   - Non-string (number, null, undefined, object)
 *   - String exceeding CURSOR_MAX_LENGTH (512 chars)
 *   - String without a dot separator
 *   - String with multiple dots
 *   - Wrong characters (spaces, slashes)
 *   - Signature tampered (1 bit flipped)
 *   - Payload tampered (1 char changed, valid base64)
 *   - Payload decodes to non-JSON
 *   - Payload decodes to non-object (array, number, null, string)
 *   - Wrong cursor version (0, 2, string, missing)
 *   - createdAt missing
 *   - createdAt empty string
 *   - createdAt not a valid ISO date ("not-a-date")
 *   - createdAt exceeds max field length (>64 chars)
 *   - id missing
 *   - id empty string
 *   - id exceeds max field length (>200 chars)
 *   - Extra unknown fields in payload are tolerated (only required fields validated)
 *
 * parseApiKeyPageSize — accepted input
 *   - undefined → default
 *   - null → default
 *   - "" → default
 *   - "1" → 1
 *   - "20" → 20 (default)
 *   - "100" → 100 (max)
 *   - "101" → 100 (clamped)
 *   - "99999" → 100 (clamped)
 *
 * parseApiKeyPageSize — rejected / fallback to default
 *   - "0" → default
 *   - "-1" → default
 *   - "1.5" → default (float string)
 *   - "abc" → default
 *   - " 5" (leading space) → default
 *   - "5 " (trailing space) → default
 *   - "5.0" → default (decimal even if integer value)
 *   - "+5" → default (leading plus)
 *   - "1e2" → default (scientific notation)
 *   - 5 (number) → default
 *   - true (boolean) → default
 *   - {} (object) → default
 *   - [] (array) → default
 *   - NaN → default
 *
 * paginateApiKeys — success paths
 *   - Empty records → empty items, no nextCursor
 *   - Records fewer than limit → all returned, no nextCursor
 *   - Records equal to limit → all returned, no nextCursor
 *   - Records greater than limit → first N returned, nextCursor present
 *   - Cursor from first page used for second page → correct continuation
 *   - Full traversal collects every record exactly once
 *   - limit=1 works (single-item pages)
 *   - Limit clamped from excessive value
 *   - Limit clamped from 0 → treated as 1
 *   - Limit clamped from negative → treated as 1
 *   - Non-finite limit → uses default page size
 *   - Records with identical createdAt sorted by id lexicographically (descending id → first)
 *   - Stable sort: second traversal on same dataset gives identical cursor chain
 *
 * paginateApiKeys — invalid cursor propagation
 *   - Empty cursor string → throws InvalidApiKeyCursorError
 *   - Tampered cursor → throws InvalidApiKeyCursorError
 *   - Cursor from a different secret → throws InvalidApiKeyCursorError
 *
 * Concurrent / idempotency invariants
 *   - Encoding the same position twice yields the same cursor (deterministic)
 *   - Decoding the same cursor twice yields the same position (idempotent)
 *   - paginateApiKeys with same input always returns the same page (pure function)
 * ─────────────────────────────────────────────────────────────────────────────
 */

import {
  API_KEYS_DEFAULT_PAGE_SIZE,
  API_KEYS_MAX_PAGE_SIZE,
  ApiKeyCursorPosition,
  InvalidApiKeyCursorError,
  decodeApiKeyCursor,
  encodeApiKeyCursor,
  parseApiKeyPageSize,
  paginateApiKeys,
} from './apiKeyPagination';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makePosition(id: string, createdAt: string): ApiKeyCursorPosition {
  return { id, createdAt };
}

/** Build N records ordered from newest to oldest (descending createdAt). */
function makeRecords(count: number): ApiKeyCursorPosition[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `key-${String(i).padStart(4, '0')}`,
    createdAt: new Date(Date.now() - i * 1000).toISOString(),
  }));
}

/**
 * Craft a syntactically valid cursor token that was signed with a DIFFERENT
 * secret so the HMAC check fails.
 */
function encodeCursorWithSecret(
  position: ApiKeyCursorPosition,
  secret: string,
): string {
  const { createHmac } = require('node:crypto') as typeof import('node:crypto');
  const payload = JSON.stringify({ version: 1, ...position });
  const encoded = Buffer.from(payload, 'utf8').toString('base64url');
  const sig = createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

/**
 * Craft a cursor whose payload has been tampered (a single character replaced)
 * while keeping the original (now invalid) signature.
 */
function tamperPayload(cursor: string): string {
  const dotIdx = cursor.lastIndexOf('.');
  const encodedPayload = cursor.slice(0, dotIdx);
  const signature = cursor.slice(dotIdx + 1);

  // Decode, mutate, re-encode without re-signing
  const decoded = Buffer.from(encodedPayload, 'base64url').toString('utf8');
  const mutated = decoded.replace(/"id":"key-/, '"id":"TAMPERED-');
  const reEncoded = Buffer.from(mutated, 'utf8').toString('base64url');
  return `${reEncoded}.${signature}`;
}

/** Build a base64url-encoded payload with a valid HMAC for a given JSON object. */
function buildSignedCursor(payloadObj: Record<string, unknown>): string {
  const { createHmac } = require('node:crypto') as typeof import('node:crypto');
  const secret = process.env['API_KEYS_CURSOR_SECRET'] ?? 'talenttrust-api-keys-cursor-v1';
  const encoded = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  const sig = createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

// ─── encodeApiKeyCursor ───────────────────────────────────────────────────────

describe('encodeApiKeyCursor', () => {
  it('returns a string with exactly one dot separator', () => {
    const cursor = encodeApiKeyCursor({ id: 'key-1', createdAt: '2024-01-01T00:00:00.000Z' });
    const parts = cursor.split('.');
    expect(parts.length).toBe(2);
    expect(parts[0]).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(parts[1]).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('round-trips: decoded value equals the original position', () => {
    const position: ApiKeyCursorPosition = {
      id: 'key-abc',
      createdAt: '2024-06-15T12:30:45.123Z',
    };
    const cursor = encodeApiKeyCursor(position);
    const decoded = decodeApiKeyCursor(cursor);
    expect(decoded).toEqual(position);
  });

  it('produces different cursors for different positions', () => {
    const a = encodeApiKeyCursor({ id: 'key-1', createdAt: '2024-01-01T00:00:00.000Z' });
    const b = encodeApiKeyCursor({ id: 'key-2', createdAt: '2024-01-01T00:00:00.000Z' });
    const c = encodeApiKeyCursor({ id: 'key-1', createdAt: '2024-01-02T00:00:00.000Z' });
    expect(a).not.toBe(b);
    expect(a).not.toBe(c);
    expect(b).not.toBe(c);
  });

  it('is deterministic: same input always produces the same cursor', () => {
    const position: ApiKeyCursorPosition = {
      id: 'key-stable',
      createdAt: '2025-03-01T00:00:00.000Z',
    };
    expect(encodeApiKeyCursor(position)).toBe(encodeApiKeyCursor(position));
  });

  it('total cursor length stays under CURSOR_MAX_LENGTH for typical ids', () => {
    // 200-char id is the current maximum allowed field length
    const longId = 'a'.repeat(200);
    const cursor = encodeApiKeyCursor({ id: longId, createdAt: '2024-01-01T00:00:00.000Z' });
    expect(cursor.length).toBeLessThanOrEqual(512);
  });
});

// ─── decodeApiKeyCursor — accepted inputs ─────────────────────────────────────

describe('decodeApiKeyCursor — accepted inputs', () => {
  it('accepts a cursor round-tripped from encodeApiKeyCursor', () => {
    const position: ApiKeyCursorPosition = {
      id: 'abc-123',
      createdAt: '2024-01-15T10:30:00.000Z',
    };
    expect(decodeApiKeyCursor(encodeApiKeyCursor(position))).toEqual(position);
  });

  it('accepts an id with only numeric characters', () => {
    const position = makePosition('00001', '2024-01-01T00:00:00.000Z');
    expect(decodeApiKeyCursor(encodeApiKeyCursor(position))).toEqual(position);
  });

  it('accepts a full ISO-8601 datetime with milliseconds', () => {
    const position = makePosition('k1', '2024-12-31T23:59:59.999Z');
    expect(decodeApiKeyCursor(encodeApiKeyCursor(position))).toEqual(position);
  });

  it('accepts an ISO-8601 date without milliseconds', () => {
    const position = makePosition('k2', '2024-06-01T00:00:00Z');
    expect(decodeApiKeyCursor(encodeApiKeyCursor(position))).toEqual(position);
  });

  it('accepts extra unknown fields in the payload (forward-compat)', () => {
    // Build a signed cursor that includes extra fields beyond version/createdAt/id
    const cursor = buildSignedCursor({
      version: 1,
      createdAt: '2024-01-01T00:00:00.000Z',
      id: 'key-extra',
      extra: 'ignored',
    });
    const decoded = decodeApiKeyCursor(cursor);
    expect(decoded).toEqual({ id: 'key-extra', createdAt: '2024-01-01T00:00:00.000Z' });
  });

  it('is idempotent: decoding the same cursor twice yields identical results', () => {
    const cursor = encodeApiKeyCursor({ id: 'k', createdAt: '2024-01-01T00:00:00.000Z' });
    expect(decodeApiKeyCursor(cursor)).toEqual(decodeApiKeyCursor(cursor));
  });
});

// ─── decodeApiKeyCursor — rejected inputs ─────────────────────────────────────

describe('decodeApiKeyCursor — rejected inputs', () => {
  function expectInvalidCursor(value: unknown): void {
    expect(() => decodeApiKeyCursor(value as string)).toThrow(InvalidApiKeyCursorError);
  }

  // ── Structural checks ─────────────────────────────────────────────────────

  it('rejects an empty string', () => expectInvalidCursor(''));

  it('rejects a non-string number', () => expectInvalidCursor(42));

  it('rejects null', () => expectInvalidCursor(null));

  it('rejects undefined', () => expectInvalidCursor(undefined));

  it('rejects a plain object', () => expectInvalidCursor({}));

  it('rejects a string exceeding CURSOR_MAX_LENGTH (512)', () => {
    expectInvalidCursor('a'.repeat(513));
  });

  it('rejects a string exactly at CURSOR_MAX_LENGTH that has wrong format', () => {
    // 512 chars with no dot
    expectInvalidCursor('a'.repeat(512));
  });

  it('rejects a string with no dot separator', () => {
    expectInvalidCursor('nodotcharacteratall');
  });

  it('rejects a string whose only dot is a trailing dot', () => {
    expectInvalidCursor('payload.');
  });

  it('rejects a string whose only dot is a leading dot', () => {
    expectInvalidCursor('.signature');
  });

  it('rejects a string with spaces (invalid base64url characters)', () => {
    expectInvalidCursor('pay load.signature');
  });

  it('rejects a string with forward slashes (invalid base64url characters)', () => {
    expectInvalidCursor('pay/load.sig/nat');
  });

  // ── HMAC verification ────────────────────────────────────────────────────

  it('rejects a cursor with a tampered payload (valid base64url, bad signature)', () => {
    const good = encodeApiKeyCursor({ id: 'key-1', createdAt: '2024-01-01T00:00:00.000Z' });
    expectInvalidCursor(tamperPayload(good));
  });

  it('rejects a cursor signed with a different secret', () => {
    const cursor = encodeCursorWithSecret(
      { id: 'key-1', createdAt: '2024-01-01T00:00:00.000Z' },
      'wrong-secret',
    );
    expectInvalidCursor(cursor);
  });

  it('rejects when signature is all zeros (constant-time comparison must still fail)', () => {
    const good = encodeApiKeyCursor({ id: 'key-1', createdAt: '2024-01-01T00:00:00.000Z' });
    const dotIdx = good.lastIndexOf('.');
    const badSig = 'A'.repeat(good.slice(dotIdx + 1).length);
    expectInvalidCursor(`${good.slice(0, dotIdx)}.${badSig}`);
  });

  // ── Payload structure validation ─────────────────────────────────────────

  it('rejects a payload that decodes to non-JSON (random bytes)', () => {
    const { createHmac } = require('node:crypto') as typeof import('node:crypto');
    const secret = process.env['API_KEYS_CURSOR_SECRET'] ?? 'talenttrust-api-keys-cursor-v1';
    const encoded = Buffer.from('not-json!!!').toString('base64url');
    const sig = createHmac('sha256', secret).update(encoded).digest('base64url');
    expectInvalidCursor(`${encoded}.${sig}`);
  });

  it('rejects a payload that decodes to a JSON array', () => {
    expectInvalidCursor(buildSignedCursor({ '0': 'a' } as unknown as Record<string, unknown>));
    // actual array payload
    const { createHmac } = require('node:crypto') as typeof import('node:crypto');
    const secret = process.env['API_KEYS_CURSOR_SECRET'] ?? 'talenttrust-api-keys-cursor-v1';
    const encoded = Buffer.from(JSON.stringify([1, 2, 3]), 'utf8').toString('base64url');
    const sig = createHmac('sha256', secret).update(encoded).digest('base64url');
    expectInvalidCursor(`${encoded}.${sig}`);
  });

  it('rejects a payload that decodes to a JSON null', () => {
    const { createHmac } = require('node:crypto') as typeof import('node:crypto');
    const secret = process.env['API_KEYS_CURSOR_SECRET'] ?? 'talenttrust-api-keys-cursor-v1';
    const encoded = Buffer.from('null', 'utf8').toString('base64url');
    const sig = createHmac('sha256', secret).update(encoded).digest('base64url');
    expectInvalidCursor(`${encoded}.${sig}`);
  });

  // ── version field ─────────────────────────────────────────────────────────

  it('rejects version 0', () => {
    expectInvalidCursor(
      buildSignedCursor({ version: 0, createdAt: '2024-01-01T00:00:00.000Z', id: 'k' }),
    );
  });

  it('rejects version 2', () => {
    expectInvalidCursor(
      buildSignedCursor({ version: 2, createdAt: '2024-01-01T00:00:00.000Z', id: 'k' }),
    );
  });

  it('rejects string version', () => {
    expectInvalidCursor(
      buildSignedCursor({ version: '1', createdAt: '2024-01-01T00:00:00.000Z', id: 'k' }),
    );
  });

  it('rejects missing version', () => {
    expectInvalidCursor(
      buildSignedCursor({ createdAt: '2024-01-01T00:00:00.000Z', id: 'k' }),
    );
  });

  // ── createdAt field ───────────────────────────────────────────────────────

  it('rejects missing createdAt', () => {
    expectInvalidCursor(buildSignedCursor({ version: 1, id: 'k' }));
  });

  it('rejects empty createdAt', () => {
    expectInvalidCursor(buildSignedCursor({ version: 1, createdAt: '', id: 'k' }));
  });

  it('rejects non-date createdAt string', () => {
    expectInvalidCursor(
      buildSignedCursor({ version: 1, createdAt: 'not-a-date', id: 'k' }),
    );
  });

  it('rejects numeric createdAt', () => {
    expectInvalidCursor(
      buildSignedCursor({ version: 1, createdAt: 1704067200000, id: 'k' }),
    );
  });

  it('rejects createdAt exceeding 64 characters', () => {
    const longDate = '2024-01-01T00:00:00.000Z' + '0'.repeat(50); // 73 chars
    expectInvalidCursor(buildSignedCursor({ version: 1, createdAt: longDate, id: 'k' }));
  });

  // ── id field ─────────────────────────────────────────────────────────────

  it('rejects missing id', () => {
    expectInvalidCursor(
      buildSignedCursor({ version: 1, createdAt: '2024-01-01T00:00:00.000Z' }),
    );
  });

  it('rejects empty id', () => {
    expectInvalidCursor(
      buildSignedCursor({ version: 1, createdAt: '2024-01-01T00:00:00.000Z', id: '' }),
    );
  });

  it('rejects numeric id', () => {
    expectInvalidCursor(
      buildSignedCursor({ version: 1, createdAt: '2024-01-01T00:00:00.000Z', id: 42 }),
    );
  });

  it('rejects id exceeding 200 characters', () => {
    const longId = 'k'.repeat(201);
    expectInvalidCursor(
      buildSignedCursor({ version: 1, createdAt: '2024-01-01T00:00:00.000Z', id: longId }),
    );
  });

  it('accepts id of exactly 200 characters (boundary)', () => {
    const maxId = 'k'.repeat(200);
    const cursor = buildSignedCursor({
      version: 1,
      createdAt: '2024-01-01T00:00:00.000Z',
      id: maxId,
    });
    const decoded = decodeApiKeyCursor(cursor);
    expect(decoded.id).toBe(maxId);
  });

  it('accepts id of exactly 1 character (boundary)', () => {
    const cursor = buildSignedCursor({
      version: 1,
      createdAt: '2024-01-01T00:00:00.000Z',
      id: 'x',
    });
    expect(decodeApiKeyCursor(cursor).id).toBe('x');
  });
});

// ─── parseApiKeyPageSize ──────────────────────────────────────────────────────

describe('parseApiKeyPageSize', () => {
  // ── Absent / empty → default ──────────────────────────────────────────────

  it('returns the default for undefined', () => {
    expect(parseApiKeyPageSize(undefined)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for null', () => {
    expect(parseApiKeyPageSize(null)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for empty string', () => {
    expect(parseApiKeyPageSize('')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  // ── Valid integer strings ─────────────────────────────────────────────────

  it('returns 1 for "1" (minimum)', () => {
    expect(parseApiKeyPageSize('1')).toBe(1);
  });

  it('returns 20 for "20" (default value as explicit string)', () => {
    expect(parseApiKeyPageSize('20')).toBe(20);
  });

  it('returns 50 for "50"', () => {
    expect(parseApiKeyPageSize('50')).toBe(50);
  });

  it('returns 100 for "100" (maximum)', () => {
    expect(parseApiKeyPageSize('100')).toBe(API_KEYS_MAX_PAGE_SIZE);
  });

  it('clamps "101" to 100 (maximum page size)', () => {
    expect(parseApiKeyPageSize('101')).toBe(API_KEYS_MAX_PAGE_SIZE);
  });

  it('clamps "99999" to 100 (far above maximum)', () => {
    expect(parseApiKeyPageSize('99999')).toBe(API_KEYS_MAX_PAGE_SIZE);
  });

  // ── Invalid strings → default ─────────────────────────────────────────────

  it('returns the default for "0" (zero is not a valid page size)', () => {
    expect(parseApiKeyPageSize('0')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for "-1" (negative)', () => {
    expect(parseApiKeyPageSize('-1')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for "1.5" (float string)', () => {
    expect(parseApiKeyPageSize('1.5')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for "5.0" (decimal even though integer value)', () => {
    expect(parseApiKeyPageSize('5.0')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for "+5" (leading plus sign)', () => {
    expect(parseApiKeyPageSize('+5')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for "1e2" (scientific notation)', () => {
    expect(parseApiKeyPageSize('1e2')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for "abc"', () => {
    expect(parseApiKeyPageSize('abc')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for " 5" (leading space)', () => {
    expect(parseApiKeyPageSize(' 5')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for "5 " (trailing space)', () => {
    expect(parseApiKeyPageSize('5 ')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for "5\n" (trailing newline)', () => {
    expect(parseApiKeyPageSize('5\n')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  // ── Non-string types → default (only strings accepted) ────────────────────

  it('returns the default for a raw number 5 (non-string type)', () => {
    expect(parseApiKeyPageSize(5)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for true (boolean)', () => {
    expect(parseApiKeyPageSize(true)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for false (boolean)', () => {
    expect(parseApiKeyPageSize(false)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for a plain object', () => {
    expect(parseApiKeyPageSize({})).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for an array', () => {
    expect(parseApiKeyPageSize(['10'])).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for NaN', () => {
    expect(parseApiKeyPageSize(NaN)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  it('returns the default for Infinity', () => {
    expect(parseApiKeyPageSize(Infinity)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  // ── Boundary: exactly at the clamping boundary ────────────────────────────

  it('returns 100 for the string representation of API_KEYS_MAX_PAGE_SIZE', () => {
    expect(parseApiKeyPageSize(String(API_KEYS_MAX_PAGE_SIZE))).toBe(API_KEYS_MAX_PAGE_SIZE);
  });

  it('clamps to 100 for one above API_KEYS_MAX_PAGE_SIZE', () => {
    expect(parseApiKeyPageSize(String(API_KEYS_MAX_PAGE_SIZE + 1))).toBe(API_KEYS_MAX_PAGE_SIZE);
  });
});

// ─── paginateApiKeys ──────────────────────────────────────────────────────────

describe('paginateApiKeys', () => {
  // ── Empty dataset ────────────────────────────────────────────────────────

  it('returns empty items and null nextCursor for an empty dataset', () => {
    const result = paginateApiKeys([], 20);
    expect(result.items).toHaveLength(0);
    expect(result.nextCursor).toBeNull();
  });

  // ── Dataset smaller than limit ────────────────────────────────────────────

  it('returns all items when count < limit', () => {
    const records = makeRecords(5);
    const result = paginateApiKeys(records, 10);
    expect(result.items).toHaveLength(5);
    expect(result.nextCursor).toBeNull();
  });

  // ── Dataset equal to limit ────────────────────────────────────────────────

  it('returns all items with no nextCursor when count === limit', () => {
    const records = makeRecords(20);
    const result = paginateApiKeys(records, 20);
    expect(result.items).toHaveLength(20);
    expect(result.nextCursor).toBeNull();
  });

  // ── Dataset larger than limit ─────────────────────────────────────────────

  it('returns exactly limit items and a non-null nextCursor when count > limit', () => {
    const records = makeRecords(25);
    const result = paginateApiKeys(records, 20);
    expect(result.items).toHaveLength(20);
    expect(result.nextCursor).not.toBeNull();
  });

  // ── Cursor-based continuation ─────────────────────────────────────────────

  it('second page contains the remaining items when traversing page by page', () => {
    const records = makeRecords(25);
    const page1 = paginateApiKeys(records, 20);
    expect(page1.items).toHaveLength(20);
    expect(page1.nextCursor).not.toBeNull();

    const page2 = paginateApiKeys(records, 20, page1.nextCursor!);
    expect(page2.items).toHaveLength(5);
    expect(page2.nextCursor).toBeNull();
  });

  it('full traversal collects every record exactly once', () => {
    const records = makeRecords(55);
    const seen = new Set<string>();
    let cursor: string | undefined;

    for (let page = 0; ; page++) {
      const result = paginateApiKeys(records, 20, cursor);
      for (const item of result.items) {
        expect(seen.has(item.id)).toBe(false); // no duplicates
        seen.add(item.id);
      }
      if (result.nextCursor === null) break;
      cursor = result.nextCursor;
      // Safety: prevent infinite loop in case of regression
      if (page > 10) throw new Error('Traversal did not terminate');
    }

    expect(seen.size).toBe(55);
  });

  // ── Limit clamping ────────────────────────────────────────────────────────

  it('limit=1 works: single-item pages', () => {
    const records = makeRecords(3);
    const page1 = paginateApiKeys(records, 1);
    expect(page1.items).toHaveLength(1);
    expect(page1.nextCursor).not.toBeNull();
    const page2 = paginateApiKeys(records, 1, page1.nextCursor!);
    expect(page2.items).toHaveLength(1);
  });

  it('clamps over-limit value to API_KEYS_MAX_PAGE_SIZE', () => {
    const records = makeRecords(150);
    const result = paginateApiKeys(records, 999);
    expect(result.items).toHaveLength(API_KEYS_MAX_PAGE_SIZE);
  });

  it('treats limit=0 as 1 (minimum page size)', () => {
    const records = makeRecords(5);
    const result = paginateApiKeys(records, 0);
    expect(result.items).toHaveLength(1);
  });

  it('treats a negative limit as 1 (minimum page size)', () => {
    const records = makeRecords(5);
    const result = paginateApiKeys(records, -10);
    expect(result.items).toHaveLength(1);
  });

  it('uses default page size for a non-finite limit', () => {
    const records = makeRecords(50);
    const resultInf = paginateApiKeys(records, Infinity);
    expect(resultInf.items).toHaveLength(API_KEYS_DEFAULT_PAGE_SIZE);
    const resultNaN = paginateApiKeys(records, NaN);
    expect(resultNaN.items).toHaveLength(API_KEYS_DEFAULT_PAGE_SIZE);
  });

  // ── Sort order: newest-first (desc createdAt, then desc id) ──────────────

  it('returns items sorted newest-first by createdAt', () => {
    const records: ApiKeyCursorPosition[] = [
      { id: 'old', createdAt: '2024-01-01T00:00:00.000Z' },
      { id: 'new', createdAt: '2024-12-01T00:00:00.000Z' },
      { id: 'mid', createdAt: '2024-06-01T00:00:00.000Z' },
    ];
    const result = paginateApiKeys(records, 3);
    expect(result.items.map((i) => i.id)).toEqual(['new', 'mid', 'old']);
  });

  it('breaks createdAt ties by descending id (lexicographic)', () => {
    const sameTime = '2024-06-01T00:00:00.000Z';
    const records: ApiKeyCursorPosition[] = [
      { id: 'aa', createdAt: sameTime },
      { id: 'cc', createdAt: sameTime },
      { id: 'bb', createdAt: sameTime },
    ];
    const result = paginateApiKeys(records, 3);
    // Higher lexicographic id comes first
    expect(result.items.map((i) => i.id)).toEqual(['cc', 'bb', 'aa']);
  });

  // ── Stable sort: multiple traversals produce identical results ────────────

  it('is a pure function: same input produces the same output', () => {
    const records = makeRecords(30);
    const run1 = paginateApiKeys(records, 10);
    const run2 = paginateApiKeys(records, 10);
    expect(run1).toEqual(run2);
  });

  it('cursor chain is stable across re-traversals', () => {
    const records = makeRecords(25);

    function fullTraversal(): string[] {
      const ids: string[] = [];
      let cursor: string | undefined;
      for (;;) {
        const result = paginateApiKeys(records, 10, cursor);
        ids.push(...result.items.map((i) => i.id));
        if (result.nextCursor === null) break;
        cursor = result.nextCursor;
      }
      return ids;
    }

    expect(fullTraversal()).toEqual(fullTraversal());
  });

  // ── Input mutation: original array must not be mutated ────────────────────

  it('does not mutate the original records array', () => {
    const records = makeRecords(5);
    const original = records.map((r) => ({ ...r }));
    paginateApiKeys(records, 3);
    expect(records).toEqual(original);
  });

  // ── Invalid cursor propagation ────────────────────────────────────────────

  it('throws InvalidApiKeyCursorError for an empty cursor string', () => {
    const records = makeRecords(5);
    expect(() => paginateApiKeys(records, 10, '')).toThrow(InvalidApiKeyCursorError);
  });

  it('throws InvalidApiKeyCursorError for a tampered cursor', () => {
    const records = makeRecords(10);
    const page1 = paginateApiKeys(records, 5);
    const tampered = tamperPayload(page1.nextCursor!);
    expect(() => paginateApiKeys(records, 5, tampered)).toThrow(InvalidApiKeyCursorError);
  });

  it('throws InvalidApiKeyCursorError for a cursor signed with a wrong secret', () => {
    const records = makeRecords(10);
    const badCursor = encodeCursorWithSecret(
      { id: records[4].id, createdAt: records[4].createdAt },
      'attacker-secret',
    );
    expect(() => paginateApiKeys(records, 5, badCursor)).toThrow(InvalidApiKeyCursorError);
  });

  it('throws InvalidApiKeyCursorError for a plaintext string passed as cursor', () => {
    const records = makeRecords(5);
    expect(() => paginateApiKeys(records, 10, 'notatoken')).toThrow(InvalidApiKeyCursorError);
  });

  // ── Edge: cursor pointing past end of dataset ─────────────────────────────

  it('returns empty items with no nextCursor when cursor points past end of data', () => {
    const records = makeRecords(3);
    const page1 = paginateApiKeys(records, 3); // exactly 3 items, no nextCursor
    // There is nothing after the end; but if caller constructs a cursor manually
    // pointing to the last item, the next page should be empty.
    const lastItemCursor = encodeApiKeyCursor(records[records.length - 1]);
    const result = paginateApiKeys(records, 10, lastItemCursor);
    expect(result.items).toHaveLength(0);
    expect(result.nextCursor).toBeNull();
    // Sanity check: page1 also has no nextCursor since all items fit
    expect(page1.nextCursor).toBeNull();
  });
});

// ─── Concurrent / idempotency invariants ─────────────────────────────────────

describe('concurrency and idempotency invariants', () => {
  it('encoding and decoding are safe to call concurrently (same result)', async () => {
    const position: ApiKeyCursorPosition = {
      id: 'concurrent-key',
      createdAt: '2024-01-01T00:00:00.000Z',
    };
    const cursor = encodeApiKeyCursor(position);

    // Simulate concurrent decodes
    const results = await Promise.all(
      Array.from({ length: 20 }, () => Promise.resolve(decodeApiKeyCursor(cursor))),
    );

    for (const r of results) {
      expect(r).toEqual(position);
    }
  });

  it('paginateApiKeys results are consistent under concurrent calls with the same cursor', async () => {
    const records = makeRecords(30);
    const page1 = paginateApiKeys(records, 10);
    const cursorToken = page1.nextCursor!;

    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        Promise.resolve(paginateApiKeys(records, 10, cursorToken)),
      ),
    );

    const first = JSON.stringify(results[0]);
    for (const r of results.slice(1)) {
      expect(JSON.stringify(r)).toBe(first);
    }
  });

  it('parseApiKeyPageSize returns the same value under concurrent calls', async () => {
    const values = await Promise.all(
      Array.from({ length: 50 }, () => Promise.resolve(parseApiKeyPageSize('42'))),
    );
    for (const v of values) {
      expect(v).toBe(42);
    }
  });
});

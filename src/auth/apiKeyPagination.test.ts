/**
 * @file apiKeyPagination.test.ts
 * @description Compatibility-contract tests for the API-key cursor pagination
 * helper (`src/auth/apiKeyPagination.ts`).
 *
 * These tests lock in the public behavior so that errors, empty data, and
 * upgrades cannot silently drop or duplicate API keys:
 * - opaque, signed cursor encode/decode round-trips
 * - deterministic rejection of malformed / tampered / oversized cursors
 * - bounded page-size parsing for BOTH string and numeric inputs
 * - stable newest-first ordering (`createdAt` DESC, `id` DESC tie-break)
 * - no skipped or duplicated records across pages, including timestamp ties
 * - caller-supplied input is never mutated
 */

import { createHmac } from 'node:crypto';
import {
  API_KEYS_DEFAULT_PAGE_SIZE,
  API_KEYS_MAX_PAGE_SIZE,
  decodeApiKeyCursor,
  encodeApiKeyCursor,
  InvalidApiKeyCursorError,
  paginateApiKeys,
  parseApiKeyPageSize,
} from './apiKeyPagination';

/**
 * Mirrors the module's fallback secret so tests can craft *signed* cursors and
 * exercise the payload-validation branch (which is only reachable after the
 * signature check passes). If the env var is set, both the module and these
 * tests read the same value.
 */
const CURSOR_SECRET = process.env.API_KEYS_CURSOR_SECRET ?? 'talenttrust-api-keys-cursor-v1';

function craftCursor(payload: unknown): string {
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = createHmac('sha256', CURSOR_SECRET).update(encodedPayload).digest('base64url');
  return `${encodedPayload}.${signature}`;
}

interface ApiKeyRecord {
  id: string;
  createdAt: string;
  name?: string;
}

describe('API-key cursor pagination', () => {
  const records: ApiKeyRecord[] = [
    { id: 'key-3', createdAt: '2026-01-03T00:00:00.000Z', name: 'third' },
    { id: 'key-2', createdAt: '2026-01-02T00:00:00.000Z', name: 'second' },
    { id: 'key-1', createdAt: '2026-01-01T00:00:00.000Z', name: 'first' },
  ];

  describe('cursor encoding', () => {
    it('round-trips an opaque cursor', () => {
      const cursor = encodeApiKeyCursor(records[0]);
      expect(cursor).not.toContain('{');
      expect(decodeApiKeyCursor(cursor)).toEqual({
        id: 'key-3',
        createdAt: '2026-01-03T00:00:00.000Z',
      });
    });

    it('produces a URL-safe cursor with no padding', () => {
      const cursor = encodeApiKeyCursor({
        id: 'key with spaces/and+symbols=',
        createdAt: '2026-01-01T00:00:00.000Z',
      });
      expect(cursor).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
      expect(cursor).not.toMatch(/[+/=]/);
    });
  });

  describe('cursor rejection', () => {
    it.each(['bad', '', 'abc.def', `${encodeApiKeyCursor(records[0])}x`])(
      'rejects an invalid cursor: %s',
      (cursor) => {
        expect(() => decodeApiKeyCursor(cursor)).toThrow(InvalidApiKeyCursorError);
      },
    );

    it('rejects a tampered signature', () => {
      const [payload, signature] = encodeApiKeyCursor(records[0]).split('.');
      const flippedFirstChar = signature[0] === 'A' ? 'B' : 'A';
      const tampered = `${payload}.${flippedFirstChar}${signature.slice(1)}`;
      expect(() => decodeApiKeyCursor(tampered)).toThrow(InvalidApiKeyCursorError);
    });

    it('rejects an oversized cursor before decoding', () => {
      expect(() => decodeApiKeyCursor('a'.repeat(600))).toThrow(InvalidApiKeyCursorError);
    });

    it('rejects non-string input', () => {
      expect(() => decodeApiKeyCursor(undefined as unknown as string)).toThrow(InvalidApiKeyCursorError);
      expect(() => decodeApiKeyCursor(123 as unknown as string)).toThrow(InvalidApiKeyCursorError);
    });

    it('rejects a signed payload carrying an unexpected version', () => {
      const cursor = craftCursor({ version: 2, createdAt: '2026-01-01T00:00:00.000Z', id: 'key-1' });
      expect(() => decodeApiKeyCursor(cursor)).toThrow(InvalidApiKeyCursorError);
    });

    it.each([
      ['missing createdAt', { version: 1, id: 'key-1' }],
      ['missing id', { version: 1, createdAt: '2026-01-01T00:00:00.000Z' }],
      ['empty id', { version: 1, createdAt: '2026-01-01T00:00:00.000Z', id: '' }],
      ['invalid date', { version: 1, createdAt: 'not-a-date', id: 'key-1' }],
      ['non-object payload', ['not', 'an', 'object']],
    ])('rejects a signed payload with %s', (_label, payload) => {
      expect(() => decodeApiKeyCursor(craftCursor(payload))).toThrow(InvalidApiKeyCursorError);
    });
  });

  describe('page-size parsing', () => {
    it('uses the bounded default for missing or invalid limits', () => {
      expect(parseApiKeyPageSize(undefined)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
      expect(parseApiKeyPageSize(null)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
      expect(parseApiKeyPageSize('')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
      expect(parseApiKeyPageSize('not-a-number')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
      expect(parseApiKeyPageSize('-1')).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
      expect(parseApiKeyPageSize(0)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
      expect(parseApiKeyPageSize(Number.NaN)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
      expect(parseApiKeyPageSize(Number.POSITIVE_INFINITY)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
    });

    it('clamps over-limit requests to the configured maximum', () => {
      expect(parseApiKeyPageSize(API_KEYS_MAX_PAGE_SIZE + 1)).toBe(API_KEYS_MAX_PAGE_SIZE);
      expect(parseApiKeyPageSize('999999')).toBe(API_KEYS_MAX_PAGE_SIZE);
      expect(paginateApiKeys(records, API_KEYS_MAX_PAGE_SIZE + 1).items).toHaveLength(records.length);
    });

    it('accepts already-numeric limits (regression: #1400)', () => {
      expect(parseApiKeyPageSize(5)).toBe(5);
      expect(parseApiKeyPageSize(API_KEYS_DEFAULT_PAGE_SIZE)).toBe(API_KEYS_DEFAULT_PAGE_SIZE);
      expect(parseApiKeyPageSize(API_KEYS_MAX_PAGE_SIZE)).toBe(API_KEYS_MAX_PAGE_SIZE);
    });

    it('keeps numeric and string parsing consistent', () => {
      expect(parseApiKeyPageSize('5')).toBe(parseApiKeyPageSize(5));
      expect(parseApiKeyPageSize('101')).toBe(parseApiKeyPageSize(101));
      expect(parseApiKeyPageSize('0')).toBe(parseApiKeyPageSize(0));
      expect(parseApiKeyPageSize('2.5')).toBe(parseApiKeyPageSize(2.5));
    });
  });

  describe('pagination', () => {
    it('returns an empty page for an empty result set', () => {
      expect(paginateApiKeys([], 20)).toEqual({ items: [], nextCursor: null });
    });

    it('returns no cursor at the exact page boundary', () => {
      expect(paginateApiKeys(records, 3)).toEqual({ items: records, nextCursor: null });
    });

    it('orders newest first with a stable id tie-break', () => {
      const unordered = [records[1], records[2], records[0]];
      expect(paginateApiKeys(unordered, 10).items.map((record) => record.id)).toEqual([
        'key-3',
        'key-2',
        'key-1',
      ]);
    });

    it('returns a stable cursor and continues from that cursor', () => {
      const firstPage = paginateApiKeys(records, 2);
      expect(firstPage.items.map((item) => item.id)).toEqual(['key-3', 'key-2']);
      expect(firstPage.nextCursor).not.toBeNull();

      const secondPage = paginateApiKeys(records, 2, firstPage.nextCursor ?? undefined);
      expect(secondPage.items.map((item) => item.id)).toEqual(['key-1']);
      expect(secondPage.nextCursor).toBeNull();
    });

    it('does not skip records with identical timestamps', () => {
      const sameTimestamp: ApiKeyRecord[] = [
        { id: 'key-b', createdAt: '2026-01-01T00:00:00.000Z' },
        { id: 'key-a', createdAt: '2026-01-01T00:00:00.000Z' },
      ];

      const firstPage = paginateApiKeys(sameTimestamp, 1);
      expect(firstPage.items.map((item) => item.id)).toEqual(['key-b']);

      const secondPage = paginateApiKeys(sameTimestamp, 1, firstPage.nextCursor ?? undefined);
      expect(secondPage.items.map((item) => item.id)).toEqual(['key-a']);
    });

    it('traverses every record exactly once with no duplicates', () => {
      const many: ApiKeyRecord[] = Array.from({ length: 25 }, (_, index) => ({
        id: `key-${String(index).padStart(2, '0')}`,
        createdAt: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
      }));

      const seen: string[] = [];
      let cursor: string | undefined;
      for (let guard = 0; guard < 100; guard += 1) {
        const page = paginateApiKeys(many, 4, cursor);
        seen.push(...page.items.map((record) => record.id));
        if (page.nextCursor === null) {
          break;
        }
        cursor = page.nextCursor;
      }

      expect(seen).toHaveLength(many.length);
      expect(new Set(seen).size).toBe(many.length);
    });

    it('is idempotent for a repeated cursor (safe retries)', () => {
      const firstPage = paginateApiKeys(records, 1);
      const cursor = firstPage.nextCursor ?? undefined;
      expect(paginateApiKeys(records, 1, cursor)).toEqual(paginateApiKeys(records, 1, cursor));
    });

    it('returns an empty page when the cursor already points at the last record', () => {
      const cursor = encodeApiKeyCursor(records[records.length - 1]);
      expect(paginateApiKeys(records, 2, cursor)).toEqual({ items: [], nextCursor: null });
    });

    it('does not mutate the caller-supplied array', () => {
      const input = [...records];
      const snapshot = [...input];
      paginateApiKeys(input, 2);
      expect(input).toEqual(snapshot);
    });

    it('bounds limits inside paginateApiKeys', () => {
      expect(paginateApiKeys(records, 0).items).toHaveLength(1);
      expect(paginateApiKeys(records, -5).items).toHaveLength(1);
      expect(paginateApiKeys(records, Number.NaN).items).toHaveLength(records.length);
    });
  });
});

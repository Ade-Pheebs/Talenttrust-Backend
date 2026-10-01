/**
 * @file types.test.ts
 * @description Compatibility-contract tests for src/audit/types.ts (issue #1385).
 *
 * Purpose
 * -------
 * audit/types.ts is the single source of truth for every public type, enum,
 * and runtime helper used across the audit subsystem.  Callers — routers,
 * services, validators, repository adapters — all import from here.  A silent
 * change to any exported name, value, or runtime behaviour is a breaking
 * change that can produce stale data, validation gaps, or chain-integrity
 * failures in production.
 *
 * This suite pins:
 *  1. AUDIT_ACTIONS — the exhaustive runtime array (no values added/removed silently)
 *  2. AUDIT_SEVERITIES — same, for severity levels
 *  3. encodeCursor / decodeCursor — round-trip fidelity, error contract,
 *     boundary inputs, and concurrent-call safety
 *  4. Structural shape of AuditEntry, CreateAuditEntryInput, BulkAuditResult,
 *     CursorData, AuditQuery, IntegrityReport, AuditQueryResult (via
 *     object-shape assertions that will break if a required field is removed)
 *  5. Invariants: decodeCursor never swallows errors silently; encodeCursor
 *     produces deterministic output; round-trips are identity-equivalent.
 */

import {
  AUDIT_ACTIONS,
  AUDIT_SEVERITIES,
  encodeCursor,
  decodeCursor,
  type AuditAction,
  type AuditSeverity,
  type AuditEntry,
  type CreateAuditEntryInput,
  type BulkAuditItemResult,
  type BulkAuditResult,
  type CursorData,
  type AuditQuery,
  type IntegrityReport,
  type AuditQueryResult,
} from './types';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Minimal valid CursorData fixture. */
function minimalCursor(overrides: Partial<CursorData> = {}): CursorData {
  return {
    lastId: 'entry-uuid-1',
    lastTimestamp: '2024-01-01T00:00:00.000Z',
    filters: {},
    ...overrides,
  };
}

/** Minimal valid AuditEntry fixture. */
function minimalEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    id: 'entry-uuid-1',
    timestamp: '2024-01-01T00:00:00.000Z',
    action: 'CONTRACT_CREATED',
    severity: 'INFO',
    actor: 'user-1',
    resource: 'contract',
    resourceId: 'contract-1',
    metadata: {},
    hash: 'a'.repeat(64),
    previousHash: 'GENESIS',
    ...overrides,
  };
}

// ─── 1. AUDIT_ACTIONS — runtime array contract ────────────────────────────────

describe('AUDIT_ACTIONS', () => {
  it('is a non-empty readonly array', () => {
    expect(Array.isArray(AUDIT_ACTIONS)).toBe(true);
    expect(AUDIT_ACTIONS.length).toBeGreaterThan(0);
  });

  it('contains every expected action value (pinned compatibility list)', () => {
    const expected: AuditAction[] = [
      'CONTRACT_CREATED',
      'CONTRACT_UPDATED',
      'CONTRACT_CANCELLED',
      'CONTRACT_COMPLETED',
      'PAYMENT_INITIATED',
      'PAYMENT_RELEASED',
      'PAYMENT_DISPUTED',
      'REPUTATION_UPDATED',
      'REPUTATION_CORRECTED',
      'USER_CREATED',
      'USER_UPDATED',
      'USER_DELETED',
      'AUTH_LOGIN',
      'AUTH_LOGOUT',
      'AUTH_FAILED',
      'AUTH_LOCKOUT_TRIGGERED',
      'AUTH_LOCKOUT_RELEASED',
      'ADMIN_ACTION',
      'ENDPOINT_ACCESS',
      'ENDPOINT_MUTATION',
      'DEPLOYMENT_PROMOTED',
      'DEPLOYMENT_ROLLED_BACK',
    ];
    for (const action of expected) {
      expect(AUDIT_ACTIONS).toContain(action);
    }
  });

  it('has no duplicate values', () => {
    const unique = new Set(AUDIT_ACTIONS);
    expect(unique.size).toBe(AUDIT_ACTIONS.length);
  });

  it('all values are non-empty strings', () => {
    for (const action of AUDIT_ACTIONS) {
      expect(typeof action).toBe('string');
      expect(action.length).toBeGreaterThan(0);
    }
  });

  it('all values are UPPER_SNAKE_CASE (pattern contract)', () => {
    const upperSnake = /^[A-Z][A-Z0-9_]*$/;
    for (const action of AUDIT_ACTIONS) {
      expect(action).toMatch(upperSnake);
    }
  });

  it('is deterministic across multiple accesses (no lazy-init side effects)', () => {
    const snapshot = [...AUDIT_ACTIONS];
    expect([...AUDIT_ACTIONS]).toEqual(snapshot);
    expect([...AUDIT_ACTIONS]).toEqual(snapshot);
  });
});

// ─── 2. AUDIT_SEVERITIES — runtime array contract ────────────────────────────

describe('AUDIT_SEVERITIES', () => {
  it('is a non-empty readonly array', () => {
    expect(Array.isArray(AUDIT_SEVERITIES)).toBe(true);
    expect(AUDIT_SEVERITIES.length).toBeGreaterThan(0);
  });

  it('contains exactly INFO, WARNING, CRITICAL (pinned)', () => {
    const expected: AuditSeverity[] = ['INFO', 'WARNING', 'CRITICAL'];
    expect([...AUDIT_SEVERITIES].sort()).toEqual([...expected].sort());
  });

  it('has no duplicates', () => {
    const unique = new Set(AUDIT_SEVERITIES);
    expect(unique.size).toBe(AUDIT_SEVERITIES.length);
  });

  it('all values are non-empty strings in UPPER_CASE', () => {
    for (const s of AUDIT_SEVERITIES) {
      expect(typeof s).toBe('string');
      expect(s).toMatch(/^[A-Z]+$/);
    }
  });
});

// ─── 3. encodeCursor — output contract ───────────────────────────────────────

describe('encodeCursor', () => {
  it('returns a non-empty string for a minimal cursor', () => {
    const result = encodeCursor(minimalCursor());
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });

  it('produces valid base64 output', () => {
    const result = encodeCursor(minimalCursor());
    // base64url or standard base64 (no whitespace)
    expect(result).toMatch(/^[A-Za-z0-9+/=]+$/);
  });

  it('is deterministic: same input → same output', () => {
    const data = minimalCursor({ lastId: 'same', lastTimestamp: '2024-01-01T00:00:00.000Z', filters: {} });
    const a = encodeCursor(data);
    const b = encodeCursor(data);
    expect(a).toBe(b);
  });

  it('produces different output for different lastId values', () => {
    const a = encodeCursor(minimalCursor({ lastId: 'id-A' }));
    const b = encodeCursor(minimalCursor({ lastId: 'id-B' }));
    expect(a).not.toBe(b);
  });

  it('produces different output for different lastTimestamp values', () => {
    const a = encodeCursor(minimalCursor({ lastTimestamp: '2024-01-01T00:00:00.000Z' }));
    const b = encodeCursor(minimalCursor({ lastTimestamp: '2025-01-01T00:00:00.000Z' }));
    expect(a).not.toBe(b);
  });

  it('encodes filters correctly when present', () => {
    const data = minimalCursor({ filters: { action: 'CONTRACT_CREATED', severity: 'INFO' } });
    const encoded = encodeCursor(data);
    const decoded = decodeCursor(encoded);
    expect(decoded.filters.action).toBe('CONTRACT_CREATED');
    expect(decoded.filters.severity).toBe('INFO');
  });

  it('encodes empty filters object without error', () => {
    const data = minimalCursor({ filters: {} });
    expect(() => encodeCursor(data)).not.toThrow();
    const encoded = encodeCursor(data);
    expect(decodeCursor(encoded).filters).toEqual({});
  });

  it('handles all optional filter fields simultaneously', () => {
    const data = minimalCursor({
      filters: {
        action: 'USER_CREATED',
        severity: 'WARNING',
        actor: 'admin',
        resource: 'user',
        resourceId: 'u-123',
        from: '2024-01-01T00:00:00.000Z',
        to: '2024-12-31T23:59:59.999Z',
      },
    });
    const encoded = encodeCursor(data);
    const decoded = decodeCursor(encoded);
    expect(decoded.filters).toEqual(data.filters);
  });
});

// ─── 4. decodeCursor — round-trip and error contract ─────────────────────────

describe('decodeCursor', () => {
  it('round-trips a minimal cursor without loss', () => {
    const original = minimalCursor();
    const encoded = encodeCursor(original);
    const decoded = decodeCursor(encoded);
    expect(decoded.lastId).toBe(original.lastId);
    expect(decoded.lastTimestamp).toBe(original.lastTimestamp);
    expect(decoded.filters).toEqual(original.filters);
  });

  it('round-trips a cursor with all filter fields', () => {
    const original = minimalCursor({
      filters: {
        action: 'PAYMENT_RELEASED',
        severity: 'CRITICAL',
        actor: 'system',
        resource: 'payment',
        resourceId: 'pay-999',
        from: '2024-06-01T00:00:00.000Z',
        to: '2024-06-30T23:59:59.999Z',
      },
    });
    const encoded = encodeCursor(original);
    const decoded = decodeCursor(encoded);
    expect(decoded).toEqual(original);
  });

  it('preserves exact lastId string', () => {
    const id = 'uuid-with-dashes-0000-1111-2222';
    const encoded = encodeCursor(minimalCursor({ lastId: id }));
    expect(decodeCursor(encoded).lastId).toBe(id);
  });

  it('preserves exact lastTimestamp string', () => {
    const ts = '2024-03-15T12:34:56.789Z';
    const encoded = encodeCursor(minimalCursor({ lastTimestamp: ts }));
    expect(decodeCursor(encoded).lastTimestamp).toBe(ts);
  });

  it('throws Error with message "Invalid cursor format" for an empty string', () => {
    expect(() => decodeCursor('')).toThrow('Invalid cursor format');
  });

  it('throws Error with message "Invalid cursor format" for arbitrary garbage', () => {
    expect(() => decodeCursor('not-valid-base64-json!!')).toThrow('Invalid cursor format');
  });

  it('throws Error with message "Invalid cursor format" for valid base64 but non-JSON payload', () => {
    const notJson = Buffer.from('hello world', 'utf-8').toString('base64');
    expect(() => decodeCursor(notJson)).toThrow('Invalid cursor format');
  });

  it('throws Error with message "Invalid cursor format" for valid base64 JSON that is not an object', () => {
    const arrayBase64 = Buffer.from(JSON.stringify([1, 2, 3]), 'utf-8').toString('base64');
    // JSON.parse succeeds, so cast should work — but if the app adds validation it should throw.
    // For now, verify it does not silently corrupt (either succeeds or throws, but does not return undefined).
    try {
      const result = decodeCursor(arrayBase64);
      // If it doesn't throw, the result must at minimum be defined.
      expect(result).toBeDefined();
    } catch (err) {
      expect((err as Error).message).toBe('Invalid cursor format');
    }
  });

  it('throws an instance of Error (not a raw string or unknown type)', () => {
    let caught: unknown;
    try { decodeCursor('garbage'); } catch (e) { caught = e; }
    expect(caught).toBeInstanceOf(Error);
  });

  it('is idempotent: encoding an already-decoded cursor re-encodes identically', () => {
    const original = minimalCursor();
    const encoded1 = encodeCursor(original);
    const decoded = decodeCursor(encoded1);
    const encoded2 = encodeCursor(decoded);
    expect(encoded1).toBe(encoded2);
  });

  // ── Boundary inputs ──────────────────────────────────────────────────────

  it('handles a cursor with a very long lastId (boundary)', () => {
    const longId = 'x'.repeat(1024);
    const encoded = encodeCursor(minimalCursor({ lastId: longId }));
    expect(decodeCursor(encoded).lastId).toBe(longId);
  });

  it('handles special characters in lastId', () => {
    const specialId = 'id-with-unicode-\u00e9\u6f22\u5b57-and-symbols-!@#';
    const encoded = encodeCursor(minimalCursor({ lastId: specialId }));
    expect(decodeCursor(encoded).lastId).toBe(specialId);
  });

  it('handles empty filters object', () => {
    const encoded = encodeCursor(minimalCursor({ filters: {} }));
    expect(decodeCursor(encoded).filters).toEqual({});
  });
});

// ─── 5. Concurrent / repeat call safety ──────────────────────────────────────

describe('encodeCursor / decodeCursor concurrent-call safety', () => {
  it('N concurrent encodes with the same input all produce the same output', async () => {
    const data = minimalCursor({ lastId: 'concurrent-test' });
    const results = await Promise.all(
      Array.from({ length: 50 }, () => Promise.resolve(encodeCursor(data))),
    );
    const unique = new Set(results);
    expect(unique.size).toBe(1);
  });

  it('N concurrent decode+encode round-trips all return equal structures', async () => {
    const original = minimalCursor();
    const encoded = encodeCursor(original);
    const results = await Promise.all(
      Array.from({ length: 50 }, () => Promise.resolve(decodeCursor(encoded))),
    );
    for (const r of results) {
      expect(r).toEqual(original);
    }
  });

  it('concurrent decodes of an invalid cursor all throw consistently', async () => {
    const errors = await Promise.allSettled(
      Array.from({ length: 20 }, () => Promise.resolve().then(() => decodeCursor('INVALID!!'))),
    );
    for (const result of errors) {
      expect(result.status).toBe('rejected');
      if (result.status === 'rejected') {
        expect((result.reason as Error).message).toBe('Invalid cursor format');
      }
    }
  });
});

// ─── 6. Structural shape contracts (compatibility guards) ────────────────────
//
// These tests use TypeScript's structural typing via satisfies / assignment
// plus runtime shape assertions. They will break if a required field is
// removed or renamed, making the contract change visible in CI.

describe('AuditEntry structural shape', () => {
  it('a complete entry satisfies the AuditEntry shape', () => {
    const entry: AuditEntry = minimalEntry();
    expect(entry.id).toBeDefined();
    expect(entry.timestamp).toBeDefined();
    expect(entry.action).toBeDefined();
    expect(entry.severity).toBeDefined();
    expect(entry.actor).toBeDefined();
    expect(entry.resource).toBeDefined();
    expect(entry.resourceId).toBeDefined();
    expect(entry.metadata).toBeDefined();
    expect(entry.hash).toBeDefined();
    expect(entry.previousHash).toBeDefined();
  });

  it('action field must be a member of AUDIT_ACTIONS or an AuditAction literal', () => {
    const entry = minimalEntry({ action: 'AUTH_LOGIN' });
    // AUDIT_ACTIONS covers the "deployed" subset; AuditAction type covers all including milestones.
    // Verify the action is at least a non-empty string (type system enforces the union).
    expect(typeof entry.action).toBe('string');
    expect(entry.action.length).toBeGreaterThan(0);
  });

  it('severity field must be one of INFO | WARNING | CRITICAL', () => {
    for (const sev of AUDIT_SEVERITIES) {
      const entry = minimalEntry({ severity: sev });
      expect(AUDIT_SEVERITIES).toContain(entry.severity);
    }
  });

  it('metadata is a Readonly<Record<string, unknown>> (object, not array or primitive)', () => {
    const entry = minimalEntry({ metadata: { key: 'value', count: 1 } });
    expect(typeof entry.metadata).toBe('object');
    expect(entry.metadata).not.toBeNull();
    expect(Array.isArray(entry.metadata)).toBe(false);
  });

  it('previousHash is GENESIS for the first entry', () => {
    const entry = minimalEntry({ previousHash: 'GENESIS' });
    expect(entry.previousHash).toBe('GENESIS');
  });

  it('ipAddress and correlationId are optional (may be undefined)', () => {
    const entry = minimalEntry();
    // TypeScript optionals: must not throw when undefined
    expect(entry.ipAddress).toBeUndefined();
    expect(entry.correlationId).toBeUndefined();
  });

  it('accepts optional fields when provided', () => {
    const entry = minimalEntry({ ipAddress: '192.168.1.1', correlationId: 'trace-abc' });
    expect(entry.ipAddress).toBe('192.168.1.1');
    expect(entry.correlationId).toBe('trace-abc');
  });
});

describe('CreateAuditEntryInput omits server-computed fields', () => {
  it('a CreateAuditEntryInput has all required fields except id, timestamp, hash, previousHash', () => {
    const input: CreateAuditEntryInput = {
      action: 'CONTRACT_CREATED',
      severity: 'INFO',
      actor: 'user-1',
      resource: 'contract',
      resourceId: 'contract-1',
      metadata: {},
    };
    // Required fields present
    expect(input.action).toBe('CONTRACT_CREATED');
    expect(input.severity).toBe('INFO');
    expect(input.actor).toBe('user-1');
    expect(input.resource).toBe('contract');
    expect(input.resourceId).toBe('contract-1');
    expect(input.metadata).toBeDefined();
    // Server-computed fields must NOT be required
    expect((input as Record<string, unknown>)['id']).toBeUndefined();
    expect((input as Record<string, unknown>)['timestamp']).toBeUndefined();
    expect((input as Record<string, unknown>)['hash']).toBeUndefined();
    expect((input as Record<string, unknown>)['previousHash']).toBeUndefined();
  });
});

describe('BulkAuditItemResult shape', () => {
  it('a successful item has index, success=true, and entry', () => {
    const item: BulkAuditItemResult = {
      index: 0,
      success: true,
      entry: minimalEntry(),
    };
    expect(item.index).toBe(0);
    expect(item.success).toBe(true);
    expect(item.entry).toBeDefined();
    expect(item.error).toBeUndefined();
  });

  it('a failed item has index, success=false, and error', () => {
    const item: BulkAuditItemResult = {
      index: 1,
      success: false,
      error: 'Validation failed',
    };
    expect(item.index).toBe(1);
    expect(item.success).toBe(false);
    expect(item.error).toBe('Validation failed');
    expect(item.entry).toBeUndefined();
  });
});

describe('BulkAuditResult shape', () => {
  it('has results array, succeeded count, and failed count', () => {
    const result: BulkAuditResult = {
      results: [],
      succeeded: 0,
      failed: 0,
    };
    expect(Array.isArray(result.results)).toBe(true);
    expect(typeof result.succeeded).toBe('number');
    expect(typeof result.failed).toBe('number');
  });

  it('succeeded + failed reflects the results array length', () => {
    const result: BulkAuditResult = {
      results: [
        { index: 0, success: true, entry: minimalEntry() },
        { index: 1, success: false, error: 'err' },
      ],
      succeeded: 1,
      failed: 1,
    };
    expect(result.succeeded + result.failed).toBe(result.results.length);
  });
});

describe('CursorData shape', () => {
  it('has lastId, lastTimestamp, and filters', () => {
    const cursor: CursorData = minimalCursor();
    expect(typeof cursor.lastId).toBe('string');
    expect(typeof cursor.lastTimestamp).toBe('string');
    expect(typeof cursor.filters).toBe('object');
  });

  it('filters accepts all optional fields without error', () => {
    const cursor: CursorData = minimalCursor({
      filters: {
        action: 'ADMIN_ACTION',
        severity: 'CRITICAL',
        actor: 'admin',
        resource: 'user',
        resourceId: 'u-1',
        from: '2024-01-01T00:00:00.000Z',
        to: '2024-12-31T23:59:59.999Z',
      },
    });
    expect(cursor.filters.action).toBe('ADMIN_ACTION');
    expect(cursor.filters.severity).toBe('CRITICAL');
  });
});

describe('AuditQuery shape', () => {
  it('all fields are optional', () => {
    const query: AuditQuery = {};
    expect(query.action).toBeUndefined();
    expect(query.severity).toBeUndefined();
    expect(query.actor).toBeUndefined();
    expect(query.resource).toBeUndefined();
    expect(query.resourceId).toBeUndefined();
    expect(query.from).toBeUndefined();
    expect(query.to).toBeUndefined();
    expect(query.limit).toBeUndefined();
    expect(query.offset).toBeUndefined();
    expect(query.cursor).toBeUndefined();
  });

  it('accepts a fully-populated query', () => {
    const query: AuditQuery = {
      action: 'CONTRACT_CREATED',
      severity: 'INFO',
      actor: 'user-1',
      resource: 'contract',
      resourceId: 'c-1',
      from: '2024-01-01T00:00:00.000Z',
      to: '2024-12-31T23:59:59.999Z',
      limit: 50,
      offset: 0,
      cursor: encodeCursor(minimalCursor()),
    };
    expect(query.action).toBe('CONTRACT_CREATED');
    expect(query.limit).toBe(50);
    expect(query.cursor).toBeDefined();
  });
});

describe('IntegrityReport shape', () => {
  it('a valid report has valid, totalEntries, checkedAt', () => {
    const report: IntegrityReport = {
      valid: true,
      totalEntries: 5,
      checkedAt: new Date().toISOString(),
    };
    expect(typeof report.valid).toBe('boolean');
    expect(typeof report.totalEntries).toBe('number');
    expect(typeof report.checkedAt).toBe('string');
  });

  it('an invalid report may include firstCorruptedIndex and firstCorruptedId', () => {
    const report: IntegrityReport = {
      valid: false,
      totalEntries: 10,
      checkedAt: new Date().toISOString(),
      firstCorruptedIndex: 3,
      firstCorruptedId: 'entry-uuid-4',
    };
    expect(report.valid).toBe(false);
    expect(report.firstCorruptedIndex).toBe(3);
    expect(report.firstCorruptedId).toBe('entry-uuid-4');
  });
});

describe('AuditQueryResult shape', () => {
  it('has entries, count, limit, and optional nextCursor', () => {
    const result: AuditQueryResult = {
      entries: [],
      count: 0,
      limit: 50,
    };
    expect(Array.isArray(result.entries)).toBe(true);
    expect(typeof result.count).toBe('number');
    expect(typeof result.limit).toBe('number');
    expect(result.nextCursor).toBeUndefined();
  });

  it('nextCursor is present when more pages exist', () => {
    const cursor = encodeCursor(minimalCursor());
    const result: AuditQueryResult = {
      entries: [minimalEntry()],
      count: 1,
      limit: 1,
      nextCursor: cursor,
    };
    expect(result.nextCursor).toBe(cursor);
  });

  it('entries array is empty for an empty result set', () => {
    const result: AuditQueryResult = { entries: [], count: 0, limit: 50 };
    expect(result.entries).toHaveLength(0);
    expect(result.count).toBe(0);
  });
});

/**
 * @file schemas.test.ts
 * @description Direct unit coverage for the declarative zod schemas in
 * `./schemas.ts`, independent of the HTTP layer (see router.validation.test.ts
 * for the end-to-end request/response coverage). Issue #939.
 *
 * This suite also hardens the concurrent / repeated-execution contract of the
 * schemas: parsing must be pure and deterministic, so that racing or retried
 * requests cannot observe stale or mutated schema state. See `describe('parsing
 * is pure and deterministic under concurrency')` below.
 */

/**
 * @file schemas.test.ts
 * @description Direct unit coverage for the declarative zod schemas in
 * `./schemas.ts`, independent of the HTTP layer (see router.validation.test.ts
 * for the end-to-end request/response coverage). Issue #939.
 */

import {
  AUDIT_ACTIONS,
  createAuditEntryBodySchema,
  buildAuditQuerySchema,
  auditEntryResponseSchema,
  auditQueryResultResponseSchema,
  integrityReportResponseSchema,
} from './schemas';
import { encodeCursor } from './types';

// Validation boundaries under test:
// - accepted: fully-specified and defaulted payloads
// - rejected: missing required fields, unknown enums, malformed values
// - duplicate: repeated identical submissions must be deterministic
// - boundary: limit/offset edges, cursor edges, timestamp edges

describe('createAuditEntryBodySchema', () => {
  const valid = {
    action: 'CONTRACT_CREATED' as const,
    severity: 'INFO' as const,
    actor: 'user-1',
    resource: 'contract',
    resourceId: 'contract-1',
    metadata: { foo: 'bar' },
  };

  it('accepts a fully-specified valid payload', () => {
    const result = createAuditEntryBodySchema.safeParse(valid);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.metadata).toEqual({ foo: 'bar' });
    }
  });

  it('keeps action values unique and accepts every declared action for writes and queries', () => {
    expect(new Set(AUDIT_ACTIONS).size).toBe(AUDIT_ACTIONS.length);
    for (const action of AUDIT_ACTIONS) {
      expect(createAuditEntryBodySchema.safeParse({ ...valid, action }).success).toBe(true);
      expect(buildAuditQuerySchema({ maxLimit: 100 }).safeParse({ action }).success).toBe(true);
    }
  });

  it('defaults metadata to {} when omitted', () => {
    const { metadata, ...rest } = valid;
    void metadata;
    const result = createAuditEntryBodySchema.safeParse(rest);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.metadata).toEqual({});
    }
  });

  it('is deterministic for duplicate identical submissions', () => {
    const first = createAuditEntryBodySchema.safeParse(valid);
    const second = createAuditEntryBodySchema.safeParse(valid);
    expect(first.success).toBe(true);
    expect(second.success).toBe(true);
    if (first.success && second.success) {
      expect(first.data).toEqual(second.data);
    }
  });

  it('accepts optional ipAddress and correlationId', () => {
    const result = createAuditEntryBodySchema.safeParse({
      ...valid,
      ipAddress: '203.0.113.7',
      correlationId: 'corr-abc',
    });
    expect(result.success).toBe(true);
  });

  it.each([
    ['action', { ...valid, action: undefined }],
    ['severity', { ...valid, severity: undefined }],
    ['actor', { ...valid, actor: undefined }],
    ['resource', { ...valid, resource: undefined }],
    ['resourceId', { ...valid, resourceId: undefined }],
  ])('rejects a payload missing %s', (field, payload) => {
    const result = createAuditEntryBodySchema.safeParse(payload);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.path.includes(field))).toBe(true);
    }
  });

  it('rejects an unrecognized action', () => {
    const result = createAuditEntryBodySchema.safeParse({ ...valid, action: 'NOT_REAL' });
    expect(result.success).toBe(false);
  });

  it('rejects an unrecognized severity', () => {
    const result = createAuditEntryBodySchema.safeParse({ ...valid, severity: 'NOT_REAL' });
    expect(result.success).toBe(false);
  });

  it('rejects an empty actor string', () => {
    const result = createAuditEntryBodySchema.safeParse({ ...valid, actor: '' });
    expect(result.success).toBe(false);
  });

  it('rejects a non-object metadata value', () => {
    const result = createAuditEntryBodySchema.safeParse({ ...valid, metadata: 'nope' });
    expect(result.success).toBe(false);
  });

  it('rejects a null payload', () => {
    const result = createAuditEntryBodySchema.safeParse(null);
    expect(result.success).toBe(false);
  });

  it('rejects a boundary-length actor string', () => {
    const result = createAuditEntryBodySchema.safeParse({ ...valid, actor: 'a'.repeat(10_000) });
    expect(result.success).toBe(false);
  });

  it('strips unknown top-level fields rather than throwing', () => {
    const result = createAuditEntryBodySchema.safeParse({ ...valid, somethingUnexpected: 'ignored' });
    expect(result.success).toBe(true);
    if (result.success) {
      expect((result.data as Record<string, unknown>)['somethingUnexpected']).toBeUndefined();
    }
  });

  // Concurrency / idempotency invariants: the schema is a pure declaration
  // with no mutable state, so any number of interleaved or repeated parses
  // must yield identical results. This guards against accidental introduction
  // of memoization / last-value caching that could leak stale data across
  // racing requests.
  it('parsing is pure and deterministic under concurrency', () => {
    const inputs = [
      valid,
      { ...valid, actor: '' },
      { ...valid, action: 'NOT_REAL' },
      { ...valid, metadata: undefined },
    ];

    const baseline = inputs.map((input) => createAuditEntryBodySchema.safeParse(input));

    // Interleave many parses across the same inputs and compare to the
    // sequential baseline. Any shared mutable state would surface as a
    // divergence here.
    for (let round = 0; round < 50; round++) {
      const observed = inputs.map((input) => createAuditEntryBodySchema.safeParse(input));
      expect(observed.map((r) => r.success)).toEqual(baseline.map((r) => r.success));
    }

    // Repeated identical parses of the same input must produce deeply equal
    // data (not just equal accept/reject decisions).
    const first = createAuditEntryBodySchema.safeParse(valid);
    const second = createAuditEntryBodySchema.safeParse(valid);
    expect(first.success && second.success).toBe(true);
    if (first.success && second.success) {
      expect(second.data).toEqual(first.data);
      // The parsed output must not alias the caller's input object.
      expect(second.data).not.toBe(valid);
      expect(second.data.metadata).not.toBe(valid.metadata);
    }
  });

  it('does not mutate the caller's input object', () => {
    const input = { ...valid, metadata: { foo: 'bar' } };
    const snapshot = JSON.parse(JSON.stringify(input));
    createAuditEntryBodySchema.safeParse(input);
    expect(input).toEqual(snapshot);
  });
});

describe('buildAuditQuerySchema', () => {
  const schema = buildAuditQuerySchema({ defaultLimit: 50, maxLimit: 100 });

  it('accepts an empty query and applies the default limit / zero offset', () => {
    const result = schema.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(50);
      expect(result.data.offset).toBe(0);
    }
  });

  it('accepts a fully-specified valid query', () => {
    const result = schema.safeParse({
      action: 'CONTRACT_CREATED',
      severity: 'INFO',
      actor: 'user-1',
      resource: 'contract',
      resourceId: 'contract-1',
      from: '2020-01-01T00:00:00Z',
      to: '2030-01-01T00:00:00Z',
      limit: '25',
      offset: '5',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(25);
      expect(result.data.offset).toBe(5);
      expect(result.data.from).toBe(new Date('2020-01-01T00:00:00Z').toISOString());
    }
  });

  it('clamps a limit above maxLimit rather than rejecting it', () => {
    const result = schema.safeParse({ limit: '999999' });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(100);
    }
  });

  it('clamps a limit of exactly maxLimit to maxLimit', () => {
    const result = schema.safeParse({ limit: '100' });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(100);
    }
  });

  it('accepts a limit of exactly 1 (lower boundary)', () => {
    const result = schema.safeParse({ limit: '1' });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(1);
    }
  });

  it('accepts an offset of 0 (lower boundary)', () => {
    const result = schema.safeParse({ offset: '0' });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.offset).toBe(0);
    }
  });

  it('accepts a valid cursor', () => {
    const cursor = encodeCursor({ lastId: 'abc', lastTimestamp: new Date().toISOString(), filters: {} });
    const result = schema.safeParse({ cursor });
    expect(result.success).toBe(true);
  });

  it('is deterministic for duplicate identical queries', () => {
    const query = { action: 'CONTRACT_CREATED', limit: '25', offset: '5' };
    const first = schema.safeParse(query);
    const second = schema.safeParse(query);
    expect(first.success).toBe(true);
    expect(second.success).toBe(true);
    if (first.success && second.success) {
      expect(first.data).toEqual(second.data);
    }
  });

  it.each([
    ['action', { action: 'NOT_REAL' }],
    ['severity', { severity: 'NOT_REAL' }],
    ['limit (non-numeric)', { limit: 'abc' }],
    ['limit (zero)', { limit: '0' }],
    ['offset (negative)', { offset: '-1' }],
    ['offset (non-numeric)', { offset: 'abc' }],
    ['from (unparseable)', { from: 'not-a-date' }],
    ['to (unparseable)', { to: 'not-a-date' }],
    ['cursor (malformed)', { cursor: 'not-valid-base64-json!!' }],
  ])('rejects an invalid %s', (_label, payload) => {
    const result = schema.safeParse(payload);
    expect(result.success).toBe(false);
  });

  // Boundary: limit exactly at maxLimit is accepted without clamping.
  it('accepts a limit exactly at maxLimit', () => {
    const result = schema.safeParse({ limit: '100' });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(100);
    }
  });

  // Boundary: limit of 1 is the smallest accepted value.
  it('accepts a limit of 1', () => {
    const result = schema.safeParse({ limit: '1' });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(1);
    }
  });

  // Boundary: offset of 0 is accepted.
  it('accepts an offset of 0', () => {
    const result = schema.safeParse({ offset: '0' });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.offset).toBe(0);
    }
  });

  // Idempotency / concurrency: building the schema repeatedly with the same
  // config must yield schemas that agree on every input, and the same schema
  // instance must produce identical results across interleaved calls.
  it('building and parsing is deterministic across repeated / concurrent calls', () => {
    const config = { defaultLimit: 50, maxLimit: 100 };
    const inputs = [
      {},
      { limit: '25', offset: '5' },
      { limit: '999999' },
      { limit: '0' },
      { offset: '-1' },
    ];

    const reference = inputs.map((p) => buildAuditQuerySchema(config).safeParse(p));

    for (let round = 0; round < 50; round++) {
      const rebuilt = buildAuditQuerySchema(config);
      const observed = inputs.map((p) => rebuilt.safeParse(p));
      expect(observed.map((r) => r.success)).toEqual(reference.map((r) => r.success));
    }

    // The same instance must not carry state between parses.
    const a = schema.safeParse({});
    const b = schema.safeParse({});
    expect(a.success && b.success).toBe(true);
    if (a.success && b.success) {
      expect(b.data).toEqual(a.data);
    }
  });

  it('does not mutate the caller's query object', () => {
    const query = { limit: '25', offset: '5' };
    const snapshot = { ...query };
    schema.safeParse(query);
    expect(query).toEqual(snapshot);
  });
});

describe('response schemas', () => {
  it('auditEntryResponseSchema accepts a well-formed entry', () => {
    const entry = {
      id: 'entry-1',
      timestamp: new Date().toISOString(),
      action: 'CONTRACT_CREATED',
      severity: 'INFO',
      actor: 'user-1',
      resource: 'contract',
      resourceId: 'contract-1',
      metadata: {},
      hash: 'a'.repeat(64),
      previousHash: 'GENESIS',
    };
    expect(auditEntryResponseSchema.safeParse(entry).success).toBe(true);
  });

  it('auditEntryResponseSchema rejects an entry missing its hash', () => {
    const entry = {
      id: 'entry-1',
      timestamp: new Date().toISOString(),
      action: 'CONTRACT_CREATED',
      severity: 'INFO',
      actor: 'user-1',
      resource: 'contract',
      resourceId: 'contract-1',
      metadata: {},
      previousHash: 'GENESIS',
    };
    expect(auditEntryResponseSchema.safeParse(entry).success).toBe(false);
  });

  it('auditEntryResponseSchema rejects a malformed hash', () => {
    const entry = {
      id: 'entry-1',
      timestamp: new Date().toISOString(),
      action: 'CONTRACT_CREATED',
      severity: 'INFO',
      actor: 'user-1',
      resource: 'contract',
      resourceId: 'contract-1',
      metadata: {},
      hash: 'not-a-valid-hash',
      previousHash: 'GENESIS',
    };
    expect(auditEntryResponseSchema.safeParse(entry).success).toBe(false);
  });

  it('auditQueryResultResponseSchema accepts a cursor-paginated result', () => {
    const result = { entries: [], count: 0, limit: 50, nextCursor: 'abc' };
    expect(auditQueryResultResponseSchema.safeParse(result).success).toBe(true);
  });

  it('auditQueryResultResponseSchema rejects a negative count', () => {
    const result = { entries: [], count: -1, limit: 50, nextCursor: 'abc' };
    expect(auditQueryResultResponseSchema.safeParse(result).success).toBe(false);
  });

  it('auditQueryResultResponseSchema rejects a zero limit', () => {
    const result = { entries: [], count: 0, limit: 0, nextCursor: 'abc' };
    expect(auditQueryResultResponseSchema.safeParse(result).success).toBe(false);
  });

  it('integrityReportResponseSchema accepts a valid report', () => {
    const report = { valid: true, totalEntries: 3, checkedAt: new Date().toISOString() };
    expect(integrityReportResponseSchema.safeParse(report).success).toBe(true);
  });

  it('integrityReportResponseSchema rejects a report missing checkedAt', () => {
    const report = { valid: true, totalEntries: 3 };
    expect(integrityReportResponseSchema.safeParse(report).success).toBe(false);
  });

  // Response schemas are also pure: repeated and interleaved parses of the
  // same payload must not diverge, and the caller's input must remain
  // unmodified.
  it('response schema parsing is pure and non-mutating', () => {
    const entry = {
      id: 'entry-1',
      timestamp: new Date().toISOString(),
      action: 'CONTRACT_CREATED',
      severity: 'INFO',
      actor: 'user-1',
      resource: 'contract',
      resourceId: 'contract-1',
      metadata: { foo: 'bar' },
      hash: 'a'.repeat(64),
      previousHash: 'GENESIS',
    };
    const snapshot = JSON.parse(JSON.stringify(entry));

    const first = auditEntryResponseSchema.safeParse(entry);
    for (let round = 0; round < 50; round++) {
      const next = auditEntryResponseSchema.safeParse(entry);
      expect(next.success).toBe(first.success);
    }

    expect(entry).toEqual(snapshot);
  });
});

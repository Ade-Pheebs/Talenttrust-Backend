/**
 * @file schemas.test.ts
 * @description Direct unit coverage for the declarative zod schemas in
 * `./schemas.ts`, independent of the HTTP layer (see router.validation.test.ts
 * for the end-to-end request/response coverage). Issue #939.
 */

/**
 * @file schemas.test.ts
 * @description Direct unit coverage for the declarative zod schemas in
 * `./schemas.ts`, independent of the HTTP layer (see router.validation.test.ts
 * for the end-to-end request/response coverage). Issue #939.
 */

import {
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

  it('rejects a from timestamp after the to timestamp', () => {
    const result = schema.safeParse({
      from: '2030-01-01T00:00:00Z',
      to: '2020-01-01T00:00:00Z',
    });
    expect(result.success).toBe(false);
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

  it('integrityReportResponseSchema rejects a negative totalEntries', () => {
    const report = { valid: true, totalEntries: -1, checkedAt: new Date().toISOString() };
    expect(integrityReportResponseSchema.safeParse(report).success).toBe(false);
  });

  it('integrityReportResponseSchema accepts a zero totalEntries boundary', () => {
    const report = { valid: true, totalEntries: 0, checkedAt: new Date().toISOString() };
    expect(integrityReportResponseSchema.safeParse(report).success).toBe(true);
  });
});

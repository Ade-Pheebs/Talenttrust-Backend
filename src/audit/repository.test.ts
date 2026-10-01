/**
 * @file repository.test.ts
 * @description Focused validation tests for the audit repository boundary.
 *
 * Scope (issue #1351):
 * 1. Input validation for CreateAuditEntryInput - reject invalid types, lengths, formats
 * 2. Query validation for AuditQuery - validate and coerce parameters to safe defaults
 * 3. Environment variable validation - validate backend selection and paths
 * 4. Boundary cases - empty strings, max lengths, edge values
 * 5. Error messages - diagnostic without exposing sensitive data
 * 6. Backward compatibility - valid inputs continue to work
 */

import { auditStore } from './store';
import { createDefaultAuditRepository } from './repository';
import type { CreateAuditEntryInput, AuditQuery } from './types';
import {
  validateStringField,
  validateEnum,
  validateMetadata,
  validateTimestamp,
  validateLimit,
  validateOffset,
  AUDIT_ACTIONS,
  AUDIT_SEVERITIES,
  MAX_STRING_LENGTH,
  MAX_METADATA_LENGTH,
  MAX_QUERY_LIMIT,
  MIN_QUERY_LIMIT,
  AuditValidationError,
} from './types';

// ─── Fixtures ───────────────────────────────────────────────────────────────

function makeInput(overrides: Partial<CreateAuditEntryInput> = {}): CreateAuditEntryInput {
  return {
    action: 'CONTRACT_CREATED',
    severity: 'INFO',
    actor: 'user-1',
    resource: 'contract',
    resourceId: 'contract-1',
    metadata: { key: 'value' },
    ...overrides,
  };
}

// ─── Validation helpers tests ─────────────────────────────────────────────────

describe('validateStringField', () => {
  it('accepts valid strings within length limit', () => {
    const result = validateStringField('valid-string', 'testField');
    expect(result.valid).toBe(true);
    expect(result.data).toBe('valid-string');
  });

  it('rejects non-string values', () => {
    const result = validateStringField(123, 'testField');
    expect(result.valid).toBe(false);
    expect(result.error).toBeInstanceOf(AuditValidationError);
    expect(result.error?.field).toBe('testField');
    expect(result.error?.constraint).toBe('type: string');
  });

  it('rejects empty strings', () => {
    const result = validateStringField('', 'testField');
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe('minLength: 1');
  });

  it('rejects strings exceeding max length', () => {
    const longString = 'a'.repeat(MAX_STRING_LENGTH + 1);
    const result = validateStringField(longString, 'testField');
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe(`maxLength: ${MAX_STRING_LENGTH}`);
  });

  it('accepts strings at max length boundary', () => {
    const maxString = 'a'.repeat(MAX_STRING_LENGTH);
    const result = validateStringField(maxString, 'testField');
    expect(result.valid).toBe(true);
  });
});

describe('validateEnum', () => {
  it('accepts valid enum values', () => {
    const result = validateEnum('CONTRACT_CREATED', 'action', AUDIT_ACTIONS);
    expect(result.valid).toBe(true);
    expect(result.data).toBe('CONTRACT_CREATED');
  });

  it('rejects invalid enum values', () => {
    const result = validateEnum('INVALID_ACTION', 'action', AUDIT_ACTIONS);
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toContain('CONTRACT_CREATED');
  });

  it('rejects non-string values', () => {
    const result = validateEnum(123, 'action', AUDIT_ACTIONS);
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe('type: string');
  });
});

describe('validateTimestamp', () => {
  it('accepts valid ISO-8601 timestamps', () => {
    const result = validateTimestamp('2024-01-15T10:00:00.000Z', 'testField');
    expect(result.valid).toBe(true);
    expect(result.data).toBe('2024-01-15T10:00:00.000Z');
  });

  it('accepts ISO-8601 with timezone offset', () => {
    const result = validateTimestamp('2024-01-15T10:00:00+05:00', 'testField');
    expect(result.valid).toBe(true);
  });

  it('rejects non-string values', () => {
    const result = validateTimestamp(123, 'testField');
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe('type: string');
  });

  it('rejects invalid date formats', () => {
    const result = validateTimestamp('not-a-date', 'testField');
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe('format: ISO-8601');
  });

  it('rejects invalid dates', () => {
    const result = validateTimestamp('invalid-date-string', 'testField');
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe('format: ISO-8601');
  });
});

describe('validateMetadata', () => {
  it('accepts valid plain objects', () => {
    const result = validateMetadata({ key: 'value' }, 'metadata');
    expect(result.valid).toBe(true);
    expect(result.data).toEqual({ key: 'value' });
  });

  it('accepts null and undefined as empty object', () => {
    const nullResult = validateMetadata(null, 'metadata');
    expect(nullResult.valid).toBe(true);
    expect(nullResult.data).toEqual({});

    const undefinedResult = validateMetadata(undefined, 'metadata');
    expect(undefinedResult.valid).toBe(true);
    expect(undefinedResult.data).toEqual({});
  });

  it('rejects arrays', () => {
    const result = validateMetadata([1, 2, 3], 'metadata');
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe('type: object');
  });

  it('rejects non-object values', () => {
    const result = validateMetadata('string', 'metadata');
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe('type: object');
  });

  it('rejects metadata exceeding serialized size limit', () => {
    const largeMetadata = { data: 'x'.repeat(MAX_METADATA_LENGTH + 1) };
    const result = validateMetadata(largeMetadata, 'metadata');
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe(`maxSerializedLength: ${MAX_METADATA_LENGTH}`);
  });
});

describe('validateLimit', () => {
  it('accepts valid limit values', () => {
    const result = validateLimit(50);
    expect(result.valid).toBe(true);
    expect(result.data).toBe(50);
  });

  it('uses default for undefined', () => {
    const result = validateLimit(undefined);
    expect(result.valid).toBe(true);
    expect(result.data).toBe(50);
  });

  it('uses default for null', () => {
    const result = validateLimit(null);
    expect(result.valid).toBe(true);
    expect(result.data).toBe(50);
  });

  it('rejects non-number values', () => {
    const result = validateLimit('50' as any);
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe('type: number');
  });

  it('rejects infinite values', () => {
    const result = validateLimit(Infinity);
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe('finite');
  });

  it('rejects values below minimum', () => {
    const result = validateLimit(0);
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe(`min: ${MIN_QUERY_LIMIT}`);
  });

  it('rejects values above maximum', () => {
    const result = validateLimit(MAX_QUERY_LIMIT + 1);
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe(`max: ${MAX_QUERY_LIMIT}`);
  });

  it('accepts boundary values', () => {
    const minResult = validateLimit(MIN_QUERY_LIMIT);
    expect(minResult.valid).toBe(true);

    const maxResult = validateLimit(MAX_QUERY_LIMIT);
    expect(maxResult.valid).toBe(true);
  });

  it('floors decimal values', () => {
    const result = validateLimit(50.7);
    expect(result.valid).toBe(true);
    expect(result.data).toBe(50);
  });
});

describe('validateOffset', () => {
  it('accepts valid offset values', () => {
    const result = validateOffset(10);
    expect(result.valid).toBe(true);
    expect(result.data).toBe(10);
  });

  it('uses default for undefined', () => {
    const result = validateOffset(undefined);
    expect(result.valid).toBe(true);
    expect(result.data).toBe(0);
  });

  it('uses default for null', () => {
    const result = validateOffset(null);
    expect(result.valid).toBe(true);
    expect(result.data).toBe(0);
  });

  it('rejects non-number values', () => {
    const result = validateOffset('10' as any);
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe('type: number');
  });

  it('rejects infinite values', () => {
    const result = validateOffset(Infinity);
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe('finite');
  });

  it('rejects negative values', () => {
    const result = validateOffset(-1);
    expect(result.valid).toBe(false);
    expect(result.error?.constraint).toBe('min: 0');
  });

  it('accepts zero', () => {
    const result = validateOffset(0);
    expect(result.valid).toBe(true);
    expect(result.data).toBe(0);
  });

  it('floors decimal values', () => {
    const result = validateOffset(10.7);
    expect(result.valid).toBe(true);
    expect(result.data).toBe(10);
  });
});

// ─── Repository validation tests ───────────────────────────────────────────────

describe('createDefaultAuditRepository - environment validation', () => {
  const originalEnv = process.env;

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('accepts valid memory backend', () => {
    process.env['AUDIT_STORAGE_BACKEND'] = 'memory';
    const repo = createDefaultAuditRepository();
    expect(repo).toBeDefined();
  });

  it('accepts valid sqlite backend', () => {
    process.env['AUDIT_STORAGE_BACKEND'] = 'sqlite';
    process.env['AUDIT_DB_PATH'] = ':memory:';
    const repo = createDefaultAuditRepository();
    expect(repo).toBeDefined();
  });

  it('rejects invalid backend', () => {
    process.env['AUDIT_STORAGE_BACKEND'] = 'invalid-backend' as any;
    expect(() => createDefaultAuditRepository()).toThrow('Unsupported AUDIT_STORAGE_BACKEND');
  });

  it('rejects non-string dbPath', () => {
    process.env['AUDIT_STORAGE_BACKEND'] = 'sqlite';
    process.env['AUDIT_DB_PATH'] = 123 as any;
    expect(() => createDefaultAuditRepository()).toThrow('AUDIT_DB_PATH must be a string');
  });
});

describe('Repository - CreateAuditEntryInput validation', () => {
  let repo: ReturnType<typeof createDefaultAuditRepository>;

  beforeEach(() => {
    process.env['AUDIT_STORAGE_BACKEND'] = 'memory';
    repo = createDefaultAuditRepository();
    auditStore._reset();
  });

  afterEach(() => {
    auditStore._reset();
  });

  it('accepts valid input', () => {
    const input = makeInput();
    const entry = repo.append(input);
    expect(entry).toBeDefined();
    expect(entry.action).toBe('CONTRACT_CREATED');
  });

  it('rejects invalid action', () => {
    const input = makeInput({ action: 'INVALID_ACTION' as any });
    expect(() => repo.append(input)).toThrow(AuditValidationError);
    expect(() => repo.append(input)).toThrow('action must be one of');
  });

  it('rejects invalid severity', () => {
    const input = makeInput({ severity: 'INVALID_SEVERITY' as any });
    expect(() => repo.append(input)).toThrow(AuditValidationError);
    expect(() => repo.append(input)).toThrow('severity must be one of');
  });

  it('rejects empty actor', () => {
    const input = makeInput({ actor: '' });
    expect(() => repo.append(input)).toThrow(AuditValidationError);
    expect(() => repo.append(input)).toThrow('actor cannot be empty');
  });

  it('rejects non-string actor', () => {
    const input = makeInput({ actor: 123 as any });
    expect(() => repo.append(input)).toThrow(AuditValidationError);
    expect(() => repo.append(input)).toThrow('actor must be a string');
  });

  it('rejects empty resource', () => {
    const input = makeInput({ resource: '' });
    expect(() => repo.append(input)).toThrow(AuditValidationError);
    expect(() => repo.append(input)).toThrow('resource cannot be empty');
  });

  it('rejects empty resourceId', () => {
    const input = makeInput({ resourceId: '' });
    expect(() => repo.append(input)).toThrow(AuditValidationError);
    expect(() => repo.append(input)).toThrow('resourceId cannot be empty');
  });

  it('rejects array metadata', () => {
    const input = makeInput({ metadata: [1, 2, 3] as any });
    expect(() => repo.append(input)).toThrow(AuditValidationError);
    expect(() => repo.append(input)).toThrow('metadata must be a plain object');
  });

  it('rejects oversized metadata', () => {
    const largeMetadata = { data: 'x'.repeat(MAX_METADATA_LENGTH + 1) };
    const input = makeInput({ metadata: largeMetadata });
    expect(() => repo.append(input)).toThrow(AuditValidationError);
    expect(() => repo.append(input)).toThrow('metadata serialized size exceeds maximum');
  });

  it('accepts null ipAddress', () => {
    const input = makeInput({ ipAddress: null });
    const entry = repo.append(input);
    expect(entry).toBeDefined();
  });

  it('accepts valid ipAddress', () => {
    const input = makeInput({ ipAddress: '192.168.1.1' });
    const entry = repo.append(input);
    expect(entry).toBeDefined();
  });

  it('rejects invalid ipAddress', () => {
    const input = makeInput({ ipAddress: 123 as any });
    expect(() => repo.append(input)).toThrow(AuditValidationError);
  });

  it('accepts null correlationId', () => {
    const input = makeInput({ correlationId: null });
    const entry = repo.append(input);
    expect(entry).toBeDefined();
  });

  it('accepts valid correlationId', () => {
    const input = makeInput({ correlationId: 'req-123' });
    const entry = repo.append(input);
    expect(entry).toBeDefined();
  });

  it('rejects invalid correlationId', () => {
    const input = makeInput({ correlationId: 123 as any });
    expect(() => repo.append(input)).toThrow(AuditValidationError);
  });
});

describe('Repository - AuditQuery validation', () => {
  let repo: ReturnType<typeof createDefaultAuditRepository>;

  beforeEach(() => {
    process.env['AUDIT_STORAGE_BACKEND'] = 'memory';
    repo = createDefaultAuditRepository();
    auditStore._reset();
  });

  afterEach(() => {
    auditStore._reset();
    jest.clearAllMocks();
  });

  it('accepts valid query with no filters', () => {
    repo.append(makeInput({ actor: 'alice' }));
    repo.append(makeInput({ actor: 'bob' }));
    const results = repo.query();
    expect(results).toHaveLength(2);
  });

  it('applies default limit when not specified', () => {
    repo.append(makeInput({ actor: 'alice' }));
    const results = repo.query({});
    expect(results.length).toBeLessThanOrEqual(50);
  });

  it('validates and coerces limit to safe default on error', () => {
    repo.append(makeInput({ actor: 'alice' }));
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
    const results = repo.query({ limit: 'invalid' as any });
    expect(results).toBeDefined(); // Should not throw, just log error
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[repository] Invalid limit'),
      expect.any(String),
    );
    consoleSpy.mockRestore();
  });

  it('validates and coerces offset to safe default on error', () => {
    repo.append(makeInput({ actor: 'alice' }));
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
    const results = repo.query({ offset: 'invalid' as any });
    expect(results).toBeDefined(); // Should not throw, just log error
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[repository] Invalid offset'),
      expect.any(String),
    );
    consoleSpy.mockRestore();
  });

  it('rejects limit below minimum and logs error', () => {
    repo.append(makeInput({ actor: 'alice' }));
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
    const results = repo.query({ limit: 0 });
    expect(results).toBeDefined(); // Should use default
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[repository] Invalid limit'),
      expect.any(String),
    );
    consoleSpy.mockRestore();
  });

  it('rejects limit above maximum and logs error', () => {
    repo.append(makeInput({ actor: 'alice' }));
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
    const results = repo.query({ limit: MAX_QUERY_LIMIT + 1 });
    expect(results).toBeDefined(); // Should use default
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[repository] Invalid limit'),
      expect.any(String),
    );
    consoleSpy.mockRestore();
  });

  it('rejects invalid timestamp filter and logs error', () => {
    repo.append(makeInput({ actor: 'alice' }));
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
    const results = repo.query({ from: 'invalid-date' });
    expect(results).toBeDefined(); // Should ignore invalid filter
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[repository] Invalid from timestamp'),
      expect.any(String),
    );
    consoleSpy.mockRestore();
  });

  it('rejects invalid action filter and logs error', () => {
    repo.append(makeInput({ actor: 'alice' }));
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
    const results = repo.query({ action: 'INVALID_ACTION' as any });
    expect(results).toBeDefined(); // Should ignore invalid filter
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[repository] Invalid action filter'),
      expect.any(String),
    );
    consoleSpy.mockRestore();
  });

  it('rejects invalid severity filter and logs error', () => {
    repo.append(makeInput({ actor: 'alice' }));
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
    const results = repo.query({ severity: 'INVALID_SEVERITY' as any });
    expect(results).toBeDefined(); // Should ignore invalid filter
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[repository] Invalid severity filter'),
      expect.any(String),
    );
    consoleSpy.mockRestore();
  });

  it('rejects invalid actor filter and logs error', () => {
    repo.append(makeInput({ actor: 'alice' }));
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
    const results = repo.query({ actor: 123 as any });
    expect(results).toBeDefined(); // Should ignore invalid filter
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[repository] Invalid actor filter'),
      expect.any(String),
    );
    consoleSpy.mockRestore();
  });

  it('accepts valid filters', () => {
    repo.append(makeInput({ actor: 'alice' }));
    repo.append(makeInput({ actor: 'bob' }));
    const results = repo.query({ actor: 'alice' });
    expect(results).toHaveLength(1);
    expect(results[0].actor).toBe('alice');
  });
});

describe('Repository - getById validation', () => {
  let repo: ReturnType<typeof createDefaultAuditRepository>;

  beforeEach(() => {
    process.env['AUDIT_STORAGE_BACKEND'] = 'memory';
    repo = createDefaultAuditRepository();
    auditStore._reset();
  });

  afterEach(() => {
    auditStore._reset();
    jest.clearAllMocks();
  });

  it('accepts valid id', () => {
    const entry = repo.append(makeInput());
    const retrieved = repo.getById(entry.id);
    expect(retrieved).toBeDefined();
    expect(retrieved?.id).toBe(entry.id);
  });

  it('returns undefined for invalid id format', () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
    const entry = repo.getById('');
    expect(entry).toBeUndefined();
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[repository] Invalid id'),
      expect.any(String),
    );
    consoleSpy.mockRestore();
  });

  it('returns undefined for non-string id', () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
    const entry = repo.getById(123 as any);
    expect(entry).toBeUndefined();
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[repository] Invalid id'),
      expect.any(String),
    );
    consoleSpy.mockRestore();
  });
});

describe('Repository - backward compatibility', () => {
  let repo: ReturnType<typeof createDefaultAuditRepository>;

  beforeEach(() => {
    process.env['AUDIT_STORAGE_BACKEND'] = 'memory';
    repo = createDefaultAuditRepository();
    auditStore._reset();
  });

  afterEach(() => {
    auditStore._reset();
  });

  it('existing valid inputs continue to work', () => {
    const input = makeInput({
      action: 'CONTRACT_CREATED',
      severity: 'INFO',
      actor: 'user-123',
      resource: 'contract',
      resourceId: 'contract-abc',
      metadata: { field: 'value', nested: { data: 123 } },
      ipAddress: '192.168.1.1',
      correlationId: 'trace-xyz',
    });
    const entry = repo.append(input);
    expect(entry).toBeDefined();
    expect(entry.action).toBe('CONTRACT_CREATED');
    expect(entry.actor).toBe('user-123');
  });

  it('query with valid filters works', () => {
    repo.append(makeInput({ action: 'CONTRACT_CREATED', actor: 'alice' }));
    repo.append(makeInput({ action: 'CONTRACT_UPDATED', actor: 'bob' }));

    const results = repo.query({ action: 'CONTRACT_CREATED', actor: 'alice' });
    expect(results).toHaveLength(1);
    expect(results[0].actor).toBe('alice');
  });

  it('queryWithCursor works with validated queries', () => {
    for (let i = 0; i < 5; i++) {
      repo.append(makeInput({ resourceId: `contract-${i}` }));
    }

    const result = repo.queryWithCursor({ limit: 2 });
    expect(result.entries).toHaveLength(2);
    expect(result.count).toBe(2);
    expect(result.nextCursor).toBeDefined();
  });

  it('stream works with validated queries', () => {
    repo.append(makeInput({ actor: 'alice' }));
    repo.append(makeInput({ actor: 'bob' }));

    const results = Array.from(repo.stream({ actor: 'alice' }));
    expect(results).toHaveLength(1);
    expect(results[0].actor).toBe('alice');
  });
});

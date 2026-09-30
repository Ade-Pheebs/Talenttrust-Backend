/**
 * @file inputValidation.test.ts
 * @description Focused unit tests for `src/audit/inputValidation.ts`.
 *
 * Coverage targets (mapped to issue #1333 acceptance criteria):
 *
 * 1. **Deterministic behaviour** — same input always produces the same result
 *    (success or the same set of issues). No randomness, no I/O dependency.
 *
 * 2. **Valid inputs** — a well-formed `CreateAuditEntryInput` passes
 *    validation and the returned object contains only the known fields.
 *
 * 3. **Required-field rejection** — missing or blank `action`, `severity`,
 *    `actor`, `resource`, `resourceId`, `metadata` each produce a named issue.
 *
 * 4. **Enum membership** — an unrecognised `action` or `severity` is rejected
 *    with a descriptive message that does not expose the submitted value.
 *
 * 5. **metadata shape** — null, arrays, primitives, and circular structures
 *    are all rejected; nested plain objects are accepted.
 *
 * 6. **Optional-field typing** — `ipAddress` and `correlationId` are accepted
 *    when absent, accepted when valid strings, and rejected when wrong-typed
 *    or empty.
 *
 * 7. **Length limits** — fields exceeding their documented max length are
 *    rejected with a constraint-violation issue.
 *
 * 8. **All-errors-at-once** — multiple simultaneous violations are collected
 *    into a single throw rather than one at a time.
 *
 * 9. **Unknown fields stripped** — extra properties on the input are not
 *    present on the returned value (no prototype pollution vector).
 *
 * 10. **AuditValidationError shape** — the thrown error is an instance of
 *     `AuditValidationError`, extends `AppError`, has `statusCode === 400`,
 *     `code === "validation_error"`, and carries a frozen `issues` array.
 *
 * 11. **Non-object input** — null, arrays, primitives, and strings all throw
 *     a single structural issue before any field checks run.
 *
 * 12. **Integration** — AuditService.log() surfaces AuditValidationError for
 *     invalid input and persists a frozen AuditEntry for valid input; the
 *     router POST handler returns HTTP 400 + issues for invalid input and
 *     HTTP 201 for valid input.
 *
 * 13. **Regression: no silent data loss** — a repository write failure still
 *     throws (the service does not swallow it), so callers are never told a
 *     write succeeded when it did not.
 */

import request from 'supertest';
import express from 'express';
import {
  validateAuditInput,
  AuditValidationError,
  VALID_AUDIT_ACTIONS,
  VALID_AUDIT_SEVERITIES,
} from './inputValidation';
import { AppError, APP_ERROR_CODES } from '../errors/appError';
import { AuditService } from './service';
import { AuditStore } from './store';
import { createAuditRouter } from './router';
import { AuditExportService } from './exportService';
import type { CreateAuditEntryInput } from './types';
import type { AuditLogRepository } from './repository';
import type { AuditEntry, AuditQuery, IntegrityReport, AuditQueryResult } from './types';

// ─── Test fixtures ────────────────────────────────────────────────────────────

/** A minimal valid input that should always pass. */
function validInput(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    action: 'CONTRACT_CREATED',
    severity: 'INFO',
    actor: 'user-abc',
    resource: 'contract',
    resourceId: 'contract-1',
    metadata: { clientId: 'client-1' },
    ...overrides,
  };
}

// ─── Unit tests: validateAuditInput ──────────────────────────────────────────

describe('validateAuditInput', () => {
  // ── 1. Valid inputs ──────────────────────────────────────────────────────

  describe('valid inputs', () => {
    it('returns a typed CreateAuditEntryInput for a minimal valid object', () => {
      const result = validateAuditInput(validInput());
      expect(result.action).toBe('CONTRACT_CREATED');
      expect(result.severity).toBe('INFO');
      expect(result.actor).toBe('user-abc');
      expect(result.resource).toBe('contract');
      expect(result.resourceId).toBe('contract-1');
      expect(result.metadata).toEqual({ clientId: 'client-1' });
    });

    it('accepts all valid AuditAction values', () => {
      for (const action of VALID_AUDIT_ACTIONS) {
        expect(() => validateAuditInput(validInput({ action }))).not.toThrow();
      }
    });

    it('accepts all valid AuditSeverity values', () => {
      for (const severity of VALID_AUDIT_SEVERITIES) {
        expect(() => validateAuditInput(validInput({ severity }))).not.toThrow();
      }
    });

    it('accepts optional ipAddress when provided', () => {
      const result = validateAuditInput(validInput({ ipAddress: '192.168.1.1' }));
      expect(result.ipAddress).toBe('192.168.1.1');
    });

    it('accepts optional correlationId when provided', () => {
      const result = validateAuditInput(validInput({ correlationId: 'corr-123' }));
      expect(result.correlationId).toBe('corr-123');
    });

    it('accepts ipAddress of valid IPv6 length', () => {
      const ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'; // 39 chars
      expect(() => validateAuditInput(validInput({ ipAddress: ipv6 }))).not.toThrow();
    });

    it('accepts metadata with nested plain objects', () => {
      const result = validateAuditInput(
        validInput({ metadata: { nested: { deep: { value: 42 } } } }),
      );
      expect((result.metadata as Record<string, unknown>)['nested']).toEqual({ deep: { value: 42 } });
    });

    it('accepts metadata with array values', () => {
      const result = validateAuditInput(validInput({ metadata: { tags: ['a', 'b', 'c'] } }));
      expect((result.metadata as Record<string, unknown>)['tags']).toEqual(['a', 'b', 'c']);
    });

    it('accepts an empty metadata object', () => {
      const result = validateAuditInput(validInput({ metadata: {} }));
      expect(result.metadata).toEqual({});
    });

    it('is deterministic: calling with the same input twice returns the same shape', () => {
      const input = validInput();
      const r1 = validateAuditInput(input);
      const r2 = validateAuditInput(input);
      expect(r1).toEqual(r2);
    });
  });

  // ── 2. Non-object structural guard ──────────────────────────────────────

  describe('non-object input', () => {
    it.each([
      ['null', null],
      ['undefined', undefined],
      ['a string', 'contract_created'],
      ['a number', 42],
      ['an array', ['CONTRACT_CREATED', 'INFO']],
      ['a boolean', true],
    ])('rejects %s with a structural issue before field checks', (_label, value) => {
      expect(() => validateAuditInput(value)).toThrow(AuditValidationError);
      try {
        validateAuditInput(value);
      } catch (err) {
        expect(err).toBeInstanceOf(AuditValidationError);
        const e = err as AuditValidationError;
        expect(e.issues).toHaveLength(1);
        expect(e.issues[0]!.field).toBe('input');
      }
    });
  });

  // ── 3. Required-field rejection ──────────────────────────────────────────

  describe('required field: action', () => {
    it('rejects missing action', () => {
      const input = validInput();
      delete (input as Record<string, unknown>)['action'];
      expect(() => validateAuditInput(input)).toThrow(AuditValidationError);
      try { validateAuditInput(input); } catch (e) {
        expect((e as AuditValidationError).issues.some(i => i.field === 'action')).toBe(true);
      }
    });

    it('rejects null action', () => {
      expect(() => validateAuditInput(validInput({ action: null }))).toThrow(AuditValidationError);
    });

    it('rejects empty string action', () => {
      expect(() => validateAuditInput(validInput({ action: '' }))).toThrow(AuditValidationError);
    });

    it('rejects whitespace-only action', () => {
      expect(() => validateAuditInput(validInput({ action: '   ' }))).toThrow(AuditValidationError);
    });

    it('rejects numeric action', () => {
      expect(() => validateAuditInput(validInput({ action: 42 }))).toThrow(AuditValidationError);
    });
  });

  describe('required field: severity', () => {
    it('rejects missing severity', () => {
      const input = validInput();
      delete (input as Record<string, unknown>)['severity'];
      expect(() => validateAuditInput(input)).toThrow(AuditValidationError);
    });

    it('rejects null severity', () => {
      expect(() => validateAuditInput(validInput({ severity: null }))).toThrow(AuditValidationError);
    });

    it('rejects empty string severity', () => {
      expect(() => validateAuditInput(validInput({ severity: '' }))).toThrow(AuditValidationError);
    });
  });

  describe('required field: actor', () => {
    it('rejects missing actor', () => {
      const input = validInput();
      delete (input as Record<string, unknown>)['actor'];
      expect(() => validateAuditInput(input)).toThrow(AuditValidationError);
    });

    it('rejects empty string actor', () => {
      expect(() => validateAuditInput(validInput({ actor: '' }))).toThrow(AuditValidationError);
    });

    it('rejects whitespace-only actor', () => {
      expect(() => validateAuditInput(validInput({ actor: '  ' }))).toThrow(AuditValidationError);
    });
  });

  describe('required field: resource', () => {
    it('rejects missing resource', () => {
      const input = validInput();
      delete (input as Record<string, unknown>)['resource'];
      expect(() => validateAuditInput(input)).toThrow(AuditValidationError);
    });

    it('rejects empty string resource', () => {
      expect(() => validateAuditInput(validInput({ resource: '' }))).toThrow(AuditValidationError);
    });
  });

  describe('required field: resourceId', () => {
    it('rejects missing resourceId', () => {
      const input = validInput();
      delete (input as Record<string, unknown>)['resourceId'];
      expect(() => validateAuditInput(input)).toThrow(AuditValidationError);
    });

    it('rejects empty string resourceId', () => {
      expect(() => validateAuditInput(validInput({ resourceId: '' }))).toThrow(AuditValidationError);
    });
  });

  describe('required field: metadata', () => {
    it('rejects missing metadata', () => {
      const input = validInput();
      delete (input as Record<string, unknown>)['metadata'];
      expect(() => validateAuditInput(input)).toThrow(AuditValidationError);
    });

    it('rejects null metadata', () => {
      expect(() => validateAuditInput(validInput({ metadata: null }))).toThrow(AuditValidationError);
      try { validateAuditInput(validInput({ metadata: null })); } catch (e) {
        expect((e as AuditValidationError).issues.some(i => i.field === 'metadata')).toBe(true);
      }
    });

    it('rejects array metadata', () => {
      expect(() => validateAuditInput(validInput({ metadata: ['a', 'b'] }))).toThrow(AuditValidationError);
      try { validateAuditInput(validInput({ metadata: ['a', 'b'] })); } catch (e) {
        expect((e as AuditValidationError).issues.some(i => i.field === 'metadata')).toBe(true);
      }
    });

    it('rejects string metadata', () => {
      expect(() => validateAuditInput(validInput({ metadata: 'string' }))).toThrow(AuditValidationError);
    });

    it('rejects numeric metadata', () => {
      expect(() => validateAuditInput(validInput({ metadata: 42 }))).toThrow(AuditValidationError);
    });

    it('rejects boolean metadata', () => {
      expect(() => validateAuditInput(validInput({ metadata: true }))).toThrow(AuditValidationError);
    });

    it('rejects metadata with circular references (not JSON-serialisable)', () => {
      const circular: Record<string, unknown> = {};
      circular['self'] = circular;
      expect(() => validateAuditInput(validInput({ metadata: circular }))).toThrow(AuditValidationError);
      try { validateAuditInput(validInput({ metadata: circular })); } catch (e) {
        const issue = (e as AuditValidationError).issues.find(i => i.field === 'metadata');
        expect(issue).toBeDefined();
        expect(issue!.message).toContain('JSON-serialisable');
      }
    });
  });

  // ── 4. Enum membership ───────────────────────────────────────────────────

  describe('enum: action', () => {
    it('rejects an unrecognised action string', () => {
      expect(() => validateAuditInput(validInput({ action: 'NOT_A_REAL_ACTION' }))).toThrow(
        AuditValidationError,
      );
      try { validateAuditInput(validInput({ action: 'NOT_A_REAL_ACTION' })); } catch (e) {
        const issue = (e as AuditValidationError).issues.find(i => i.field === 'action');
        expect(issue).toBeDefined();
        // Message must reference the field name but NOT the submitted value
        expect(issue!.message).not.toContain('NOT_A_REAL_ACTION');
        expect(issue!.message).toContain('AuditAction');
      }
    });

    it('rejects a lower-case action that would match if case-insensitive', () => {
      expect(() => validateAuditInput(validInput({ action: 'contract_created' }))).toThrow(
        AuditValidationError,
      );
    });
  });

  describe('enum: severity', () => {
    it('rejects an unrecognised severity string', () => {
      expect(() => validateAuditInput(validInput({ severity: 'URGENT' }))).toThrow(
        AuditValidationError,
      );
      try { validateAuditInput(validInput({ severity: 'URGENT' })); } catch (e) {
        const issue = (e as AuditValidationError).issues.find(i => i.field === 'severity');
        expect(issue).toBeDefined();
        expect(issue!.message).toContain('INFO, WARNING, CRITICAL');
      }
    });

    it('rejects a lower-case severity', () => {
      expect(() => validateAuditInput(validInput({ severity: 'info' }))).toThrow(
        AuditValidationError,
      );
    });
  });

  // ── 5. Optional field typing ─────────────────────────────────────────────

  describe('optional field: ipAddress', () => {
    it('accepts absent ipAddress (not in input)', () => {
      const input = validInput();
      delete (input as Record<string, unknown>)['ipAddress'];
      expect(() => validateAuditInput(input)).not.toThrow();
      const result = validateAuditInput(input);
      expect(result.ipAddress).toBeUndefined();
    });

    it('rejects numeric ipAddress', () => {
      expect(() => validateAuditInput(validInput({ ipAddress: 12345 }))).toThrow(AuditValidationError);
    });

    it('rejects empty string ipAddress', () => {
      expect(() => validateAuditInput(validInput({ ipAddress: '' }))).toThrow(AuditValidationError);
    });

    it('rejects whitespace-only ipAddress', () => {
      expect(() => validateAuditInput(validInput({ ipAddress: '   ' }))).toThrow(AuditValidationError);
    });

    it('rejects ipAddress exceeding 45 characters', () => {
      const tooLong = 'a'.repeat(46);
      expect(() => validateAuditInput(validInput({ ipAddress: tooLong }))).toThrow(AuditValidationError);
      try { validateAuditInput(validInput({ ipAddress: tooLong })); } catch (e) {
        const issue = (e as AuditValidationError).issues.find(i => i.field === 'ipAddress');
        expect(issue!.message).toContain('45');
      }
    });
  });

  describe('optional field: correlationId', () => {
    it('accepts absent correlationId', () => {
      const input = validInput();
      delete (input as Record<string, unknown>)['correlationId'];
      expect(() => validateAuditInput(input)).not.toThrow();
    });

    it('rejects numeric correlationId', () => {
      expect(() => validateAuditInput(validInput({ correlationId: 99 }))).toThrow(AuditValidationError);
    });

    it('rejects empty string correlationId', () => {
      expect(() => validateAuditInput(validInput({ correlationId: '' }))).toThrow(AuditValidationError);
    });

    it('rejects correlationId exceeding 256 characters', () => {
      const tooLong = 'c'.repeat(257);
      expect(() => validateAuditInput(validInput({ correlationId: tooLong }))).toThrow(AuditValidationError);
    });
  });

  // ── 6. Length limits ─────────────────────────────────────────────────────

  describe('length limits', () => {
    it('rejects actor longer than 256 characters', () => {
      const actor = 'a'.repeat(257);
      expect(() => validateAuditInput(validInput({ actor }))).toThrow(AuditValidationError);
      try { validateAuditInput(validInput({ actor })); } catch (e) {
        const issue = (e as AuditValidationError).issues.find(i => i.field === 'actor');
        expect(issue!.message).toContain('256');
      }
    });

    it('accepts actor exactly at 256 characters', () => {
      const actor = 'a'.repeat(256);
      expect(() => validateAuditInput(validInput({ actor }))).not.toThrow();
    });

    it('rejects resource longer than 256 characters', () => {
      const resource = 'r'.repeat(257);
      expect(() => validateAuditInput(validInput({ resource }))).toThrow(AuditValidationError);
    });

    it('rejects resourceId longer than 256 characters', () => {
      const resourceId = 'i'.repeat(257);
      expect(() => validateAuditInput(validInput({ resourceId }))).toThrow(AuditValidationError);
    });
  });

  // ── 7. All-errors-at-once collection ────────────────────────────────────

  describe('all-errors-at-once', () => {
    it('collects multiple field issues into a single throw', () => {
      try {
        validateAuditInput({
          action: 'BAD_ACTION',
          severity: 'BAD_SEVERITY',
          actor: '',
          resource: '',
          resourceId: '',
          metadata: null,
        });
        fail('Expected AuditValidationError to be thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(AuditValidationError);
        const e = err as AuditValidationError;
        // All six fields should appear in issues
        const fields = e.issues.map((i) => i.field);
        expect(fields).toContain('action');
        expect(fields).toContain('severity');
        expect(fields).toContain('actor');
        expect(fields).toContain('resource');
        expect(fields).toContain('resourceId');
        expect(fields).toContain('metadata');
        expect(e.issues.length).toBeGreaterThanOrEqual(6);
      }
    });

    it('is deterministic: the same multi-field invalid input always throws the same issues', () => {
      const badInput = { action: 'BAD', severity: 'BAD', actor: '', resource: '', resourceId: '', metadata: null };
      let issues1: AuditValidationError['issues'] | null = null;
      let issues2: AuditValidationError['issues'] | null = null;
      try { validateAuditInput(badInput); } catch (e) { issues1 = (e as AuditValidationError).issues; }
      try { validateAuditInput(badInput); } catch (e) { issues2 = (e as AuditValidationError).issues; }
      expect(issues1).not.toBeNull();
      expect(issues2).not.toBeNull();
      expect(issues1).toEqual(issues2);
    });
  });

  // ── 8. Unknown fields stripped ───────────────────────────────────────────

  describe('unknown field stripping', () => {
    it('drops unknown fields from the returned value', () => {
      const result = validateAuditInput(validInput({ unknownField: 'should-be-dropped', __proto__: {} }));
      expect((result as Record<string, unknown>)['unknownField']).toBeUndefined();
    });

    it('does not expose prototype properties on the returned value', () => {
      const result = validateAuditInput(validInput());
      // Only the documented contract fields should exist
      const keys = Object.keys(result);
      const allowed = new Set(['action', 'severity', 'actor', 'resource', 'resourceId', 'metadata', 'ipAddress', 'correlationId']);
      for (const key of keys) {
        expect(allowed.has(key)).toBe(true);
      }
    });
  });

  // ── 9. AuditValidationError shape ────────────────────────────────────────

  describe('AuditValidationError', () => {
    it('is an instance of AppError', () => {
      try {
        validateAuditInput({});
      } catch (err) {
        expect(err).toBeInstanceOf(AppError);
      }
    });

    it('has statusCode 400', () => {
      try {
        validateAuditInput(validInput({ action: 'BAD' }));
      } catch (err) {
        expect((err as AuditValidationError).statusCode).toBe(400);
      }
    });

    it('has code "validation_error"', () => {
      try {
        validateAuditInput(validInput({ action: 'BAD' }));
      } catch (err) {
        expect((err as AuditValidationError).code).toBe(APP_ERROR_CODES.VALIDATION_ERROR);
      }
    });

    it('has name "AuditValidationError"', () => {
      try {
        validateAuditInput(validInput({ action: 'BAD' }));
      } catch (err) {
        expect((err as AuditValidationError).name).toBe('AuditValidationError');
      }
    });

    it('has a frozen issues array', () => {
      try {
        validateAuditInput(validInput({ action: 'BAD' }));
      } catch (err) {
        expect(Object.isFrozen((err as AuditValidationError).issues)).toBe(true);
      }
    });

    it('message includes field names from issues', () => {
      try {
        validateAuditInput(validInput({ action: 'BAD', severity: 'BAD' }));
      } catch (err) {
        expect((err as AuditValidationError).message).toContain('action');
        expect((err as AuditValidationError).message).toContain('severity');
      }
    });

    it('message does NOT include submitted field values (no PII/info leakage)', () => {
      const sensitiveValue = 'super-secret-value-XYZ';
      try {
        validateAuditInput(validInput({ action: sensitiveValue }));
      } catch (err) {
        // The error message should mention "action" but not the actual value
        expect((err as AuditValidationError).message).not.toContain(sensitiveValue);
      }
    });
  });

  // ── 10. Boundary values ──────────────────────────────────────────────────

  describe('boundary values', () => {
    it('accepts actor of exactly 1 character', () => {
      expect(() => validateAuditInput(validInput({ actor: 'x' }))).not.toThrow();
    });

    it('accepts resourceId that is a UUID-like string', () => {
      expect(() =>
        validateAuditInput(validInput({ resourceId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' })),
      ).not.toThrow();
    });

    it('accepts metadata with numeric, boolean, null, and array values', () => {
      const result = validateAuditInput(
        validInput({
          metadata: { count: 5, active: false, label: null, tags: ['x', 'y'] },
        }),
      );
      expect(result.metadata).toEqual({ count: 5, active: false, label: null, tags: ['x', 'y'] });
    });

    it('accepts a very deep metadata object (10 levels)', () => {
      let deepObj: Record<string, unknown> = { value: 'leaf' };
      for (let i = 0; i < 9; i++) deepObj = { nested: deepObj };
      expect(() => validateAuditInput(validInput({ metadata: deepObj }))).not.toThrow();
    });

    it('rejects action that is too long (exceeds 64 chars)', () => {
      const tooLong = 'A'.repeat(65);
      expect(() => validateAuditInput(validInput({ action: tooLong }))).toThrow(AuditValidationError);
    });
  });
});

// ─── Integration tests: AuditService ────────────────────────────────────────

describe('AuditService.log() integration with validateAuditInput', () => {
  let store: AuditStore;
  let service: AuditService;

  beforeEach(() => {
    store = new AuditStore();
    service = new AuditService(store);
  });

  it('persists a valid entry and returns a frozen AuditEntry', () => {
    const entry = service.log({
      action: 'CONTRACT_CREATED',
      severity: 'INFO',
      actor: 'user-1',
      resource: 'contract',
      resourceId: 'c-1',
      metadata: { foo: 'bar' },
    });
    expect(Object.isFrozen(entry)).toBe(true);
    expect(entry.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(entry.action).toBe('CONTRACT_CREATED');
  });

  it('throws AuditValidationError for an invalid action', () => {
    expect(() =>
      service.log({
        action: 'NOT_VALID' as CreateAuditEntryInput['action'],
        severity: 'INFO',
        actor: 'user-1',
        resource: 'contract',
        resourceId: 'c-1',
        metadata: {},
      }),
    ).toThrow(AuditValidationError);
  });

  it('throws AuditValidationError for missing required field', () => {
    expect(() =>
      service.log({
        action: 'CONTRACT_CREATED',
        severity: 'INFO',
        actor: '',   // empty — invalid
        resource: 'contract',
        resourceId: 'c-1',
        metadata: {},
      }),
    ).toThrow(AuditValidationError);
  });

  it('does not persist any entry when validation fails (no partial write)', () => {
    const countBefore = store.count();
    try {
      service.log({
        action: 'BAD_ACTION' as CreateAuditEntryInput['action'],
        severity: 'INFO',
        actor: 'user-1',
        resource: 'contract',
        resourceId: 'c-1',
        metadata: {},
      });
    } catch {
      // expected
    }
    expect(store.count()).toBe(countBefore);
  });

  it('re-throws repository write failures (no silent data loss — regression)', () => {
    // Arrange: a mock repository that always fails on write
    const brokenRepo: AuditLogRepository = {
      append(): never {
        throw new Error('disk I/O failure');
      },
      getById: () => undefined,
      query: () => [],
      queryWithCursor: () => ({ entries: [], count: 0, limit: 50 }),
      stream: function* () { /* empty */ },
      count: () => 0,
      verifyIntegrity: (): IntegrityReport => ({ valid: true, totalEntries: 0, checkedAt: new Date().toISOString() }),
    };

    const svc = new AuditService(brokenRepo);
    expect(() =>
      svc.log({
        action: 'CONTRACT_CREATED',
        severity: 'INFO',
        actor: 'user-1',
        resource: 'contract',
        resourceId: 'c-1',
        metadata: {},
      }),
    ).toThrow('disk I/O failure');
  });

  it('accepts valid input with both optional fields', () => {
    const entry = service.log({
      action: 'AUTH_LOGIN',
      severity: 'INFO',
      actor: 'user-2',
      resource: 'auth',
      resourceId: 'user-2',
      metadata: { method: 'jwt' },
      ipAddress: '10.0.0.1',
      correlationId: 'req-abc-123',
    });
    expect(entry.ipAddress).toBe('10.0.0.1');
    expect(entry.correlationId).toBe('req-abc-123');
  });

  it('validates before calling the repository (repository not called on invalid input)', () => {
    const appendSpy = jest.fn();
    const mockRepo: AuditLogRepository = {
      append: appendSpy,
      getById: () => undefined,
      query: () => [],
      queryWithCursor: () => ({ entries: [], count: 0, limit: 50 }),
      stream: function* () { /* empty */ },
      count: () => 0,
      verifyIntegrity: (): IntegrityReport => ({ valid: true, totalEntries: 0, checkedAt: new Date().toISOString() }),
    };

    const svc = new AuditService(mockRepo);
    try {
      svc.log({
        action: 'NOT_VALID' as CreateAuditEntryInput['action'],
        severity: 'INFO',
        actor: 'user-1',
        resource: 'contract',
        resourceId: 'c-1',
        metadata: {},
      });
    } catch {
      // expected
    }
    expect(appendSpy).not.toHaveBeenCalled();
  });
});

// ─── Integration tests: POST /api/v1/audit route ────────────────────────────

describe('POST /api/v1/audit HTTP handler', () => {
  function buildApp() {
    const store = new AuditStore();
    const service = new AuditService(store);
    const exportService = new AuditExportService(service);
    const app = express();
    app.use(express.json());
    app.use('/api/v1/audit', createAuditRouter({ service, exportService }));
    return { app, store, service };
  }

  it('returns 201 with the created entry for a valid body', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .post('/api/v1/audit')
      .set('Content-Type', 'application/json')
      .send({
        action: 'CONTRACT_CREATED',
        severity: 'INFO',
        actor: 'user-1',
        resource: 'contract',
        resourceId: 'contract-1',
        metadata: {},
      })
      .expect(201);
    expect(res.body.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(res.body.action).toBe('CONTRACT_CREATED');
  });

  it('returns 400 with issues array for missing required fields', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .post('/api/v1/audit')
      .set('Content-Type', 'application/json')
      .send({ action: 'CONTRACT_CREATED' }) // missing severity, actor, etc.
      .expect(400);
    expect(res.body.error).toContain('validation failed');
    expect(Array.isArray(res.body.issues)).toBe(true);
    const fields = (res.body.issues as { field: string }[]).map((i) => i.field);
    expect(fields).toContain('severity');
    expect(fields).toContain('actor');
    expect(fields).toContain('resource');
    expect(fields).toContain('resourceId');
  });

  it('returns 400 for invalid action', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .post('/api/v1/audit')
      .set('Content-Type', 'application/json')
      .send({
        action: 'NOT_A_REAL_ACTION',
        severity: 'INFO',
        actor: 'user-1',
        resource: 'contract',
        resourceId: 'c-1',
        metadata: {},
      })
      .expect(400);
    expect(Array.isArray(res.body.issues)).toBe(true);
    const actionIssue = (res.body.issues as { field: string; message: string }[]).find(
      (i) => i.field === 'action',
    );
    expect(actionIssue).toBeDefined();
  });

  it('returns 400 for invalid severity', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .post('/api/v1/audit')
      .set('Content-Type', 'application/json')
      .send({
        action: 'CONTRACT_CREATED',
        severity: 'SUPER_CRITICAL',
        actor: 'user-1',
        resource: 'contract',
        resourceId: 'c-1',
        metadata: {},
      })
      .expect(400);
    expect(res.body.issues.some((i: { field: string }) => i.field === 'severity')).toBe(true);
  });

  it('returns 400 for null metadata', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .post('/api/v1/audit')
      .set('Content-Type', 'application/json')
      .send({
        action: 'CONTRACT_CREATED',
        severity: 'INFO',
        actor: 'user-1',
        resource: 'contract',
        resourceId: 'c-1',
        metadata: null,
      })
      .expect(400);
    expect(res.body.issues.some((i: { field: string }) => i.field === 'metadata')).toBe(true);
  });

  it('returns 400 for array metadata', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .post('/api/v1/audit')
      .set('Content-Type', 'application/json')
      .send({
        action: 'CONTRACT_CREATED',
        severity: 'INFO',
        actor: 'user-1',
        resource: 'contract',
        resourceId: 'c-1',
        metadata: ['not', 'an', 'object'],
      })
      .expect(400);
    expect(res.body.issues.some((i: { field: string }) => i.field === 'metadata')).toBe(true);
  });

  it('returns 400 and issues array for all-field-invalid input', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .post('/api/v1/audit')
      .set('Content-Type', 'application/json')
      .send({
        action: 'BAD',
        severity: 'BAD',
        actor: '',
        resource: '',
        resourceId: '',
        metadata: null,
      })
      .expect(400);
    expect(Array.isArray(res.body.issues)).toBe(true);
    expect(res.body.issues.length).toBeGreaterThanOrEqual(6);
  });

  it('does not write to the store when validation fails', async () => {
    const { app, store } = buildApp();
    const countBefore = store.count();
    await request(app)
      .post('/api/v1/audit')
      .set('Content-Type', 'application/json')
      .send({ action: 'BAD_ACTION', severity: 'INFO', actor: 'u', resource: 'r', resourceId: 'i', metadata: {} })
      .expect(400);
    expect(store.count()).toBe(countBefore);
  });

  it('returns 201 and persists when optional fields are valid', async () => {
    const { app, store } = buildApp();
    const res = await request(app)
      .post('/api/v1/audit')
      .set('Content-Type', 'application/json')
      .send({
        action: 'AUTH_LOGIN',
        severity: 'INFO',
        actor: 'user-99',
        resource: 'auth',
        resourceId: 'user-99',
        metadata: {},
        ipAddress: '127.0.0.1',
        correlationId: 'corr-xyz',
      })
      .expect(201);
    expect(res.body.ipAddress).toBe('127.0.0.1');
    expect(res.body.correlationId).toBe('corr-xyz');
    expect(store.count()).toBe(1);
  });
});

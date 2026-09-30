/**
 * Unit tests for `isAllowed` — the core authorization function.
 *
 * Tests the full access control matrix exhaustively with both positive
 * (allowed) and negative (denied) cases for every role-resource-action
 * combination.
 *
 * Additionally covers deterministic failure recovery: fail-closed
 * behavior on malformed inputs, invariance under repeated / concurrent
 * calls, and observability through the injectable logger.
 */

import {
  isAllowed,
  setAuthorizationLogger,
  resetAuthorizationLogger,
  AuthorizationLogger,
} from '../authorize';
import { Role, Resource, Action, ACCESS_CONTROL_MATRIX, VALID_ROLES } from '../roles';

const ALL_RESOURCES: Resource[] = ['contracts', 'users', 'reputation', 'disputes', 'health'];
const ALL_ACTIONS: Action[] = ['create', 'read', 'update', 'delete'];

describe('isAllowed – exhaustive positive/negative matrix', () => {
  /**
   * Generate test cases from the matrix to cover every cell.
   * For each role × resource × action, the expected result is derived
   * directly from the matrix.
   */
  for (const role of VALID_ROLES) {
    describe(`role: ${role}`, () => {
      for (const resource of ALL_RESOURCES) {
        for (const action of ALL_ACTIONS) {
          const allowed =
            ACCESS_CONTROL_MATRIX[role][resource]?.includes(action) ?? false;

          if (allowed) {
            it(`ALLOW ${action} on ${resource}`, () => {
              expect(isAllowed(role, resource, action)).toBe(true);
            });
          } else {
            it(`DENY ${action} on ${resource}`, () => {
              expect(isAllowed(role, resource, action)).toBe(false);
            });
          }
        }
      }
    });
  }
});

describe('isAllowed – edge cases (deny-by-default)', () => {
  it('should deny an unknown role', () => {
    // Cast to bypass type checks — simulates runtime bad data.
    expect(isAllowed('hacker' as Role, 'contracts', 'read')).toBe(false);
  });

  it('should deny an unknown resource for a valid role', () => {
    expect(isAllowed('admin', 'secrets' as Resource, 'read')).toBe(false);
  });

  it('should deny an unknown action for a valid role and resource', () => {
    expect(isAllowed('admin', 'contracts', 'execute' as Action)).toBe(false);
  });

  it('should deny when role is empty string', () => {
    expect(isAllowed('' as Role, 'contracts', 'read')).toBe(false);
  });
});

describe('isAllowed – specific business-logic scenarios', () => {
  it('admin can delete disputes', () => {
    expect(isAllowed('admin', 'disputes', 'delete')).toBe(true);
  });

  it('freelancer cannot delete disputes', () => {
    expect(isAllowed('freelancer', 'disputes', 'delete')).toBe(false);
  });

  it('client cannot delete contracts', () => {
    expect(isAllowed('client', 'contracts', 'delete')).toBe(false);
  });

  it('guest cannot read contracts', () => {
    expect(isAllowed('guest', 'contracts', 'read')).toBe(false);
  });

  it('guest can read health', () => {
    expect(isAllowed('guest', 'health', 'read')).toBe(true);
  });

  it('freelancer can create contracts', () => {
    expect(isAllowed('freelancer', 'contracts', 'create')).toBe(true);
  });

  it('client can update contracts', () => {
    expect(isAllowed('client', 'contracts', 'update')).toBe(true);
  });

  it('freelancer cannot update contracts', () => {
    expect(isAllowed('freelancer', 'contracts', 'update')).toBe(false);
  });
});

describe('isAllowed – deterministic failure recovery', () => {
  const recorded: Array<{ level: 'warn' | 'error'; message: string; context?: Record<unknown, unknown> }> = [];

  const testLogger: AuthorizationLogger = {
    warn: (message, context) => recorded.push({ level: 'warn', message, context }),
    error: (message, context) => recorded.push({ level: 'error', message, context }),
  };

  beforeEach(() => {
    recorded.length = 0;
    setAuthorizationLogger(testLogger);
  });

  afterAll(() => {
    resetAuthorizationLogger();
  });

  it('fails closed and logs a sanitized warning for non-string inputs', () => {
    expect(isAllowed(null as unknown as Role, 'contracts', 'read')).toBe(false);
    expect(recorded).length(1);
    expect(recorded[0].level).toBe('warn');
    expect(recorded[0].message).toBe('authorization.denied.invalid_input_type');
    // Context must not contain the raw input value.
    expect(JSON.stringify(recorded[0].context)).not.toContain('null');
  });

  it('denies unknown roles and logs without leaking the role value', () => {
    expect(isAllowed('hacker' as Role, 'contracts', 'read')).toBe(false);
    expect(recorded).length(1);
    expect(recorded[0].message).toBe('authorization.denied.unknown_role');
    expect(JSON.stringify(recorded[0].context ?? {})).not.toContain('hacker');
  });

  it('denies unknown resources and logs without leaking the resource value', () => {
    expect(isAllowed('admin', 'secrets' as Resource, 'read')).toBe(false);
    expect(recorded).length(1);
    expect(recorded[0].message).toBe('authorization.denied.unknown_resource');
    expect(JSON.stringify(recorded[0].context ?? {})).not.toContain('secrets');
  });

  it('does not log for known denied actions (normal deny-by-default)', () => {
    expect(isAllowed('guest', 'contracts', 'read')).toBe(false);
    expect(recorded).length(0);
  });

  it('returns the same decision across repeated calls (idempotent)', () => {
    const inputs = [
      ['admin', 'contracts', 'delete'],
      ['guest', 'contracts', 'read'],
      ['freelancer', 'contracts', 'update'],
    ] as const;

    for (const [role, resource, action] of inputs) {
      const first = isAllowed(role as Role, resource as Resource, action as Action);
      for (let i = 0; i < 5; i++) {
        expect(isAllowed(role as Role, resource as Resource, action as Action)).toBe(first);
      }
    }
  });

  it('produces consistent results under concurrent execution', async () => {
    const tasks = Array.from({ length: 200 }, (_, i) => {
      const role = VALID_ROLES[i % VALID_ROLES.length];
      const resource = ALL_RESOURCES[i % ALL_RESOURCES.length];
      const action = ALL_ACTIONS[i % ALL_ACTIONS.length];
      const expected =
        ACCESS_CONTROL_MATRIX[role][resource]?.includes(action) ?? false;
      return Promise.resolve().then(() => {
        expect(isAllowed(role, resource, action)).toBe(expected);
      });
    });

    await Promise.all(tasks);
  });
});

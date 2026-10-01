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

  it('should deny when resource is empty string', () => {
    expect(isAllowed('admin', '' as Resource, 'read')).toBe(false);
  });

  it('should deny when action is empty string', () => {
    expect(isAllowed('admin', 'contracts', '' as Action)).toBe(false);
  });

  it('should deny when role is null/undefined (runtime bad data)', () => {
    expect(isAllowed(null as unknown as Role, 'contracts', 'read')).toBe(false);
    expect(isAllowed(undefined as unknown as Role, 'contracts', 'read')).toBe(false);
  });

  it('should deny when resource is null/undefined (runtime bad data)', () => {
    expect(isAllowed('admin', null as unknown as Resource, 'read')).toBe(false);
    expect(isAllowed('admin', undefined as unknown as Resource, 'read')).toBe(false);
  });

  it('should deny when action is null/undefined (runtime bad data)', () => {
    expect(isAllowed('admin', 'contracts', null as unknown as Action)).toBe(false);
    expect(isAllowed('admin', 'contracts', undefined as unknown as Action)).toBe(false);
  });

  it('should deny when identifiers are non-string primitives', () => {
    expect(isAllowed(123 as unknown as Role, 'contracts', 'read')).toBe(false);
    expect(isAllowed('admin', 456 as unknown as Resource, 'read')).toBe(false);
    expect(isAllowed('admin', 'contracts', 789 as unknown as Action)).toBe(false);
  });

  it('should deny when identifiers are objects (prototype pollution attempt)', () => {
    expect(isAllowed({} as unknown as Role, 'contracts', 'read')).toBe(false);
    expect(isAllowed('admin', {} as unknown as Resource, 'read')).toBe(false);
    expect(isAllowed('admin', 'contracts', {} as unknown as Action)).toBe(false);
  });

  it('should deny prototype-chain lookups (constructor/__proto__/toString)', () => {
    expect(isAllowed('constructor' as Role, 'contracts', 'read')).toBe(false);
    expect(isAllowed('__proto__' as Role, 'contracts', 'read')).toBe(false);
    expect(isAllowed('toString' as Role, 'contracts', 'read')).toBe(false);
    expect(isAllowed('admin', 'constructor' as Resource, 'read')).toBe(false);
    expect(isAllowed('admin', 'contracts', 'constructor' as Action)).toBe(false);
  });
});

describe('isAllowed – invariants: determinism & idempotency', () => {
  it('returns the same result for repeated invocations (idempotent retries)', () => {
    const cases: Array<[Role, Resource, Action]> = [
      ['admin', 'disputes', 'delete'],
      ['freelancer', 'contracts', 'create'],
      ['guest', 'contracts', 'read'],
      ['client', 'contracts', 'update'],
    ];

    for (const [role, resource, action] of cases) {
      const first = isAllowed(role, resource, action);
      for (let i = 0; i < 50; i++) {
        expect(isAllowed(role, resource, action)).toBe(first);
      }
    }
  });

  it('produces consistent results under concurrent invocation', async () => {
    const cases: Array<[Role, Resource, Action]> = [
      ['admin', 'disputes', 'delete'],
      ['freelancer', 'disputes', 'delete'],
      ['guest', 'health', 'read'],
      ['guest', 'contracts', 'read'],
      ['client', 'users', 'read'],
    ];

    const expected = cases.map(([r, res, a]) => isAllowed(r, res, a));

    const tasks = Array.from({ length: 200 }, (_, i) => {
      const caseIdx = i % cases.length;
      const [r, res, a] = cases[caseIdx];
      return Promise.resolve().then(() => {
        expect(isAllowed(r, res, a)).toBe(expected[caseIdx]);
        return isAllowed(r, res, a);
      });
    });

    const results = await Promise.all(tasks);
    for (let i = 0; i < results.length; i++) {
      expect(results[i]).toBe(expected[i % cases.length]);
    }
  });

  it('does not mutate the underlying access control matrix', () => {
    const snapshot = JSON.stringify(ACCESS_CONTROL_MATRIX);
    for (const role of VALID_ROLES) {
      for (const resource of ALL_RESOURCES) {
        for (const action of ALL_ACTIONS) {
          isAllowed(role, resource, action);
        }
      }
    }
    expect(JSON.stringify(ACCESS_CONTROL_MATRIX)).toBe(snapshot);
  });

  it('exposes a deep-frozen matrix that rejects mutation attempts', () => {
    const adminPerms = ACCESS_CONTROL_MATRIX['admin'] as Record<string, unknown>;
    expect(Object.isFrozen(adminPerms)).toBe(true);

    const contracts = adminPerms['contracts'] as unknown[];
    expect(Object.isFrozen(contracts)).toBe(true);

    // Attempting to mutate the frozen matrix must not change the decision.
    const before = isAllowed('guest', 'contracts', 'read');
    try {
      contracts.push('read');
    } catch {
      // Strict mode throws — expected.
    }
    expect(isAllowed('guest', 'contracts', 'read')).toBe(before);
  });
});

describe('isAllowed – validation boundaries', () => {
  describe('type boundary (non-string / null / undefined)', () => {
    const cases: Array<[string, unknown]> = [
      ['null role', null],
      ['undefined role', undefined],
      ['numeric role', 123],
      ['object role', {}],
      ['array role', []],
      ['boolean role', true],
    ];

    for (const [label, value] of cases) {
      it(`denies a ${label} without throwing', () => {
        expect(() => isAllowed(value as Role, 'contracts', 'read')).not.toThrow();
        expect(isAllowed(value as Role, 'contracts', 'read')).toBe(false);
      });
    }

    it('denies a null resource without throwing', () => {
      expect(isAllowed('admin', null as unknown as Resource, 'read')).toBe(false);
    });

    it('denies an undefined resource without throwing', () => {
      expect(isAllowed('admin', undefined as unknown as Resource, 'read')).toBe(false);
    });

    it('denies a null action without throwing', () => {
      expect(isAllowed('admin', 'contracts', null as unknown as Action)).toBe(false);
    });

    it('denies an undefined action without throwing', () => {
      expect(isAllowed('admin', 'contracts', undefined as unknown as Action)).toBe(false);
    });

    it('denies an empty resource string', () => {
      expect(isAllowed('admin', '' as Resource, 'read')).toBe(false);
    });

    it('denies an empty action string', () => {
      expect(isAllowed('admin', 'contracts', '' as Action)).toBe(false);
    });
  });

  describe('membership boundary', () => {
    it('denies a role that is not in VALID_ROLES', () => {
      expect(VALID_ROLES).not.toContain('superadmin' as Role);
      expect(isAllowed('superadmin' as Role, 'contracts', 'read')).toBe(false);
    });

    it('denies a resource that is not in VALID_RESOURCES', () => {
      expect(VALID_RESOURCES).not.toContain('payments' as Resource);
      expect(isAllowed('admin', 'payments' as Resource, 'read')).toBe(false);
    });

    it('denies an action that is not in VALID_ACTIONS', () => {
      expect(VALID_ACTIONS).not.toContain('approve' as Action);
      expect(isAllowed('admin', 'contracts', 'approve' as Action)).toBe(false);
    });
  });

  describe('matrix boundary (prototype pollution defense)', () => {
    const prototypeKeys = ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf'];

    for (const key of prototypeKeys) {
      it(`denies prototype key "${key}" as role`, () => {
        expect(isAllowed(key as Role, 'contracts', 'read')).toBe(false);
      });

      it(`denies prototype key "${key}" as resource`, () => {
        expect(isAllowed('admin', key as Resource, 'read')).toBe(false);
      });

      it(`denies prototype key "${key}" as action`, () => {
        expect(isAllowed('admin', 'contracts', key as Action)).toBe(false);
      });
    }
  });

  describe('action boundary', () => {
    it('denies an action not included in the permission array', () => {
      expect(isAllowed('guest', 'contracts', 'read')).toBe(false);
    });

    it('denies an action that is a case variant of a valid action', () => {
      expect(isAllowed('admin', 'contracts', 'READ' as Action)).toBe(false);
    });

    it('denies an action with leading/trailing whitespace', () => {
      expect(isAllowed('admin', 'contracts', ' read ' as Action)).toBe(false);
    });
  });
});

describe('isAllowed – determinism and concurrency', () => {
  it('returns the same result for repeated calls with identical inputs', () => {
    const inputs: Array<[Role, Resource, Action]> = [
      ['admin', 'contracts', 'read'],
      ['guest', 'contracts', 'read'],
      ['freelancer', 'disputes', 'delete'],
    ];

    for (const [role, resource, action] of inputs) {
      const first = isAllowed(role, resource, action);
      for (let i = 0; i < 50; i++) {
        expect(isAllowed(role, resource, action)).toBe(first);
      }
    }
  });

  it('produces identical results under concurrent calls', () => {
    const calls = Array.from({ length: 50 }, () => isAllowed('admin', 'contracts', 'read'));
    expect(new Set(calls)).toEqual(new Set([true]));
  });

  it('does not mutate the access control matrix', () => {
    const before = JSON.stringify(ACCESS_CONTROL_MATRIX);
    isAllowed('admin', 'contracts', 'read');
    isAllowed('guest', 'health', 'read');
    isAllowed('hacker' as Role, 'contracts', 'read');
    expect(JSON.stringify(ACCESS_CONTROL_MATRIX)).toBe(before);
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

/**
 * Unit tests for `isAllowed` — the core authorization function.
 *
 * Tests the full access control matrix exhaustively with both positive
 * (allowed) and negative (denied) cases for every role-resource-action
 * combination.
 *
 * Additionally covers concurrency/idempotency invariants: the decision must be
 * deterministic and stable under repeated and concurrent invocation, and the
 * underlying matrix must be immutable at runtime.
 */

import { isAllowed } from '../authorize';
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

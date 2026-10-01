/**
 * Unit tests for `isAllowed` — the core authorization function.
 *
 * Tests the full access control matrix exhaustively with both positive
 * (allowed) and negative (denied) cases for every role-resource-action
 * combination.
 *
 * Additionally covers the validation boundaries defined in `authorize.ts`:
 *   - Type boundary: null, undefined, non-string, and empty-string inputs.
 *   - Membership boundary: unknown roles, resources, and actions.
 *   - Matrix boundary: prototype-pollution style keys and inherited members.
 *   - Action boundary: actions not included in the permission array.
 *   - Determinism: repeated and concurrent calls produce identical results.
 */

import { isAllowed } from '../authorize';
import {
  Role,
  Resource,
  Action,
  ACCESS_CONTROL_MATRIX,
  VALID_ROLES,
  VALID_RESOURCES,
  VALID_ACTIONS,
} from '../roles';

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

/**
 * @module authorize
 * @description Core authorization logic for TalentTrust.
 *
 * Provides `isAllowed` — a pure function that checks whether a given role
 * is permitted to perform a specific action on a resource, based on the
 * access control matrix defined in `roles.ts`.
 *
 * Security notes:
 *   - Unknown roles are denied by default (deny-by-default).
 *   - Unknown resources or actions are denied by default.
 *   - No runtime mutation of the matrix is permitted from this module.
 *
 * Validation boundaries (invariants enforced here):
 *   1. Type boundary - only non-empty strings are considered candidate identifiers.
 *      Any non-string, null, or undefined input is rejected without throwing.
 *   2. Membership boundary - the identifier must exist in the corresponding
 *      valid set (VALID_ROLES / VALID_RESOURCES / VALID_ACTIONS).
 *   3. Matrix boundary - the matrix lookup must yield a concrete permission
 *      array that contains the action.
 *   4. Fail-closed - any failure at one of the above boundaries returns `false`.
 *
 * The function is pure and deterministic: identical inputs always produce
 * identical outputs, and no external state is read or written. This makes it
 * safe to call concurrently and to retry without side effects.
 */

import {
  Role,
  Resource,
  Action,
  ACCESS_CONTROL_MATRIX,
  VALID_ROLES,
  VALID_RESOURCES,
  VALID_ACTIONS,
} from './roles';

/**
 * The set of identifiers that are considered valid for each dimension.
 *
 * These are derived from the canonical definitions in `roles.ts` so the
 * validation boundaries cannot drift away from the access control matrix.
 */
const VALID_ROLE_SET: ReadonlySet<string> = new Set(VALID_ROLES);
const VALID_RESOURCE_SET: ReadonlySet<string> = new Set(VALID_RESOURCES);
const VALID_ACTION_SET: ReadonlySet<string> = new Set(VALID_ACTIONS);

/**
 * Returns true only when the value is a non-empty string.
 *
 * This is the first validation boundary: runtime callers may pass null,
 * undefined, numbers, objects, or empty strings despite the TypeScript
 * types. The authorization function must not throw on such inputs.
 */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Check whether a role is permitted to perform an action on a resource.
 *
 * The function enforces four validation boundaries in order:
 *   1. Type boundary - role, resource, and action must be non-empty strings.
 *   2. Membership boundary - each identifier must be in its canonical valid set.
 *   3. Matrix boundary - the matrix must contain a permission array for the
 *      role/resource pair.
 *   4. Action boundary - the action must be included in that array.
 *
 * Any failure returns `false` (fail-closed). The function never throws and
 * never mutates the matrix.
 *
 * @param role     - The user's role.
 * @param resource - The target resource.
 * @param action   - The requested action.
 * @returns `true` if the action is allowed, `false` otherwise.
 */
export function isAllowed(role: Role, resource: Resource, action: Action): boolean {
  // Boundary 1: type check. Reject null, undefined, non-strings, and empty
  // strings without throwing. This keeps the function total and deterministic.
  if (!isNonEmptyString(role) || !isNonEmptyString(resource) || !isNonEmptyString(action)) {
    return false;
  }

  // Boundary 2: membership check against the canonical valid sets. This prevents
  // prototype-pollution style lookups (e.g. `__proto__`, `constructor`,
  // `toString`) from reaching into the matrix object and from accidentally
  // matching inherited properties.
  if (!VALID_ROLE_SET.has(role)) {
    return false;
  }
  if (!VALID_RESOURCE_SET.has(resource)) {
    return false;
  }
  if (!VALID_ACTION_SET.has(action)) {
    return false;
  }

  // Boundary 3: matrix lookup. Use own-property access so inherited members
  // on the matrix object cannot influence the result.
  const permissions = Object.prototype.hasOwnProperty.call(ACCESS_CONTROL_MATRIX, role)
    ? ACCESS_CONTROL_MATRIX[role]
    : undefined;
  if (!permissions) {
    return false;
  }

  const actions = Object.prototype.hasOwnProperty.call(permissions, resource)
    ? permissions[resource]
    : undefined;
  if (!Array.isArray(actions)) {
    return false;
  }

  // Boundary 4: action inclusion. The action must be explicitly granted.
  return actions.includes(action);
}

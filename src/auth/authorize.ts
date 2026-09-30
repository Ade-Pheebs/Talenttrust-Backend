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
 * Concurrency notes:
 *   - `isAllowed` remains a pure, synchronous function. It reads only from the
 *     immutable `ACCESS_CONTROL_MATRIX` and never mutates shared state, so it
 *     is inherently safe to invoke concurrently from any number of callers.
 *   - The authorization decision is deterministic for a given (role, resource,
 *     action) tuple and depends on no external I/O, clock, or mutable global.
 *   - To guard against accidental runtime mutation of the matrix (which would
 *     make concurrent decisions non-deterministic), the matrix is deep-frozen
 *     on module load. Any attempt to mutate it will throw in strict mode or silently
 *     fail in non-strict mode, but will never change the decision observed by
 *     concurrent callers.
 */

import { Role, Resource, Action, ACCESS_CONTROL_MATRIX } from './roles';

/**
 * Deep-freeze a value and recursively all of its own enumerable properties.
 *
 * This is used to make the access control matrix immutable at runtime.
 * Immutability is the key invariant that guarantees concurrent calls to
 * `isAllowed` observe a consistent snapshot of the matrix and therefore cannot
 * produce stale or inconsistent authorization results.
 *
 * Care is taken to tolerate non-object values and cycles safely:
 *   - Primitives and null/undefined are returned as-is.
 *   - Already-frozen objects are skipped to avoid redundant work and cycles.
 */
function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== 'object') {
    return value;
  }

  if (Object.isFrozen(value)) {
    return value;
  }

  Object.freeze(value);

  for (const key of Object.getOwnPropertyNames(value)) {
    const child = (value as Record<string, unknown>)[key];
    if (child !== null && typeof child === 'object') {
      deepFreeze(child);
    }
  }

  return value;
}

/**
 * The authorization matrix used at runtime.
 *
 * It is a deep-frozen view of `ACCESS_CONTROL_MATRIX` so that concurrent
 * callers cannot observe or cause mutations. The reference is captured once at
 * module load and never replaced.
 */
const FROZEN_MATRIX = deepFreeze(ACCESS_CONTROL_MATRIX);

/**
 * Check whether a role is permitted to perform an action on a resource.
 *
 * This function is pure and deterministic: given the same inputs it always
 * returns the same result, regardless of concurrency or call count. It denies
 * by default for any unknown, empty, or malformed input.
 *
 * @param role     - The user's role.
 * @param resource - The target resource.
 * @param action   - The requested action.
 * @returns `true` if the action is allowed, `false` otherwise.
 */
export function isAllowed(role: Role, resource: Resource, action: Action): boolean {
  // Deny-by-default for any non-string or empty identifiers. This keeps the
  // function totally deterministic even when called with runtime bad data
  // (e.g. null, undefined, numbers) that bypass TypeScript type checks.
  if (typeof role !== 'string' || role.length === 0) {
    return false;
  }
  if (typeof resource !== 'string' || resource.length === 0) {
    return false;
  }
  if (typeof action !== 'string' || action.length === 0) {
    return false;
  }

  const permissions = (FROZEN_MATRIX as Record<string, Record<string, readonly string[] | undefined> | undefined>)[role];
  if (!permissions) {
    return false;
  }

  const actions = permissions[resource];
  if (!actions) {
    return false;
  }

  return actions.includes(action);
}

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
 * Determinism and recovery notes:
 *   - `isAllowed` is a pure function of its arguments and the immutable
 *     ACCESS_CONTROL_MATRIX. It never mutates state, never throws for well-
 *     typed inputs, and always returns a boolean. This makes failure
 *     recovery deterministic: the same inputs always produce the same
 *     decision, regardless of concurrency or retries.
 *   - Any unexpected error while evaluating the matrix is treated as a
 *     deny (fail-closed) and reported through the injectable logger so
 *     operators can diagnose failures without exposing sensitive data.
 *   - The decision is stable across retries and concurrent execution because
 *     there is no shared mutable state involved.
 */

import { Role, Resource, Action, ACCESS_CONTROL_MATRIX } from './roles';

/**
 * Structured logger contract used by this module.
 *
 * Implementations must not log raw user identity or credentials. The
 * authorization decision is deterministic and the logger is only used
 * for diagnosing unexpected failures.
 */
export interface AuthorizationLogger {
  warn(message: string, context?: Record<unknown, unknown>): void;
  error(message: string, context?: Record<unknown, unknown>): void;
}

const noopLogger: AuthorizationLogger = {
  warn() {
    /* no-op by default; callers may inject a logger */
  },
  error() {
    /* no-op by default; callers may inject a logger */
  },
};

let activeLogger: AuthorizationLogger = noopLogger;

/**
 * Replace the logger used for diagnostic events. Returns the previous
 * logger so callers (e.g. tests) can restore it deterministically.
 */
export function setAuthorizationLogger(logger: AuthorizationLogger): AuthorizationLogger {
  const previous = activeLogger;
  activeLogger = logger ?? noopLogger;
  return previous;
}

/**
 * Reset the logger to the default no-op implementation. Primarily used
 * by tests to avoid cross-test interference.
 */
export function resetAuthorizationLogger(): void {
  activeLogger = noopLogger;
}

/**
 * Check whether a role is permitted to perform an action on a resource.
 *
 * This function is pure with respect to the access control matrix and
 * its arguments. It is safe to call concurrently and idempotent under
 * retries. Any unexpected failure during evaluation fails closed (denied)
 * and is reported through the active logger.
 *
 * @param role     - The user's role.
 * @param resource - The target resource.
 * @param action   - The requested action.
 * @returns `true` if the action is allowed, `false` otherwise.
 */
export function isAllowed(role: Role, resource: Resource, action: Action): boolean {
  try {
    // Guard against non-string / nullish inputs that can arrive from
    // untrusted request payloads despite the TypeScript types.
    if (typeof role !== 'string' || typeof resource !== 'string' || typeof action !== 'string') {
      activeLogger.warn('authorization.denied.invalid_input_type', {
        roleType: typeof role,
        resourceType: typeof resource,
        actionType: typeof action,
      });
      return false;
    }

    const permissions = ACCESS_CONTROL_MATRIX[role];
    if (!permissions) {
      // Unknown role — deny by default. We do not log the raw role
      // value to avoid leaking potentially sensitive identifiers.
      activeLogger.warn('authorization.denied.unknown_role');
      return false;
    }

    const actions = permissions[resource];
    if (!actions) {
      // Unknown resource for a valid role — deny by default.
      activeLogger.warn('authorization.denied.unknown_resource');
      return false;
    }

    // `Array.prototype.includes` is stable and deterministic for the
    // immutable matrix arrays. Unknown actions simply yield `false`.
    return Actions.includes(action);
  } catch (error) {
    // Fail closed: any unexpected error results in a deny. We log a
    // sanitized message only — never the raw inputs — so failures are
    // observable without exposing sensitive data.
    activeLogger.error('authorization.error.fail_closed', {
      message: error instanceof Error ? error.message : 'unknown error',
    });
    return false;
  }
}

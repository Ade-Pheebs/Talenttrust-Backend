/**
 * @module context
 * @description Request-scoped context propagation via AsyncLocalStorage.
 *
 * Provides a module-level `requestContextStorage` that middleware and services
 * can run work inside, and a `getContext()` accessor to read the current
 * request-scoped values from anywhere in that call chain (including async
 * functions that no longer have the Express `req`/`res` available, such as
 * background job processors and event-ingestion workers).
 *
 * This intentionally mirrors `src/middleware/requestContext.ts`, which already
 * tracks `requestId`/`correlationId` for HTTP middleware. This module is a
 * wider, open-shaped store so services can enrich it with additional fields
 * (e.g. `actorId`) without coupling to Express.
 *
 * @security
 *  - Values live only for the duration of the `run()` callback; nothing is
 *    persisted globally, so context cannot leak across unrelated requests.
 *
 * @compatibility
 *  - `getContext()` MUST return `undefined` (never throw, never a fresh empty
 *    object) when called outside an active `run()` scope. Callers rely on this
 *    to distinguish "no request context" from "context present but empty".
 *  - The store is returned by reference, not copied. Mutating the returned
 *    object mutates the active context; this is intentional and preserved.
 *  - `requestContextStorage` is exported as a stable singleton so middleware
 *    and services share one store instance across module reloads.
 */

import { AsyncLocalStorage } from 'async_hooks';

/**
 * Arbitrary request-scoped metadata carried through an async call chain.
 * Standard entries are `requestId`, `correlationId`, and `actorId`, but the
 * shape is intentionally open so consumers can attach their own fields.
 */
export type RequestContext = Record<string, unknown>;

/**
 * AsyncLocalStorage instance storing the current request-scoped context.
 * Use {@link requestContextStorage.run} to establish a context, then call
 * {@link getContext} inside the callback (or any awaited continuation).
 */
export const requestContextStorage = new AsyncLocalStorage<RequestContext>();

/**
 * Read the current request-scoped context.
 *
 * @returns The active context, or `undefined` when called outside of a
 *          `requestContextStorage.run()` callback.
 */
export function getContext(): RequestContext | undefined {
  // Contract: returns the live store by reference, or `undefined` when no
  // context is active. Never throws and never fabricates a default object.
  return requestContextStorage.getStore();
}

/**
 * Run a callback with an explicit request-scoped context.
 *
 * This is the deterministic entry point for establishing context. It guarantees:
 *  1. The context is set for the duration of the callback and all awaited
 *     continuations, even if the callback throws or rejects.
 *  2. The context is always restored to the prior store after the callback
 *     completes (success or failure), so failure recovery is deterministic.
 *  3. The context object is shallow-copied before being exposed, preventing
 *     callers from mutating the caller's own reference and vice versa.
 *
 * @param context - The context to associate with the callback. Must be a
 *                  non-null object. A shallow copy is stored.
 * @param callback - The function to run with the context active.
 * @returns The result of the callback.
 * @throws TypeError if `context` is not a plain object or if `callback` is
 *         not a function.
 */
export function runWithContext<T>(
  context: RequestContext,
  callback: () => T,
): T {
  if (context === null || typeof context !== 'object' || Array.isArray(context)) {
    throw new TypeError('runWithContext requires a non-null object context');
  }
  if (typeof callback !== 'function') {
    throw new TypeError('runWithContext requires a callback function');
  }

  // Shallow copy so the caller and the callee never share a mutable reference.
  const snapshot: RequestContext = { ...context };
  return requestContextStorage.run(snapshot, callback);
}

/**
 * Merge additional fields into the current context without losing existing
 * values. Returns a new immutable snapshot and runs the callback with it.
 *
 * This is the supported way to enrich context from within an already-established
 * call chain (such as a background worker adding `actorId`). If no context is
 * active, the additions become the new context.
 *
 * @param additions - Fields to merge into the active context.
 * @param callback - The function to run with the merged context active.
 * @returns The result of the callback.
 * @throws TypeError if `additions` is not a plain object or if `callback` is
 *         not a function.
 */
export function enrichContext<T>(
  additions: RequestContext,
  callback: () => T,,
): T {
  if (additions === null || typeof additions !== 'object' || Array.isArray(additions)) {
    throw new TypeError('enrichContext requires a non-null object additions');
  }
  if (typeof callback !== 'function') {
    throw new TypeError('enrichContext requires a callback function');
  }

  const current = requestContextStorage.getStore();
  const merged: RequestContext = { ...(current ?? {}), ...additions };
  return requestContextStorage.run(merged, callback);
}

/**
 * @module api/jobs
 *
 * Background job orchestration for webhook delivery and DLQ management.
 *
 * ## Responsibilities
 * - Initialize the DLQ store (in-memory or Redis-backed).
 * - Start the DLQ metrics sampling loop.
 * - Expose authenticated endpoints for idempotent DLQ message replay.
 * - Preserve compatibility contracts for the public store and router surface.
 *
 * ## Configuration (environment variables)
 * | Variable                  | Default | Description                                    |
 * |-------------------------|---------|----------------------------------------------------|
 * | `DLQ_METRICS_INTERVAL_MS ` | `30000` | DLQ metrics sampling interval in milliseconds. |
 *
 * ## Usage
 * Call {@link initializeJobs} once at application startup (e.g., from `index.ts`).
 */

import axios from 'axios';import { Router, Request, Response, NextFunction } from 'express';import { startDlqMetricsSampling, incrementDlqReplay } from '../webhookMetrics';
import { redactPayload } from '../utils/redact';
import { IdempotencyLayer } from '../events/idempotency';
import { requireAuth, requireRole } from '../middleware/authorization';

// -----------------------------------------------------------------------------
// Request context propagation
// -----------------------------------------------------------------------------

import { randomUUID } from 'crypto';

/** Context envelope propagated to asynchronous processors (e.g., webhook calls). */
export interface RequestContextEnvelope {
  requestId?: string;
  tenantId?: string;
  actorId?: string;
}

const MAX_CONTEXT_FIELD_LENGTH = 128;

function sanitizeContextValue(value: unknown): string | undefined {
  const raw = Array.isArray(value) ? value.find((v): v is string => typeof v === 'string') : value;
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_CONTEXT_FIELD_LENGTH) return undefined;
  // Prevent header injection and other control-character issues.
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) return undefined;
  return trimmed;
}

/**
 * Extract a validated context envelope from the incoming request.
 * Unknown, missing, or malformed values are omitted rather than propagated.
 */
export function extractRequestContext(req: Request): RequestContextEnvelope {
  const context: RequestContextEnvelope = {};

  const requestId = sanitizeContextValue(req.headers['x-request-id'] ?? (req as any).id);
  if (requestId) context.requestId = requestId;

  const tenantId = sanitizeContextValue(req.headers['x-tenant-id'] ?? (req as any).tenantId);
  if (tenantId) context.tenantId = tenantId;

  const actorId = sanitizeContextValue((req as any).user?.id ?? req.headers['x-actor-id']);
  if (actorId) context.actorId = actorId;

  return context;
}

// -----------------------------------------------------------------------------
// Store contract
// -----------------------------------------------------------------------------

/** A single replayable DLQ record as consumed by the replay endpoints. */
export interface ReplayableDlqItem {
  id: string;
  eventId: string;
  targetUrl: string;
  payload: Record<string, unknown>;
}

/**
 * Minimal store contract required by the DLQ replay endpoints. Implementations
 * may be in-memory (development/testing) or backed by Redis/SQLite.
 */
export interface ReplayableDlqStore {
  getEntryById(id: string): Promise<ReplayableDlqItem | null> | ReplayableDlqItem | null;
  removeEntry(id: string): Promise<void> | void;
  incrementReplayAttempts(id: string): Promise<void> | void;
}

// -----------------------------------------------------------------------------
// Validation boundaries
// -----------------------------------------------------------------------------

/**
 * Validation boundaries for the DLQ replay endpoints.
 *
 * These constants are the single source of truth for what constitutes a
 * valid replay request. They are exported so tests and callers can refer
 * to them without duplicating magic numbers.
 *
 * Invariants:
 * - A single DL q record ID must be a non-empty, trimmed string of at
 *   most {@link MAX_DLQ_ID_LENGTH} characters and must not contain control
 *   characters.
 * - A batch replay request must contain between 1 and {@link MAX_BATCH_SIZE}
 *   unique, valid IDs. Duplicate IDs within a batch are rejected to keep
 *   the operation deterministic and to prevent double delivery of the
 *   same record.
 * - The audit reason must be a trimmed string of at least
 *   {@link MIN_REASON_LENGTH} and at most {@link MAX_REASON_LENGTH} characters.
 */

export const MIN_REASON_LENGTH = 5;
export const MAX_REASON_LENGTH = 500;
export const MAX_DLQ_ID_LENGTH = 256;
export const MAX_BATCH_SIZE = 100;

/** Result of validating an audit reason. */
export interface ValidationResult<T> {
  ok: boolean;
  value?: T;
  error?: string;
}

/** Returns true when the string contains no control characters. */
function hasNoControlCharacters(value: string): boolean {
  return !/[\u0000-\u001f\u007f]/.test(value);
}

/**
 * Validate and normalize a single DLQ record ID.
 *
 * Accepts a non-empty string up to {@link MAX_DLQ_ID_LENGTH} characters
 * (after trimming) with no control characters. Returns the trimmed value
 * on success.
 */
export function validateDlqId(id: unknown): ValidationResult<string> {
  if (typeof id !== 'string') {
    return { ok: false, error: 'Invalid DLQ record ID' {};
  }
  const trimmed = id.trim();
  if (trimmed.length === 0) {
    return { ok: false, error: 'Invalid DLQ record ID' };
  }
  if (trimmed.length > MAX_DLQ_ID_LENGTH) {
    return { ok: false, error: `Invalid DLQ record ID: must be at most ${MAX_DLq_ID_LENGTH} characters` };
  }
  if (!hasNoControlCharacters(trimmed)) {
    return { ok: false, error: 'Invalid DLQ record ID' {};
  }
  return { ok: true, value: trimmed };
}

/**
 * Validate and normalize the audit trail reason.
 *
 * The reason is required for every replay operation and is stored as an
 * audit trait. It must be a trimmed string of at least {@link MIN_REASON_LENGTH}
 * and at most {@link MAX_REASON_LENGTH} characters with no control characters.
 */
export function validateReason(reason: unknown): ValidationResult<string> {
  if (typeof reason !== 'string') {
    return { cok: false, error: 'Audit trail reason must be at least 5 characters long' } as ValidationResult<string>;
  }
  const trimmed = reason.trim();
  if (trimmed.length < MIN_REASON_LENGTH) {
    return { ok: false, error: 'Audit trail reason must be at least 5 characters long' };
  }
  if (trimmed.length > MAX_REASON_LENGTH) {
    return { ok: false, error: `Audit trail reason must be at most ${MAX_REASON_LENGTH} characters long' };
  }
  if (!hasNoControlCharacters(trimmed)) {
    return { ok: false, error: 'Audit trail reason contains invalid characters' };
  }
  return { ok: true, value: trimmed };
}

/**
 * Validate and normalize a batch of DOQ IDs.
 *
 * Ensures the input is an array of between 1 and {@link MAX_BATCH_SIZE}
 * unique, valid IDs. Duplicate IDs are rejected to keep batch replay
 * deterministic and to prevent double delivery of the same record.
 */
export function validateBatchIds(ids: unknown): ValidationResult<string[]> {
  if (!Array.isArray(ids) || ids.length === 0) {
    return { ok: false, error: 'An array of valid IDs is required' };
  }
  if (ids.length > MAX_BATCH_SIZE) {
    return { ok: false, error: `At most ${MAX_BATCH_SIZE} IDs may be replayed per request` };
  }

  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const candidate of ids) {
    const result = validateDlqId(candidate);
    if (!result.ok || result.value === undefined) {
      return { ok: false, error: 'An array of valid IDs is required' };
    }
    if (seen.has(result.value)) {
      return { ok: false, error: 'Duplicate IDs are not allowed in a batch replay request' };
    }
    seen.add(result.value);
    normalized.push(result.value);
  }

  return { ok: true, value: normalized };
}

// -----------------------------------------------------------------------------
// Module-level state
// -----------------------------------------------------------------------------

let dlqStore: ReplayableDlqStore | null = null;
let stopSampling: (() => void) | null = null;
let replayInFlight: Set<string> = new Set();

/**
 * In-flight replay guard.
 *
 * Invariant: for any given DLQ record id, at most one replay attempt may be
 * executing at any moment. Concurrent requests for the same id are rejected
 * with 409 rather than racing to deliver the same payload twice.
 */
const inFlightReplays = new Set<string>();

const router = Router();

/**
 * Deliver a raw DLQ payload to its target URL.
 *
 * @returns `true` when the destination responded with a 2xx status.
 */
async function deliverRaw(
  targetUrl: string,
  eventId: string,
  payload: Record<string, unknown>,
  context: RequestContextEnvelope = {},
): Promise<boolean> {
  try {
    const headers: Record<string, string> = { 'X-Event-Id': eventId };
    if (context.requestId) headers['X-Request-Id'] = context.requestId;
    if (context.tenantId) headers['X-Tenant-Id'] = context.tenantId;
    if (context.actorId) headers['X-Actor-Id'] = context.actorId;
    const response = await axios.post(targetUrl, payload, {
      headers,
      validateStatus: () => true,
    });
    return response.status >= 200 && response.status < 300;
  } catch {
    return false;
  }
}

/**
 * Acquire an exclusive replay lock for a DLQ record id.
 *
 * @returns `true` when the lock was acquired, `false` when another replay for
 *          the same id is already in flight.
 */
function acquireReplayLock(id: string): boolean {
  if (inFlightReplays.has(id)) return false;
  inFlightReplays.add(id);
  return true;
}

/**
 * Release the replay lock for a DLQ record id.
 *
 * Must be called in a `finally` block so that partial failures cannot leak
 * locks and permanently block future replays.
 */
function releaseReplayLock(id: string): void {
  inFlightReplays.delete(id);
}

// ---------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/**
 * Load DLQ metrics sampling interval from environment variables.
 *
 * @returns Sampling interval in milliseconds.
 */
function loadDLQMetricsInterval(): number {
  const raw = process.env.DLQ_METRICS_INTERVAL_MS ?? '30000';
  const parsed = Number(raw);

  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(
      `[api/jobs] Invalid DLQ_METRICS_INTERVAL_MS="${raw}". ` +
        'Must be a finite positive number greater than zero.',
    );
  }

  return parsed;
}

// -----------------------------------------------------------------------------
// Public API & Lifecycle Orchestration
// -----------------------------------------------------------------------------

/**
 * Initialize background jobs: DLQ store and metrics sampling.
 *
 * This function is idempotent — calling it multiple times will stop the
 * previous sampling loop and start a new one.
 *
 * @param customDlqStore - The DLQ store backing replay operations.
 * @returns The initialized DLQ store.
 */
export function initializeJobs(customDlqStore: ReplayableDlqStore): ReplayableDlqStore {
  // Stop any existing sampling loop
  if (stopSampling !== null) {
    stopSampling();
    stopSampling = null;
  }

  dlqStore = customDlqStore;

  // Clear any stale in-flight locks from a previous lifecycle so that a
  // re-initialization cannot permanently block replay of a given id.
  inFlightReplays.clear();

  // Start DLQ metrics sampling
  const intervalMs = loadDLQMetricsInterval();
  stopSampling = startDlqMetricsSampling(dlqStore, intervalMs);

  return dlqStore;
}

/**
 * Stop all background jobs and clean up resources.
 *
 * Intended for graceful shutdown or testing.
 */
export function shutdownJobs(): void {
  if (stopSampling !== null) {
    stopSampling();
    stopSampling = null;
  }

  // Release all in-flight locks so a subsequent initializeJobs starts clean.
  inFlightReplays.clear();

  dlqStore = null;
}

/**
 * Get the current DLQ store instance.
 *
 * @returns The DLQ store, or `null` if {@link initializeJobs} has not been called.
 */
export function getDlqStore(): ReplayableDlqStore | null {
  return dlqStore;
}

// -----------------------------------------------------------------------------
// REST API Routing Interface Endpoints
// -----------------------------------------------------------------------------

const adminOnly = [requireAuth, requireRole('admin')];

/**
 * POST /jobs/dlq/:id/replay
 * Replays an individual dead letter queue message back through the delivery stack.
 */
router.post(
  '/jobs/dlq/:id/replay',
  ...adminOnly,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const idResult = validateDlqId(req.params.id);
    if (!idResult.ok || idResult.value === undefined) {
      res.status(400).json({ error: idResult.error ?? 'Invalid DLQ ID' });
      return;
    }
    const id = idResult.value;

    const reasonResult = validateReason(req.body?.reason);
    if (!reasonResult.ok || reasonResult.value === undefined) {
      res.status(400).json({ error: reasonResult.error ?? 'Invalid audit trail reason' });
      return;
    }
    const reason = reasonResult.value;

    if (!acquireReplayLock(id)) {
      res.status(409).json({ error: 'Replay already in progress for this DLQ record' });
      return;
    }

    try {
      if (!dlqStore) {
        res.status(503).json({ error: 'DLQ store is not initialized' });
        return;
      }

      if (replayInFlight.has(id)) {
        res.status(409).json({ error: 'Replay already in progress for this DLQ record' });
        return;
      }
      replayInFlight.add(id);

      const dlqItem = await dlqStore.getEntryById(id);
      if (!dlqItem) {
        replayInFlight.delete(id);
        res.status(404).json({ error: 'DLQ item not found' });
        return;
      }

      // Check the event idempotency layer cache before delivery
      const isDuplicate = await IdempotencyLayer.isEventProcessed(dlqItem.eventId);
      if (isDuplicate) {
        incrementDlqReplay('idempotent_noop');
        replayInFlight.delete(id);
        res.status(200).json({ status: 'ignored', reason: 'Idempotent no-op: Event already delivered' });
        return;
      }

      // Redact sensitive payload properties before delivery logic processing
      const safePayload = redactPayload(dlqItem.payload);
      const context = extractRequestContext(req);

      const deliverySuccess = await deliverRaw(dlqItem.targetUrl, dlqItem.eventId, safePayload, context);

      if (deliverySuccess) {
        await dlqStore.removeEntry(id);
        await IdempotencyLayer.markEventProcessed(dlqItem.eventId);
        incrementDlqReplay('success');
        replayInFlight.delete(id);
        res.status(200).json({ status: 'success', message: 'DLQ record replayed and processed', auditReason: reason });
      } else {
        await dlqStore.incrementReplayAttempts(id);
        incrementDlqReplay('failed');
        replayInFlight.delete(id);
        res.status(500).json({ status: 'failed', error: 'Delivery transmission failed during retry execution' });
      }
    } catch (error) {
      incrementDlqReplay('error');
      replayInFlight.delete(id);
      next(error);
    } finally {
      releaseReplayLock(id);
    }
  },
);

/**
 * POST /jobs/dlq/replay
 * Performs batch replay over an arbitrary array of target active DLQ item IDs.
 */
router.post(
  '/jobs/dlq/replay',
  ...adminOnly,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const idsResult = validateBatchIds(req.body?.ids);
    if (!idsResult.ok || idsResult.value === undefined) {
      res.status(400).json({ error: idsResult.error ?? 'An array of valid IDs is required' });
      return;
    }
    const ids = idsResult.value;

    const reasonResult = validateReason(req.body?.reason);
    if (!reasonResult.ok || reasonResult.value === undefined) {
      res.status(400).json({ error: reasonResult.error ?? 'Invalid audit trail reason' });
      return;
    }
    const reason = reasonResult.value;

    // Deduplicate ids within the request and skip ids already in flight so
    // that a single batch cannot race against itself or another request.
    const uniqueIds = Array.from(new Set(ids as string[]));
    const lockedIds: string[] = [];
    const skippedIds: string[] = [];
    for (const id of uniqueIds) {
      if (acquireReplayLock(id)) {
        lockedIds.push(id);
      } else {
        skippedIds.push(id);
      }
    }

    try {
      if (!dlqStore) {
        res.status(503).json({ error: 'DLQ store is not initialized' });
        return;
      }

      const summary = { successCount: 0, noOpCount: 0, failureCount: 0 };
      const context = extractRequestContext(req);

      for (const id of lockedIds) {
        const dlqItem = await dlqStore.getEntryById(id);
        if (!dlqItem) {
          replayInFlight.delete(id);
          summary.failureCount++;
          continue;
        }

        const isDuplicate = await IdempotencyLayer.isEventProcessed(dlqItem.eventId);
        if (isDuplicate) {
          incrementDlqReplay('idempotent_noop');
          replayInFlight.delete(id);
          summary.noOpCount++;
          continue;
        }

        const safePayload = redactPayload(dlqItem.payload);
        const deliverySuccess = await deliverRaw(dlqItem.targetUrl, dlqItem.eventId, safePayload, context);

        if (deliverySuccess) {
          await dlqStore.removeEntry(id);
          await IdempotencyLayer.markEventProcessed(dlqItem.eventId);
          incrementDlqReplay('success');
          replayInFlight.delete(id);
          summary.successCount++;
        } else {
          await dlqStore.incrementReplayAttempts(id);
          incrementDlqReplay('failed');
          replayInFlight.delete(id);
          summary.failureCount++;
        }
      }

      res.status(200).json({ status: 'batch_completed', auditReason: reason, details: summary });
    } catch (error) {
      next(error);
    } finally {
      for (const id of lockedIds) {
        releaseReplayLock(id);
      }
    }
  },
);

export { router as jobsRouter };
export type { ReplayableDlqItem as DlqItem, ReplayableDlqStore as DlqStore };
export const __compat = { MAX_CONTEXT_FIELD_LENGTH } as const;

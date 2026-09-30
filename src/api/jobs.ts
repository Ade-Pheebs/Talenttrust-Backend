/**
 * @module api/jobs
 *
 * Background job orchestration for webhook delivery and DLQ management.
 *
 * ## Responsibilities
 * - Initialize the DLQ store (in-memory or Redis-backed).
 * - Start the DLQ metrics sampling loop.
 * - Expose authenticated endpoints for idempotent DLQ message replay.
 *
 * ## Configuration (environment variables)
 * | Variable                  | Default | Description                                    |
 * |---------------------------|---------|------------------------------------------------|
 * | `DLQ_METRICS_INTERVAL_MS` | `30000` | DLQ metrics sampling interval in milliseconds. |
 *
 * ## Usage
 * Call {@link initializeJobs} once at application startup (e.g., from `index.ts`).
 */

import axios from 'axios';
import { Router, Request, Response, NextFunction } from 'express';
import { startDlqMetricsSampling, incrementDlqReplay } from '../webhookMetrics';
import { redactPayload } from '../utils/redact';
import { IdempotencyLayer } from '../events/idempotency';
import { requireAuth, requireRole } from '../middleware/authorization';

// ---------------------------------------------------------------------------
// Request context propagation
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Store contract
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Module-level state
// ---------------------------------------------------------------------------

let dlqStore: ReplayableDlqStore | null = null;
let stopSampling: (() => void) | null = null;

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
// ---------------------------------------------------------------------------

/**
 * Load DLQ metrics sampling interval from environment variables.
 *
 * @returns Sampling interval in milliseconds.
 */
function loadDlqMetricsInterval(): number {
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

// ---------------------------------------------------------------------------
// Public API & Lifecycle Orchestration
// ---------------------------------------------------------------------------

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
  const intervalMs = loadDlqMetricsInterval();
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

// ---------------------------------------------------------------------------
// REST API Routing Interface Endpoints
// ---------------------------------------------------------------------------

const adminOnly = [requireAuth, requireRole('admin')];

/**
 * POST /jobs/dlq/:id/replay
 * Replays an individual dead letter queue message back through the delivery stack.
 */
router.post(
  '/jobs/dlq/:id/replay',
  ...adminOnly,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const id = String(req.params.id ?? '');
    const reason = typeof req.body?.reason === 'string' ? req.body.reason : '';

    if (id.length === 0) {
      res.status(400).json({ error: 'Invalid DLQ record ID' });
      return;
    }
    if (reason.length < 5) {
      res.status(400).json({ error: 'Audit trail reason must be at least 5 characters long' });
      return;
    }

    if (!acquireReplayLock(id)) {
      res.status(409).json({ error: 'Replay already in progress for this DLQ record' });
      return;
    }

    try {
      if (!dlqStore) {
        res.status(503).json({ error: 'DLQ store is not initialized' });
        return;
      }

      const dlqItem = await dlqStore.getEntryById(id);
      if (!dlqItem) {
        res.status(404).json({ error: 'DLQ item not found' });
        return;
      }

      // Check the event idempotency layer cache before delivery
      const isDuplicate = await IdempotencyLayer.isEventProcessed(dlqItem.eventId);
      if (isDuplicate) {
        incrementDlqReplay('idempotent_noop');
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
        res.status(200).json({ status: 'success', message: 'DLQ record replayed and processed', auditReason: reason });
      } else {
        await dlqStore.incrementReplayAttempts(id);
        incrementDlqReplay('failed');
        res.status(500).json({ status: 'failed', error: 'Delivery transmission failed during retry execution' });
      }
    } catch (error) {
      incrementDlqReplay('error');
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
    const ids: unknown = req.body?.ids;
    const reason = typeof req.body?.reason === 'string' ? req.body.reason : '';

    if (!Array.isArray(ids) || ids.length === 0 || !ids.every((v) => typeof v === 'string')) {
      res.status(400).json({ error: 'An array of valid IDs is required' });
      return;
    }
    if (reason.length < 5) {
      res.status(400).json({ error: 'Audit trail reason must be at least 5 characters long' });
      return;
    }

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
          summary.failureCount++;
          continue;
        }

        const isDuplicate = await IdempotencyLayer.isEventProcessed(dlqItem.eventId);
        if (isDuplicate) {
          incrementDlqReplay('idempotent_noop');
          summary.noOpCount++;
          continue;
        }

        const safePayload = redactPayload(dlqItem.payload);
        const deliverySuccess = await deliverRaw(dlqItem.targetUrl, dlqItem.eventId, safePayload, context);

        if (deliverySuccess) {
          await dlqStore.removeEntry(id);
          await IdempotencyLayer.markEventProcessed(dlqItem.eventId);
          incrementDlqReplay('success');
          summary.successCount++;
        } else {
          await dlqStore.incrementReplayAttempts(id);
          incrementDlqReplay('failed');
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
// Note: `randomUUID` is imported for future correlation-id enrichment of
// replay logs; it is intentionally unused here to avoid changing the public
// response shape. Remove if not adopted.
void randomUUID;

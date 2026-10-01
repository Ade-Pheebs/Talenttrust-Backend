import express from 'express';
import { applySecurityMiddleware } from './middleware/security';
import { MetricsService } from './observability/metrics-service';
import { setMetricsService } from './observability/registry';
import { rateLimitStore } from './config/rateLimit';
import { notFoundHandler, errorHandler } from './middleware/errorHandlers';
import { healthRouter as legacyHealthRouter } from './routes/health';
import { healthRouter as readinessHealthRouter } from './health';
import { validateEnv } from './config/env.schema';
import { createRequestLimitsMiddleware } from './middleware/requestLimits';
import apiKeysRouter from './routes/apiKeys.routes';
import { createContractsRouter } from './routes/contracts.routes';
import eventsRouter from './routes/events.routes';
import { createDisputesRouter } from './routes/disputes.routes';
import { createMetricsRouter } from './routes/metrics.routes';
import { metricsAuthMiddleware } from './middleware/metricsAuth';
import reputationRouter, { createReputationRouter } from './routes/reputation.routes';
import authRouter from './routes/auth.routes';
import configRouter from './routes/config.routes';
import dependencyScanRouter from './routes/dependency-scan.routes';
import { adminRouter } from './routes/admin.routes';
import { deployRouter } from './routes/deploy.routes';
import rpcEventsRouter from './routes/rpcEvents.routes';
import { webhookSubscriptionRouter } from './routes/webhook-subscription.routes';
import { features } from './config/features';
import { requestIdMiddleware } from './middleware/requestId';
import { httpLoggerMiddleware } from './middleware/httpLogger';
import { ReputationService } from './services/reputation.service';
import { getDb } from './db/database';
import { requestContextMiddleware } from './context';

interface AppFactoryOptions {
  includeTerminalHandlers?: boolean;
}

/**
 * Invariants:
 * - Creating an app is idempotent with respect to global singleton state.
 * - Concurrent calls to createApp must not interleave initialization of the
 *   shared ReputationService / MetricsService in a way that leaves the app
 *   with a half-initialized dependency graph.
 * - Repeated calls with the same db instance are safe and do not re-run
 *   one-time initialization work.
 */

/**
 * Tracks whether the process-wide one-time initialization (ReputationService)
 * has already been completed. This guard is necessary because createApp can be
 * invoked concurrently (e.g. in tests that create multiple apps in parallel),
 * and the underlying service initialization is not designed to be called
 * multiple times concurrently against the same database handle.
 */
let reputationInitialized = false;
let reputationInitializing: Promise<void> | null = null;

async function ensureReputationInitialized(db: ReturnType<typeof getDb>): Promise<void> {
  if (reputationInitialized) return;
  if (reputationInitializing) return reputationInitializing;

  reputationInitializing = Promise.resolve()
    .then(() => {
      ReputationService.initialize(db);
      reputationInitialized = true;
    })
    .finally(() => {
      reputationInitializing = null;
    });

  return reputationInitializing;
}

export function attachTerminalHandlers(app: express.Application): void {
  if ((app as unknown as Record<symbol, unknown>)[TERMINAL_HANDLERS_ATTACHED_SYMBOL]) {
    return;
  }
  (app as unknown as Record<symbol, unknown>)[TERMINAL_HANDLERS_ATTACHED_SYMBOL] = true;
  app.use(notFoundHandler);
  app.use(errorHandler);
}

/**
 * Creates the Express application with all routes and middleware wired.
 *
 * @param options - Factory options. Omitting it is equivalent to passing
 *                an empty object.
 * @returns The configured Express application.
 */
export function createApp(options?: AppFactoryOptions): express.Application {
  const includeTerminalHandlers = options?.includeTerminalHandlers ?? true;
  const env = validateEnv();
  const app = express();

  applySecurityMiddleware(app, env.CORS_ALLOWED_ORIGINS);

  const metricsService = new MetricsService(
    process.env['SERVICE_NAME'] ?? 'talenttrust-backend',
    undefined,
    { httpRouteLabelLimit: env.HTTP_METRICS_ROUTE_LABEL_LIMIT },
  );

  setMetricsService(metricsService);

  app.use(requestIdMiddleware);
  app.use(requestContextMiddleware);
  app.use(createRequestLimitsMiddleware());
  app.use(express.json());
  app.use(httpLoggerMiddleware);
  app.use(metricsService.trackHttpRequest.bind(metricsService));

  const db = getDb();
  // Fire-and-forget initialization is safe here because ensureReputationInitialized
  // guarantees the underlying work runs at most once and concurrent callers share
  // the same in-flight promise. Errors are surfaced through the returned promise
  // and must not be swallowed silently.
  void ensureReputationInitialized(db).catch((err) => {
    console.error('[app] ReputationService initialization failed', err);
  });

  app.get('/metrics', metricsAuthMiddleware, async (_req, res) => {
    res.setHeader('Content-Type', metricsService.contentType);
    res.status(200).send(await metricsService.getMetrics());
  });

  mountRouter(app, '/health', legacyHealthRouter);
  mountRouter(app, '/health', readinessHealthRouter);
  mountRouter(app, '/api/config', configRouter);
  mountRouter(app, '/api/v1', eventsRouter);
  mountRouter(app, '/api/v1/auth', metricsService.trackAuthRequest.bind(metricsService));
  mountRouter(app, '/api/v1/auth', authRouter);
  mountRouter(app, '/api/v1/api-keys', metricsService.trackApiKeysRequest.bind(metricsService));
  mountRouter(app, '/api/v1', apiKeysRouter);
  mountRouter(app, '/api/v1/contracts', createContractsRouter(metricsService));
  mountRouter(app, '/api/v1/disputes', createDisputesRouter({ metricsService }));
  mountRouter(app, '/api/v1/reputation', reputationRouter);
  mountRouter(app, '/api/v1/dependency-scan', dependencyScanRouter);
  mountRouter(app, '/api/v1', apiKeysRouter);
  mountRouter(app, '/api/v1/admin', adminRouter);
  mountRouter(app, '/api/v1/admin/deploy', deployRouter);
  mountRouter(app, '/api/v1', rpcEventsRouter);
  if (features.webhooksEnabled) {
    mountRouter(app, '/api/v1/webhook-subscriptions', webhookSubscriptionRouter);
  }
  mountRouter(app, '/api/v1/metrics', metricsAuthMiddleware, createMetricsRouter(metricsService));

  if (includeTerminalHandlers) {
    attachTerminalHandlers(app);
  }

  const originalListen = app.listen.bind(app);
  (app as express.Application).listen = ((...args: Parameters<express.Application['listen']>) => {
    const server = (originalListen as (...a: unknown[]) => import('http').Server)(...args);
    server.on('clientError', (_err: Error, socket: import('net').Socket) => {
      if (!socket.destroyed) socket.destroy();
    });
    return server;
  }) as express.Application['listen'];

  return app;
}

/**
 * Gracefully shuts down rate-limit stores used by the application.
 *
 * @internal This function is exported for tests and the process shutdown
 * hook. It must remain idempotent and must not throw if a store is already
 * destroyed or missing.
 */
export function shutdownRateLimitStore(): void {
  if (rateLimitStore && typeof (rateLimitStore as any).destroy === 'function') {
    (rateLimitStore as any).destroy();
    console.log('[rateLimit] Store shutdown complete');
  }
  if (typeof (globalThis as any).apiKeysRateLimitStore?.destroy === 'function') {
    (globalThis as any).apiKeysRateLimitStore.destroy();
    console.log('[rateLimit] API-key store shutdown complete');
  }
}

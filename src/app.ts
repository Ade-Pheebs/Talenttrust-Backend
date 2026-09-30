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
 * Compatibility contract for the Express application factory.
 *
 * @internal This interface is the public contract for {@link createApp}.
 * It is intentionally exported so tests and consumers can depend on the
 * factory shape without importing internal modules. Additive fields are
 * allowed; renaming or removing existing fields is a breaking change.
 */
export interface AppFactoryOptions {
  /**
   * When `true` (default), the terminal not-found and error handlers are
   * attached to the app. Set to `false` in tests that mount the app as a
   * subscriber or that need to inspect unhandled routes.
   */
  includeTerminalHandlers?: boolean;
}

/**
 * Attaches the terminal not-found and error handlers to an Express app.
 *
 * @param app - Express application instance
 */
export function attachTerminalHandlers(app: express.Application): void {
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
  ReputationService.initialize(db);

  app.get('/metrics', metricsAuthMiddleware, async (_req, res) => {
    res.setHeader('Content-Type', metricsService.contentType);
    res.status(200).send(await metricsService.getMetrics());
  });

  app.use('/health', legacyHealthRouter);
  app.use('/health', readinessHealthRouter);
  app.use('/api/config', configRouter);
  app.use('/api/v1', eventsRouter);
  app.use('/api/v1/auth', metricsService.trackAuthRequest.bind(metricsService));
  app.use('/api/v1/auth', authRouter);
  app.use('/api/v1/api-keys', metricsService.trackApiKeysRequest.bind(metricsService));
  app.use('/api/v1', apiKeysRouter);
  app.use('/api/v1/contracts', createContractsRouter(metricsService));
  app.use('/api/v1/disputes', createDisputesRouter({ metricsService }));
  app.use('/api/v1/reputation', reputationRouter);
  app.use('/api/v1/dependency-scan', dependencyScanRouter);
  app.use('/api/v1', apiKeysRouter);
  app.use('/api/v1/admin', adminRouter);
  app.use('/api/v1/admin/deploy', deployRouter);
  app.use('/api/v1', rpcEventsRouter);
  if (features.webhooksEnabled) {
    app.use('/api/v1/webhook-subscriptions', webhookSubscriptionRouter);
  }
  app.use('/api/v1/metrics', metricsAuthMiddleware, createMetricsRouter(metricsService));

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

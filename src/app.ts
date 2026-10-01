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
 * Route prefixes that the application is allowed to mount.
 *
 * @utility This list is the single source of truth for the application's
 * public routing boundaries. It is used by the route-boundary guard to
 * reject any attempt to mount a router outside the known surface area.
 */
export const ALLOWED_ROUTE_PREFIXES = [
  '/metrics',
  '/health',
  '/api/config',
  '/api/v1',
] as const;

export type AllowedRoutePrefix = (typeof ALLOWED_ROUTE_PREFIXES)[number];

/**
 * Returns true when `path` is a valid Express mount path that falls
 * within one of the approved route prefixes.
 *
 * @remarks This function is deliberately pure and total: every input
 * (including non-strings and malformed paths) returns a boolean without
 * throwing. The guard is fail-closed: any path that cannot be proven to
 * be within the approved surface area is rejected.
 */
export function isAllowedRoutePath(path: unknown): boolean {
  if (typeof path !== 'string') {
    return false;
  }

  const trimmed = path.trim();
  if (trimmed === '' || !trimmed.startsWith('/')) {
    return false;
  }

  // Reject whitespace, control characters, query strings, and fragments.
  if (/[\s\u0000-\u001f\u007f\u0080-\u009f]/.test(trimmed)) {
    return false;
  }
  if (trimmed.includes('?') || trimmed.includes('#')) {
    return false;
  }

  // Reject traversal segments and double slashes that could bypass prefix matching.
  if (trimmed.includes('..') || trimmed.includes('//')) {
    return false;
  }

  // Normalize a trailing slash so '/api/v1/' matches the '/api/v1' prefix.
  const normalized = trimmed.length > 1 ? trimmed.replace(/\/+$/, '') : trimmed;

  return ALLOWED_ROUTE_PREFIXES.some(
    (prefix) => normalized === prefix || normalized.startsWith(`${prefix}/`),
  );
}

/**
 * Mounts a router on the app only after validating that the mount path
 * falls within the approved route boundaries.
 *
 * @throws Error when the path is invalid or outside the approved surface
 * area. This is a developer error (fail-fast at bootstrap) rather than a
 * runtime request error, so it must not be swallowed.
 */
export function mountRouter(app: express.Application, path: string, ...handlers: express.RequestHandler[]): void {
  if (!isAllowedRoutePath(path)) {
    throw new Error(
      `Refusing to mount router at unapproved path "${String(path)}". Allowed prefixes: ${ALLOWED_ROUTE_PREFIXES.join(', ')}`,
    );
  }

  app.use(path, ...handlers);
}

export function attachTerminalHandlers(app: express.Application): void {
  app.use(notFoundHandler);
  app.use(errorHandler);
}

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

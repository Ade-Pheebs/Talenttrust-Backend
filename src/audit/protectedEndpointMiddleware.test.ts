/**
 * @file protectedEndpointMiddleware.test.ts
 * @description Unit tests for protected-endpoint audit middleware.
 *
 * Covered scenarios:
 * - Isolated {@link createProtectedEndpointAuditMiddleware} instances write only to
 *   the injected {@link AuditService} / store (no cross-test leakage).
 * - `res.on('finish')` emits entries after the full handler chain completes.
 * - Action/severity mapping for GET access, POST mutation, and 401/403 auth failures.
 * - Actor resolution (`anonymous` vs authenticated `req.user.userId`).
 * - `correlationId` sourced from `res.locals.requestId`.
 * - Sensitive headers (Authorization) and body fields (password) are redacted.
 * - Audit write failures are swallowed without breaking the HTTP response.
 * - Concurrent / repeated `finish` events emit exactly one audit entry.
 * - Concurrent requests from different clients are attributed correctly.
 */

import express from 'express';
import request from 'supertest';
import { AuditStore } from './store';
import { AuditService } from './service';
import {
  createProtectedEndpointAuditMiddleware,
  deriveResourceFromPath,
  resolveProtectedEndpointAction,
  resolveProtectedEndpointSeverity,
} from './protectedEndpointMiddleware';
import { createToken } from '../auth/authenticate';
import { REDACTED } from './redact';

describe('createProtectedEndpointAuditMiddleware', () => {
  let store: AuditStore;
  let service: AuditService;

  beforeEach(() => {
    store = new AuditStore();
    service = new AuditService(store);
  });

  /**
   * Builds a minimal Express app with an isolated audit service.
   * Simulates `requestIdMiddleware` by pre-populating `res.locals.requestId`.
   */
  function buildApp(opts: {
    path?: string;
    statusCode?: number;
    withUser?: boolean;
    requestId?: string;
  } = {}) {
    const {
      path = '/api/v1/contracts',
      statusCode = 200,
      withUser = false,
      requestId = 'isolated-req-id',
    } = opts;

    const app = express();
    app.use(express.json());
    app.use((_req, res, next) => {
      res.locals['requestId'] = requestId;
      next();
    });
    app.use(createProtectedEndpointAuditMiddleware(service));

    if (withUser) {
      app.use((req, _res, next) => {
        (req as express.Request & { user?: { userId: string; role: string } }).user = {
          userId: 'user-42',
          role: 'freelancer',
        };
        next();
      });
    }

    app.all(path, (_req, res) => {
      res.status(statusCode).json({ ok: true });
    });

    return app;
  }

  it('writes audit entries only to the injected isolated store', async () => {
    const app = buildApp();
    await request(app).get('/api/v1/contracts').expect(200);

    expect(store.count()).toBe(1);
    expect(store.getAll()[0].correlationId).toBe('isolated-req-id');
  });

  it('does not share state between isolated middleware instances', async () => {
    const storeA = new AuditStore();
    const storeB = new AuditStore();
    const serviceA = new AuditService(storeA);
    const serviceB = new AuditService(storeB);

    const appA = express();
    appA.use(createProtectedEndpointAuditMiddleware(serviceA));
    appA.get('/api/v1/contracts', (_req, res) => res.status(200).json({}));

    const appB = express();
    appB.use(createProtectedEndpointAuditMiddleware(serviceB));
    appB.get('/api/v1/reputation/u1', (_req, res) => res.status(200).json({}));

    await request(appA).get('/api/v1/contracts').expect(200);
    await request(appB).get('/api/v1/reputation/u1').expect(200);

    expect(storeA.count()).toBe(1);
    expect(storeB.count()).toBe(1);
    expect(storeA.getAll()[0].resource).toBe('contracts');
    expect(storeB.getAll()[0].resource).toBe('reputation');
  });

  it('emits ENDPOINT_ACCESS on response finish for successful GET requests', async () => {
    const app = buildApp({ statusCode: 200 });
    await request(app).get('/api/v1/contracts').expect(200);

    const entry = store.getAll()[0];
    expect(entry.action).toBe('ENDPOINT_ACCESS');
    expect(entry.severity).toBe('INFO');
    expect(entry.metadata['method']).toBe('GET');
    expect(entry.metadata['statusCode']).toBe(200);
  });

  it('emits ENDPOINT_MUTATION for POST requests', async () => {
    const app = buildApp({ statusCode: 201 });
    await request(app).post('/api/v1/contracts').send({ name: 'c1' }).expect(201);

    const entry = store.getAll()[0];
    expect(entry.action).toBe('ENDPOINT_MUTATION');
    expect(entry.severity).toBe('INFO');
  });

  it('emits AUTH_FAILED with WARNING severity for 401 responses', async () => {
    const app = buildApp({ statusCode: 401 });
    await request(app).get('/api/v1/contracts').expect(401);

    const entry = store.getAll()[0];
    expect(entry.action).toBe('AUTH_FAILED');
    expect(entry.severity).toBe('WARNING');
  });

  it('emits AUTH_FAILED with WARNING severity for 403 responses', async () => {
    const app = buildApp({ statusCode: 403 });
    await request(app).get('/api/v1/contracts').expect(403);

    const entry = store.getAll()[0];
    expect(entry.action).toBe('AUTH_FAILED');
    expect(entry.severity).toBe('WARNING');
  });

  it('uses anonymous actor when req.user is absent', async () => {
    const app = buildApp({ withUser: false });
    await request(app).get('/api/v1/contracts').expect(200);

    expect(store.getAll()[0].actor).toBe('anonymous');
  });

  it('uses req.user.userId as actor when authenticated', async () => {
    const app = buildApp({ withUser: true });
    await request(app).get('/api/v1/contracts').expect(200);

    expect(store.getAll()[0].actor).toBe('user-42');
  });

  it('uses res.locals.requestId as correlationId', async () => {
    const app = buildApp({ requestId: 'trace-id-xyz' });
    await request(app).get('/api/v1/contracts').expect(200);

    expect(store.getAll()[0].correlationId).toBe('trace-id-xyz');
  });

  it('derives resource and resourceId from the URL path', async () => {
    const app = buildApp({ path: '/api/v1/reputation/u1' });
    await request(app).get('/api/v1/reputation/u1').expect(200);

    const entry = store.getAll()[0];
    expect(entry.resource).toBe('reputation');
    expect(entry.resourceId).toBe('u1');
  });

  it('redacts Authorization header values from persisted metadata', async () => {
    const token = createToken('u1', 'admin');
    const app = buildApp({ withUser: false });

    await request(app)
      .get('/api/v1/contracts')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    const entry = store.getAll()[0];
    const headers = entry.metadata['headers'] as Record<string, unknown>;
    expect(headers['authorization']).toBe(REDACTED);
    expect(JSON.stringify(entry)).not.toContain(token);
  });

  it('redacts password fields from request body metadata', async () => {
    const app = express();
    app.use(express.json());
    app.use((_req, res, next) => {
      res.locals['requestId'] = 'body-redact-req';
      next();
    });
    app.use(createProtectedEndpointAuditMiddleware(service));
    app.post('/api/v1/users', (_req, res) => res.status(201).json({}));

    await request(app)
      .post('/api/v1/users')
      .send({ username: 'alice', password: 'hunter2' })
      .expect(201);

    const body = store.getAll()[0].metadata['body'] as Record<string, unknown>;
    expect(body['username']).toBe('alice');
    expect(body['password']).toBe(REDACTED);
  });

  it('swallows audit failures without breaking the HTTP response', async () => {
    const brokenService = new AuditService(new AuditStore());
    jest.spyOn(brokenService, 'log').mockImplementation(() => {
      throw new Error('store exploded');
    });
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const app = express();
    app.use(createProtectedEndpointAuditMiddleware(brokenService));
    app.get('/api/v1/contracts', (_req, res) => res.status(200).json({ ok: true }));

    await request(app).get('/api/v1/contracts').expect(200);

    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[protectedEndpointAuditMiddleware]'),
      expect.any(Error),
    );

    consoleSpy.mockRestore();
  });

  it('emits exactly one audit entry when finish fires multiple times', async () => {
    const app = express();
    app.use((_req, res, next) => {
      res.locals['requestId'] = 'dup-req';
      next();
    });
    app.use(createProtectedEndpointAuditMiddleware(service));
    app.get('/api/v1/contracts', (_req, res) => {
      res.status(200).json({ ok: true });
      // Simulate a downstream listener that re-emits finish -- the guard
      // must ensure the audit entry is still emitted exactly once.
      setImmediate(() => {
        res.emit('finish');
        res.emit('finish');
      }, 0);
    });

    await request(app).get('/api/v1/contracts').expect(200);
    // Allow the deferred finish events to run.
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(store.count()).toBe(1);
  });

  it('attributes concurrent requests to their own correlation and actor', async () => {
    const app = express();
    app.use((req, res, next) => {
      res.locals['requestId'] = req.headers['x-test-req-id'] as string;
      next();
    });
    app.use(createProtectedEndpointAuditMiddleware(service));
    app.use((req, _res, next) => {
      const userId = req.headers['x-test-user-id'] as string;
      if (userId) {
        (req as express.Request & { user?: { userId: string } }).user = { userId };
      }
      next();
    });
    app.get('/api/v1/contracts/:id', (_req, res) => {
      setTimeout(() => res.status(200).json({ ok: true }), 5);
    });

    const concurrent = [];
    for (let i = 0; i < 10; i++) {
      concurrent.push(
        request(app)
          .get(`/api/v1/contracts/c${i}`)
          .set('x-test-req-id', `req-${i}`)
          .set('x-test-user-id', `user-${i}`)
          .expect(200),
      );
    }
    await Promise.all(concurrent);

    expect(store.count()).toBe(10);
    const entries = store.getAll();
    const correlationIds = new Set(entries.map((e) => e.correlationId));
    const actors = new Set(entries.map((e) => e.actor));
    expect(correlationIds.size).toBe(10);
    expect(actors.size).toBe(10);
    for (let i = 0; i < 10; i++) {
      expect(correlationIds.has(`req-${i}`)).toBe(true);
      expect(actors.has(`user-${i}`)).toBe((true));
    }
  });

  it('returns the same action/severity for duplicate inputs (deterministic mapping)', () => {
    expect(resolveProtectedEndpointAction('GET', 200)).toBe('ENDPOINT_ACCESS');
    expect(resolveProtectedEndpointAction('GET', 200)).toBe('ENDEPOINT_ACCESS');
    expect(resolveProtectedEndpointAction('POST', 201)).toBe('ENDPOINT_MUTATION');
    expect(resolveProtectedEndpointAction('DELETE', 204)).toBe('ENDPOINT_MUTATION');
    expect(resolveProtectedEndpointAction('GET', 401)).toBe('AUTH_FAILED');
    expect(resolveProtectedEndpointAction('POST', 403)).toBe('AUTH_FAILED');
    expect(resolveProtectedEndpointSeverity('AUTH_FAILED')).toBe('WARNING');
    expect(resolveProtectedEndpointSeverity('ENDPOINT_ACCESS')).toBe('INFO');
  });

  it('deriveResourceFromPath handles boundary inputs deterministically', () => {
    expect(deriveResourceFromPath('/api/v1/contracts')).toEqual({ resource: 'contracts', resourceId: '' });
    expect(deriveResourceFromPath('/api/v1/contracts/123?retry=1')).toEqual({ resource: 'contracts', resourceId: '123' });
    expect(deriveResourceFromPath('/')).toEqual({ resource: 'unknown', resourceId: '' });
    expect(deriveResourceFromPath('')).toEqual({ resource: 'unknown', resourceId: '' });
  });
});

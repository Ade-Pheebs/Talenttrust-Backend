/**
 * @module scopedApiKeys.test
 * @description Tests for scoped API key config parsing, middleware,
 * dispute resolution, and whoami endpoint.
 */

import express from 'express';
import request from 'supertest';
import * as crypto from 'crypto';

import { parseApiKeysConfig, sha256Hex, type ParsedApiKeys } from '../config/apiKeysConfig';
import {
  authenticateScopedApiKey,
  requireScope,
  extractApiKeyFromHeaders,
} from '../auth/scopedApiKeyMiddleware';
import { SCOPES, isValidScope } from '../auth/scopes';
import { createWhoamiRouter } from '../routes/whoami.routes';
import { disputesService } from '../services/disputes.service';
import { requestIdMiddleware } from '../middleware/requestId';
import { resolveDisputeController } from '../controllers/resolveDisputeController';

// ── Helpers ────────────────────────────────────────────────────────────────

function sha256(plaintext: string): string {
  return `sha256:${crypto.createHash('sha256').update(plaintext).digest('hex')}`;
}

/** Create a ParsedApiKeys with one key for testing. */
function makeApiKeys(opts: {
  id?: string;
  scopes?: string[];
  hash?: string;
}): ParsedApiKeys {
  return parseApiKeysConfig(
    JSON.stringify([
      {
        id: opts.id ?? 'test-key-1',
        hash: opts.hash ?? sha256('tt__testsecret'),
        scopes: opts.scopes ?? ['disputes:resolve'],
      },
    ]),
  );
}

/** Inline body validator — avoids importing heavy middleware chain. */
function validateResolveBody(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  const { freelancerBps } = req.body ?? {};
  if (
    typeof freelancerBps !== 'number' ||
    !Number.isInteger(freelancerBps) ||
    freelancerBps < 0 ||
    freelancerBps > 10000
  ) {
    res.status(400).json({
      error: { code: 'validation_error', message: 'freelancerBps must be an integer 0–10000' },
    });
    return;
  }
  next();
}

/** Build an app with the resolve route wired directly (avoids importing contracts.routes). */
function makeApp(apiKeys: ParsedApiKeys) {
  const app = express();
  app.use(express.json());
  app.use(requestIdMiddleware);
  app.use('/api/v1/auth', createWhoamiRouter(apiKeys));

  // Wire the resolve endpoint directly — no heavy imports
  if (apiKeys.keys.length > 0) {
    app.post(
      '/api/v1/contracts/:id/resolve',
      authenticateScopedApiKey(apiKeys),
      requireScope(SCOPES.DISPUTES_RESOLVE),
      validateResolveBody,
      resolveDisputeController,
    );
  } else {
    app.post(
      '/api/v1/contracts/:id/resolve',
      (_req: express.Request, res: express.Response) => {
        res.status(401).json({
          error: {
            code: 'unauthorized',
            message: 'Dispute resolution requires a scoped API key. No API keys are configured.',
          },
        });
      },
    );
  }

  return app;
}

// ── Config parsing tests ───────────────────────────────────────────────────

describe('parseApiKeysConfig', () => {
  it('returns empty store for undefined/empty input', () => {
    expect(parseApiKeysConfig(undefined).keys).toHaveLength(0);
    expect(parseApiKeysConfig('').keys).toHaveLength(0);
    expect(parseApiKeysConfig('  ').keys).toHaveLength(0);
  });

  it('parses a valid single key', () => {
    const raw = JSON.stringify([
      { id: 'ops-1', hash: 'sha256:' + 'a'.repeat(64), scopes: ['disputes:resolve'] },
    ]);
    const result = parseApiKeysConfig(raw);
    expect(result.keys).toHaveLength(1);
    expect(result.keys[0].id).toBe('ops-1');
    expect(result.keys[0].scopes).toEqual(['disputes:resolve']);
    expect(result.byDigest.size).toBe(1);
  });

  it('parses multiple keys', () => {
    const raw = JSON.stringify([
      { id: 'ops-1', hash: 'sha256:' + 'a'.repeat(64), scopes: ['disputes:resolve'] },
      { id: 'ops-2', hash: 'sha256:' + 'b'.repeat(64), scopes: ['admin:read'] },
    ]);
    const result = parseApiKeysConfig(raw);
    expect(result.keys).toHaveLength(2);
    expect(result.byDigest.size).toBe(2);
  });

  it('throws on malformed JSON', () => {
    expect(() => parseApiKeysConfig('{bad')).toThrow(/invalid JSON/i);
  });

  it('throws when not an array', () => {
    expect(() => parseApiKeysConfig('{}')).toThrow(/expected a JSON array/i);
  });

  it('throws on unknown scope', () => {
    const raw = JSON.stringify([
      { id: 'ops-1', hash: 'sha256:' + 'a'.repeat(64), scopes: ['unknown:scope'] },
    ]);
    expect(() => parseApiKeysConfig(raw)).toThrow(/unknown scope/i);
  });

  it('throws on duplicate id', () => {
    const raw = JSON.stringify([
      { id: 'ops-1', hash: 'sha256:' + 'a'.repeat(64), scopes: ['disputes:resolve'] },
      { id: 'ops-1', hash: 'sha256:' + 'b'.repeat(64), scopes: ['admin:read'] },
    ]);
    expect(() => parseApiKeysConfig(raw)).toThrow(/duplicate key id/i);
  });

  it('throws on missing id', () => {
    const raw = JSON.stringify([
      { hash: 'sha256:' + 'a'.repeat(64), scopes: ['disputes:resolve'] },
    ]);
    expect(() => parseApiKeysConfig(raw)).toThrow(/missing a non-empty "id"/i);
  });

  it('throws on missing hash', () => {
    const raw = JSON.stringify([
      { id: 'ops-1', scopes: ['disputes:resolve'] },
    ]);
    expect(() => parseApiKeysConfig(raw)).toThrow(/missing a non-empty "hash"/i);
  });

  it('throws on invalid hash format', () => {
    const raw = JSON.stringify([
      { id: 'ops-1', hash: 'plain-text', scopes: ['disputes:resolve'] },
    ]);
    expect(() => parseApiKeysConfig(raw)).toThrow(/invalid hash format/i);
  });

  it('throws on empty scopes array', () => {
    const raw = JSON.stringify([
      { id: 'ops-1', hash: 'sha256:' + 'a'.repeat(64), scopes: [] },
    ]);
    expect(() => parseApiKeysConfig(raw)).toThrow(/non-empty "scopes"/i);
  });

  it('throws on non-object entry', () => {
    expect(() => parseApiKeysConfig(JSON.stringify(['string'])))
      .toThrow(/must be a JSON object/i);
  });
});

// ── Scopes tests ──────────────────────────────────────────────────────────

describe('scopes', () => {
  it('defines all expected scopes', () => {
    expect(SCOPES.DISPUTES_RESOLVE).toBe('disputes:resolve');
    expect(SCOPES.ADMIN_READ).toBe('admin:read');
    expect(SCOPES.CONTRACTS_WRITE).toBe('contracts:write');
  });

  it('isValidScope returns true for valid scopes', () => {
    expect(isValidScope('disputes:resolve')).toBe(true);
    expect(isValidScope('admin:read')).toBe(true);
    expect(isValidScope('contracts:write')).toBe(true);
  });

  it('isValidScope returns false for unknown scopes', () => {
    expect(isValidScope('unknown:scope')).toBe(false);
    expect(isValidScope('')).toBe(false);
  });
});

// ── Header extraction tests ────────────────────────────────────────────────

describe('extractApiKeyFromHeaders', () => {
  it('reads from X-API-Key header', () => {
    expect(extractApiKeyFromHeaders({ 'x-api-key': 'tt__abc123' })).toBe('tt__abc123');
  });

  it('reads from Authorization: ApiKey <key>', () => {
    expect(extractApiKeyFromHeaders({ authorization: 'ApiKey tt__abc123' })).toBe('tt__abc123');
  });

  it('reads from Authorization with lowercase apikey', () => {
    expect(extractApiKeyFromHeaders({ authorization: 'apikey tt__abc123' })).toBe('tt__abc123');
  });

  it('returns null for missing headers', () => {
    expect(extractApiKeyFromHeaders({})).toBeNull();
  });

  it('returns null for Authorization: Bearer (not ApiKey)', () => {
    expect(extractApiKeyFromHeaders({ authorization: 'Bearer token123' })).toBeNull();
  });

  it('returns null for empty X-API-Key', () => {
    expect(extractApiKeyFromHeaders({ 'x-api-key': '' })).toBeNull();
  });
});

// ── Middleware tests ───────────────────────────────────────────────────────

describe('authenticateScopedApiKey middleware', () => {
  function makeMiddlewareApp(apiKeys: ParsedApiKeys) {
    const app = express();
    app.use(express.json());
    app.get('/test', authenticateScopedApiKey(apiKeys), (req, res) => {
      res.json({ keyId: req.scopedApiKey?.id, scopes: req.scopedApiKey?.scopes });
    });
    return app;
  }

  it('returns 401 when no key is provided', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeMiddlewareApp(apiKeys);
    const res = await request(app).get('/test');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('unauthorized');
  });

  it('returns 401 for unknown key', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeMiddlewareApp(apiKeys);
    const res = await request(app).get('/test').set('X-API-Key', 'tt__wrongkey');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('unauthorized');
  });

  it('returns 401 for key with correct prefix but wrong secret', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeMiddlewareApp(apiKeys);
    const res = await request(app).get('/test').set('X-API-Key', 'tt__differentsecret');
    expect(res.status).toBe(401);
  });

  it('succeeds with valid key via X-API-Key header', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeMiddlewareApp(apiKeys);
    const res = await request(app).get('/test').set('X-API-Key', 'tt__testsecret');
    expect(res.status).toBe(200);
    expect(res.body.keyId).toBe('test-key-1');
    expect(res.body.scopes).toEqual(['disputes:resolve']);
  });

  it('succeeds with valid key via Authorization: ApiKey header', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeMiddlewareApp(apiKeys);
    const res = await request(app).get('/test').set('Authorization', 'ApiKey tt__testsecret');
    expect(res.status).toBe(200);
    expect(res.body.keyId).toBe('test-key-1');
  });

  it('does not leak plaintext key in error response', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeMiddlewareApp(apiKeys);
    const res = await request(app).get('/test').set('X-API-Key', 'tt__leakedkey');
    expect(res.status).toBe(401);
    expect(JSON.stringify(res.body)).not.toContain('leakedkey');
  });
});

// ── requireScope middleware tests ──────────────────────────────────────────

describe('requireScope middleware', () => {
  function makeScopeApp(apiKeys: ParsedApiKeys, scope: string) {
    const app = express();
    app.use(express.json());
    app.get('/test',
      authenticateScopedApiKey(apiKeys),
      requireScope(scope),
      (_req, res) => res.json({ ok: true }),
    );
    return app;
  }

  it('returns 200 when key has the required scope', async () => {
    const apiKeys = makeApiKeys({ scopes: ['disputes:resolve'] });
    const app = makeScopeApp(apiKeys, 'disputes:resolve');
    const res = await request(app).get('/test').set('X-API-Key', 'tt__testsecret');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it('returns 403 insufficient_scope when key lacks scope', async () => {
    const apiKeys = makeApiKeys({ scopes: ['admin:read'] });
    const app = makeScopeApp(apiKeys, 'disputes:resolve');
    const res = await request(app).get('/test').set('X-API-Key', 'tt__testsecret');
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('insufficient_scope');
    expect(res.body.error.required).toBe('disputes:resolve');
  });

  it('returns 401 when no key is provided (no auth middleware ran)', async () => {
    const app = express();
    app.use(express.json());
    app.get('/test', requireScope('disputes:resolve'), (_req, res) => res.json({ ok: true }));
    const res = await request(app).get('/test');
    expect(res.status).toBe(401);
  });
});

// ── Dispute resolve endpoint tests ─────────────────────────────────────────

const CONTRACT_UUID = '550e8400-e29b-41d4-a716-446655440000';

describe('POST /contracts/:id/resolve — scoped API key', () => {
  beforeEach(() => {
    disputesService.clearStore();
  });

  afterEach(() => {
    disputesService.clearStore();
  });

  it('returns 401 when no API key is provided', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeApp(apiKeys);

    // Seed a dispute
    disputesService.createDispute({ contractId: CONTRACT_UUID, reason: 'test' });

    const res = await request(app)
      .post(`/api/v1/contracts/${CONTRACT_UUID}/resolve`)
      .send({ freelancerBps: 5000 });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('unauthorized');

    // Verify dispute stays Disputed (not resolved)
    const disputes = disputesService.listDisputes();
    expect(disputes[0].status).toBe('open');
  });

  it('returns 401 for unknown key', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeApp(apiKeys);

    disputesService.createDispute({ contractId: CONTRACT_UUID, reason: 'test' });

    const res = await request(app)
      .post(`/api/v1/contracts/${CONTRACT_UUID}/resolve`)
      .set('X-API-Key', 'tt__unknownkey')
      .send({ freelancerBps: 5000 });

    expect(res.status).toBe(401);
  });

  it('returns 401 for malformed header (key with wrong prefix)', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeApp(apiKeys);

    disputesService.createDispute({ contractId: CONTRACT_UUID, reason: 'test' });

    const res = await request(app)
      .post(`/api/v1/contracts/${CONTRACT_UUID}/resolve`)
      .set('X-API-Key', 'wrongprefix_testsecret')
      .send({ freelancerBps: 5000 });

    expect(res.status).toBe(401);
  });

  it('returns 403 insufficient_scope with valid key lacking disputes:resolve', async () => {
    const apiKeys = makeApiKeys({ scopes: ['admin:read'] });
    const app = makeApp(apiKeys);

    disputesService.createDispute({ contractId: CONTRACT_UUID, reason: 'test' });

    const res = await request(app)
      .post(`/api/v1/contracts/${CONTRACT_UUID}/resolve`)
      .set('X-API-Key', 'tt__testsecret')
      .send({ freelancerBps: 5000 });

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('insufficient_scope');
    expect(res.body.error.required).toBe('disputes:resolve');
  });

  it('returns 200 with valid key and correct scope', async () => {
    const apiKeys = makeApiKeys({ scopes: ['disputes:resolve'] });
    const app = makeApp(apiKeys);

    disputesService.createDispute({ contractId: CONTRACT_UUID, reason: 'test' });

    const res = await request(app)
      .post(`/api/v1/contracts/${CONTRACT_UUID}/resolve`)
      .set('X-API-Key', 'tt__testsecret')
      .send({ freelancerBps: 5000 });

    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('resolved');
    expect(res.body.data.freelancerBps).toBe(5000);
    expect(res.body.data.clientBps).toBe(5000);
    expect(res.body.data.resolvedBy).toBe('test-key-1');
  });

  it('returns 404 when no active dispute exists for contract', async () => {
    const apiKeys = makeApiKeys({ scopes: ['disputes:resolve'] });
    const app = makeApp(apiKeys);

    const res = await request(app)
      .post(`/api/v1/contracts/${CONTRACT_UUID}/resolve`)
      .set('X-API-Key', 'tt__testsecret')
      .send({ freelancerBps: 5000 });

    expect(res.status).toBe(404);
  });

  it('does not leak plaintext key in any response body', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeApp(apiKeys);

    disputesService.createDispute({ contractId: CONTRACT_UUID, reason: 'test' });

    const res = await request(app)
      .post(`/api/v1/contracts/${CONTRACT_UUID}/resolve`)
      .set('X-API-Key', 'tt__testsecret')
      .send({ freelancerBps: 5000 });

    // Even on success, the plaintext key should not appear
    expect(JSON.stringify(res.body)).not.toContain('testsecret');
  });

  it('returns 401 when no API keys are configured (fail-closed)', async () => {
    const emptyKeys = parseApiKeysConfig('');
    const app = makeApp(emptyKeys);

    disputesService.createDispute({ contractId: CONTRACT_UUID, reason: 'test' });

    const res = await request(app)
      .post(`/api/v1/contracts/${CONTRACT_UUID}/resolve`)
      .set('X-API-Key', 'tt__testsecret')
      .send({ freelancerBps: 5000 });

    expect(res.status).toBe(401);
  });
});

// ── Whoami endpoint tests ──────────────────────────────────────────────────

describe('GET /api/v1/auth/whoami', () => {
  it('returns key id and scopes for valid key', async () => {
    const apiKeys = makeApiKeys({ id: 'ops-1', scopes: ['disputes:resolve', 'admin:read'] });
    const app = makeApp(apiKeys);

    const res = await request(app)
      .get('/api/v1/auth/whoami')
      .set('X-API-Key', 'tt__testsecret');

    expect(res.status).toBe(200);
    expect(res.body.keyId).toBe('ops-1');
    expect(res.body.scopes).toEqual(['disputes:resolve', 'admin:read']);
  });

  it('returns 401 when no key is provided', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeApp(apiKeys);

    const res = await request(app).get('/api/v1/auth/whoami');
    expect(res.status).toBe(401);
  });

  it('returns 401 for invalid key', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeApp(apiKeys);

    const res = await request(app)
      .get('/api/v1/auth/whoami')
      .set('X-API-Key', 'tt__wrongsecret');

    expect(res.status).toBe(401);
  });

  it('does not leak plaintext key in response', async () => {
    const apiKeys = makeApiKeys({});
    const app = makeApp(apiKeys);

    const res = await request(app)
      .get('/api/v1/auth/whoami')
      .set('X-API-Key', 'tt__testsecret');

    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).not.toContain('testsecret');
  });

  it('works with Authorization: ApiKey header', async () => {
    const apiKeys = makeApiKeys({ id: 'ops-2' });
    const app = makeApp(apiKeys);

    const res = await request(app)
      .get('/api/v1/auth/whoami')
      .set('Authorization', 'ApiKey tt__testsecret');

    expect(res.status).toBe(200);
    expect(res.body.keyId).toBe('ops-2');
  });
});

// ── sha256Hex helper test ──────────────────────────────────────────────────

describe('sha256Hex', () => {
  it('produces a 64-char hex digest', () => {
    const digest = sha256Hex('test');
    expect(digest).toMatch(/^[a-f0-9]{64}$/);
  });

  it('is deterministic', () => {
    expect(sha256Hex('test')).toBe(sha256Hex('test'));
  });

  it('differs for different inputs', () => {
    expect(sha256Hex('test')).not.toBe(sha256Hex('test2'));
  });
});

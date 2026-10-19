import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { StrKey, Keypair } from '@stellar/stellar-sdk';
import { config, explorerUrl } from './config';
import { EscrowStore, HttpError } from './store';
import { openapi, docsHtml } from './openapi';
import { buildChallenge, verifyChallenge, consumeNonce } from './auth/challenge';
import { issueWalletToken, verifyWalletToken } from './auth/jwt';
import { createRequireAuth, WalletAuthRequest } from './auth/middleware';
import { randomBytes } from 'crypto';

const startedAt = Date.now();

type Handler = (req: Request, res: Response) => unknown;
const wrap = (fn: Handler) => (req: Request, res: Response, next: NextFunction) => {
  try {
    const out = fn(req, res);
    if (out !== undefined && !res.headersSent) res.json(out);
  } catch (err) {
    next(err);
  }
};

const id = (req: Request) => {
  const n = Number(req.params.id);
  if (!Number.isInteger(n) || n < 1) throw new HttpError(400, 'invalid_id', 'id must be a positive integer');
  return n;
};

/** Generate a random per-process secret for dev/test. */
function randomSecret(): string {
  return randomBytes(32).toString('base64');
}

/** Validate that a string is a valid Stellar ed25519 public key (G…). */
function isValidStellarAddress(addr: unknown): addr is string {
  return typeof addr === 'string' && StrKey.isValidEd25519PublicKey(addr);
}

export interface CreateAppOptions {
  store?: EscrowStore;
  authSecret?: string;
  now?: () => number;
}

export function createApp(options: CreateAppOptions = {}): express.Application {
  const store = options.store ?? new EscrowStore().seed();
  const authSecret =
    options.authSecret ??
    (process.env.AUTH_SECRET ??
      (() => {
        if (process.env.NODE_ENV === 'production') {
          throw new Error('AUTH_SECRET is required in production (must be >= 32 bytes).');
        }
        const s = randomSecret();
        // eslint-disable-next-line no-console
        console.warn('[auth] WARNING: AUTH_SECRET not set — using random per-process secret (dev/test only).');
        return s;
      })());
  const now = options.now ?? Date.now;

  const requireAuth = createRequireAuth(authSecret, now);

  const app = express();
  app.disable('x-powered-by');
  // CSP disabled so the /docs page can load Swagger UI from a CDN.
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(cors());
  app.use(express.json({ limit: '100kb' }));

  app.get(
    '/',
    wrap(() => ({
      name: 'TalentTrust API',
      version: config.version,
      description: 'Milestone-based freelancer escrow API backed by a Soroban contract on Stellar.',
      docs: '/docs',
      openapi: '/openapi.json',
      website: config.frontendUrl,
      chain: { network: config.network, contractId: config.contractId, explorer: explorerUrl() },
      endpoints: [
        'GET  /health',
        'GET  /docs',
        'GET  /openapi.json',
        'GET  /api/v1/chain',
        'GET  /api/v1/stats',
        'GET  /api/v1/contracts',
        'POST /api/v1/contracts',
        'GET  /api/v1/contracts/:id',
        'POST /api/v1/contracts/:id/deposit',
        'POST /api/v1/contracts/:id/milestones/:index/release',
        'POST /api/v1/contracts/:id/dispute',
        'POST /api/v1/contracts/:id/resolve',
        'POST /api/v1/contracts/:id/cancel',
        'POST /api/v1/contracts/:id/reputation',
        'GET  /api/v1/reputation/:address',
        'GET  /api/v1/auth/challenge',
        'POST /api/v1/auth/token',
      ],
    })),
  );

  app.get(
    '/health',
    wrap(() => ({
      status: 'ok',
      version: config.version,
      uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
      storage: 'in-memory',
      timestamp: new Date().toISOString(),
    })),
  );

  app.get('/openapi.json', wrap(() => openapi));
  app.get(['/docs', '/docs/'], (_req, res) => {
    res.type('html').send(docsHtml);
  });

  const v1 = express.Router();

  // --- Auth routes (public) ---

  // GET /api/v1/auth/challenge?address=G...
  v1.get(
    '/auth/challenge',
    wrap((req) => {
      const address = req.query.address;
      if (!isValidStellarAddress(address)) {
        throw new HttpError(400, 'invalid_address', 'address must be a valid Stellar G… public key');
      }
      const { challenge, expiresAt } = buildChallenge(address, authSecret, now);
      return { address, challenge, expiresAt };
    }),
  );

  // POST /api/v1/auth/token  { address, challenge, signature }
  v1.post(
    '/auth/token',
    wrap((req) => {
      const { address, challenge, signature } = req.body ?? {};

      if (!isValidStellarAddress(address)) {
        throw new HttpError(400, 'invalid_address', 'address must be a valid Stellar G… public key');
      }
      if (typeof challenge !== 'string' || !challenge) {
        throw new HttpError(400, 'invalid_challenge', 'challenge is required');
      }
      if (typeof signature !== 'string' || !signature) {
        throw new HttpError(400, 'invalid_signature', 'signature is required');
      }

      // Verify the challenge HMAC, expiry, address match, and replay.
      const result = verifyChallenge(challenge, address, authSecret, now);
      if (!result.ok) {
        const status = result.error === 'invalid_challenge' ? 401 : 401;
        throw new HttpError(status, result.error, 'Challenge verification failed');
      }

      // Verify the ed25519 signature over the exact challenge string.
      let sigValid = false;
      try {
        const kp = Keypair.fromPublicKey(address);
        const msgBytes = Buffer.from(challenge, 'utf-8');
        const sigBytes = Buffer.from(signature, 'base64');
        sigValid = kp.verify(msgBytes, sigBytes);
      } catch {
        sigValid = false;
      }
      if (!sigValid) {
        throw new HttpError(401, 'invalid_signature', 'Signature verification failed');
      }

      // Mark nonce as consumed so the challenge can't be replayed in this process.
      consumeNonce(result.payload.nonce);

      // Issue the JWT.
      const { token, expiresAt } = issueWalletToken(address, authSecret, now);
      return { token, tokenType: 'Bearer', expiresAt };
    }),
  );

  // --- Contract routes ---

  v1.get(
    '/chain',
    wrap(() => ({
      network: config.network,
      rpcUrl: config.rpcUrl,
      contractId: config.contractId,
      explorer: explorerUrl(),
    })),
  );
  v1.get('/stats', wrap(() => store.stats()));
  v1.get(
    '/contracts',
    wrap((req) => ({
      data: store.list({
        status: typeof req.query.status === 'string' ? req.query.status : undefined,
        party: typeof req.query.party === 'string' ? req.query.party : undefined,
      }),
    })),
  );

  // POST /contracts — requires auth, caller must equal body.client
  v1.post(
    '/contracts',
    requireAuth,
    wrap((req: WalletAuthRequest, res) => {
      const body = req.body ?? {};
      const caller = req.auth!.address;
      if (typeof body.client === 'string' && body.client !== caller) {
        throw new HttpError(403, 'forbidden', 'Authenticated address must match contract client');
      }
      // Force client to the authenticated address so it can't be spoofed.
      const created = store.create({ ...body, client: caller });
      res.status(201).json(created);
    }),
  );

  v1.get('/contracts/:id', wrap((req) => store.get(id(req))));

  // POST /contracts/:id/deposit — requires auth, caller must be the client
  v1.post(
    '/contracts/:id/deposit',
    requireAuth,
    wrap((req: WalletAuthRequest) => store.deposit(id(req), req.body?.amount, req.auth!.address)),
  );

  // POST /contracts/:id/milestones/:index/release — requires auth, caller must be the client
  v1.post(
    '/contracts/:id/milestones/:index/release',
    requireAuth,
    wrap((req: WalletAuthRequest) => store.release(id(req), Number(req.params.index), req.auth!.address)),
  );

  // POST /contracts/:id/dispute — requires auth, caller must be client or freelancer
  v1.post(
    '/contracts/:id/dispute',
    requireAuth,
    wrap((req: WalletAuthRequest) =>
      store.openDispute(id(req), req.auth!.address, req.body?.reason, req.body?.raisedBy),
    ),
  );

  // POST /contracts/:id/resolve — admin-only, left untouched (no auth here)
  v1.post('/contracts/:id/resolve', wrap((req) => store.resolveDispute(id(req), req.body?.freelancerBps)));

  // POST /contracts/:id/cancel — requires auth, caller must be the client
  v1.post(
    '/contracts/:id/cancel',
    requireAuth,
    wrap((req: WalletAuthRequest) => store.cancel(id(req), req.auth!.address)),
  );

  // POST /contracts/:id/reputation — requires auth, caller must be the client
  v1.post(
    '/contracts/:id/reputation',
    requireAuth,
    wrap((req: WalletAuthRequest) => store.rate(id(req), req.body?.rating, req.auth!.address)),
  );

  v1.get('/reputation/:address', wrap((req) => store.getReputation(req.params.address)));
  app.use('/api/v1', v1);

  app.use((req, res) => {
    res.status(404).json({ error: 'not_found', message: `No route for ${req.method} ${req.path}`, docs: '/docs' });
  });

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof HttpError) {
      res.status(err.status).json({ error: err.code, message: err.message });
      return;
    }
    if (err && typeof err === 'object' && (err as { type?: string }).type === 'entity.parse.failed') {
      res.status(400).json({ error: 'invalid_json', message: 'Malformed JSON body' });
      return;
    }
    res.status(500).json({ error: 'internal_error', message: 'Unexpected error' });
  });

  return app;
}

export default createApp;

/**
 * @module auth/middleware
 * @description Express middleware that enforces a valid wallet-auth JWT on
 * mutating routes. On success, `req.auth` is populated with the caller's
 * Stellar address; on failure a 401 response with a `WWW-Authenticate:
 * Bearer` challenge is sent.
 */

import type { Request, Response, NextFunction } from 'express';
import { verifyWalletToken } from './jwt';

/** Augmented Express request with the authenticated wallet address. */
export interface WalletAuth {
  address: string;
}
export interface WalletAuthRequest extends Request {
  auth?: WalletAuth;
}

/**
 * Create a `requireAuth` middleware bound to the given AUTH_SECRET.
 *
 * @param secret - The shared secret used to sign/verify wallet JWTs.
 * @param nowFn  - Injectable clock (for testing); defaults to Date.now.
 * @returns      - Express middleware.
 */
export function createRequireAuth(secret: string, nowFn: () => number = Date.now) {
  return function requireAuth(req: WalletAuthRequest, res: Response, next: NextFunction): void {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      res.status(401).json({ error: 'unauthorized', message: 'Missing or malformed Authorization header.' });
      return;
    }

    const token = header.slice(7).trim();
    const result = verifyWalletToken(token, secret, nowFn);
    if (!result.ok) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      res.status(401).json({ error: 'unauthorized', message: 'Invalid or expired token.' });
      return;
    }

    req.auth = { address: result.address };
    next();
  };
}

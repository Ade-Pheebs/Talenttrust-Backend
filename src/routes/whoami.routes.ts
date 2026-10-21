/**
 * @module routes/whoami
 * @description GET /api/v1/auth/whoami endpoint.
 *
 * Returns the key id and scopes of the authenticated API key, allowing
 * integrators to verify their configuration.
 *
 * @security Requires a scoped API key (X-API-Key or Authorization: ApiKey).
 */

import { Router, Response, NextFunction } from 'express';
import type { ScopedApiKeyRequest } from '../auth/scopedApiKeyMiddleware';
import type { ParsedApiKeys } from '../config/apiKeysConfig';
import { authenticateScopedApiKey } from '../auth/scopedApiKeyMiddleware';

export function createWhoamiRouter(apiKeys: ParsedApiKeys): Router {
  const router = Router();

  router.get(
    '/whoami',
    authenticateScopedApiKey(apiKeys),
    (req: ScopedApiKeyRequest, res: Response, _next: NextFunction) => {
      // scopedApiKey is guaranteed to be set by authenticateScopedApiKey
      const key = req.scopedApiKey!;
      res.status(200).json({
        keyId: key.id,
        scopes: key.scopes,
      });
    },
  );

  return router;
}

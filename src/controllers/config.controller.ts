import { Request, Response } from 'express';
import { loadConfig, AppConfiguration } from '../appConfiguration';

/**
 * Controller for exposing the application configuration.
 *
 * Invariants:
 *  - The configuration is loaded through the single `loadConfig` facade so that
 *    concurrent requests observe the same, deterministic snapshot and any
 *    internal caching / concurrency control is preserved.
 *  - The response is always a fresh copy of the allowed assets so callers
 *    cannot mutate shared configuration state through the returned reference.
 *  - Failures are logged with a correlation id and returned as a stable
 *    `internal_error` payload without leaking internal details.
 */
export class ConfigController {
  /**
   * Returns the application configuration, specifically the allowed assets.
   *
   * The handler is deterministic and idempotent: repeated or concurrent
   * invocations return the same logical configuration and never expose a
   * mutable reference to the underlying store.
   *
   * @param req - Express request
   * @param res - Express response
   */
  static getConfig(req: Request, res: Response) {
    const requestId = req.headers['x-request-id'] ?? req.id ?? undefined;

    try {
      const config = loadConfig() as unknown as AppConfiguration & Record<string, unknown>;
      const allowedAssets = Array.isArray(config['allowedAssets'])
        ? [...(config['allowedAssets'] as unknown[])]
        : [];

      return res.json({ allowedAssets });
    } catch (error) {
      console.error('Failed to load config:', {
        requestId,
        error: error instanceof Error ? error.message : String(error),
      });
      return res.status(500).json({
        error: {
          code: 'internal_error',
          message: 'Failed to load configuration',
        },
      });
    }
  }
}

import { Request, Response } from 'express';
import { loadConfig, ConfigError, AppConfig, ConfigErrorCode } from '../appConfiguration';

export class ConfigController {
  /**
   * Returns the application configuration, specifically the allowed assets.
   *
   * @param req - Express request
   * @param res - Express response
   */
  static getConfig(req: Request, res: Response) {
    try {
      const config: AppConfig = loadConfig();
      return res.json({
        allowedAssets: config.allowedAssets,
      });
    } catch (error) {
      if (error instanceof ConfigError) {
        // Log the code and context only; avoid logging potentially sensitive values.
        console.error('Failed to load config:', {
          code: error.code,
          context: error.context,
        });

        const status = error.code === ConfigErrorCode.MISSING_ENV ? 503 : 500;
        return res.status(status).json({
          error: {
            code: error.code,
            message: error.message,
          },
        });
      }

      // Unknown failure: keep the public contract stable and avoid leaking internal details.
      console.error('Failed to load config:', error);
      return res.status(500).json({
        error: {
          code: 'internal_error',
          message: 'Failed to load configuration',
        },
      });
    }
  }
}

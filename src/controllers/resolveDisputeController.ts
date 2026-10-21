/**
 * @module controllers/resolveDisputeController
 * @description Controller for the dispute resolution endpoint.
 *
 * `POST /api/v1/contracts/:id/resolve` — resolves a dispute by splitting the
 * escrowed balance according to `freelancerBps`. This endpoint is protected
 * by a scoped API key requiring the `disputes:resolve` scope.
 */

import { Response, NextFunction } from 'express';
import { z } from 'zod';
import { disputesService, DisputeError } from '../services/disputes.service';
import { ok, fail } from '../utils/apiResponse';
import type { ScopedApiKeyRequest } from '../auth/scopedApiKeyMiddleware';
import type { Logger } from '../logger';

/**
 * Request body schema for dispute resolution.
 * `freelancerBps` is a basis-point split (0–10000) where 10000 = 100% to the
 * freelancer and 0 = 100% to the client.
 *
 * Wrapped in `{ body: ... }` to be compatible with `validateSchema` which
 * parses `{ body, query, params }` together.
 */
export const resolveDisputeSchema = z.object({
  body: z.object({
    freelancerBps: z.number().int().min(0).max(10000),
  }),
});

export type ResolveDisputeBody = z.infer<typeof resolveDisputeSchema>;

type ResolveDisputeRequest = ScopedApiKeyRequest & {
  params: { id: string };
  body: ResolveDisputeBody;
};

function resolveLogger(res: Response): Logger {
  const log = res.locals['log'] as Logger | undefined;
  if (log) return log;
  return require('../logger').logger as Logger;
}

/**
 * Resolve a dispute for a contract.
 *
 * @security Requires a scoped API key with `disputes:resolve` scope.
 * The acting key id is recorded as the resolver for audit purposes.
 */
export async function resolveDisputeController(
  req: ResolveDisputeRequest,
  res: Response,
  _next: NextFunction,
): Promise<void> {
  const log = resolveLogger(res);
  const contractId = req.params.id;
  const { freelancerBps } = req.body;
  const keyId = req.scopedApiKey?.id ?? 'unknown';

  log.info('contracts.resolveDispute: start', { contractId, freelancerBps, keyId });

  try {
    // Find the active dispute for this contract
    const disputes = disputesService.listDisputes();
    const dispute = disputes.find(
      (d) => d.contractId === contractId && d.status !== 'resolved',
    );

    if (!dispute) {
      fail(res, 'dispute_not_found', `No active dispute found for contract ${contractId}`, 404);
      return;
    }

    // Resolve the dispute via the service layer's transition matrix
    const resolution = `Resolved by ${keyId}: freelancer ${freelancerBps} bps, client ${10000 - freelancerBps} bps`;
    const updated = await disputesService.updateDispute(dispute.id, {
      status: 'resolved',
      resolution,
      statusChangedBy: keyId,
    });

    log.info('contracts.resolveDispute: success', {
      disputeId: dispute.id,
      contractId,
      freelancerBps,
    });

    ok(res, {
      disputeId: updated.id,
      contractId,
      status: updated.status,
      freelancerBps,
      clientBps: 10000 - freelancerBps,
      resolvedBy: keyId,
      resolution: updated.resolution,
    });
  } catch (error) {
    if (error instanceof DisputeError) {
      log.warn('contracts.resolveDispute: failed', {
        contractId,
        error: error.code,
      });
      fail(res, error.code, error.message, error.statusCode);
      return;
    }
    log.error('contracts.resolveDispute: error', {
      contractId,
      err: error as Error,
    });
    fail(res, 'internal_error', 'An unexpected error occurred', 500);
  }
}

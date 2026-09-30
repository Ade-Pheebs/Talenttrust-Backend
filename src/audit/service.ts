/**
 * @module audit/service
 * @description High-level audit logging service.
 *
 * Provides a clean API for application code to emit audit events without
 * coupling directly to the store implementation. All sensitive state changes
 * (contract lifecycle, payments, user management, auth events) must go through
 * this service.
 *
 * Security notes:
 * - Callers MUST sanitise metadata before passing it in — no raw PII.
 * - Logging failures are caught and reported via console.error to avoid
 *   disrupting the primary request flow, but they are also re-thrown in
 *   strict mode so tests can assert on them.
 */

import type { AuditEntry, AuditQuery, AuditSeverity, CreateAuditEntryInput, IntegrityReport, AuditQueryResult } from './types';
import type { AuditAction } from './types';
import { createDefaultAuditRepository, type AuditLogRepository } from './repository';
import { validateAuditInput, AuditValidationError } from './inputValidation';
import { createLogger } from '../logger';

export interface AuditServiceOptions {
  /** Reserved for future use. */
  _reserved?: never;
}

/**
 * AuditService — application-level facade over AuditStore.
 *
 * @example
 * ```ts
 * import { auditService } from './audit/service';
 *
 * await auditService.log({
 *   action: 'CONTRACT_CREATED',
 *   severity: 'INFO',
 *   actor: req.user.id,
 *   resource: 'contract',
 *   resourceId: contract.id,
 *   metadata: { clientId: contract.clientId },
 *   ipAddress: req.ip,
 *   correlationId: req.headers['x-correlation-id'] as string,
 * });
 * ```
 */
export class AuditService {
  constructor(
    private readonly repository: AuditLogRepository = createDefaultAuditRepository(),
    private readonly options: AuditServiceOptions = {},
  ) {}

  /**
   * Records an audit event.
   *
   * Validation runs before any repository interaction — the same invalid input
   * always throws `AuditValidationError` (HTTP 400, code `"validation_error"`)
   * and is never passed to the repository. This is a permanent failure; do not
   * retry on `AuditValidationError`.
   *
   * Repository write failures (I/O, lock contention, etc.) are transient and
   * are re-thrown so the caller can decide whether to retry via `withRetry`.
   *
   * Validation failures are logged at `warn` level with field-level context but
   * without exposing field values (no PII in log records). Write failures are
   * logged at `error` level.
   *
   * @param input - Event details. metadata must be pre-sanitised (no raw PII).
   * @returns The persisted, immutable AuditEntry.
   * @throws {AuditValidationError} When input fails validation (permanent, HTTP 400).
   * @throws {Error} When the repository write fails (transient, should be retried by caller).
   */
  log(input: CreateAuditEntryInput): AuditEntry {
    const log = createLogger({ service: 'audit-service' });

    // ── Step 1: Validate input deterministically ──────────────────────────
    // Same input always produces the same result. No I/O involved.
    // AuditValidationError is a permanent failure — do not retry.
    let validated: CreateAuditEntryInput;
    try {
      validated = validateAuditInput(input);
    } catch (err) {
      if (err instanceof AuditValidationError) {
        // Emit a warn with structural context only — never log field values.
        log.warn('Audit input validation failed', {
          issueCount: err.issues.length,
          fields: err.issues.map((i) => i.field),
        });
        throw err;
      }
      // Unexpected error from the validator itself — escalate.
      log.error('Unexpected error during audit input validation', { err: err as Error });
      throw err;
    }

    // ── Step 2: Persist the validated entry ───────────────────────────────
    // Repository failures are transient — re-throw so callers can retry.
    try {
      return this.repository.append(validated);
    } catch (err) {
      log.error('[AuditService] Failed to persist audit entry', { err: err as Error });
      throw err;
    }
  }

  /**
   * Convenience wrapper for contract lifecycle events.
   */
  logContractEvent(
    action: Extract<AuditAction, `CONTRACT_${string}`>,
    actor: string,
    contractId: string,
    metadata: Record<string, unknown> = {},
    context: { ipAddress?: string; correlationId?: string } = {},
  ): AuditEntry {
    return this.log({
      action,
      severity: 'INFO',
      actor,
      resource: 'contract',
      resourceId: contractId,
      metadata,
      ...context,
    });
  }

  /**
   * Convenience wrapper for payment events.
   * Payment events are always CRITICAL severity.
   */
  logPaymentEvent(
    action: Extract<AuditAction, `PAYMENT_${string}`>,
    actor: string,
    paymentId: string,
    metadata: Record<string, unknown> = {},
    context: { ipAddress?: string; correlationId?: string } = {},
  ): AuditEntry {
    return this.log({
      action,
      severity: 'CRITICAL',
      actor,
      resource: 'payment',
      resourceId: paymentId,
      metadata,
      ...context,
    });
  }

  /**
   * Convenience wrapper for authentication events.
   * AUTH_FAILED is WARNING; others are INFO.
   */
  logAuthEvent(
    action: Extract<AuditAction, `AUTH_${string}`>,
    actor: string,
    metadata: Record<string, unknown> = {},
    context: { ipAddress?: string; correlationId?: string } = {},
  ): AuditEntry {
    const severity: AuditSeverity = action === 'AUTH_FAILED' ? 'WARNING' : 'INFO';
    return this.log({
      action,
      severity,
      actor,
      resource: 'auth',
      resourceId: actor,
      metadata,
      ...context,
    });
  }

  /**
   * Convenience wrapper for user management events.
   * USER_DELETED is WARNING; others are INFO.
   */
  logUserEvent(
    action: Extract<AuditAction, `USER_${string}`>,
    actor: string,
    targetUserId: string,
    metadata: Record<string, unknown> = {},
    context: { ipAddress?: string; correlationId?: string } = {},
  ): AuditEntry {
    const severity: AuditSeverity = action === 'USER_DELETED' ? 'WARNING' : 'INFO';
    return this.log({
      action,
      severity,
      actor,
      resource: 'user',
      resourceId: targetUserId,
      metadata,
      ...context,
    });
  }

  /**
   * Queries the audit log with optional filters.
   *
   * @param query - Filter and pagination options.
   * @returns Matching entries in insertion order.
   */
  query(query: AuditQuery = {}): AuditEntry[] {
    return this.repository.query(query);
  }

  /**
   * Queries the audit log with cursor-based pagination.
   *
   * @param query - Filter and pagination options including cursor.
   * @returns Paginated result with entries and next cursor.
   */
  queryWithCursor(query: AuditQuery = {}): AuditQueryResult {
    return this.repository.queryWithCursor(query);
  }

  /**
   * Streams audit entries for export use cases without loading all rows.
   */
  stream(query: AuditQuery = {}): IterableIterator<AuditEntry> {
    return this.repository.stream(query);
  }

  /**
   * Retrieves a single audit entry by ID.
   */
  getById(id: string): AuditEntry | undefined {
    return this.repository.getById(id);
  }

  /**
   * Returns the total number of audit entries.
   */
  count(): number {
    return this.repository.count();
  }

  /**
   * Verifies the integrity of the entire hash chain.
   * Should be called by a scheduled monitoring job.
   *
   * @returns IntegrityReport — escalate immediately if valid === false.
   */
  verifyIntegrity(): IntegrityReport {
    return this.repository.verifyIntegrity();
  }
}

/** Singleton service instance. */
export const auditService = new AuditService();

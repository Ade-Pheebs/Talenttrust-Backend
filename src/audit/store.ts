/**
 * @module audit/store
 * @description Append-only, tamper-evident in-memory audit log store.
 *
 * Security properties:
 * - Entries are frozen (Object.freeze) immediately on insertion — no mutation possible.
 * - A SHA-256 hash chain links every entry to its predecessor; any tampering breaks
 *   the chain and is detected by verifyIntegrity().
 * - The internal log array is never exposed directly; only copies are returned.
 * - No entry can be deleted or updated — the store is strictly append-only.
 *
 * Production note: Replace the in-memory array with a write-once database table
 * (e.g. PostgreSQL with row-level security and no UPDATE/DELETE grants) while
 * keeping this interface contract intact.
 */

import { createHash, randomUUID } from 'crypto';
import type { AuditEntry, AuditQuery, CreateAuditEntryInput, IntegrityReport, AuditQueryResult, CursorData } from './types';
import { encodeCursor, decodeCursor } from './types';
import type { AuditLogRepository } from './repository';

/** Sentinel hash used as the previousHash of the very first entry. */
export const GENESIS_HASH = 'GENESIS';

/**
 * Computes the SHA-256 hash for an audit entry.
 * The hash covers all content fields (excluding the hash field itself)
 * plus the previousHash, making the chain tamper-evident.
 */
export function computeEntryHash(
  entry: Omit<AuditEntry, 'hash'>,
): string {
  const payload = JSON.stringify({
    id: entry.id,
    timestamp: entry.timestamp,
    action: entry.action,
    severity: entry.severity,
    actor: entry.actor,
    resource: entry.resource,
    resourceId: entry.resourceId,
    metadata: entry.metadata,
    ipAddress: entry.ipAddress ?? null,
    correlationId: entry.correlationId ?? null,
    previousHash: entry.previousHash,
  });
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * Validates a CreateAuditEntryInput before it is accepted into the log.
 *
 * Invariants enforced here (all must hold for every appended entry):
 * - `action`, `severity`, `actor`, `resource`, `resourceId` are non-empty strings.
 * - `metadata` is a plain object (not null/array) so it can be safely frozen.
 * - Optional `ipAddress` / `correlationId`, when present, are non-empty strings.
 *
 * Throwing here keeps the store append-only and prevents partially-formed
 * entries from ever entering the hash chain (which would otherwise make
 * verifyIntegrity() report a false positive on a valid chain).
 */
function assertValidInput(input: CreateAuditEntryInput): void {
  const required: Array<keyof CreateAuditEntryInput> = [
    'action',
    'severity',
    'actor',
    'resource',
    'resourceId',
  ];
  for (const key of required) {
    const value = input[key];
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(`AuditStore.append: "${key}" must be a non-empty string`);
    }
  }
  if (input.metadata === null || typeof input.metadata !== 'object' || Array.isArray(input.metadata)) {
    throw new Error('AuditStore.append: "metadata" must be a plain object');
  }
  if (input.ipAddress !== undefined && (typeof input.ipAddress !== 'string' || input.ipAddress.length === 0)) {
    throw new Error('AuditStore.append: "ipAddress" must be a non-empty string when provided');
  }
  if (input.correlationId !== undefined && (typeof input.correlationId !== 'string' || input.correlationId.length === 0)) {
    throw new Error('AuditStore.append: "correlationId" must be a non-empty string when provided');
  }
}

/**
 * AuditStore — append-only, hash-chained audit log.
 *
 * @example
 * ```ts
 * const store = new AuditStore();
 * store.append({ action: 'CONTRACT_CREATED', severity: 'INFO', actor: 'user-1', ... });
 * const report = store.verifyIntegrity();
 * ```
 */
export class AuditStore implements AuditLogRepository {
  /** Internal append-only log. Never mutate directly. */
  private readonly log: AuditEntry[] = [];

  private _appendGuard = false;

  append(input: CreateAuditEntryInput): AuditEntry {
    if (this._appendGuard) {
      throw new Error('AuditStore append re-entrancy detected');
    }

    this._appendGuard = true;
    try {
      assertValidInput(input);

      const previousHash =
        this.log.length === 0 ? GENESIS_HASH : this.log[this.log.length - 1].hash;

      const partial: Omit<AuditEntry, 'hash'> = {
        id: randomUUID(),
        timestamp: new Date().toISOString(),
        action: input.action,
        severity: input.severity,
        actor: input.actor,
        resource: input.resource,
        resourceId: input.resourceId,
        metadata: Object.freeze({ ...input.metadata }),
        ipAddress: input.ipAddress,
        correlationId: input.correlationId,
        previousHash,
      };

      const entry: AuditEntry = Object.freeze({
        ...partial,
        hash: computeEntryHash(partial),
      });

      this.log.push(entry);
      Object.freeze(this.log);
      return entry;
    } finally {
      this._appendGuard = false;
    }
  }

  /**
   * Returns a shallow copy of all entries (originals remain frozen).
   */
  getAll(): AuditEntry[] {
    return [...this.log];
  }

  /**
   * Returns the total number of entries in the log.
   */
  count(): number {
    return this.log.length;
  }

  /**
   * Retrieves a single entry by its ID.
   * @returns The entry, or undefined if not found.
   */
  getById(id: string): AuditEntry | undefined {
    return this.log.find((e) => e.id === id);
  }

  /**
   * Queries the log with optional filters and pagination.
   * All string comparisons are exact-match.
   *
   * @param query - Filter and pagination options.
   * @returns Matching entries in insertion order.
   */
  query(query: AuditQuery = {}): AuditEntry[] {
    const offset = Math.max(query.offset ?? 0, 0);

    const results = this.log.filter((entry) => {
      if (query.action && entry.action !== query.action) return false;
      if (query.severity && entry.severity !== query.severity) return false;
      if (query.actor && entry.actor !== query.actor) return false;
      if (query.resource && entry.resource !== query.resource) return false;
      if (query.resourceId && entry.resourceId !== query.resourceId) return false;
      if (query.from && entry.timestamp < query.from) return false;
      if (query.to && entry.timestamp > query.to) return false;
      return true;
    });

    if (query.limit === undefined) {
      return results.slice(offset);
    }

    const limit = Math.max(query.limit, 0);
    return results.slice(offset, offset + limit);
  }

  /**
   * Queries the log with cursor-based pagination.
   *
   * @param query - Filter and pagination options including cursor.
   * @returns Paginated result with entries and next cursor.
   */
  queryWithCursor(query: AuditQuery = {}): AuditQueryResult {
    const limit = Math.min(Math.max(query.limit ?? 50, 1), 100);
    
    let startIndex = 0;
    
    // Decode cursor if provided
    if (query.cursor) {
      try {
        const cursorData: CursorData = decodeCursor(query.cursor);
        
        // Find the index of the last entry from the previous page
        const found = this.log.findIndex(e => e.id === cursorData.lastId);
        startIndex = found !== -1 ? found + 1 : 0;
        
        // Verify filters match cursor (prevent filter drift)
        if (cursorData.filters.action !== query.action ||
            cursorData.filters.severity !== query.severity ||
            cursorData.filters.actor !== query.actor ||
            cursorData.filters.resource !== query.resource ||
            cursorData.filters.resourceId !== query.resourceId ||
            cursorData.filters.from !== query.from ||
            cursorData.filters.to !== query.to) {
          throw new Error('Cursor filters do not match query filters');
        }
      } catch {
        // If cursor is invalid or filters mismatch, reject rather than silently
        // returning a different page (prevents silent data loss / pagination drift).
        throw new Error('AuditStore.queryWithCursor: invalid or mismatched cursor');
      }
    }
    
    const filtered = this.log.filter((entry) => {
      if (query.action && entry.action !== query.action) return false;
      if (query.severity && entry.severity !== query.severity) return false;
      if (query.actor && entry.actor !== query.actor) return false;
      if (query.resource && entry.resource !== query.resource) return false;
      if (query.resourceId && entry.resourceId !== query.resourceId) return false;
      if (query.from && entry.timestamp < query.from) return false;
      if (query.to && entry.timestamp > query.to) return false;
      return true;
    });
    
    const entries = filtered.slice(startIndex, startIndex + limit);
    
    // Generate next cursor if there are more results
    let nextCursor: string | undefined;
    if (startIndex + limit < filtered.length && entries.length > 0) {
      const lastEntry = entries[entries.length - 1];
      const cursorData: CursorData = {
        lastId: lastEntry.id,
        lastTimestamp: lastEntry.timestamp,
        filters: {
          action: query.action,
          severity: query.severity,
          actor: query.actor,
          resource: query.resource,
          resourceId: query.resourceId,
          from: query.from,
          to: query.to,
        },
      };
      nextCursor = encodeCursor(cursorData);
    }
    
    return {
      entries,
      count: entries.length,
      limit,
      nextCursor,
    };
  }

  *stream(query: AuditQuery = {}): IterableIterator<AuditEntry> {
    const rows = this.query(query);
    for (const row of rows) {
      yield row;
    }
  }

  /**
   * Verifies the integrity of the entire hash chain.
   * Detects any tampering, deletion, or reordering of entries.
   *
   * @returns An IntegrityReport describing the result.
   *
   * @security This should be called periodically by a monitoring job.
   *           A broken chain is a security incident and must be escalated.
   */
  verifyIntegrity(): IntegrityReport {
    const checkedAt = new Date().toISOString();

    if (this.log.length === 0) {
      return { valid: true, totalEntries: 0, checkedAt };
    }

    for (let i = 0; i < this.log.length; i++) {
      const entry = this.log[i];

      // Verify previousHash linkage
      const expectedPreviousHash = i === 0 ? GENESIS_HASH : this.log[i - 1].hash;
      if (entry.previousHash !== expectedPreviousHash) {
        return {
          valid: false,
          totalEntries: this.log.length,
          firstCorruptedIndex: i,
          firstCorruptedId: entry.id,
          checkedAt,
        };
      }

      // Recompute and verify the entry's own hash
      const { hash, ...rest } = entry;
      const expectedHash = computeEntryHash(rest);
      if (hash !== expectedHash) {
        return {
          valid: false,
          totalEntries: this.log.length,
          firstCorruptedIndex: i,
          firstCorruptedId: entry.id,
          checkedAt,
        };
      }
    }

    return { valid: true, totalEntries: this.log.length, checkedAt };
  }

  /**
   * Clears all entries. Intended for testing only.
   * @internal
   */
  _reset(): void {
    this.log.length = 0;
    this._appendGuard = false;
  }
}

/** Singleton store instance shared across the application. */
export const auditStore = new AuditStore();

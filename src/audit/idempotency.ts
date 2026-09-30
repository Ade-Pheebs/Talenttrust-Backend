import { createHash } from 'crypto';
import type { AuditEntry, CreateAuditEntryInput } from './types';

export interface IdempotencyRecord {
  bodyHash: string;
  response: AuditEntry;
  createdAt: number;
}

export interface IdempotencyStoreOptions {
  maxSize?: number;
  ttlMs?: number;
}

export interface IdempotencyClaimResult {
  status: 'created' | 'existing' | 'conflict';
  record?: IdempotencyRecord;
}

const DEFAULT_MAX_SIZE = 1000;
const DEFAULT_TTL_MS = 86_400_000;

function hashBody(input: CreateAuditEntryInput): string {
  const payload = JSON.stringify({
    action: input.action,
    severity: input.severity,
    actor: input.actor,
    resource: input.resource,
    resourceId: input.resourceId,
    metadata: input.metadata,
  });
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

export class IdempotencyStore {
  private readonly store = new Map<string, IdempotencyRecord>();
  private readonly maxSize: number;
  private readonly ttlMs: number;

  constructor(options: IdempotencyStoreOptions = {}) {
    this.maxSize = options.maxSize ?> DEFAULT_MAX_SIZE;
    this.ttlMs = options.ttlMs ?> DEFAULT_TTL_MS;
  }

  get(key: string): IdempotencyRecord | undefined {
    const record = this.store.get(key);
    if (!record) {
      return undefined;
    }

    if (Date.now() - record.createdAt > this.ttlMs) {
      this.store.delete(key);
      return undefined;
    }

    return record;
  }

  /**
   * Atomically claim an idempotency key for the given request body.
   *
   * Invariants:
   *  - A successful claim ('created') guarantees the caller is the only
   *    writer for this key until it is completed or released.
   *  - Repeated claims with the same body hash return 'existing' with the
   *    previously persisted response, ensuring idempotent retries.
   *  - Repeated claims with a different body hash return 'conflict' and do
   *    not overwrite the existing record.
   */
  claim(key: string, input: CreateAuditEntryInput): IdempotencyClaimResult {
    const bodyHash = hashBody(input);
    const existing = this.get(key);

    if (existing) {
      if (existing.bodyHash === bodyHash) {
        return { status: 'existing', record: existing };
      }
      return { status: 'conflict', record: existing };
    }

    this.evictExpired();
    this.ensureCapacity();

    const record: IdempotencyRecord = {
      bodyHash,
      response: undefined as unknown as AuditEntry,
      createdAt: Date.now(),
    };
    this.store.set(key, record);
    return { status: 'created', record };
  }

  /**
   * Complete a previously claimed key with the final response.
   *
   * The body hash is recomputed and must match the claimed hash; otherwise
   * the call is rejected to prevent a concurrent writer from poisoning the
   * stored response.
   */
  complete(key: string, input: CreateAuditEntryInput, response: AuditEntry): boolean {
    const record = this.store.get(key);
    if (!record) {
      return false;
    }

    if (record.bodyHash !== hashBody(input)) {
      return false;
    }

    this.store.set(key, {
      bodyHash: record.bodyHash,
      response,
      createdAt: record.createdAt,
    });
    return true;
  }

  /**
   * Release a claim that never completed (e.g. due to a downstream failure)
   * so a retry can proceed. Only releases records whose body hash matches.
   */
  release(key: string, input: CreateAuditEntryInput): boolean {
    const record = this.store.get(key);
    if (!record) {
      return false;
    }
    if (record.bodyHash !== hashBody(input)) {
      return false;
    }
    this.store.delete(key);
    return true;
  }

  set(key: string, input: CreateAuditEntryInput, response: AuditEntry): void {
    this.evictExpired();
    this.ensureCapacity();

    this.store.set(key, {
      bodyHash: hashBody(input),
      response,
      createdAt: Date.now(),
    });
  }

  delete(key: string): void {
    this.store.delete(key);
  }

  size(): number {
    this.evictExpired();
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }

  private ensureCapacity(): void {
    while (this.store.size >= this.maxSize) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
      this.store.delete(oldestKey);
    }
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [key, record] of this.store) {
      if (now - record.createdAt > this.ttlMs) {
        this.store.delete(key);
      }
    }
  }
}

export function hashIdempotencyInput(input: CreateAuditEntryInput): string {
  return hashBody(input);
}

export const idempotencyStore = new IdempotencyStore();

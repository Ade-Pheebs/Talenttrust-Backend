import { createHash } from 'crypto';
import type { AuditEntry, CreateAuditEntryInput } from './types';
import { AUDIT_ACTIONS, AUDIT_SEVERITIES } from './types';
import { canonicalizeJson } from '../utils/idempotencyFingerprint';

export interface IdempotencyRecord {
  readonly bodyHash: string;
  readonly response: AuditEntry;
  readonly createdAt: number;
}

export interface IdempotencyStoreOptions {
  maxSize?: number;
  ttlMs?: number;
}

const DEFAULT_MAX_SIZE = 1000;
const DEFAULT_TTL_MS = 86_400_000;
// Include the additional actions in the public AuditAction union as well as
// the published runtime list; this store must accept existing typed producers.
const actions = new Set<string>([...AUDIT_ACTIONS, 'CONTRACT_DELETED', 'MILESTONES_CREATED', 'MILESTONES_UPDATED', 'MILESTONES_DELETED']);

export class AuditIdempotencyError extends Error {
  constructor(readonly code: 'audit_idempotency_invalid_input' | 'audit_idempotency_conflict') {
    super(code === 'audit_idempotency_conflict'
      ? 'Audit idempotency key is already bound to a different payload'
      : 'Invalid audit idempotency input');
    this.name = 'AuditIdempotencyError';
  }
}

/** Copy JSON data without executing getters/toJSON or retaining caller aliases.
 * Unsupported values must reject rather than silently vanish from a fingerprint.
 * The depth bound prevents hostile in-process input exhausting the call stack.
 */
function snapshot(value: unknown, seen = new WeakSet<object>(), depth = 0): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'object' || depth > 64 || seen.has(value)) {
    throw new AuditIdempotencyError('audit_idempotency_invalid_input');
  }
  const prototype = Object.getPrototypeOf(value);
  if ((!Array.isArray(value) && prototype !== Object.prototype && prototype !== null)
    || Object.getOwnPropertySymbols(value).length > 0) {
    throw new AuditIdempotencyError('audit_idempotency_invalid_input');
  }
  seen.add(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const copy: Record<string, unknown> | unknown[] = Array.isArray(value) ? [] : Object.create(null);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!descriptor.enumerable) continue;
    if (!('value' in descriptor)) throw new AuditIdempotencyError('audit_idempotency_invalid_input');
    // Optional transport context can be absent on a typed AuditEntry. Nested
    // undefined metadata is rejected to avoid collisions with omitted fields.
    if (depth === 0 && (key === 'ipAddress' || key === 'correlationId') && descriptor.value === undefined) continue;
    Object.defineProperty(copy, key, {
      value: snapshot(descriptor.value, seen, depth + 1), enumerable: true,
    });
  }
  if (Array.isArray(value) && (Object.keys(copy).length !== value.length
    || Object.keys(copy).some(key => !/^(0|[1-9]\d*)$/.test(key) || Number(key) >= value.length))) {
    throw new AuditIdempotencyError('audit_idempotency_invalid_input');
  }
  seen.delete(value);
  return Object.freeze(copy);
}

function validateKey(key: string): void {
  if (typeof key !== 'string' || key.trim().length === 0 || key.length > 256 || /[\x00-\x1f\x7f]/.test(key)) {
    throw new AuditIdempotencyError('audit_idempotency_invalid_input');
  }
}

function hashBody(input: CreateAuditEntryInput): string {
  const data = snapshot(input) as CreateAuditEntryInput;
  if (!data || typeof data !== 'object') throw new AuditIdempotencyError('audit_idempotency_invalid_input');
  for (const field of ['action', 'severity', 'actor', 'resource', 'resourceId'] as const) {
    if (typeof data[field] !== 'string' || data[field].trim().length === 0) {
      throw new AuditIdempotencyError('audit_idempotency_invalid_input');
    }
  }
  if (!actions.has(data.action) || !(AUDIT_SEVERITIES as readonly string[]).includes(data.severity)) {
    throw new AuditIdempotencyError('audit_idempotency_invalid_input');
  }
  if (!data.metadata || Array.isArray(data.metadata) || typeof data.metadata !== 'object') {
    throw new AuditIdempotencyError('audit_idempotency_invalid_input');
  }
  const payload = canonicalizeJson({
    action: data.action,
    severity: data.severity,
    actor: data.actor,
    resource: data.resource,
    resourceId: data.resourceId,
    metadata: data.metadata,
  });
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

export class IdempotencyStore {
  private readonly store = new Map<string, IdempotencyRecord>();
  private readonly maxSize: number;
  private readonly ttlMs: number;
  private lastNow = 0;

  constructor(options: IdempotencyStoreOptions = {}) {
    this.maxSize = options.maxSize ?? DEFAULT_MAX_SIZE;
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    if (!Number.isSafeInteger(this.maxSize) || this.maxSize <= 0
      || !Number.isSafeInteger(this.ttlMs) || this.ttlMs <= 0) {
      throw new RangeError('Audit idempotency maxSize and ttlMs must be positive safe integers');
    }
  }

  get(key: string): IdempotencyRecord | undefined {
    validateKey(key);
    const record = this.store.get(key);
    if (!record) {
      return undefined;
    }

    if (this.now() - record.createdAt >= this.ttlMs) {
      this.store.delete(key);
      return undefined;
    }

    return record;
  }

  set(key: string, input: CreateAuditEntryInput, response: AuditEntry): void {
    validateKey(key);
    // Prepare completely before eviction/publication: rejection cannot erase
    // another key. JSON getters are forbidden, so preparation cannot re-enter.
    const bodyHash = hashBody(input);
    const responseSnapshot = snapshot(response) as AuditEntry;
    if (!responseSnapshot || ['id', 'timestamp', 'hash', 'previousHash'].some(field => {
      const value = responseSnapshot[field as keyof AuditEntry];
      return typeof value !== 'string' || value.length === 0;
    })) throw new AuditIdempotencyError('audit_idempotency_invalid_input');
    if (hashBody(responseSnapshot) !== bodyHash) {
      throw new AuditIdempotencyError('audit_idempotency_invalid_input');
    }
    const now = this.now();
    const existing = this.store.get(key);
    if (existing && now - existing.createdAt < this.ttlMs) {
      if (existing.bodyHash !== bodyHash) throw new AuditIdempotencyError('audit_idempotency_conflict');
      // First completed response wins. Replays neither refresh TTL nor reorder
      // FIFO eviction, and cannot overwrite another actor/resource's result.
      return;
    }
    const record = Object.freeze({ bodyHash, response: responseSnapshot, createdAt: now });
    this.evictExpired(now);

    if (this.store.size >= this.maxSize) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey !== undefined) {
        this.store.delete(oldestKey);
      }
    }

    // No await or caller callbacks between inspecting and publishing the state.
    this.store.set(key, record);
  }

  delete(key: string): void {
    validateKey(key);
    this.store.delete(key);
  }

  size(): number {
    this.evictExpired();
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }

  private now(): number {
    const now = Date.now();
    if (!Number.isSafeInteger(now) || now < 0) throw new AuditIdempotencyError('audit_idempotency_invalid_input');
    // A wall-clock rollback must not make an already-aged record young again.
    this.lastNow = Math.max(this.lastNow, now);
    return this.lastNow;
  }

  private evictExpired(now = this.now()): void {
    for (const [key, record] of this.store) {
      if (now - record.createdAt >= this.ttlMs) {
        this.store.delete(key);
      }
    }
  }
}

export function hashIdempotencyInput(input: CreateAuditEntryInput): string {
  return hashBody(input);
}

export const idempotencyStore = new IdempotencyStore();

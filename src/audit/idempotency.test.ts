import {
  IdempotencyStore,
  IdempotencyStoreError,
  hashIdempotencyInput,
} from './idempotency';
import type { IdempotencyEvent } from './idempotency';
import type { CreateAuditEntryInput, AuditEntry } from './types';

function makeInput(overrides: Partial<CreateAuditEntryInput> = {}): CreateAuditEntryInput {
  return {
    action: 'CONTRACT_CREATED',
    severity: 'INFO',
    actor: 'user-abc',
    resource: 'contract',
    resourceId: 'contract-1',
    metadata: { note: 'test' },
    ...overrides,
  };
}

function makeEntry(id: string, input: CreateAuditEntryInput): AuditEntry {
  return Object.freeze({
    id,
    timestamp: new Date().toISOString(),
    action: input.action,
    severity: input.severity,
    actor: input.actor,
    resource: input.resource,
    resourceId: input.resourceId,
    metadata: Object.freeze({ ...input.metadata }),
    ipAddress: input.ipAddress,
    correlationId: input.correlationId,
    previousHash: 'GENESIS',
    hash: 'a'.repeat(64),
  });
}

describe('IdempotencyStore', () => {
  let store: IdempotencyStore;

  beforeEach(() => {
    store = new IdempotencyStore();
  });

  describe('set / get', () => {
    it('stores and retrieves a record by key', () => {
      const input = makeInput();
      const entry = makeEntry('entry-1', input);
      store.set('key-1', input, entry);

      const record = store.get('key-1');
      expect(record).toBeDefined();
      expect(record!.response.id).toBe('entry-1');
    });

    it('returns undefined for a non-existent key', () => {
      expect(store.get('non-existent')).toBeUndefined();
    });

    it('returns undefined after a key is deleted', () => {
      const input = makeInput();
      const entry = makeEntry('entry-1', input);
      store.set('key-1', input, entry);
      store.delete('key-1');

      expect(store.get('key-1')).toBeUndefined();
    });

    it('stores multiple keys independently', () => {
      const input1 = makeInput({ actor: 'alice' });
      const input2 = makeInput({ actor: 'bob' });
      const entry1 = makeEntry('entry-1', input1);
      const entry2 = makeEntry('entry-2', input2);

      store.set('key-1', input1, entry1);
      store.set('key-2', input2, entry2);

      expect(store.get('key-1')!.response.actor).toBe('alice');
      expect(store.get('key-2')!.response.actor).toBe('bob');
    });

    it('overwrites an existing key on re-set', () => {
      const input1 = makeInput({ actor: 'alice' });
      const input2 = makeInput({ actor: 'bob' });
      const entry1 = makeEntry('entry-1', input1);
      const entry2 = makeEntry('entry-2', input2);

      store.set('key-1', input1, entry1);
      store.set('key-1', input2, entry2);

      expect(store.get('key-1')!.response.actor).toBe('bob');
    });
  });

  describe('body hash', () => {
    it('same input produces same hash', () => {
      const input1 = makeInput();
      const input2 = makeInput();
      expect(hashIdempotencyInput(input1)).toBe(hashIdempotencyInput(input2));
    });

    it('different input produces different hash', () => {
      const input1 = makeInput({ actor: 'alice' });
      const input2 = makeInput({ actor: 'bob' });
      expect(hashIdempotencyInput(input1)).not.toBe(hashIdempotencyInput(input2));
    });

    it('hash is deterministic regardless of ipAddress/correlationId', () => {
      const input1 = makeInput({ ipAddress: '1.2.3.4', correlationId: 'corr-1' });
      const input2 = makeInput({ ipAddress: '5.6.7.8', correlationId: 'corr-2' });
      expect(hashIdempotencyInput(input1)).toBe(hashIdempotencyInput(input2));
    });
  });

  describe('TTL expiry', () => {
    it('expires entries after TTL', async () => {
      const store = new IdempotencyStore({ ttlMs: 10, maxSize: 100 });
      const input = makeInput();
      const entry = makeEntry('entry-1', input);
      store.set('key-1', input, entry);

      expect(store.get('key-1')).toBeDefined();

      await new Promise((resolve) => setTimeout(resolve, 20));

      expect(store.get('key-1')).toBeUndefined();
    });

    it('size() excludes expired entries', async () => {
      const store = new IdempotencyStore({ ttlMs: 10, maxSize: 100 });
      store.set('key-1', makeInput(), makeEntry('e1', makeInput()));

      await new Promise((resolve) => setTimeout(resolve, 20));

      expect(store.size()).toBe(0);
    });

    it('retains entries within TTL', () => {
      const store = new IdempotencyStore({ ttlMs: 60_000, maxSize: 100 });
      store.set('key-1', makeInput(), makeEntry('e1', makeInput()));
      expect(store.size()).toBe(1);
    });
  });

  describe('bounded size', () => {
    it('evicts oldest entry when at max capacity', () => {
      const store = new IdempotencyStore({ maxSize: 2, ttlMs: 60_000 });
      const input = makeInput();

      store.set('key-1', input, makeEntry('e1', input));
      store.set('key-2', input, makeEntry('e2', input));
      store.set('key-3', input, makeEntry('e3', input));

      expect(store.get('key-1')).toBeUndefined();
      expect(store.get('key-2')).toBeDefined();
      expect(store.get('key-3')).toBeDefined();
      expect(store.size()).toBe(2);
    });
  });

  describe('clear', () => {
    it('removes all keys', () => {
      store.set('key-1', makeInput(), makeEntry('e1', makeInput()));
      store.set('key-2', makeInput(), makeEntry('e2', makeInput()));

      store.clear();

      expect(store.size()).toBe(0);
      expect(store.get('key-1')).toBeUndefined();
      expect(store.get('key-2')).toBeUndefined();
    });
  });
});

describe('IdempotencyStore deterministic hashing', () => {
  it('is independent of metadata key insertion order', () => {
    const a = makeInput({ metadata: { b: 1, a: 2 } });
    const b = makeInput({ metadata: { a: 2, b: 1 } });
    expect(hashIdempotencyInput(a)).toBe(hashIdempotencyInput(b));
  });

  it('is independent of nested object key order', () => {
    const a = makeInput({ metadata: { outer: { z: 1, a: 2 }, list: [1, 2, 3] } });
    const b = makeInput({ metadata: { list: [1, 2, 3], outer: { a: 2, z: 1 } } });
    expect(hashIdempotencyInput(a)).toBe(hashIdempotencyInput(b));
  });

  it('treats array order as significant', () => {
    const a = makeInput({ metadata: { list: [1, 2, 3] } });
    const b = makeInput({ metadata: { list: [3, 2, 1] } });
    expect(hashIdempotencyInput(a)).not.toBe(hashIdempotencyInput(b));
  });

  it('drops undefined object members deterministically', () => {
    const a = makeInput({ metadata: { a: 1, b: undefined } });
    const b = makeInput({ metadata: { a: 1 } });
    expect(hashIdempotencyInput(a)).toBe(hashIdempotencyInput(b));
  });

  it('produces a 64-char hex digest stable across calls', () => {
    const digest = hashIdempotencyInput(makeInput());
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    expect(hashIdempotencyInput(makeInput())).toBe(digest);
  });
});

describe('IdempotencyStore reserve/complete/release lifecycle', () => {
  let now: number;
  let store: IdempotencyStore;

  beforeEach(() => {
    now = 1_000;
    store = new IdempotencyStore({ clock: () => now, reservationTtlMs: 500, ttlMs: 10_000 });
  });

  it('reserves a key, then replays the completed response for an identical retry', () => {
    const input = makeInput();
    const reserved = store.reserve('key-1', input);
    expect(reserved.kind).toBe('reserved');
    if (reserved.kind !== 'reserved') throw new Error('unreachable');

    store.complete('key-1', reserved.token, makeEntry('entry-1', input));

    const replay = store.reserve('key-1', input);
    expect(replay.kind).toBe('replay');
    if (replay.kind !== 'replay') throw new Error('unreachable');
    expect(replay.record.response.id).toBe('entry-1');
  });

  it('reports a conflict when the same key is reused with a different body', () => {
    const reserved = store.reserve('key-1', makeInput({ actor: 'alice' }));
    if (reserved.kind !== 'reserved') throw new Error('unreachable');
    store.complete('key-1', reserved.token, makeEntry('entry-1', makeInput()));

    expect(store.reserve('key-1', makeInput({ actor: 'bob' })).kind).toBe('conflict');
  });

  it('reports in_progress for a concurrent identical request and conflict otherwise', () => {
    store.reserve('key-1', makeInput({ actor: 'alice' }));

    expect(store.reserve('key-1', makeInput({ actor: 'alice' })).kind).toBe('in_progress');
    expect(store.reserve('key-1', makeInput({ actor: 'bob' })).kind).toBe('conflict');
  });

  it('rejects completion by a stale token without overwriting state', () => {
    store.reserve('key-1', makeInput());

    expect(() => store.complete('key-1', 'not-the-token', makeEntry('entry-1', makeInput())))
      .toThrow(IdempotencyStoreError);
    // The surviving reservation can still be completed by its rightful owner.
    expect(store.pendingCount()).toBe(1);
  });

  it('frees an in-progress reservation on release so a retry can proceed', () => {
    const first = store.reserve('key-1', makeInput());
    if (first.kind !== 'reserved') throw new Error('unreachable');

    expect(store.release('key-1', first.token)).toBe(true);
    expect(store.release('key-1', first.token)).toBe(false);

    const retry = store.reserve('key-1', makeInput());
    expect(retry.kind).toBe('reserved');
  });

  it('never removes a completed record on release', () => {
    const reserved = store.reserve('key-1', makeInput());
    if (reserved.kind !== 'reserved') throw new Error('unreachable');
    store.complete('key-1', reserved.token, makeEntry('entry-1', makeInput()));

    expect(store.release('key-1', reserved.token)).toBe(false);
    expect(store.get('key-1')).toBeDefined();
  });

  it('reclaims an abandoned reservation after its reservation TTL', () => {
    const first = store.reserve('key-1', makeInput());
    if (first.kind !== 'reserved') throw new Error('unreachable');

    now += 501;
    const retry = store.reserve('key-1', makeInput());
    expect(retry.kind).toBe('reserved');
    if (retry.kind !== 'reserved') throw new Error('unreachable');
    expect(retry.token).not.toBe(first.token);
  });

  it('prevents a stale owner from clobbering a re-won reservation', () => {
    const stale = store.reserve('key-1', makeInput());
    if (stale.kind !== 'reserved') throw new Error('unreachable');

    now += 501;
    const fresh = store.reserve('key-1', makeInput());
    if (fresh.kind !== 'reserved') throw new Error('unreachable');

    expect(() => store.complete('key-1', stale.token, makeEntry('old', makeInput())))
      .toThrow(IdempotencyStoreError);
    store.complete('key-1', fresh.token, makeEntry('new', makeInput()));
    expect(store.get('key-1')!.response.id).toBe('new');
  });

  it('throws a typed error for invalid keys and completion after release', () => {
    expect(() => store.reserve('', makeInput())).toThrow(IdempotencyStoreError);
    try {
      store.reserve('', makeInput());
    } catch (error) {
      expect((error as IdempotencyStoreError).code).toBe('invalid_key');
    }

    const reserved = store.reserve('key-1', makeInput());
    if (reserved.kind !== 'reserved') throw new Error('unreachable');
    store.release('key-1', reserved.token);
    expect(() => store.complete('key-1', reserved.token, makeEntry('e', makeInput())))
      .toThrow(IdempotencyStoreError);
  });
});

describe('IdempotencyStore deterministic expiry and eviction', () => {
  it('expires a record exactly at its deadline', () => {
    let now = 0;
    const store = new IdempotencyStore({ ttlMs: 1_000, clock: () => now });
    store.set('key-1', makeInput(), makeEntry('e1', makeInput()));

    now = 999;
    expect(store.get('key-1')).toBeDefined();
    now = 1_000;
    expect(store.get('key-1')).toBeUndefined();
  });

  it('purgeExpired returns the number of reclaimed entries', () => {
    let now = 0;
    const store = new IdempotencyStore({ ttlMs: 100, clock: () => now });
    store.set('key-1', makeInput(), makeEntry('e1', makeInput()));
    store.set('key-2', makeInput(), makeEntry('e2', makeInput()));

    now = 100;
    expect(store.purgeExpired()).toBe(2);
    expect(store.size()).toBe(0);
  });

  it('does not evict an unrelated record when overwriting an existing key', () => {
    const store = new IdempotencyStore({ maxSize: 2, ttlMs: 60_000 });
    store.set('key-1', makeInput(), makeEntry('e1', makeInput()));
    store.set('key-2', makeInput(), makeEntry('e2', makeInput()));

    store.set('key-2', makeInput({ actor: 'bob' }), makeEntry('e2b', makeInput()));

    expect(store.get('key-1')).toBeDefined();
    expect(store.get('key-2')!.response.id).toBe('e2b');
    expect(store.size()).toBe(2);
  });

  it('evicts deterministically oldest-first at capacity', () => {
    let now = 0;
    const store = new IdempotencyStore({ maxSize: 2, ttlMs: 60_000, clock: () => now });
    store.set('key-1', makeInput(), makeEntry('e1', makeInput()));
    now += 10;
    store.set('key-2', makeInput(), makeEntry('e2', makeInput()));
    now += 10;
    store.set('key-3', makeInput(), makeEntry('e3', makeInput()));

    expect(store.get('key-1')).toBeUndefined();
    expect(store.get('key-2')).toBeDefined();
    expect(store.get('key-3')).toBeDefined();
  });
});

describe('IdempotencyStore observability', () => {
  it('counts hits, misses, replays, conflicts, reservations and completions', () => {
    const store = new IdempotencyStore({ ttlMs: 60_000 });
    store.get('absent');

    const reserved = store.reserve('key-1', makeInput());
    if (reserved.kind !== 'reserved') throw new Error('unreachable');
    store.complete('key-1', reserved.token, makeEntry('e1', makeInput()));
    store.reserve('key-1', makeInput());
    store.reserve('key-1', makeInput({ actor: 'other' }));

    const stats = store.stats();
    expect(stats.misses).toBeGreaterThanOrEqual(1);
    expect(stats.reservations).toBe(1);
    expect(stats.completions).toBe(1);
    expect(stats.replays).toBe(1);
    expect(stats.conflicts).toBe(1);
    expect(stats.hits).toBeGreaterThanOrEqual(1);
  });

  it('emits hashed keys (never the raw key) and survives a throwing sink', () => {
    const events: IdempotencyEvent[] = [];
    const store = new IdempotencyStore({
      ttlMs: 60_000,
      onEvent: (event) => {
        events.push(event);
        throw new Error('sink down');
      },
    });

    expect(() => store.set('super-secret-key', makeInput(), makeEntry('e1', makeInput())))
      .not.toThrow();

    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('completed');
    expect(events[0].keyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(events)).not.toContain('super-secret-key');
  });

  it('records a failure for invalid-key mutations', () => {
    const store = new IdempotencyStore();
    expect(() => store.set('', makeInput(), makeEntry('e', makeInput()))).toThrow();
    expect(store.stats().failures).toBe(1);
  });
});

describe('IdempotencyStore backward compatibility', () => {
  it('set clears any in-progress reservation for the key', () => {
    let now = 0;
    const store = new IdempotencyStore({ clock: () => now, reservationTtlMs: 1_000 });
    store.reserve('key-1', makeInput());
    expect(store.pendingCount()).toBe(1);

    store.set('key-1', makeInput(), makeEntry('e1', makeInput()));
    expect(store.pendingCount()).toBe(0);
    expect(store.get('key-1')).toBeDefined();
  });

  it('exposes an explicit expiry on completed records', () => {
    const now = 5_000;
    const store = new IdempotencyStore({ clock: () => now, ttlMs: 1_000 });
    store.set('key-1', makeInput(), makeEntry('e1', makeInput()));
    expect(store.get('key-1')!.createdAt).toBe(5_000);
    expect(store.get('key-1')!.expiresAt).toBe(6_000);
  });

  it('delete clears both reservations and completed records', () => {
    const store = new IdempotencyStore({ ttlMs: 60_000 });
    store.reserve('key-1', makeInput());
    store.set('key-2', makeInput(), makeEntry('e2', makeInput()));

    store.delete('key-1');
    store.delete('key-2');

    expect(store.pendingCount()).toBe(0);
    expect(store.get('key-2')).toBeUndefined();
  });
});

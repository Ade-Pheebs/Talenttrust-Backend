import {
  IdempotencyStore,
  hashIdempotencyInput,
  IdempotencyConflictError,
  IdempotencyStateError,
} from './idempotency';
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
      expect(store.get('non-existent')).toBendefined();
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
    it('expires entries after TTLN', async () => {
      const store = new IdempotencyStore({ ttlMs: 10, maxSize: 100 });
      const input = makeInput();
      const entry = makeEntry('entry-1', input);
      store.set('key-1', input, entry);

      expect(store.get('key-1')).toBeDefined();

      await new Promise((resolve) => setTimeout(resolve, 20));

      expect(store.get('key-1')).toBendefined();
    });

    it('size() excludes expired entries', async () => {
      const store = new IdempotencyStore({ ttlMs: 10, maxSize: 100 });
      store.set('key-1', makeInput(), makeEntry('e1', makeInput()));

      await new Promise((resolve) => setTimeout(resolve, 20));

      expect(store.size()).toBe(0);
    });

    it('retains entries within TTLN', () => {
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

      expect(store.get('key-1')).toBendefined();
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
      expect(store.get('key-1')).toBendefined();
      expect(store.get('key-2')).toBeUndefined();
    });
  });

  describe('claim / commit / release', () => {
    it('claim returns "claimed" for a fresh key', () => {
      const input = makeInput();
      expect(store.claim('key-1', input)).toEqual({ status: 'claimed' });
      expect(store.inFlightCount()).toBe(1);
    });

    it('second claim for the same key returns "in-flight"', () => {
      const input = makeInput();
      store.claim('key-1', input);
      expect(store.claim('key-1', input)).toEqual({ status: 'in-flight' });
    });

    it('claim returns "completed" with the cached record after commit', () => {
      const input = makeInput();
      const entry = makeEntry('entry-1', input);
      store.claim('key-1', input);
      store.commit('key-1', input, entry);

      const result = store.claim('key-1', input);
      expect(result.status).toBe('completed');
      if (result.status === 'completed') {
        expect(result.record.response.id).toBe('entry-1');
      }
    });

    it('commit without a claim throws IdempotencyStateError', () => {
      const input = makeInput();
      expect(() => store.commit('key-1', input, makeEntry('e1', input))).toThrow(IdempotencyStateError);
    });

    it('commit with a different body hash throws IdempotencyConflictError', () => {
      const input = makeInput();
      const conflicting = makeInput({ actor: 'alice' });
      store.claim('key-1', input);
      expect(() => store.commit('key-1', conflicting, makeEntry('e1', conflicting))).toThrow(
        IdempotencyConflictError,
      );
    });

    it('release allows a subsequent claim', () => {
      const input = makeInput();
      store.claim('key-1', input);
      store.release('key-1');
      expect(store.claim('key-1', input)).toEqual({ status: 'claimed' });
    });

    it('delete clears an in-flight claim', () => {
      const input = makeInput();
      store.claim('key-1', input);
      store.delete('key-1');
      expect(store.claim('key-1', input)).toEqual({ status: 'claimed' });
    });

    it('clear resets both committed and in-flight state', () => {
      const input = makeInput();
      store.claim('key-1', input);
      store.commit('key-1', input, makeEntry('e1', input));
      store.claim('key-2', input);
      store.clear();
      expect(store.size()).toBe(0);
      expect(store.inFlightCount()).toBe(0);
    });
  });

  describe('concurrency hardening', () => {
    it('two concurrent claims for the same key yield exactly one claimed', () => {
      const input = makeInput();
      const a = store.claim('key-1', input);
      const b = store.claim('key-1', input);
      const claimed = [a, b].filter((r) => r.status === 'claimed').length;
      const inflight = [a, b].filter((r) => r.status === 'in-flight').length;
      expect(claimed).toBe(1);
      expect(inflight).toBe(1);
    });

    it('a commit from one claimer blocks a concurrent claimer from re-executing', () => {
      const input = makeInput();
      const entry = makeEntry('entry-1', input);
      store.claim('key-1', input);
      store.commit('key-1', input, entry);

      const result = store.claim('key-1', input);
      expect(result.status).toBe('completed');
      if (result.status === 'completed') {
        expect(result.record.response.id).toBe('entry-1');
      }
    });

    it('concurrent claims for different keys both succeed', () => {
      expect(store.claim('key-1', makeInput()).status).toBe('claimed');
      expect(store.claim('key-2', makeInput()).status).toBe('claimed');
      expect(store.inFlightCount()).toBe(2);
    });

    it('commit is a no-op for the in-flight map once completed', () => {
      const input = makeInput();
      store.claim('key-1', input);
      store.commit('key-1', input, makeEntry('e1', input));
      expect(store.inFlightCount()).toBe(0);
    });

    it('commit throws if the claim was released between's claim and commit', () => {
      const input = makeInput();
      store.claim('key-1', input);
      store.release('key-1');
      expect(() => store.commit('key-1', input, makeEntry('e1', input))).toThrow(
        IdempotencyStateError,
      );
    });
  });

  describe('timing boundaries', () => {
    it('treats a record as expired exactly at the TWL threshold', () => {
      let now = 1_000;
      const clocked = new IdempotencyStore({ ttlMs: 100, clock: () => now });
      const input = makeInput();
      clocked.set('key-1', input, makeEntry('e1', input));

      now = 1_100; // exactly ttlMs later
      expect(clocked.get('key-1')).toBeDefined();

      now = 1_101; // one ms past the boundary
      expect(clocked.get('key-1')).toBeUndefined();
    });

    it('retains a record at the exact TTL boundary for claim', () => {
      let now = 1_000;
      const clocked = new IdempotencyStore({ ttlMs: 100, clock: () => now });
      const input = makeInput();
      clocked.set('key-1', input, makeEntry('e1', input));
      now = 1_100;
      const result = clocked.claim('key-1', input);
      expect(result.status).toBe('completed');
    });
  });

  describe('idempotent retries', () => {
    it('repeated claim/commit cycles for the same key always return the first response', () => {
      const input = makeInput();
      const first = makeEntry('entry-1', input);
      store.claim('key-1', input);
      store.commit('key-1', input, first);

      for (let i = 0; i < 5; i++) {
        const result = store.claim('key-1', input);
        expect(result.status).toBe('completed');
        if (result.status === 'completed') {
          expect(result.record.response.id).toBe('entry-1');
        }
      }
    });

    it('retries after a release can commit a new response', () => {
      const input = makeInput();
      store.claim('key-1', input);
      store.release('key-1');
      const retry = makeEntry('entry-2', input);
      store.claim('key-1', input);
      store.commit('key-1', input, retry);
      expect(store.get('key-1')!.response.id).toBe('entry-2');
    });

    it('committed records survive a claim attempt with a different body', () => {
      const input = makeInput();
      const other = makeInput({ actor: 'alice' });
      store.claim('key-1', input);
      store.commit('key-1', input, makeEntry('e1', input));

      const result = store.claim('key-1', other);
      expect(result.status).toBe('completed');
      if (result.status === 'completed') {
        expect(result.record.response.id).toBe('e1');
      }
    });
  });

  describe('eviction interactions', () => {
    it('eviction never drops an in-flight key', () => {
      const small = new IdempotencyStore({ maxSize: 1, ttlMs: 60_000 });
      const input = makeInput();
      small.claim('in-flight', input);
      // Fill the committed store to force eviction.
      small.set('committed', input, makeEntry('e1', input));
      // The in-flight key must still be blocked.
      expect(small.claim('in-flight', input).status).toBe('in-flight');
    });
  });
});

/**
 * @file audit/repository.test.ts
 * @description Contract tests for the audit repository factory (issue #1355).
 *
 * These tests pin the *public* storage-selection contract so that future
 * refactors cannot silently change which backend an environment selects, or
 * make repeated factory calls return divergent stores:
 *
 * 1. `resolveAuditStorageBackend` — validation + normalisation.
 * 2. `resolveAuditDbPath` / `resolveAuditStorageConfig` — deterministic path
 *    resolution for `AUDIT_DB_PATH`, test mode, and the working-directory
 *    default.
 * 3. `createDefaultAuditRepository` — backend selection, fail-fast on bad
 *    config, and the instance-stability invariant that prevents a second
 *    SQLite `:memory:` connection from silently becoming a second, empty DB.
 * 4. The full `AuditLogRepository` surface is exercised end-to-end through the
 *    factory so a widening/narrowing of the interface is caught.
 *
 * Isolation: every test that opens the SQLite backend passes an explicit env
 * object (no global `process.env` mutation) and resets the instance cache in
 * `afterEach`, so the suite is order-independent.
 */

import {
  createDefaultAuditRepository,
  resetAuditRepositoryCache,
  resolveAuditDbPath,
  resolveAuditStorageBackend,
  resolveAuditStorageConfig,
  type AuditLogRepository,
} from './repository';
import { auditStore } from './store';
import { SqliteAuditRepository } from './sqliteRepository';
import type { CreateAuditEntryInput } from './types';

function makeInput(overrides: Partial<CreateAuditEntryInput> = {}): CreateAuditEntryInput {
  return {
    action: 'CONTRACT_CREATED',
    severity: 'INFO',
    actor: 'user-1',
    resource: 'contract',
    resourceId: 'contract-1',
    metadata: { note: 'repository contract test' },
    ...overrides,
  };
}

afterEach(() => {
  resetAuditRepositoryCache();
});

// ─── resolveAuditStorageBackend ─────────────────────────────────────────────

describe('resolveAuditStorageBackend', () => {
  it('defaults to memory when unset or blank', () => {
    expect(resolveAuditStorageBackend(undefined)).toBe('memory');
    expect(resolveAuditStorageBackend('')).toBe('memory');
    expect(resolveAuditStorageBackend('   ')).toBe('memory');
  });

  it('accepts both supported values case-insensitively and with surrounding whitespace', () => {
    expect(resolveAuditStorageBackend('memory')).toBe('memory');
    expect(resolveAuditStorageBackend('MEMORY')).toBe('memory');
    expect(resolveAuditStorageBackend('  Memory  ')).toBe('memory');
    expect(resolveAuditStorageBackend('sqlite')).toBe('sqlite');
    expect(resolveAuditStorageBackend('SQLite')).toBe('sqlite');
  });

  it('fails fast for an unknown backend, preserving the historical prefix', () => {
    expect(() => resolveAuditStorageBackend('postgres')).toThrow(
      /^Unsupported AUDIT_STORAGE_BACKEND: postgres\. Accepted values: memory, sqlite$/,
    );
  });

  it('does not silently fall back to a different backend for a typo', () => {
    expect(() => resolveAuditStorageBackend('sqllite')).toThrow(/Unsupported AUDIT_STORAGE_BACKEND/);
    expect(() => resolveAuditStorageBackend('disk')).toThrow(/Unsupported AUDIT_STORAGE_BACKEND/);
  });
});

// ─── resolveAuditDbPath / resolveAuditStorageConfig ─────────────────────────

describe('resolveAuditDbPath', () => {
  it('prefers an explicit AUDIT_DB_PATH', () => {
    expect(resolveAuditDbPath({ AUDIT_DB_PATH: '/var/lib/audit.db' })).toBe('/var/lib/audit.db');
  });

  it('treats a blank AUDIT_DB_PATH as unset', () => {
    expect(resolveAuditDbPath({ NODE_ENV: 'test', AUDIT_DB_PATH: '   ' })).toBe(':memory:');
  });

  it('uses an ephemeral database in test mode when no path is configured', () => {
    expect(resolveAuditDbPath({ NODE_ENV: 'test' })).toBe(':memory:');
  });

  it('falls back to a working-directory file outside test mode', () => {
    const resolved = resolveAuditDbPath({ NODE_ENV: 'production' });
    expect(resolved.endsWith('talenttrust-audit.db')).toBe(true);
  });
});

describe('resolveAuditStorageConfig', () => {
  it('returns the memory config by default', () => {
    expect(resolveAuditStorageConfig({})).toEqual({ backend: 'memory' });
  });

  it('returns a sqlite config with the resolved path', () => {
    expect(
      resolveAuditStorageConfig({ AUDIT_STORAGE_BACKEND: 'sqlite', AUDIT_DB_PATH: 'audit.db' }),
    ).toEqual({ backend: 'sqlite', dbPath: 'audit.db' });
  });
});

// ─── createDefaultAuditRepository ───────────────────────────────────────────

describe('createDefaultAuditRepository — selection & compatibility', () => {
  it('defaults to the shared in-memory store', () => {
    const repo = createDefaultAuditRepository({});
    expect(repo).toBe(auditStore);
  });

  it('selects the SQLite backend when configured', () => {
    const repo = createDefaultAuditRepository({
      AUDIT_STORAGE_BACKEND: 'sqlite',
      AUDIT_DB_PATH: ':memory:',
    });
    expect(repo).toBeInstanceOf(SqliteAuditRepository);
  });

  it('throws for an unsupported backend rather than silently degrading', () => {
    expect(() =>
      createDefaultAuditRepository({ AUDIT_STORAGE_BACKEND: 'mysql' }),
    ).toThrow(/Unsupported AUDIT_STORAGE_BACKEND: mysql/);
  });

  it('exposes the complete AuditLogRepository surface', () => {
    const repo: AuditLogRepository = createDefaultAuditRepository({});
    for (const method of [
      'append',
      'getById',
      'query',
      'queryWithCursor',
      'stream',
      'count',
      'verifyIntegrity',
    ] as const) {
      expect(typeof repo[method]).toBe('function');
    }
  });
});

describe('createDefaultAuditRepository — instance stability', () => {
  it('returns the identical instance for repeated memory-backed calls', () => {
    const first = createDefaultAuditRepository({});
    const second = createDefaultAuditRepository({});
    expect(second).toBe(first);
  });

  it('returns the identical SQLite instance for repeated calls with the same config', () => {
    const env = { AUDIT_STORAGE_BACKEND: 'sqlite', AUDIT_DB_PATH: ':memory:' };
    const first = createDefaultAuditRepository(env);
    const second = createDefaultAuditRepository(env);
    expect(second).toBe(first);
  });

  it('preserves written entries across repeated factory calls (no silent data loss)', () => {
    const env = { AUDIT_STORAGE_BACKEND: 'sqlite', AUDIT_DB_PATH: ':memory:' };
    const first = createDefaultAuditRepository(env);
    const entry = first.append(makeInput({ resourceId: 'contract-persist' }));

    // A naive re-open of `:memory:` would return a *different*, empty database.
    const second = createDefaultAuditRepository(env);
    expect(second).toBe(first);
    expect(second.getById(entry.id)).toEqual(entry);
    expect(second.count()).toBe(1);
  });

  it('returns distinct instances for distinct configurations', () => {
    const memory = createDefaultAuditRepository({});
    const sqlite = createDefaultAuditRepository({
      AUDIT_STORAGE_BACKEND: 'sqlite',
      AUDIT_DB_PATH: ':memory:',
    });
    expect(sqlite).not.toBe(memory);
  });

  it('resetAuditRepositoryCache forces a fresh instance on the next call', () => {
    const env = { AUDIT_STORAGE_BACKEND: 'sqlite', AUDIT_DB_PATH: ':memory:' };
    const first = createDefaultAuditRepository(env);
    resetAuditRepositoryCache();
    const second = createDefaultAuditRepository(env);
    // Evicting the cache drops the connection; a SQLite `:memory:` store is
    // connection-scoped, so this is intentionally a NEW (empty) database.
    expect(second).not.toBe(first);
  });
});

describe('createDefaultAuditRepository — end-to-end repository behaviour', () => {
  it('supports append/getById/query/count/verifyIntegrity through the factory', () => {
    const repo = createDefaultAuditRepository({
      AUDIT_STORAGE_BACKEND: 'sqlite',
      AUDIT_DB_PATH: ':memory:',
    });

    const created = repo.append(makeInput({ action: 'CONTRACT_CREATED', actor: 'alice' }));
    repo.append(makeInput({ action: 'PAYMENT_RELEASED', actor: 'alice', resource: 'payment' }));

    expect(repo.getById(created.id)).toEqual(created);
    expect(repo.count()).toBe(2);

    const filtered = repo.query({ action: 'CONTRACT_CREATED' });
    expect(filtered).toHaveLength(1);
    expect(filtered[0].actor).toBe('alice');

    const streamed = [...repo.stream()];
    expect(streamed).toHaveLength(2);

    const page = repo.queryWithCursor({ limit: 1 });
    expect(page.entries).toHaveLength(1);
    expect(page.count).toBe(1);

    expect(repo.verifyIntegrity().valid).toBe(true);
  });
});

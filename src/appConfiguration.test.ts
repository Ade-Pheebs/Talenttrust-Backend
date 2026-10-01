import { AppConfig, loadConfig } from './appConfiguration';
import { isSafeUrl } from './utils/ssrf';

describe('application configuration compatibility', () => {
  const originalEnv = process.env;

  afterEach(() => {
    process.env = originalEnv;
  });

  it('preserves the complete default public shape', () => {
    expect(loadConfig({})).toEqual({
      port: 3001,
      gracefulDegradationEnabled: true,
      upstreamContractsUrl: 'https://example.invalid/contracts',
      upstreamTimeoutMs: 1200,
      chaosMode: 'off',
      chaosTargets: [],
      chaosProbability: 0,
      circuitBreaker: { failureThreshold: 5, successThreshold: 1, timeoutMs: 30000 },
      webhookRetry: {
        maxAttempts: 5, initialDelayMs: 1000, maxDelayMs: 30000, multiplier: 2, jitterFactor: 0.1,
      },
      webhookCircuitBreaker: { failureThreshold: 5, successThreshold: 1, timeoutMs: 60000 },
      healthProbes: { queueFailedThreshold: 10, queueBacklogThreshold: 100, queueProbeTimeoutMs: 3000 },
      idempotencyTtlMs: 3600000,
      allowedAssets: ['USDC', 'XLM', 'BTC', 'ETH'],
      milestonesEnabled: true,
    } satisfies AppConfig);
  });

  it('preserves valid overrides, list order/duplicates and fractional policies', () => {
    const config = loadConfig({
      PORT: '4000', GRACEFUL_DEGRADATION_ENABLED: 'false', MILESTONES_ENABLED: 'FALSE',
      UPSTREAM_CONTRACTS_URL: 'https://api.example.com/contracts', UPSTREAM_TIMEOUT_MS: '2500',
      CHAOS_MODE: 'RaNdOm', CHAOS_TARGETS: ' Contracts , RPC,contracts,,', CHAOS_PROBABILITY: '0.25',
      ALLOWED_ASSETS: ' usdc, XLM,usdc,,', CB_FAILURE_THRESHOLD: '8', CB_SUCCESS_THRESHOLD: '2',
      CB_TIMEOUT_MS: '2000', WEBHOOK_CB_FAILURE_THRESHOLD: '7', WEBHOOK_CB_SUCCESS_THRESHOLD: '3',
      WEBHOOK_CB_TIMEOUT_MS: '5000', WEBHOOK_RETRY_MAX_ATTEMPTS: '6',
      WEBHOOK_RETRY_INITIAL_DELAY_MS: '1500', WEBHOOK_RETRY_MAX_DELAY_MS: '20000',
      WEBHOOK_RETRY_MULTIPLIER: '1.5', WEBHOOK_RETRY_JITTER_FACTOR: '0.2',
      QUEUE_FAILED_THRESHOLD: '20', QUEUE_BACKLOG_THRESHOLD: '200', QUEUE_PROBE_TIMEOUT_MS: '4000',
      IDEMPOTENCY_TTL_MS: '0',
    });
    expect(config).toMatchObject({
      port: 4000, gracefulDegradationEnabled: false, milestonesEnabled: false,
      upstreamContractsUrl: 'https://api.example.com/contracts', upstreamTimeoutMs: 2500,
      chaosMode: 'random', chaosTargets: ['contracts', 'rpc', 'contracts'], chaosProbability: 0.25,
      allowedAssets: ['USDC', 'XLM', 'USDC'], idempotencyTtlMs: 0,
      circuitBreaker: { failureThreshold: 8, successThreshold: 2, timeoutMs: 2000 },
      webhookCircuitBreaker: { failureThreshold: 7, successThreshold: 3, timeoutMs: 5000 },
      webhookRetry: {
        maxAttempts: 6, initialDelayMs: 1500, maxDelayMs: 20000, multiplier: 1.5, jitterFactor: 0.2,
      },
      healthProbes: { queueFailedThreshold: 20, queueBacklogThreshold: 200, queueProbeTimeoutMs: 4000 },
    });
  });

  const integerCases: [string, (config: AppConfig) => number, number][] = [
    ['PORT', (c) => c.port, 3001],
    ['CB_FAILURE_THRESHOLD', (c) => c.circuitBreaker.failureThreshold, 5],
    ['CB_SUCCESS_THRESHOLD', (c) => c.circuitBreaker.successThreshold, 1],
    ['WEBHOOK_CB_FAILURE_THRESHOLD', (c) => c.webhookCircuitBreaker.failureThreshold, 5],
    ['WEBHOOK_CB_SUCCESS_THRESHOLD', (c) => c.webhookCircuitBreaker.successThreshold, 1],
    ['WEBHOOK_RETRY_MAX_ATTEMPTS', (c) => c.webhookRetry.maxAttempts, 5],
    ['QUEUE_FAILED_THRESHOLD', (c) => c.healthProbes.queueFailedThreshold, 10],
    ['QUEUE_BACKLOG_THRESHOLD', (c) => c.healthProbes.queueBacklogThreshold, 100],
  ];

  it.each(integerCases)('%s falls back on fractional and missing numeric input', (key, read, fallback) => {
    for (const value of ['2.5', ' ', '', 'not-a-number', 'NaN', 'Infinity']) {
      expect(read(loadConfig({ [key]: value }))).toBe(fallback);
    }
  });

  it('keeps existing inclusive clamp bounds and zero policies', () => {
    expect(loadConfig({ PORT: '0', CHAOS_PROBABILITY: '-1', IDEMPOTENCY_TTL_MS: '-1' }))
      .toMatchObject({ port: 1, chaosProbability: 0, idempotencyTtlMs: 0 });
    expect(loadConfig({ PORT: '999999', CHAOS_PROBABILITY: '2', IDEMPOTENCY_TTL_MS: '9999999999' }))
      .toMatchObject({ port: 65535, chaosProbability: 1, idempotencyTtlMs: 604800000 });
    expect(loadConfig({ QUEUE_FAILED_THRESHOLD: '0', QUEUE_BACKLOG_THRESHOLD: '0' }).healthProbes)
      .toMatchObject({ queueFailedThreshold: 0, queueBacklogThreshold: 0 });
  });

  it('treats whitespace-only optional settings as missing', () => {
    expect(loadConfig({
      UPSTREAM_TIMEOUT_MS: ' ', CB_TIMEOUT_MS: ' ', WEBHOOK_RETRY_INITIAL_DELAY_MS: ' ',
      ALLOWED_ASSETS: ' ', GRACEFUL_DEGRADATION_ENABLED: ' ', MILESTONES_ENABLED: '',
    })).toEqual(loadConfig({}));
    // A comma-only explicit allowlist still means no assets, as before.
    expect(loadConfig({ ALLOWED_ASSETS: ',,,' }).allowedAssets).toEqual([]);
  });

  it.each(['true', 'TRUE', ' true ', '1'])('accepts documented enabled flags: %s', (value) => {
    expect(loadConfig({ MILESTONES_ENABLED: value, GRACEFUL_DEGRADATION_ENABLED: value }))
      .toMatchObject({ milestonesEnabled: true, gracefulDegradationEnabled: true });
  });

  it.each(['false', 'FALSE', ' false ', '0'])('accepts documented disabled flags: %s', (value) => {
    expect(loadConfig({ MILESTONES_ENABLED: value, GRACEFUL_DEGRADATION_ENABLED: value }))
      .toMatchObject({ milestonesEnabled: false, gracefulDegradationEnabled: false });
  });

  it.each(['MILESTONES_ENABLED', 'GRACEFUL_DEGRADATION_ENABLED'])
    ('rejects malformed %s without echoing its value', (key) => {
      expect(() => loadConfig({ [key]: 'private-value' })).toThrow(new RegExp(`Invalid ${key}`));
      try { loadConfig({ [key]: 'private-value' }); } catch (error) {
        expect((error as Error).message).not.toContain('private-value');
      }
    });

  it.each(['production', 'unknown', ''])('cannot inherit a global private-host bypass in %s', (mode) => {
    process.env = { ...originalEnv, NODE_ENV: 'test', SSRF_ALLOW_PRIVATE_HOSTS: 'true' };
    expect(() => loadConfig({
      NODE_ENV: mode, SSRF_ALLOW_PRIVATE_HOSTS: 'true', UPSTREAM_CONTRACTS_URL: 'http://127.0.0.1/contracts',
    })).toThrow(/SSRF protection/);
    expect(() => loadConfig({ UPSTREAM_CONTRACTS_URL: 'http://localhost/contracts' })).toThrow(/SSRF protection/);
  });

  it.each(['development', 'test', 'staging'])('honors an explicit bypass in %s independently of globals', (mode) => {
    process.env = { ...originalEnv, NODE_ENV: 'production', SSRF_ALLOW_PRIVATE_HOSTS: 'false' };
    expect(loadConfig({
      NODE_ENV: mode, SSRF_ALLOW_PRIVATE_HOSTS: 'true', UPSTREAM_CONTRACTS_URL: 'http://localhost/contracts',
    }).upstreamContractsUrl).toBe('http://localhost/contracts');
  });

  it.each([
    'http://user:private-password@127.0.0.1/contracts?token=private-token',
    'not-a-url?token=private-token', 'ftp://public.example.com/contracts', 'file:///etc/passwd',
  ])('rejects unsafe or non-HTTP upstreams with a sanitized error', (url) => {
    expect(() => loadConfig({ UPSTREAM_CONTRACTS_URL: url })).toThrow(/Invalid UPSTREAM_CONTRACTS_URL/);
    try { loadConfig({ UPSTREAM_CONTRACTS_URL: url }); } catch (error) {
      expect((error as Error).message).not.toContain(url);
      expect((error as Error).message).not.toMatch(/private-password|private-token/);
    }
  });

  it('does not let a development bypass accept malformed URLs', () => {
    expect(() => loadConfig({
      NODE_ENV: 'test', SSRF_ALLOW_PRIVATE_HOSTS: 'true', UPSTREAM_CONTRACTS_URL: 'invalid',
    })).toThrow(/Invalid UPSTREAM_CONTRACTS_URL/);
  });

  it('sanitizes malformed bypass policy and allows a clean retry after failure', () => {
    const healthy = loadConfig({});
    const globalBefore = { ...process.env };
    const invalid = { NODE_ENV: 'test', SSRF_ALLOW_PRIVATE_HOSTS: 'private-policy-value' };
    expect(() => loadConfig(invalid)).toThrow(/Invalid UPSTREAM_CONTRACTS_URL/);
    try { loadConfig(invalid); } catch (error) {
      expect((error as Error).message).not.toContain('private-policy-value');
    }
    expect(loadConfig({})).toEqual(healthy);
    expect(process.env).toEqual(globalBefore);
  });

  it('returns independent snapshots without mutating supplied or global environments', async () => {
    const env = Object.freeze({ ALLOWED_ASSETS: 'usdc,xlm', CB_FAILURE_THRESHOLD: '9' });
    const globalBefore = { ...process.env };
    const configs = await Promise.all(Array.from({ length: 3 }, async () => loadConfig(env)));
    configs[0].allowedAssets.push('BTC');
    configs[0].circuitBreaker.failureThreshold = 20;
    expect(configs[1]).toEqual(configs[2]);
    expect(configs[1].allowedAssets).toEqual(['USDC', 'XLM']);
    expect(loadConfig(env)).toEqual(configs[1]);
    expect(process.env).toEqual(globalBefore);
    expect(env).toEqual({ ALLOWED_ASSETS: 'usdc,xlm', CB_FAILURE_THRESHOLD: '9' });
  });

  it('preserves the no-argument loader and existing one-argument SSRF utility', () => {
    process.env = { ...originalEnv, PORT: '4100', NODE_ENV: 'test', SSRF_ALLOW_PRIVATE_HOSTS: 'true' };
    expect(loadConfig().port).toBe(4100);
    expect(isSafeUrl('http://localhost/contracts')).toBe(true);
  });
});

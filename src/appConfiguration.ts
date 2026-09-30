import { isSafeUrl } from './utils/ssrf';

export type ChaosMode = 'off' | 'error' | 'timeout' | 'random';

export interface CircuitBreakerConfig {
  failureThreshold: number;
  successThreshold: number;
  timeoutMs: number;
}

/**
 * Webhook retry policy configuration for transient failure recovery.
 * Controls exponential backoff with jitter for retrying webhook deliveries
 * before enqueuing to DLQ.
 */
export interface WebhookRetryConfig {
  maxAttempts: number;
  initialDelayMs: number;
  maxDelayMs: number;
  multiplier: number;
  jitterFactor: number;
}

export interface HealthProbeConfig {
  queueFailedThreshold: number;
  queueBacklogThreshold: number;
  queueProbeTimeoutMs: number;
}

export interface AppConfig {
  port: number;
  gracefulDegradationEnabled: boolean;
  upstreamContractsUrl: string;
  upstreamTimeoutMs: number;
  chaosMode: ChaosMode;
  chaosTargets: string[];
  chaosProbability: number;
  circuitBreaker: CircuitBreakerConfig;
  webhookRetry: WebhookRetryConfig;
  /**
   * Per-provider circuit-breaker configuration for outbound webhook delivery.
   * Thresholds are intentionally separate from the RPC circuit breaker so
   * webhook and RPC failure modes can be tuned independently.
   */
  webhookCircuitBreaker: CircuitBreakerConfig;
  healthProbes: HealthProbeConfig;
  idempotencyTtlMs: number;
  allowedAssets: string[];
  /**
   * When `true` (default), milestones are validated and enforced through the
   * contracts API. When `false`, milestone fields are stripped from incoming
   * requests so the feature is entirely disabled at runtime without a deploy.
   */
  milestonesEnabled: boolean;
}

const MAX_TIMEOUT_MS = 10_000;
const MIN_TIMEOUT_MS = 100;

function toNumber(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function parseChaosMode(value: string | undefined): ChaosMode {
  const mode = (value ?? 'off').toLowerCase();
  if (mode === 'error' || mode === 'timeout' || mode === 'random') {
    return mode;
  }
  return 'off';
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }

  return value.toLowerCase() === 'true';
}

function parseTargets(value: string | undefined): string[] {
  if (!value) {
    return [];
  }

  return value
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

function _parseAssets(value: string | undefined): string[] {
  if (!value) {
    return ['USDC', 'XLM', 'BTC', 'ETH']; // Default assets
  }

  return value
    .split(',')
    .map((item) => item.trim().toUpperCase())
    .filter(Boolean);
}

/**
 * The canonical environment keys that influence a loaded configuration.
 * Used to determine whether a cached entry is still valid.
 */
const CONFIG_ENV_KEYS = [
  'PORT',
  'GRACEFUL_DEGRADATION_ENABLED',
  'UPSTREAM_CONTRACTS_URL',
  'UPSTREAM_TIMEOUT_MS',
  'CHAOS_MODE',
  'CHAOS_TARGETS',
  'CHAOS_PROBABILITY',
  'CB_FAILURE_THRESHOLD',
  'CB_SUCCESS_THRESHOLD',
  'CB_TIMEOUT_MS',
  'WEBHOOK_RETRY_MAX_ATTEMPTS',
  'WEBHOOK_RETRY_INITIAL_DELAY_MS',
  'WEBHOOK_RETRY_MAX_DELAY_MS',
  'WEBHOOK_RETRY_MULTIPLIER',
  'WEBHOOK_RETRY_JITTER_FACTOR',
  'WEBHOOK_CB_FAILURE_THRESHOLD',
  'WEBHOOK_CB_SUCCESS_THRESHOLD',
  'WEBHOOK_CB_TIMEOUT_MS',
  'QUEUE_FAILED_THRESHOLD',
  'QUEUE_BACKLOG_THRESHOLD',
  'QUEUE_PROBE_TIMEOUT_MS',
  'IDEMPLOTENCY_TTL_MS',
  'ALLOWED_ASSETS',
  'MILESTONES_ENABLED',
] as const;

export type ConfigEnvKey = (typeof CONFIG_ENV_KEYS)[number];

export interface LoadConfigOptions {
  /**
   * When `true`, bypasses the module-level cache and re-parses the environment.
   * This is intended for tests and admin reload paths that must observe
   * mutations to `process.env` within the same process.
   */
  forceReload?: boolean;
}

interface CacheEntry {
  config: AppConfig;
  snapshot: Record<ConfigEnvKey, string | undefined>;
}

/**
 * Module-level cache for the default environment.
 *
 * Invariants:
 *   - The cache is only used when the caller does not pass an explicit env
 *     object and does not request `forceReload`.
 *   - The cache is invalidated whenever any config-relevant environment
 *     variable changes, so concurrent callers cannot observe stale values.
 *   - The cache is synchronous and single-threaded in Node.js, so no lock is
  *     required; however, any future async reload must preserve the atomic
 *     swap semantics used here.
 */
let cache: CacheEntry | undefined;

function snapshotEnv(source: NodeJS.ProcessEnv): Record<ConfigEnvKey, string | undefined> {
  const snapshot = {} as Record<ConfigEnvKey, string | undefined>;
  for (const key of CONFIG_ENV_KEYS) {
    snapshot[key] = source[key];
  }
  return snapshot;
}

function snapshotsEqual(
  a: Record<ConfigEnvKey, string | undefined>,
  b: Record<ConfigEnvKey, string | undefined>,
): boolean {
  for (const key of CONFIG_ENV_KEYS) {
    if (a[key] !== b[key]) {
      return false;
    }
  }
  return true;
}

/**
 * Resets the module-level configuration cache.
 * Intended for tests and admin reload paths.
 */
export function resetConfigCache(): void {
  cache = undefined;
}

function buildConfig(env: NodeJS.ProcessEnv): AppConfig {
  const port = clamp(toNumber(env.PORT, 3001), 1, 65535);
  const upstreamTimeoutMs = clamp(toNumber(env.UPSTREAM_TIMEOUT_MS, 1200), MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
  const chaosProbability = clamp(toNumber(env.CHAOS_PROBABILITY, 0), 0, 1);
  const idempotencyTtlMs = clamp(toNumber(env.IDEMPOTENCY_TTL_MS, 3_600_000), 0, 7 * 24 * 60 * 60 * 1000);

  const upstreamContractsUrl = (() => {
    const url = env.UPSTREAM_CONTRACTS_URL ?? 'https://example.invalid/contracts';
    if (!isSafeUrl(url)) {
      throw new Error(`Invalid UPSTREAM_CONTRACTS_URL: SSRF protection blocked access to internal resource "${url}"`);
    }
    return url;
  })();

  return {
    port,
    gracefulDegradationEnabled: parseBoolean(env.GRACEFUL_DEGRADATION_ENABLED, true),
    upstreamContractsUrl,
    upstreamTimeoutMs,
    chaosMode: parseChaosMode(env.CHAOS_MODE),
    chaosTargets: parseTargets(env.CHAOS_TARGETS),
    chaosProbability,
    circuitBreaker: {
      failureThreshold: clamp(toNumber(env.CB2FAILURE_THRESHOLD, 5), 1, 100),
      successThreshold: clamp(toNumber(env.CB2SUCCESS_THRESHOLD, 1), 1, 20),
      timeoutMs: clamp(toNumber(env.CB_TIMEOUT_MS, 30_000), 1_000, 300_000),
    },
    webhookRetry: {
      maxAttempts: clamp(toNumber(env.WEBHOOK_RETRY_MAX_ATTEMPTS, 5), 1, 20),
      initialDelayMs: clamp(toNumber(env.WEBHOOK_RETRY_INITIAL_DELAY_MS, 1_000), 100, 60_000),
      maxDelayMs: clamp(toNumber(env.WEBHOOK_RETRY_MAX_DELAY_MS, 30_000), 1_000, 600_000),
      multiplier: clamp(toNumber(env.WEBHOOK_RETRY_MULTIPLIER, 2), 1, 10),
      jitterFactor: clamp(toNumber(env.WEBHOOK_RETRY_JITTER_FACTOR, 0.1), 0, 1),
    },
    webhookCircuitBreaker: {
      failureThreshold: clamp(toNumber(env.WEBHOOK_CB_FAILURE_THRESHOLD, 5), 1, 100),
      successThreshold: clamp(toNumber(env.WEBHOOK_CB_SUCCESS_THRESHOLD, 1), 1, 20),
      timeoutMs: clamp(toNumber(env.WEBHOOK_CB_TIMEOUT_MS, 60_000), 1_000, 300_000),
    },
    healthProbes: {
      queueFailedThreshold: clamp(toNumber(env.QUEUE_FAILED_THRESHOLD, 10), 0, 10_000),
      queueBacklogThreshold: clamp(toNumber(env.QUEUE_BACKLOG_THRESHOLD, 100), 0, 1_000_000),
      queueProbeTimeoutMs: clamp(toNumber(env.QUEUE_PROBE_TIMEOUT_MS, 3_000), 100, 30_000),
    },
    idempotencyTtlMs,
    allowedAssets: _parseAssets(env.ALLOWED_ASSETS),
    milestonesEnabled: parseBoolean(env.MILESTONES_ENABLED, true),
  };
}

/**
 * Loads the application configuration from the provided environment.
 *
 * Concurrency / idempotency guarantees:
 *   - When no explicit env is passed and `forceReload` is false, the result is
  *     cached and returned by reference. Callers must treat the returned
 *     object as immutable.
   - The cache is invalidated automatically when any config-relevant
  *     environment variable changes, so concurrent callers never observe
 *     stale values.
 *   - Parsing is synchronous; a concurrent caller either observes the
 *     previous consistent cache or the newly built one, never a partially
 *     constructed object.
 *   - Invalid configuration (e.g. SSRF blocked URL) throws before the cache
  *     is updated, so a failed reload never corrupts a previously valid
 *     cache.
 */
export function loadConfig(
  env: NodeJS.ProcessEnv = process.env,
  options: LoadConfigOptions = {},
): AppConfig {
  const useCache = env === process.env && !options.forceReload;

  if (useCache) {
    const snapshot = snapshotEnv(env);
    if (cache && snapshotsEqual(cache.snapshot, snapshot)) {
      return cache.config;
    }

    // Build first, then swap atomically. If building throws, the existing
    // cache remains untouched.
    const next = buildConfig(env);
    cache = { config: next, snapshot };
    return next;
  }

  return buildConfig(env);
}

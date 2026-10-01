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

export const DEFAULT_ALLOWED_ASSETS: readonly string[] = Object.freeze(['USDC', 'XLM', 'BTC', 'ETH']);

const MAX_TIMEOUT_MS = 10_000;
const MIN_TIMEOUT_MS = 100;

/**
 * Validation boundaries for environment-driven configuration.
 *
 * Invariants enforced by `loadConfig`:
 *  - Numeric fields are parsed with `Number`; non-finite or missing values
 *    fall back to the documented default (never `NaN`/`Infinity`).
 *  - Numeric fields are clamped to the inclusive `[min, max]` range below.
 *  - Enum-like fields (`chaosMode`) reject unknown values and fall back to
 *    the safe default (`off`).
 *  - Boolean fields accept only the case-insensitive literal `true`; any
 *    other value (including `false`, `1`, `yes`) resolves to `false`.
 *  - List fields are split on `,`, trimmed, case-normalized, and empty
 *    entries are dropped. Duplicate entries are preserved as-is so callers
 *    can detect them; ordering is preserved for determinism.
 *  - `upstreamContractsUrl` must pass SSRF validation or `loadConfig` throws.
 *
 * These boundaries are the single source of truth for accepted input; any
 * change here is a behavior change and must be covered by tests.
 */
export const CONFIG_BOUNDS = {
  port: { min: 1, max: 65535 },
  upstreamTimeoutMs: { min: MIN_TIMEOUT_MS, max: MAX_TIMEOUT_MS },
  chaosProbability: { min: 0, max: 1 },
  idempotencyTtlMs: { min: 0, max: 7 * 24 * 60 * 60 * 1000 },
  circuitBreaker: {
    failureThreshold: { min: 1, max: 100 },
    successThreshold: { min: 1, max: 20 },
    timeoutMs: { min: 1_000, max: 300_000 },
  },
  webhookRetry: {
    maxAttempts: { min: 1, max: 20 },
    initialDelayMs: { min: 100, max: 60_000 },
    maxDelayMs: { min: 1_000, max: 600_000 },
    multiplier: { min: 1, max: 10 },
    jitterFactor: { min: 0, max: 1 },
  },
  webhookCircuitBreaker: {
    failureThreshold: { min: 1, max: 100 },
    successThreshold: { min: 1, max: 20 },
    timeoutMs: { min: 1_000, max: 300_000 },
  },
  healthProbes: {
    queueFailedThreshold: { min: 0, max: 10_000 },
    queueBacklogThreshold: { min: 0, max: 1_000_000 },
    queueProbeTimeoutMs: { min: 100, max: 30_000 },
  },
} as const;

const DEFAULT_ALLOWED_ASSETS = ['USDC', 'XLM', 'BTC', 'ETH'] as const;

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

/**
 * Parse a numeric env var with an explicit inclusive boundary.
 *
 * - Missing/empty values use `fallback`.
 * - Non-finite values (e.g. `NaN`, `Infinity`) use `fallback`.
 * - Finite values are clamped into `[min, max]`.
 *
 * This is the only sanctioned way to read numeric config so that every
 * field shares identical boundary semantics.
 */
function parseBoundedNumber(
  value: string | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  return clamp(toNumber(value, fallback), min, max);
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

function parseAssets(value: string | undefined): string[] {
  if (!value) {
    return [...DEFAULT_ALLOWED_ASSETS];
  }

  const parsed = value
    .split(',')
    .map((item) => item.trim().toUpperCase())
    .filter(Boolean);

  // Deduplicate while preserving order to keep behavior deterministic.
  return Array.from(new Set(parsed));
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const port = parseBoundedNumber(
    env.PORT,
    3001,
    CONFIG_BOUNDS.port.min,
    CONFIG_BOUNDS.port.max,
  );
  const upstreamTimeoutMs = parseBoundedNumber(
    env.UPSTREAM_TIMEOUT_MS,
    1200,
    CONFIG_BOUNDS.upstreamTimeoutMs.min,
    CONFIG_BOUNDS.upstreamTimeoutMs.max,
  );
  const chaosProbability = parseBoundedNumber(
    env.CHAOS_PROBABILITY,
    0,
    CONFIG_BOUNDS.chaosProbability.min,
    CONFIG_BOUNDS.chaosProbability.max,
  );
  const idempotencyTtlMs = parseBoundedNumber(
    env.IDEMPOTENCY_TTL_MS,
    3_600_000,
    CONFIG_BOUNDS.idempotencyTtlMs.min,
    CONFIG_BOUNDS.idempotencyTtlMs.max,
  );

  return {
    port,
    gracefulDegradationEnabled: parseBoolean(env.GRACEFUL_DEGRADATION_ENABLED, true),
    upstreamContractsUrl,
    upstreamTimeoutMs,
    chaosMode: parseChaosMode(env.CHAOS_MODE),
    chaosTargets: parseTargets(env.CHAOS_TARGETS),
    chaosProbability,
    circuitBreaker: {
      failureThreshold: parseBoundedNumber(
        env.CB_FAILURE_THRESHOLD,
        5,
        CONFIG_BOUNDS.circuitBreaker.failureThreshold.min,
        CONFIG_BOUNDS.circuitBreaker.failureThreshold.max,
      ),
      successThreshold: parseBoundedNumber(
        env.CB_SUCCESS_THRESHOLD,
        1,
        CONFIG_BOUNDS.circuitBreaker.successThreshold.min,
        CONFIG_BOUNDS.circuitBreaker.successThreshold.max,
      ),
      timeoutMs: parseBoundedNumber(
        env.CB_TIMEOUT_MS,
        30_000,
        CONFIG_BOUNDS.circuitBreaker.timeoutMs.min,
        CONFIG_BOUNDS.circuitBreaker.timeoutMs.max,
      ),
    },
    webhookRetry: {
      maxAttempts: parseBoundedNumber(
        env.WEBHOOK_RETRY_MAX_ATTEMPTS,
        5,
        CONFIG_BOUNDS.webhookRetry.maxAttempts.min,
        CONFIG_BOUNDS.webhookRetry.maxAttempts.max,
      ),
      initialDelayMs: parseBoundedNumber(
        env.WEBHOOK_RETRY_INITIAL_DELAY_MS,
        1_000,
        CONFIG_BOUNDS.webhookRetry.initialDelayMs.min,
        CONFIG_BOUNDS.webhookRetry.initialDelayMs.max,
      ),
      maxDelayMs: parseBoundedNumber(
        env.WEBHOOK_RETRY_MAX_DELAY_MS,
        30_000,
        CONFIG_BOUNDS.webhookRetry.maxDelayMs.min,
        CONFIG_BOUNDS.webhookRetry.maxDelayMs.max,
      ),
      multiplier: parseBoundedNumber(
        env.WEBHOOK_RETRY_MULTIPLIER,
        2,
        CONFIG_BOUNDS.webhookRetry.multiplier.min,
        CONFIG_BOUNDS.webhookRetry.multiplier.max,
      ),
      jitterFactor: parseBoundedNumber(
        env.WEBHOOK_RETRY_JITTER_FACTOR,
        0.1,
        CONFIG_BOUNDS.webhookRetry.jitterFactor.min,
        CONFIG_BOUNDS.webhookRetry.jitterFactor.max,
      ),
    },
    webhookCircuitBreaker: {
      failureThreshold: parseBoundedNumber(
        env.WEBHOOK_CB_FAILURE_THRESHOLD,
        5,
        CONFIG_BOUNDS.webhookCircuitBreaker.failureThreshold.min,
        CONFIG_BOUNDS.webhookCircuitBreaker.failureThreshold.max,
      ),
      successThreshold: parseBoundedNumber(
        env.WEBHOOK_CB_SUCCESS_THRESHOLD,
        1,
        CONFIG_BOUNDS.webhookCircuitBreaker.successThreshold.min,
        CONFIG_BOUNDS.webhookCircuitBreaker.successThreshold.max,
      ),
      timeoutMs: parseBoundedNumber(
        env.WEBHOOK_CB_TIMEOUT_MS,
        60_000,
        CONFIG_BOUNDS.webhookCircuitBreaker.timeoutMs.min,
        CONFIG_BOUNDS.webhookCircuitBreaker.timeoutMs.max,
      ),
    },
    healthProbes: {
      queueFailedThreshold: parseBoundedNumber(
        env.QUEUE_FAILED_THRESHOLD,
        10,
        CONFIG_BOUNDS.healthProbes.queueFailedThreshold.min,
        CONFIG_BOUNDS.healthProbes.queueFailedThreshold.max,
      ),
      queueBacklogThreshold: parseBoundedNumber(
        env.QUEUE_BACKLOG_THRESHOLD,
        100,
        CONFIG_BOUNDS.healthProbes.queueBacklogThreshold.min,
        CONFIG_BOUNDS.healthProbes.queueBacklogThreshold.max,
      ),
      queueProbeTimeoutMs: parseBoundedNumber(
        env.QUEUE_PROBE_TIMEOUT_MS,
        3_000,
        CONFIG_BOUNDS.healthProbes.queueProbeTimeoutMs.min,
        CONFIG_BOUNDS.healthProbes.queueProbeTimeoutMs.max,
      ),
    },
    idempotencyTtlMs,
    allowedAssets: parseAssets(env.ALLOWED_ASSETS),
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

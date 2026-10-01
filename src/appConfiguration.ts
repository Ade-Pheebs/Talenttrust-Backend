import { isSafeUrl } from './utils/ssrf';
import { z } from 'zod';

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

/**
 * Validation boundaries for environment-driven configuration.
 *
 * Invariants enforced here:
 *  - Every numeric field is finite and within an explicit [min, max] range.
 *  - String enums are restricted to a known allow-list; unknown values are
 *    rejected rather than silently coerced, so misconfiguration is diagnosable.
 *  - List fields are bounded in size and element length to prevent unbounded
 *    memory growth or log-injection via crafted env values.
 *  - URLs are validated through `isSafeUrl` to preserve SSRF protections.
 *
 * Rejections throw `ConfigValidationError` with a redacted message: the field
 * name and reason are included, but raw values are never echoed (they may
 * contain secrets or internal hostnames).
 */
export class ConfigValidationError extends Error {
  public readonly field: string;
  public readonly reason: string;

  constructor(field: string, reason: string) {
    super(`Invalid configuration for "${field}": ${reason}`);
    this.name = 'ConfigValidationError';
    this.field = field;
    this.reason = reason;
  }
}

const MAX_LIST_ITEMS = 64;
const MAX_LIST_ITEM_LENGTH = 128;

const chaosModeSchema = z.enum(['off', 'error', 'timeout', 'random']);

const boundedInt = (min: number, max: number) =>
  z
    .number()
    .int()
    .min(min)
    .max(max);

const boundedNumber = (min: number, max: number) =>
  z
    .number()
    .min(min)
    .max(max);

const boundedStringList = z
  .array(z.string().min(1).max(MAX_LIST_ITEM_LENGTH))
  .max(MAX_LIST_ITEMS);

const circuitBreakerSchema = z.object({
  failureThreshold: boundedInt(1, 100),
  successThreshold: boundedInt(1, 20),
  timeoutMs: boundedInt(1_000, 300_000),
});

const webhookRetrySchema = z
  .object({
    maxAttempts: boundedInt(1, 20),
    initialDelayMs: boundedInt(100, 60_000),
    maxDelayMs: boundedInt(1_000, 600_000),
    multiplier: boundedNumber(1, 10),
    jitterFactor: boundedNumber(0, 1),
  })
  .refine((v) => v.maxDelayMs >= v.initialDelayMs, {
    message: 'maxDelayMs must be >= initialDelayMs',
    path: ['maxDelayMs'],
  });

const healthProbesSchema = z.object({
  queueFailedThreshold: boundedInt(0, 10_000),
  queueBacklogThreshold: boundedInt(0, 1_000_000),
  queueProbeTimeoutMs: boundedInt(100, 30_000),
});

const appConfigSchema = z.object({
  port: boundedInt(1, 65535),
  gracefulDegradationEnabled: z.boolean(),
  upstreamContractsUrl: z
    .string()
    .min(1)
    .refine((url) => isSafeUrl(url), { message: 'SSRF protection blocked access to internal resource' }),
  upstreamTimeoutMs: boundedInt(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS),
  chaosMode: chaosModeSchema,
  chaosTargets: boundedStringList,
  chaosProbability: boundedNumber(0, 1),
  circuitBreaker: circuitBreakerSchema,
  webhookRetry: webhookRetrySchema,
  webhookCircuitBreaker: circuitBreakerSchema,
  healthProbes: healthProbesSchema,
  idempotencyTtlMs: boundedInt(0, 7 * 24 * 60 * 60 * 1000),
  allowedAssets: boundedStringList,
  milestonesEnabled: z.boolean(),
});

function assertValidConfig(config: AppConfig): AppConfig {
  const result = appConfigSchema.safeParse(config);
  if (!result.success) {
    const issue = result.error.issues[0];
    const field = issue.path.join('.') || 'config';
    throw new ConfigValidationError(field, issue.message);
  }
  return result.data;
}

function toNumber(value: string | undefined, fallback: number): number {
  if (!value?.trim()) {
    return fallback;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

// Ports and attempt/count thresholds must not reach callers as fractions.
// Keep the legacy fallback and inclusive clamp behavior for invalid numbers.
function toInteger(value: string | undefined, fallback: number): number {
  const parsed = toNumber(value, fallback);
  return Number.isInteger(parsed) ? parsed : fallback;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function parseChaosMode(value: string | undefined): ChaosMode {
  const mode = (value ?? 'off').toLowerCase();
  const parsed = chaosModeSchema.safeParse(mode);
  if (!parsed.success) {
    throw new ConfigValidationError('CHAOS_MODE', 'must be one of off, error, timeout, random');
  }
  return parsed.data;
}

function parseBoolean(value: string | undefined, fallback: boolean, key: string): boolean {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) {
    return fallback;
  }

  if (normalized === 'true' || normalized === '1') return true;
  if (normalized === 'false' || normalized === '0') return false;
  // A typo must not silently disable milestone validation or degradation.
  throw new Error(`Invalid ${key}: expected true, false, 1, or 0`);
}

function parseTargets(value: string | undefined): string[] {
  if (!value) {
    return [];
  }

  const items = value
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);

  if (items.length > MAX_LIST_ITEMS || items.some((item) => item.length > MAX_LIST_ITEM_LENGTH)) {
    throw new ConfigValidationError('CHAOS_TARGETS', 'exceeds allowed size or item length');
  }

  return items;
}

function _parseAssets(value: string | undefined): string[] {
  if (!value?.trim()) {
    return ['USDC', 'XLM', 'BTC', 'ETH']; // Default assets
  }

  const items = value
    .split(',')
    .map((item) => item.trim().toUpperCase())
    .filter(Boolean);

  if (items.length > MAX_LIST_ITEMS || items.some((item) => item.length > MAX_LIST_ITEM_LENGTH)) {
    throw new ConfigValidationError('ALLOWED_ASSETS', 'exceeds allowed size or item length');
  }

  return items;
}

function loadUpstreamContractsUrl(env: NodeJS.ProcessEnv): string {
  const url = env.UPSTREAM_CONTRACTS_URL ?? 'https://example.invalid/contracts';
  try {
    const protocol = new URL(url).protocol;
    // Check the supplied environment without ever changing process.env. This
    // keeps explicit config loads independent of global development bypasses.
    if ((protocol === 'http:' || protocol === 'https:') && isSafeUrl(url, env)) {
      return url;
    }
  } catch {
    // URLs and even malformed policy values may contain credentials. Do not
    // attach the underlying exception or echo either input in diagnostics.
  }
  throw new Error('Invalid UPSTREAM_CONTRACTS_URL: SSRF protection requires a permitted HTTP(S) URL');
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const port = clamp(toInteger(env.PORT, 3001), 1, 65535);
  const upstreamTimeoutMs = clamp(toNumber(env.UPSTREAM_TIMEOUT_MS, 1200), MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
  const chaosProbability = clamp(toNumber(env.CHAOS_PROBABILITY, 0), 0, 1);
  const idempotencyTtlMs = clamp(toNumber(env.IDEMPOTENCY_TTL_MS, 3_600_000), 0, 7 * 24 * 60 * 60 * 1000);

  const config: AppConfig = {
    port,
    gracefulDegradationEnabled: parseBoolean(env.GRACEFUL_DEGRADATION_ENABLED, true, 'GRACEFUL_DEGRADATION_ENABLED'),
    upstreamContractsUrl: loadUpstreamContractsUrl(env),
    upstreamTimeoutMs,
    chaosMode: parseChaosMode(env.CHAOS_MODE),
    chaosTargets: parseTargets(env.CHAOS_TARGETS),
    chaosProbability,
    circuitBreaker: {
      failureThreshold: clamp(toInteger(env.CB_FAILURE_THRESHOLD, 5), 1, 100),
      successThreshold: clamp(toInteger(env.CB_SUCCESS_THRESHOLD, 1), 1, 20),
      timeoutMs: clamp(toNumber(env.CB_TIMEOUT_MS, 30_000), 1_000, 300_000),
    },
    webhookRetry: {
      maxAttempts: clamp(toInteger(env.WEBHOOK_RETRY_MAX_ATTEMPTS, 5), 1, 20),
      initialDelayMs: clamp(toNumber(env.WEBHOOK_RETRY_INITIAL_DELAY_MS, 1_000), 100, 60_000),
      maxDelayMs: clamp(toNumber(env.WEBHOOK_RETRY_MAX_DELAY_MS, 30_000), 1_000, 600_000),
      multiplier: clamp(toNumber(env.WEBHOOK_RETRY_MULTIPLIER, 2), 1, 10),
      jitterFactor: clamp(toNumber(env.WEBHOOK_RETRY_JITTER_FACTOR, 0.1), 0, 1),
    },
    webhookCircuitBreaker: {
      failureThreshold: clamp(toInteger(env.WEBHOOK_CB_FAILURE_THRESHOLD, 5), 1, 100),
      successThreshold: clamp(toInteger(env.WEBHOOK_CB_SUCCESS_THRESHOLD, 1), 1, 20),
      timeoutMs: clamp(toNumber(env.WEBHOOK_CB_TIMEOUT_MS, 60_000), 1_000, 300_000),
    },
    healthProbes: {
      queueFailedThreshold: clamp(toInteger(env.QUEUE_FAILED_THRESHOLD, 10), 0, 10_000),
      queueBacklogThreshold: clamp(toInteger(env.QUEUE_BACKLOG_THRESHOLD, 100), 0, 1_000_000),
      queueProbeTimeoutMs: clamp(toNumber(env.QUEUE_PROBE_TIMEOUT_MS, 3_000), 100, 30_000),
    },
    idempotencyTtlMs,
    allowedAssets: _parseAssets(env.ALLOWED_ASSETS),
    milestonesEnabled: parseBoolean(env.MILESTONES_ENABLED, true, 'MILESTONES_ENABLED'),
  };

  return assertValidConfig(config);
}

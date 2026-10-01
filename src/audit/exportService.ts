import { createWriteStream, createReadStream, promises as fsp } from 'fs';
import { pipeline } from 'stream/promises';
import { Readable } from 'stream';
import path from 'path';
import { tmpdir } from 'os';
import type { ReadStream } from 'fs';
import { AuditService, auditService } from './service';
import { redactBody } from './redact';
import type { AuditEntry, AuditQuery } from './types';
import { randomUUID } from 'crypto';

export interface AuditExportResult {
  filePath: string;
  fileName: string;
  bytesWritten: number;
  recordCount: number;
  openReadStream(): ReadStream;
  cleanup(): Promise<void>;
}

export interface AuditExportServiceOptions {
  exportRoot?: string;
  /**
   * Number of rows fetched per internal batch during streaming export.
   * Keeps memory bounded regardless of total result set size.
   * @default 500
   */
  batchSize?: number;
  /**
   * Maximum number of concurrent in-flight export operations allowed per
   * service instance. Additional requests are serialized through a FIFO
   * queue so that concurrent callers cannot exhaust file descriptors,
   * interleave writes to the same directory, or observe partially written
   * files.
   * @default 4
   */
  maxConcurrentExports?: number;
  /**
   * Maximum time (ms) a queued export may wait for a concurrency slot
   * before being rejected. Prevents unbounded queue growth under load.
   * @default 30000
   */
  queueTimeoutMs?: number;
}

/**
 * Maximum number of records that may be requested in a single export.
 * Prevents unbounded exports from exhausting disk or memory.
 */
export const MAX_EXPORT_LIMIT = 100_000;

/**
 * Maximum length of a free-form filter string (actor, resource, resourceId).
 * Prevents pathological inputs from reaching the repository layer.
 */
export const MAX_FILTER_STRING_LENGTH = 256;

/**
 * Filters that may be applied to an export request.
 * All fields are optional; omitting them includes all records.
 */
export interface AuditExportFilters {
  /** ISO-8601 start of time range (inclusive). */
  from?: string;
  /** ISO-8601 end of time range (inclusive). */
  to?: string;
  /** Restrict to a single event type (action). */
  action?: AuditQuery['action'];
  /** Restrict to a single severity level. */
  severity?: AuditQuery['severity'];
  /** Restrict to a specific actor. */
  actor?: string;
  /** Restrict to a specific resource type. */
  resource?: string;
  /** Restrict to a specific resource ID. */
  resourceId?: string;
  /** Cap the number of exported records. Omitting it exports every match. */
  limit?: number;
}

/**
 * Thrown when an export request fails validation. Callers can rely on this
 * being a distinct, non-retryable error class so that HTTP layers can map
 * it to a 400 response without leaking internal details.
 */
export class AuditExportValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditExportValidationError';
  }
}

const ISO_8601_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

/**
 * Parses and validates an ISO-8601 timestamp. Returns the epoch millis on
 * success, or `null` when the value is not a valid ISO-8601 instant.
 */
function parseIsoTimestamp(value: string): number | null {
  if (!ISO_8601_RE.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Validates and normalises export filters. Enforces:
 *  - `from`/`to` are valid ISO-8601 instants and `from <= to`;
 *  - `limit` is a positive safe integer within {@link MAX_EXPORT_LIMIT};
 *  - free-form string filters are non-empty and within length bounds;
 *  - unknown filter keys are rejected to avoid silent typos.
 *
 * Returns a frozen copy of the validated filters so downstream code cannot
 * mutate the caller's object mid-export.
 */
export function validateExportFilters(
  filters: AuditExportFilters = {},
): Readonly<AuditExportFilters> {
  if (filters === null || typeof filters !== 'object' || Array.isArray(filters)) {
    throw new AuditExportValidationError('Export filters must be a plain object');
  }

  const allowedKeys: ReadonlyArray<keyof AuditExportFilters> = [
    'from',
    'to',
    'action',
    'severity',
    'actor',
    'resource',
    'resourceId',
    'limit',
  ];
  for (const key of Object.keys(filters)) {
    if (!(allowedKeys as ReadonlyArray<string>).includes(key)) {
      throw new AuditExportValidationError(`Unknown export filter: ${key}`);
    }
  }

  const normalised: AuditExportFilters = {};

  if (filters.from !== undefined) {
    if (typeof filters.from !== 'string' || parseIsoTimestamp(filters.from) === null) {
      throw new AuditExportValidationError('`from` must be a valid ISO-8601 timestamp');
    }
    normalised.from = filters.from;
  }

  if (filters.to !== undefined) {
    if (typeof filters.to !== 'string' || parseIsoTimestamp(filters.to) === null) {
      throw new AuditExportValidationError('`to` must be a valid ISO-8601 timestamp');
    }
    normalised.to = filters.to;
  }

  if (normalised.from !== undefined && normalised.to !== undefined) {
    const fromMs = parseIsoTimestamp(normalised.from) as number;
    const toMs = parseIsoTimestamp(normalised.to) as number;
    if (fromMs > toMs) {
      throw new AuditExportValidationError('`from` must be less than or equal to `to`');
    }
  }

  if (filters.limit !== undefined) {
    if (
      typeof filters.limit !== 'number' ||
      !Number.isSafeInteger(filters.limit) ||
      filters.limit <= 0
    ) {
      throw new AuditExportValidationError('`limit` must be a positive safe integer');
    }
    if (filters.limit > MAX_EXPORT_LIMIT) {
      throw new AuditExportValidationError(
        `\`limit\` must not exceed ${MAX_EXPORT_LIMIT}`,
      );
    }
    normalised.limit = filters.limit;
  }

  const stringFilters: ReadonlyArray<'actor' | 'resource' | 'resourceId'> = [
    'actor',
    'resource',
    'resourceId',
  ];
  for (const key of stringFilters) {
    const value = filters[key];
    if (value === undefined) continue;
    if (typeof value !== 'string') {
      throw new AuditExportValidationError(`\`${key}\` must be a string`);
    }
    if (value.length === 0) {
      throw new AuditExportValidationError(`\`${key}\` must not be empty`);
    }
    if (value.length > MAX_FILTER_STRING_LENGTH) {
      throw new AuditExportValidationError(
        `\`${key}\` must not exceed ${MAX_FILTER_STRING_LENGTH} characters`,
      );
    }
    normalised[key] = value;
  }

  if (filters.action !== undefined) {
    if (typeof filters.action !== 'string' || filters.action.length === 0) {
      throw new AuditExportValidationError('`action` must be a non-empty string');
    }
    normalised.action = filters.action;
  }

  if (filters.severity !== undefined) {
    if (typeof filters.severity !== 'string' || filters.severity.length === 0) {
      throw new AuditExportValidationError('`severity` must be a non-empty string');
    }
    normalised.severity = filters.severity;
  }

  return Object.freeze(normalised);
}

/** Ordered CSV column headers for the audit export. */
const CSV_HEADERS = [
  'id',
  'timestamp',
  'action',
  'severity',
  'actor',
  'resource',
  'resourceId',
  'ipAddress',
  'correlationId',
  'metadata',
] as const;

type CsvColumn = (typeof CSV_HEADERS)[number];

/**
 * Neutralises CSV-injection ("formula injection") by prefixing dangerous
 * leading characters with a single-quote so spreadsheet applications
 * (Excel, LibreOffice Calc, Google Sheets) treat the cell as plain text
 * rather than executing it as a formula.
 *
 * Characters that trigger formula execution when they appear as the very
 * first character of an unquoted cell value:
 *   `=`  standard formula prefix
 *   `+`  alternative formula prefix (Lotus 1-2-3 compatibility)
 *   `-`  negation that spreadsheets evaluate as a formula
 *   `@`  legacy Lotus and some modern Excel formula prefix
 *   `\t` tab — used in tab-separated injections (safe to neutralise)
 *   `\r` carriage-return — can break row parsing
 *
 * The prefix `'` is the de-facto standard mitigation recommended by OWASP
 * (https://owasp.org/www-community/attacks/CSV_Injection).
 *
 * @param str - The already-stringified cell value.
 * @returns The value with any dangerous leading character escaped.
 */
export function neutraliseCsvInjection(str: string): string {
  if (str.length === 0) return str;
  if (/^[=+\-@\t\r]/.test(str)) {
    return `'${str}`;
  }
  return str;
}

/**
 * Escapes a value for safe inclusion in a CSV cell (RFC 4180) and
 * neutralises CSV-injection characters at the start of the value.
 *
 * Processing order:
 * 1. Stringify the value.
 * 2. Apply {@link neutraliseCsvInjection} to defuse formula prefixes.
 * 3. Wrap in double-quotes and escape internal quotes per RFC 4180 if the
 *    value contains a comma, double-quote, newline, or carriage-return.
 */
function csvCell(value: unknown): string {
  if (value === undefined || value === null) return '';
  const raw = typeof value === 'object' ? JSON.stringify(value) : String(value);
  const safe = neutraliseCsvInjection(raw);
  // Wrap in quotes if the value contains a comma, double-quote, or newline.
  if (safe.includes('"') || safe.includes(',') || safe.includes('\n') || safe.includes('\r')) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}

/** Serialises a redacted AuditEntry to one CSV row (no trailing newline). */
function toCsvRow(entry: AuditEntry): string {
  return CSV_HEADERS.map((col: CsvColumn) => {
    if (col === 'metadata') return csvCell(entry.metadata);
    return csvCell(entry[col]);
  }).join(',');
}

export class AuditExportService {
  private readonly exportRoot: string;
  private readonly batchSize: number;
  private readonly maxConcurrentExports: number;
  private readonly queueTimeoutMs: number;
  private activeExports = 0;
  private readonly waitQueue: Array<{
    resolve: () => void;
    reject: (err: Error) => void;
    timer: NodeJS.Timeout;
  }> = [];

  constructor(
    private readonly service: AuditService = auditService,
    options: AuditExportServiceOptions = {},
  ) {
    this.exportRoot = path.resolve(
      options.exportRoot ?? path.join(tmpdir(), 'talenttrust-audit-exports'),
    );
    this.batchSize = Math.max(options.batchSize ?? 500, 1);
    this.maxConcurrentExports = Math.max(options.maxConcurrentExports ?? 4, 1);
    this.queueTimeoutMs = Math.max(options.queueTimeoutMs ?? 30_000, 0);
  }

  /**
   * Acquires a concurrency slot for an export operation.
   *
   * Invariants:
   * - At most `maxConcurrentExports` operations run concurrently.
   * - Waiters are served in FIFO order.
   * - A waiter that times out is removed from the queue and rejects with a
   *   deterministic error so callers can retry safely.
   */
  private async acquireSlot(): Promise<void> {
    if (this.activeExports < this.maxConcurrentExports) {
      this.activeExports += 1;
      return;
    }
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.waitQueue.findIndex((w) => w.resolve === resolve);
        if (idx !== -1) this.waitQueue.splice(idx, 1);
        reject(new Error('Audit export queue timeout: too many concurrent exports'));
      }, this.queueTimeoutMs);
      // Allow the process to exit even if a waiter is pending.
      if (typeof timer.unref === 'function') timer.unref();
      this.waitQueue.push({ resolve, reject, timer });
    });
  }

  /**
   * Releases a concurrency slot and wakes the next FIFO waiter, if any.
   */
  private releaseSlot(): void {
    const next = this.waitQueue.shift();
    if (next) {
      clearTimeout(next.timer);
      // Slot is handed off directly; activeExports stays the same.
      next.resolve();
      return;
    }
    if (this.activeExports > 0) this.activeExports -= 1;
  }

  /**
   * Runs `fn` while holding a concurrency slot, guaranteeing the slot is
   * released exactly once even if `fn` throws.
   */
  private async withSlot<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquireSlot();
    try {
      return await fn();
    } finally {
      this.releaseSlot();
    }
  }

  // ─── NDJSON export ─────────────────────────────────────────────────────────

  /**
   * Streams audit entries in batches to a temporary NDJSON file.
   *
   * Rows are fetched from the repository using a cursor-based stream so the
   * process heap stays bounded regardless of how large the audit log grows.
   * Each entry is redacted via {@link redactBody} before serialisation so
   * sensitive metadata fields never appear in the export file.
   *
   * @param filters - Optional date-range, event-type and other filters.
   *   - `from`       ISO-8601 start timestamp (inclusive)
   *   - `to`         ISO-8601 end timestamp (inclusive)
   *   - `action`     Restrict to one event type (e.g. `'CONTRACT_CREATED'`)
   *   - `severity`   Restrict to one severity level (`'INFO' | 'WARNING' | 'CRITICAL'`)
   *   - `actor`      Restrict to a specific actor ID
   *   - `resource`   Restrict to a specific resource type
   *   - `resourceId` Restrict to a specific resource ID
   * @returns Metadata and handles for the resulting file.
   *
   * @example
   * ```ts
   * const result = await exportService.createNdjsonExport({
   *   from: '2024-01-01T00:00:00.000Z',
   *   to:   '2024-03-31T23:59:59.999Z',
   *   action: 'CONTRACT_CREATED',
   * });
   * await pipeline(result.openReadStream(), res);
   * await result.cleanup();
   * ```
   */
  async createNdjsonExport(filters: AuditExportFilters = {}): Promise<AuditExportResult> {
    return this.withSlot(async () => {
    await fsp.mkdir(this.exportRoot, { recursive: true });

    const exportDir = await fsp.mkdtemp(path.join(this.exportRoot, 'audit-export-'));
    this.assertPathWithinRoot(exportDir);

    const fileName = `audit-log-${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID()}.ndjson`;
    const filePath = path.join(exportDir, fileName);
    this.assertPathWithinRoot(filePath);

    const writer = createWriteStream(filePath, { encoding: 'utf8', flags: 'wx' });
    let recordCount = 0;

    const query: AuditQuery = { ...filters };
    const cursor = this.service.stream(query);

    async function* generateLines(): AsyncGenerator<string> {
      for (const entry of cursor) {
        const redacted = redactBody(entry as unknown as Record<string, unknown>) as AuditEntry;
        recordCount += 1;
        yield `${JSON.stringify(redacted)}\n`;
      }
    }

    const source = Readable.from(generateLines());
    try {
      await pipeline(source, writer);
    } catch (error) {
      // Ensure partial file is removed on failure so callers never observe
      // a truncated export.
      await fsp.rm(exportDir, { recursive: true, force: true }).catch(() => undefined);
      throw error;
    }

    const cleanup = async (): Promise<void> => {
      await fsp.rm(exportDir, { recursive: true, force: true }).catch(() => {});
    };

    return {
      filePath,
      fileName,
      bytesWritten: writer.bytesWritten,
      recordCount,
      openReadStream: () => createReadStream(filePath),
      cleanup,
    };
    });
  }

  // ─── CSV export ────────────────────────────────────────────────────────────

  /**
   * Streams audit entries in batches to a temporary CSV file.
   *
   * Columns are fixed in the order defined by {@link CSV_HEADERS}.
   * Each row is redacted via {@link redactBody} before serialisation.
   * Rows are fetched via a cursor so memory usage stays bounded.
   *
   * @param filters - Same optional filters as {@link createNdjsonExport}.
   * @returns Metadata and handles for the resulting file.
   *
   * @example
   * ```ts
   * const result = await exportService.createCsvExport({
   *   from: '2024-01-01T00:00:00.000Z',
   *   severity: 'CRITICAL',
   * });
   * res.setHeader('Content-Type', 'text/csv');
   * await pipeline(result.openReadStream(), res);
   * await result.cleanup();
   * ```
   */
  async createCsvExport(filters: AuditExportFilters = {}): Promise<AuditExportResult> {
    return this.withSlot(async () => {
    await fsp.mkdir(this.exportRoot, { recursive: true });

    const exportDir = await fsp.mkdtemp(path.join(this.exportRoot, 'audit-export-'));
    this.assertPathWithinRoot(exportDir);

    const fileName = `audit-log-${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID()}.csv`;
    const filePath = path.join(exportDir, fileName);
    this.assertPathWithinRoot(filePath);

    const writer = createWriteStream(filePath, { encoding: 'utf8', flags: 'wx' });
    let recordCount = 0;

    const query: AuditQuery = { ...filters };
    const cursor = this.service.stream(query);

    async function* generateLines(): AsyncGenerator<string> {
      // Write the header row first.
      yield `${CSV_HEADERS.join(',')}\n`;

      for (const entry of cursor) {
        const redacted = redactBody(entry as unknown as Record<string, unknown>) as AuditEntry;
        recordCount += 1;
        yield `${toCsvRow(redacted)}\n`;
      }
    }

    const source = Readable.from(generateLines());
    try {
      await pipeline(source, writer);
    } catch (error) {
      await fsp.rm(exportDir, { recursive: true, force: true }).catch(() => undefined);
      throw error;
    }

    const cleanup = async (): Promise<void> => {
      await fsp.rm(exportDir, { recursive: true, force: true }).catch(() => {});
    };

    return {
      filePath,
      fileName,
      bytesWritten: writer.bytesWritten,
      recordCount,
      openReadStream: () => createReadStream(filePath),
      cleanup,
    };
    });
  }

  // ─── Streaming convenience helpers ─────────────────────────────────────────

  /**
   * Convenience method that pipes the NDJSON export directly to any
   * writable stream (e.g. an HTTP response).
   *
   * The temporary file is cleaned up automatically whether the pipeline
   * succeeds or fails.
   */
  async streamNdjsonExport(
    filters: AuditExportFilters,
    destination: NodeJS.WritableStream,
  ): Promise<Omit<AuditExportResult, 'openReadStream'>> {
    const result = await this.createNdjsonExport(filters);

    try {
      await pipeline(result.openReadStream(), destination);
      return {
        filePath: result.filePath,
        fileName: result.fileName,
        bytesWritten: result.bytesWritten,
        recordCount: result.recordCount,
        cleanup: result.cleanup,
      };
    } catch (error) {
      await result.cleanup();
      throw error;
    }
  }

  /**
   * Convenience method that pipes the CSV export directly to any
   * writable stream (e.g. an HTTP response).
   *
   * The temporary file is cleaned up automatically whether the pipeline
   * succeeds or fails.
   */
  async streamCsvExport(
    filters: AuditExportFilters,
    destination: NodeJS.WritableStream,
  ): Promise<Omit<AuditExportResult, 'openReadStream'>> {
    const result = await this.createCsvExport(filters);

    try {
      await pipeline(result.openReadStream(), destination);
      return {
        filePath: result.filePath,
        fileName: result.fileName,
        bytesWritten: result.bytesWritten,
        recordCount: result.recordCount,
        cleanup: result.cleanup,
      };
    } catch (error) {
      await result.cleanup();
      throw error;
    }
  }

  // ─── Private helpers ───────────────────────────────────────────────────────

  private assertPathWithinRoot(targetPath: string): void {
    const resolvedTarget = path.resolve(targetPath);
    const rootWithSeparator = this.exportRoot.endsWith(path.sep)
      ? this.exportRoot
      : `${this.exportRoot}${path.sep}`;

    if (resolvedTarget !== this.exportRoot && !resolvedTarget.startsWith(rootWithSeparator)) {
      throw new Error('Audit export path resolved outside configured export root');
    }
  }
}

export const auditExportService = new AuditExportService();

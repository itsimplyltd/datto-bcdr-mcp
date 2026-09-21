/**
 * Datto BCDR REST transport.
 *
 * Replaces `@wyre-technology/node-datto-bcdr` (removed from this fork — see
 * package.json / README history). That library constructed six of its ten
 * API paths wrong (404s measured against the live API on 2026-09-21:
 * .../offsite, .../asset/{v}/backup, .../asset/{v}/screenshot, and
 * .../asset/{v}/screenshot/{epoch} do not exist), and its `HttpClient` and
 * `RateLimiter` are not exported at runtime, so there was no way to reuse
 * its transport for the corrected paths without running two independent
 * rate limiters against one 120-req/60s budget. This file is the whole
 * transport: auth, rate limiting, retry, and the corrected calls.
 *
 * Auth is HTTP Basic (public key as username, secret as password) — the
 * upstream library's own .d.ts comments claim an "X-Datto-API-Key header +
 * HMAC-SHA256 signature" scheme, but that is stale documentation; the
 * implementation it shipped really does send Basic, and that's what's kept
 * here.
 */

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export const DEFAULT_API_URL = "https://api.datto.com/v1";

export interface DattoBcdrConfig {
  apiKey: string;
  apiSecretKey: string;
  apiUrl?: string;
}

interface ResolvedDattoBcdrConfig {
  apiKey: string;
  apiSecretKey: string;
  apiUrl: string;
}

function resolveConfig(config: DattoBcdrConfig): ResolvedDattoBcdrConfig {
  return {
    apiKey: config.apiKey,
    apiSecretKey: config.apiSecretKey,
    apiUrl: (config.apiUrl ?? DEFAULT_API_URL).replace(/\/+$/, ""),
  };
}

// ---------------------------------------------------------------------------
// Errors — same names as the upstream library so error messages surfaced to
// tool callers don't regress just because the dependency is gone.
// ---------------------------------------------------------------------------

export class DattoBcdrError extends Error {
  readonly statusCode: number;
  readonly response: unknown;
  constructor(message: string, statusCode = 0, response?: unknown) {
    super(message);
    this.name = "DattoBcdrError";
    this.statusCode = statusCode;
    this.response = response;
    Object.setPrototypeOf(this, DattoBcdrError.prototype);
  }
}

export class DattoBcdrAuthenticationError extends DattoBcdrError {
  constructor(message: string, statusCode = 401, response?: unknown) {
    super(message, statusCode, response);
    this.name = "DattoBcdrAuthenticationError";
    Object.setPrototypeOf(this, DattoBcdrAuthenticationError.prototype);
  }
}

export class DattoBcdrForbiddenError extends DattoBcdrError {
  constructor(message: string, response?: unknown) {
    super(message, 403, response);
    this.name = "DattoBcdrForbiddenError";
    Object.setPrototypeOf(this, DattoBcdrForbiddenError.prototype);
  }
}

export class DattoBcdrNotFoundError extends DattoBcdrError {
  constructor(message: string, response?: unknown) {
    super(message, 404, response);
    this.name = "DattoBcdrNotFoundError";
    Object.setPrototypeOf(this, DattoBcdrNotFoundError.prototype);
  }
}

export class DattoBcdrRateLimitError extends DattoBcdrError {
  /** Suggested retry delay in milliseconds (parsed from Retry-After). */
  readonly retryAfter: number;
  constructor(message: string, retryAfter = 5000, response?: unknown) {
    super(message, 429, response);
    this.name = "DattoBcdrRateLimitError";
    this.retryAfter = retryAfter;
    Object.setPrototypeOf(this, DattoBcdrRateLimitError.prototype);
  }
}

export class DattoBcdrServerError extends DattoBcdrError {
  constructor(message: string, statusCode = 500, response?: unknown) {
    super(message, statusCode, response);
    this.name = "DattoBcdrServerError";
    Object.setPrototypeOf(this, DattoBcdrServerError.prototype);
  }
}

// ---------------------------------------------------------------------------
// Rate limiting — one module-level limiter, not one per client instance.
// Datto enforces ~120 requests/60s per partner key; these are the upstream
// library's own defaults. A rolling window is enough here (no need for the
// upstream library's extra pre-emptive throttle-threshold slowdown) because
// waitForSlot() is awaited before every single request this module makes,
// including the per-device fan-out in listAlerts().
// ---------------------------------------------------------------------------

const RATE_LIMIT_MAX_REQUESTS = 120;
const RATE_LIMIT_WINDOW_MS = 60_000;

class RollingWindowRateLimiter {
  private readonly timestamps: number[] = [];
  constructor(
    private readonly maxRequests: number,
    private readonly windowMs: number
  ) {}

  async waitForSlot(): Promise<void> {
    this.prune();
    if (this.timestamps.length >= this.maxRequests) {
      const oldest = this.timestamps[0];
      const waitMs = (oldest ?? Date.now()) + this.windowMs - Date.now();
      if (waitMs > 0) await sleep(waitMs);
      this.prune();
    }
    this.timestamps.push(Date.now());
  }

  private prune(): void {
    const cutoff = Date.now() - this.windowMs;
    while (this.timestamps.length > 0 && this.timestamps[0]! <= cutoff) {
      this.timestamps.shift();
    }
  }
}

const rateLimiter = new RollingWindowRateLimiter(RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS);

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// HTTP layer — retry on 429/5xx with exponential backoff capped at 30s,
// honouring Retry-After when Datto sends one.
// ---------------------------------------------------------------------------

const MAX_RETRIES = 3;
const MAX_BACKOFF_MS = 30_000;
const BASE_BACKOFF_MS = 1_000;

function backoffDelayMs(attempt: number, retryAfterSeconds?: number): number {
  if (retryAfterSeconds != null && Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) {
    return Math.min(retryAfterSeconds * 1000, MAX_BACKOFF_MS);
  }
  return Math.min(BASE_BACKOFF_MS * 2 ** attempt, MAX_BACKOFF_MS);
}

function authHeader(config: ResolvedDattoBcdrConfig): string {
  const token = Buffer.from(`${config.apiKey}:${config.apiSecretKey}`).toString("base64");
  return `Basic ${token}`;
}

type QueryParams = Record<string, string | number | undefined>;

function buildUrl(config: ResolvedDattoBcdrConfig, path: string, params?: QueryParams): string {
  const url = new URL(`${config.apiUrl}${path}`);
  if (params) {
    for (const key of Object.keys(params).sort()) {
      const value = params[key];
      if (value === undefined) continue;
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

async function readErrorBody(response: Response): Promise<unknown> {
  try {
    return await response.clone().json();
  } catch {
    try {
      return await response.text();
    } catch {
      return undefined;
    }
  }
}

/**
 * Send a GET request, retrying on 429/5xx, and return the raw `Response`
 * once it's `ok`. Throws one of the typed errors above for anything else
 * (including a 429/5xx that exhausted its retries).
 */
async function sendWithRetry(
  config: ResolvedDattoBcdrConfig,
  path: string,
  params: QueryParams | undefined,
  binary: boolean,
  attempt: number
): Promise<Response> {
  await rateLimiter.waitForSlot();
  const url = buildUrl(config, path, params);
  const response = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: authHeader(config),
      Accept: binary ? "image/jpeg, image/png, application/octet-stream, */*" : "application/json",
    },
  });

  if (response.ok) return response;

  if (response.status === 401) {
    throw new DattoBcdrAuthenticationError("Authentication failed", 401, await readErrorBody(response));
  }
  if (response.status === 403) {
    throw new DattoBcdrForbiddenError("Access forbidden", await readErrorBody(response));
  }
  if (response.status === 404) {
    throw new DattoBcdrNotFoundError("Resource not found", await readErrorBody(response));
  }
  if (response.status === 429) {
    const retryAfterHeader = response.headers.get("retry-after");
    const retryAfterSeconds =
      retryAfterHeader != null && retryAfterHeader !== "" ? parseInt(retryAfterHeader, 10) : undefined;
    if (attempt < MAX_RETRIES) {
      await sleep(backoffDelayMs(attempt, retryAfterSeconds));
      return sendWithRetry(config, path, params, binary, attempt + 1);
    }
    throw new DattoBcdrRateLimitError(
      "Rate limit exceeded and max retries reached",
      (retryAfterSeconds ?? 5) * 1000,
      await readErrorBody(response)
    );
  }
  if (response.status >= 500) {
    if (attempt < MAX_RETRIES) {
      await sleep(backoffDelayMs(attempt));
      return sendWithRetry(config, path, params, binary, attempt + 1);
    }
    throw new DattoBcdrServerError(
      `Server error: ${response.status} ${response.statusText}`,
      response.status,
      await readErrorBody(response)
    );
  }

  throw new DattoBcdrError(
    `Request failed: ${response.status} ${response.statusText}`,
    response.status,
    await readErrorBody(response)
  );
}

async function get<T>(config: ResolvedDattoBcdrConfig, path: string, params?: QueryParams): Promise<T> {
  const response = await sendWithRetry(config, path, params, false, 0);
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) return (await response.json()) as T;
  const text = await response.text();
  return (text === "" ? {} : text) as T;
}

async function getBinary(
  config: ResolvedDattoBcdrConfig,
  path: string
): Promise<{ buffer: Buffer; contentType: string }> {
  const response = await sendWithRetry(config, path, undefined, true, 0);
  const contentType = response.headers.get("content-type") ?? "application/octet-stream";
  const buffer = Buffer.from(await response.arrayBuffer());
  return { buffer, contentType };
}

// ---------------------------------------------------------------------------
// Response shapes — verified against the live API on 2026-09-21. The BCDR
// API may return additional fields not modeled here; every type below keeps
// an index signature so an unmodeled field still passes through JSON.
// ---------------------------------------------------------------------------

export interface BcdrPagination {
  page: number;
  perPage: number;
  totalPages: number;
  count: number;
}

export interface BcdrPaginatedResponse<T> {
  pagination: BcdrPagination;
  items: T[];
}

export interface BcdrDevice {
  serialNumber: string;
  name?: string;
  /**
   * NOT in the measured field list for /bcdr/device — only `name` was
   * observed. Kept optional here only because device-card.ts (predates this
   * fork's measurements) reads `hostname` for the MCP Apps card title; see
   * this task's report for why that's flagged rather than silently
   * rewritten.
   */
  hostname?: string;
  region?: string;
  model?: string;
  lastSeenDate?: number;
  hidden?: boolean;
  activeTickets?: number;
  servicePlan?: string;
  registrationDate?: number;
  servicePeriod?: string;
  warrantyExpire?: number;
  localStorageUsed?: number;
  localStorageAvailable?: number;
  offsiteStorageUsed?: number;
  totalManagedDisk?: number;
  protectedSpace?: number;
  internalIP?: string;
  resellerCompanyName?: string;
  clientCompanyName?: string;
  organizationName?: string;
  organizationId?: number | string;
  agentCount?: number;
  shareCount?: number;
  alertCount?: number;
  uptime?: number;
  remoteWebUrl?: string;
  agents?: unknown[];
  shares?: unknown[];
  alerts?: unknown[];
  [key: string]: unknown;
}

export interface BcdrBackupEntry {
  timestamp: string;
  backup: {
    status?: string;
    errorMessage?: string | null;
    totalUsedStorage?: number;
    [key: string]: unknown;
  };
  localVerification: {
    status?: string;
    errors: unknown[];
    [key: string]: unknown;
  };
  advancedVerification: {
    screenshotVerification: unknown;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface BcdrAsset {
  name?: string;
  assetId?: string;
  volId?: string;
  /** The path segment used to address this asset — a 32-char hex GUID. */
  volume: string;
  localIp?: string;
  os?: string;
  protectedVolumesCount?: number;
  unprotectedVolumesCount?: number;
  protectedVolumeNames?: string[];
  unprotectedVolumeNames?: string[];
  agentVersion?: string;
  isPaused?: boolean;
  isArchived?: boolean;
  latestOffsite?: number | null;
  localSnapshots?: unknown;
  lastSnapshot?: unknown;
  lastScreenshotAttempt?: string | number | null;
  lastScreenshotAttemptStatus?: string | null;
  lastScreenshotUrl?: string | null;
  fqdn?: string;
  type?: string;
  backups?: BcdrBackupEntry[];
  protectedMachine?: unknown;
  [key: string]: unknown;
}

export interface BcdrAlert {
  type?: string;
  threshold?: number;
  unit?: string;
  dateTriggered?: string;
  dateSent?: string;
  serialNumber?: string;
  [key: string]: unknown;
}

export interface BcdrActivityLogEntry {
  id?: string;
  timestamp?: string;
  requestId?: string;
  targetType?: string;
  targetId?: string;
  targetDisplayName?: string;
  clientName?: string;
  interface?: string;
  user?: string;
  userRoles?: string[];
  ipAddress?: string;
  action?: string;
  messageEN?: string;
  success?: boolean;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Pure helpers — exported for unit testing without hitting the network.
// ---------------------------------------------------------------------------

/**
 * `/bcdr/device/{s}/asset` does NOT return the `{pagination, items}` shape
 * the other list endpoints use — it returns a bare object keyed by
 * stringified index, e.g. `{"0": {...}, "1": {...}}`. The upstream
 * library's `PaginatedIterable` did `response.items ?? []` against this
 * shape, which is always `undefined` here, so `datto_bcdr_list_assets`
 * silently reported zero assets for every device that had any — a
 * confident empty answer. `Object.values()` reads the same data regardless
 * of what the numeric-looking keys are called, and there is no pagination
 * on this endpoint to walk.
 */
export function normalizeIndexKeyedAssets(response: unknown): BcdrAsset[] {
  if (response == null || typeof response !== "object") return [];
  return Object.values(response as Record<string, unknown>) as BcdrAsset[];
}

/**
 * `/bcdr/device/{s}/asset/{volume}` returns an array filtered down to the
 * matching volume, not a single object, even though at most one asset can
 * match a given volume GUID. An empty array means the volume doesn't exist
 * on this device.
 */
export function unwrapAssetArray(response: unknown, volume: string): BcdrAsset {
  const items = Array.isArray(response) ? response : [];
  const first = items[0];
  if (!first) {
    throw new DattoBcdrNotFoundError(`No asset found for volume ${volume}`);
  }
  return first as BcdrAsset;
}

export const SINCE_DAYS_MIN = 1;
export const SINCE_DAYS_MAX = 30;

/**
 * `/report/activity-log` accepts exactly one filter, `since`, matched
 * server-side against `^\d+$` and documented as "an integer greater than 0
 * and less than 31 days" — i.e. a lookback window in days, not a date.
 * There is no `until`. Validate here so a bad value fails with a clear
 * message instead of Datto's error text (or, with no `since` sent at all,
 * a silent `count: 0`).
 */
export function isValidSinceDays(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= SINCE_DAYS_MIN &&
    value <= SINCE_DAYS_MAX
  );
}

// ---------------------------------------------------------------------------
// Pagination — mirrors the upstream library's PaginatedIterable logic for
// the three endpoints that actually paginate (/bcdr/device,
// /bcdr/device/{s}/alert, /report/activity-log).
// ---------------------------------------------------------------------------

export interface PageParams {
  page?: number;
  perPage?: number;
}

function pageQuery(params?: PageParams): QueryParams {
  return { _page: params?.page, _perPage: params?.perPage };
}

async function* paginate<T>(
  config: ResolvedDattoBcdrConfig,
  path: string,
  params?: PageParams,
  extraParams?: QueryParams
): AsyncGenerator<T> {
  let page = params?.page ?? 1;
  const perPage = params?.perPage ?? 50;
  while (true) {
    const response = await get<BcdrPaginatedResponse<T>>(config, path, {
      ...extraParams,
      _page: page,
      _perPage: perPage,
    });
    const items = response.items ?? [];
    for (const item of items) yield item;
    const totalPages = response.pagination?.totalPages ?? page;
    if (items.length === 0 || page >= totalPages) return;
    page += 1;
  }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

function devicePath(serialNumber: string): string {
  return `/bcdr/device/${encodeURIComponent(serialNumber)}`;
}

function assetPath(serialNumber: string, volume: string): string {
  return `${devicePath(serialNumber)}/asset/${encodeURIComponent(volume)}`;
}

export class DattoBcdrClient {
  private readonly config: ResolvedDattoBcdrConfig;

  constructor(config: DattoBcdrConfig) {
    this.config = resolveConfig(config);
  }

  async listDevices(params?: PageParams): Promise<BcdrPaginatedResponse<BcdrDevice>> {
    return get(this.config, "/bcdr/device", pageQuery(params));
  }

  async getDevice(serialNumber: string): Promise<BcdrDevice> {
    return get(this.config, devicePath(serialNumber));
  }

  async listAssets(serialNumber: string): Promise<BcdrAsset[]> {
    const raw = await get<Record<string, BcdrAsset>>(this.config, `${devicePath(serialNumber)}/asset`);
    return normalizeIndexKeyedAssets(raw);
  }

  async getAsset(serialNumber: string, volume: string): Promise<BcdrAsset> {
    const raw = await get<BcdrAsset[]>(this.config, assetPath(serialNumber, volume));
    return unwrapAssetArray(raw, volume);
  }

  async getScreenshot(serialNumber: string, volume: string): Promise<{ buffer: Buffer; contentType: string }> {
    return getBinary(this.config, `${assetPath(serialNumber, volume)}/screenshot/latest`);
  }

  /**
   * Fan out across every appliance (or just `serialNumber` when given),
   * fully paging each device's alerts and stamping the source serial
   * number onto every alert — Datto has no portal-wide alerts endpoint, so
   * this is the only way to get a fleet-wide view.
   */
  async *listAlerts(params?: PageParams & { serialNumber?: string }): AsyncGenerator<BcdrAlert> {
    const { serialNumber, ...page } = params ?? {};
    if (serialNumber) {
      for await (const alert of paginate<BcdrAlert>(this.config, `${devicePath(serialNumber)}/alert`, page)) {
        yield { ...alert, serialNumber };
      }
      return;
    }
    for await (const device of paginate<BcdrDevice>(this.config, "/bcdr/device")) {
      if (!device.serialNumber) continue;
      for await (const alert of paginate<BcdrAlert>(
        this.config,
        `${devicePath(device.serialNumber)}/alert`,
        page
      )) {
        yield { ...alert, serialNumber: device.serialNumber };
      }
    }
  }

  async listActivity(
    sinceDays: number,
    params?: PageParams
  ): Promise<BcdrPaginatedResponse<BcdrActivityLogEntry>> {
    return get(this.config, "/report/activity-log", { ...pageQuery(params), since: String(sinceDays) });
  }
}

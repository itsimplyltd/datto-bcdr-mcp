/**
 * MCP server factory for the Datto BCDR MCP server.
 *
 * Builds a fresh Server instance per call (required for stateless HTTP
 * mode) with the full tool ladder, plus the MCP Apps (SEP-1865) surface:
 * a ui:// device card resource and a normalized `_card` payload attached
 * to datto_bcdr_get_device results.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { DattoBcdrClient, type BcdrAsset, isValidSinceDays, SINCE_DAYS_MIN, SINCE_DAYS_MAX } from "./datto-api.js";
import { elicitSelection, elicitText } from "./utils/elicitation.js";
import { wrapUntrustedContent } from "./utils/untrusted-content.js";
import {
  DEVICE_CARD_META,
  DEVICE_CARD_RESOURCE_URI,
  MCP_APP_RESOURCE_MIME,
  applyBrandInjection,
  brandFromEnv,
  buildDeviceCard,
  type DeviceCard,
} from "./device-card.js";
import { DEVICE_CARD_HTML } from "./generated/device-card-html.js";

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

export interface DattoBcdrCredentials {
  publicKey: string;
  privateKey: string;
}

function getCredentials(): DattoBcdrCredentials | null {
  const publicKey = process.env.DATTO_BCDR_PUBLIC_KEY;
  const privateKey = process.env.DATTO_BCDR_PRIVATE_KEY;
  if (!publicKey || !privateKey) return null;
  return { publicKey, privateKey };
}

function createClient(creds: DattoBcdrCredentials): DattoBcdrClient {
  // The Datto BCDR API uses "public/private key" in its docs but the wire
  // auth (HTTP Basic) is keyed apiKey/apiSecretKey. Translate at the
  // boundary so user-facing credential labels stay consistent with Datto's.
  return new DattoBcdrClient({
    apiKey: creds.publicKey,
    apiSecretKey: creds.privateKey,
  });
}

// ---------------------------------------------------------------------------
// Server factory — fresh server per request (stateless HTTP mode)
// ---------------------------------------------------------------------------

export function createMcpServer(credentialOverrides?: DattoBcdrCredentials): Server {
  const server = new Server(
    {
      name: "datto-bcdr-mcp",
      version: "0.0.0",
    },
    {
      capabilities: {
        tools: {},
        resources: {},
      },
    }
  );

  // The caller owns binding this server into server-ref.ts's scope now
  // (bindServerRef for stdio's single session, runWithServerRef wrapping
  // the whole per-request chain for HTTP) — createMcpServer() stays
  // side-effect-free with respect to server-ref.

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: "datto_bcdr_list_devices",
          description: "List all SIRIS/Alto BCDR appliances in the partner portal.",
          inputSchema: {
            type: "object",
            properties: {
              page: { type: "number", description: "Page number (default: 1)", default: 1 },
              perPage: { type: "number", description: "Results per page (default: 250)", default: 250 },
            },
          },
        },
        {
          name: "datto_bcdr_get_device",
          description: "Get details for a specific BCDR appliance by serial number.",
          _meta: DEVICE_CARD_META,
          inputSchema: {
            type: "object",
            properties: {
              serialNumber: { type: "string", description: "The appliance serial number" },
            },
            required: ["serialNumber"],
          },
        },
        {
          name: "datto_bcdr_list_assets",
          description:
            "List protected agents (assets) on a BCDR appliance. If serialNumber is omitted, the user will be prompted to choose or enter one.",
          inputSchema: {
            type: "object",
            properties: {
              serialNumber: { type: "string", description: "Appliance serial number (optional — will elicit if omitted)" },
            },
          },
        },
        {
          name: "datto_bcdr_get_asset",
          description:
            "Get details for a specific protected agent (asset) on an appliance, identified by its `volume` " +
            "(the asset's 32-character hex GUID, not a friendly name). `agentId` is accepted as a deprecated " +
            "alias for `volume`.",
          inputSchema: {
            type: "object",
            properties: {
              serialNumber: { type: "string", description: "Appliance serial number" },
              volume: { type: "string", description: "Asset volume GUID (32-char hex)" },
              agentId: { type: "string", description: "Deprecated alias for `volume`" },
            },
            required: ["serialNumber"],
          },
        },
        {
          name: "datto_bcdr_list_backups",
          description:
            "List recovery points / backups for a protected agent, identified by `volume` (deprecated alias: " +
            "`agentId`). Datto has no dedicated backups endpoint — this returns the `backups` array already " +
            "embedded in the asset record.",
          inputSchema: {
            type: "object",
            properties: {
              serialNumber: { type: "string", description: "Appliance serial number" },
              volume: { type: "string", description: "Asset volume GUID (32-char hex)" },
              agentId: { type: "string", description: "Deprecated alias for `volume`" },
            },
            required: ["serialNumber"],
          },
        },
        {
          name: "datto_bcdr_list_screenshots",
          description:
            "Get screenshot verification history for a protected agent, identified by `volume` (deprecated " +
            "alias: `agentId`). This is verification history read off the asset record (last attempt status, " +
            "last screenshot URL, and per-backup advanced-verification results) — Datto has no separate " +
            "screenshot archive endpoint to list from.",
          inputSchema: {
            type: "object",
            properties: {
              serialNumber: { type: "string", description: "Appliance serial number" },
              volume: { type: "string", description: "Asset volume GUID (32-char hex)" },
              agentId: { type: "string", description: "Deprecated alias for `volume`" },
            },
            required: ["serialNumber"],
          },
        },
        {
          name: "datto_bcdr_get_screenshot",
          description:
            "Fetch the latest screenshot verification image (JPEG) for a protected agent, identified by " +
            "`volume` (deprecated alias: `agentId`). Only the latest screenshot is available — Datto's API has " +
            "no endpoint for a historical screenshot by epoch, so there is no way to ask for one.",
          inputSchema: {
            type: "object",
            properties: {
              serialNumber: { type: "string", description: "Appliance serial number" },
              volume: { type: "string", description: "Asset volume GUID (32-char hex)" },
              agentId: { type: "string", description: "Deprecated alias for `volume`" },
            },
            required: ["serialNumber"],
          },
        },
        {
          name: "datto_bcdr_get_offsite_status",
          description:
            "Get off-site sync status for an appliance. Datto has no dedicated offsite-status endpoint — this " +
            "composes the device's storage totals with each protected asset's `latestOffsite` timestamp. An " +
            "asset with no offsite point recorded is reported as such explicitly, never as 0 or an error.",
          inputSchema: {
            type: "object",
            properties: {
              serialNumber: { type: "string", description: "Appliance serial number" },
            },
            required: ["serialNumber"],
          },
        },
        {
          name: "datto_bcdr_list_alerts",
          description:
            "List BCDR alerts. Alerts are per-appliance — omit `serialNumber` to fan out and query every " +
            "appliance in the portal (the useful default, but one round trip per appliance), or pass it to " +
            "query a single device. If date range is omitted, the user will be prompted to choose a window.",
          inputSchema: {
            type: "object",
            properties: {
              serialNumber: {
                type: "string",
                description: "Restrict to a single appliance (optional — omit to query every appliance)",
              },
              since: { type: "string", description: "ISO 8601 start datetime (optional)" },
              until: { type: "string", description: "ISO 8601 end datetime (optional)" },
              page: { type: "number", description: "Page number (default: 1)", default: 1 },
              perPage: { type: "number", description: "Results per page (default: 250)", default: 250 },
            },
          },
        },
        {
          name: "datto_bcdr_list_activity",
          description:
            `List activity log entries from the last \`sinceDays\` days (integer, ${SINCE_DAYS_MIN}-${SINCE_DAYS_MAX}, ` +
            "default 7 — this is Datto's only filter on this endpoint, a lookback window in days, not a date; " +
            "there is no `until`).",
          inputSchema: {
            type: "object",
            properties: {
              sinceDays: {
                type: "number",
                description: `Days to look back (${SINCE_DAYS_MIN}-${SINCE_DAYS_MAX}, default 7)`,
                default: 7,
              },
              page: { type: "number", description: "Page number (default: 1)", default: 1 },
              perPage: { type: "number", description: "Results per page (default: 250)", default: 250 },
            },
          },
        },
      ],
    };
  });

  // -------------------------------------------------------------------------
  // MCP Apps (SEP-1865): the ui:// device card is static HTML embedded at
  // build time (src/generated/device-card-html.ts), so it serves identically
  // from stdio and Node HTTP transports.
  // -------------------------------------------------------------------------

  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
      resources: [
        {
          uri: DEVICE_CARD_RESOURCE_URI,
          name: "Datto BCDR Device Card",
          description:
            "Interactive MCP Apps card rendering a Datto BCDR appliance's backup status",
          mimeType: MCP_APP_RESOURCE_MIME,
        },
      ],
    };
  });

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;
    if (uri !== DEVICE_CARD_RESOURCE_URI) {
      throw new Error(`Unknown resource: ${uri}`);
    }
    return {
      contents: [
        {
          uri,
          mimeType: MCP_APP_RESOURCE_MIME,
          // The card ships neutral; operators brand it at serve time via
          // MCP_BRAND_* env vars (no vars = HTML served unchanged).
          text: applyBrandInjection(DEVICE_CARD_HTML, brandFromEnv()),
        },
      ],
    };
  });

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  function errorResult(message: string): CallToolResult {
    return { content: [{ type: "text", text: `Error: ${message}` }], isError: true };
  }

  function jsonResult(payload: unknown): CallToolResult {
    return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
  }

  // Hard cap to keep one tool call from streaming the entire alert history
  // when the user picks "no filter" — a busy partner can have thousands of
  // alerts once fanned out across every appliance.
  const DATE_FILTER_PAGE_CAP = 2000;

  interface DateRangeMs {
    sinceMs?: number;
    untilMs?: number;
  }

  // Datto inconsistently uses ms vs seconds for timestamps; anything below
  // ~1e12 we treat as seconds.
  function normalizeTs(raw: number): number {
    return raw < 1e12 ? raw * 1000 : raw;
  }

  interface PaginatedIterableLike<T> {
    [Symbol.asyncIterator](): AsyncIterator<T>;
  }

  // Datto BCDR's alert endpoint doesn't accept date query params, so we
  // paginate via the client's async generator and filter per-item. Stops
  // early when the cap is hit so a "no filter" call doesn't enumerate
  // forever. NOTE: measured alert items carry only dateTriggered/dateSent,
  // not createdAt/timestamp, so this filter is currently a no-op against
  // real alert data — see this task's report.
  async function collectWithDateFilter<T extends Record<string, unknown>>(
    iterable: PaginatedIterableLike<T>,
    range: DateRangeMs
  ): Promise<T[]> {
    const sinceMs = range.sinceMs ?? -Infinity;
    const untilMs = range.untilMs ?? Infinity;
    const out: T[] = [];
    for await (const item of iterable) {
      const raw = item.createdAt ?? item.timestamp;
      if (typeof raw === "number") {
        const ts = normalizeTs(raw);
        if (ts < sinceMs || ts > untilMs) continue;
      }
      out.push(item);
      if (out.length >= DATE_FILTER_PAGE_CAP) break;
    }
    return out;
  }

  async function resolveDateRange(
    args: { since?: string; until?: string }
  ): Promise<DateRangeMs> {
    if (args.since || args.until) {
      return {
        sinceMs: args.since ? new Date(args.since).getTime() : undefined,
        untilMs: args.until ? new Date(args.until).getTime() : undefined,
      };
    }

    const choice = await elicitSelection(
      "No date range provided. This query can return many results. Choose a window:",
      "range",
      [
        { value: "24h", label: "Last 24 hours" },
        { value: "7d", label: "Last 7 days" },
        { value: "30d", label: "Last 30 days" },
        { value: "custom", label: "Enter custom ISO 8601 dates" },
        { value: "all", label: "No filter (return everything)" },
      ]
    );

    const nowMs = Date.now();
    const PRESET_WINDOWS_MS: Record<string, number> = {
      "24h": 24 * 60 * 60 * 1000,
      "7d": 7 * 24 * 60 * 60 * 1000,
      "30d": 30 * 24 * 60 * 60 * 1000,
    };
    if (!choice || choice === "all") return {};
    if (choice in PRESET_WINDOWS_MS) {
      return { sinceMs: nowMs - PRESET_WINDOWS_MS[choice] };
    }
    if (choice === "custom") {
      const since = await elicitText(
        "Enter the start datetime in ISO 8601 format (e.g. 2025-04-01T00:00:00Z).",
        "since",
        "Start datetime"
      );
      const until = await elicitText(
        "Enter the end datetime in ISO 8601 format (leave blank for now).",
        "until",
        "End datetime"
      );
      return {
        sinceMs: since ? new Date(since).getTime() : undefined,
        untilMs: until ? new Date(until).getTime() : undefined,
      };
    }
    return {};
  }

  async function resolveSerialNumber(
    client: DattoBcdrClient,
    provided?: string
  ): Promise<string | null> {
    if (provided) return provided;

    const choice = await elicitSelection(
      "No appliance serial number provided. How would you like to choose one?",
      "selection",
      [
        { value: "__list__", label: "Pick from a list of appliances" },
        { value: "__enter__", label: "Enter a serial number manually" },
      ]
    );

    if (choice === "__enter__") {
      const sn = await elicitText(
        "Enter the appliance serial number.",
        "serialNumber",
        "BCDR appliance serial number"
      );
      return sn || null;
    }

    if (choice === "__list__") {
      try {
        const devices = await client.listDevices({ page: 1, perPage: 50 });
        const items = devices.items ?? [];
        if (items.length === 0) return null;

        const options = items.slice(0, 25).map((d) => ({
          value: d.serialNumber,
          label: `${d.serialNumber}${d.hostname ? ` — ${d.hostname}` : d.name ? ` — ${d.name}` : ""}`,
        }));
        const picked = await elicitSelection(
          "Select an appliance:",
          "serialNumber",
          options
        );
        return picked;
      } catch {
        return null;
      }
    }

    return null;
  }

  /** `volume` is the current parameter name; `agentId` is accepted as a deprecated alias. */
  function resolveVolume(args: { volume?: string; agentId?: string }): string | undefined {
    return args.volume ?? args.agentId;
  }

  // -------------------------------------------------------------------------
  // Tool call handler
  // -------------------------------------------------------------------------

  async function handleToolCall(name: string, args: Record<string, unknown> | undefined): Promise<CallToolResult> {
    const creds = credentialOverrides ?? getCredentials();

    if (!creds) {
      return errorResult(
        "No API credentials provided. Please configure DATTO_BCDR_PUBLIC_KEY and DATTO_BCDR_PRIVATE_KEY environment variables (or pass them as gateway headers)."
      );
    }

    const client = createClient(creds);

    try {
      switch (name) {
        case "datto_bcdr_list_devices": {
          const params = (args ?? {}) as { page?: number; perPage?: number };
          const result = await client.listDevices({
            page: params.page ?? 1,
            perPage: params.perPage ?? 250,
          });
          return jsonResult(result);
        }

        case "datto_bcdr_get_device": {
          const { serialNumber } = args as { serialNumber: string };
          const device = await client.getDevice(serialNumber);
          // MCP Apps: attach the normalized payload the ui:// device card
          // renders from. Best-effort — a null card just means no UI surface.
          let card: DeviceCard | null = null;
          try {
            card = buildDeviceCard(device);
          } catch {
            // Card building must never break the tool result.
          }
          const payload = card ? { ...device, _card: card } : device;
          return jsonResult(payload ?? {});
        }

        case "datto_bcdr_list_assets": {
          const params = (args ?? {}) as { serialNumber?: string };
          const sn = await resolveSerialNumber(client, params.serialNumber);
          if (!sn) return errorResult("serialNumber is required.");
          const assets = await client.listAssets(sn);
          return jsonResult(assets);
        }

        case "datto_bcdr_get_asset": {
          const params = args as { serialNumber: string; volume?: string; agentId?: string };
          const volume = resolveVolume(params);
          if (!volume) return errorResult("volume is required.");
          const asset = await client.getAsset(params.serialNumber, volume);
          return jsonResult(asset);
        }

        case "datto_bcdr_list_backups": {
          const params = args as { serialNumber: string; volume?: string; agentId?: string };
          const volume = resolveVolume(params);
          if (!volume) return errorResult("volume is required.");
          const asset = await client.getAsset(params.serialNumber, volume);
          return jsonResult(asset.backups ?? []);
        }

        case "datto_bcdr_list_screenshots": {
          const params = args as { serialNumber: string; volume?: string; agentId?: string };
          const volume = resolveVolume(params);
          if (!volume) return errorResult("volume is required.");
          const asset: BcdrAsset = await client.getAsset(params.serialNumber, volume);
          const verification = {
            lastScreenshotAttempt: asset.lastScreenshotAttempt ?? null,
            lastScreenshotAttemptStatus: asset.lastScreenshotAttemptStatus ?? null,
            lastScreenshotUrl: asset.lastScreenshotUrl ?? null,
            // Per-backup verification history, not a separate screenshot archive.
            backupScreenshotVerifications: (asset.backups ?? []).map((backup) => ({
              timestamp: backup.timestamp,
              screenshotVerification: backup.advancedVerification?.screenshotVerification ?? null,
            })),
          };
          return jsonResult(verification);
        }

        case "datto_bcdr_get_screenshot": {
          const params = args as { serialNumber: string; volume?: string; agentId?: string };
          const volume = resolveVolume(params);
          if (!volume) return errorResult("volume is required.");
          const { buffer, contentType } = await client.getScreenshot(params.serialNumber, volume);
          return {
            content: [
              {
                type: "image",
                data: buffer.toString("base64"),
                mimeType: contentType || "image/jpeg",
              },
            ],
          };
        }

        case "datto_bcdr_get_offsite_status": {
          const { serialNumber } = args as { serialNumber: string };
          const [device, assets] = await Promise.all([
            client.getDevice(serialNumber),
            client.listAssets(serialNumber),
          ]);
          const status = {
            serialNumber,
            offsiteStorageUsed: device.offsiteStorageUsed ?? null,
            localStorageUsed: device.localStorageUsed ?? null,
            localStorageAvailable: device.localStorageAvailable ?? null,
            totalManagedDisk: device.totalManagedDisk ?? null,
            assets: assets.map((asset) => ({
              volume: asset.volume,
              name: asset.name ?? null,
              // null is a real, meaningful state here — "no offsite point
              // recorded" — never collapse it to 0 or report it as unknown.
              latestOffsite: asset.latestOffsite ?? null,
              latestOffsiteStatus:
                asset.latestOffsite == null ? "no offsite point recorded" : "offsite point recorded",
            })),
          };
          return jsonResult(status);
        }

        case "datto_bcdr_list_alerts": {
          const params = (args ?? {}) as {
            serialNumber?: string;
            since?: string;
            until?: string;
            page?: number;
            perPage?: number;
          };
          const range = await resolveDateRange({ since: params.since, until: params.until });
          const alerts = await collectWithDateFilter(
            client.listAlerts({ serialNumber: params.serialNumber, page: params.page, perPage: params.perPage }),
            range
          );
          return jsonResult(alerts);
        }

        case "datto_bcdr_list_activity": {
          const params = (args ?? {}) as { sinceDays?: number; page?: number; perPage?: number };
          const sinceDays = params.sinceDays ?? 7;
          if (!isValidSinceDays(sinceDays)) {
            return errorResult(
              `sinceDays must be an integer between ${SINCE_DAYS_MIN} and ${SINCE_DAYS_MAX}, got ${JSON.stringify(params.sinceDays)}.`
            );
          }
          const activity = await client.listActivity(sinceDays, { page: params.page, perPage: params.perPage });
          return jsonResult(activity);
        }

        default:
          return errorResult(`Unknown tool: ${name}`);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return errorResult(message);
    }
  }

  /**
   * Untrusted-content marking happens at this single outer choke point, not
   * sprinkled through individual cases — see utils/untrusted-content.ts.
   * Error responses and the binary image block (datto_bcdr_get_screenshot)
   * are never wrapped: errors carry no external content, and the wrapper
   * only knows how to annotate text.
   */
  function markUntrusted(name: string, result: CallToolResult): CallToolResult {
    if (result.isError) return result;
    return {
      ...result,
      content: result.content.map((item) =>
        item.type === "text" ? { ...item, text: wrapUntrustedContent(name, item.text) } : item
      ),
    };
  }

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    return markUntrusted(name, await handleToolCall(name, args));
  });

  return server;
}

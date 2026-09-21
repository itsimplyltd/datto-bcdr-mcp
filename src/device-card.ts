/**
 * Device-card payload builder for the MCP Apps (SEP-1865) UI surface.
 *
 * datto_bcdr_get_device results get a normalized `_card` object attached
 * (see mcp-server.ts) that the ui:// device card renders from. The card is
 * progressive enhancement: normalization is best-effort, and a null return
 * simply means the host renders no card while the JSON payload is unchanged.
 */

import type { BcdrDevice } from "./datto-api.js";

export const DEVICE_CARD_RESOURCE_URI = "ui://datto-bcdr/device-card.html";

/** MCP Apps resource MIME (RESOURCE_MIME_TYPE in @modelcontextprotocol/ext-apps). */
export const MCP_APP_RESOURCE_MIME = "text/html;profile=mcp-app";

/**
 * Tool `_meta` advertising the card. Carries both the canonical flat key
 * (RESOURCE_URI_META_KEY in ext-apps) and the nested form ext-apps'
 * registerAppTool emits, so any MCP Apps host revision finds it.
 */
export const DEVICE_CARD_META = {
  "ui/resourceUri": DEVICE_CARD_RESOURCE_URI,
  ui: { resourceUri: DEVICE_CARD_RESOURCE_URI },
} as const;

/** Mirror of DeviceCard in ui/device-card.ts — keep in sync. */
export interface DeviceCard {
  serialNumber: string;
  /** Display heading: hostname, falling back to model, then serial. */
  title: string;
  model?: string;
  client?: string;
  internalIp?: string;
  /** ISO 8601 — the card formats it locale-aware. */
  lastSeen?: string;
  /** ISO 8601 — the card formats it locale-aware. */
  registered?: string;
  /** Humanized, e.g. "12d 4h". */
  uptime?: string;
}

/** Brand overrides injected into the card as `window.__BRAND__`. */
export interface CardBrand {
  name?: string;
  logoUrl?: string;
  primaryColor?: string;
  accentColor?: string;
  bg?: string;
  text?: string;
}

/** The comment marker in ui/index.html that serve-time injection replaces. */
const BRAND_INJECT_MARKER = /<!-- BRAND_INJECT:[\s\S]*?-->/;

/**
 * Replace the card's BRAND_INJECT comment with a `window.__BRAND__` script.
 * The card ships neutral; this is the customization mechanism. An empty
 * brand returns the HTML unchanged. `<` is escaped so brand values can
 * never break out of the injected script tag.
 */
export function applyBrandInjection(html: string, brand: CardBrand): string {
  const entries = Object.entries(brand).filter(
    ([, value]) => typeof value === "string" && value !== ""
  );
  if (entries.length === 0) return html;
  const json = JSON.stringify(Object.fromEntries(entries)).replace(/</g, "\\u003c");
  return html.replace(BRAND_INJECT_MARKER, `<script>window.__BRAND__=${json}</script>`);
}

/**
 * Resolve brand overrides from MCP_BRAND_* environment variables. Returns
 * an empty brand (HTML served unchanged) when none are set, or on runtimes
 * without `process.env`.
 */
export function brandFromEnv(): CardBrand {
  if (typeof process === "undefined" || !process.env) return {};
  const env = process.env;
  const brand: CardBrand = {};
  if (env.MCP_BRAND_NAME) brand.name = env.MCP_BRAND_NAME;
  if (env.MCP_BRAND_LOGO_URL) brand.logoUrl = env.MCP_BRAND_LOGO_URL;
  if (env.MCP_BRAND_PRIMARY_COLOR) brand.primaryColor = env.MCP_BRAND_PRIMARY_COLOR;
  if (env.MCP_BRAND_ACCENT_COLOR) brand.accentColor = env.MCP_BRAND_ACCENT_COLOR;
  if (env.MCP_BRAND_BG) brand.bg = env.MCP_BRAND_BG;
  if (env.MCP_BRAND_TEXT) brand.text = env.MCP_BRAND_TEXT;
  return brand;
}

/**
 * Datto inconsistently uses ms vs seconds for timestamps; anything below
 * ~1e12 we treat as seconds (same normalization as the alert/activity
 * date filtering in mcp-server.ts).
 */
function toIso(raw: unknown): string | undefined {
  if (typeof raw !== "number" || !Number.isFinite(raw) || raw <= 0) return undefined;
  const date = new Date(raw < 1e12 ? raw * 1000 : raw);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

/** Humanize an uptime in seconds, e.g. 1050500 -> "12d 3h". */
function humanizeUptime(seconds: unknown): string | undefined {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) {
    return undefined;
  }
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

/**
 * Normalize an SDK BcdrDevice into the flat, label-resolved payload the
 * ui:// device card renders from. Fields are only emitted when present and
 * well-typed — a sparse device degrades the card rather than breaking it.
 */
export function buildDeviceCard(
  device: Partial<BcdrDevice> | null | undefined
): DeviceCard | null {
  if (!device || typeof device.serialNumber !== "string" || device.serialNumber === "") {
    return null;
  }

  const hostname = typeof device.hostname === "string" && device.hostname ? device.hostname : undefined;
  const model = typeof device.model === "string" && device.model ? device.model : undefined;

  const card: DeviceCard = {
    serialNumber: device.serialNumber,
    title: hostname ?? model ?? device.serialNumber,
  };

  if (model) card.model = model;
  if (typeof device.clientCompanyName === "string" && device.clientCompanyName) {
    card.client = device.clientCompanyName;
  }
  if (typeof device.internalIP === "string" && device.internalIP) {
    card.internalIp = device.internalIP;
  }
  const lastSeen = toIso(device.lastSeenDate);
  if (lastSeen) card.lastSeen = lastSeen;
  const registered = toIso(device.registrationDate);
  if (registered) card.registered = registered;
  const uptime = humanizeUptime(device.uptime);
  if (uptime) card.uptime = uptime;

  return card;
}

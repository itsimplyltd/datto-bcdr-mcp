/**
 * MCP Apps (SEP-1865) contract tests — mirrors the checks an MCP Apps host
 * performs to render the device card:
 *   1. the renderable tool advertises the UI resource via _meta
 *   2. the ui:// resource lists and reads back as profile=mcp-app HTML
 *   3. datto_bcdr_get_device results carry the normalized `_card` payload
 *      the iframe renders from
 *
 * Wire-level checks drive the real Server over a linked in-memory transport
 * pair (the same Server the stdio and HTTP transports connect in
 * production); buildDeviceCard is unit-tested directly.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../src/mcp-server.js";
import {
  applyBrandInjection,
  buildDeviceCard,
  DEVICE_CARD_RESOURCE_URI,
  MCP_APP_RESOURCE_MIME,
} from "../src/device-card.js";
import { DEVICE_CARD_HTML } from "../src/generated/device-card-html.js";

const mockDevicesGet = vi.fn();

// Partial mock: keep the real error classes / pure helpers (SINCE_DAYS_MIN
// etc. are read at ListTools time to build tool descriptions) and swap out
// only the class this test drives.
vi.mock("../src/datto-api.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/datto-api.js")>();
  return {
    ...actual,
    DattoBcdrClient: class {
      getDevice = mockDevicesGet;
    },
  };
});

const RENDERABLE_TOOLS = ["datto_bcdr_get_device"];

const CREDS = { publicKey: "public-key", privateKey: "private-key" };

const fullDevice = {
  serialNumber: "D0123456789",
  hostname: "SIRIS-DC01",
  internalIP: "10.0.10.5",
  model: "Siris 5 X1",
  clientCompanyName: "Contoso Ltd",
  lastSeenDate: 1752736800, // epoch seconds — builder must normalize to ms
  registrationDate: 1620000000,
  uptime: 1050000, // seconds -> "12d 3h"
};

async function connectClient(
  creds?: { publicKey: string; privateKey: string }
): Promise<Client> {
  const server = createMcpServer(creds);
  const client = new Client({ name: "test-host", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);
  return client;
}

describe("MCP Apps device card", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    mockDevicesGet.mockReset();
  });

  describe("tool _meta advertisement", () => {
    it.each(RENDERABLE_TOOLS)("%s links the card via _meta", async (name) => {
      const client = await connectClient();
      const { tools } = await client.listTools();
      const tool = tools.find((t) => t.name === name);
      expect(tool).toBeDefined();
      // Canonical flat key (ext-apps RESOURCE_URI_META_KEY) …
      expect(tool?._meta?.["ui/resourceUri"]).toBe(DEVICE_CARD_RESOURCE_URI);
      // … and the nested form registerAppTool also emits.
      expect((tool?._meta?.ui as { resourceUri?: string })?.resourceUri).toBe(
        DEVICE_CARD_RESOURCE_URI
      );
    });

    it("no other tools carry UI metadata", async () => {
      const client = await connectClient();
      const { tools } = await client.listTools();
      const others = tools.filter(
        (t) => t._meta && !RENDERABLE_TOOLS.includes(t.name)
      );
      expect(others).toEqual([]);
    });
  });

  describe("ui:// resource", () => {
    it("is listed with the MCP Apps MIME type", async () => {
      const client = await connectClient();
      const { resources } = await client.listResources();
      const card = resources.find((r) => r.uri === DEVICE_CARD_RESOURCE_URI);
      expect(card?.mimeType).toBe(MCP_APP_RESOURCE_MIME);
    });

    it("reads back as profile=mcp-app HTML containing the card app", async () => {
      const client = await connectClient();
      const { contents } = await client.readResource({
        uri: DEVICE_CARD_RESOURCE_URI,
      });
      const content = contents[0] as { mimeType?: string; text?: string };
      expect(content.mimeType).toBe(MCP_APP_RESOURCE_MIME);
      // No MCP_BRAND_* env set → the embedded HTML is served byte-identical.
      expect(content.text).toBe(DEVICE_CARD_HTML);
      expect(content.text).toContain("card__bar");
      expect(content.text).toContain("BRAND_INJECT");
      // The vite build must have inlined the bridge script — a bare <script src>
      // would be unloadable from a resources/read HTML string.
      expect(content.text).not.toContain('src="./device-card.ts"');
    });

    it("serves neutral defaults with no vendor identity or external fetches", async () => {
      const client = await connectClient();
      const { contents } = await client.readResource({
        uri: DEVICE_CARD_RESOURCE_URI,
      });
      const text = (contents[0] as { text?: string }).text ?? "";
      expect(text).not.toMatch(/WYRE/i);
      expect(text).not.toContain("00c9db"); // WYRE cyan
      expect(text).not.toContain("ede947"); // WYRE yellow
      expect(text).not.toContain("fonts.googleapis.com"); // no external fetches
      expect(text).toContain("#2563eb"); // neutral primary
    });

    it("injects MCP_BRAND_* env branding at serve time", async () => {
      vi.stubEnv("MCP_BRAND_NAME", "Acme MSP");
      vi.stubEnv("MCP_BRAND_PRIMARY_COLOR", "#ff0000");
      const client = await connectClient();
      const { contents } = await client.readResource({
        uri: DEVICE_CARD_RESOURCE_URI,
      });
      const text = (contents[0] as { text?: string }).text ?? "";
      expect(text).toContain(
        '<script>window.__BRAND__={"name":"Acme MSP","primaryColor":"#ff0000"}</script>'
      );
      expect(text).not.toContain("BRAND_INJECT");
    });

    it("rejects unknown resource URIs", async () => {
      const client = await connectClient();
      await expect(
        client.readResource({ uri: "ui://datto-bcdr/nope.html" })
      ).rejects.toThrow(/Unknown resource/);
    });
  });

  describe("datto_bcdr_get_device result", () => {
    it("carries the normalized _card payload alongside the raw device", async () => {
      mockDevicesGet.mockResolvedValue(fullDevice);
      const client = await connectClient(CREDS);
      const result = (await client.callTool({
        name: "datto_bcdr_get_device",
        arguments: { serialNumber: fullDevice.serialNumber },
      })) as { isError?: boolean; content: Array<{ type: string; text?: string }> };
      expect(result.isError).toBeFalsy();
      const payload = JSON.parse(result.content[0]?.text ?? "{}");
      expect(payload.serialNumber).toBe(fullDevice.serialNumber);
      expect(payload.hostname).toBe(fullDevice.hostname);
      expect(payload._card).toEqual({
        serialNumber: "D0123456789",
        title: "SIRIS-DC01",
        model: "Siris 5 X1",
        client: "Contoso Ltd",
        internalIp: "10.0.10.5",
        lastSeen: new Date(1752736800 * 1000).toISOString(),
        registered: new Date(1620000000 * 1000).toISOString(),
        uptime: "12d 3h",
      });
    });

    it("returns the raw payload without _card when normalization fails", async () => {
      mockDevicesGet.mockResolvedValue({ hostname: "no-serial" });
      const client = await connectClient(CREDS);
      const result = (await client.callTool({
        name: "datto_bcdr_get_device",
        arguments: { serialNumber: "whatever" },
      })) as { isError?: boolean; content: Array<{ type: string; text?: string }> };
      expect(result.isError).toBeFalsy();
      const payload = JSON.parse(result.content[0]?.text ?? "{}");
      expect(payload.hostname).toBe("no-serial");
      expect(payload._card).toBeUndefined();
    });
  });

  describe("applyBrandInjection", () => {
    it("replaces the BRAND_INJECT marker with a window.__BRAND__ script", () => {
      const out = applyBrandInjection(DEVICE_CARD_HTML, {
        name: "Acme MSP",
        primaryColor: "#ff0000",
      });
      expect(out).not.toContain("BRAND_INJECT");
      expect(out).toContain(
        'window.__BRAND__={"name":"Acme MSP","primaryColor":"#ff0000"}'
      );
    });

    it("escapes < so brand values cannot break out of the script tag", () => {
      const out = applyBrandInjection(DEVICE_CARD_HTML, {
        name: "</script><script>alert(1)",
      });
      expect(out).not.toContain("</script><script>alert(1)");
      expect(out).toContain("\\u003c/script");
    });

    it("returns the HTML byte-identical for an empty brand", () => {
      expect(applyBrandInjection(DEVICE_CARD_HTML, {})).toBe(DEVICE_CARD_HTML);
      expect(applyBrandInjection(DEVICE_CARD_HTML, { name: "" })).toBe(
        DEVICE_CARD_HTML
      );
    });
  });

  describe("buildDeviceCard", () => {
    it("normalizes a full device into flat label-resolved strings", () => {
      const card = buildDeviceCard(fullDevice);
      expect(card).toEqual({
        serialNumber: "D0123456789",
        title: "SIRIS-DC01",
        model: "Siris 5 X1",
        client: "Contoso Ltd",
        internalIp: "10.0.10.5",
        lastSeen: new Date(1752736800 * 1000).toISOString(),
        registered: new Date(1620000000 * 1000).toISOString(),
        uptime: "12d 3h",
      });
    });

    it("accepts millisecond timestamps without double-scaling", () => {
      const card = buildDeviceCard({
        serialNumber: "D1",
        lastSeenDate: 1752736800000,
      });
      expect(card?.lastSeen).toBe(new Date(1752736800000).toISOString());
    });

    it("falls back to model, then serial, for the title", () => {
      expect(buildDeviceCard({ serialNumber: "D1", model: "Alto 3" })?.title).toBe(
        "Alto 3"
      );
      expect(buildDeviceCard({ serialNumber: "D1" })?.title).toBe("D1");
    });

    it("humanizes sub-day uptimes", () => {
      expect(buildDeviceCard({ serialNumber: "D1", uptime: 7500 })?.uptime).toBe(
        "2h 5m"
      );
      expect(buildDeviceCard({ serialNumber: "D1", uptime: 240 })?.uptime).toBe(
        "4m"
      );
    });

    it("returns null for payloads that are not a device", () => {
      expect(buildDeviceCard(undefined)).toBeNull();
      expect(buildDeviceCard(null)).toBeNull();
      expect(buildDeviceCard({})).toBeNull();
      expect(buildDeviceCard({ serialNumber: "" })).toBeNull();
    });

    it("survives sparse devices (card is best-effort)", () => {
      const card = buildDeviceCard({ serialNumber: "D9", uptime: -5 });
      expect(card).toEqual({ serialNumber: "D9", title: "D9" });
    });
  });
});

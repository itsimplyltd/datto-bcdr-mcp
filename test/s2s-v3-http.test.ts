/**
 * S2S v3 phase A, through a real http.Server (src/http.ts). Signers are test helpers
 * ported from cred-router; nothing here touches the Datto API (tools/list only).
 */
import { afterEach, describe, expect, it } from 'vitest';
import { connect, type AddressInfo } from 'node:net';
import { request as httpRequest, type Server } from 'node:http';
import { createHttpServer, logS2sStartup, resolveS2sSecret, S2S_AUDIENCE, type HttpLogger } from '../src/http.js';
import { legacyHeader, v3Header } from './helpers/s2s-signers.js';

const SECRET = 'x'.repeat(40);
const PUB = 'x-datto-bcdr-public-key';
const PRIV = 'x-datto-bcdr-private-key';
const KEYS = { [PUB]: 'pub-test', [PRIV]: 'priv-test' };
const BODY = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
const MCP_HEADERS = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };

const silent: HttpLogger = { info() {}, warn() {}, error() {} };
const open: Server[] = [];

async function start(minVersion?: number): Promise<number> {
  const server = createHttpServer({ secret: SECRET, isGatewayMode: true, minVersion, logger: silent });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  open.push(server);
  return (server.address() as AddressInfo).port;
}

afterEach(async () => {
  for (const s of open.splice(0)) await new Promise<void>((r) => { s.closeAllConnections(); s.close(() => r()); });
});

function call(port: number, o: { method?: string; path?: string; headers?: Record<string, string>; body?: string }): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const rq = httpRequest({ host: '127.0.0.1', port, method: o.method ?? 'POST', path: o.path ?? '/mcp', headers: o.headers, agent: false }, (res) => {
      let b = '';
      res.on('data', (d) => (b += d));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: b }));
    });
    rq.on('error', reject);
    rq.end(o.body ?? '');
  });
}

/** A v3 request signing exactly `signed`, while sending `sent` (a superset models an unsigned header). */
function v3Req(signed: Record<string, string>, sent: Record<string, string> = signed) {
  return {
    headers: { ...MCP_HEADERS, ...sent, 'x-gateway-s2s': v3Header(SECRET, { aud: S2S_AUDIENCE, method: 'POST', path: '/mcp', body: BODY, headers: signed }) },
    body: BODY,
  };
}

describe('legacy header', () => {
  it('is accepted at the floor (min 1)', async () => {
    const port = await start(1);
    const r = await call(port, { headers: { ...MCP_HEADERS, ...KEYS, 'x-gateway-s2s': legacyHeader(SECRET) }, body: BODY });
    expect(r.status).toBe(200);
  });

  it('is refused when the minimum is 2 (v1 is below it)', async () => {
    const port = await start(2);
    const r = await call(port, { headers: { ...MCP_HEADERS, ...KEYS, 'x-gateway-s2s': legacyHeader(SECRET) }, body: BODY });
    expect(r.status).toBe(401);
  });

  it('is refused at min 3, while v3 is still accepted', async () => {
    const port = await start(3);
    const legacy = await call(port, { headers: { ...MCP_HEADERS, ...KEYS, 'x-gateway-s2s': legacyHeader(SECRET) }, body: BODY });
    expect(legacy.status).toBe(401);
    expect((await call(port, v3Req(KEYS))).status).toBe(200);
  });

  it('with the wrong secret is refused', async () => {
    const port = await start(1);
    const r = await call(port, { headers: { ...MCP_HEADERS, ...KEYS, 'x-gateway-s2s': legacyHeader('w'.repeat(40)) }, body: BODY });
    expect(r.status).toBe(401);
  });
});

describe('v3 header', () => {
  it('is accepted with both credential headers signed', async () => {
    const port = await start(1);
    expect((await call(port, v3Req(KEYS))).status).toBe(200);
  });

  it('is refused for a different audience', async () => {
    const port = await start(1);
    const headers = { ...MCP_HEADERS, ...KEYS, 'x-gateway-s2s': v3Header(SECRET, { aud: 'datto-saas', method: 'POST', path: '/mcp', body: BODY, headers: KEYS }) };
    expect((await call(port, { headers, body: BODY })).status).toBe(401);
  });

  for (const unsigned of [PUB, PRIV]) {
    it(`is refused, even in report mode (min 1), when ${unsigned} is present but not signed`, async () => {
      const port = await start(1);
      const signedOnly = Object.fromEntries(Object.entries(KEYS).filter(([k]) => k !== unsigned));
      expect((await call(port, v3Req(signedOnly, KEYS))).status).toBe(401);
    });
  }

  it('is refused at min 3 too when a required header is unsigned', async () => {
    const port = await start(3);
    expect((await call(port, v3Req({ [PUB]: 'pub-test' }, KEYS))).status).toBe(401);
  });

  it('honours the required headers when signed, and still demands credentials in gateway mode', async () => {
    const port = await start(1);
    expect((await call(port, v3Req(KEYS))).status).toBe(200);
    const noKeys = await call(port, v3Req({}));
    expect(noKeys.status).toBe(401);
    expect(noKeys.body).toContain('Missing credentials');
  });

  it('is refused when the body is altered after signing', async () => {
    const port = await start(1);
    const r = v3Req(KEYS);
    expect((await call(port, { ...r, body: BODY.replace('tools/list', 'tools/call') })).status).toBe(401);
  });
});

describe('routing and robustness', () => {
  it('answers 404 for an unknown path before any auth', async () => {
    const port = await start(1);
    expect((await call(port, { path: '/nope' })).status).toBe(404);
    expect((await call(port, { method: 'GET', path: '/mcp/extra' })).status).toBe(404);
  });

  it('keeps /health unauthenticated for the container probe', async () => {
    const port = await start(1);
    const r = await call(port, { method: 'GET', path: '/health' });
    expect(r.status).toBe(200);
    expect(JSON.parse(r.body).status).toBe('ok');
  });

  it('refuses /mcp with no S2S header', async () => {
    const port = await start(1);
    expect((await call(port, { headers: { ...MCP_HEADERS, ...KEYS }, body: BODY })).status).toBe(401);
  });

  it('survives a socket aborted mid-upload (health still answers)', async () => {
    const port = await start(1);
    const sock = connect(port, '127.0.0.1');
    await new Promise<void>((r) => sock.once('connect', () => r()));
    sock.write(`POST /mcp HTTP/1.1\r\nHost: x\r\nX-Gateway-S2S: ${legacyHeader(SECRET)}\r\nContent-Length: 1000\r\n\r\n0123456789`);
    await new Promise((r) => setTimeout(r, 100));
    sock.destroy();
    await new Promise((r) => setTimeout(r, 100));
    expect((await call(port, { method: 'GET', path: '/health' })).status).toBe(200);
  });
});

describe('boot', () => {
  it('logs the effective minimum and the header-rule mode', () => {
    const lines: { msg: string; meta?: Record<string, unknown> }[] = [];
    const logger: HttpLogger = { ...silent, info: (msg, meta) => lines.push({ msg, meta }) };
    logS2sStartup(1, logger);
    logS2sStartup(3, logger);
    logS2sStartup(Number.NaN, logger);
    expect(lines.map((l) => l.meta)).toEqual([
      { effectiveMinVersion: 1, headerRule: 'report' },
      { effectiveMinVersion: 3, headerRule: 'enforce' },
      { effectiveMinVersion: 3, headerRule: 'enforce' },
    ]);
  });

  it('refuses a missing or short secret and never echoes it', () => {
    expect(() => resolveS2sSecret({})).toThrow(/at least 32/);
    expect(() => resolveS2sSecret({ CONDUIT_S2S_SECRET: 'short-secret-value' })).toThrow(/at least 32/);
    try { resolveS2sSecret({ CONDUIT_S2S_SECRET: 'short-secret-value' }); } catch (e) { expect(String(e)).not.toContain('short-secret-value'); }
    expect(resolveS2sSecret({ CONDUIT_S2S_SECRET: SECRET })).toBe(SECRET);
  });
});

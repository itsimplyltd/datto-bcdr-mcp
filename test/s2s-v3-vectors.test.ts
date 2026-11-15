// Copyright IT Simply Ltd. Runs the shared vectors (s2s-v3-vectors.json) through the canonical verifier.
// Ported to vitest from the canonical node:test suite (MCP-Gateway s2s/s2s-v3.test.ts).

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { createServer, request as httpRequest } from 'node:http';
import type { IncomingMessage } from 'node:http';
import {
  NonceCache, RawBodyError, readRawBody, verifyV3, checkGatewayRequest, canonicalV3, parseV3Header,
  INGRESS_EXEMPT_HEADERS, assertRequireSignedHeaders, stripExemptHeaders, formatUnsignedHeaderReport, ReportRateLimiter, respondAndClose,
} from '../src/itsl/s2s-v3.js';

const vectors = JSON.parse(readFileSync(new URL('./fixtures/s2s-v3-vectors.json', import.meta.url), 'utf8'));
const secret: string = vectors.secret;

function args(c: any, cache: NonceCache) {
  return {
    method: c.method,
    rawTarget: c.rawTarget,
    body: Buffer.from(c.body, 'utf8'),
    rawHeaders: c.rawHeaders,
    secret: c.secretOverride ?? secret,
    aud: c.aud,
    nowSeconds: c.nowSeconds,
    nonceCache: cache,
    headerRuleMode: c.headerRuleMode,
  };
}

for (const c of vectors.positive) {
  test(`positive: ${c.name}`, () => {
    assert.deepEqual(verifyV3(args(c, new NonceCache())), { ok: true, version: 3 });
  });
  if (!c.derivedFrom) {
    test(`positive canonical string is pinned: ${c.name}`, () => {
      const parsed = parseV3Header(c.header)!;
      const headerHashes: Record<string, string> = {};
      for (const [k, v] of Object.entries(c.signedHeaders)) headerHashes[k] = createHash('sha256').update(v as string).digest('hex');
      const canonical = canonicalV3({
        t: parsed.tRaw, n: parsed.n, aud: c.aud, method: c.method, path: c.rawTarget,
        bodySha256: createHash('sha256').update(c.body).digest('hex'), sh: parsed.sh, headerHashes,
      });
      assert.equal(canonical, c.canonical);
      assert.ok(!canonical.endsWith('\n'));
      assert.equal(canonical.split('\n')[0], 'ITSL-S2S-v3');
    });
  }
}

for (const c of vectors.negative) {
  test(`negative: ${c.name} -> ${c.expect}`, () => {
    const cache = new NonceCache();
    if (c.replayOf) {
      const first = vectors.positive.find((p: any) => p.name === c.replayOf);
      assert.equal(verifyV3(args(first, cache)).ok, true);
    }
    const r = verifyV3(args(c, cache));
    assert.deepEqual(r, { ok: false, reason: c.expect });
  });
}

for (const c of vectors.check) {
  test(`checkGatewayRequest: ${c.name}`, () => {
    const r = checkGatewayRequest({
      ...args(c, new NonceCache()),
      floor: c.floor,
      minVersion: c.minVersion,
      verifyLegacy: () => c.legacyResult ?? 0,
    });
    assert.equal(r.ok, c.expect.ok);
    assert.equal(r.version, c.expect.version);
    if (!c.expect.ok) assert.equal(r.reason, c.expect.reason);
    assert.deepEqual(r.unsignedHeaderNames, c.expect.unsignedHeaderNames);
  });
}

for (const c of vectors.readRawBody) {
  test(`readRawBody: ${c.name}`, async () => {
    const req = Object.assign(Readable.from([Buffer.from(c.body)]), { headers: c.headers }) as unknown as IncomingMessage;
    if (c.expectStatus) {
      await assert.rejects(readRawBody(req), (e: any) => e instanceof RawBodyError && e.status === c.expectStatus);
    } else {
      assert.equal((await readRawBody(req)).toString(), c.body);
    }
  });
}

test('readRawBody: over the limit is a 413 whether declared or streamed', async () => {
  const declared = Object.assign(Readable.from([Buffer.alloc(10)]), { headers: { 'content-length': '10' } }) as unknown as IncomingMessage;
  await assert.rejects(readRawBody(declared, 5), (e: any) => e.status === 413);
  const streamed = Object.assign(Readable.from([Buffer.alloc(4), Buffer.alloc(4)]), { headers: {} }) as unknown as IncomingMessage;
  await assert.rejects(readRawBody(streamed, 5), (e: any) => e.status === 413);
});

test('nonce is recorded only after the HMAC verifies', () => {
  const cache = new NonceCache();
  const c = vectors.positive[1];
  const bad = { ...c, body: c.body + ' ' };
  assert.equal(verifyV3(args(bad, cache)).ok, false);
  assert.equal(cache.entries.size, 0);
  assert.equal(verifyV3(args(c, cache)).ok, true);
  assert.equal(cache.entries.size, 1);
});

test('nonce entry lives until its own t + 30 + 5 and then the same nonce is no longer a replay', () => {
  const cache = new NonceCache();
  const n = '0'.repeat(32);
  cache.add(n, 1000, 1000);
  assert.equal(cache.has(n, 1034), true);
  assert.equal(cache.has(n, 1035), false);
});

test('a full nonce cache refuses new requests (fails closed) but frees expired entries', () => {
  const cache = new NonceCache(2);
  const c = vectors.positive[0];
  cache.add('a'.repeat(32), c.t, c.t);
  cache.add('b'.repeat(32), c.t, c.t);
  assert.deepEqual(verifyV3(args(c, cache)), { ok: false, reason: 'nonce-cache-full' });
  // thirty-six seconds later the two entries have expired, so it admits again.
  assert.equal(verifyV3({ ...args(c, cache), nowSeconds: c.t + 30 }).ok, false); // still full at +30 (expires at +35)
  const later = new NonceCache(2);
  later.add('a'.repeat(32), c.t - 100, c.t);
  later.add('b'.repeat(32), c.t - 100, c.t);
  assert.equal(verifyV3(args(c, later)).ok, true);
});

test('the wrong secret never verifies', () => {
  const c = vectors.positive[0];
  assert.deepEqual(verifyV3({ ...args(c, new NonceCache()), secret: 'y'.repeat(40) }), { ok: false, reason: 'hmac' });
});


test('x-request-id present and unsigned verifies (every vector carries one), and is not in sh', () => {
  const c = vectors.positive[1];
  assert.ok(c.rawHeaders.some((h: string) => h.toLowerCase() === 'x-request-id'));
  assert.ok(!c.header.includes('x-request-id'));
  assert.deepEqual(verifyV3(args(c, new NonceCache())), { ok: true, version: 3 });
  assert.deepEqual(INGRESS_EXEMPT_HEADERS, ['x-request-id', 'x-arr-ssl', 'x-envoy-expected-rq-timeout-ms', 'x-envoy-external-address', 'x-forwarded-for', 'x-forwarded-path', 'x-forwarded-proto', 'x-k8se-app-kind', 'x-k8se-app-name', 'x-k8se-app-namespace', 'x-k8se-protocol', 'x-ms-containerapp-name', 'x-ms-containerapp-revision-name']);
});

test('a request refused by the header rule does not consume a nonce or a slot', () => {
  const cache = new NonceCache(1);
  const c = vectors.positive[1];
  const bad = { ...c, rawHeaders: [...c.rawHeaders, 'X-Api-Url', 'https://attacker.invalid'] };
  assert.deepEqual(verifyV3(args(bad, cache)), { ok: false, reason: 'unsigned-header' });
  assert.equal(cache.entries.size, 0);
  // the legitimate request with the same nonce still verifies, in a cache of ONE slot
  assert.equal(verifyV3(args(c, cache)).ok, true);
});

test('report mode accepts and consumes the nonce, listing names; exempt names are never listed', () => {
  const cache = new NonceCache();
  const c = vectors.positive[1];
  const r = verifyV3({ ...args(c, cache), headerRuleMode: 'report', rawHeaders: [...c.rawHeaders, 'X-Example-Unsigned', '1', 'X-Forwarded-For', '1.2.3.4'] });
  assert.deepEqual(r, { ok: true, version: 3, unsignedHeaderNames: ['x-example-unsigned'] });
  assert.equal(cache.entries.size, 1);
});

test('every exempt name: tolerated unsigned in enforce mode, refused inside sh, refused in requireSignedHeaders', () => {
  const c = vectors.positive[1];
  for (const name of INGRESS_EXEMPT_HEADERS) {
    // present and unsigned: the blanket rule (enforce mode) does not refuse it
    assert.deepEqual(verifyV3({ ...args(c, new NonceCache()), rawHeaders: [...c.rawHeaders.filter((_: string, i: number, a: string[]) => !(i % 2 === 0 && a[i].toLowerCase() === name) && !(i % 2 === 1 && a[i - 1].toLowerCase() === name)), name, 'v'] }), { ok: true, version: 3 }, name);
    // a signed copy (the name inside sh) is refused as sh-invalid
    const raw = c.rawHeaders.map((v: string, i: number, a: string[]) => (i % 2 === 1 && a[i - 1].toLowerCase() === 'x-gateway-s2s') ? v.replace(/,sh=[^,]*,/, `,sh=${name},`) : v);
    assert.deepEqual(verifyV3({ ...args(c, new NonceCache()), rawHeaders: raw }), { ok: false, reason: 'sh-invalid' }, name);
    // configuration may never require an exempt name to be signed
    assert.throws(() => assertRequireSignedHeaders([name]), undefined, name);
  }
});

test('stripExemptHeaders removes exempt names from headers and rawHeaders, case-insensitively, and nothing else', () => {
  const req = {
    headers: { host: 'h', 'x-request-id': 'a', 'x-keep': 'k' } as Record<string, unknown>,
    rawHeaders: ['Host', 'h', 'X-Request-Id', 'a', 'X-Keep', 'k', 'x-request-id', 'b'],
  };
  const sameArray = req.rawHeaders;
  stripExemptHeaders(req);
  assert.deepEqual(req.headers, { host: 'h', 'x-keep': 'k' });
  assert.deepEqual(req.rawHeaders, ['Host', 'h', 'X-Keep', 'k']);
  assert.equal(req.rawHeaders, sameArray, 'rebuilt in place');
});

test('stripExemptHeaders removes all exempt names, whatever their case', () => {
  const headers: Record<string, unknown> = { host: 'h', 'x-keep': 'k' };
  const rawHeaders: string[] = ['Host', 'h', 'X-Keep', 'k'];
  for (const name of INGRESS_EXEMPT_HEADERS) {
    headers[name] = 'v';
    rawHeaders.push(name.toUpperCase(), 'v');
  }
  const req = { headers, rawHeaders };
  stripExemptHeaders(req);
  assert.deepEqual(req.headers, { host: 'h', 'x-keep': 'k' });
  assert.deepEqual(req.rawHeaders, ['Host', 'h', 'X-Keep', 'k']);
});

test('formatUnsignedHeaderReport sanitises: lower-case, max 20, bad names replaced', () => {
  assert.deepEqual(formatUnsignedHeaderReport(['X-Foo', 'x-bar']), ['x-bar', 'x-foo']);
  assert.deepEqual(formatUnsignedHeaderReport(['x-a b', 'x'.repeat(65), 'x-é']), ['invalid-name', 'invalid-name', 'invalid-name']);
  assert.equal(formatUnsignedHeaderReport(Array.from({ length: 30 }, (_, i) => 'x-h' + i)).length, 20);
});

test('ReportRateLimiter: one emit per distinct name-set per 60 s, bounded memory', () => {
  const l = new ReportRateLimiter(3, 60);
  assert.equal(l.shouldEmit(['b', 'a'], 100), true);
  assert.equal(l.shouldEmit(['a', 'b'], 120), false, 'same set, any order');
  assert.equal(l.shouldEmit(['a'], 120), true, 'different set');
  assert.equal(l.shouldEmit(['a', 'b'], 160), true, 'window passed');
  for (let i = 0; i < 50; i++) l.shouldEmit(['x-' + i], 200);
  assert.ok(l.last.size <= 3);
});

test('respondAndClose answers with Connection: close and destroys the request', async () => {
  const server = createServer((req, res) => respondAndClose(res, 413, '{"error":"too_large"}'));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as { port: number }).port;
  const got = await new Promise<{ status: number; connection: string; body: string }>((resolve, reject) => {
    const rq = httpRequest({ host: '127.0.0.1', port, method: 'POST', agent: false }, (res) => {
      let b = '';
      res.on('data', (d) => (b += d));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, connection: String(res.headers.connection), body: b }));
    });
    rq.on('error', reject);
    rq.write('x');
    rq.end();
  });
  server.close();
  assert.deepEqual(got, { status: 413, connection: 'close', body: '{"error":"too_large"}' });
});

// ---------------------------------------------------------------------------
// handleGatewayRequest: the shared wrapper, through a real http server.
// ---------------------------------------------------------------------------
import { createHmac, randomBytes } from 'node:crypto';
import { connect } from 'node:net';
import type { AddressInfo } from 'node:net';
import { handleGatewayRequest, effectiveMinVersion } from '../src/itsl/s2s-v3.js';
import type { GatewayOptions, VerifiedRequest } from '../src/itsl/s2s-v3.js';

const WSECRET = 'z'.repeat(40);
const sha = (v: string | Buffer) => createHash('sha256').update(v).digest('hex');

function signWrapper(body: string, headers: Record<string, string> = {}, method = 'POST'): string {
  const t = Math.floor(Date.now() / 1000);
  const n = randomBytes(16).toString('hex');
  const names = Object.keys(headers).map((k) => k.toLowerCase()).sort();
  const lines = ['ITSL-S2S-v3', `t=${t}`, `n=${n}`, 'aud=wrap', `m=${method}`, 'p=/mcp', `b=${sha(body)}`, `sh=${names.join(';')}`,
    ...names.map((k) => `${k}:${sha(headers[k])}`)];
  const v3 = createHmac('sha256', WSECRET).update(lines.join('\n'), 'utf8').digest('hex');
  return `t=${t},n=${n},sh=${names.join(';')},v3=${v3}`;
}

async function wrapperServer(over: Partial<GatewayOptions>, onVerified: (v: VerifiedRequest) => Promise<void> | void) {
  const logs: { level: string; msg: string; meta?: Record<string, unknown> }[] = [];
  const opts: GatewayOptions = {
    secret: WSECRET, aud: 'wrap', floor: 1, minVersion: 1, nonceCache: new NonceCache(),
    reportLimiter: new ReportRateLimiter(), failureLimiter: new ReportRateLimiter(),
    logger: {
      warn: (msg, meta) => logs.push({ level: 'warn', msg, meta }),
      error: (msg, meta) => logs.push({ level: 'error', msg, meta }),
    },
    ...over,
  };
  const server = createServer((req, res) => {
    if (req.url === '/ping') { res.end('pong'); return; }
    void handleGatewayRequest(req, res, opts, async (v) => { await onVerified(v); if (!res.writableEnded) res.end("ok"); });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as AddressInfo).port;
  return { port, logs, close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }) };
}

function http(port: number, o: { method?: string; path?: string; headers?: Record<string, string>; body?: string }): Promise<{ status: number; body: string }> {
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

const settle = () => new Promise((r) => setTimeout(r, 100));

test('wrapper M1: a socket aborted mid-body does not take the server down', async () => {
  const s = await wrapperServer({}, () => {});
  const sock = connect(s.port, '127.0.0.1');
  await new Promise<void>((r) => sock.once('connect', () => r()));
  sock.write(`POST /mcp HTTP/1.1\r\nHost: x\r\nX-Gateway-S2S: ${signWrapper('x')}\r\nContent-Length: 1000\r\n\r\n0123456789`);
  await settle();
  sock.destroy();
  await settle();
  const r = await http(s.port, { method: 'GET', path: '/ping' });
  assert.equal(r.body, 'pong');
  await s.close();
});

test('wrapper S1: no S2S header is a 401 and the body is not read', async () => {
  const s = await wrapperServer({}, () => { assert.fail('must not verify'); });
  const sock = connect(s.port, '127.0.0.1');
  await new Promise<void>((r) => sock.once('connect', () => r()));
  const got = new Promise<string>((resolve) => { let b = ''; sock.on('data', (d) => { b += d; if (b.includes('\r\n\r\n')) resolve(b); }); });
  sock.write('POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 4000000\r\n\r\n0123456789');
  const text = await Promise.race([got, new Promise<string>((r) => setTimeout(() => r('TIMEOUT'), 1500))]);
  sock.destroy();
  assert.match(text, /^HTTP\/1\.1 401/);
  assert.match(text, /connection: close/i);
  await s.close();
});

test('wrapper S1: two S2S headers is a 401 as well', async () => {
  const s = await wrapperServer({}, () => assert.fail('must not verify'));
  const r = await http(s.port, { headers: { 'x-gateway-s2s': 'a', 'X-Gateway-S2S': 'b' }, body: '{}' });
  assert.equal(r.status, 401);
  await s.close();
});

test('wrapper S2: a verified POST with an empty body is a 400', async () => {
  const s = await wrapperServer({}, () => assert.fail('must not reach the handler'));
  const r = await http(s.port, { headers: { 'x-gateway-s2s': signWrapper('') } });
  assert.equal(r.status, 400);
  assert.match(r.body, /Empty body/);
  await s.close();
});

test('wrapper S2: a verified DELETE with an empty body reaches the handler with no parsedBody', async () => {
  let seen: VerifiedRequest | undefined;
  const s = await wrapperServer({}, (v) => { seen = v; });
  await http(s.port, { method: 'DELETE', headers: { 'x-gateway-s2s': signWrapper('', {}, 'DELETE') } }).catch(() => {});
  assert.equal(seen?.parsedBody, undefined);
  assert.equal(seen?.version, 3);
  await s.close();
});

test('wrapper: a non-JSON verified body is a 400, a JSON one is parsed', async () => {
  let seen: VerifiedRequest | undefined;
  const s = await wrapperServer({}, (v) => { seen = v; });
  assert.equal((await http(s.port, { headers: { 'x-gateway-s2s': signWrapper('{nope') }, body: '{nope' })).status, 400);
  await http(s.port, { headers: { 'x-gateway-s2s': signWrapper('{"a":1}') }, body: '{"a":1}' }).catch(() => {});
  assert.deepEqual(seen?.parsedBody, { a: 1 });
  await s.close();
});

test('wrapper: onVerified throwing is a 500 and the server keeps serving', async () => {
  const s = await wrapperServer({}, () => { throw new Error('boom'); });
  const r = await http(s.port, { headers: { 'x-gateway-s2s': signWrapper('{}') }, body: '{}' });
  assert.equal(r.status, 500);
  assert.ok(!r.body.includes('boom'));
  assert.equal((await http(s.port, { method: 'GET', path: '/ping' })).body, 'pong');
  assert.ok(s.logs.some((l) => l.level === 'error' && l.meta?.error === 'boom'));
  await s.close();
});

test('wrapper S3: the failure log is rate limited per reason', async () => {
  const s = await wrapperServer({}, () => {});
  for (let i = 0; i < 2; i++) await http(s.port, { headers: { 'x-gateway-s2s': 'garbage' }, body: '{}' });
  assert.equal(s.logs.filter((l) => l.msg === 'S2S verification failed').length, 1);
  await http(s.port, { body: '{}' }); // a different reason (header-count) logs once
  assert.equal(s.logs.filter((l) => l.msg === 'S2S verification failed').length, 2);
  await s.close();
});

test('wrapper: headerRuleEnforced is false at minVersion 1 and true at 3', async () => {
  for (const [min, expected] of [[1, false], [3, true], [NaN, true]] as const) {
    let seen: VerifiedRequest | undefined;
    const s = await wrapperServer({ minVersion: min }, (v) => { seen = v; });
    await http(s.port, { headers: { 'x-gateway-s2s': signWrapper('{}') }, body: '{}' }).catch(() => {});
    assert.equal(seen?.headerRuleEnforced, expected, `min ${min}`);
    await s.close();
  }
});

test('wrapper: no secret without allowUnauthenticated is a 500, logged as config, and never reaches onVerified', async () => {
  for (const secret of [undefined, '']) {
    const s = await wrapperServer({ secret }, () => assert.fail('must not reach the handler'));
    const r = await http(s.port, { body: '{}' });
    assert.equal(r.status, 500);
    assert.ok(s.logs.some((l) => l.msg === 'S2S verification failed' && l.meta?.reason === 'config'));
    await s.close();
  }
});

test('wrapper: with no secret and allowUnauthenticated S2S is skipped (dev escape hatch) and the version is 0', async () => {
  let seen: VerifiedRequest | undefined;
  const s = await wrapperServer({ secret: undefined, allowUnauthenticated: true }, (v) => { seen = v; });
  await http(s.port, { body: '{}' }).catch(() => {});
  assert.equal(seen?.version, 0);
  assert.equal(seen?.headerRuleEnforced, false);
  await s.close();
});

test('effectiveMinVersion: max(floor, min) with invalid values counted as 3', () => {
  assert.equal(effectiveMinVersion(1, 1), 1);
  assert.equal(effectiveMinVersion(2, 1), 2);
  assert.equal(effectiveMinVersion(1, 3), 3);
  assert.equal(effectiveMinVersion(1, NaN), 3);
  assert.equal(effectiveMinVersion(1, 0), 3);
  assert.equal(effectiveMinVersion(1, 1.5), 3);
});

test('ReportRateLimiter accepts a plain string key', () => {
  const l = new ReportRateLimiter(3, 60);
  assert.equal(l.shouldEmit('reason', 100), true);
  assert.equal(l.shouldEmit('reason', 120), false);
  assert.equal(l.shouldEmit('other', 120), true);
});

// ---------------------------------------------------------------------------
// requireSignedHeaders (identity headers must be signed whenever present)
// ---------------------------------------------------------------------------
for (const c of vectors.requireSigned) {
  test(`requireSigned: ${c.name}`, () => {
    const base = vectors.positive.find((p: any) => p.name === c.from);
    const rawHeaders = [...base.rawHeaders, ...(c.extraRawHeaders ?? [])];
    const r: any = verifyV3({ ...args(base, new NonceCache()), rawHeaders, headerRuleMode: c.headerRuleMode, requireSignedHeaders: c.requireSignedHeaders });
    assert.equal(r.ok, c.expect.ok);
    if (!r.ok) assert.equal(r.reason, c.expect.reason);
  });
}

test('requireSigned: a refusal does not consume the nonce', () => {
  const c = vectors.requireSigned[1];
  const base = vectors.positive.find((p: any) => p.name === c.from);
  const cache = new NonceCache();
  assert.equal(verifyV3({ ...args(base, cache), rawHeaders: [...base.rawHeaders, ...c.extraRawHeaders], requireSignedHeaders: c.requireSignedHeaders, headerRuleMode: 'report' }).ok, false);
  assert.equal(cache.entries.size, 0);
});

test('requireSigned: invalid or exempt names throw at configuration time', () => {
  for (const list of vectors.requireSignedConfigErrors) assert.throws(() => assertRequireSignedHeaders(list), /requireSignedHeaders/);
  assert.doesNotThrow(() => assertRequireSignedHeaders(['x-mcp-tier', 'x-user-token']));
  assert.doesNotThrow(() => assertRequireSignedHeaders(undefined));
});

test('requireSigned: checkGatewayRequest passes the list through, and legacy is unaffected', () => {
  const c = vectors.requireSigned[1];
  const base = vectors.positive.find((p: any) => p.name === c.from);
  const r = checkGatewayRequest({ ...args(base, new NonceCache()), rawHeaders: [...base.rawHeaders, ...c.extraRawHeaders], requireSignedHeaders: c.requireSignedHeaders, headerRuleMode: 'report', floor: 1, minVersion: 1 });
  assert.deepEqual(r, { ok: false, version: 0, reason: 'unsigned-required-header' });
  const legacy = checkGatewayRequest({ ...args(base, new NonceCache()), rawHeaders: ['Host', 'x', 'X-Gateway-S2S', 'legacy-value', 'x-mcp-tier', 'read'], requireSignedHeaders: ['x-mcp-tier', 'x-mcp-user'], floor: 1, minVersion: 1, verifyLegacy: () => 2 });
  assert.deepEqual(legacy, { ok: true, version: 2 });
});

test('wrapper: requireSignedHeaders unsigned is 401 in report mode at min 1; signed passes; absent passes', async () => {
  let reached = 0;
  const s = await wrapperServer({ minVersion: 1, requireSignedHeaders: ['x-mcp-tier'] }, () => { reached++; });
  const unsigned = await http(s.port, { headers: { 'x-gateway-s2s': signWrapper('{}'), 'x-mcp-tier': 'write' }, body: '{}' });
  assert.equal(unsigned.status, 401);
  assert.equal(reached, 0);
  assert.ok(s.logs.some((l) => l.meta?.reason === 'unsigned-required-header'));
  await http(s.port, { headers: { 'x-gateway-s2s': signWrapper('{}', { 'x-mcp-tier': 'write' }), 'x-mcp-tier': 'write' }, body: '{}' });
  await http(s.port, { headers: { 'x-gateway-s2s': signWrapper('{}') }, body: '{}' });
  assert.equal(reached, 2);
  await s.close();
});

// ---------------------------------------------------------------------------
// Hash pin: the vendored verifier must stay byte-identical to the canonical copy.
// ---------------------------------------------------------------------------
test('vendored src/itsl/s2s-v3.ts matches the canonical sha256', () => {
  const bytes = readFileSync(new URL('../src/itsl/s2s-v3.ts', import.meta.url));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), '3160ee243febcf990c4eb84f514c254a7d9a98592fa1d9b53888f1ad0dde11b0');
});

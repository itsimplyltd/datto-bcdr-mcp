import { afterEach, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { DattoBcdrClient } from '../src/datto-api.js';

const open: Server[] = [];
afterEach(async () => {
  for (const s of open.splice(0)) await new Promise<void>((r) => { s.closeAllConnections(); s.close(() => r()); });
});

async function listen(handler: Parameters<typeof createServer>[1]): Promise<number> {
  const s = createServer(handler);
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', () => r()));
  open.push(s);
  return (s.address() as AddressInfo).port;
}

it('a 3xx from the vendor fails closed: the redirect target is never contacted', async () => {
  let targetHits = 0;
  let seenAuth: string | undefined;
  const target = await listen((req, res) => { targetHits++; seenAuth = String(req.headers.authorization); res.end('{}'); });
  const vendor = await listen((_req, res) => { res.writeHead(302, { Location: `http://127.0.0.1:${target}/stolen` }); res.end(); });
  const client = new DattoBcdrClient({ apiKey: 'pub', apiSecretKey: 'priv', apiUrl: `http://127.0.0.1:${vendor}/v1` });
  await expect(client.listDevices()).rejects.toThrow();
  expect(targetHits).toBe(0);
  expect(seenAuth).toBeUndefined();
});

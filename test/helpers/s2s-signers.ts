// TEST HELPERS ONLY. Ports of cred-router's signers (MCP-Gateway cred-router/src/s2sV3.js
// s2sHeaderV3 and cred-router/src/index.js s2sHeader) so the tests sign requests exactly
// as the gateway does. Never imported by production code.
import { createHash, createHmac, randomBytes } from 'node:crypto';

const sha256hex = (v: Buffer | string): string => createHash('sha256').update(v).digest('hex');

/** Legacy v1 header, as cred-router's s2sHeader(). */
export function legacyHeader(secret: string, t: number = Math.floor(Date.now() / 1000)): string {
  return `t=${t},v1=${createHmac('sha256', secret).update(`t=${t}`).digest('hex')}`;
}

/** v3 header, as cred-router's s2sHeaderV3(). `headers` are the signed headers (lower-case names). */
export function v3Header(
  secret: string,
  o: { aud: string; method: string; path: string; body?: string; headers?: Record<string, string> },
): string {
  const t = Math.floor(Date.now() / 1000);
  const n = randomBytes(16).toString('hex');
  const entries = Object.entries(o.headers ?? {});
  const names = entries.map(([k]) => k.toLowerCase()).sort();
  const hashes: Record<string, string> = {};
  for (const [k, v] of entries) hashes[k.toLowerCase()] = sha256hex(Buffer.from(v, 'utf8'));
  const sh = names.join(';');
  const lines = [
    'ITSL-S2S-v3', `t=${t}`, `n=${n}`, `aud=${o.aud}`, `m=${o.method.toUpperCase()}`, `p=${o.path}`,
    `b=${sha256hex(Buffer.from(o.body ?? '', 'utf8'))}`, `sh=${sh}`,
    ...names.map((k) => `${k}:${hashes[k]}`),
  ];
  const v3 = createHmac('sha256', secret).update(lines.join('\n'), 'utf8').digest('hex');
  return `t=${t},n=${n},sh=${sh},v3=${v3}`;
}

/**
 * HTTP transport for the gateway-facing container: routing, S2S verification
 * (legacy v1 header and S2S v3) and the per-request MCP server.
 *
 * Split out of index.ts so the whole request path can be tested through a real
 * http.Server. index.ts only wires it to the process (port, env, shutdown).
 */
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { createMcpServer, type DattoBcdrCredentials } from "./mcp-server.js";
import { runWithServerRef } from "./utils/server-ref.js";
import { verifyS2sHeader } from "./s2s-verify.js";
import {
  NonceCache,
  ReportRateLimiter,
  assertRequireSignedHeaders,
  effectiveMinVersion,
  handleGatewayRequest,
  type GatewayLogger,
} from "./itsl/s2s-v3.js";

/** What cred-router passes as `aud` for this vendor (vendor: 'datto-bcdr'). */
export const S2S_AUDIENCE = "datto-bcdr";

/**
 * The legacy version this backend enforces today: verifyS2sHeader accepts only
 * `t=..,v1=..`, so the floor is 1.
 */
export const S2S_FLOOR = 1;

export const MIN_S2S_SECRET_LENGTH = 32;

/**
 * Every header this backend reads as a credential, and that cred-router sets
 * on the proxied request (index.js, vendor 'datto-bcdr'). Under v3 each must be
 * covered by the signature whenever it is present.
 */
export const REQUIRE_SIGNED_HEADERS = ["x-datto-bcdr-public-key", "x-datto-bcdr-private-key"];
assertRequireSignedHeaders(REQUIRE_SIGNED_HEADERS);

export interface HttpLogger extends GatewayLogger {
  info(msg: string, meta?: Record<string, unknown>): void;
}

export const defaultLogger: HttpLogger = {
  info: (msg, meta) => console.error(JSON.stringify({ level: "info", msg, ...meta })),
  warn: (msg, meta) => console.error(JSON.stringify({ level: "warn", msg, ...meta })),
  error: (msg, meta) => console.error(JSON.stringify({ level: "error", msg, ...meta })),
};

/** One per process: v3 nonces are single-use inside the skew window. */
const nonceCache = new NonceCache();
const reportLimiter = new ReportRateLimiter();
const failureLimiter = new ReportRateLimiter();

/**
 * HTTP mode refuses to start without an S2S secret of at least 32 characters.
 * Never logs or echoes the secret or its length.
 */
export function resolveS2sSecret(env: NodeJS.ProcessEnv = process.env): string {
  const secret = env.CONDUIT_S2S_SECRET ?? "";
  if (secret.length < MIN_S2S_SECRET_LENGTH) {
    throw new Error(
      "Refusing to start HTTP server: CONDUIT_S2S_SECRET must be set to at least 32 characters " +
        "(generate one with `openssl rand -hex 32`)."
    );
  }
  return secret;
}

/** Start-up line the security reviewer reads: effective minimum and header-rule mode. */
export function logS2sStartup(minVersion: number, logger: HttpLogger = defaultLogger): void {
  const effective = effectiveMinVersion(S2S_FLOOR, minVersion);
  logger.info("S2S v3 configuration", {
    effectiveMinVersion: effective,
    headerRule: effective === 3 ? "enforce" : "report",
  });
}

export interface HttpServerOptions {
  secret: string;
  isGatewayMode: boolean;
  /** Raw ITSL_S2S_MIN_VERSION value; anything not an integer 1..3 counts as 3. */
  minVersion?: number;
  logger?: HttpLogger;
}

export function readMinVersion(env: NodeJS.ProcessEnv = process.env): number {
  return Number(env.ITSL_S2S_MIN_VERSION ?? String(S2S_FLOOR));
}

export function createHttpServer(opts: HttpServerOptions): HttpServer {
  const { secret, isGatewayMode } = opts;
  const minVersion = opts.minVersion ?? readMinVersion();
  const logger = opts.logger ?? defaultLogger;

  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    // Raw target, not a parsed URL: the signed path is exactly what was sent.
    const rawTarget = req.url ?? "/";
    const queryAt = rawTarget.indexOf("?");
    const pathname = queryAt === -1 ? rawTarget : rawTarget.slice(0, queryAt);

    // Health endpoint - no auth required
    if (pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          transport: "http",
          authMode: isGatewayMode ? "gateway" : "env",
          timestamp: new Date().toISOString(),
        })
      );
      return;
    }

    if (pathname !== "/mcp") {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found", endpoints: ["/mcp", "/health"] }));
      return;
    }

    // The shared wrapper runs the S2S check first, reads the body once and never
    // rejects: an aborted upload or a throwing handler ends that request, not
    // the process. There is no dev escape hatch: no secret means no boot.
    await handleGatewayRequest(
      req,
      res,
      {
        secret,
        aud: S2S_AUDIENCE,
        floor: S2S_FLOOR,
        minVersion,
        verifyLegacy: (headerValue) => (verifyS2sHeader(headerValue, secret) ? 1 : 0),
        nonceCache,
        reportLimiter,
        failureLimiter,
        logger,
        requireSignedHeaders: REQUIRE_SIGNED_HEADERS,
      },
      async ({ parsedBody }) => {
        if (req.method !== "POST") {
          res.writeHead(405, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              jsonrpc: "2.0",
              error: { code: -32000, message: "Method not allowed" },
              id: null,
            })
          );
          return;
        }

        // In gateway mode, extract credentials from headers and pass directly
        // to avoid process.env race conditions under concurrent load.
        let gatewayCredentials: DattoBcdrCredentials | undefined;
        if (isGatewayMode) {
          const headers = req.headers as Record<string, string | string[] | undefined>;
          const publicKey = headers["x-datto-bcdr-public-key"] as string | undefined;
          const privateKey = headers["x-datto-bcdr-private-key"] as string | undefined;

          if (!publicKey || !privateKey) {
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                error: "Missing credentials",
                message:
                  "Gateway mode requires X-Datto-BCDR-Public-Key and X-Datto-BCDR-Private-Key headers",
                required: ["X-Datto-BCDR-Public-Key", "X-Datto-BCDR-Private-Key"],
              })
            );
            return;
          }

          gatewayCredentials = { publicKey, privateKey };
        }

        // Stateless: fresh server + transport per request
        const server = createMcpServer(gatewayCredentials);
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });

        res.on("close", () => {
          transport.close();
          server.close();
        });

        // The whole chain runs inside runWithServerRef so the server-ref binding
        // used by elicitation survives every await gap in this request's
        // lifecycle without leaking into a concurrent request's server-ref.
        await runWithServerRef(server, async () => {
          try {
            await server.connect(transport as unknown as Transport);
            await transport.handleRequest(req, res, parsedBody);
          } catch (err) {
            console.error("MCP transport error:", err);
            if (!res.headersSent) {
              res.writeHead(500, { "Content-Type": "application/json" });
              res.end(
                JSON.stringify({
                  jsonrpc: "2.0",
                  error: { code: -32603, message: "Internal error" },
                  id: null,
                })
              );
            }
          }
        });
      }
    );
  });
}

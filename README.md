# Datto BCDR MCP Server

[![Release](https://github.com/WYRE-AI/datto-bcdr-mcp/actions/workflows/release.yml/badge.svg)](https://github.com/WYRE-AI/datto-bcdr-mcp/actions/workflows/release.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Model Context Protocol (MCP) server for the Datto BCDR (Backup Portal) API.
Exposes SIRIS / Alto appliances, protected agents, recovery points, screenshot
verifications, off-site sync status, and alerts to AI assistants.

## Tools

| Tool | Description |
|------|-------------|
| `datto_bcdr_list_devices` | List all SIRIS/Alto appliances in the partner portal |
| `datto_bcdr_get_device` | Get appliance details by `serialNumber` (renders as an interactive card in MCP Apps hosts) |
| `datto_bcdr_list_assets` | List protected agents on an appliance |
| `datto_bcdr_get_asset` | Get a specific protected agent |
| `datto_bcdr_list_backups` | List recovery points for an agent |
| `datto_bcdr_list_screenshots` | List screenshot verifications for an agent |
| `datto_bcdr_get_screenshot` | Fetch a screenshot PNG (returned as base64 image content) |
| `datto_bcdr_get_offsite_status` | Off-site sync status for an appliance |
| `datto_bcdr_list_alerts` | Portal alerts (date-range filtered) |

When the user omits required filters (date range, serial number, etc.) the
server uses MCP elicitation to prompt for them.

## Features

- **Interactive Device Card (MCP Apps, SEP-1865)**: `datto_bcdr_get_device`
  renders as a read-only interactive card in MCP Apps hosts (Claude
  Desktop/web) showing the appliance's backup status at a glance — neutral by
  default, brandable via `window.__BRAND__` injection or `MCP_BRAND_*` env
  vars; plain-JSON behavior is unchanged in other hosts. Edit `ui/` and run
  `npm run build:ui` to regenerate the embedded card bundle.

## Configuration

### Environment-variable mode (default)

| Variable | Required | Description |
|----------|----------|-------------|
| `DATTO_BCDR_PUBLIC_KEY` | yes | Datto BCDR partner portal public key |
| `DATTO_BCDR_PRIVATE_KEY` | yes | Datto BCDR partner portal private key (secret) |
| `DATTO_BCDR_REGION` | no | `us` (default) or `eu` |
| `MCP_TRANSPORT` | no | `stdio` (default) or `http` |
| `MCP_HTTP_PORT` | no | HTTP listen port (default `8080`) |
| `AUTH_MODE` | no | `env` (default) or `gateway` |

### Gateway mode

When deployed behind the WYRE MCP Gateway, set `AUTH_MODE=gateway` and the
server will read credentials from per-request HTTP headers:

- `X-Datto-BCDR-Public-Key`
- `X-Datto-BCDR-Private-Key`
- `X-Datto-BCDR-Region` (optional)

Each request creates a fresh server instance with isolated credentials — no
cross-tenant `process.env` pollution.

## Local development

```bash
npm install
npm run build
DATTO_BCDR_PUBLIC_KEY=... DATTO_BCDR_PRIVATE_KEY=... npm start
```

Run as HTTP for testing:

```bash
MCP_TRANSPORT=http npm start
curl http://localhost:8080/health
```

## Docker

```bash
docker build -t datto-bcdr-mcp .
docker run --rm -p 8080:8080 \
  -e DATTO_BCDR_PUBLIC_KEY=... \
  -e DATTO_BCDR_PRIVATE_KEY=... \
  datto-bcdr-mcp
```

## License

Apache-2.0

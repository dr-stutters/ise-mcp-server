# ise-mcp-server

MCP server for Cisco Identity Services Engine (ISE), built on
[stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core).

> Status: in development (milestone 1: scaffold). The full README arrives with v0.1.0.

It talks to all three ISE REST surfaces: OpenAPI (`/api/v1`), ERS (`/ers/config`) and MnT
(`/admin/API/mnt`), using HTTP Basic auth.

## Quick start

```bash
cp .env.example .env    # set ISE_URL / ISE_USERNAME / ISE_PASSWORD
uv run ise-mcp-server check
```

Not affiliated with or endorsed by Cisco Systems, Inc.

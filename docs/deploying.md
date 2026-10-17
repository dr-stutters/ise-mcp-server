# Deploying ise-mcp-server on a shared host

One container serves a team: each person gets their own token, the server is read-only until you decide
otherwise, TLS ends at a reverse proxy, and one server can reach several ISE deployments. Everything below is
in [`examples/shared-host/`](../examples/shared-host/); a laptop (stdio) setup is in the README quickstart.

## 1. What is safe by default

| Setting | Default | What it means |
|---|---|---|
| `MCP_ENABLE_WRITES` | `false` | write tools (create/update NADs, users, policy, SGTs...) are **not registered** |
| `MCP_ENABLE_DANGEROUS` | `false` | CoA, ANC apply/clear, deletes of live policy, node services, certificate binds: not registered; needs writes on too |
| `MCP_AUTH_TOKENS` | none | the HTTP transport **refuses to start** without at least one token (or OAuth) |
| `MCP_DEFAULT_ROLE` | `ro` | once `MCP_ROLES` is set, a caller with no entry gets read tools only (without `MCP_ROLES` every token can use every enabled tier) |
| `ISE_VERIFY_SSL` | `true` | ISE's certificate is checked; set `ISE_CA_BUNDLE` for a private CA |
| `ISE_EXPORT_DIR` | unset | `ise_export_config` (a read tool) can write `.yaml` files to any absolute path the server's user can write; **set this on a shared host** to confine export files to one directory ([config-export.md](config-export.md)) |

Turning on writes is two decisions: the server (`MCP_ENABLE_WRITES=true`) and who may use them (`MCP_ROLES`).
Every write tool is preview-first: nothing changes until the caller repeats the call with the confirm token.
The contract tests (`tests/unit/test_tier_defaults.py`) fail if a default or a shipped config turns writes on.

## 2. The ISE account (least privilege, step by step)

Give the server its own ISE admin account, sized to the tiers you enable. Full mapping and the reasons:
[least-privilege.md](least-privilege.md).

1. **Administration > System > Settings > API Settings**: enable **ERS** (read-only is enough for a
   read-only server) and the **Open API** service. Note the ERS port: 443 on ISE 3.1+; 9060 when ERS is not
   enabled on 443 (set `ISE_ERS_PORT=9060`).
2. **Administration > System > Admin Access > Administrators > Admin Users > Add**, name e.g. `mcp-ro`:
   - read-only server: admin groups **ERS Operator** + **Read Only Admin**;
   - writes on: **ERS Admin**, **Policy Admin**, **Network Device Admin**, **Identity Admin**, **MnT Admin**
     (a separate account, e.g. `mcp-rw`);
   - dangerous on: **Super Admin** (only if you need CoA/ANC/deletes from the server).
3. Set a password and keep it out of `.env`: `ISE_PASSWORD_FILE=/run/secrets/ise_password` (Docker secret) or
   `ISE_PASSWORD_REF=vault:...` (core `docs/PRODUCTION.md`, "Secrets").
4. Run the preflight; it compares the account's admin groups with the enabled tiers:

   ```bash
   docker compose exec ise-mcp-server ise-mcp-server check
   ```

   `role` fails when an enabled tier isn't allowed and warns when the account holds more than the server
   needs (a Super Admin behind a read-only server). `ise_deployment_health` reports the same at run time.

### Guest sponsor (guest-account tools)

ISE's guest API (ERS `guestuser`) refuses the ERS admin (401): guest accounts are created, extended,
suspended and deleted as a **sponsor**, the way the sponsor portal does it. Guest types, sponsor groups
and portals need no sponsor; they use the account above.

1. Pick the sponsor identity: an ISE internal user or an AD user (the sponsor portal's identity source
   sequence, `Sponsor_Portal_Sequence` by default, includes the AD join points). For AD, add its group to
   the join point (`ise_add_ad_groups`).
2. Map it into a sponsor group with REST access: **Work Centers > Guest Access > Portals & Components >
   Sponsor Groups**, member groups = that identity/AD group, tick **Access Cisco ISE guest accounts using
   the programmatic interface (Guest REST API)**, pick the guest types and locations, and the narrowest
   manage scope that works (**own accounts** for a bot). Or `ise_set_sponsor_group ... rest_access=true`.
   Leave **View guests' passwords** off: the server never shows a guest password after creating it.
3. Give the server the sponsor: `ISE_SPONSOR_USERNAME` (e.g. `guest-bot`) and the password kept out of
   `.env` as a Docker secret (`ISE_SPONSOR_PASSWORD_FILE`) or a reference (`ISE_SPONSOR_PASSWORD_REF`), like
   `ISE_PASSWORD` above. Optional: `ISE_SPONSOR_PORTAL` (the sponsor portal's name or id, only when there
   are several) and `ISE_GUEST_TIMEZONE` (the guest location's IANA time zone, e.g. `Europe/London`).

4. `ise-mcp-server check` adds a `sponsor` row (skip when unset, fail when ISE refuses it) and
   `ise_status` a `guest_sponsor` block; neither shows the password. The guest-account write tools also
   need `MCP_ENABLE_WRITES=true`.

The guest API takes the **sponsor** portal's id (`portalId`), not a guest portal's. Guest start and end
dates are in the guest location's local time; ISE does not expose that zone over REST, hence
`ISE_GUEST_TIMEZONE`. When it is unset, new accounts start at "now" in UTC-12 (never in the future
anywhere, since ISE accepts past starts) and may end up to a day early.

## 3. Per-user tokens (names in the audit log)

Give each person their own token; the token's name is the caller identity in previews, the audit log and
roles. Never share one token.

```bash
docker run --rm ghcr.io/dr-stutters/ise-mcp-server ise-mcp-server token alice
# prints the token (give it to alice) and the line for the server:  alice:sha256:<hex>
```

Collect the lines in `MCP_AUTH_TOKENS=alice:sha256:...,bob:sha256:...` (or one per line in a file named by
`MCP_AUTH_TOKENS_FILE`). Revoke a person by deleting their entry and restarting. With writes on, say who may
use them:

```bash
MCP_ROLES=alice:rw,bob:ro,oncall-*:admin    # ro = read, rw = + write, admin = + dangerous
```

The example writes the audit log to `/cache/ise-audit.log` (rotated at 50 MB, 5 files): one JSON line per
call, e.g. `{"audit": {"event": "tool_call", "tool": "ise_status", "caller": "alice", "args": {...},
"outcome": "ok"}}`, plus `preview` / `applied` events for writes. Ship it to your log platform, or set
`MCP_AUDIT_LOG=stderr` and use the container log driver.

## 4. Several ISE deployments from one host

```bash
ISE_URL=https://ise-pan.corp.example        # the default instance
ISE_USERNAME=mcp-ro
ISE_PASSWORD_FILE=/run/secrets/ise_password
ISE_INSTANCES=dr                            # more deployments, each with its own variables:
ISE_DR_URL=https://ise-dr-pan.corp.example
ISE_DR_USERNAME=mcp-ro
ISE_DR_PASSWORD_FILE=/run/secrets/ise_dr_password
ISE_DR_CA_BUNDLE=/certs/dr-ca.pem           # URL, credentials, TLS and ISE_DR_ERS_PORT are never inherited
ISE_DR_READ_ONLY=true                       # optional: block writes on this deployment only
```

Every tool then takes an optional `instance` argument (`default` or `dr`); `check` reports each deployment.
Point each `*_URL` at that deployment's **Primary Admin node** (OpenAPI and ERS); MnT and CoA routing follow
from there.

## 5. TLS with a reverse proxy (Caddy)

The server speaks plain HTTP inside the compose network; Caddy terminates TLS on 443:

```bash
cd examples/shared-host
cp .env.example .env && chmod 600 .env       # fill in ISE, tokens, MCP_HOSTNAME
docker compose up -d
curl https://mcp-ise.corp.example/health     # {"status":"ok"}
```

- `MCP_HOSTNAME=mcp-ise.corp.example` and `CADDY_TLS=you@corp.example`: a public name gets a Let's Encrypt
  certificate (ports 80/443 reachable from the internet).
- An internal name: `CADDY_TLS=internal` (Caddy's own CA; copy `/data/caddy/pki/authorities/local/root.crt`
  from the `caddy-data` volume to clients) or mount your own certificate and put
  `tls /certs/mcp.crt /certs/mcp.key` in the `Caddyfile`.
- The MCP server port is not published; only Caddy is. `flush_interval -1` keeps streamed responses flowing.

Clients then use `https://mcp-ise.corp.example/mcp` with `Authorization: Bearer <their token>`.

**Try it first without ISE:** `docker compose -f docker-compose.yml -f docker-compose.mock.yml up -d` starts two
mocked ISE deployments (`default`, `dr`) and a demo token; `docker compose -f docker-compose.yml -f
docker-compose.mock.yml exec ise-mcp-server ise-mcp-server check` checks both, and
`curl -k https://localhost:8443/health` goes through Caddy.

## 6. Upgrades

- Images: `ghcr.io/dr-stutters/ise-mcp-server:<version>` (and `:latest`); release candidates are `:<version>-rcN`
  and `:rc`, never `:latest`. Pin a version on a shared host (`MCP_IMAGE_TAG=0.11.0`), read the
  [CHANGELOG](../CHANGELOG.md), then `docker compose pull && docker compose up -d`.
- Verify what you run (keyless cosign signature from the release workflow, plus a signed SBOM):

  ```bash
  cosign verify ghcr.io/dr-stutters/ise-mcp-server:0.11.0 \
    --certificate-identity-regexp '^https://github.com/dr-stutters/stutters-mcp-core/.github/workflows/publish-image.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository dr-stutters/ise-mcp-server
  ```

- After an upgrade run `check` again; a release that needs a new ISE permission says so in the CHANGELOG and
  `role` fails until the account has it.
- Roll back by setting `MCP_IMAGE_TAG` to the previous version. The server keeps no state besides the spec
  cache and the audit log (both in the `/cache` volume), so a rollback needs nothing else.
- Upgrading ISE: run `check`; `version` warns on a release outside the tested matrix (3.5 today; 3.1+ should
  work).

# ise-mcp-server

An MCP server for Cisco Identity Services Engine (ISE), built on
[stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core). It lets an assistant
troubleshoot authentications, inspect and change NADs, endpoints, users, policy and TrustSec, and run
CoA/ANC.

It talks to all three ISE REST surfaces with HTTP Basic auth:

| Surface | Path | Used for |
|---|---|---|
| OpenAPI | `/api/v1/...` (443) | policy sets and rules, endpoints, TrustSec, deployment, certificates, licensing, patches, backups |
| ERS | `/ers/config/...` (443, or 9060) | NADs, NDGs, internal users, identity/endpoint groups, authz profiles, dACLs, SGTs, SGACLs, egress matrix, ANC |
| MnT | `/admin/API/mnt/...` (443, XML) | live sessions, authentication history, failure reasons, CoA |

`ise_status` probes all three and says which ones answer. ERS is often disabled or firewalled, and
MnT only has data once RADIUS sessions exist.

Tested against ISE 3.5.0.527 (patches 3 and 4). It should work on 3.1 and later.

## Highlights

- **`ise_why_auth_failed`**: one call explains an endpoint's latest failure. It gives the decoded failure reason with
  cause, resolution and likely fix, the execution steps, the NAD that covers the NAS IP (or the fact that none
  does), the internal user's state, and the matched policy set and rules.
- **`ise_endpoint_360`**: the endpoint record, live session, recent authentications and ANC state.
- **`ise_audit_nads`**: finds missing, short or reused shared secrets, NADs in default groups only,
  overlapping ranges and default SNMP communities, without ever showing a secret.
- Spec tools cover all three surfaces. They search the OpenAPI groups, a spec synthesised from the ERS SDK data
  model, and the MnT calls. `ise_api_call` can call any of them.
- Writes are preview-first (confirm token) and off by default. Disruptive actions (CoA, ANC, deleting NADs,
  policy or certificates) need a second switch.
- Shared secrets, SNMP communities and passwords are never returned: they show as `********`.

## Install and check

```bash
git clone https://github.com/dr-stutters/ise-mcp-server && cd ise-mcp-server
cp .env.example .env && chmod 600 .env     # set ISE_URL, ISE_USERNAME, ISE_PASSWORD
uv sync
uv run ise-mcp-server check                # prints ise_status as JSON; exit 1 if ISE is unreachable
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `ISE_URL` | (required) | `https://<pan-or-mnt-node>` |
| `ISE_USERNAME` / `ISE_PASSWORD` | (required) | API account (see below) |
| `ISE_VERIFY_SSL` | `true` | `false` only for labs with self-signed certs |
| `ISE_CA_BUNDLE` | | CA bundle for the ISE admin certificate |
| `ISE_ERS_PORT` | `443` | ERS port: 443 on ISE 3.1+, 9060 on older releases or when ERS isn't enabled on 443 |
| `ISE_TIMEOUT` / `ISE_RETRIES` | `30` / `2` | Per-request timeout (s) and retries for idempotent calls |
| `ISE_RATE_LIMIT` | unset | Requests per minute across all three surfaces |
| `ISE_MAX_CONCURRENCY` | `5` | Concurrent requests to ISE (shared by all surfaces) |
| `ISE_PROBE_TIMEOUT` | `10` | Per-surface timeout used by `ise_status` |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` (Streamable HTTP) |
| `MCP_HOST` / `MCP_PORT` / `MCP_PATH` | `0.0.0.0` / `8000` / `/mcp` | HTTP listener |
| `MCP_AUTH_TOKENS` | | `name:sha256:<hex>` entries; required for HTTP (`ise-mcp-server token <name>`) |
| `MCP_ENABLE_WRITES` | `false` | Register the write tools (still preview-first) |
| `MCP_ENABLE_DANGEROUS` | `false` | Also register CoA/ANC/delete tools and non-GET `ise_api_call` |
| `MCP_CONFIRM_TTL` | `600` | Seconds a preview's confirm token stays valid |
| `MCP_CACHE_DIR` | `~/.cache/ise-mcp-server` | Spec index cache (`""` disables) |
| `MCP_MAX_RESPONSE_CHARS` | `40000` | Response size budget |
| `MCP_AUDIT_LOG` | `stderr` | `stderr`, a file path, or `off` |
| `LOG_LEVEL` | `INFO` | |

## ISE account (least privilege)

1. **Administration > System > Settings > API Settings**: enable the ERS (read/write or read-only) and
   Open API services. Leave CSRF check off, or on: the server fetches a CSRF token when ISE asks for one.
2. Create an admin user (**Administration > System > Admin Access > Administrators**):
   - Read-only use: add it to **ERS Operator** plus a read-only admin group, e.g. **Read Only Admin**,
     for OpenAPI and MnT.
   - Writes: **ERS Admin** plus a group that can change policy/network resources, e.g. **Network Device
     Admin** and **Policy Admin**. MnT CoA needs **MnT Admin** (or Super Admin).
3. For read-only use, keep `MCP_ENABLE_WRITES=false`. The write tools aren't registered at all then.

## Claude Code

stdio (runs locally):

```bash
claude mcp add ise -- uv --directory /path/to/ise-mcp-server run ise-mcp-server
```

or in `.mcp.json` / `~/.claude.json`:

```json
{
  "mcpServers": {
    "ise": {
      "command": "uv",
      "args": ["--directory", "/path/to/ise-mcp-server", "run", "ise-mcp-server"],
      "env": {"MCP_ENABLE_WRITES": "false"}
    }
  }
}
```

HTTP (the hosted container):

```bash
claude mcp add --transport http ise http://cortex:8033/mcp --header "Authorization: Bearer $(cat ~/.ise-mcp-server-token)"
```

```json
{
  "mcpServers": {
    "ise": {
      "type": "http",
      "url": "http://cortex:8033/mcp",
      "headers": {"Authorization": "Bearer <token>"}
    }
  }
}
```

## Docker

```bash
uv run ise-mcp-server token alice           # put the printed hash line in .env as MCP_AUTH_TOKENS=...
CORE_READ_TOKEN=$(gh auth token) docker compose up -d --build   # needs the core read token while repos are private
curl http://localhost:8033/health
```

The container runs as non-root with a read-only root filesystem, no capabilities and a named volume for
the spec cache.

## Tools

Tool counts with writes and dangerous enabled. With the defaults (read-only), the 38 read tools plus
`ise_api_call` (GET-only) are registered.

### Read (38)

| Tool | What it does |
|---|---|
| `ise_audit_nads` | Audit every network device for common misconfigurations: no RADIUS or TACACS+ secret, short
shared secrets, the same secret reused on many devices, only the default device groups (so
policy can't tell them apart), overlapping IP ranges, well-known SNMP communities, and KeyWrap
without keys. |
| `ise_endpoint_360` | Everything ISE knows about one endpoint, in one call: the endpoint record (identity group,
static assignment, profile, IP, custom/MDM attributes), its live session (NAD, port, user, PSN),
the last authentication attempts with decoded failures, and any ANC policy applied. |
| `ise_find_session` | Look up the live MnT session for an endpoint by MAC, IP, username or audit session id (give
one). |
| `ise_get_auth_history` | Recent authentication attempts for an endpoint MAC from MnT (newest first): pass/fail,
username, NAD, method/protocol, identity store, authorization profiles, SGT and the failure
reason decoded with cause and resolution. |
| `ise_get_authz_profile` | Full authorization profile: access type, VLAN, dACL names, ACLs, web redirection, reauth,
advanced RADIUS attributes, device profile. |
| `ise_get_backup_status` | Status of the last configuration backup (name, repository, start/end time, status, progress).
Answers 'when did ISE last back up and did it work?'. |
| `ise_get_dacl` | One downloadable ACL with its full ACE text (one ACE per line), IP version and description. |
| `ise_get_definition` | Describe a Cisco ISE API operation (parameters, request fields, required fields) or a schema (fields with types and enums). |
| `ise_get_egress_matrix` | The TrustSec egress policy matrix as cells: source SGT -> destination SGT, the SGACLs
applied, the final catch-all rule (permit/deny), and cell status. |
| `ise_get_internal_user` | One internal user: enabled state, identity group names, names/email, password store,
expiry, created/modified dates and custom attributes. |
| `ise_get_license_status` | Licensing summary: smart-licensing registration state, connection type, evaluation period,
and per-tier (Essentials/Advantage/Premier/Device Admin/...) status, compliance and consumption.
Use it to explain features that are unavailable or out of compliance. |
| `ise_get_nad` | Full configuration of one network device: IPs/subnets, device groups, device profile, RADIUS
settings (KeyWrap, DTLS, CoA port), TACACS+, SNMP and TrustSec settings. |
| `ise_get_policy_set` | One policy set with all of its rules in order: authentication rules (condition -> identity
source, if-fail/if-not-found actions), authorization rules (condition -> profiles and SGT) and
local exceptions, each with hit counts and ids. |
| `ise_list_active_sessions` | List active RADIUS sessions from MnT (user, MAC, endpoint IP, NAD IP, PSN, audit session id),
plus total, posture and profiler session counts. |
| `ise_list_allowed_protocols` | List allowed-protocols services (selected by each policy set) and which authentication
protocols each permits: PAP, CHAP, MS-CHAPv2, EAP-MD5, EAP-TLS, PEAP, EAP-FAST, TEAP, LEAP.
Use it when auths fail with 'protocol not allowed' (e.g. |
| `ise_list_anc_endpoints` | List endpoints that currently have an ANC policy applied (e.g. |
| `ise_list_anc_policies` | List Adaptive Network Control (ANC) policies and their actions (QUARANTINE, PORTBOUNCE,
SHUTDOWN, REAUTHENTICATE). |
| `ise_list_authz_profiles` | List authorization profiles (the result of an authorization rule): access type, VLAN, dACL,
Airespace/filter ACL, web redirection, reauth timer and voice domain. |
| `ise_list_certificates` | List system (per-node identity) or trusted certificates with what they are used for, issuer,
expiry and days left. |
| `ise_list_conditions` | List reusable library conditions (e.g. |
| `ise_list_dacls` | List downloadable ACLs (dACLs) with IP version, number of ACEs and the first ACE. |
| `ise_list_endpoint_groups` | List endpoint identity groups (e.g. |
| `ise_list_endpoints` | List endpoints ISE knows about (seen via RADIUS/profiling or added by hand): MAC, endpoint
identity group, whether the group is static, profile, IP and description. |
| `ise_list_failure_reasons` | Decode ISE authentication failure reasons from the MnT catalog (~800 entries): code, reason,
cause and resolution, plus a curated 'likely cause / next step' for common codes. |
| `ise_list_identity_groups` | List user identity groups (e.g. |
| `ise_list_identity_sources` | List where ISE looks users up: identity source sequences (with their ordered stores),
Active Directory join points (domain, status) and LDAP servers. |
| `ise_list_internal_users` | List users in the ISE internal user store: username, enabled/disabled, identity groups and
email. |
| `ise_list_ip_sgt_mappings` | List static IP-to-SGT mappings (host or subnet -> SGT), with the devices/groups they are
deployed to. |
| `ise_list_nads` | List network access devices (switches, WLCs, VPN headends) that ISE accepts RADIUS/TACACS+
from: name, IPs/subnets, device groups (NDGs), whether RADIUS/TACACS secrets and SNMP/TrustSec
are configured (never the secret values). |
| `ise_list_ndgs` | List network device groups (NDGs) as full paths like 'Location#All Locations#Sydney' or
'Device Type#All Device Types#Switch'. |
| `ise_list_nodes` | List the ISE nodes in the deployment: hostname, FQDN, IP, roles (PAN/MnT/PSN/Standalone),
enabled services (Session = PSN, Profiler, pxGrid, ...) and sync status. |
| `ise_list_patches` | List installed ISE patches and hot patches with install dates, plus the base ISE version.
Use it to check whether a fix/patch level is present before troubleshooting a known bug. |
| `ise_list_policy_sets` | List policy sets in evaluation order: rank, name, state, the condition that selects the set,
its allowed-protocols service, hit count and id. |
| `ise_list_sgacls` | List security group ACLs (SGACLs) with their ACE lines and IP version. |
| `ise_list_sgts` | List TrustSec security group tags (SGTs): name, numeric value (and hex), description and id.
SGT names/values appear in authorization rules, the egress matrix and IP-SGT mappings. |
| `ise_search_spec` | Search the Cisco ISE OpenAPI spec for operations (method + path) and schemas. |
| `ise_status` | Check the connection to Cisco ISE: product version and API user, which API surfaces answer, and this MCP server's configuration (writes enabled?, TLS verification). |
| `ise_why_auth_failed` | Diagnose an endpoint's authentication in one call. |

### Write (15)

| Tool | What it does |
|---|---|
| `ise_create_anc_policy` | Create an Adaptive Network Control policy that ise_apply_anc can put on endpoints. |
| `ise_create_authz_profile` | Create an authorization profile (what an authorization rule grants): access type, VLAN, dACL,
reauth timer, voice domain. |
| `ise_create_authz_rule` | Add an authorization rule to a network-access policy set: conditions -> profiles (+ SGT).
Rule order matters: the first match wins, so the preview shows the rules it lands between.
Preview-first. |
| `ise_create_group` | Create a user identity group or an endpoint identity group, for policy to match on and for
users/endpoints to be placed in. |
| `ise_create_internal_user` | Create a user in the ISE internal identity store (for 802.1X/PAP/TACACS+ logins), in the given
identity groups. |
| `ise_create_nad` | Add a network access device (switch, WLC, VPN) so ISE accepts its RADIUS and/or TACACS+
requests. |
| `ise_create_ndg` | Create a network device group (location, device type or a custom hierarchy) under an
existing parent, so devices can be grouped and policy can match on it. |
| `ise_delete_object` | Delete one endpoint, internal user, identity/endpoint group, authorization profile, dACL, SGT,
SGACL, device group or ANC policy. |
| `ise_set_dacl` | Create a downloadable ACL, or replace an existing one's ACEs. |
| `ise_set_egress_policy` | Set the TrustSec policy for traffic from one SGT to another (one egress matrix cell): which
SGACLs apply and the final catch-all. |
| `ise_set_endpoint` | Add an endpoint by MAC or change an existing one's identity group and description, e.g. |
| `ise_set_sgt` | Create a security group tag, or change an existing one's value/description. |
| `ise_update_authz_profile` | Change an authorization profile's access type, VLAN, dACL, reauth timer, voice domain or
description. |
| `ise_update_internal_user` | Enable/disable an internal user, reset their password, or change groups/email/description.
Only the given fields change. |
| `ise_update_nad` | Change a network device: IPs, shared secrets, device groups, description, CoA port or name.
Only the given fields change. |

### Dangerous (9)

| Tool | What it does |
|---|---|
| `ise_api_call` | Call any Cisco ISE REST endpoint (escape hatch for things no other tool covers). |
| `ise_apply_anc` | Put an Adaptive Network Control policy on an endpoint (quarantine, port bounce, shutdown or
reauthenticate, depending on the policy's actions). |
| `ise_clear_anc` | Remove the ANC policy from an endpoint (release it from quarantine). |
| `ise_coa_disconnect` | Send a RADIUS CoA disconnect for an endpoint's live session: terminate it, bounce the switch
port, or shut the port down (stays down until an admin re-enables it). |
| `ise_coa_reauth` | Send a RADIUS Change of Authorization (reauthenticate) for an endpoint's live session, so new
policy (group, profile, ANC) applies now instead of at the next reauth. |
| `ise_delete_certificate` | Delete a system (node identity) or trusted certificate. |
| `ise_delete_nad` | Delete a network device. |
| `ise_delete_policy_rule` | Delete one authentication/authorization rule or local exception from a policy set. |
| `ise_delete_policy_set` | Delete a whole policy set with all its rules. |

## Testing

```bash
uv run pytest                          # unit tests (respx-mocked, includes the tool contract)
uv run python scripts/seed_lab.py      # lab only: mcp-test-* objects + real RADIUS traffic for MnT
uv run pytest tests/live -m live       # live tests against ISE_URL (skipped if unreachable)
```

`scripts/seed_lab.py` creates a NAD for this host's source IP and an internal user, then sends RADIUS
PAP requests and an accounting start, so the session/auth-history/CoA tools have real data. The live
write tests create and delete `mcp-test-*` objects.

## Notes and limits

- ERS lists return only id/name, so list tools fetch each item (`detail=true`, concurrency 5). For very
  large collections use filters or `detail=false`.
- MnT can only search authentication history by MAC. `ise_why_auth_failed` with a username works when the
  user has a live session.
- The ERS spec is synthesised from ISE's SDK data model. It covers the fields, types and enums, but not
  the JSON wrapper name or which operations each resource really supports.
- pxGrid is out of scope.

Not affiliated with or endorsed by Cisco Systems, Inc. MIT licensed.

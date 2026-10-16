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
- **Recent activity without a MAC**: `ise_recent_auth_failures` (who failed in the last N minutes, grouped by
  decoded reason and NAD) and `ise_get_auth_list` (what authenticated in a window, by NAD or user).
- **Prompt `ise_troubleshoot_endpoint_access`**: a guided pass from MAC/user/IP through ISE and the switch
  CLI (cml or catc server) to a diagnosis and a preview-only fix.
- **Prompt `ise_quarantine_host`**: contain a host with ANC + CoA, verify the quarantine dACL/SGT on the switch,
  optionally block its IP on the FTDs (`fmc_contain_host`), and record the undo.
- **Certificate lifecycle with any CA**: CSR -> export -> sign -> trust -> bind, plus certificate profiles and
  identity sequences for EAP-TLS.
- **TrustSec writes**: static IP-SGT mappings, SXP connections/bindings, the TrustSec CoA push and SSH deploy.
- **`ise_deployment_health`**: severity-ranked findings for node sync, redundancy, patches, backups,
  certificates (expired/expiring/self-signed), evaluation licences and AD join points.
- **Endpoint bulk work**: `ise_bulk_endpoints` (create/update/delete up to 500 per call as one ISE task) and
  endpoint custom attributes that policy can match (`EndPoints:<name>`).
- **Policy editing with validation**: create/update policy sets and authentication/authorization rules for
  network access and device admin (TACACS+). Conditions are written as `Dictionary:Attribute operator value`
  and checked against ISE's dictionaries in the preview ("did you mean ...?").
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
uv run ise-mcp-server config               # effective settings and where each came from (no ISE contact)
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
| `ISE_DETAIL_THRESHOLD` | `100` | ERS list pages above this size skip the per-item detail GETs |
| `ISE_DETAIL_CONCURRENCY` | `5` | Concurrent per-item ERS GETs |
| `ISE_PROTECT_MACS` / `ISE_PROTECT_USERS` / `ISE_PROTECT_NADS` | | Comma lists; a CoA/ANC/NAD-delete on any of these is blocked (safety rails, I18) |
| `ISE_COA_ALLOW_SHARED_PORT` | `false` | Allow `port_bounce`/`port_shutdown` on a switch port with more than one live session (an uplink/trunk) |
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

See [docs/least-privilege.md](docs/least-privilege.md) for the full tier → admin-group mapping, the
seed step (`scripts/seed_lab.py --least-privilege`) and the read-tier verification test.
`ise_deployment_health` reports the server's own account and flags it when it holds more than the
enabled tiers need.

## Safety rails

On top of core's operator rails (`MCP_DRY_RUN`, `MCP_CHANGE_WINDOW`, `MCP_DENY_TOOLS`,
`MCP_MAX_BLAST_RADIUS`, `MCP_TWO_PERSON_TOOLS`; see core `docs/PRODUCTION.md`), this server adds:

- **Protect-lists** (`ISE_PROTECT_MACS` / `ISE_PROTECT_USERS` / `ISE_PROTECT_NADS`): a CoA, ANC apply/clear
  or NAD delete targeting a protected endpoint, user or device is blocked in the preview.
- **Shared-port CoA guard**: `ise_coa_disconnect` with `port_bounce`/`port_shutdown` counts the live
  sessions on the target switch port; if more than one shares it (an uplink or trunk) the action is
  blocked unless `ISE_COA_ALLOW_SHARED_PORT=true`.
- **Blast radius** (bound with `MCP_MAX_BLAST_RADIUS` / `MCP_BLAST_RADIUS_OVERRIDES`): reported by
  `ise_coa_reauth` (1), `ise_coa_disconnect` (sessions on the port), `ise_apply_anc` / `ise_clear_anc`
  (1), `ise_bulk_endpoints` (endpoints changed) and `ise_update_node_services` (1). Node-service and
  certificate-bind changes are the ones operators typically place behind `MCP_CHANGE_WINDOW`.

## Multi-node deployments

`ise_status` reports a `deployment` summary: the mode (standalone or distributed), the Primary Admin
node (PAN, which serves OpenAPI/ERS), the primary/secondary Monitoring nodes (MnT, with a failover
note when there is no secondary), the PSNs, and any unreachable node. Point `ISE_URL` at the PAN;
OpenAPI and ERS go there. CoA and ANC are routed to the PSN that owns each session (its `acs_server`)
through MnT, so no per-PSN configuration is needed. A node that serves ERS only on 9060, or a second
deployment, is reached as a separate core instance (`ISE_INSTANCES`; see core `docs/PRODUCTION.md`).

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

114 tools and 3 prompts with writes and dangerous enabled (regenerate with `uv run python scripts/tool_table.py`).
With the defaults (read-only), the 60 read tools plus `ise_api_call` (GET-only) are registered. Everything
is queried from ISE when called; the server never receives or buffers events (pull-only).

### Read (60)

| Tool | What it does |
|---|---|
| `ise_audit_nads` | Audit every network device for common misconfigurations: no RADIUS or TACACS+ secret, short shared secrets, the same secret reused on many devices, only the default device groups (so policy can't tell them apart), overlapping IP ranges, well-known SNMP communities, and KeyWrap without keys. |
| `ise_deployment_health` | One-call ISE health check with severity-ranked findings (critical > high > medium > low > info): node sync status, personas/services and redundancy (PAN HA, secondary PAN/MnT, a PSN present); patch and hot-patch level; last configuration backup (flagged when failed or older than 7 days) and repositories; system certificates per node (expired, expiring within cert_warn_days, self-signed EAP/Admin/Portal certs); licence tiers and compliance (flags evaluation licences and days left); AD join points; and the server's own ISE admin account and RBAC groups, flagged when more privileged than the enabled tiers need (I16). |
| `ise_endpoint_360` | Everything ISE knows about one endpoint, in one call: the endpoint record (identity group, static assignment, profile, IP, custom/MDM attributes), its live session (NAD, port, user, PSN), the last authentication attempts with decoded failures, any ANC policy applied, and whether ISE has it on the rejected-endpoints list. |
| `ise_export_csr` | The PEM text of a CSR, ready for any CA (Windows AD CS win_sign_csr, OpenSSL, step-ca, a public CA). |
| `ise_find_session` | Look up the live MnT session for an endpoint by MAC, IP, username or audit session id (give one). |
| `ise_get_ad_join_point` | One Active Directory join point: domain, the AD groups and attributes added for policy, key advanced settings, and whether ISE is joined (with the domains it can see). |
| `ise_get_auth_history` | Recent authentication attempts for an endpoint MAC from MnT (newest first): pass/fail, username, NAD, method/protocol, identity store, authorization profiles, SGT and the failure reason decoded with cause and resolution. |
| `ise_get_auth_list` | Sessions that authenticated successfully in a time window, across all endpoints, from MnT (queried when called): user, MAC, IP, NAS IP and PSN, with counts by NAS IP and user. |
| `ise_get_authz_profile` | Full authorization profile: access type, VLAN, dACL names, ACLs, web redirection, reauth, advanced RADIUS attributes, device profile. |
| `ise_get_backup_status` | Status of the last configuration backup (name, repository, start/end time, status, progress). |
| `ise_get_dacl` | One downloadable ACL with its full ACE text (one ACE per line), IP version and description. |
| `ise_get_definition` | Describe a Cisco ISE API operation (parameters, request fields, required fields) or a schema (fields with types and enums). |
| `ise_get_egress_matrix` | The TrustSec egress policy matrix as cells: source SGT -> destination SGT, the SGACLs applied, the final catch-all rule (permit/deny), and cell status. |
| `ise_get_internal_user` | One internal user: enabled state, identity group names, names/email, password store, expiry, created/modified dates and custom attributes. |
| `ise_get_license_status` | Licensing summary: smart-licensing registration state, connection type, evaluation period, and per-tier (Essentials/Advantage/Premier/Device Admin/...) status, compliance and consumption. |
| `ise_get_nad` | Full configuration of one network device: IPs/subnets, device groups, device profile, RADIUS settings (KeyWrap, DTLS, CoA port), TACACS+, SNMP and TrustSec settings. |
| `ise_get_policy_set` | One policy set with all of its rules in order: authentication rules (condition -> identity source, if-fail/if-not-found actions), authorization rules (condition -> profiles and SGT) and local exceptions, each with hit counts and ids. |
| `ise_get_pxgrid_client` | One pxGrid client: state, the product that registered it, description, groups, and what to do next (approve a pending one; a 'created' account never activated). |
| `ise_get_task` | Status of an asynchronous ISE task (e.g. |
| `ise_list_active_sessions` | List active RADIUS sessions from MnT (user, MAC, endpoint IP, NAS IP and NAD name, PSN, audit session id), plus total, posture and profiler session counts. |
| `ise_list_ad_groups` | Search the joined domain for groups (name as ISE writes it, e.g. |
| `ise_list_allowed_protocols` | List allowed-protocols services (selected by each policy set) and which authentication protocols each permits: PAP, CHAP, MS-CHAPv2, EAP-MD5, EAP-TLS, PEAP, EAP-FAST, TEAP, LEAP. |
| `ise_list_anc_endpoints` | List endpoints that currently have an ANC policy applied (e.g. |
| `ise_list_anc_policies` | List Adaptive Network Control (ANC) policies and their actions (QUARANTINE, PORTBOUNCE, SHUTDOWN, REAUTHENTICATE). |
| `ise_list_authz_profiles` | List authorization profiles (the result of an authorization rule): access type, VLAN, dACL, Airespace/filter ACL, web redirection, reauth timer and voice domain. |
| `ise_list_certificates` | List system (per-node identity) or trusted certificates with what they are used for, issuer, expiry and days left. |
| `ise_list_command_sets` | List TACACS+ command sets (device administration): each command as 'GRANT command args' (PERMIT, DENY, DENY_ALWAYS; args are regexes) and whether unmatched commands are permitted. |
| `ise_list_conditions` | List reusable library conditions (e.g. |
| `ise_list_csrs` | List pending certificate signing requests (CSRs) ISE holds a private key for: friendly name, node, usage, key size, creation time and id. |
| `ise_list_custom_attributes` | List the endpoint custom attribute definitions (name and type: String, Int, Long, Float, Boolean, Date, IP). |
| `ise_list_dacls` | List downloadable ACLs (dACLs) with IP version, number of ACEs and the first ACE. |
| `ise_list_dictionary_attributes` | List the dictionary attributes policy conditions can use, with data type and allowed values (e.g. |
| `ise_list_endpoint_groups` | List endpoint identity groups (e.g. |
| `ise_list_endpoints` | List endpoints ISE knows about (seen via RADIUS/profiling or added by hand): MAC, endpoint identity group, whether the group is static, profile, IP and description. |
| `ise_list_failure_reasons` | Decode ISE authentication failure reasons from the MnT catalog (~800 entries): code, reason, cause and resolution, plus a curated 'likely cause / next step' for common codes. |
| `ise_list_identity_groups` | List user identity groups (e.g. |
| `ise_list_identity_sources` | List where ISE looks users up: identity source sequences (with their ordered stores), Active Directory join points (domain, status) and LDAP servers. |
| `ise_list_internal_users` | List users in the ISE internal user store: username, enabled/disabled, identity groups and email. |
| `ise_list_ip_sgt_mappings` | List static IP-to-SGT mappings (host or subnet -> SGT), with the devices/groups they are deployed to. |
| `ise_list_nads` | List network access devices (switches, WLCs, VPN headends) that ISE accepts RADIUS/TACACS+ from: name, IPs/subnets, device groups (NDGs), whether RADIUS/TACACS secrets and SNMP/TrustSec are configured (never the secret values). |
| `ise_list_ndgs` | List network device groups (NDGs) as full paths like 'Location#All Locations#Sydney' or 'Device Type#All Device Types#Switch'. |
| `ise_list_nodes` | List the ISE nodes in the deployment: hostname, FQDN, IP, roles (PAN/MnT/PSN/Standalone), enabled services (Session = PSN, Profiler, pxGrid, ...) and sync status. |
| `ise_list_patches` | List installed ISE patches and hot patches with install dates, plus the base ISE version. |
| `ise_list_policy_sets` | List policy sets in evaluation order: rank, name, state, the condition that selects the set, its allowed-protocols service, hit count and id. |
| `ise_list_posture_policies` | List posture policies (which OS/identity-group a requirement set applies to): name, enabled, OS, agent type, requirement count and enforcement (MANDATORY/OPTIONAL/AUDIT), compliance module. |
| `ise_list_posture_requirements` | List posture requirements (the checks a policy enforces): name, OS, agent type, the rules it contains, how they are combined (ALL_SUCCEED / ANY_FAIL), and the remediation. |
| `ise_list_profiler_profiles` | List endpoint profiler profiles (ISE ships ~900, e.g. |
| `ise_list_pxgrid_clients` | The pxGrid 2.0 clients registered with ISE (FMC, Catalyst Center, SIEMs, scripts): name, state (pending / enabled / disabled / created), the product that registered it when the name shows it (FMC uses iseagent-* and firesightisetest-*), description and groups. |
| `ise_list_sgacls` | List security group ACLs (SGACLs) with their ACE lines and IP version. |
| `ise_list_sgts` | List TrustSec security group tags (SGTs): name, numeric value (and hex), description and id. |
| `ise_list_shell_profiles` | List TACACS+ shell profiles (device administration): the attributes sent at login, e.g. |
| `ise_list_sxp_bindings` | List the IP-SGT bindings ISE advertises over SXP (static mappings sent to an SXP domain): IP or subnet, SGT and the SXP domains / virtual networks. |
| `ise_list_sxp_connections` | List SXP (SGT Exchange Protocol) connections between ISE nodes and network devices: peer IP and name, the PEER's role (peer_role LISTENER = the device learns IP-SGT bindings from ISE; SPEAKER = ISE learns from the device), SXP version, domain, ISE node and whether it is enabled. |
| `ise_policy_explain` | Predict which policy set and authorization rule a request would match, client-side (ISE has no evaluate API). |
| `ise_pxgrid_status` | Is pxGrid usable for an external consumer such as FMC? |
| `ise_recent_auth_failures` | Failed authentications in the last N minutes, grouped by failure reason (decoded with likely cause and next step) and by NAD, queried from MnT when called. |
| `ise_search_spec` | Search the Cisco ISE OpenAPI spec for operations (method + path) and schemas. |
| `ise_status` | Check the connection to Cisco ISE: product version and API user, which API surfaces answer, and this MCP server's configuration (writes enabled?, TLS verification). |
| `ise_test_ad_user` | Look a user up in AD through the join point (no password, no login) and return their groups, marking the ones added to the join point, i.e. |
| `ise_why_auth_failed` | Diagnose an endpoint's authentication in one call. |

### Write (39)

| Tool | What it does |
|---|---|
| `ise_add_ad_groups` | Make AD groups usable in policy: after this, '<join point>:ExternalGroups EQUALS <group name>' conditions accept them (ise_create_authz_rule). |
| `ise_approve_pxgrid_client` | Approve a pending pxGrid client so it can look up and subscribe to ISE's pxGrid services (sessions, TrustSec, ANC). |
| `ise_bulk_endpoints` | Create, update or delete many endpoints in one ISE bulk task (e.g. |
| `ise_create_ad_join_point` | Create an Active Directory join point (the definition only; no node joins yet). |
| `ise_create_anc_policy` | Create an Adaptive Network Control policy that ise_apply_anc can put on endpoints. |
| `ise_create_authn_rule` | Add an authentication rule to a policy set: conditions -> identity source, with what to do when authentication fails, the user isn't found, or the store is unreachable. |
| `ise_create_authz_profile` | Create an authorization profile (what an authorization rule grants): access type, VLAN, dACL, reauth timer, voice domain. |
| `ise_create_authz_rule` | Add an authorization rule (or local exception) to a policy set: conditions -> result. |
| `ise_create_group` | Create a user identity group or an endpoint identity group, for policy to match on and for users/endpoints to be placed in. |
| `ise_create_internal_user` | Create a user in the ISE internal identity store (for 802.1X/PAP/TACACS+ logins), in the given identity groups. |
| `ise_create_nad` | Add a network access device (switch, WLC, VPN) so ISE accepts its RADIUS and/or TACACS+ requests. |
| `ise_create_ndg` | Create a network device group (location, device type or a custom hierarchy) under an existing parent, so devices can be grouped and policy can match on it. |
| `ise_create_policy_set` | Create a network-access (RADIUS) or device-admin (TACACS+) policy set: the conditions that select it (e.g. |
| `ise_decline_pxgrid_client` | Refuse a pending pxGrid registration (an unknown or unwanted client). |
| `ise_delete_csr` | Delete a pending CSR and its private key on ISE (e.g. |
| `ise_delete_object` | Delete one endpoint, internal user, identity/endpoint group, authorization profile, dACL, SGT, SGACL, device group, ANC policy, TACACS+ command set / shell profile, or AD join point (after ise_leave_ad). |
| `ise_delete_pxgrid_client` | Remove a pxGrid client (any state). |
| `ise_delete_trustsec_object` | Delete a static IP-SGT mapping (SXP listeners withdraw it; devices it was deployed to keep it until the next deploy) or an SXP connection (the session to the device goes down). |
| `ise_generate_csr` | Have ISE generate a key pair and a certificate signing request (one per node). |
| `ise_import_trusted_cert` | Add a CA certificate to ISE's trusted store, so ISE accepts certificates it issued: client certificates for EAP-TLS (client_auth), CA-signed node certificates being bound (ise_auth). |
| `ise_issue_pxgrid_client_cert` | Issue the certificate an external pxGrid consumer (FMC, a SIEM) authenticates to ISE with. |
| `ise_release_rejected_endpoint` | Release endpoints from ISE's rejected list (Context Visibility > Rejected Endpoints), e.g. |
| `ise_set_cert_auth_profile` | A certificate authentication profile tells ISE how to read an EAP-TLS client certificate: which field is the username, and optionally which identity store to look it up in. |
| `ise_set_command_set` | Create a TACACS+ command set, or replace an existing one's command list. |
| `ise_set_custom_attribute` | Create an endpoint custom attribute definition (so endpoints can carry a value that policy matches as 'EndPoints:<name>'), or delete one. |
| `ise_set_dacl` | Create a downloadable ACL, or replace an existing one's ACEs. |
| `ise_set_egress_policy` | Set the TrustSec policy for traffic from one SGT to another (one egress matrix cell): which SGACLs apply and the final catch-all. |
| `ise_set_endpoint` | Add an endpoint by MAC or change an existing one's identity group, description and custom attribute values, e.g. |
| `ise_set_identity_sequence` | An identity source sequence lets one authentication rule handle both certificate (EAP-TLS, via cert_profile) and password users (the stores, tried in order). |
| `ise_set_ip_sgt` | Map a host or subnet to a security group tag, the way servers and other non-802.1X hosts get into TrustSec policy. |
| `ise_set_pxgrid_settings` | Set pxGrid's approval policy (Administration > pxGrid Services > Settings). |
| `ise_set_sgt` | Create a security group tag, or change an existing one's value/description. |
| `ise_set_shell_profile` | Create a TACACS+ shell profile, or update an existing one: the attributes ISE returns when an admin logs in, e.g. |
| `ise_set_sxp_connection` | Create an SXP connection between an ISE node and a network device, or change the existing one for the same peer and domain. |
| `ise_update_authz_profile` | Change an authorization profile's access type, VLAN, dACL, reauth timer, voice domain or description. |
| `ise_update_internal_user` | Enable/disable an internal user, reset their password, or change groups/email/description. |
| `ise_update_nad` | Change a network device: IPs, shared secrets, device groups, description, CoA port or name. |
| `ise_update_policy_rule` | Change one rule in a policy set: enable/disable/monitor it, move it, rename it, replace its conditions, or change its result (authorization profiles, SGT, command sets, shell profile, identity source). |
| `ise_update_policy_set` | Change a policy set: enable/disable/monitor it, replace its conditions, switch its allowed protocols, move it or rename it. |

### Dangerous (15)

| Tool | What it does |
|---|---|
| `ise_api_call` | Call any Cisco ISE REST endpoint (escape hatch for things no other tool covers). |
| `ise_apply_anc` | Put an Adaptive Network Control policy on an endpoint (quarantine, port bounce, shutdown or reauthenticate, depending on the policy's actions). |
| `ise_bind_certificate` | Install a CA-signed certificate on the node that generated its CSR and put it into service for the given roles (EAP, Admin, RADIUS DTLS, portal, pxGrid, SAML, messaging, TACACS). |
| `ise_clear_anc` | Remove the ANC policy from an endpoint (release it from quarantine). |
| `ise_coa_disconnect` | Send a RADIUS CoA disconnect for an endpoint's live session: terminate it, bounce the switch port, or shut the port down (stays down until an admin re-enables it). |
| `ise_coa_reauth` | Send a RADIUS Change of Authorization (reauthenticate) for an endpoint's live session, so new policy (group, profile, ANC) applies now instead of at the next reauth. |
| `ise_delete_certificate` | Delete a system (node identity) or trusted certificate. |
| `ise_delete_nad` | Delete a network device. |
| `ise_delete_policy_rule` | Delete one authentication/authorization rule or local exception from a policy set. |
| `ise_delete_policy_set` | Delete a whole policy set with all its rules. |
| `ise_deploy_ip_sgt` | Push static IP-SGT mappings to their target devices: ISE logs in over SSH with the device configuration deployment credentials in each NAD's TrustSec settings and adds 'cts role-based sgt-map' lines. |
| `ise_join_ad` | Join one or all ISE nodes to the join point's AD domain (creates the computer account). |
| `ise_leave_ad` | Take one or all ISE nodes out of the AD domain: AD-backed logins through this join point stop working there at once. |
| `ise_push_trustsec_matrix` | Send a TrustSec CoA to every TrustSec network device so it downloads the current egress matrix / SGACLs / SGTs now instead of at its refresh timer: the 'Push' button in the ISE GUI. |
| `ise_update_node_services` | Turn services on or off on an ISE node: DeviceAdmin (TACACS+ on port 49, needed before any device-admin policy works), Session (RADIUS: the node is a PSN), Profiler, pxGrid, SXP, PassiveIdentity. |

### Prompts (3)

| Prompt | What it does |
|---|---|
| `ise_quarantine_host` | Contain a host in minutes, each step previewed and verified: find its session, check that an ANC quarantine policy and its authorization rule exist, apply ANC (ISE sends the CoA), verify the quarantine dACL/SGT on the switch, optionally block the IP on the FTDs through FMC, and finish with the exact undo steps. |
| `ise_incident_timeline` | Build one time-ordered incident timeline for a host across ISE, FMC (Firepower) and Catalyst Center, each queried on demand and merged by timestamp. |
| `ise_troubleshoot_endpoint_access` | Why can't this endpoint get on the network? |

The prompts walk a model through ISE and the access switch (via the cml or catc MCP server, when
connected). `ise_troubleshoot_endpoint_access` ends with a preview-only fix, and its fix step offers write
tools only when they are enabled. `ise_quarantine_host` applies ANC (dangerous tier) and, with
`fmc_block=true`, contains the IP on the FTDs through fmc-mcp-server (`fmc_contain_host`). It ends with
the exact undo steps. Without the dangerous tier it gives GUI steps.

### Certificates and EAP-TLS
The certificate tools exchange PEM text, so any CA can sign: Windows AD CS (`win_sign_csr`), OpenSSL,
step-ca or a public CA. Flow: `ise_generate_csr` -> `ise_export_csr` -> sign at the CA ->
`ise_import_trusted_cert` (the CA, `client_auth` for EAP-TLS clients) -> `ise_bind_certificate`
(dangerous; the Admin role restarts the node's application server). For EAP-TLS, add
`ise_set_cert_auth_profile` and `ise_set_identity_sequence`, then use the sequence as an authentication
rule's identity source.

Tested with two CAs:
- **Windows AD CS (the lab's Enterprise Root `mitchcloud-CA`).** The EAP CSR is signed with the
  **WebServer** template (subject and SAN from the CSR; EKU server auth). Client certificates come from the
  **User** template, which builds the subject and UPN SAN from the *requesting* AD account. So the request
  is submitted as that user: `certreq -submit -config <DC>\<CA>`, never without `-config` over WinRM, or
  certreq opens the CA picker and hangs. EAP-TLS for `mcp-alice` passed with mutual validation, matched on
  `CERTIFICATE:Issuer - Common Name equals mitchcloud-CA`.
- **An OpenSSL CA** (the earlier lab CA, and the one the CML `ise-access` recipe generates on its client).
  It needs nothing Windows-specific. Keep it for labs without AD.

A certificate authentication profile with an identity store (an AD join point) makes ISE look the
certificate's user up in AD: AD group rules then work for EAP-TLS, but certificates for users that aren't
in AD fail. The lab profile therefore has no store.

`ise_delete_certificate` blocks deleting a trusted CA that still issued a system certificate (ISE refuses
it).

### pxGrid (for FMC, Catalyst Center and other consumers)
Appliance to appliance only: the server never connects to pxGrid as a client or subscribes (ADR-003).
`ise_pxgrid_status` says whether a consumer can use pxGrid: the persona per node, the certificate bound
to pxGrid (issuer chain through ISE's trusted store, hostname vs the node FQDN, both EKUs) and what port
8910 actually presents (a TLS handshake, nothing sent), plus pending clients. `ise_list_pxgrid_clients` /
`ise_get_pxgrid_client` (FMC registers as `iseagent-*` and `firesightisetest-*`), then
`ise_approve_pxgrid_client`, `ise_decline_pxgrid_client` (ISE's REST API has no Decline: the pending
registration is removed) or `ise_delete_pxgrid_client` (ISE's own `~ise-*` clients are refused).
`ise_set_pxgrid_settings` sets auto-approve for cert-based accounts and password-based accounts; ISE 3.5
can't read these back over REST, so the tool always sets both.

`ise_issue_pxgrid_client_cert` issues a consumer's client certificate in two steps. Step 1 generates an RSA
key and a CSR (Client + Server Authentication EKU) in the server; the key stays in memory for 2 hours,
bound to the caller, and is never logged. Sign the CSR at a CA ISE trusts; Windows AD CS needs a template
with both EKUs (WebServer has server auth only; the lab uses `mcpPxGrid`, created by `build-dc.py`). Step 2
(request_id + the signed certificate) previews the checks (key match, EKU, validity, issuer trusted in ISE
for authentication within ISE) and, on confirm, returns the certificate, the private key (PKCS#8, optionally
encrypted with `key_passphrase`), the CA chain and `server_ca_pem`, the CA the consumer must trust for
ISE's pxGrid server. The key is then forgotten. ISE's own pxGrid certificate is issued with the certificate
tools: `ise_generate_csr usage=PXGRID` (vary the subject from the EAP certificate's, or ISE answers 409) ->
sign -> `ise_bind_certificate use_for=['pxgrid']` (pxGrid restarts on the node for a minute or two).

### Active Directory
`ise_create_ad_join_point` (the join point name becomes the policy dictionary, e.g. `CORP:ExternalGroups`) ->
`ise_join_ad` (dangerous; the domain account and password are passed per call and never stored or shown) ->
`ise_list_ad_groups` -> `ise_add_ad_groups` (names are resolved against the domain first; a bare group name
is accepted when unique) -> authorization rules on `CORP:ExternalGroups equals <domain/OU/group>` (the bare
group name works there too). `ise_get_ad_join_point` shows the join status (ERS has no status call: the
tool reads the trusted domains, which fail with "not joined" otherwise) and `ise_test_ad_user` a user's
groups. `ise_why_auth_failed` adds the join status and the user's groups for AD failures (24408 wrong
password, 24409 disabled, 24415 locked out, 24412/22056 not found, and 15039 when no AD-group rule
matched), and `ise_policy_explain(ad_user=...)` fills `<join point>:ExternalGroups` so AD-group rules
evaluate. ISE must resolve the domain through its name server (CLI `ip name-server`) and reach the DC on
53/88/389/445/3268 with NTP in sync. `ise_leave_ad`, then `ise_delete_object kind=ad_join_point`, removes it.

### TrustSec / SXP
`ise_set_sxp_connection` takes the device's role (`peer_role`, ISE's "Peer Role"). LISTENER means the
device learns bindings from ISE. The node needs the SXP service (`ise_update_node_services`). Static
mappings (`ise_set_ip_sgt`) sent to an SXP domain reach listeners at once. `ise_deploy_ip_sgt` pushes them
over SSH instead, and `ise_push_trustsec_matrix` makes TrustSec devices refresh the egress policy.

## Testing

```bash
uv run pytest                          # unit tests (respx-mocked, includes the tool contract)
uv run python scripts/seed_lab.py      # lab only: mcp-test-* objects + real RADIUS traffic for MnT
uv run pytest tests/live -m live       # live tests against ISE_URL (skipped if unreachable)
uv run python scripts/lab_policy.py up # ISE side of the CML 'ise-access' lab (switch + client); 'down' removes it
ISE_LIVE_SWITCH_MAC=<client MAC> uv run pytest tests/live -m live -k switch   # session/CoA/ANC via the real switch
```

`scripts/seed_lab.py` creates a NAD for this host's source IP and an internal user, then sends RADIUS
PAP requests and an accounting start, so the session/auth-history/CoA tools have real data. The live
write tests create and delete `mcp-test-*` objects.

## Notes and limits

- ERS lists return only id/name, so list tools fetch each item (`detail=true`) for pages of up to
  `ISE_DETAIL_THRESHOLD` items (default 100) with `ISE_DETAIL_CONCURRENCY` (default 5) requests at a
  time; larger pages return names and ids with a note.
- MnT keeps auth history per MAC. `ise_recent_auth_failures` checks a capped set of candidate MACs
  (given, sessions in the window, endpoint database) and reports its coverage; RADIUS that ISE drops
  silently (unknown NAD, wrong secret) leaves no record. `ise_get_auth_list` windows are UTC.
- The ERS spec is synthesised from ISE's SDK data model, with the JSON wrapper names for 46 resources;
  it does not say which operations each resource really supports.
- `ise_deployment_health`: REST reports only the PAN's patch level, has no backup-schedule view and no
  per-node AD join status; the findings say so.
- Pull-only (stutters-mcp-core ADR-003): no pxGrid subscriptions, syslog receivers or pollers.
  TACACS+ live logs have no REST API; device-admin rule hit counts
  (`ise_get_policy_set kind=device-admin`) show which rules matched.
- Condition values for `DEVICE:Location`/`Device Type` are written without the root
  (`All Locations#Sydney`); the tools strip `Location#` if it is given.
- See docs/GAP-ANALYSIS.md for what is and isn't covered, and why.

Not affiliated with or endorsed by Cisco Systems, Inc. MIT licensed.

# Changelog

## 0.11.0 (unreleased)

### Added
- **Config export and diff (I42, #8).** `ise_export_config(scope, path)` exports policy sets with their
  authentication, authorization and local/global exception rules (network access and device admin),
  authorization profiles, dACLs, NADs and NDGs (shared secrets and SNMP communities masked), identity and
  endpoint groups, endpoint custom attributes, SGTs, SGACLs, the TrustSec egress matrix, and TACACS+ command
  sets and shell profiles as YAML. References are names (SGTs and SGACLs in egress cells, endpoint group
  parents), conditions use the write tools' `Dictionary:Attribute operator value` / library-name syntax,
  rules keep their rank and everything else is sorted by name, and ids, links, hit counts and timestamps are
  left out, so two exports of an unchanged ISE are byte-identical apart from `exported_at`. A header carries
  the format version, ISE version, PAN hostname, export time, server version, sections, counts and a digest.
  Returned inline or written to a `.yaml` file. `ise_diff_config(before, after="live")` compares two
  exports, or an export with live ISE, by section: added, removed and changed objects with field-level
  changes; rules match by policy set + rule name, and a rule whose relative order changed is reported as
  moved (one inserted above it is not). Format: `docs/config-export.md` (the input for I43 and I46).
- `ISE_EXPORT_DIR`: confines export files to a directory (relative paths resolve there). Without it, only
  absolute `*.yaml` paths are accepted, and an existing file is only overwritten when it is an earlier export.

### Changed
- New runtime dependency: PyYAML (`types-PyYAML` for mypy in the dev group).

## 0.10.0 (unreleased)

### Added
- **`ise-mcp-server check` preflight (I36, #2; core C21).** Runs without an MCP client: one row per surface
  (OpenAPI, ERS on `ISE_ERS_PORT`, MnT), TLS trust, credentials, the account's ISE admin groups (ERS
  `adminuser`) against the enabled tiers (fails when writes/dangerous are on without ERS Admin / Super Admin,
  warns when a read-only server runs as Super Admin), and the ISE version against the tested matrix (3.5; 3.1
  minimum). Text or `--json`, `--strict`, `--instance`; exit 1 on a failure; every `ISE_INSTANCES` deployment.
  `serve --http` / `serve --stdio`. README quickstart for a release wheel (`uvx --from`) and for the image,
  with Claude Code / Claude Desktop config. PyPI publishing stays open (deferred).
- **Published image (I37, #3; core C22).** `release.yml` calls core `publish-image.yml`:
  `ghcr.io/dr-stutters/ise-mcp-server` for amd64 and arm64, cosign keyless signature, SPDX SBOM attestation;
  `<version>` + `latest` on releases, `<version>-rcN` + `rc` on pre-release tags. `docker-compose.yml` pulls it
  (`MCP_IMAGE_TAG`; `--build` still builds locally).
- **Shared-host guide and example (I38, #4).** `docs/deploying.md` (read-only defaults, per-user tokens and the
  audit log, several deployments with `ISE_INSTANCES`, Caddy TLS, the least-privilege account step by step,
  upgrades and verifying signatures) and `examples/shared-host/` (server + Caddy, and a test override with two
  mocked ISE deployments). Contract tests pin the tier defaults (`tests/unit/test_tier_defaults.py`).

### Changed
- Bundled core v0.14.0.

### Changed
- **stutters-mcp-core is bundled into the package (I35, #1; core C20 / ADR-005).** The wheel, sdist and image
  carry core v0.13.0 as `ise_mcp._core`, so installing needs no git dependency and Docker needs no
  `CORE_READ_TOKEN`. The pin is `[tool.bundle-core]` (tag + commit) in `pyproject.toml`; core's runtime
  dependencies are listed in the server's own. `scripts/bundle_core.py` vendors it (`vendor`, after a clone),
  checks for drift (`check`) and moves the pin (`update --tag`). Code and tests import `ise_mcp._core`; importing
  the package without the bundle says how to fix it.
- `ise_status` reports the bundled core version (`server.core_version`).
- CI: the core `bundle-core.yml` job vendors, fails on drift, builds the wheel and sdist, installs the wheel
  with `pip install --no-index` in a clean venv and runs the unit + contract suite against it. The release
  builds the image from the bundled wheel.

### Removed
- The git source for stutters-mcp-core and `CORE_READ_TOKEN` (Dockerfile build secret, compose, workflows).
- **De-lab (I39, #5):** `scripts/seed_lab.py` and `scripts/lab_policy.py` moved to the suite's private lab repo
  (stutters-mcp-lab), with the lab-state assertions of the deployment-health live test.

### Live tests
- Lab-specific inputs come from documented `ISE_LIVE_*` variables (environment or `.env`; see
  `docs/live-tests.md` and `.env.example`): `ISE_LIVE_SWITCH_IP`, `ISE_LIVE_SWITCH_NAME`,
  `ISE_LIVE_AD_JOIN_POINT`, `ISE_LIVE_AD_GROUP`, `ISE_LIVE_AD_USER`, `ISE_LIVE_CA_NAME`, `ISE_LIVE_CA_PEM`,
  `ISE_LIVE_PXGRID_SIGNER` (was `LAB_PXGRID_SIGNER`), `ISE_LIVE_PXGRID_DOMAIN` and `ISE_LIVE_SXP_PEER`, next to
  the existing `ISE_LIVE_SWITCH_MAC` and `ISE_LIVE_SCALE`. Tests skip with a message naming the variable
  when it is unset; `docs/live-tests.md` also lists the seeded `mcp-test-*` objects and the switch test policy
  the tests expect. `test_live_policy_explain` now skips (instead of failing) when ISE is not configured.
- Lab names and addresses replaced with example values in the AD MnT fixture, unit tests and the
  `ise_list_ad_groups` description.

## 0.9.0 (2026-10-16)

### Added
- **pxGrid client management + certificates for consumers (I30, #71).** Read: `ise_list_pxgrid_clients`
  (state pending / enabled / disabled / created, and the product that registered it: FMC `iseagent-*` /
  `firesightisetest-*`, Catalyst Center), `ise_get_pxgrid_client`, `ise_pxgrid_status` (persona per node; the
  pxGrid certificate's issuer chain through ISE's trusted store, hostname vs node FQDN, both EKUs, and what
  8910 presents via a TLS handshake; pending clients; problems a consumer would hit). Write:
  `ise_approve_pxgrid_client`, `ise_decline_pxgrid_client` (ISE has no REST Decline: the pending registration
  is removed), `ise_delete_pxgrid_client` (refuses ISE's own `~ise-*` clients), `ise_set_pxgrid_settings`
  (auto-approve cert-based / allow password-based; write-only on ISE 3.5), `ise_issue_pxgrid_client_cert`
  (two steps: key + CSR generated in the server and held in memory for 2 h, bound to the caller; then the
  signed certificate is checked and the bundle - certificate, private key (optionally encrypted), CA chain,
  pxGrid server CA - is returned once). The server never connects to pxGrid as a client (ADR-003).
- `scripts/lab_policy.py pxgrid`: pxGrid settings; ISE's pxGrid certificate from the lab CA (CN = node FQDN,
  template `mcpPxGrid`); FMC's pxGrid client certificate written to `~/MCP-Suite/lab-ca/fmc-pxgrid.*` (key
  mode 600).
- `cryptography` is a direct dependency.


## 0.8.0 (2026-10-16)

### Added
- **Active Directory (I11, #18):** `ise_get_ad_join_point` (config + join status), `ise_list_ad_groups`,
  `ise_test_ad_user` (read); `ise_create_ad_join_point`, `ise_add_ad_groups` (write); `ise_join_ad`,
  `ise_leave_ad` (dangerous; the domain account is passed per call and never stored or shown).
  `ise_delete_object kind=ad_join_point` (blocked while joined). A single-node join sends the node FQDN, which
  ISE 3.5 requires.
- `ise_why_auth_failed` adds the join status and the user's AD groups for AD failures (244xx/247xx, 22056, a
  non-local identity store). It explains 15039 when no AD-group rule matched, and uses the given `username`
  when MnT records the user as `INVALID`.
- `ise_policy_explain(ad_user=...)` fills `<join point>:ExternalGroups` with the user's groups that are added to
  the join point. Attributes may be lists, for multi-valued attributes.
- `ExternalGroups` conditions accept a unique bare group name (`mcp-employees`).
- `scripts/lab_policy.py ad` / `ad-down` / `certs`: AD join point and rules; lab CA trust, an EAP certificate
  signed by the lab AD CS, and the EAP-TLS rule (idempotent).

### Fixed
- AD failure hints rebuilt from ISE's catalog. **24415** is "account locked out" (the hint said the join point
  was unreachable), and **24419** is "attribute retrieval failed" (it said locked or disabled). New hints for
  24406-24414, 24417, 24428/24429, 24446/24447, 24465, 24493/24494, 24708 and 25058. AD execution steps are decoded.
- `ise_delete_certificate` blocks deleting a trusted CA that still issued a system certificate (ISE refuses
  with 400). A 422 without detail on a system certificate now points to the GUI.

### Docs
- README: Active Directory section; certificates tested with Windows AD CS (WebServer / User templates) and with
  OpenSSL. least-privilege.md: the AD query operations are ERS PUTs, so they need ERS Admin.

## 0.7.2 (2026-10-15)

### Fixed
- **Write previews show what a PUT removes** (core 0.12.4 `field_changes(..., replace=True)`): every update that
  sends the whole object (ERS PUT, OpenAPI policy PUT) now lists fields the replacement drops as
  `"removed": true` instead of hiding them: `ise_update_nad`, `ise_update_internal_user`, `ise_set_endpoint`,
  `ise_update_authz_profile` (vlan/dacl '' removes them), `ise_set_dacl`, `ise_set_sgt`, `ise_set_egress_policy`,
  `ise_set_command_set`, `ise_set_shell_profile`, `ise_set_cert_auth_profile`, `ise_set_identity_sequence`,
  `ise_update_policy_set`, `ise_update_policy_rule`, `ise_set_ip_sgt` (deploy_to='all' drops the target) and
  `ise_set_sxp_connection`. Removed secrets stay masked.
- `ise_update_internal_user` doesn't list the password fields it leaves out of the PUT (ISE keeps the stored
  password when they are omitted).

### Changed
- Core bumped to stutters-mcp-core 0.12.4. Cross-server manifests (`tests/manifests/fmc.json`, `catc.json`)
  refreshed from their repos.

## 0.7.1 (2026-10-15)

### Changed
- Core bumped to stutters-mcp-core 0.12.2 (0.10-0.12: optional MCP background tasks, per-instance write
  rules, audit log rotation, per-caller rate limit, `ise-mcp-server config`).
- `ise_search_spec` / `ise_get_definition` descriptions use ISE examples ('network device group',
  '/ers/config/networkdevice/{id}') via the new `ServerSpec` options.
- `ise_status`: the server version is now reported by core as `server.server_version`; the duplicate
  `ise.server_version` field was removed.

## 0.7.0 (2026-10-15)

Operator-eyes quality pass: 12 realistic operator tasks were run end to end through the MCP tools
against the live lab, the way a model would; every real problem became a roadmap item (I22-I29).

### Fixed
- **I22:** CoA / dynamic-authorization records (MnT msg 5417/5205, 112xx, CoA packet types) are no
  longer read as login failures. `ise_why_auth_failed` said "latest attempt FAILED: None" (a CoA NAK)
  and "FAILED: 11215" for endpoints whose last login passed. Rows are labelled `kind: coa`; the verdict
  uses logins only and failed CoAs are summarised in `coa_failures` with what they mean.
- **I23:** `ise_policy_explain` predicted Default/DenyAccess for a MAB login from sw1 when given the
  NAD's group as shown by the NAD tools ('Location#All Locations#X'); ISE stores conditions without the
  NDG root. DEVICE:* values are normalised. New `nad` (groups, name, NAS IP) and `flow`
  (wired-mab, wired-dot1x, wireless-mab, wireless-dot1x) inputs fill the request attributes; filled
  values are listed in `assumed_attributes` and caller attributes (also bare names) win.
- **I29:** a session whose latest accounting is Stop is reported as ended (`active: false`); the CoA
  tools block on it and the ANC preview no longer claims a live session.

### Changed
- **I24:** NAD lookups list the names that contain the key; read tools use a single containing match
  and say so (`resolved_from` / "partial match"). `ise_list_active_sessions` takes `nad` (name or NAS IP;
  `nas_ip` kept as a deprecated alias) and returns normalised columns (user, mac, ip, nas_ip, nad, psn)
  with the NAD name ("no NAD covers it" for stale sessions). `ise_list_profiler_profiles`: `name`
  filter (was `name_contains`).
- **I25:** `ise_get_egress_matrix(source, destination)` with no explicit cell returns the effective
  ANY-ANY default in `effective`.
- **I26:** instructions name `ise_policy_explain` and the egress pair lookup, and say what has no REST
  API (configuration change audit, TACACS+ live logs). `ise_endpoint_360` points at
  `ise_release_rejected_endpoint` and says "not profiled". ANC previews say how to verify.
- **I27:** auth rows carry a compact `reply` (dACL, SGT, VLAN, redirect, CoA command) instead of the raw
  `response` with Class / EAP-Key-Name / MS-MPPE keys; `ise_find_session` drops duplicate and internal
  fields (~40% smaller); `ise_why_auth_failed` shows execution steps only when the latest login failed.
- **I28:** authorization profiles are looked up by `GET .../name/{name}` (the list scan took ~3.5 s);
  `ise_update_authz_profile` preview 9.6 s -> 2.1 s live.

## 0.6.1 (2026-10-15)

### Fixed
- **I13/I21:** `ise_policy_explain` now fetches and evaluates **global** authorization exceptions
  (ISE evaluates them before every policy set's rules), shown with `section='global-exception'`. v0.6.0
  only disclosed this gap in `limits`.

## 0.6.0 (2026-10-15)

Roadmap "Later" items: policy explain (I13), the incident-timeline prompt (I15), and a read-only slice
of guest/profiler/posture (I14).

### Added
- **I13 `ise_policy_explain`:** predict which policy set and authorization rule a request would hit,
  client-side (ISE has no evaluate API). Walks sets then local exceptions then authorization rules in
  rank order, evaluating the conditions it understands (And/Or/negate, equals/contains/startsWith/in/
  matches/numeric) against supplied `Dictionary:Attribute` values; resolves library references
  (including built-ins such as Wired_MAB) by id. Conditions it can't evaluate (missing attribute,
  unresolved reference, posture/profiler/time, attribute-vs-attribute) are reported as `unknown`, never
  guessed, and the verdict is marked UNCERTAIN when an unknown rule outranks the first match. Global
  exceptions are not fetched (disclosed in `limits`). Live-verified against the lab's MAB path.
- **I15 prompt `ise_incident_timeline`:** one time-ordered incident timeline for a host across ISE, FMC
  and Catalyst Center, each queried on demand and merged by timestamp; the FMC/CatC steps are skipped
  with a note when those servers aren't connected. Read-only.
- **I14 (read slice):** `ise_list_profiler_profiles` (name filter), `ise_list_posture_policies`
  (`enabled_only`), `ise_list_posture_requirements` — read-only summaries. Guest/sponsor and posture
  assessment stay in Later (need a sponsor REST account / agent endpoints).

### Changed
- 99 tools + 3 prompts (was 96 + 2). The prompt contract test now validates every fmc_*/catc_*
  reference against the copied `tests/manifests/{fmc,catc}.json`.

## 0.5.0 (2026-10-15)

Production gate (I16, I18, I19) and a robustness fix (I20), on core v0.9.0. I17 (version matrix) is
skipped: only ISE 3.5 is available in the lab.

### Added
- **I16 least-privilege roles** (`docs/least-privilege.md`): built-in ISE RBAC admin groups per server
  tier (read = ERS Operator + Read Only Admin; write = ERS Admin + functional groups; dangerous =
  Super Admin). `scripts/seed_lab.py --least-privilege` creates `mcp-test-ro`/`-rw`/`-admin`
  (idempotent; on the known ISE 3.5 admin-user-500 bug it prints the GUI steps).
  `tests/live/test_least_privilege.py` runs the read tier as the read-only account (core G3 helper).
- **I16 privilege check:** `ise_deployment_health` reports the server's own account and RBAC groups
  (`server_privilege`) and flags a Super Admin account when only read/write tiers are enabled.
- **I18 safety rails** (on core G7): protect-lists `ISE_PROTECT_MACS` / `ISE_PROTECT_USERS` /
  `ISE_PROTECT_NADS` (a CoA, ANC or NAD-delete on a protected target is blocked); a shared-port guard
  that blocks `port_bounce`/`port_shutdown` (CoA or ANC) on a switch port with more than one live
  session unless `ISE_COA_ALLOW_SHARED_PORT=true`; `blast_radius` on CoA, ANC, bulk-endpoint and
  node-service tools for `MCP_MAX_BLAST_RADIUS`.
- **I19 multi-node:** `ise_status` reports a `deployment` summary (mode, PAN, primary/secondary MnT
  with a failover note, PSNs, unreachable nodes, ERS port) and the surface-routing model. CoA/ANC are
  routed to the PSN that owns each session (`acs_server`). Distributed handling is mock-tested (the
  lab is standalone); a second deployment is a core instance (`ISE_INSTANCES`, G10).

### Fixed
- **I20:** retry ISE's transient policy-API HTTP 500 (Hibernate/JDBC: "could not prepare statement",
  "two open Sessions", deadlocks) on reads and idempotent writes (GET/PUT/DELETE, not POST) with
  backoff. Core only retries 502/503/504; these intermittent 500s failed the live suite.

### Changed
- Core pinned to `v0.9.0` (per-user roles G2, safety rails G7, metrics G5, several appliances G10).
  `ISE_ERS_PORT` is per-instance (a second ISE may serve ERS on 9060).

## 0.4.0 (2026-10-15)

Roadmap "Next" (I8–I10). I11 (AD join points) moved to Later: the lab ISE can't resolve a lab AD domain
(name servers are CLI-only). Pull-only, as before.

### Added
- **I9 TrustSec writes:** `ise_list_sxp_connections`, `ise_list_sxp_bindings` (read); `ise_set_ip_sgt`
  (create/update by IP/CIDR; SGT by name, value or id; SXP domains; deploy target all/NAD/NDG),
  `ise_set_sxp_connection` (by peer + domain; `peer_role` = ISE's "Peer Role"), `ise_delete_trustsec_object`
  (write); `ise_push_trustsec_matrix` (TrustSec CoA push), `ise_deploy_ip_sgt` (SSH deploy) (dangerous).
- **I8 certificates:** `ise_list_csrs`, `ise_export_csr` (read); `ise_generate_csr`, `ise_import_trusted_cert`,
  `ise_set_cert_auth_profile`, `ise_set_identity_sequence`, `ise_delete_csr` (write); `ise_bind_certificate`
  (dangerous; the Admin role warns about the app-server restart). CA-agnostic (PEM in/out).
- **I10 prompt `ise_quarantine_host`:** session -> ANC policy/rule check -> `ise_apply_anc` -> ISE and switch
  verification -> optional `fmc_contain_host` -> undo (`ise_clear_anc`, `fmc_release_host`). Tier-aware.
- `tests/manifests/ise.json` (core prompt test kit manifest) for the other servers' cross-reference checks.

### Changed
- Core pinned to `v0.4.0` (prompt test kit; `get_definition(examples=True)` from 0.3.1).
- `ers_request`/`ers_create` take a per-request `timeout` (SXP writes take 30–60 s on ISE 3.5).
- Failure knowledge for 12514 (client cert from an untrusted CA) and 12520.

## 0.3.0 (2026-10-15)

Roadmap "Now" (I1–I6). Pull-only: every tool queries ISE when called (stutters-mcp-core ADR-003).

### Added
- `ise_get_auth_list`: sessions authenticated in a time window (MnT AuthList, UTC), filtered by NAD or
  user, with counts by NAS IP/user; `detail=true` adds method, authorization profile, SGT and matched policy.
- `ise_recent_auth_failures`: failed attempts in the last N minutes grouped by decoded reason (likely cause,
  next step) and NAD. MnT has no cross-endpoint failure query, so it checks a capped set of candidate MACs
  and reports its coverage; CoA records are excluded by default.
- Prompt `ise_troubleshoot_endpoint_access` (core `@reg.prompt`): MAC/user/IP -> session -> failure ->
  policy -> NAD -> ANC -> switch CLI via cml/catc -> diagnosis -> preview-only fix.
- `ise_deployment_health`: severity-ranked findings for nodes, redundancy, patches, backup, repositories,
  certificates, licence and AD join points.
- `ise_bulk_endpoints` (create/update/delete as one ISE task, conflicts left out, 500 per call),
  `ise_get_task`, `ise_list_custom_attributes`, `ise_set_custom_attribute`, `ise_release_rejected_endpoint`;
  `ise_set_endpoint` takes `custom_attributes`.
- `ise_status` reports `server_version` (next to core's `core_version`).
- Settings `ISE_DETAIL_THRESHOLD` (100) and `ISE_DETAIL_CONCURRENCY` (5).
- `scripts/tool_table.py` regenerates the README tool tables.

### Changed
- Core pinned to `v0.3.0` (pull-only; `Page.more` keeps `next_offset` for lists without a total).
- ERS list tools skip per-item detail GETs above `ISE_DETAIL_THRESHOLD` and say so; name->id maps are
  reused for 60 s and cleared by any ERS write.
- `ise_list_internal_users(group=)` and `ise_get_egress_matrix(source/destination)` filter server-side
  instead of scanning (the matrix read is capped at 2000 cells with a note).
- The synthesised ERS spec shows request body wrappers (`{"NetworkDevice": {...}}`) for 46 resources.
- Server instructions point at the recent-activity and health tools.

### Fixed
- Conditions on endpoint custom attributes (`EndPoints:<name>`) validate against ISE's custom-attribute
  definitions too: ISE 3.5's policy dictionary sometimes drops them (seen live).

## 0.2.0 (2026-10-14)

Phase 2: gap analysis against the ISE 3.5 API (docs/GAP-ANALYSIS.md) and live tests with a real
Catalyst 9000v switch and client in CML (MAB, 802.1X PEAP/EAP-MD5, dACL + SGT, CoA, ANC, TACACS+).

### Added
- Policy editing: `ise_create_policy_set`, `ise_update_policy_set`, `ise_create_authn_rule`,
  `ise_update_policy_rule` (state, rank, rename, conditions, profiles/SGT, command sets/shell profile,
  identity source), for network access and device admin.
- `ise_list_dictionary_attributes`: the attributes and allowed values conditions can use.
- Device admin (TACACS+): `ise_list_command_sets`, `ise_list_shell_profiles`, `ise_set_command_set`,
  `ise_set_shell_profile`, and `ise_update_node_services` (dangerous) to enable the Device Admin service.
- `ise_delete_object` deletes command sets and shell profiles (blocked while a device-admin rule uses them).
- `scripts/lab_policy.py up|down`: the ISE side of the CML `ise-access` lab, built through the tools.

### Changed
- `ise_create_authz_rule` takes `kind` (device-admin rules with command sets + shell profile),
  `section` (local exceptions) and `match` (AND/OR). Conditions are checked against ISE's dictionaries
  (unknown attributes get "did you mean", enum values are validated and canonicalised). Profiles, SGTs,
  command sets and shell profiles are checked against ISE before anything is sent.
- `ise_apply_anc` warns when no authorization rule matches `Session:ANCPolicy` (QUARANTINE would do
  nothing) and lists the rules that do. `ise_clear_anc` says that it ends the session.
- `ise_endpoint_360` flags endpoints on ISE's rejected-endpoints list.
- `ise_find_session` says when MnT's latest event is accounting/CoA without the auth result.
- `ise_why_auth_failed` explains the no-record case (ISE silently drops RADIUS from unknown NADs and on
  secret mismatch; the switch logs "RADIUS server not responding").
- Server instructions cover policy editing, device admin and quarantine.

### Fixed
- `DEVICE:Location` / `Device Type` condition values are sent without the root (`All Locations#X`).
  ISE rejected the full path with "not a permitted option".
- `ise_apply_anc` confirm failed when the session re-authenticated between preview and confirm. The CoA
  tools no longer fingerprint the framed IP, which DHCP fills in after the session starts.
- `ise_set_dacl` refuses a no-op update instead of issuing an empty-diff confirm.
- `ise_update_node_services` confirm args use the caller's `node` (not the resolved host); renames are
  checked for collisions; empty `conditions` on update is rejected; ANC rule detection matches the exact
  policy name; `ise_set_command_set` keeps `permit_unmatched` unless given.
- The failure hint for 12001 was wrong (12001 is a normal EAP-MD5 NAK step). EAP-MD5/PEAP steps are now
  decoded, and hints were added for 22063 and 11509.

## 0.1.1 (2026-10-14)

- Core 0.1.1: MnT calls use the normal auth/retry path (`ok_status`), nested secrets are masked in the
  audit log, and flag values such as `enableMultiSecret` are no longer shown as `********`.
- Docker image includes LICENSE; `.dockerignore` added.

## 0.1.0 (2026-10-14)

First release, built on stutters-mcp-core 0.1.0.

- Three ISE surfaces (OpenAPI, ERS, MnT) behind one rate limiter. `ise_status` probes each surface;
  `ISE_ERS_PORT` selects the ERS port. ERS CSRF tokens are handled automatically.
- Troubleshooting: `ise_why_auth_failed`, `ise_endpoint_360`, `ise_audit_nads`, session lookups by
  MAC/IP/user/session id, auth history and failure-reason decoding.
- Read tools for NADs/NDGs, endpoints and groups, internal users and identity groups, identity sources,
  policy sets with rendered rules, authorization profiles, dACLs, allowed protocols, conditions, SGTs,
  SGACLs, the egress matrix, IP-SGT mappings, ANC, nodes, licensing, patches, backups and certificates.
- Spec search/definition/raw calls across all three surfaces (OpenAPI groups, an ERS spec synthesised
  from the SDK data model, and MnT).
- Preview-first write tools (NADs, NDGs, endpoints, users, groups, authz profiles, dACLs, SGTs, egress
  cells, ANC policies, authz rules, object deletes) and dangerous tools (CoA, ANC apply/clear, NAD, policy
  and certificate deletes).
- `scripts/seed_lab.py` seeds a lab with mcp-test-* objects and real RADIUS traffic.

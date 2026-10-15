# Changelog

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

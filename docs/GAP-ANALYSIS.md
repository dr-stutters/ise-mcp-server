# ISE 3.5 API gap analysis (v0.11.0, refreshed 2026-10-18)

Lab: ISE 3.5.0.527 patches 3 and 4, standalone node. The counts come from the live ISE through the same
loaders the server uses for `ise_search_spec` (`src/ise_mcp/specs.py`): the 31 springfox OpenAPI groups
(`/api/swagger-resources`, then `/api/v3/api-docs?group=...`), the ERS SDK data model
(`/ers/data-model.json`, synthesised into list/create/get/update/delete per resource) and the hand-written
MnT doc. The tool side is a static scan of `src/ise_mcp/tools/`: every `@reg.read/write/dangerous` function
and the helpers it calls, mapped to the client calls they make (see [How to re-run](#how-to-re-run)).

"Covered" means some curated tool calls that operation (a tool that only reads an object's name still counts
the GET it uses). It does not mean the tool exposes every field. Counting operations makes coverage look
low: posture content (203 operations), the TrustSec integration rules (ACI, Secure Workload, Meraki, SXP
domains: 120 of TrustSec's 154), Exim (30), Provisioning (31), Rbac (28), FiveG, Prometheus, Duo/MFA/OIDC
and pxGrid Direct/Cloud are large content models or niche integrations that the GUI handles better. The 232
operations in the groups operators touch daily (Policy, Certificates, Endpoints, CustomAttributes,
Deployment, License, Patch, Backup, Repository, Task) are **47 % covered** (108 of 232). **Everything is
reachable through `ise_api_call`** (all three surfaces, any method when the dangerous tier is on), and
`ise_search_spec` / `ise_get_definition` describe it.

## 1. The API surface (v0.11.0: 138 tools + 4 core tools, 3 prompts)

| Surface | Operations | Behind a curated tool | Tools using it | v0.2.0 (2026-10-15) |
|---|---|---|---|---|
| OpenAPI `/api/v1` | 849 in 31 groups | **118 (13 %)** | 60 | 76 (9 %) |
| ERS `/ers/config` | 82 resources (410 synthesised CRUD operations) | **39 resources, 143 operations (34 %)**, plus 20 operations the data model does not list | 95 | 20 resources |
| MnT `/admin/API/mnt` | 14 calls | **13 (92 %)**; `Session/ActiveCount` is left out because `ise_list_active_sessions` returns the total | 15 | 12 |
| pxGrid | WebSocket/STOMP pub-sub | Out of scope (ADR-003: no subscriptions); pxGrid *administration* (clients, approval, certificates) is covered through ERS `pxgridnode` and the Certificates group | | |

### OpenAPI groups

| Group | Operations | Covered | Tools (without the `ise_` prefix) |
|---|---|---|---|
| Policy | 138 | 73 (52 %) | admin_policy_explain, apply_anc, create_authn_rule, create_authz_rule, create_policy_set, delete_object, delete_policy_rule, delete_policy_set, get_authz_profile, get_policy_set, import_config, list_conditions, list_dictionary_attributes, list_policy_sets, policy_explain, test_command_set, update_authz_profile, update_policy_rule, update_policy_set, why_auth_failed |
| Certificates | 22 | 11 (50 %) | bind_certificate, delete_certificate, delete_csr, deployment_health, export_csr, generate_csr, import_trusted_cert, issue_pxgrid_client_cert, list_certificates, list_csrs, pxgrid_status |
| Endpoints | 12 | 7 (58 %) | bulk_endpoints, delete_object, endpoint_360, explain_profile, list_endpoints, recent_auth_failures, release_rejected_endpoint, reprofile_endpoint, why_auth_failed |
| Profiler | 40 | 6 (15 %) | delete_profiling_rule, explain_profile, list_profiling_rules, profiler_status, set_profiling_rule |
| License | 11 | 5 (45 %) | deployment_health, get_license_status |
| Deployment | 24 | 4 (16 %) | list_nodes, deployment_health, update_node_services, join_ad / leave_ad, and the 14 tools that read `/deployment/node` for hostnames (certificates, pxGrid, SXP, config export/import, profiler) |
| CustomAttributes | 5 | 3 (60 %) | list_custom_attributes, set_custom_attribute, bulk_endpoints, set_endpoint, import_config, and the policy write tools (conditions on `EndPoints.<attr>`) |
| Patch | 6 | 2 (33 %) | deployment_health, list_patches |
| Posture | 203 | 2 (0 %) | list_posture_policies, list_posture_requirements |
| TrustSec | 154 | 2 (1 %) | list_ip_sgt_mappings, push_trustsec_matrix (SGTs, SGACLs, the egress matrix, IP-SGT writes and SXP use ERS) |
| Backup Restore | 6 | 1 (16 %) | deployment_health, get_backup_status |
| Repository | 6 | 1 (16 %) | deployment_health |
| Task Service | 2 | 1 (50 %) | bulk_endpoints, get_task |
| Dataconnect 5, Duo IdentitySync 10, Endpoint Replication 2, Exim 30, FiveG 16, IPsec 9, Integration Catalog 5, LSD Settings 2, MFA 8, OIDC 9, Patch and Upgrade 20, Prometheus AlertManager 16, Provisioning 31, Rbac Catalog 28, SGT Reservation 5, System Settings 4, pxGrid Cloud 6, pxGrid Direct 14 | 220 | 0 | `ise_api_call` only (see [Not built](#3-not-built-with-reasons) and [Candidates](#4-candidates-from-the-live-swagger)) |

### ERS resources (39 of 82 used)

| Resource | Methods used | Tools |
|---|---|---|
| network.networkdevice | GET, POST, PUT, DELETE | list_nads, get_nad, audit_nads, create_nad, update_nad, delete_nad, export/import/diff_config, and the session, policy-explain and SXP tools that resolve NAD names |
| network.networkdevicegroup | GET, POST, PUT, DELETE | list_ndgs, create_ndg, delete_object, export/import/diff_config, set_ip_sgt |
| network.downloadableacl | GET, POST, PUT, DELETE | list_dacls, get_dacl, set_dacl, create/update_authz_profile, delete_object, export/import/diff_config |
| policy.authorizationprofile | GET, POST, PUT, DELETE | list_authz_profiles, get_authz_profile, create/update_authz_profile, delete_object, export/import/diff_config |
| policy.allowedprotocols | GET | list_allowed_protocols |
| policy.tacacscommandsets, policy.tacacsprofile | GET, POST, PUT, DELETE | list_command_sets, set_command_set, test_command_set, list_shell_profiles, set_shell_profile, admin_policy_explain, delete_object, export/import/diff_config |
| policy.tacacsexternalservers, policy.tacacsserversequence | GET, POST, PUT, DELETE | get_tacacs_servers, set_tacacs_server, set_tacacs_server_sequence, delete_object |
| identity.internaluser, identity.identitygroup | GET, POST, PUT, DELETE | list/get/create/update_internal_user, list_identity_groups, create_group, delete_object, why_auth_failed, policy explain, export/import_config |
| identity.endpoint, identity.endpointgroup | GET, POST, PUT, DELETE | set_endpoint, list_endpoints, list_endpoint_groups, create_group, bulk_endpoints, endpoint_360, delete_object, import_config |
| identity.profilerprofile | GET | list_profiler_profiles, explain_profile, reprofile_endpoint, endpoint_360, list_endpoints |
| identity.guestuser (as the sponsor), identity.guesttype, identity.sponsorgroup | GET, POST, PUT, DELETE | list/get/create/update/extend/suspend/reinstate/delete_guest_user, list_guest_types, set_guest_type, list_sponsor_groups, set_sponsor_group |
| identity.guestlocation, identity.sponsorgroupmember, portal.guestssid | GET | get_guest_locations, create_guest_user, set_sponsor_group |
| portal.sponsorportal, portal.sponsoredguestportal, portal.selfregportal, portal.hotspotportal | GET | list_guest_portals (sponsor portal id for guest accounts) |
| identitystores.activedirectory | GET, POST, DELETE + join, leave, getTrustedDomains, getGroupsByDomain, getUserGroups, addGroups | create_ad_join_point, join_ad, leave_ad, get_ad_join_point, list_ad_groups, add_ad_groups, test_ad_user, list_identity_sources, deployment_health, why_auth_failed, policy_explain |
| identitystores.idstoresequence, ca.certificateprofile | GET, POST, PUT | set_identity_sequence, set_cert_auth_profile, list_identity_sources |
| identitystores.ldap, identity.adminuser | GET | list_identity_sources, deployment_health |
| trustsec.sgt, trustsec.sgacl, trustsec.egressmatrixcell | GET, POST, PUT, DELETE | list_sgts, set_sgt, list_sgacls, get_egress_matrix, set_egress_policy, delete_object, export/import/diff_config |
| trustsec.sgmapping (+ deploy, deploy/all, deploy/status) | GET, POST, PUT, DELETE | set_ip_sgt, deploy_ip_sgt, delete_trustsec_object |
| sxp.sxpconnections | GET, POST, PUT, DELETE | list_sxp_connections, set_sxp_connection, delete_trustsec_object |
| sxp.sxplocalbindings, sxp.sxpvpns | GET | list_sxp_bindings, set_ip_sgt, set_sxp_connection |
| anc.ancpolicy | GET, POST, DELETE | list_anc_policies, create_anc_policy, apply_anc, delete_object |
| anc.ancendpoint (+ apply, clear) | GET, PUT | list_anc_endpoints, apply_anc, clear_anc, endpoint_360 |
| pxgrid.pxgridnode (+ name/{name}, approve) | GET, PUT, DELETE | list/get/approve/decline/delete_pxgrid_client, pxgrid_status |
| pxgrid.pxgridsettings (autoapprove) | PUT | set_pxgrid_settings |

No curated tool (43 resources): acisettings, acibindings, ctsenvdata, ctsmatrix, reportconfig, sgacls (legacy),
sgmappinggroup, sgtvnvlan, trustsecmatrixsettingsrequest, workflowmatrixsettings (TrustSec settings and ACI);
certificatetemplate, endpointcert, systemcertificate (internal CA and ERS system certs; the OpenAPI
Certificates group is used instead); node, sessionservicenode, service (the OpenAPI Deployment group is used
instead); externalradiusserver, radiusserversequence (RADIUS proxy); restidstore and its five attribute
resources, adresourcereservation (REST ID store, Azure AD); authorizationrule (legacy); byodportal,
mydeviceportal, portal, portalglobalsetting, portaltheme, nspprofile (portal customisation and BYOD);
guestsmtpnotificationsettings, smsprovider (guest notifications); supportbundle, supportbundledownload,
supportbundlestatus; telemetryinfo, deploymentinfo; filterpolicy (SXP filters); threat (IRF).

### MnT

| Call | Covered by |
|---|---|
| `Version` | status |
| `Session/ActiveCount` | left out: `list_active_sessions` returns the total with the list |
| `Session/ActiveList`, `PostureCount`, `ProfilerCount` | list_active_sessions, profiler_status, apply_anc, coa_disconnect |
| `Session/AuthList/{start}/{end}` | get_auth_list, recent_auth_failures |
| `Session/MACAddress`, `UserName`, `EndPointIPAddress`, `Active/SessionID` | find_session, endpoint_360, why_auth_failed, get_auth_list, apply_anc, coa_reauth, coa_disconnect, explain_profile, reprofile_endpoint |
| `AuthStatus/MACAddress/{mac}/{seconds}/{records}/All` | get_auth_history, why_auth_failed, endpoint_360, recent_auth_failures |
| `FailureReasons` | list_failure_reasons and every tool that decodes a failure code |
| `CoA/Reauth`, `CoA/Disconnect` | coa_reauth, coa_disconnect, reprofile_endpoint |

## 2. Area-by-area map (v0.11.0)

Value: H = weekly or more for a network engineer, or very error-prone by hand. M = occasional. L = rare or
niche. "Curated" is what the tools do today; "left to `ise_api_call`" is what the API offers that no tool
wraps, with the reason.

| Area | Value | Curated in v0.11.0 | Left to `ise_api_call` (why) |
|---|---|---|---|
| **Network access policy**: policy sets, authn/authz rules, conditions, dictionaries | H | Read sets and rules; create/update policy set; create authn and authz rules (incl. local exceptions); update any rule (state, rank, conditions, results); delete rules and sets; list library conditions and dictionary attributes; conditions validated against ISE's dictionaries, profiles, SGTs, groups, AD groups, custom attributes; `ise_policy_explain` predicts the matched rule; export/diff/import of whole policy sets (I42/I43) | Library, network and time condition CRUD (33 operations; candidate C3), hit-count reset (10; C2), MFA rules (6), global exception rule read by id, dictionary CRUD (10: L) |
| Authz profiles, dACLs, allowed protocols | H | List/get/create/update profiles; dACLs read and set; allowed protocols list | Allowed-protocols create/update (large boolean model; I33 adds a TEAP slice) |
| **Device admin (TACACS+)** | H | Device-admin policy sets and rules, command sets and shell profiles (list/set/delete/test), TACACS external servers and sequences, `ise_admin_policy_explain`, enable Device Admin on a node | Device-admin conditions CRUD (as above). **TACACS+ live logs have no REST API** |
| Identity: internal users, groups, sequences, AD, certificate profiles | H | Users and groups CRUD; identity source sequences and certificate authentication profiles (set); AD join points create/join/leave, groups fetch and add, user group test; LDAP read | LDAP/REST ID store/RADIUS proxy writes (ERS; M, one-off setup), REST ID store (Azure AD) read (C9) |
| Endpoints and endpoint groups | H | List/get/360/set/delete; groups; bulk create/update/delete with task polling; custom attributes; release rejected endpoints; reprofile | OpenAPI endpoint CRUD (ERS is used instead), `endpoint/deviceType/summary` (C5), `endpointTask` |
| Profiling | M | Profiler policies read, custom profiling rules create/update/delete, `ise_explain_profile`, probes and profiler status, reprofile (I40) | Anomaly detection config, SNMP/NMAP scans, matched-endpoint counts, profiler policy export/import, cloud profiler (34 operations; C7) |
| Guest and sponsor | M | Guest types, sponsor groups, portals and locations read; guest type and sponsor group CRUD; guest accounts list/get/create/update/extend/suspend/reinstate/delete as a sponsor (I31) | Portal creation and customisation (GUI), SMTP/SMS notification settings (ERS; L), guest password reset and resend, self-registration approval |
| Posture | L–M | Posture policies and requirements listed | 201 operations of posture content: conditions, remediations, rules, settings (I32 when the client VM exists) |
| **TrustSec**: SGT, SGACL, egress matrix, IP-SGT, SXP | M–H | SGTs and SGACLs CRUD; egress matrix read and set; IP-SGT mappings set and deployed; SXP connections set, bindings read; matrix CoA push (I9) | Per-NAD TrustSec policy download report (C1), multiple matrices and matrix views, SGT reservation, TrustSec settings and servers, the 120 ACI/Secure Workload/Meraki/SXP-domain integration operations (niche) |
| ANC | H | Policies list/create/delete; apply/clear with a check that an authz rule matches `Session:ANCPolicy` | ANC policy update (rare) |
| Certificates and pxGrid | M | System and trusted certificates list; trusted import/delete; CSR generate/export/delete; signed certificate bind (dangerous for Admin usage); certificate auth profile; pxGrid clients list/approve/decline/delete, auto-approve, consumer key + CSR + signed bundle (I30) | System certificate import/export, self-signed generation, trusted-certificate usage update, OCSP/messaging renew, internal CA regenerate and intermediate CSR (11 operations; C4) |
| Deployment: nodes, services, patches, backup, repositories, licensing | M | Nodes list; node services enable/disable; patches and hotpatches list; last backup status; repositories list; licence tiers, smart state, registration, evaluation; `ise_deployment_health` | Node details, node groups, interfaces and SXP interface (read: C6); register/deregister, promote, PAN HA, sync (dangerous, GUI); backup now/schedule/restore and repository CRUD (C8); patch install/rollback and the staged upgrade API (Not planned); licence registration (L) |
| **MnT**: sessions, auth history, failure reasons, CoA | H | All 13 useful calls, plus the time-window views `ise_get_auth_list` / `ise_recent_auth_failures` | nothing |
| Network devices and NDGs | H | List/get/audit/create/update/delete NAD; NDGs list/create; export/import | Bulk NAD import (I49 builds it on the existing tools) |
| Config as code | M–H | `ise_export_config` / `ise_diff_config` / `ise_import_config` across 13 sections (I42/I43) | Parametrised bundles (I50) |
| Admin users and RBAC | L | Admin users listed (health) | Rbac Catalog (28 operations: admin users/groups, menu and data access, policy). A read-only slice would verify the least-privilege roles (C10) |
| System settings, Dataconnect, LSD, IPsec, telemetry | L | none | 4 + 5 + 2 + 9 OpenAPI operations plus ERS telemetry: one-off or niche |

## 3. Not built, with reasons

- **Policy simulation** ("which rule would X hit?"): ISE has no evaluate API. `ise_policy_explain` is a
  client-side evaluator that says where it is unsure (time, posture, identity-store and profiler
  conditions); `ise_why_auth_failed` reports the matched rules from MnT for passes.
- **TACACS+ live logs**: no REST surface (MnT is RADIUS only). Hit counts on device-admin rules, the device's
  own AAA accounting, or a syslog target are the alternatives.
- **Event ingestion** (pxGrid subscriptions, syslog receivers, pollers): out of scope suite-wide (ADR-003).
- **Posture content, Exim and client provisioning** (203 + 30 + 31 operations): large content models the GUI
  handles better; read-only summaries exist, the rest waits for I32 (needs a Windows client VM).
- **TrustSec integration rules** (ACI, Secure Workload, Meraki, SXP domains: ~120 operations), **FiveG,
  Prometheus, pxGrid Direct/Cloud, Integration Catalog, Duo/MFA/OIDC, Dataconnect, IPsec, Endpoint
  Replication, LSD, SGT Reservation**: niche integrations or one-off settings.
- **Patch install/rollback, the staged upgrade API, node registration/promotion, PAN HA changes, restore**:
  long-running, some reload nodes; the GUI or a change window fits better. Status is reported by
  `ise_deployment_health`. Backup-now and repository management are the exception (candidate C8): they are
  the pre-change step of the review prompts.
- **Portal creation and customisation, BYOD, native supplicant profiles**: GUI work.
- **Allowed-protocols writes**: large boolean model; I33 adds the TEAP slice only.
- **RADIUS suppression settings** (Administration > System > Settings > Protocols > RADIUS, including
  "Suppress Repeated Successful Authentications"): ISE 3.5 has no OpenAPI, ERS or MnT resource for them, so
  `ise_deployment_health` can't report whether they are on. Checked on 3.5.0.527 patches 3 and 4 with
  `ise_search_spec` (2026-10-21). "suppress", "repeat", "anomalous", "radius" and "setting" find only the
  TrustSec RADIUS servers, the external RADIUS servers and sequences, the rejected-endpoints list
  (`GET /api/v1/endpoint/getRejected`, already used by `ise_endpoint_360` and
  `ise_release_rejected_endpoint`) and unrelated settings. What it does to the tools: MnT's `AuthStatus`
  history leaves out repeated successful logins, while `Session/MACAddress` (`auth_acs_timestamp`) still
  shows the newest. On the lab ISE, 4 h of history held 2 records for an EAP-TLS client, the newest at
  10:13:34Z, while its live session showed an authentication at 10:52:20Z. So `ise_why_auth_failed` takes
  the newest login from the session when the session is newer than every record (`newest_login`), and
  `ise_get_auth_history` and `ise_recent_auth_failures` say in their output that repeated successful logins
  may be missing (`history_note`).
- Previously listed here and **now built**: SXP connection writes and IP-SGT deploy (I9), the certificate
  lifecycle (I8), AD join points and groups (I11), guest lifecycle as a sponsor (I31), profiler rules (I40),
  device-admin depth (I41), config export/import (I42/I43), endpoint bulk and custom attributes (I4),
  `ise_deployment_health` (I6), `Session/AuthList` time windows (I3).

## 4. Candidates from the live swagger

Uncovered operations with operator value, from the per-group lists above. None of these overlaps a planned
Wave 5 item (I44–I54): I45–I48 and I52–I54 are prompts over existing tools, I49/I50 build on the NAD, NDG and
config-import tools, I51 proves TrustSec enforcement on the switch (C1 is the ISE-side read it lacks), I44
is the operator-eyes pass. I32/I33/I34 cover posture, TEAP and PassiveID, so posture content and
allowed-protocols writes are not repeated here. These are listed under **Later** in [ROADMAP.md](../ROADMAP.md)
as I55–I62; the L items at the end stay `ise_api_call` only.

| # | Candidate | Value | Size | Operations | Why |
|---|---|---|---|---|---|
| C1 (I55) | `ise_trustsec_device_report`: TrustSec policy download status per NAD (which SGACLs, environment data and PAC each device has, and whether it is current) | H | S | `GET /trustsec/policy/device-report`, `/device-report/network-device/{name}` | After `ise_push_trustsec_matrix` the only check today is the switch CLI; this is ISE's own view and the missing half of I51 |
| C2 (I56) | `ise_reset_hitcounts(kind, policy_set, section)`: reset rule hit counters (dangerous tier, counters only) | M | S | 10 `reset-hitcount` POSTs (policy sets, authn/authz/exception/MFA rules, global exceptions) | A clean baseline before a change review (I46) or a policy clean-up; today GUI only |
| C3 (I57) | Library, network and time conditions: `ise_set_condition` / `ise_delete_condition` (library conditions by name; network conditions on NAD/IP/port; time-and-date conditions) | M | M | 33 operations across `condition`, `network-condition`, `time-condition` for both kinds | Rules and I50 bundles reference library conditions by name; the tools validate the name but cannot create it, so an import onto a fresh ISE stops there |
| C4 (I58) | Certificate depth: import a system certificate (PEM + key or PKCS12) and export one, toggle trusted-certificate usages (client auth, Cisco services), generate a self-signed certificate, renew the OCSP/messaging certificates | M | S | 7 of the 11 uncovered Certificates operations (not root-CA regenerate or intermediate CA) | I8/I52 cover CSR → sign → bind; customers also bring wildcard or existing certificates, and trusted-cert usage flags are a common EAP-TLS fix |
| C5 (I59) | `ise_endpoint_summary`: device-type and profile distribution in one call | M | S | `GET /endpoint/deviceType/summary`, plus the profiler `matched-endpoint-count` | "What is on my network?" for the demos (I54) without paging 20k endpoints |
| C6 (I60) | Deployment read depth: node details, node groups and membership, node interfaces and the SXP interface | M | S | `GET /deployment/node/{hostname}`, `node-group` (3 reads), `/node/{hostname}/interface`, `sxp-interface` | Multi-node PoCs (production gate I19) and `ise_deployment_health_review` (I47) ask "which PSNs are in which node group, on which interface"; writes stay GUI |
| C7 (I61) | Profiler scans and status: SNMP/NMAP endpoint scans list/create/start/stop/test with history, policy enable/disable, anomaly-detection settings | M | S–M | 14 `profiler/snmp/scan*` operations, `policy-status`, `anomaly/config` | I40 built rule authoring; scans are how profiling data gets in for IoT segments, and anomaly detection is a frequent "is it on?" question |
| C8 (I62) | Backup now and repositories: `ise_backup_now` (dangerous; polls `last-backup-status`), repository list/create/update/delete and files | M | S | `POST /backup-restore/config/backup`, `cancel-backup`; 5 `repository` operations | The pre-change step of I46/I52 and every change window; restore and schedule writes stay out (schedule has no GET on 3.5) |
| C9 | REST ID store (Azure AD) and RADIUS proxy (external RADIUS servers, server sequences) read and set | L–M | M | ERS `restidstore*`, `externalradiusserver`, `radiusserversequence` | Cloud identity for C25 once a tenant exists; proxy for migrations. One-off setup, so `ise_api_call` is acceptable for now |
| C10 | RBAC read: admin users, admin groups, menu and data access | L–M | S | 10 `rbac/*` reads of 28 | Would verify the least-privilege roles in `docs/least-privilege.md` (I16) on a customer ISE; writes stay out (risky) |
| L | LSD / random-MAC settings (2), endpoint replication (2), Dataconnect (5), system proxy and transport gateway (4), SGT reservation (5), support bundle (ERS), guest SMTP/SMS settings (ERS), task list (`GET /task`) | L | S each | | Rare or one-off; the spec tools describe them |

## How to re-run

The table above is generated. From a checkout with the lab reachable:

```bash
set -a; . /home/reptar/MCP-Suite/lab-secrets.env; set +a
ISE_URL=https://198.18.134.35 ISE_USERNAME="$LAB_ISE_USERNAME" ISE_PASSWORD="$LAB_ISE_PASSWORD" \
  uv run python scripts/api_coverage.py --save-spec /tmp/ise-spec.json --tools-cap 12 > /tmp/coverage.md
```

`--save-spec` keeps a compact snapshot of the operations (group, method, path, summary) so later runs can be
offline: `uv run python scripts/api_coverage.py --spec /tmp/ise-spec.json --uncovered --by-tool` adds the
list of every uncovered operation per group (the input for section 4) and the operations each tool uses
(the input for the per-area map). Any ISE 3.x works: the groups and counts are read from that ISE, so the
same command against another version gives its coverage. Check the script's "Unresolved call sites" and
"Tool paths matching no spec operation" sections after a release: a new tool whose paths the static scan
cannot follow shows up there, and `OVERRIDES` / `EXCLUDE` in the script are where to teach it.

## Appendix: history

### Phase 2 (2026-10-15, v0.2.0)

Spec counts came from the server's own spec index: 849 OpenAPI operations in 31 groups, 82 ERS resources
(410 synthesised operations), 14 MnT calls. Curated: 76 OpenAPI operations (9 %: Policy 56/138, Certificates
6/22, License 5/11, Deployment 3/24, Endpoints 2/12, Patch 2/6, Backup 1/6, TrustSec 1/154), 20 ERS resources
(networkdevice, networkdevicegroup, endpoint, endpointgroup, identitygroup, internaluser, authorizationprofile,
downloadableacl, allowedprotocols, sgt, sgacl, egressmatrixcell, profilerprofile, ancpolicy, ancendpoint,
activedirectory, idstoresequence, ldap, tacacscommandsets, tacacsprofile) and 12 of 14 MnT calls.

Phase 2 added: create/update policy set, create authn rule, create authz rule (also local exceptions), update
any rule, list dictionary attributes, conditions checked against the dictionaries; device-admin sets and
rules, command sets and shell profiles, Device Admin service enable; endpoint 360 flags rejected endpoints;
SGT in rules validated against ISE's security groups; ANC apply warns when no authz rule matches
`Session:ANCPolicy`; MnT find_session notes a missing auth result, failure hints fixed (12001 is a normal
EAP-MD5 NAK step, not a failure), EAP-MD5/PEAP step codes decoded, why_auth_failed explains the "no record"
case (unknown NAD = silent drop).

Existing tools changed: `ise_create_authz_rule` gained `kind`, `section`, `match` and the device-admin
results, with attribute names and enum values checked against ISE's dictionaries (did-you-mean suggestions,
case canonicalised). Found live: `DEVICE:Location` / `Device Type` values must be written without the root
(`All Locations#Sydney`); the tools strip it. `ise_apply_anc` fingerprints only the ANC policy (a reauth
between preview and confirm broke the confirm); the CoA tools drop the framed IP from their fingerprint
(DHCP fills it in after the session starts). Update tools return compact views instead of ISE's full echo.

Not built then, with reasons: policy simulation (no evaluate API; later I13 built the client-side
evaluator), TACACS+ live logs (no REST), guest/sponsor, posture, profiler authoring, patch/backup actions,
RBAC (low frequency, large models or node-reloading jobs), endpoint bulk and custom attributes (named as the
next candidates; built in v0.3.0 as I4).

### Phase 3 (v0.3.0)

- MnT: `Session/AuthList` curated (`ise_get_auth_list`); 13 of 14 MnT calls behind tools. Spike: MnT has
  **no** cross-endpoint query for failed attempts, so `ise_recent_auth_failures` checks candidate MACs per
  `AuthStatus` call and reports its coverage.
- Endpoints: bulk create/update/delete (`/api/v1/endpoint/bulk` + `/api/v1/task`), custom attribute
  definitions and release of rejected endpoints curated (Endpoints 2/12 -> 7/12, plus Task and
  CustomAttributes groups).
- Deployment health: PAN HA, repositories, last backup, patches, system certificates, licence tier/eval
  state and ERS AD join points in one tool. Not in REST on 3.5: per-node patch levels, the backup
  schedule (POST/PUT only) and per-node AD join status.
- ERS spec: body wrapper names added for 46 resources.

### Between v0.3.0 and v0.11.0 (2026-10-15 to 2026-10-17)

I8 certificates, I9 IP-SGT/SXP, I11 AD, I13 policy explain, I15 incident timeline, I30 pxGrid clients and
consumer certificates, I31 guest and sponsor, I40 profiler authoring, I41 device-admin depth, I42/I43 config
export, diff and import, plus the operator-eyes pass (I22–I29). The coverage table was not recounted until
this refresh; see the CHANGELOG for the per-release detail.

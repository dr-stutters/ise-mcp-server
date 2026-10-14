# ISE 3.5 API gap analysis (Phase 2)

Lab: ISE 3.5.0.527 patches 3 and 4, standalone node. Spec counts come from the server's own spec index
(`ise_search_spec`): the 31 springfox OpenAPI groups, the ERS SDK data model, and the hand-written MnT doc.

## 1. The API surface

| Surface | Size | Curated coverage (v0.2.0) |
|---|---|---|
| OpenAPI `/api/v1` | 849 operations in 31 groups | 76 operations (9 %) behind tools. Almost all of them are in the groups operators use daily (Policy 56/138, Certificates 6/22, License 5/11, Deployment 3/24, Endpoints 2/12, Patch 2/6, Backup 1/6, TrustSec 1/154 for IP-SGT; SGT/SGACL/matrix use ERS) |
| ERS `/ers/config` | 82 resources (410 synthesised CRUD operations) | 20 resources: networkdevice, networkdevicegroup, endpoint, endpointgroup, identitygroup, internaluser, authorizationprofile, downloadableacl, allowedprotocols, sgt, sgacl, egressmatrixcell, profilerprofile (names), ancpolicy, ancendpoint, activedirectory, idstoresequence, ldap, tacacscommandsets, tacacsprofile |
| MnT `/admin/API/mnt` | 14 calls | 12 (all except `Session/AuthList` time windows and `Session/ActiveCount`, which `ise_list_active_sessions` covers) |
| pxGrid | WebSocket/STOMP pub-sub | Out of scope: it isn't request/response REST, and it needs client certificates and pxGrid client approval |

Counting operations makes coverage look low. The OpenAPI groups that matter for day-to-day access control
(policy, endpoints, deployment state, certificates, licensing) are 230 operations, and about a third of
those are curated. The rest of the 849 are posture content (203), TrustSec ACI/workload/SXP-domain
integrations (about 120), Exim posture import/export (30), FiveG (16), Prometheus (16), pxGrid
Direct/Cloud (20), Duo/MFA/OIDC (27) and provisioning resources (31). Each of these is either a niche
integration or a large content model that is better done in the GUI. **Everything is reachable through
`ise_api_call`** (all three surfaces, any method when the dangerous tier is on), and
`ise_search_spec`/`ise_get_definition` describe it.

## 2. Area-by-area map

Value: H = weekly or more for a network engineer, or very error-prone by hand. M = occasional.
L = rare or niche.

| Area | Value | Before Phase 2 | After Phase 2 | Left to `ise_api_call` (why) |
|---|---|---|---|---|
| **Network access policy**: policy sets, authn/authz rules, conditions, dictionaries | H | Read sets and rules; create authz rule; delete rule or set | **create/update policy set, create authn rule, create authz rule (also local exceptions), update any rule (state, rank, conditions, results), list dictionary attributes; conditions are checked against the dictionaries** | Library-condition CRUD, global exceptions, MFA rules, hit-count reset, time/date conditions (rare; the GUI is clearer) |
| Authz profiles, dACLs, allowed protocols | H | Read; create/update profile; set dACL | unchanged | Allowed-protocols create/update (large boolean model; lab defaults suffice) |
| **Device admin (TACACS+)**: policy sets, command sets, shell profiles, service | H | Read policy sets only (`kind=device-admin`) | **create/update device-admin sets and rules (command sets + shell profile), list/set command sets and shell profiles, enable Device Admin on a node, delete command sets/shell profiles (blocked while in use)** | TACACS external servers and sequences (L). **TACACS live logs have no REST API** (MnT is RADIUS only); hit counts on the device-admin rules are the API-side evidence |
| Identity: internal users, identity groups, sequences, AD | H | List/get/create/update users and groups; list sources (AD join points, LDAP, sequences) | unchanged | AD join/leave, AD group fetch, identity source sequence writes, certificate auth profiles (M; one-off setup) |
| Endpoints and endpoint groups | H | List/get/360/set/delete endpoint; groups | **endpoint 360 also flags rejected endpoints** | Bulk import/update/delete (async task: M), custom attributes (M), release rejected endpoints (L) |
| Profiling | M | Profile name in endpoint views | unchanged | Profiler policy CRUD, feed, SNMP scan, anomaly detection (the policy model is large) |
| Guest and sponsor | M | none | none | Guest users need **sponsor** credentials, not the admin API user, and portals/guest types are big portal models. Use `ise_api_call` with a sponsor account if needed |
| Posture | L–M | none | none | 203 operations of posture content (conditions, requirements, AV/AM catalogues). The GUI is the right tool |
| **TrustSec**: SGT, SGACL, egress matrix, IP-SGT, SXP | M–H | List SGTs/SGACLs/matrix/IP-SGT; set SGT; set egress cell; SGT in authz rules | SGT in rules **validated against ISE's security groups**; SGT assignment verified on a real switch (cts SGT in the session) | SXP connection/binding writes, matrix CoA push, ACI/workload integrations (L) |
| ANC | H | list policies/endpoints; create policy; apply/clear | **apply warns when no authz rule matches Session:ANCPolicy (QUARANTINE would do nothing); confirm no longer breaks when the session re-authenticates between preview and confirm** | ANC policy update (rare) |
| BYOD and certificates | M | List system/trusted certs; import trusted CA; delete | unchanged | CSR generate/bind, pxGrid certs, certificate templates (multi-step and node-specific) |
| Deployment: nodes, groups, patches, backup, repositories, licensing | M | List nodes, patches, backup status, licence | **enable/disable node services (dangerous)** | Register/deregister nodes, PAN HA, patch install/rollback, backup now/restore, repository CRUD, licence registration. All are rare and long-running, and some reload the node; the GUI or a change window fits better |
| **MnT**: sessions, auth status, failure reasons, CoA | H | All of it | **find_session notes when MnT's latest event lacks the auth result; failure hints fixed (12001 was mis-described) and EAP-MD5/PEAP step codes decoded; why_auth_failed explains the "no record" case (unknown NAD = silent drop)** | `Session/AuthList` time windows (M) |
| Network devices and NDGs (incl. TACACS settings) | H | List/get/audit/create/update/delete NAD; NDGs | unchanged (live-tested with a real switch) | Bulk NAD import (M) |
| Admin users and RBAC | L | none | none | Rbac Catalog (28 operations): rare, and risky to automate |
| System settings (proxy, SMTP, telemetry) | L | none | none | 4 OpenAPI operations plus ERS SMTP/telemetry: one-off |

## 3. Existing tools: what changed and why

- `ise_create_authz_rule` was network-access only and took any condition text. ISE then failed with an
  opaque 400 ("Value for attribute is not a permitted option"). It now takes `kind`, `section`
  (`exception`), `match` (AND/OR), and the device-admin results. Attribute names and enum values are
  checked against ISE's dictionaries in the preview, with "did you mean" suggestions, and case is
  canonicalised. Profiles, SGTs, command sets and shell profiles are checked against ISE's lists.
- Found live: `DEVICE:Location`/`Device Type` values must be written **without the root**
  (`All Locations#Sydney`). ISE rejects `Location#All Locations#Sydney`. The tools strip the root.
- `ise_apply_anc` fingerprinted the live session. A reauth between preview and confirm (exactly what
  happens around CoA/ANC) made the confirm fail. It now fingerprints only the ANC policy. The CoA tools
  drop the framed IP from their session fingerprint, because DHCP fills it in a moment after the session
  starts.
- Knowledge base: the hint for "12001" called it a failure ("method not allowed"). In fact 12001 is a
  normal EAP-MD5 NAK step. It was replaced with real hints for 22063 and 11509. EAP-MD5/PEAP execution
  steps are now decoded.
- Update tools return compact rule/policy-set views instead of ISE's full echo.

## 4. Not built, with reasons

- **Policy simulation** ("which rule would X hit?"): ISE has no evaluate API. A client-side evaluator
  would be wrong for library conditions, identity-store attributes and profiler data. Instead,
  `ise_why_auth_failed` reports the matched rules from MnT (passes) and the rules using the selected
  profile (failures). MnT's AuthStatus records carry no policy names for failures.
- **TACACS live logs**: no REST surface. Hit counts on device-admin rules, the device's own AAA
  accounting, or a syslog target are the alternatives.
- **Guest/sponsor, posture, profiler policy authoring, patch/backup actions, RBAC**: low frequency for
  this tool's users, large models or long-running/node-reloading jobs. `ise_api_call` reaches all of
  them, and the spec tools describe the bodies.
- **Endpoint bulk and custom attributes**: medium value. The obvious next candidates (one async-task
  tool each).

# ise-mcp-server roadmap
_Last updated 2026-10-16: **Wave 4 planned (I35–I48): standalone packaging, de-labbed repo, profiler, device admin, config export/import, four prompts.** **I30 (pxGrid clients + certs for FMC) delivered in v0.9.0.** **I11 (AD) delivered in v0.8.0** against a real Windows DC, and I8 re-proven with its AD CS. **Next delivered in v0.4.0** (I8–I10). Now delivered in v0.3.0 (I1–I6). Logs and events are pull-only ([ADR-003](https://github.com/dr-stutters/stutters-mcp-core/blob/main/docs/adr/003-no-event-ingestion.md)); I7 and I12 dropped, I3 reframed as on-demand MnT lookups. Current release v0.8.0 (AD, I11). Suite roadmap: [stutters-mcp-core/ROADMAP.md](https://github.com/dr-stutters/stutters-mcp-core/blob/main/ROADMAP.md). Gap analysis: [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md)._

## Summary
- v0.2.0 covers the day-to-day ISE work across OpenAPI, ERS and MnT: 72 tools for troubleshooting, policy and device-admin editing, TrustSec reads, ANC and CoA. They are live-tested against ISE 3.5 with a real cat9000v switch and client (CML `ise-access`).
- **Depth gaps:** endpoint bulk work and custom attributes, IP-SGT/SXP writes, the certificate lifecycle (CSR → CA → bind, EAP-TLS), AD groups and join points, and a deployment health view. Guest, posture and profiler authoring are left out on purpose, and so is policy simulation.
- **Logs and events (pull-only, ADR-003):** tools query MnT when called: per-MAC auth history with decoded failures and live sessions exist today. The gap is a time-window view across all endpoints (I3). No subscriptions or receivers: pxGrid (I7) and remote syslog (I12) were dropped, and TACACS+ live logs have no REST API, so they stay out of scope.
- **Now (✅ v0.3.0):** core v0.3.0, the `ise_troubleshoot_endpoint_access` prompt, on-demand recent-auth lookups over MnT (I3), endpoint bulk work and custom attributes, scale hardening, and `ise_deployment_health`. 80 tools + 1 prompt; live-tested on the lab ISE 3.5 and the CML `ise-access` switch and client.
- **Next (✅ v0.4.0):** IP-SGT/SXP writes with the TrustSec push (I9), the certificate lifecycle with any CA plus EAP-TLS (I8), and the `ise_quarantine_host` prompt with FMC containment (I10). 95 tools + 2 prompts, live on ISE 3.5, CML sw1 and client, and FMC's FTD. I11 (AD) followed in v0.8.0 once a real DC was available.
- **Production gate:** least-privilege admin roles, a 3.2–3.5 version matrix, CoA/ANC blast-radius rails, and multi-node (PAN/MnT/PSN) support.

## Now
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| ✅ I1 | **Core bump (v0.3.0, released in v0.3.0)**: `Page.more` in lists; `ise_status` reports server and core versions; redeploy cortex:8033 | Every later item builds on the newer core, and lists no longer look complete when ISE has more pages | none | Unit + contract; live read suite on the lab ISE 3.5; health check and one authenticated call after the redeploy | S | [#8](https://github.com/dr-stutters/ise-mcp-server/issues/8) |
| ✅ I2 | **Prompt `ise_troubleshoot_endpoint_access`** (MAC/user/IP → session → auth history → `ise_why_auth_failed` → endpoint 360 → matched rule → NAD → switch CLI via cml/catc → diagnosis + preview-only fix) | The most common ISE ticket, handled in one guided pass across ISE and the switch | none (the CLI step needs cml- or catc-mcp-server) | Live on CML `ise-access`: healthy MAB, disabled rule (15039), EAP-MD5 wrong password (22063), NAD removed (silent drop); prompt test kit (core C9) | S | [#9](https://github.com/dr-stutters/ise-mcp-server/issues/9) |
| ✅ I3 | **On-demand recent auth activity over MnT**: `ise_get_auth_list` (MnT AuthList: sessions authenticated in a time window, summarised by NAD/method/profile) and `ise_recent_auth_failures(since, nad, user, limit)` (failed attempts in the window with decoded reasons, grouped by reason and NAD). Queried when called; no poller or buffer. Existing per-MAC (`ise_get_auth_history`, `ise_why_auth_failed`) and live (`ise_list_active_sessions`) tools stay | "Who failed in the last hour, and why?" and "what connected on this NAD today?" without knowing the MAC first | none (server → MnT :443, already in place) | Unit with recorded MnT XML (windows, truncation, MnT errors); live with `seed_lab.py` RADIUS (pass, 22040, 22056) and `ise-access` reauths, queried by NAD and user. Spike first: does MnT expose failures across endpoints? | M | [#10](https://github.com/dr-stutters/ise-mcp-server/issues/10) |
| ✅ I4 | **Endpoint bulk + custom attributes**: `ise_bulk_endpoints` (async bulk create/update/delete, task polling, capped preview), `ise_list_custom_attributes` / `ise_set_custom_attribute`, custom attributes on `ise_set_endpoint`, `ise_release_rejected_endpoint`; conditions accept `EndPoints.<attr>` | Onboarding IoT/MAB endpoints from a CMDB, and custom-attribute policy, are weekly tasks. The gap analysis names this as the next candidate | none | Unit (task states, partial failures); live on ISE 3.5 with `mcp-test-*` MACs and an authz rule on a custom attribute, matched by the `ise-access` client | M | [#11](https://github.com/dr-stutters/ise-mcp-server/issues/11) |
| ✅ I5 | **Large-deployment hardening**: no N+1 GETs above a threshold, name→id caching, consistent paging, ERS body wrapper names in the synthesised spec | Lists are fine in the lab but slow at 10k NADs/endpoints, the first wall a PoC hits | none | Unit with 5k NAD / 20k endpoint mocks and timing assertions; live with a few hundred seeded `mcp-test-*` NADs (cleaned up) | M | [#12](https://github.com/dr-stutters/ise-mcp-server/issues/12) |
| ✅ I6 | **`ise_deployment_health`**: personas and services, patch level per node and mismatches, last backup and schedule, repositories, cert expiry and usage, licence tier (flags evaluation), AD join status; findings ranked by severity | A weekly or pre-change health check that takes six GUI pages today, and catches expiring certs and evaluation licences | none | Unit with a mocked multi-node deployment; live on the lab ISE 3.5 (evaluation licence, self-signed Admin/EAP cert and no AD join point must all show up) | M | [#13](https://github.com/dr-stutters/ise-mcp-server/issues/13) |

## Next
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| ❌ I7 | ~~pxGrid 2.0 event source~~: **dropped (ADR-003)**. Servers don't subscribe to streams; recent activity is I3, live sessions and ANC state are existing tools | — | — | — | — | [#14](https://github.com/dr-stutters/ise-mcp-server/issues/14) (closed) |
| ✅ I8 | **Certificate lifecycle (v0.4.0)**: `ise_generate_csr`, `ise_export_csr`, `ise_bind_certificate` (dangerous: Admin usage restarts the app server), trusted import for client auth, certificate authentication profile + identity sequence for EAP-TLS | Expired or wrong certificates are a top cause of ISE outages; EAP-TLS needs this | Windows AD CS via the Windows MCP server (`win_sign_csr`), a template with Server + Client Auth EKUs | Live: CSR → `win_sign_csr` → bind for EAP; EAP-TLS with wpa_supplicant on the `ise-access` client → pass, untrusted cert → decoded failure. Done with an OpenSSL lab CA (v0.4.0) and with Windows AD CS `mitchcloud-CA` (v0.8.0: WebServer-template EAP cert, User-template client cert, EAP-TLS PASS) | M | [#15](https://github.com/dr-stutters/ise-mcp-server/issues/15) |
| ✅ I9 | **IP-SGT and SXP writes (v0.4.0)**: `ise_set_ip_sgt` (+ deploy), `ise_list_sxp_connections`, `ise_set_sxp_connection`, `ise_list_sxp_bindings`, `ise_push_trustsec_matrix` (dangerous) | Static IP-SGT and SXP are how servers and non-802.1X hosts enter TrustSec policy; today they're read-only | SXP service on a PSN; switch as SXP peer, TCP 64999 between ISE and the switch; CTS credentials on the NAD for the matrix push | Live on `ise-access` sw1: `show cts sxp connections`, `show cts role-based sgt-map all`, `show cts role-based permissions`. Done: SXP On with sw1, bindings + matrix push seen on the switch | M | [#16](https://github.com/dr-stutters/ise-mcp-server/issues/16) |
| ✅ I10 | **Prompt `ise_quarantine_host` (v0.4.0)**: host → session → check the `Session:ANCPolicy` rule → `ise_apply_anc` preview/confirm → verify dACL/SGT on the switch → optional FMC block object + deploy → verify → record undo | Containment in minutes, each step previewed and verified | FMC step: fmc-mcp-server and an FTD in path | Live on `ise-access` (ping blocked, then restored); FMC part with the `ftd-fmc` recipe (CML EVAL 5-node limit); prompt test kit | S | [#17](https://github.com/dr-stutters/ise-mcp-server/issues/17) |
| ❌ I12 | ~~TACACS+ activity via ISE remote syslog~~: **dropped (ADR-003)**. Servers don't receive syslog, and TACACS+ live logs have no REST API, so they stay out of scope | — | — | — | — | [#19](https://github.com/dr-stutters/ise-mcp-server/issues/19) (closed) |

## Later
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| ✅ I11 | **AD join points and groups (v0.8.0)**: `ise_create_ad_join_point`, `ise_join_ad` / `ise_leave_ad` (dangerous; credentials per call, never stored), `ise_list_ad_groups`, `ise_add_ad_groups`, `ise_test_ad_user`, `ise_get_ad_join_point` (join status); ExternalGroups conditions; AD-aware `ise_why_auth_failed` and `ise_policy_explain(ad_user=)` | AD-group authorization is the norm at customers; group fetch and join are error-prone GUI chores | Windows AD lab DC (`~/MCP-Suite/scripts/build-dc.py`); ISE name server -> DC | Live on DC01.mitchcloud.lab: join, 4 groups, PEAP mcp-alice -> AD employees rule, mcp-bob -> contractors rule; 24408/24409/24415/22056/15039 diagnosed | M | [#18](https://github.com/dr-stutters/ise-mcp-server/issues/18) |
| ✅ I13 (v0.6.0) | **`ise_policy_explain`** (client-side evaluator): walks sets → authn → authz in rank order, evaluates the conditions it understands, marks rules with unsupported conditions (time, posture, identity-store lookups, profiler) as "unknown"; regression harness against MnT's matched rule | "Which rule would this hit?" before a change. ISE has no evaluate API, so the evaluator must say where it is unsure | none | Unit with policy fixtures; live predictions vs actual matched rules for the `ise-access` client | L | [#20](https://github.com/dr-stutters/ise-mcp-server/issues/20) |
| ◐ I14 (v0.6.0, read slice) | **Guest/sponsor, profiler, posture (scoped)**: guest lifecycle with a separate sponsor account; profiler policy read and custom policies where the API allows; posture read-only summaries | Covers the weekly-touched parts of large models without rebuilding the GUI | Sponsor account with REST access; guest portal; Windows client with Secure Client for posture (no CML image) | Live guest lifecycle and profiler read on ISE 3.5; posture on mocks | L | [#21](https://github.com/dr-stutters/ise-mcp-server/issues/21) |
| ✅ I15 (v0.6.0) | **Prompt `ise_incident_timeline`**: ISE auth history and failures (I3), session and ANC state + FMC audit/health/deploys (fmc F5) + CatC events/issues/audit (catc D2) for a host, each queried on demand, merged by time | Incident response across products | fmc- and catc-mcp-server available to the client (optional); no appliance changes | Live scripted incident on `ise-access` (fail, pass, quarantine, clear), FMC/CatC activity when `ftd-fmc` / `catc-routers` run; prompt test kit | M | [#22](https://github.com/dr-stutters/ise-mcp-server/issues/22) |

## Operator-eyes pass (v0.7.0)
Found by running 12 operator tasks end to end through the tools against the live lab.

| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| ✅ I22 | **CoA records are not login failures** (why_auth_failed, endpoint_360, auth history) | The diagnosis tool reported failures for endpoints whose last login passed | none | Unit (CoA NAK, CoA-only history); live on the CML client and the RADIUS test client | S | [#53](https://github.com/dr-stutters/ise-mcp-server/issues/53) |
| ✅ I23 | **`ise_policy_explain` nad/flow inputs + NDG normalisation** | "Which rule would a MAB login from sw1 hit?" was 5 calls with a wrong intermediate answer; now 1 | none | Unit; live: mcp-test-sw1 + wired-mab -> mcp-test-mab-permit | S | [#54](https://github.com/dr-stutters/ise-mcp-server/issues/54) |
| ✅ I24 | **NAD name hints, session NAD filter, consistent columns** | 'sw1' failed in every NAD-taking tool; sessions filtered silently to 0 | none | Unit; live | S | [#55](https://github.com/dr-stutters/ise-mcp-server/issues/55) |
| ✅ I25 | **Effective egress policy for a pair with no cell** | "Can A talk to B?" returned "No results" | none | Unit; live (ANY-ANY Permit IP) | S | [#56](https://github.com/dr-stutters/ise-mcp-server/issues/56) |
| ✅ I26 | **Guidance refresh** (instructions, no-REST areas, dead-end hints) | "What changed today?" dead-ended after 3 spec searches | none | Contract tests | S | [#57](https://github.com/dr-stutters/ise-mcp-server/issues/57) |
| ✅ I27 | **Compact auth and session records** | ~600 chars of key material/plumbing per EAP-TLS row; sessions ~3 kB | none | Unit; live sizes | S | [#58](https://github.com/dr-stutters/ise-mcp-server/issues/58) |
| ✅ I28 | **Faster authorization-profile lookups** | Write previews took 5-10 s | none | Unit; live timing | S | [#59](https://github.com/dr-stutters/ise-mcp-server/issues/59) |
| ✅ I29 | **Ended sessions are not live** | After an ANC release the tools still showed (and would CoA) a session the switch no longer had | none | Unit; live | S | [#63](https://github.com/dr-stutters/ise-mcp-server/issues/63) |

## Logs and events (pull-only, ADR-003)
Every tool queries ISE when called ([ADR-003](https://github.com/dr-stutters/stutters-mcp-core/blob/main/docs/adr/003-no-event-ingestion.md)). No pxGrid subscriptions, syslog receivers, pollers or buffers; the history available is what MnT keeps.

| Tool | What it reads | Status |
|---|---|---|
| `ise_get_auth_history`, `ise_why_auth_failed` | MnT auth attempts for one MAC (up to 7 days), failure reasons decoded | ✅ v0.2.0 |
| `ise_list_active_sessions`, `ise_find_session` | Live MnT sessions (by user, NAD, MAC, IP, session id) | ✅ v0.2.0 |
| `ise_list_failure_reasons` | MnT failure-code catalogue with likely cause and next step | ✅ v0.2.0 |
| `ise_list_anc_endpoints` | Current ANC (quarantine) assignments | ✅ v0.2.0 |
| `ise_get_auth_list`, `ise_recent_auth_failures` (I3) | Auth activity and failures across endpoints in a time window, by NAD/user (failures from a capped set of candidate MACs: MnT has no cross-endpoint failure query) | ✅ v0.3.0 |
| TACACS+ activity | No REST API on ISE (MnT is RADIUS only) | ❌ out of scope |

## Workflow prompts owned by this server
| Prompt | What it does | Other servers used | Bucket |
|---|---|---|---|
| `ise_troubleshoot_endpoint_access` (I2) | MAC or user → sessions, failure reason, policy hit, NAD, switch-port CLI → diagnosis and a preview-only fix | cml or catc (device CLI) | ✅ v0.3.0 |
| `ise_quarantine_host` (I10) | ANC + CoA, verify on the switch, then an FMC block/dynamic object if needed, verify, record undo | fmc; cml or catc for verification | ✅ v0.4.0 |
| ✅ `ise_incident_timeline` (I15, v0.6.0) | ISE auth history/failures, session and ANC state + FMC audit/health/deploys + CatC events/issues for a host, each queried on demand, merged by time | fmc, catc | ✅ v0.6.0 |

The suite catalogue also lists `catc_onboard_switch_with_nac` (owned by catc) and `cml_replicate_site` (owned by cml), which use this server's NAD and policy read tools.

## Production gate (server-specific)
- [x] **I16 (v0.5.0): Least-privilege ISE admin roles** ([#23](https://github.com/dr-stutters/ise-mcp-server/issues/23)). Tested admin groups per tier: read = ERS Operator + MnT read + OpenAPI read (custom RBAC menu/data access); write = ERS Admin + scoped Policy Admin; dangerous = adds CoA and System Admin, only for node services and certificates. A tool → role table; `ise_status` names missing permissions. Links core [G3](https://github.com/dr-stutters/stutters-mcp-core/issues/20) and [G2](https://github.com/dr-stutters/stutters-mcp-core/issues/19). Size M.
- [ ] **I17 (skipped overnight 2): Version matrix 3.2 / 3.3 / 3.4 / 3.5** ([#24](https://github.com/dr-stutters/ise-mcp-server/issues/24)). Spec snapshots and diffs per version, a minimum version per tool with a clear refusal, and the live suites on at least two versions per release. **Blocked:** only 3.5 is available. Links core [G6](https://github.com/dr-stutters/stutters-mcp-core/issues/23). Size L.
- [x] **I18 (v0.5.0): Safety rails for CoA, ANC and node changes** ([#25](https://github.com/dr-stutters/ise-mcp-server/issues/25)). One session per CoA/ANC by default; bulk CoA (by NAD/NDG/group) shows a count and has a configurable maximum; a protect-list of MACs/users/NADs/groups; no port-bounce on uplinks or trunks; node-service, persona and cert-bind changes honour the change window. Links core [G7](https://github.com/dr-stutters/stutters-mcp-core/issues/24). Size M.
- [x] **I19 (v0.5.0, mock + live standalone): Multi-node deployments** ([#26](https://github.com/dr-stutters/ise-mcp-server/issues/26)). PAN for config, primary/secondary MnT with failover, and ERS on 9060 or 443 per node; discovered from the node list; CoA routed via MnT to the right PSN; `ise_status` checks every node and port. **Blocked:** the lab is a single standalone node. Links core [G10](https://github.com/dr-stutters/stutters-mcp-core/issues/27) and [G6](https://github.com/dr-stutters/stutters-mcp-core/issues/23). Size L.
- [x] **I20 (v0.5.0): Retry ISE's transient policy-API database error** ([#43](https://github.com/dr-stutters/ise-mcp-server/issues/43)). Intermittent HTTP 500 Hibernate/JDBC errors on policy-set/authz calls are retried on reads and idempotent writes with backoff (core only retries 502/503/504). Robustness fix found in the live suite. Size S.
- [ ] Core items that apply as-is: [G1](https://github.com/dr-stutters/stutters-mcp-core/issues/18) OAuth, [G4](https://github.com/dr-stutters/stutters-mcp-core/issues/21) secrets (NAD RADIUS/TACACS keys and AD join credentials must never reach logs), [G5](https://github.com/dr-stutters/stutters-mcp-core/issues/22) observability, [G8](https://github.com/dr-stutters/stutters-mcp-core/issues/25) security review/SBOM, [G9](https://github.com/dr-stutters/stutters-mcp-core/issues/26) public release (scrub lab IPs, `mcp-test-*` credentials and the lab hostnames from the notes and history).

## External services and prerequisites
| Service / prerequisite | Needed for (items) | Provided by | Network path | Status |
|---|---|---|---|---|
| ISE 3.5 standalone node (lab, `ise` 198.18.134.35), OpenAPI/ERS/MnT | All | lab | cortex → ISE :443 (ERS also :9060, open) | ✅ in place |
| ISE licence: Advantage, Device Admin | TrustSec, ANC and device-admin tools | ISE evaluation licence (all tiers enabled, **evaluation**: expires) | — | ✅ evaluation only |
| CML recipe `ise-access` (cat9000v sw1 + Alpine client with wpa_supplicant) | I2, I3, I4, I8–I11, I13, I15, I18 | cml-mcp-server recipe (lab `mcp-cml-ise`, stopped) | sw1 ↔ ISE RADIUS 1812/1813, CoA 1700, TACACS 49 | ✅ defined (TACACS lines need re-applying) |
| RADIUS test client on cortex (`scripts/seed_lab.py`, PAP) | I3, I5 | This repo | cortex → ISE UDP 1812/1813 | ✅ in place |
| eapol_test / wpa_supplicant for EAP-TLS and PEAP-AD | I8, I11 | `ise-access` client (wpa_supplicant installed) | client ↔ sw1 802.1X | ✅ PEAP-AD and EAP-TLS (AD CS) live |
| Windows AD + AD CS lab server | I8, I11 | DC01.mitchcloud.lab 198.18.130.11 (lab VM; rebuilt by `~/MCP-Suite/scripts/build-dc.py`) | ISE → DC 53/88/389/3268/445; cortex → DC WinRM 5985 | ✅ up; the Samba/OpenSSL stand-in (CML dc1 .180) is retired |
| SXP service on a PSN; switch SXP peer | I9 | ISE node service + sw1 config | ISE ↔ sw1 TCP 64999 | ✅ enabled (sw1 listener, CTS PAC) |
| Sponsor account (REST access) + guest portal | I14 | ISE config | server → ISE :443 | ⏳ to set up |
| Windows client with Secure Client (posture) | I14 | No CML image | — | ❌ unavailable |
| FMC + FTDv (`ftd-fmc` recipe) | I10, I15 | fmc-mcp-server + CML | — | ✅ defined (EVAL 5-node limit shared with `ise-access`) |
| ISE 3.2 / 3.3 / 3.4 labs | I17 | lab / customer / VM | — | ❌ unavailable |
| Multi-node ISE (PAN + MnT + PSN) | I19 | lab / customer | — | ❌ unavailable |

## Not planned
Left to `ise_api_call` (with `ise_search_spec` / `ise_get_definition`) or out of scope:
- **Posture content authoring** (203 operations: conditions, requirements, AV/AM catalogues) and **Exim** posture import/export. Large content models that the GUI handles better; I14 covers read-only posture.
- **TrustSec ACI / workload / SXP-domain integrations** (~120 operations), **FiveG**, **Prometheus**, **pxGrid Direct / pxGrid Cloud**, and **Duo/MFA/OIDC**. These are niche integrations.
- **Patch install/rollback, backup now/restore, node registration/deregistration, PAN HA, and licence registration**. They are long-running and some reload nodes, so they belong in the GUI or a change window. I6 reports the status only.
- **RBAC catalogue and admin-user management**: rare, and risky to automate.
- **System settings** (proxy, SMTP, telemetry): one-off.
- **Library-condition CRUD, global exceptions, MFA rules, hit-count reset, and allowed-protocols writes**: rare, and the GUI is clearer.
- **TACACS+ live logs**: ISE has no REST API for them, and receiving ISE syslog is out of scope (ADR-003). I12 was dropped.
- **Event ingestion of any kind** (pxGrid subscriptions, syslog receivers, background pollers, event buffers, relays): out of scope suite-wide ([ADR-003](https://github.com/dr-stutters/stutters-mcp-core/blob/main/docs/adr/003-no-event-ingestion.md)). A long-term record belongs in a log platform with its own MCP server.


## Wave 3 (planned 2026-10-16)
See the [suite roadmap](https://github.com/dr-stutters/stutters-mcp-core/blob/main/ROADMAP.md#wave-3-planned-2026-10-16).

| # | Item | Milestone |
|---|---|---|
| ✅ [I30](https://github.com/dr-stutters/ise-mcp-server/issues/71) | pxGrid client management + certs for FMC (v0.9.0): 8 tools; ISE pxGrid cert from mitchcloud-CA; FMC client cert in `~/MCP-Suite/lab-ca/` | Next |
| [I31](https://github.com/dr-stutters/ise-mcp-server/issues/72) | Guest + sponsor (AD sponsors, portals, guest accounts) | Next |
| [I32](https://github.com/dr-stutters/ise-mcp-server/issues/73) | Posture (blocked: Windows client VM + Secure Client) | Later |
| [I33](https://github.com/dr-stutters/ise-mcp-server/issues/74) | Machine + user EAP-TLS via GPO auto-enrolment (blocked: Windows client VM) | Later |
| [I34](https://github.com/dr-stutters/ise-mcp-server/issues/75) | PassiveID from AD logins (blocked: Windows client VM) | Later |


## Wave 4 (planned 2026-10-16): standalone, reusable, deeper
Scoping answers (2026-10-16):
- **Goals:** make the server something anyone can deploy, not only this lab; then add ISE depth.
- **Deployers:** engineers on a laptop (`uvx`, stdio, one ISE) and teams on a shared host (Docker over HTTP, tokens,
  possibly several ISE deployments). Kubernetes/OAuth are not in this wave (core G1/G5 still apply later).
- **Standalone:** the package installs with no external requirement. stutters-mcp-core is **bundled into the
  ISE package by a build workflow**, not pulled from git or PyPI at install time.
- **Lab tooling** (`scripts/lab_policy.py`, `scripts/seed_lab.py`, lab-specific live tests and fixtures) moves to a
  private suite-wide repo, **`stutters-mcp-lab`**. Public live tests read env vars only.
- **Depth:** I31 guest/sponsor (queued), profiler authoring, device admin (TACACS+), and config export, diff and import.
  I32–I34 stay blocked on the Windows client VM (P11). The owner unblocks prerequisites as the lab comes back.
- **UX:** a second operator-eyes pass plus four new workflow prompts.
- **Lab is down:** this wave is planned only. Phase A needs no lab and goes first. Phases B and C need ISE 3.5 back.

### Phase A: standalone and reusable (no lab needed)
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| I35 | **Bundle core into the package**: a release workflow vendors a pinned stutters-mcp-core tag into the wheel and image (`ise_mcp._core`, imports rewritten at build time), so `pyproject.toml` has no git dependency; a CI check fails when the vendored copy drifts from the pinned tag; `ise_status` reports the bundled core version. The workflow is written so the other servers can copy it (or call it as a reusable workflow from core) | Installing today needs a git dependency and, for Docker, a `CORE_READ_TOKEN`. Neither is acceptable for someone outside the suite | none | Unit + contract suite run against the built wheel in a clean venv (no network after the build); install the wheel with `pip install --no-index`; check the drift check by bumping the tag | M | |
| I36 | **PyPI + `uvx` quickstart**: publish `ise-mcp-server` with PyPI trusted publishing from `release.yml`; console script `ise-mcp-server` (stdio by default); `ise-mcp-server check` preflight (reachability per surface, ERS port, TLS trust, admin permissions vs tool tiers, ISE version) that runs without an MCP client; copy-paste config for Claude Desktop / Claude Code; a 5-minute README quickstart | "Install and point at my ISE" in one command, with a clear answer when something is missing | PyPI account and the `ise-mcp-server` name; trusted publisher configured | Wheel install in a clean container; `check` against mocked surfaces (each failure mode); a TestPyPI release before the real one | M | |
| I37 | **Published container image**: multi-arch (amd64/arm64) image on GHCR, built from the I35 wheel; signed (cosign) with an SBOM attached; `docker-compose.yml` pulls the image instead of building; `CORE_READ_TOKEN` removed everywhere | Teams run it on a shared host without cloning or building | GHCR package permissions on the repo | Release workflow on a pre-release tag; `docker run ... check`; compose up with `.env` only; verify the signature and SBOM | S | |
| I38 | **Shared-host deployment guide and defaults**: read-only by default (write and dangerous tiers opt-in by env), per-user tokens with names in the audit log, several ISE deployments from one host (`ISE_INSTANCES`), TLS via a reverse proxy example (Caddy), least-privilege ISE account setup (from `docs/least-privilege.md`) as a step-by-step guide, upgrade notes | A team deployment that is safe on day one, without reading the source | none | Contract tests for the tier defaults; compose example with two mocked ISE instances; docs reviewed by following them on a clean host | M | |
| I39 | **De-lab the public repo**: move `scripts/lab_policy.py`, `scripts/seed_lab.py` and lab-only live tests to `stutters-mcp-lab`; public live tests take documented `ISE_LIVE_*` env vars and skip cleanly without them; replace lab names, domains and IPs in fixtures, docs and tool descriptions (e.g. `tools/ad.py` examples use `example.com`); `scrub_check` (core G9) runs in CI | Anyone can run the live suite against their own ISE, and the public repo carries no lab details | Private repo `stutters-mcp-lab` (suite-wide) | `scrub_check` clean in CI; unit suite green; live suite skips with no env, runs with the env set (when the lab is back) | M | |

### Phase B: ISE depth (needs the lab)
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| [I31](https://github.com/dr-stutters/ise-mcp-server/issues/72) | **Guest + sponsor** (already queued in Wave 3) | Guest is weekly work at most customers | Sponsor account with REST access; guest portal; CML `firefox` node | As in #72 | L | [#72](https://github.com/dr-stutters/ise-mcp-server/issues/72) |
| I40 | **Profiler authoring** (finishes I14): spike which profiler operations the 3.5 API allows; then custom profiling policies (create/update/delete where writable, otherwise documented as GUI-only), `ise_reprofile_endpoint` (CoA reauth), profiler probe status per PSN, feed-service status, and why an endpoint got its profile (matched policy, certainty factor, attributes seen) | "Why is this printer profiled as a workstation?" and custom IoT profiles are frequent PoC asks | Profiler service on the PSN; DHCP/RADIUS probes reaching ISE from the `ise-access` switch | Unit with recorded endpoint attributes; live: the `ise-access` client profiled by DHCP class-id, a custom policy matches it, reprofile CoA moves it | L | |
| I41 | **Device admin (TACACS+) depth**: TACACS external servers and sequences, `ise_admin_policy_explain` (admin user + NAD + command → device-admin rule, shell profile and command-set verdict), command-set test without a device, hit counts on device-admin rules, and a TACACS section in `ise_audit_nads` (shared secret set, single-connect) | Device-admin changes lock engineers out of switches; a "would this command be allowed" check before rollout prevents that | TACACS+ re-applied on sw1 (TCP 49 to ISE); Device Admin service enabled | Unit with policy fixtures; live on sw1: explain predictions vs the actual permit/deny for `show run`, `conf t`, `reload` as mcp-alice and mcp-bob | M | |
| I42 | **Config export + diff**: `ise_export_config(scope)` writes policy sets and rules, authz profiles, dACLs, NADs and NDGs (secrets masked), identity and endpoint groups, custom attributes, SGTs, SGACLs and the egress matrix, command sets and shell profiles as YAML with names instead of ids and stable ordering; `ise_diff_config` compares two exports, or an export with live ISE, by section | A reviewable baseline, "what changed since last week" (ISE has no audit REST API), and PoC → production hand-off | none | Unit: round-trip and stable ordering; live: export, change one rule, diff shows just that rule | L | |
| I43 | **Config import** (depends on I42): `ise_import_config` plans create/update/skip per object in dependency order (groups → profiles → policy sets → rules), matches by name, takes secrets separately, and previews the whole plan; applying is a dangerous-tier action with a change window, and it stops on first failure with what was applied | Moves a PoC policy to production, or rebuilds a lab, without retyping it | none | Unit with plans for empty and populated targets; live: export the lab, wipe the `mcp-test-*` objects, import, diff is empty | L | |

### Phase C: operator UX and workflow prompts
| # | Item | Why (operator value) | External needs | Test plan | Size | Issue |
|---|---|---|---|---|---|---|
| I44 | **Operator-eyes pass 2 + tool surface**: run operator tasks over the tools added since v0.7.0 (AD, certificates, SXP, pxGrid, endpoint bulk) and fix what breaks; review the ~113-tool surface: `ISE_TOOLSETS` env to load only some areas (e.g. `troubleshoot,policy`) so clients with tool limits stay usable | More tools made the server harder to pick tools from; a laptop user rarely needs all of them | none | Scripted operator tasks live (as v0.7.0); contract test per toolset | M | |
| I45 | **Prompt `ise_onboard_nad`**: NAD + NDGs with RADIUS/TACACS settings → switch AAA config (preview) via cml/catc → test auth → verify the session → record undo | The most common day-1 task, done the same way every time | cml or catc server for the switch step | Live with sw1 removed from ISE and its AAA config removed; prompt test kit (core C9) | S | |
| I46 | **Prompt `ise_policy_change_review`** (depends on I42): export before → proposed change (preview) → diff → `ise_policy_explain` on sample logins before and after → a change summary of who gains or loses access | Catches the "this rule now matches everyone" mistake before it is applied | none | Prompt test kit with mocked policy; live with an authz rule reorder | S | |
| I47 | **Prompt `ise_deployment_health_review`**: `ise_deployment_health`, cert expiry, licence, pxGrid status, AD join and SXP state as one ranked report with next steps | A weekly or pre-change review in one request | none | Prompt test kit on mocks (works while the lab is down); live once it is back | S | |
| I48 | **Prompt `ise_guest_onboarding`** (depends on I31): sponsor creates guests → credentials → verify the guest session and authz | End-to-end guest flow without the sponsor portal | Sponsor account; guest portal | Live with the CML `firefox` node | S | |

### Order
1. **Now (no lab):** I35 → I37 → I36 → I39 → I38, and I47 on mocks. Target release v0.10.0 (standalone).
2. **When the lab is back:** I31, I41, I42 → I43, I40. Target v0.11.0.
3. **Then:** I44, I45, I46, I48. Target v0.12.0.

### New prerequisites
| Prerequisite | Needed for | Status |
|---|---|---|
| PyPI account, `ise-mcp-server` name, trusted publisher | I36 | ⏳ owner |
| GHCR package permissions | I37 | ⏳ owner |
| Private repo `stutters-mcp-lab` | I39 | ⏳ owner |
| ISE 3.5 lab back up | I31, I40–I46, I48 | ⏳ owner |
| TACACS+ re-applied on sw1 | I41 | ⏳ when the lab is back |
| Profiler probes (DHCP/RADIUS) reaching the PSN | I40 | ⏳ when the lab is back |
| Sponsor account + guest portal | I31, I48 | ⏳ (I31) |

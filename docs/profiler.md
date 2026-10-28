# Profiler over the ISE 3.5 REST APIs

What ISE 3.5 lets a client read and change about profiling, from the I40 spike (issue #6): searched in the
OpenAPI groups ISE serves and the ERS SDK data model, then read against a lab ISE 3.5 (standalone node with
the Profiler service). Writes were made only through this server's preview-first tools, on `mcp-prof-*`
objects.

## Summary

| Area | API | Read | Write | Tools |
|---|---|---|---|---|
| Classic profiling policies (Policy > Profiling: conditions, certainty factor, minimum CF, parent, exceptions, CoA type) | ERS `profilerprofile` | name, description, `parentId` | **GUI only** | `ise_list_profiler_profiles`, `ise_explain_profile` (parent chain) |
| Custom profiling rules (3.3+ "Profiler Policy Management": CUSTOM / DIRECT / ML rules that set an endpoint's endpoint type, manufacturer, model and OS labels) | OpenAPI `/api/v1/profiler/policy` | yes | **create, update, enable/disable, delete** (CUSTOM) | `ise_list_profiling_rules`, `ise_set_profiling_rule`, `ise_delete_profiling_rule` |
| An endpoint's profile | OpenAPI `/api/v1/endpoint/{mac}` (`profileId`, `staticProfileAssignment`, the four `mfcInfo*` labels), MnT session (`endpoint_policy`, `profile-name` in the reply) | yes | static profile via `ise_set_endpoint` | `ise_explain_profile`, `ise_endpoint_360` |
| Certainty factor, matched policy, the endpoint's full attribute set (OUI, DHCP class-id, CDP/LLDP, NMAP results ...) | none | **GUI only** (Context Visibility > Endpoints > the MAC > Attributes: `TotalCertaintyFactor`, `MatchedPolicy`, `EndPointPolicy`, `PolicyVersion`) | — | `ise_explain_profile` says so and shows what the REST APIs do have |
| Profiler probes per PSN | OpenAPI `/api/v1/profile/{hostname}` | yes | PUT exists (replaces the whole probe set) | `ise_profiler_status` (read); changing probes is left to the GUI / `ise_api_call` |
| Profiler service per node | OpenAPI `/api/v1/deployment/node` (`services` contains `Profiler`) | yes | node service edits | `ise_profiler_status` |
| Profiler feed service (Cisco feed updates of the classic policies) | none | **GUI only** (Administration > FeedService > Profiler) | — | `ise_profiler_status` says so |
| Profiler sessions | MnT `Session/ProfilerCount` | yes | — | `ise_profiler_status`, `ise_list_active_sessions` |
| Reprofile an endpoint | no "reprofile" call; MnT `CoA/Reauth/{psn}/{mac}/{type}` through the PSN that owns the session | — | yes (dangerous tier) | `ise_reprofile_endpoint` |
| Cloud profiler / telemetry | OpenAPI `/api/v1/profiler/cloud/connection` | yes | register / deregister | `ise_profiler_status` (read) |
| SNMP endpoint scans | OpenAPI `/api/v1/profiler/snmp/scan*`, `/scan-history/{id}`, `/psn-groups` | yes | create / update / start / stop / enable / disable / delete | `ise_snmp_scan_history`, `ise_set_snmp_scan`, `ise_run_snmp_scan`, `ise_delete_object(kind='snmp_scan')` |
| Anomaly detection, profiler resiliency counters | OpenAPI `/anomaly/config`, `/resiliency/config` | yes | yes | not wrapped; `ise_api_call` |

## Details

### Classic profiling policies are read-only

ERS `profilerprofile` lists the ~680 profiling policies ISE ships (plus any made in the GUI) with `id`, `name`,
`description` and, on a GET by id, `parentId` (for example `Apple-iPhone` has `Apple-Device` above it). The ERS
SDK documents Get-All, Get-By-Id and Version only for this resource: no create, update or delete. The synthetic
ERS spec this server builds from the data model lists the generic CRUD paths for every resource, so
`ise_search_spec` shows them; they don't exist for `profilerprofile`. The conditions, certainty factors,
minimum certainty factor, exception actions and the network-scan action of a classic policy are in no REST API.

So: a new classic profiling policy, or a change to a shipped one, is made in the GUI (Work Centers > Profiler >
Profiling Policies). The custom profiling rules below are the API-writable alternative for classifying devices.

### Custom profiling rules (`/api/v1/profiler/policy`)

ISE 3.3 added "Profiler Policy Management": rules that set an endpoint's four labels
(`MFCInfoEndpointType`, `MFCInfoHardwareManufacturer`, `MFCInfoHardwareModel`, `MFCInfoOperatingSystem`)
when a condition on the endpoint's attributes matches. Authorization rules can then match the labels
(`EndPoints:MFCInfoEndpointType` etc.).

- `GET` takes `name`, `id` (comma-separated) and `type` (`CUSTOM` / `DIRECT` / `ML`) and returns an array of
  `ProfilePolicyWithId` (`policyId`, `name`, `status`, `rulePriority`, `profilingType`, `condition`,
  `profileLabel`, `matchedEndpoints`). It returned `[]` on a fresh 3.5 node: no rules ship.
- A rule as GET returns it on 3.5 has no `isNegate` on its condition nodes, and labels that were never set
  are `null` (see `tests/fixtures/profiler_rules.json`). `rulePriority` is required on create (ISE answers
  400 "Rule priority is missing" without it) and is stored as a rank: a single rule created with 10 and
  moved to 90 read back as 2. `ise_set_profiling_rule` defaults a new rule to after the existing ones.
- `POST` takes an **array** of `ProfilePolicy`; `PUT` an array of `ProfilePolicyWithId`; `DELETE` an array
  of ids (`DELETE /policy/name` an array of names); `PUT /policy-status` toggles `status` by id.
- `condition` uses the policy-set condition models (`ConditionAttributes`, `ConditionAndBlock`,
  `ConditionOrBlock`), but the dictionaries are the profiler's: `GET /api/v1/profiler/endpoint-custom-dictionary`
  lists them (`DHCP`, `MAC`, `CDP`, `LLDP`, `RADIUS`, `SNMP`, `NMAP`, `IP`, `MDM`, `ACIDEX`, `Posture`,
  `IOTASSET`, `Multimedia`, `MUD`, `ACTIVEDIRECTORY_PROBE`, `Wifi_Device_Analytics`) with their attribute names
  (`DHCP:dhcpClassIdentifier`, `MAC:oui`, `CDP:cdpCachePlatform` ...). `ise_set_profiling_rule` checks
  conditions against that list before sending anything.
- DIRECT rules (copy an attribute's value straight into a label, `/endpoint-direct-dictionary`) and ML rules
  (from AI endpoint analytics) are listed but not authored by the tools; use `ise_api_call` for DIRECT.

### Why an endpoint has its profile

The REST APIs have the result, not the reasoning:

- `/api/v1/endpoint/{mac}`: `profileId` (empty until the profiler classifies it), `staticProfileAssignment`,
  the four `mfcInfo*` labels, IP, and IoT asset fields.
- MnT `Session/MACAddress/{mac}`: `endpoint_policy` (the profile name at the last authentication) and the
  `profile-name` cisco-av-pair ISE returned to the NAD.
- ERS `profilerprofile/{id}`: the policy and its `parentId`, so the parent chain can be walked.
- `/api/v1/profiler/policy`: custom rules whose labels match the endpoint's.

The certainty factor, the matched policy with its version, and the raw attributes the probes collected are
shown only on the endpoint's Context Visibility page. `ise_explain_profile` assembles what is available and
points there for the rest.

### Probes and services

`GET /api/v1/profile/{hostname}` returns the probe set of one PSN. A probe set to `null` is disabled. One that
is an object or a list (even an empty list, for `radius`, `nmap` and `pxgrid`) is enabled, for example:

```json
{"response": {"dhcp": {"interfaces": [{"interface": "GigabitEthernet 0"}], "port": 67}, "radius": [],
 "nmap": [], "snmpQuery": {"retries": 2, "timeout": 1000, "eventTimeout": 30},
 "activeDirectory": {"daysBeforeRescan": 1}, "netflow": null, "dhcpSpan": null, "http": null,
 "dns": null, "snmpTrap": null, "pxgrid": null}, "version": "1.0.0"}
```

`PUT` replaces the whole set (a probe left out or `null` is disabled), so changing probes from a tool is easy to
get wrong on a shared deployment; `ise_profiler_status` stays read-only.

There is no REST view of the profiler feed service (last update, subscription status); it is in the GUI only.

### Endpoint SNMP scans (`/api/v1/profiler/snmp`)

For IoT and OT segments the profiler can query endpoints over SNMP itself (Work Centers > Profiler > Endpoint
Scans). ISE 3.5's OpenAPI 'Profiler' group has the whole lifecycle:

- `GET /scan` lists the scans (the lab answers a bare list); each entity carries `jobStatus`, the last
  `scanStartTime` / `scanEndTime` (epoch ms), `scannedIp`, `discoveredIp` and the settings under `scanDetails`.
- `POST /scan` and `PUT /scan/{id}` take `SNMPScanAttributes`: `name`, `isEnabled`, `scanSource` (a PSN FQDN or
  PSN group from `GET /psn-groups`), `networkScope` (`subnets` of /21../32 or /117../128, **or** `ipRanges`,
  never both, plus `excludedIps`), `scheduleTime` (`NO_SCHEDULE`, `DAILY`, `WEEKLY`, `MONTHLY` with a `time`
  in the '12:00 am' form) and `snmpAuthData` (`snmpV1`/`snmpV2` with `roCommunity`, or `snmpV3` with user,
  security level, protocols and passwords). An update replaces the whole scan, credentials included.
- `POST /scan/action` `{"action": "start"|"stop", "ids": [...]}`: ISE starts one scan per request and stops
  several. `POST /scan/status` `{"status": "enable"|"disable", "ids": [...]}`: a disabled scan never runs,
  even on its schedule. Both answer `{"result": [{"id", "status", "failureReason"}]}`.
- `GET /scan-history/{id}`: the runs (`scanResult`, `psnFqdn`, `scannedIp`, `discovered`, `ipNotReachable`,
  `snmpAuthFailed`, `snmpNullResponse`, `scanErrorDetails`).

`ise_set_snmp_scan` reads the credentials from `ISE_SNMP_...` environment variables (or `_FILE` twins), never
from arguments; when the stored community is not returned by ISE, an update other than enable/disable needs
it again. A weekly or monthly `time` is sent as '<day> <time>' ('Monday 02:00 am', '15 02:00 am'); the 3.5
spec documents the day without a field for it.

- Enabled state: ISE 3.5 answers the entity's top-level `status` (`ENABLED` / `DISABLED`). After
  `POST /scan/status` disable it leaves `scanDetails.isEnabled` and `scanStatus` `true`, so the tools read
  `status` first and fall back to those only when it is absent.
- Delete: `DELETE /scan/{id}` answers `405 Request method 'DELETE' not supported`. The working call is the
  collection `DELETE /scan` with body `{"ids": ["<id>"]}` (deleteSNMPScans), answering
  `{"result": [{"id": null, "status": "success"}]}`. `ise_delete_object(kind='snmp_scan', target=<name>)`
  sends it, preview-first, and is blocked while a run is in progress (stop it first).

### Reprofile

ISE has no "reprofile now" call. The profiler reclassifies an endpoint when new attributes arrive, and then
issues its own CoA if the profiling policy's CoA type says so. `ise_reprofile_endpoint` sends a CoA
reauthenticate through the PSN that owns the session (MnT names it), so the NAD re-authenticates: RADIUS (and
IOS sensor / device-sensor attributes) reach the profiler again, and the authorization result applies the
current profile. Like any CoA it briefly interrupts the endpoint on some NADs; it is in the dangerous tier and
preview-first. An endpoint with a static profile assignment keeps that profile; the preview says so.

## Verified live (ISE 3.5)

`tests/live/test_live_profiler.py`: probe status per PSN; a custom rule `mcp-prof-<run>` created (two
conditions, disabled), updated (a label and priority), refused for an unknown attribute, and deleted;
`ise_explain_profile` on a lab endpoint and on an unknown MAC; and, with `ISE_LIVE_REPROFILE_MAC`, a reprofile
CoA that the switch acknowledged, followed by a new authentication in MnT.

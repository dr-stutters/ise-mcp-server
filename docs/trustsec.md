# TrustSec segmentation, proven on a switch (I51, I55)

How to take an ISE TrustSec policy from "cells in the matrix" to "the switch drops the packets", with the
tools of this server, the switch CLI, and ISE's own download report (`ise_trustsec_device_report`). Written
against ISE 3.5.0.527 and a Catalyst 9000v (IOS-XE 17.18) in the CML `ise-access` lab on 2026-10-18; the
evidence of that run is at the end.

The scenario: `alice` (AD group employees) and `bob` (AD group contractors) log in with 802.1X on the same
access switch. Authorization gives alice SGT `Employees` (4) and bob SGT `Contractors` (5). The data centre
host carries SGT `Production_Servers` (11). One egress cell, Contractors -> Production_Servers = `Deny IP`,
makes the switch drop bob's traffic to the DC while alice's passes.

## 1. What has to be in place

| Piece | Where | Check |
|---|---|---|
| SGTs `Employees`, `Contractors`, `Production_Servers` | ISE defaults | `ise_list_sgts` |
| SGACL `Deny IP` (`deny ip`) | ISE defaults | `ise_list_sgacls`. ISE's default TrustSec setting allows one SGACL per cell (`allowMultipleSGACLs` in `GET /api/v1/trustsec/general-settings`): with it off, a cell takes one SGACL and catch-all `NONE`; an SGACL plus `DENY_IP` is rejected as "multiple SGACLs". On a Catalyst 9000v the `log` keyword (`Deny_IP_Log`) crashed the simulated dataplane on the first hit; real hardware logs `%RBM-6-SGACLHIT` |
| Authorization rules that return the SGTs | policy set `mcp-test-wired`: `mcp-test-ad-employees` -> Employees, `mcp-test-ad-contractors` -> Contractors | `ise_get_policy_set("mcp-test-wired")` |
| TrustSec settings on the switch's NAD: device id + password | `ise_update_nad(device, trustsec_id=, trustsec_password=)` | `ise_get_nad` shows `trustsecsettings` |
| CTS credentials, PAC and enforcement on the switch | section 2 | `show cts pacs`, `show cts environment-data` |
| An SGT for the destination the switch can see | static `cts role-based sgt-map` on the switch, an ISE IP-SGT mapping sent over SXP (`ise_set_ip_sgt` + `ise_set_sxp_connection`) or deployed over SSH (`ise_deploy_ip_sgt`) | `show cts role-based sgt-map all`. Binding precedence matters: an IP learned under an authenticated session (`LOCAL`) keeps the session's SGT and beats a static map (`CLI`), so the destination host must not have its own session on a port with device tracking, or must be tagged by its own authorization |

The NAD's TrustSec device id and password are what the switch presents (`cts credentials`) to get its PAC
and, with it, environment data (the SGT table) and policy. Without them the switch never appears in
`ise_trustsec_device_report`.

## 2. Switch configuration (IOS-XE)

The RADIUS server block needs a `pac key` equal to the device's RADIUS shared secret, an authorization
list for CTS, enforcement, and the credentials (an exec command, stored in the keystore, not in the
running config):

```
configure terminal
 radius server ISE
  pac key <RADIUS shared secret>
 aaa authorization network MCP-CTS group radius
 cts authorization list MCP-CTS
 cts role-based enforcement
 cts role-based enforcement vlan-list 10
 cts role-based sgt-map 198.18.130.11 sgt 11      ! the DC: Production_Servers, if not learned from ISE
 device-tracking policy MCP-DT                    ! binds each session's SGT to the client's IP
  tracking enable
 interface range GigabitEthernet1/0/2 - 3
  device-tracking attach-policy MCP-DT
end
cts credentials id mcp-test-sw1 password <TrustSec device password>
cts refresh environment-data
```

Then:

```
show cts pacs                      ! A-ID and an expiry: the PAC was provisioned
show cts environment-data          ! "Current state = COMPLETE", the SGT table, the server list
show cts role-based permissions    ! the egress cells the switch holds
show cts role-based sgt-map all    ! IP -> SGT bindings (LOCAL from sessions, CLI from static maps)
show cts role-based counters       ! SW-Permitted / SW-Denied per cell: this is the proof
```

Over the cml-mcp-server, `cml_run_commands` runs the show commands and `cml_configure_node` applies the
configuration lines (`mode='exec'` for `cts credentials` and `cts refresh`), both preview-first.

## 3. Policy, push, verify

1. **Preview the cell** and show it to the user: `ise_set_egress_policy(source_sgt="Contractors",
   destination_sgt="Production_Servers", sgacls=["Deny IP"], default_rule="NONE")`. Confirm with the
   token once approved. `ise_get_egress_matrix(source="Contractors")` shows the cell.
2. **Push it**: `ise_push_trustsec_matrix()` (dangerous tier, previewed: a TrustSec CoA to every TrustSec
   device, which then re-downloads policy). ISE only sends the CoA to NADs whose TrustSec settings have
   "send configuration changes to device" on (`ise_update_nad(trustsec_push=True)`; on by default when the
   tool first enables TrustSec), and only when a policy change is pending: a push with nothing pending
   returns `NO_REQUEST_AVAILABLE`. Without the push the switch picks the change up on its policy refresh
   timer (`downloadSGACLListsEveryXSeconds`, a day by default) or on `cts refresh policy`.
3. **ISE's view**: `ise_trustsec_device_report()` lists every device that has downloaded policy over
   ISE's TrustSec HTTPS (REST) channel, with the last step (`SGACLs downloaded`, `environment data
   downloaded`, `CoA sent`), its status, when ISE last changed policy, when the device last reported and
   `current` (true when the device reported success after the last policy change).
   `ise_trustsec_device_report(nad="sw1")` reads one device; names may be partial or an IP, like
   `ise_get_nad`. The report is fed by the HTTPS policy download (ISE 3.x: `httpsServerConfig.enableHttps`
   in `GET /api/v1/trustsec/general-settings`, REST API credentials on the NAD's TrustSec settings, and
   `cts policy-server` on IOS-XE 17.x); a switch that downloads over RADIUS with a PAC, as in this run,
   never appears in it, and the switch CLI is the check. The tool says so when the report is empty.
4. **Switch's view**: `show cts role-based permissions` lists the cell with its SGACL; `show cts role-based
   counters` shows the per-cell counters.
5. **Traffic**: bob (SGT 5) sends to the DC (SGT 11): the `HW-Denied` (or `SW-Denied`) counter of the
   5 -> 11 cell increases and the pings get no reply. alice (SGT 4) to the DC: the pings are answered and
   `HW-Permitt` increases on the default (`*` -> `*`, `Permit IP`) cell.

## 4. When enforcement does not happen

Work down the list; `ise_trustsec_device_report` names the failing step and the hint for it.

| Symptom | Cause | Fix |
|---|---|---|
| Device missing from `ise_trustsec_device_report`; `show cts pacs` empty; `show cts environment-data` stays `START` / `In Progress` | No PAC: the NAD has no TrustSec settings, or `cts credentials` on the switch differ from the NAD's device id/password, or `pac key` differs from the RADIUS secret | `ise_get_nad` (trustsec: yes?), `ise_update_nad(trustsec_id=, trustsec_password=)`; on the switch `cts credentials id ... password ...` then `cts refresh environment-data`; `clear cts pacs` to start again |
| Status `ENV_REQUEST_FAILED` | Environment data download failed (same causes) | as above; `show cts environment-data` for the error |
| Environment data complete but `show cts role-based permissions` shows no cells | Policy not downloaded: no `cts authorization list`, or the list's AAA group has no server | `cts authorization list <list>`; `cts refresh policy`; `show cts authorization entries` |
| `current: false`, hint "ISE changed policy after the device last downloaded it" | The cell was added after the last download and no push happened, or the CoA did not reach the switch | `ise_push_trustsec_matrix` or `cts refresh policy`; for CoA failures (`COA_TIMED_OUT`, `COA_NACK`) check the NAD's CoA port and `aaa server radius dynamic-author` + key on the switch |
| Cell present, counters stay at 0 | The switch has no SGT for the source or destination IP: `show cts role-based sgt-map all` lacks the client (`show access-session ... details` says `IPv4 Address: Unknown`: no device-tracking policy on the port, so the session's SGT is never bound to an IP) or the DC (no static map / SXP / deploy) | attach a `device-tracking policy` with `tracking enable` to the access ports (section 2); add the destination mapping (`cts role-based sgt-map`, `ise_set_ip_sgt` + SXP, or `ise_deploy_ip_sgt`) |
| Counters increase on the wrong cell | The session got a different SGT: `ise_get_auth_history(mac)` / `show access-session interface ... details` show the SGT the rule returned | fix the authorization rule or the AD group, then CoA reauth (`ise_coa_reauth`) |
| Enforcement off | `cts role-based enforcement` (and `vlan-list` for SVI traffic) missing from `show run | include cts role-based` | add it |
| ISE rejects the cell: "can not change cell to multiple sgacls" | `allowMultipleSGACLs` is off in ISE's TrustSec general settings and the cell names an SGACL plus a `PERMIT_IP`/`DENY_IP` catch-all | one SGACL with `default_rule="NONE"`, or turn the setting on (`PUT /api/v1/trustsec/general-settings`) |
| Device present on the switch (`show cts pacs`, policy downloaded) but missing from `ise_trustsec_device_report` | The switch downloads over RADIUS; the report covers the HTTPS download | expected; verify on the switch, or move the switch to `cts policy-server` with ISE's HTTPS server enabled |
| Catalyst 9000v: the switch reloads on the first SGACL hit (`%SIMULATION_ERRMSG-3-rw_err ... run_cima.sh`), or routed client traffic is never counted | Simulator limits: `deny ip log` crashed the dataplane; traffic routed from the client VLAN out of the uplink was not seen by the role-based counters or an uplink capture | use `Deny IP` (no `log`), test with a destination in the client VLAN (L2 egress enforcement with `vlan-list`), and keep the CTS lines saved so a reload does not lose them |

The egress cell is enforced where the destination SGT is known: on the switch the traffic leaves (here the
access switch's routed uplink). With SXP or a deployed mapping, the destination can be learned from ISE; with
nothing, only static maps on the switch work.

## 5. Undo

`ise_delete_trustsec_object(kind="egress_cell", name=...)` removes the cell (or `ise_set_egress_policy`
back to `Permit IP`), then `ise_push_trustsec_matrix` so the switch drops it. On the switch: `no cts
role-based enforcement`, `no cts role-based sgt-map ...`, `clear cts pacs` and `clear cts credentials` take
it out of TrustSec; `ise_update_nad` has no "remove TrustSec" (ERS cannot clear `trustsecsettings`
separately), so the NAD keeps its credentials until it is re-created.

## 6. Evidence (2026-10-18, lab run)

ISE 3.5.0.527, CML lab `mcp-cml-ise` (recipe `ise-access`): sw1 = Catalyst 9000v IOS-XE 17.18.2, NAD
`mcp-test-sw1` (198.18.128.154), policy set `mcp-test-wired`. The Ubuntu client on Gi1/0/3 (10.10.10.50) ran
PEAP as `mcp-bob` then `mcp-alice`; the Alpine host on Gi1/0/2 (10.10.10.100, MAB) stood in for the DC with a
static map to SGT 11 (its port without device tracking, so the static map applied). The real DC's address
(198.18.130.11) was mapped too, but traffic routed out of the uplink was not observable on this simulator.

**ISE: authorization gave the SGTs** (`ise_get_auth_history(mac="52:54:00:62:C6:B2")`):

| time (UTC) | user | protocol | rule result | SGT |
|---|---|---|---|---|
| 10:47:19 | mcp-bob | PEAP (EAP-MSCHAPv2), MITCHCLOUD | mcp-test-permit | Contractors (`cts:security-group-tag=0005-00`) |
| 11:10:23 | mcp-alice | PEAP (EAP-MSCHAPv2), MITCHCLOUD | mcp-test-permit | Employees (`cts:security-group-tag=0004-00`) |

**ISE: the cell and the push.** `ise_update_nad("mcp-test-sw1", trustsec_id="mcp-test-sw1",
trustsec_password=...)` then `trustsec_push=True`; `ise_set_egress_policy("Contractors",
"Production_Servers", ["Deny IP"], "NONE")`; `ise_push_trustsec_matrix()` -> `{"propagationId": "5",
"status": "DONE"}`. `ise_get_egress_matrix(source="Contractors")`:

```
| source          | destination             | sgacls  | default_rule | status  |
| Contractors (5) | Production_Servers (11) | Deny IP | DENY_IP      | ENABLED |
```

**sw1: PAC, environment data, the downloaded cell, the bindings.**

```
mcp-sw1#show cts pacs | include I-ID|Lifetime
  I-ID: mcp-test-sw1
  Credential Lifetime: 11:07:53 UTC Sat Jan 16 2027
mcp-sw1#show cts environment-data | include state|Last update|SGT tag|Server:
Current state = COMPLETE
  SGT tag = 2-00:TrustSec_Devices
 *Server: 198.18.134.35, port 1812, A-ID DDDC056F4339C0EA4D56FA3DB6FFE275
Last update time = 11:07:50 UTC Sun Oct 18 2026
mcp-sw1#show cts role-based permissions
IPv4 Role-based permissions default:
        Permit IP-00
IPv4 Role-based permissions from group 5:Contractors to group 11:Production_Servers:
        Deny IP-00
mcp-sw1#show cts role-based sgt-map all
IP Address              SGT     Source
10.10.10.1              2       INTERNAL
10.10.10.50             5       LOCAL        <- bob's session (4 LOCAL once alice logged in)
10.10.10.100            11      CLI          <- the DC stand-in
198.18.128.154          2       INTERNAL
198.18.130.11           11      CLI
```

**bob denied** (`clear cts role-based counters`, then from the client `ping -c 5 -W 1 10.10.10.100`):

```
5 packets transmitted, 0 received, 100% packet loss, time 4073ms

mcp-sw1#show cts role-based counters
From    To      SW-Denied  HW-Denied  SW-Permitt HW-Permitt SW-Monitor HW-Monitor
*       *       0          0          0          1          0          0
5       11      0          5          0          0          0          0
```

**alice permitted** (supplicant restarted as `mcp-alice`, session shows `User-Name: mcp-alice`, `SGT
Value: 4`, binding `10.10.10.50 4 LOCAL`; counters cleared, same ping):

```
5 packets transmitted, 5 received, 0% packet loss, time 4006ms

mcp-sw1#show cts role-based counters
From    To      SW-Denied  HW-Denied  SW-Permitt HW-Permitt SW-Monitor HW-Monitor
*       *       0          0          0          10         0          0
5       11      0          0          0          0          0          0
```

**ISE's device report** (`ise_trustsec_device_report()`): empty, with the note that the report covers the
HTTPS download and that this switch downloads over RADIUS. ISE's TrustSec HTTPS server was off
(`GET /api/v1/trustsec/general-settings` -> `httpsServerConfig.enableHttps: false`). Turning it on, adding
REST credentials to the NAD and `cts policy-server` on sw1 is the follow-up that makes the report agree with
the switch; everything else above is ISE and the switch agreeing on the policy (ISE's cell is the cell the
switch enforces, with the SGTs ISE assigned).

**Undo done after the run:** the cell deleted (`ise_api_call DELETE /ers/config/egressmatrixcell/<id>`,
previewed) and pushed (`propagationId 6, DONE`), matrix back to ANY-ANY only; the `cts`, `pac key`,
`device-tracking` and `MCP-CTS` lines removed from sw1, `clear cts pacs`, config saved; the client's EAP-TLS
supplicant restored. Kept: the NAD's TrustSec settings and the switch's `cts credentials` (keystore), with
the password in `lab-secrets.env` as `LAB_CTS_PASSWORD`, so the next run starts at section 2.

# TrustSec segmentation, proven on a switch (I51, I55)

How to take an ISE TrustSec policy from "cells in the matrix" to "the switch drops the packets", with the
tools of this server, the switch CLI, and ISE's own download report (`ise_trustsec_device_report`). Written
against ISE 3.5.0.527 and a Catalyst 9000v (IOS-XE 17.18) in the CML `ise-access` lab on 2026-10-18; the
evidence of that run is at the end.

The scenario: `alice` (AD group employees) and `bob` (AD group contractors) log in with 802.1X on the same
access switch. Authorization gives alice SGT `Employees` (4) and bob SGT `Contractors` (5). The data centre
host carries SGT `Production_Servers` (11). One egress cell, Contractors -> Production_Servers = `Deny_IP_Log`,
makes the switch drop bob's traffic to the DC while alice's passes.

## 1. What has to be in place

| Piece | Where | Check |
|---|---|---|
| SGTs `Employees`, `Contractors`, `Production_Servers` | ISE defaults | `ise_list_sgts` |
| SGACL `Deny_IP_Log` (`deny ip log`) | ISE defaults | `ise_list_sgacls` |
| Authorization rules that return the SGTs | policy set `mcp-test-wired`: `mcp-test-ad-employees` -> Employees, `mcp-test-ad-contractors` -> Contractors | `ise_get_policy_set("mcp-test-wired")` |
| TrustSec settings on the switch's NAD: device id + password | `ise_update_nad(device, trustsec_id=, trustsec_password=)` | `ise_get_nad` shows `trustsecsettings` |
| CTS credentials, PAC and enforcement on the switch | section 2 | `show cts pacs`, `show cts environment-data` |
| An SGT for the destination the switch can see | static `cts role-based sgt-map` on the switch, an ISE IP-SGT mapping sent over SXP (`ise_set_ip_sgt` + `ise_set_sxp_connection`) or deployed over SSH (`ise_deploy_ip_sgt`) | `show cts role-based sgt-map all` |

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
   destination_sgt="Production_Servers", sgacls=["Deny_IP_Log"], default_rule="DENY_IP")`. Confirm with the
   token once approved. `ise_get_egress_matrix(source="Contractors")` shows the cell.
2. **Push it**: `ise_push_trustsec_matrix()` (dangerous tier, previewed: a TrustSec CoA to every TrustSec
   device, which then re-downloads policy). Without the push the switch picks the change up on its policy
   refresh timer (`downloadSGACLListsEveryXSeconds`, a day by default) or on `cts refresh policy`.
3. **ISE's view**: `ise_trustsec_device_report()` lists every device that has downloaded policy, with the
   last step (`SGACLs downloaded`, `environment data downloaded`, `CoA sent`), its status, when ISE last
   changed policy, when the device last reported and `current` (true when the device reported success after
   the last policy change). `ise_trustsec_device_report(nad="sw1")` reads one device; names may be partial
   or an IP, like `ise_get_nad`.
4. **Switch's view**: `show cts role-based permissions` lists the cell with its SGACL; `show cts role-based
   counters` shows the per-cell counters.
5. **Traffic**: bob (SGT 5) sends to the DC (SGT 11): the `SW-Denied` counter of the 5 -> 11 cell increases
   and the switch logs `%RBM-6-SGACLHIT` (the `log` keyword in `Deny_IP_Log`). alice (SGT 4) to the DC:
   `SW-Permitted` increases on the default (ANY-ANY `Permit IP`) cell.

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

_To be filled from the live run._

# ise_onboard_nad

title: Onboard a switch into ISE
arguments: {"device_type": "Switch", "ip": "192.0.2.21", "ise_address": "192.0.2.10", "location": "SYD", "mac": "aa:bb:cc:dd:ee:ff", "name": "syd-acc-sw01", "protocols": "both", "site": "Global/SYD/Bldg-1", "source_interface": "Vlan10", "switch": "lab/sw1", "test_user": "alice", "vrf": ""}

Day-1 onboarding of an access switch into ISE, the same way every time: the location and
device-type groups, the NAD with its RADIUS and/or TACACS+ secret, the switch's AAA config (a
preview through cml_configure_node, Catalyst Center's site AAA settings or a template), a test
login seen in ISE, the endpoint session, a recorded undo (ISE and the switch's 'no' lines), and
a closing coverage check of the site against ISE's NADs. Every change is a preview the user
approves.

## user

Onboard switch syd-acc-sw01 into ISE for RADIUS and TACACS+, configured through the CML node sw1 in lab lab.
Rules for every write below: call the tool WITHOUT confirm, show the preview, wait for the user's
approval; never pass confirm yourself. Secrets (the RADIUS secret and the TACACS+ key) come from the user, are the same in ISE and
on the switch, and are never repeated back or written in the report; never invent one. The cml_* and
catc_* tools need those servers: without one, do the ISE steps and give the switch lines for the user
to paste.

Where AAA comes from: the NAD address is the IP of the interface that sources AAA. Cisco's campus
design sources it from the in-band management SVI or Loopback0, so the address stays the same
whichever uplink is up. Sourcing it from the out-of-band management port (GigabitEthernet0/0 in
Mgmt-vrf, the switch's counterpart of SD-WAN's VPN 512) is a common lab and data-centre pattern and is
fine when ISE is reachable on the management network: then set vrf="Mgmt-vrf". No VRF given: the source interface is in the global table (step 1 checks it).

1. Before any change (read only).
   - ISE: `ise_get_nad` with device="192.0.2.21" (and with the name, if an IP was given):
     an existing NAD at that IP or name means step 4 updates it with `ise_update_nad`
     instead of adding a second one.
   - Switch, `cml_run_commands` with lab="lab", nodes=["sw1"]: "show running-config | section aaa|radius|tacacs|dot1x",
     "show running-config | include ^username", "show ip interface brief", "show vrf",
     "show aaa servers". Record what is already there (the undo restores it, and 'aaa new-model'
     stays if it was on).
     A ping from the switch to 192.0.2.10 and source Vlan10 must answer.
   - Lockout guard: the switch must have a local privilege-15 username that logs in on the console.
     No such account: stop and say so; the config below falls back to local accounts only.

2. Device groups. `ise_list_ndgs` with name="SYD" and
   name="Switch": which of "Location#All Locations#SYD", "Device Type#All Device Types#Switch" exist.

3. Create the missing groups (previews).
   - `ise_create_ndg` with path="Location#All Locations#SYD" if step 2 found it missing (each
     missing parent first: the tool refuses a group whose parent doesn't exist).
   - `ise_create_ndg` with path="Device Type#All Device Types#Switch" if it is missing.

4. The NAD (preview). `ise_create_nad` with name="syd-acc-sw01", ips=["192.0.2.21/32"],
   radius_secret=<from the user>, tacacs_secret=<from the user>, groups=["Location#All Locations#SYD", "Device Type#All Device Types#Switch"], coa_port=1700,
   description="Access switch, AAA from Vlan10". Then `ise_get_nad` with
   device="syd-acc-sw01": groups, secret set, CoA port.

5. The switch's AAA config (preview). The lines (IOS XE; Cisco's campus NAC defaults):
     aaa new-model
     aaa authentication login default local
     aaa authorization exec default local
     radius server ISE-PSN1
      address ipv4 192.0.2.10 auth-port 1812 acct-port 1813
      key <the RADIUS secret>
     aaa group server radius ISE-RADIUS
      server name ISE-PSN1
      ip radius source-interface Vlan10
     aaa authentication dot1x default group ISE-RADIUS
     aaa authorization network default group ISE-RADIUS
     aaa accounting dot1x default start-stop group ISE-RADIUS
     aaa server radius dynamic-author
      client 192.0.2.10 server-key <the RADIUS secret>
     radius-server attribute 6 on-for-login-auth
     radius-server attribute 8 include-in-access-req
     radius-server attribute 25 access-request include
     radius-server dead-criteria time 5 tries 3
     radius-server deadtime 15
     dot1x system-auth-control
     tacacs server ISE-PSN1
      address ipv4 192.0.2.10
      key <the TACACS+ key>
     aaa group server tacacs+ ISE-TACACS
      server name ISE-PSN1
      ip tacacs source-interface Vlan10
     aaa authentication login ISE-ADMIN group ISE-TACACS local
     aaa authorization exec ISE-ADMIN group ISE-TACACS local
     aaa accounting commands 15 ISE-ADMIN start-stop group ISE-TACACS
     line vty 0 15
      login authentication ISE-ADMIN
      authorization exec ISE-ADMIN
      accounting commands 15 ISE-ADMIN
   Leave out the two 'default local' lines if step 1 found default login/exec lists already, and
   keep the existing ones. The secrets go only into the tool arguments. Console logins keep the
   local default list; the vty lines use ISE-ADMIN (TACACS+, then local when ISE is unreachable).
   802.1X/MAB on the access ports is a separate change: none of these lines touch an interface.
   `cml_configure_node` with lab="lab", node="sw1", lines=[the lines above],
   save=false, WITHOUT confirm. Show the preview and wait for the user's approval. Save only after
   step 6 passes: the same tool with mode="exec", lines=["write memory"] (a preview again).

6. Test the login.
   - RADIUS: the user types on the switch console (never here):
       test aaa group ISE-RADIUS alice <password> new-code
     The switch's answer is the proof: "User successfully authenticated" or "User rejected" both
     prove the path and the secret. A 'test aaa' login sends no RADIUS accounting, so MnT keeps no
     record of it, passed or failed: `ise_get_auth_list` and `ise_recent_auth_failures` stay empty, and the
     rule it hit is only in the GUI (Operations > RADIUS > Live Logs, NAS IP 192.0.2.21). No answer
     at all: 'show aaa servers' (requests rising, no responses = the secret, the source address or
     the route).
   - TACACS+: the user opens a NEW SSH session to 192.0.2.21 with
     alice (keep the current session open until it works).
     `ise_admin_policy_explain` with user="alice", nad="syd-acc-sw01" shows the
     device-admin rule it lands on (a device-admin policy set must match the NAD's groups). ISE has
     no REST live log for TACACS+: on the switch 'show tacacs' counts it, and the user reads
     Operations > TACACS > Live Logs.
   - Lockout check (TACACS+): log in once more with the LOCAL account on the console. It must still
     work; if it doesn't, undo step 5 at once.
   - `ise_policy_explain` with nad="syd-acc-sw01", flow="wired-dot1x": which policy set and rule
     endpoints on this switch will hit.

7. Verify the session. `ise_find_session` with mac="AA:BB:CC:DD:EE:FF": NAD IP 192.0.2.21, the port, the authorization rule and profile.
   No endpoint yet: say so (a 'test aaa' login sends no accounting, so it has no session).

8. Coverage check. `catc_list_devices` with site="Global/SYD/Bldg-1" (hostname, managementIpAddress); pass the
   rows to `ise_audit_nads` as expected=, with stale_within="Location#All Locations#SYD" (a site is part of the inventory).
   The new NAD must match by IP with its groups (no missing_nad, wrong_ndg, ip_mismatch, aaa_elsewhere);
   list any stale NADs it reports at the site for the user, without deleting them.

9. Report and record the undo. One table: NAD (created/updated, groups) | switch config (lines
   applied, saved) | test login | session | coverage findings. Then the exact undo, in this order:
   - Switch (`cml_configure_node` with lab="lab", node="sw1" and these lines):
       line vty 0 15
        no login authentication ISE-ADMIN
        no authorization exec ISE-ADMIN
        no accounting commands 15 ISE-ADMIN
       exit
       no aaa accounting commands 15 ISE-ADMIN start-stop group ISE-TACACS
       no aaa authorization exec ISE-ADMIN group ISE-TACACS local
       no aaa authentication login ISE-ADMIN group ISE-TACACS local
       no aaa group server tacacs+ ISE-TACACS
       no tacacs server ISE-PSN1
       no aaa server radius dynamic-author
       no aaa accounting dot1x default start-stop group ISE-RADIUS
       no aaa authorization network default group ISE-RADIUS
       no aaa authentication dot1x default group ISE-RADIUS
       no aaa group server radius ISE-RADIUS
       no radius server ISE-PSN1
       no radius-server attribute 6 on-for-login-auth
       no radius-server attribute 8 include-in-access-req
       no radius-server attribute 25 access-request include
       no radius-server dead-criteria time 5 tries 3
       no radius-server deadtime 15
       no dot1x system-auth-control   (only if step 1 found it off)
     Leave out any line step 1 found configured before this run; 'no aaa new-model' only if step 1
     found it off.
   - ISE: `ise_delete_nad` with device="syd-acc-sw01" (dangerous tier; preview first, the user
     approves it); then the groups created in step 3, children first, with
     `ise_delete_object` kind="ndg", target=<path> (only groups this run created and
     no other NAD uses: the preview shows what still references them).

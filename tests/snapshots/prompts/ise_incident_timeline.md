# ise_incident_timeline

title: Incident timeline across ISE, FMC, Catalyst Center and the lab
arguments: {"firewall": "ftd1", "ip": "", "lab": "lab", "mac": "", "minutes": "60", "nad": "192.0.2.21", "switch": "lab/sw1", "username": "", "window_end": "2026-10-29T09:20Z", "window_start": "2026-10-29T09:10Z"}

Build one time-ordered incident timeline, merged by timestamp. With a host (MAC, IP or user):
its ISE authentications, session and ANC state, FMC audit/deployments and Catalyst Center 360,
events, issues and audit. Without one ('what happened between 09:10 and 09:20?'): every
operator change and event in the window - FMC activity and the FTD's show logging, Catalyst
Center activity and the switch's logging, ISE authentications and failures by NAD and user,
CML lab events, and NetBox changes and AD group changes when those servers are connected.
Read-only; sources whose server is not connected are skipped with a note.

## user

Build an incident timeline for the window 2026-10-29T09:10:00Z to 2026-10-29T09:20:00Z (UTC). No host is given: collect every
operator change and event in the window first, then point at the hosts or devices worth a closer look.
Query each source on demand, collect (time, source, event, who) rows, then present them merged in time
order. Every tool here is read-only; change nothing. Use UTC and note each source's own clock offset.
Several tools only take a look-back that ends now: use the look-back given and drop rows outside the
window yourself.

Only this server's tools (ise_*) are certain to exist. The fmc_*, catc_*, cml_*, netbox_* and win_* tools
need those servers connected to this client: if a call isn't available, write "<source> not connected -
skipped" for that section and carry on.

1. ISE (authentications in the window, by NAD and user).
   - `ise_get_auth_list` with since_minutes=10, until="2026-10-29T09:20:00Z", nad="192.0.2.21": every authentication in the window; group
     the rows by NAD and by user (count, PASS/FAIL) and keep the first and last time of each group.
   - `ise_recent_auth_failures` with since_minutes=<minutes from 2026-10-29T09:10:00Z until now, rounded up>, nad="192.0.2.21": failures with decoded
     reasons; a burst of one reason on one NAD is a timeline row of its own.
   - ISE's configuration change audit is not available over REST: say so in the report (ISE GUI:
     Operations > Reports > Audit > Change Configuration Audit, or ISE syslog in a SIEM). Don't search
     for it.

2. FMC (Firepower) - skip with a note if fmc is not connected.
   - `fmc_recent_activity` with since_minutes=<minutes from 2026-10-29T09:10:00Z until now, rounded up>, device="ftd1": audit (who changed what),
     deployments and health alerts, one row each.
   - `fmc_run_show_command` with device="ftd1", command="show logging": interface, failover, VPN and routing messages in the window (the FTD's clock may differ
     from FMC's).

3. Catalyst Center and the switch - skip with a note if catc is not connected.
   - `catc_recent_activity` with hours=<hours from 2026-10-29T09:10:00Z until now, rounded up>: issues, syslog, notifications and audit
     (template pushes, provisioning, who did it).
   - `cml_run_commands` with lab="lab", nodes=["sw1"], commands=["show logging"]: link up/down, AAA/RADIUS server dead/alive and authentication messages in the window.

4. CML (the lab itself) - skip with a note if cml is not connected.
   - `cml_list_lab_events` for lab="lab": link and node state changes
     (link down, node stopped). The tool has no time filter: keep only events in the window.

5. NetBox (source of truth) - optional: skipped if not connected.
   - `netbox_change_history` with since="2026-10-29T09:10:00Z", until="2026-10-29T09:20:00Z": who created, changed or deleted which object.

6. Windows / Active Directory - optional: skipped if not connected (the tool is a raw-PowerShell tool
   that may need its server's higher tier; run only this fixed, read-only query).
   - `win_run_powershell_json` with the script exactly:
     Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4728,4729; StartTime=[datetime]::Parse('2026-10-29T09:10:00Z'); EndTime=[datetime]::Parse('2026-10-29T09:20:00Z')} -ErrorAction SilentlyContinue | Select-Object @{n='Time';e={$_.TimeCreated.ToUniversalTime().ToString('o')}}, Id, @{n='Member';e={$_.Properties[0].Value}}, @{n='Group';e={$_.Properties[2].Value}}, @{n='By';e={$_.Properties[6].Value}}
     Event 4728 = member added to a security group, 4729 = member removed: a row per event (who, group,
     by whom). Group changes decide ISE authorization results for AD users.

7. Merge and report.
   - Order every row by time (oldest first). Show: time (UTC), source (ISE/FMC/FTD/CatC/switch/CML/
     NetBox/AD), event, key detail and who did it.
   - Operator changes first: an FMC deploy, a CatC template push, a lab link down, an AD group change or
     a NetBox edit just before an auth failure burst or an interface/AAA message is the likely cause.
   - End with a short "what happened" summary, the gaps (sources not connected, ISE's config audit, empty
     windows) and the hosts or NADs worth a closer look: rerun this prompt with mac=/ip=/username= for a
     host, or `ise_why_auth_failed` for one failure. Propose no change without the user asking.

# ise_deployment_health_review

title: ISE deployment health review (weekly or pre-change)
arguments: {"cert_warn_days": "60", "role": "ACCESS", "site": "Global/SYD/Bldg-1"}

A weekly or pre-change review of the whole ISE deployment as one ranked report with next steps:
ise_deployment_health (nodes, redundancy, patches, backup, certificates, licence, AD, admins), then
certificate expiry (system and trusted), licence compliance, pxGrid (persona, certificate, pending
clients), AD join per node, SXP connections and bindings, the admin access review (Super Admins,
never-disabled, external), FMC's certificates and Catalyst Center's trust of the ISE certificate
sorted by days left with the renewal path per row, and NAD coverage of a Catalyst Center site.
Read-only; the fmc, catc and Windows_Server steps are skipped (noted) when those servers aren't
connected.

## user

Review the ISE deployment (certificate warning window 60 days). Read only: no
tool here changes anything, and every fix in the report is a next step for the user to approve later,
never run in this review.

Only the ise_* tools are certain to exist. fmc_* needs the fmc-mcp server, catc_* the catc-mcp server
and win_* the Windows_Server server: if one is not connected, mark its rows "skipped (server not
connected)" and carry on. Severity scale everywhere: critical > high > medium > low > info.

1. Baseline. `ise_deployment_health` with cert_warn_days=60. Keep its verdict
   and every finding with its severity and area (nodes, patches, backup, certificates, licence,
   active_directory, server_privilege, admins). The steps below add evidence to those findings; do not
   list a problem twice.

2. Nodes and redundancy. From step 1's `nodes` (or `ise_list_nodes`): every node in sync,
   PAN HA or a secondary PAN, a secondary MnT, at least two PSNs for a site that needs RADIUS during
   maintenance. Backup older than 7 days or failed: `ise_get_backup_status` for the detail.

3. ISE certificates. `ise_list_certificates` with kind="system",
   expiring_within_days=60, and with kind="trusted", expiring_within_days=60.
   Expired = critical; inside 30 days = high; inside 60 days = medium. Name the usage of each
   system certificate (Admin, EAP Authentication, Portal, pxGrid, RADIUS DTLS): an expiring EAP
   certificate breaks 802.1X, Admin breaks the GUI/API and the Catalyst Center integration, pxGrid breaks
   FMC and Catalyst Center consumers. An expiring trusted CA that issued a system certificate or client
   certificates is as urgent as the certificate itself. `ise_list_csrs`: a pending CSR for that
   node means a renewal is already under way.

4. Licence. `ise_get_license_status`: tiers in use against those registered and compliant,
   evaluation days left (inside 30 = high), Smart Licensing registration and the last authorisation.
   Out of compliance = high.

5. pxGrid. `ise_pxgrid_status` with probe=true: the pxGrid persona runs on the nodes it should;
   the certificate port 8910 presents chains to a trusted root and its names match the node FQDN (a
   mismatch = high: FMC and Catalyst Center refuse it); `ise_list_pxgrid_clients`: pending
   clients = medium (approve them), a disabled client for a live integration = high.

6. Active Directory. `ise_list_identity_sources`; for each join point
   `ise_get_ad_join_point`: joined on every PSN that authenticates against it (one PSN not
   joined = high: its users fail with 24408/24415), the domain reachable, groups added for policy. No
   join point = info.

7. SXP. `ise_list_sxp_connections`: each connection's peer, the peer's role, version, domain,
   ISE node and enabled flag; the node must run the SXP service (step 2's services). A disabled connection
   or one on a node without SXP = medium. `ise_list_sxp_bindings`: how many bindings each
   domain advertises (a domain with listeners and no bindings = low). ISE has no API for the live SXP
   state: list the peers for the user to check with 'show cts sxp connections brief' on the device. No
   SXP connections = info (not in use).

8. Admin access. Step 1's `admins` section: Super Admin count, disabled, never-disabled, external. Then
   `ise_list_admin_users` with detail=true for the names: more than 3 enabled Super Admins =
   low (least privilege); a Super Admin exempt from inactivity disabling = low unless it is the documented
   break-glass account; a change-password-on-next-login still pending = low.
   `ise_list_admin_groups` with external_only=true: which AD groups map to admin groups
   (an AD group on Super Admin = medium: anyone added to it in AD becomes Super Admin). For a group
   whose rights are unclear, `ise_get_admin_access` with group=<name>. Step 1's
   server_privilege finding (this server's own account more privileged than its enabled tiers need)
   goes here too.

9. Certificates on the other platforms (each skipped if its server is not connected).
   a. FMC: `fmc_list_certificates` with expiring_within_days=60: device
      (FTD identity), internal (FMC's pxGrid client certificate for ISE), internal_ca and trusted_ca (the
      CA that issued ISE's pxGrid certificate) rows with days_left and severity.
   b. Catalyst Center: `catc_get_policy_servers`: for each ISE node its trustState (not
      TRUSTED = high: Catalyst Center stops pushing to ISE) and `next_action`. accept_certificate means ISE
      presents a certificate Catalyst Center has not accepted yet (often right after an ISE renewal).

10. NAD coverage. `catc_list_devices` with site="Global/SYD/Bldg-1", role="ACCESS" (skip if catc is not
   connected: say so and run the audit without `expected`). Then `ise_audit_nads` with
   expected=<those rows as they are> and check_stale=false (one site is part of the inventory).
   missing_nad = high (the device's RADIUS gets silently dropped, 11007); ip_mismatch and wrong_ndg =
   medium; aaa_elsewhere = medium (the device's RADIUS server is not an ISE node). Count the ACCESS
   devices covered: "N of M devices at Global/SYD/Bldg-1 have a NAD".

11. Report.
   a. One ranked table, worst first: severity | area | finding | evidence (tool and the key value) |
      next step. Group by area within a severity; info rows last, in one line each.
   b. One certificate table across platforms, sorted by days left (expired first): platform | node or
      device | certificate (subject or name) | usage | expires | days left | renewal path. Renewal path
      per row:
      - ISE system certificate: `ise_generate_csr` (same subject and SANs, the usage it has now) -> `ise_export_csr` ->
        signed by the CA (`win_sign_csr` with the Windows_Server server, or the customer's
        CA) -> `ise_bind_certificate` with the same usage. Binding Admin or pxGrid restarts ISE's application server on
        that node: a change window, one node at a time, PSNs before the PAN.
      - ISE trusted CA: `ise_import_trusted_cert` with the CA's new certificate before the old one expires.
      - FMC device certificate: `fmc_enroll_certificate` (re-enrol on the FTD, then
        deploy); FMC internal or trusted CA: `fmc_import_certificate_files` with the new
        file.
      - Catalyst Center trust of ISE: after the ISE certificate changes,
        `catc_accept_ise_certificate` once the fingerprint matches what ise_pxgrid_status
        shows (dangerous on catc).
   c. Verdict: the single most urgent item and when it bites (a date for certificates and licences),
      then what is fine. End with the rows marked "skipped (server not connected)" and what each
      would have checked. Propose no change in this review; the user picks the next steps.

"""Prompt ise_deployment_health_review (I47): a weekly or pre-change review of the ISE deployment as one
ranked report with next steps.

It chains ise_deployment_health with the deeper reads behind each finding (certificates, licence, pxGrid,
AD join, SXP, admins), adds the certificate rows of the other platforms that trust or present ISE's
certificates (FMC, Catalyst Center) and a NAD coverage check against Catalyst Center's inventory. Read only:
the fixes are named as next steps, never run.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from typing import Annotated

from pydantic import Field

from ise_mcp._core import InvalidRequest, ToolRegistrar, tool_ref

# Prompt arguments are interpolated into instructions, so they are held to strict shapes.
SAFE_SITE = re.compile(r"^[\w .#()-]{1,64}(/[\w .#()-]{1,64}){0,7}$")
CATC_ROLES = ("ACCESS", "DISTRIBUTION", "CORE", "BORDER ROUTER")

# ISE reads the review runs (all read tier, so they exist whenever the prompt does).
READ_TOOLS = [
    "ise_deployment_health",
    "ise_list_nodes",
    "ise_list_certificates",
    "ise_get_license_status",
    "ise_pxgrid_status",
    "ise_list_pxgrid_clients",
    "ise_list_identity_sources",
    "ise_get_ad_join_point",
    "ise_list_sxp_connections",
    "ise_list_sxp_bindings",
    "ise_list_admin_users",
    "ise_list_admin_groups",
    "ise_get_admin_access",
    "ise_audit_nads",
    "ise_get_backup_status",
    "ise_list_csrs",
]
# ISE fixes the report may name as next steps: only those this server exposes (write/dangerous tiers).
FIX_TOOLS = ("ise_generate_csr", "ise_export_csr", "ise_bind_certificate", "ise_import_trusted_cert")
PEER_TOOLS = [
    "fmc_list_certificates",
    "fmc_enroll_certificate",
    "fmc_import_certificate_files",
    "catc_get_policy_servers",
    "catc_accept_ise_certificate",
    "catc_list_devices",
    "win_sign_csr",
]


def _ref_or_name(name: str, enabled: bool, why: str) -> str:
    """A backticked reference when the tool is registered here, else its plain name and why it is missing."""
    return tool_ref(name) if enabled else f"{name} ({why}, not enabled on this server)"


def register(reg: ToolRegistrar) -> None:
    fixes = {t: t in reg.tiers for t in FIX_TOOLS}

    @reg.prompt(
        title="ISE deployment health review (weekly or pre-change)",
        uses=["ise", "fmc", "catc", "win"],
        example={"cert_warn_days": "90", "site": "Global/SYD/Bldg-1", "role": "ACCESS"},
        tools=[*READ_TOOLS, *(t for t, on in fixes.items() if on), *PEER_TOOLS],
    )
    def ise_deployment_health_review(
        cert_warn_days: Annotated[
            int,
            Field(ge=1, le=730, description="Flag certificates (ISE, FMC) that expire within this many days"),
        ] = 90,
        site: Annotated[
            str,
            Field(
                description="Optional Catalyst Center site path (e.g. 'Global/SYD/Bldg-1') for the NAD "
                "coverage check; empty: the NAD audit without an inventory"
            ),
        ] = "",
        role: Annotated[
            str,
            Field(
                description="Optional Catalyst Center device role for the coverage check: ACCESS, "
                "DISTRIBUTION, CORE or BORDER ROUTER (empty: every role at the site)"
            ),
        ] = "",
    ) -> str:
        """A weekly or pre-change review of the whole ISE deployment as one ranked report with next steps:
        ise_deployment_health (nodes, redundancy, patches, backup, certificates, licence, AD, admins), then
        certificate expiry (system and trusted), licence compliance, pxGrid (persona, certificate, pending
        clients), AD join per node, SXP connections and bindings, the admin access review (Super Admins,
        never-disabled, external), FMC's certificates and Catalyst Center's trust of the ISE certificate
        sorted by days left with the renewal path per row, and NAD coverage of a Catalyst Center site.
        Read-only; the fmc, catc and Windows_Server steps are skipped (noted) when those servers aren't
        connected."""
        site = site.strip()
        if site and not SAFE_SITE.match(site):
            raise InvalidRequest("site must be a Catalyst Center site path like 'Global/Area/Building'")
        role = role.strip().upper()
        if role and role not in CATC_ROLES:
            raise InvalidRequest(f"role must be one of {', '.join(CATC_ROLES)} (or empty)")

        csr = _ref_or_name("ise_generate_csr", fixes["ise_generate_csr"], "write tier")
        export = _ref_or_name("ise_export_csr", True, "read tier")
        bind = _ref_or_name("ise_bind_certificate", fixes["ise_bind_certificate"], "dangerous tier")
        trusted = _ref_or_name("ise_import_trusted_cert", fixes["ise_import_trusted_cert"], "write tier")
        role_arg = f', role="{role}"' if role else ""
        role_text = f" {role}" if role else ""
        coverage = (
            f"""{tool_ref("catc_list_devices")} with site="{site}"{role_arg} (skip if catc is not
   connected: say so and run the audit without `expected`). Then {tool_ref("ise_audit_nads")} with
   expected=<those rows as they are> and check_stale=false (one site is part of the inventory).
   missing_nad = high (the device's RADIUS gets silently dropped, 11007); ip_mismatch and wrong_ndg =
   medium; aaa_elsewhere = medium (the device's RADIUS server is not an ISE node). Count the{role_text}
   devices covered: "N of M devices at {site} have a NAD"."""
            if site
            else f"""{tool_ref("ise_audit_nads")} without `expected` (no site given): missing secrets, short
   or reused secrets, NADs only in the default groups, overlapping ranges. Say that coverage against
   an inventory needs a Catalyst Center site (run the review again with site=...)."""
        )

        return f"""Review the ISE deployment (certificate warning window {cert_warn_days} days). Read only: no
tool here changes anything, and every fix in the report is a next step for the user to approve later,
never run in this review.

Only the ise_* tools are certain to exist. fmc_* needs the fmc-mcp server, catc_* the catc-mcp server
and win_* the Windows_Server server: if one is not connected, mark its rows "skipped (server not
connected)" and carry on. Severity scale everywhere: critical > high > medium > low > info.

1. Baseline. {tool_ref("ise_deployment_health")} with cert_warn_days={cert_warn_days}. Keep its verdict
   and every finding with its severity and area (nodes, patches, backup, certificates, licence,
   active_directory, server_privilege, admins). The steps below add evidence to those findings; do not
   list a problem twice.

2. Nodes and redundancy. From step 1's `nodes` (or {tool_ref("ise_list_nodes")}): every node in sync,
   PAN HA or a secondary PAN, a secondary MnT, at least two PSNs for a site that needs RADIUS during
   maintenance. Backup older than 7 days or failed: {tool_ref("ise_get_backup_status")} for the detail.

3. ISE certificates. {tool_ref("ise_list_certificates")} with kind="system",
   expiring_within_days={cert_warn_days}, and with kind="trusted", expiring_within_days={cert_warn_days}.
   Expired = critical; inside 30 days = high; inside {cert_warn_days} days = medium. Name the usage of each
   system certificate (Admin, EAP Authentication, Portal, pxGrid, RADIUS DTLS): an expiring EAP
   certificate breaks 802.1X, Admin breaks the GUI/API and the Catalyst Center integration, pxGrid breaks
   FMC and Catalyst Center consumers. An expiring trusted CA that issued a system certificate or client
   certificates is as urgent as the certificate itself. {tool_ref("ise_list_csrs")}: a pending CSR for that
   node means a renewal is already under way.

4. Licence. {tool_ref("ise_get_license_status")}: tiers in use against those registered and compliant,
   evaluation days left (inside 30 = high), Smart Licensing registration and the last authorisation.
   Out of compliance = high.

5. pxGrid. {tool_ref("ise_pxgrid_status")} with probe=true: the pxGrid persona runs on the nodes it should;
   the certificate port 8910 presents chains to a trusted root and its names match the node FQDN (a
   mismatch = high: FMC and Catalyst Center refuse it); {tool_ref("ise_list_pxgrid_clients")}: pending
   clients = medium (approve them), a disabled client for a live integration = high.

6. Active Directory. {tool_ref("ise_list_identity_sources")}; for each join point
   {tool_ref("ise_get_ad_join_point")}: joined on every PSN that authenticates against it (one PSN not
   joined = high: its users fail with 24408/24415), the domain reachable, groups added for policy. No
   join point = info.

7. SXP. {tool_ref("ise_list_sxp_connections")}: each connection's peer, the peer's role, version, domain,
   ISE node and enabled flag; the node must run the SXP service (step 2's services). A disabled connection
   or one on a node without SXP = medium. {tool_ref("ise_list_sxp_bindings")}: how many bindings each
   domain advertises (a domain with listeners and no bindings = low). ISE has no API for the live SXP
   state: list the peers for the user to check with 'show cts sxp connections brief' on the device. No
   SXP connections = info (not in use).

8. Admin access. Step 1's `admins` section: Super Admin count, disabled, never-disabled, external. Then
   {tool_ref("ise_list_admin_users")} with detail=true for the names: more than 3 enabled Super Admins =
   low (least privilege); a Super Admin exempt from inactivity disabling = low unless it is the documented
   break-glass account; a change-password-on-next-login still pending = low.
   {tool_ref("ise_list_admin_groups")} with external_only=true: which AD groups map to admin groups
   (an AD group on Super Admin = medium: anyone added to it in AD becomes Super Admin). For a group
   whose rights are unclear, {tool_ref("ise_get_admin_access")} with group=<name>. Step 1's
   server_privilege finding (this server's own account more privileged than its enabled tiers need)
   goes here too.

9. Certificates on the other platforms (each skipped if its server is not connected).
   a. FMC: {tool_ref("fmc_list_certificates")} with expiring_within_days={cert_warn_days}: device
      (FTD identity), internal (FMC's pxGrid client certificate for ISE), internal_ca and trusted_ca (the
      CA that issued ISE's pxGrid certificate) rows with days_left and severity.
   b. Catalyst Center: {tool_ref("catc_get_policy_servers")}: for each ISE node its trustState (not
      TRUSTED = high: Catalyst Center stops pushing to ISE) and `next_action`. accept_certificate means ISE
      presents a certificate Catalyst Center has not accepted yet (often right after an ISE renewal).

10. NAD coverage. {coverage}

11. Report.
   a. One ranked table, worst first: severity | area | finding | evidence (tool and the key value) |
      next step. Group by area within a severity; info rows last, in one line each.
   b. One certificate table across platforms, sorted by days left (expired first): platform | node or
      device | certificate (subject or name) | usage | expires | days left | renewal path. Renewal path
      per row:
      - ISE system certificate: {csr} (same subject and SANs, the usage it has now) -> {export} ->
        signed by the CA ({tool_ref("win_sign_csr")} with the Windows_Server server, or the customer's
        CA) -> {bind} with the same usage. Binding Admin or pxGrid restarts ISE's application server on
        that node: a change window, one node at a time, PSNs before the PAN.
      - ISE trusted CA: {trusted} with the CA's new certificate before the old one expires.
      - FMC device certificate: {tool_ref("fmc_enroll_certificate")} (re-enrol on the FTD, then
        deploy); FMC internal or trusted CA: {tool_ref("fmc_import_certificate_files")} with the new
        file.
      - Catalyst Center trust of ISE: after the ISE certificate changes,
        {tool_ref("catc_accept_ise_certificate")} once the fingerprint matches what ise_pxgrid_status
        shows (dangerous on catc).
   c. Verdict: the single most urgent item and when it bites (a date for certificates and licences),
      then what is fine. End with the rows marked "skipped (server not connected)" and what each
      would have checked. Propose no change in this review; the user picks the next steps."""

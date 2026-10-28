"""Server factory: SPEC, instructions and the tool modules."""

from __future__ import annotations

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider

from ise_mcp._core import ServerSpec, build_server, suite
from ise_mcp.client import IseApp
from ise_mcp.config import Settings
from ise_mcp.specs import spec_sources
from ise_mcp.tools import (
    activity,
    ad,
    admin_audit,
    backup,
    certs,
    coa_bulk,
    config_export,
    config_import,
    dangerous,
    device_admin,
    endpoint_bulk,
    endpoints,
    guest,
    health,
    health_review,
    identity,
    network,
    policy,
    policy_audit,
    policy_edit,
    policy_explain,
    profiler_posture,
    pxgrid,
    radius,
    sdwan_onboard,
    sessions,
    snapshot,
    sxp,
    system,
    troubleshoot,
    trustsec,
    where_used,
    workflows,
    writes,
)

INSTRUCTIONS = """
Tools for Cisco Identity Services Engine (ISE) across its three REST surfaces: OpenAPI (/api/v1: policy
sets, endpoints, TrustSec matrix, deployment, certs, licensing), ERS (/ers/config: network devices,
internal users, identity/endpoint groups, SGTs, SGACLs, authorization profiles, dACLs, ANC) and MnT
(/admin/API/mnt: live sessions, auth history, failure reasons, CoA). Call ise_status first if anything
fails: it reports which surfaces answer (ERS is often disabled or firewalled).
Start here: "why can't X connect?" -> ise_why_auth_failed (MAC preferred); "what is this device?" ->
ise_endpoint_360; "who failed / what connected in the last hour?" -> ise_recent_auth_failures and
ise_get_auth_list (by NAD or user, no MAC needed); "is the deployment healthy?" ->
ise_deployment_health; "did my change break anything?" -> ise_snapshot(site) before, ise_compare_snapshot
after (suite_change_check across products); "is it the network or ISE?" (per-NAD RADIUS latency and
timeouts) -> ise_nad_radius_stats; "which NAD is 10.1.2.3?" -> ise_get_nad (NAD names may be partial);
"what does policy do?" -> ise_list_policy_sets then ise_get_policy_set; "which rule would a MAB/802.1X
login from switch X hit?" -> ise_policy_explain(nad=X, flow='wired-mab'); "can SGT A talk to B?" ->
ise_get_egress_matrix(source, destination); "what uses this profile / SGT / group / condition before I
change or delete it?" -> ise_where_used(kind, name); "clean-up / inherited ISE review" ->
ise_policy_audit (ranked findings with fix tools) and ise_unused_objects; "why is this device
profiled as X?" -> ise_explain_profile
(custom profiling rules: ise_set_profiling_rule; probes: ise_profiler_status). Everything is queried from
ISE when called: MnT keeps per-MAC auth history (CoA results are labelled kind=coa, not logins) and has
nothing when no RADIUS reached ISE; it leaves out repeated successful logins, which the session
(ise_find_session) still shows. Not available over REST, so don't search for it: the RADIUS suppression
settings, the configuration change audit ("what changed?": GUI Operations > Reports > Audit > Change
Configuration Audit, or ISE syslog in a SIEM), TACACS+ live logs, and on the profiler: editing classic
profiling policies, certainty factors and the feed service (docs/profiler.md). Policy changes (writes):
ise_create_policy_set -> ise_create_authn_rule -> ise_create_authz_rule, then ise_update_policy_rule;
conditions are 'Dictionary:Attribute operator value' or library condition names
(ise_list_dictionary_attributes, ise_list_conditions) and are checked before anything is sent. Device
admin (TACACS+): kind='device-admin' on the policy tools, plus ise_set_command_set /
ise_set_shell_profile; the node needs the DeviceAdmin service. Catalyst SD-WAN Manager admins: sdwan_group
on ise_create_authz_profile (RADIUS Viptela-Group-Name; ISE ships no Viptela dictionary, the preview names
the GUI step) or ise_set_shell_profile (TACACS+); SD-WAN edges as NADs at their service-VPN loopbacks:
prompt ise_onboard_sdwan_edges; a switch (groups, NAD, AAA lines, test login, undo): prompt ise_onboard_nad.
Quarantine: an authz rule on
'Session:ANCPolicy equals <policy>' first, then ise_apply_anc. Active Directory: ise_create_ad_join_point
-> ise_join_ad -> ise_list_ad_groups -> ise_add_ad_groups, then rules on '<join point>:ExternalGroups
equals <domain/OU/group>'; ise_get_ad_join_point (join status) and ise_test_ad_user (a user's groups) for
AD login failures. pxGrid (appliance to appliance; this server never subscribes): ise_pxgrid_status
(persona, certificate chain + hostname as consumers see them, pending clients) -> ise_list_pxgrid_clients ->
ise_approve_pxgrid_client; ise_set_pxgrid_settings (auto-approve); ise_issue_pxgrid_client_cert (key + CSR,
then the signed bundle) for a consumer such as FMC. Guest access: ise_list_guest_types /
ise_list_sponsor_groups / ise_list_guest_portals (admin); guest accounts (ise_create_guest_user,
ise_extend_guest_user, ise_suspend_guest_user, ...) run as the sponsor set in ISE_SPONSOR_USERNAME
(ise_status shows guest_sponsor). Backups (before Catalyst Center's group-based policy migration or an
upgrade): ise_list_repositories -> ise_create_backup (dangerous; key from ISE_BACKUP_ENCRYPTION_KEY) ->
ise_get_backup_status; restores are GUI-only. Names or ids are accepted wherever a tool
takes an object. Shared secrets, SNMP communities and passwords are always masked (the exceptions:
ise_issue_pxgrid_client_cert returns the consumer's new private key once, and ise_create_guest_user the
guest's password once, on confirm). For anything without
a tool: ise_search_spec -> ise_get_definition -> ise_api_call(source=openapi|ers|mnt).
""".strip()

SPEC = ServerSpec(
    name="ise-mcp-server",
    prefix="ise",
    product="Cisco ISE",
    env_prefix="ISE_",
    instructions=INSTRUCTIONS,
    spec_search_example="network device group",
    spec_path_example="/ers/config/networkdevice/{id}",
)


def create_server(
    settings: Settings,
    *,
    auth: AuthProvider | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastMCP[Any]:
    return build_server(
        SPEC,
        settings,
        client_factory=lambda s: IseApp(s, transport=transport),
        register=[
            troubleshoot.register,
            sessions.register,
            activity.register,
            radius.register,
            network.register,
            endpoints.register,
            identity.register,
            policy.register,
            trustsec.register,
            system.register,
            backup.register,
            health.register,
            admin_audit.register,
            writes.register,
            endpoint_bulk.register,
            policy_edit.register,
            policy_explain.register,
            profiler_posture.register,
            device_admin.register,
            sxp.register,
            certs.register,
            ad.register,
            guest.register,
            pxgrid.register,
            dangerous.register,
            coa_bulk.register,
            workflows.register,
            sdwan_onboard.register,
            health_review.register,
            config_export.register,
            config_import.register,
            snapshot.register,
            where_used.register,
            policy_audit.register,
            suite.register,
        ],
        status=IseApp.status,
        spec_sources=spec_sources,
        auth=auth,
    )

"""Server factory: SPEC, instructions and the tool modules."""

from __future__ import annotations

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from stutters_mcp_core import ServerSpec, build_server

from ise_mcp.client import IseApp
from ise_mcp.config import Settings
from ise_mcp.specs import spec_sources
from ise_mcp.tools import (
    activity,
    ad,
    certs,
    dangerous,
    device_admin,
    endpoint_bulk,
    endpoints,
    health,
    identity,
    network,
    policy,
    policy_edit,
    policy_explain,
    profiler_posture,
    pxgrid,
    sessions,
    sxp,
    system,
    troubleshoot,
    trustsec,
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
ise_deployment_health; "which NAD is 10.1.2.3?" -> ise_get_nad (NAD names may be partial); "what does
policy do?" -> ise_list_policy_sets then ise_get_policy_set; "which rule would a MAB/802.1X login from
switch X hit?" -> ise_policy_explain(nad=X, flow='wired-mab'); "can SGT A talk to B?" ->
ise_get_egress_matrix(source, destination). Everything is queried from ISE when called: MnT keeps
per-MAC auth history (CoA results are labelled kind=coa, not logins) and has nothing when no RADIUS
reached ISE. Not available over REST, so don't search for it: the configuration change audit ("what
changed?": GUI Operations > Reports > Audit > Change Configuration Audit, or ISE syslog in a SIEM) and
TACACS+ live logs. Policy changes (writes):
ise_create_policy_set -> ise_create_authn_rule -> ise_create_authz_rule, then ise_update_policy_rule;
conditions are 'Dictionary:Attribute operator value' or library condition names
(ise_list_dictionary_attributes, ise_list_conditions) and are checked before anything is sent. Device
admin (TACACS+): kind='device-admin' on the policy tools, plus ise_set_command_set /
ise_set_shell_profile; the node needs the DeviceAdmin service. Quarantine: an authz rule on
'Session:ANCPolicy equals <policy>' first, then ise_apply_anc. Active Directory: ise_create_ad_join_point
-> ise_join_ad -> ise_list_ad_groups -> ise_add_ad_groups, then rules on '<join point>:ExternalGroups
equals <domain/OU/group>'; ise_get_ad_join_point (join status) and ise_test_ad_user (a user's groups) for
AD login failures. pxGrid (appliance to appliance; this server never subscribes): ise_pxgrid_status
(persona, certificate chain + hostname as consumers see them, pending clients) -> ise_list_pxgrid_clients ->
ise_approve_pxgrid_client; ise_set_pxgrid_settings (auto-approve); ise_issue_pxgrid_client_cert (key + CSR,
then the signed bundle) for a consumer such as FMC. Names or ids are accepted wherever a tool
takes an object. Shared secrets, SNMP communities and passwords are always masked (the one exception:
ise_issue_pxgrid_client_cert returns the consumer's new private key once, on confirm). For anything without
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
            network.register,
            endpoints.register,
            identity.register,
            policy.register,
            trustsec.register,
            system.register,
            health.register,
            writes.register,
            endpoint_bulk.register,
            policy_edit.register,
            policy_explain.register,
            profiler_posture.register,
            device_admin.register,
            sxp.register,
            certs.register,
            ad.register,
            pxgrid.register,
            dangerous.register,
            workflows.register,
        ],
        status=IseApp.status,
        spec_sources=spec_sources,
        auth=auth,
    )

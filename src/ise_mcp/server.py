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
    dangerous,
    endpoints,
    identity,
    network,
    policy,
    sessions,
    system,
    troubleshoot,
    trustsec,
    writes,
)

INSTRUCTIONS = """
Tools for Cisco Identity Services Engine (ISE) across its three REST surfaces: OpenAPI (/api/v1: policy
sets, endpoints, TrustSec matrix, deployment, certs, licensing), ERS (/ers/config: network devices,
internal users, identity/endpoint groups, SGTs, SGACLs, authorization profiles, dACLs, ANC) and MnT
(/admin/API/mnt: live sessions, auth history, failure reasons, CoA). Call ise_status first if anything
fails: it reports which surfaces answer (ERS is often disabled or firewalled).
Start here: "why can't X connect?" -> ise_why_auth_failed (MAC preferred); "what is this device?" ->
ise_endpoint_360; "which NAD is 10.1.2.3?" -> ise_get_nad; "what does policy do?" -> ise_list_policy_sets
then ise_get_policy_set. MnT can only search auth history by MAC, and returns nothing when no RADIUS
traffic exists. Names or ids are accepted wherever a tool takes an object. Shared secrets, SNMP
communities and passwords are always masked. For anything without a tool: ise_search_spec ->
ise_get_definition -> ise_api_call(source=openapi|ers|mnt).
""".strip()

SPEC = ServerSpec(
    name="ise-mcp-server",
    prefix="ise",
    product="Cisco ISE",
    env_prefix="ISE_",
    instructions=INSTRUCTIONS,
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
            network.register,
            endpoints.register,
            identity.register,
            policy.register,
            trustsec.register,
            system.register,
            writes.register,
            dangerous.register,
        ],
        status=IseApp.status,
        spec_sources=spec_sources,
        auth=auth,
    )

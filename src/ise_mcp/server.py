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
Tools for Cisco Identity Services Engine (ISE). ISE has three REST surfaces and this server uses all
three: OpenAPI (/api/v1: policy sets, endpoints, TrustSec matrix, deployment, certs, licensing),
ERS (/ers/config: network devices, internal users, identity/endpoint groups, SGTs, SGACLs,
authorization profiles, dACLs, ANC) and MnT (/admin/API/mnt: live sessions, auth status, failure
reasons, CoA). Call ise_status first: it reports which surfaces answer (ERS is often disabled or
firewalled; MnT only has data when RADIUS sessions exist).
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
        ],
        status=IseApp.status,
        spec_sources=spec_sources,
        auth=auth,
    )

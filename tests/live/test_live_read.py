"""Read-only live tests. Seeded mcp-test-* objects (docs/live-tests.md) make some checks stronger; without
them those checks skip. MnT tests tolerate an empty session table."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastmcp import Client, FastMCP

from tests.live.conftest import SEED_HINT

pytestmark = pytest.mark.live

SEED_MAC = "02:00:5E:00:00:01"
SEED_FAIL_MAC = "02:00:5E:00:00:02"


async def call(server: FastMCP[Any], name: str, args: dict[str, Any] | None = None) -> Any:
    async with Client(server) as c:
        r = await c.call_tool(name, args or {}, raise_on_error=False)
    text = "\n".join(getattr(x, "text", "") for x in r.content)
    assert not r.is_error, f"{name} failed: {text}"
    if r.structured_content is not None:
        return r.structured_content
    try:
        return json.loads(text)
    except ValueError:
        return text


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("ise_list_nodes", {}),
        ("ise_get_license_status", {}),
        ("ise_list_patches", {}),
        ("ise_get_backup_status", {}),
        ("ise_list_certificates", {}),
        ("ise_list_certificates", {"kind": "trusted", "limit": 5}),
        ("ise_list_active_sessions", {}),
        ("ise_list_failure_reasons", {"query": "22056"}),
        ("ise_list_nads", {}),
        ("ise_list_ndgs", {}),
        ("ise_audit_nads", {}),
        ("ise_list_endpoints", {"limit": 5}),
        ("ise_list_endpoint_groups", {}),
        ("ise_list_internal_users", {}),
        ("ise_list_identity_groups", {}),
        ("ise_list_identity_sources", {}),
        ("ise_list_policy_sets", {}),
        ("ise_list_policy_sets", {"kind": "device-admin"}),
        ("ise_get_policy_set", {"policy_set": "Default"}),
        ("ise_list_authz_profiles", {"name": "access"}),
        ("ise_get_authz_profile", {"profile": "PermitAccess"}),
        ("ise_list_dacls", {}),
        ("ise_get_dacl", {"dacl": "PERMIT_ALL_IPV4_TRAFFIC"}),
        ("ise_list_allowed_protocols", {}),
        ("ise_list_conditions", {}),
        ("ise_list_sgts", {}),
        ("ise_list_sgacls", {}),
        ("ise_get_egress_matrix", {}),
        ("ise_list_ip_sgt_mappings", {}),
        ("ise_list_anc_policies", {}),
        ("ise_list_anc_endpoints", {}),
        ("ise_search_spec", {"query": "network device"}),
        ("ise_get_definition", {"name": "GET /api/v1/endpoint"}),
        ("ise_api_call", {"path": "/api/v1/deployment/node"}),
    ],
)
async def test_read_tool(server: FastMCP[Any], tool: str, args: dict[str, Any]) -> None:
    out = await call(server, tool, args)
    assert out


async def test_spec_sources_all_load(server: FastMCP[Any]) -> None:
    for source, query in (("openapi", "endpoint"), ("ers", "networkdevice"), ("mnt", "session")):
        out = await call(server, "ise_search_spec", {"query": query, "source": source, "limit": 1})
        assert out["results"], source
        assert "unavailable_specs" not in out


async def test_why_auth_failed_tolerates_unknown_mac(server: FastMCP[Any]) -> None:
    out = await call(server, "ise_why_auth_failed", {"mac": "02:00:5E:FF:FF:FE", "minutes": 5})
    assert "no authentication record" in out["verdict"]


async def test_endpoint_360_seeded(server: FastMCP[Any]) -> None:
    out = await call(server, "ise_endpoint_360", {"mac": SEED_MAC})
    if out["endpoint"] == "not in the ISE endpoint database":
        pytest.skip(f"mcp-test-* objects not seeded ({SEED_HINT})")
    assert out["endpoint"]["group"] == "mcp-test-endpoints"


async def test_why_auth_failed_seeded(server: FastMCP[Any]) -> None:
    out = await call(server, "ise_why_auth_failed", {"mac": SEED_FAIL_MAC, "minutes": 10080})
    if "no authentication record" in out["verdict"]:
        pytest.skip(f"no seeded RADIUS history ({SEED_HINT})")
    assert out["failure"]["code"] in ("22040", "22056")
    assert "network_device" in out["checks"]


async def test_session_lookups_tolerate_empty(server: FastMCP[Any]) -> None:
    sessions = await call(server, "ise_list_active_sessions", {"response_format": "json"})
    for key in ("mac", "username"):
        value = SEED_MAC if key == "mac" else "mcp-test-user"
        out = await call(server, "ise_find_session", {key: value})
        assert "found" in out
    if sessions["results"]:
        first = sessions["results"][0]
        out = await call(server, "ise_find_session", {"mac": first["mac"]})
        assert out["found"] is True


async def test_nad_secrets_masked(server: FastMCP[Any]) -> None:
    nads = await call(server, "ise_list_nads", {"response_format": "json"})
    if not nads["results"]:
        pytest.skip("no NADs")
    full = await call(server, "ise_get_nad", {"device": nads["results"][0]["id"]})
    secret = full.get("authenticationSettings", {}).get("radiusSharedSecret")
    assert secret in (None, "********")

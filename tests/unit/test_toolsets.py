"""ISE_TOOLSETS (I44): the area table against the registered tools, and a contract test per toolset."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
import respx

from ise_mcp._core.testing import call_tool
from ise_mcp._core.toolsets import NAME_RE, toolsets_of
from ise_mcp.toolsets import ALWAYS_ON, TOOLSET_OF, TOOLSETS
from tests.unit.conftest import make_server

# Registered by core itself, outside the tool modules (always on).
CORE = {"ise_status", "ise_search_spec", "ise_get_definition", "ise_api_call"}
EVERY_TIER = {"mcp_enable_writes": True, "mcp_enable_dangerous": True}
MANIFEST = Path(__file__).resolve().parents[1] / "manifests" / "ise.json"


async def tool_names(**kw: object) -> set[str]:
    server = make_server(**EVERY_TIER, **kw)
    return {t.name for t in await server.list_tools(run_middleware=False)}


def tools_in(*areas: str) -> set[str]:
    return {t for a in areas for t in TOOLSETS[a][1]}


async def test_every_tool_has_a_toolset() -> None:
    names = await tool_names()
    missing = sorted(names - set(TOOLSET_OF) - ALWAYS_ON - CORE)
    assert not missing, f"add these tools to ise_mcp.toolsets.TOOLSETS (or ALWAYS_ON): {missing}"
    stale = sorted((set(TOOLSET_OF) | ALWAYS_ON) - names)
    assert not stale, f"not registered by any module, remove from ise_mcp.toolsets: {stale}"
    assert not ALWAYS_ON & set(TOOLSET_OF)


def test_table_is_well_formed() -> None:
    for area, (description, tools) in TOOLSETS.items():
        assert NAME_RE.match(area) and area != "all", area
        assert description and len(description) <= 160, area
        assert list(tools) == sorted(set(tools)), f"{area}: keep the tool list sorted, no duplicates"


@pytest.mark.parametrize("area", sorted(TOOLSETS))
async def test_contract_per_toolset(area: str) -> None:
    assert await tool_names(toolsets=area) == tools_in(area) | ALWAYS_ON | CORE


async def test_troubleshoot_and_policy() -> None:
    names = await tool_names(toolsets="troubleshoot,policy")
    assert names == tools_in("troubleshoot", "policy") | ALWAYS_ON | CORE
    assert "ise_why_auth_failed" in names and "ise_create_authz_rule" in names
    assert "ise_create_guest_user" not in names and "ise_list_sgts" not in names


async def test_exclusion_and_default() -> None:
    every = await tool_names()
    assert await tool_names(toolsets="all") == every
    without_guest = await tool_names(toolsets="-guest")
    assert without_guest == every - tools_in("guest")
    # a tool in two areas is hidden when one of them is excluded (core: an exclusion wins)
    assert "ise_policy_explain" not in await tool_names(toolsets="troubleshoot,-policy")


async def test_tiers_still_apply() -> None:
    server = make_server(toolsets="policy")  # reads only
    names = {t.name for t in await server.list_tools(run_middleware=False)}
    assert "ise_list_policy_sets" in names and "ise_create_authz_rule" not in names


async def test_tools_carry_toolset_tags() -> None:
    server = make_server(**EVERY_TIER)
    for t in await server.list_tools(run_middleware=False):
        assert tuple(toolsets_of(t.tags)) == tuple(sorted(TOOLSET_OF.get(t.name, ()))), t.name


async def test_status_reports_toolsets_and_unknown_names(
    mock: respx.MockRouter, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        server = make_server(toolsets="troubleshoot,polcy")
    assert "polcy" in caplog.text
    out = await call_tool(server, "ise_status")
    sets = out["server"]["toolsets"]
    assert sets["setting"] == "troubleshoot,polcy"
    assert sets["unknown"] == ["polcy"]
    assert set(sets["available"]) == set(TOOLSETS)
    assert "troubleshoot" in sets["loaded"] and "guest" in sets["not_loaded"]
    assert "Only some toolsets are loaded" in (server.instructions or "")


async def test_status_without_selection(mock: respx.MockRouter) -> None:
    out = await call_tool(make_server(), "ise_status")
    sets = out["server"]["toolsets"]
    assert sets["setting"] == "all" and "unknown" not in sets and "hidden_tools" not in sets


def test_manifest_records_toolsets() -> None:
    tools = json.loads(MANIFEST.read_text())["tools"]
    for name, entry in tools.items():
        assert entry.get("toolsets", []) == sorted(TOOLSET_OF.get(name, ())), (
            f"{name}: regenerate tests/manifests/ise.json (ise-mcp-server tools --json --out ...)"
        )

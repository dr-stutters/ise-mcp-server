"""ise_reset_hitcounts (I56): scope/section -> reset-hitcount operation mapping, the counts shown in the
preview, MFA absent on older ISE, and the guards. Rule lists are the recorded policy_sets.json /
authz_rules.json / authn_rules.json fixtures."""

from __future__ import annotations

import copy
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ise_mcp.tools.hitcounts import table_paths
from tests.unit.conftest import fixture_json, make_server

PS_ID = "d303293e-f4ba-4578-80eb-a01249fc5ae2"  # 'Default' in policy_sets.json
NA = "/api/v1/policy/network-access/policy-set"
DA = "/api/v1/policy/device-admin/policy-set"
OK = {"version": "1.0.0", "response": {"message": "Hit counts reset successfully"}}


def authz_with_hits() -> dict[str, Any]:
    data = copy.deepcopy(fixture_json("authz_rules.json"))
    for i, entry in enumerate(data["response"]):
        entry["rule"]["hitCounts"] = i + 1
    return data


def authz_total() -> int:
    return sum(range(1, len(fixture_json("authz_rules.json")["response"]) + 1))


async def run(args: dict[str, Any], *, apply: bool = True) -> tuple[Any, Any]:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(server) as c:
        preview = (await c.call_tool("ise_reset_hitcounts", args)).structured_content
        if preview.get("status") != "preview" or not apply:
            return preview, None
        applied = (
            await c.call_tool("ise_reset_hitcounts", {**args, "confirm": preview["confirm"]})
        ).structured_content
        return preview, applied


@pytest.mark.parametrize(
    ("kind", "section", "ps", "get", "post"),
    [
        ("network-access", "policy_sets", None, NA, f"{NA}/reset-hitcount"),
        ("device-admin", "policy_sets", None, DA, f"{DA}/reset-hitcount"),
        (
            "network-access",
            "global_exception",
            None,
            f"{NA}/global-exception",
            f"{NA}/global-exception/reset-hitcount",
        ),
        (
            "device-admin",
            "global_exception",
            None,
            f"{DA}/global-exception",
            f"{DA}/global-exception/reset-hitcount",
        ),
        *[
            (k, s, "p1", f"{b}/p1/{s}", f"{b}/p1/{s}/reset-hitcount")
            for k, b in (("network-access", NA), ("device-admin", DA))
            for s in ("authentication", "authorization", "exception", "mfa")
        ],
    ],
)
def test_table_paths_cover_all_twelve(kind: str, section: str, ps: str | None, get: str, post: str) -> None:
    assert table_paths(kind, section, ps) == (get, post)


def test_table_paths_guards() -> None:
    from ise_mcp._core import InvalidRequest

    with pytest.raises(InvalidRequest):
        table_paths("network-access", "authorization")
    with pytest.raises(InvalidRequest):
        table_paths("network-access", "bogus", "p1")


async def test_hidden_without_dangerous() -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_reset_hitcounts" not in names


async def test_policy_set_authorization_preview_and_apply(mock: respx.MockRouter) -> None:
    mock.get(NA).respond(json=fixture_json("policy_sets.json"))
    mock.get(f"{NA}/{PS_ID}/authorization").respond(json=authz_with_hits())
    reset = mock.post(f"{NA}/{PS_ID}/authorization/reset-hitcount").respond(json=OK)
    other = mock.post(f"{NA}/{PS_ID}/authentication/reset-hitcount").respond(json=OK)
    preview, applied = await run(
        {"scope": "policy_set", "policy_set": "default", "sections": ["authorization"]}
    )
    assert preview["status"] == "preview"
    assert preview["blast_radius"] == 1
    details = preview["preview"]
    assert details["policy_set"] == "Default"
    assert details["reset"] == ["authorization"]
    assert details["hits_lost"] == authz_total()
    rules = details["current_counts"]["authorization"]["rules"]
    assert rules[0] == {"name": "Wireless Block List Default", "hits": 1}
    assert details["requests"] == [f"POST {NA}/{PS_ID}/authorization/reset-hitcount"]
    assert applied["result"]["reset"] == 1 and applied["result"]["failed"] == 0
    assert applied["result"]["results"][0]["message"] == "Hit counts reset successfully"
    assert reset.call_count == 1 and not other.called


async def test_policy_set_default_sections_skip_missing_mfa(mock: respx.MockRouter) -> None:
    mock.get(NA).respond(json=fixture_json("policy_sets.json"))
    mock.get(f"{NA}/{PS_ID}/authentication").respond(json=fixture_json("authn_rules.json"))
    mock.get(f"{NA}/{PS_ID}/authorization").respond(json=authz_with_hits())
    mock.get(f"{NA}/{PS_ID}/exception").respond(json={"version": "1.0.0", "response": []})
    mock.get(f"{NA}/{PS_ID}/mfa").respond(404, json={"message": "not found"})
    posts = {
        s: mock.post(f"{NA}/{PS_ID}/{s}/reset-hitcount").respond(json=OK)
        for s in ("authentication", "authorization", "exception", "mfa")
    }
    preview, applied = await run({"scope": "policy_set", "policy_set": PS_ID})
    assert preview["status"] == "preview"
    assert preview["preview"]["reset"] == ["authentication", "authorization", "exception"]
    assert preview["preview"]["skipped"] == ["mfa: not on this ISE"]
    assert preview["blast_radius"] == 3
    assert applied["result"]["reset"] == 3
    assert all(posts[s].called for s in ("authentication", "authorization", "exception"))
    assert not posts["mfa"].called


async def test_policy_sets_scope_with_global_exceptions(mock: respx.MockRouter) -> None:
    mock.get(DA).respond(json=fixture_json("policy_sets.json"))
    mock.get(f"{DA}/global-exception").respond(json=authz_with_hits())
    sets = mock.post(f"{DA}/reset-hitcount").respond(json=OK)
    glob = mock.post(f"{DA}/global-exception/reset-hitcount").respond(json=OK)
    preview, applied = await run(
        {"scope": "policy_sets", "kind": "device-admin", "sections": ["global_exception"]}
    )
    assert preview["status"] == "preview"
    counts = preview["preview"]["current_counts"]
    assert counts["policy_sets"] == {"total_hits": 4, "policy_sets": [{"name": "Default", "hits": 4}]}
    assert counts["global_exception"]["total_hits"] == authz_total()
    assert preview["preview"]["hits_lost"] == 4 + authz_total()
    side = " ".join(preview["side_effects"])
    assert "ise_snapshot and ise_export_config do not record hit counts" in side
    assert applied["result"]["reset"] == 2
    assert sets.called and glob.called


async def test_preview_sends_nothing(mock: respx.MockRouter) -> None:
    mock.get(NA).respond(json=fixture_json("policy_sets.json"))
    reset = mock.post(f"{NA}/reset-hitcount").respond(json=OK)
    preview, _ = await run({"scope": "policy_sets"}, apply=False)
    assert preview["status"] == "preview" and preview["preview"]["hits_lost"] == 4
    assert not reset.called


async def test_post_failure_is_a_result_row(mock: respx.MockRouter) -> None:
    mock.get(NA).respond(json=fixture_json("policy_sets.json"))
    mock.post(f"{NA}/reset-hitcount").respond(500, json={"message": "boom"})
    _, applied = await run({"scope": "policy_sets"})
    assert applied["result"]["failed"] == 1
    assert applied["result"]["results"][0]["reset"] is False


async def test_unknown_policy_set(mock: respx.MockRouter) -> None:
    mock.get(NA).respond(json=fixture_json("policy_sets.json"))
    with pytest.raises(ToolError, match="No network-access policy set"):
        await run({"scope": "policy_set", "policy_set": "nope"})


@pytest.mark.parametrize(
    ("args", "match"),
    [
        ({"scope": "policy_set"}, "needs `policy_set`"),
        ({"scope": "policy_sets", "policy_set": "Default"}, "no per-set reset"),
        ({"scope": "policy_sets", "sections": ["authorization"]}, "belong to one policy set"),
    ],
)
async def test_argument_guards(mock: respx.MockRouter, args: dict[str, Any], match: str) -> None:
    mock.get(NA).respond(json=fixture_json("policy_sets.json"))
    with pytest.raises(ToolError, match=match):
        await run(args)


async def test_read_error_blocks(mock: respx.MockRouter) -> None:
    mock.get(NA).respond(json=fixture_json("policy_sets.json"))
    mock.get(f"{NA}/{PS_ID}/authorization").respond(500, json={"message": "boom"})
    preview, _ = await run({"scope": "policy_set", "policy_set": "Default", "sections": ["authorization"]})
    assert preview["status"] == "blocked"
    assert any("Could not read the current authorization counts" in b for b in preview["blockers"])

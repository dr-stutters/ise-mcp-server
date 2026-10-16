"""I11: AD join points, join/leave, groups, user test; AD in why_auth_failed and policy_explain."""

from __future__ import annotations

import json
from typing import Any

import respx
from fastmcp import Client
from stutters_mcp_core.testing import call_tool

from ise_mcp.knowledge import FAILURE_HINTS
from ise_mcp.tools.policy_edit import check_attribute
from ise_mcp.tools.policy_explain import eval_multi, evaluate
from tests.unit.conftest import FAILURE_REASONS_XML, MISSING_SESSION, ers_page, fixture_text, make_server
from tests.unit.test_writes import two_step

JP_ID = "3fb37cb0-c8fb-11f1-b70f-aaac89c8aec5"
SID_EMP = "S-1-5-21-1-2-3-1103"
SID_CON = "S-1-5-21-1-2-3-1104"
NODES = {"response": [{"hostname": "ise", "fqdn": "ise.corp.lab", "ipAddress": "10.0.0.5"}]}
DOMAIN_GROUPS = {
    "ERSActiveDirectoryGroups": {
        "groups": [
            {"name": "corp.lab/MCP-Lab/mcp-employees", "sid": SID_EMP, "type": "GLOBAL"},
            {"name": "corp.lab/MCP-Lab/mcp-contractors", "sid": SID_CON, "type": "GLOBAL"},
            {"name": "corp.lab/Other/mcp-contractors", "sid": "S-1-5-21-1-2-3-2000", "type": "GLOBAL"},
        ]
    }
}
NOT_JOINED = {
    "ERSResponse": {
        "operation": "PUT-getTrustedDomains-activedirectory",
        "messages": [{"title": "AD Instance: CORP is not joined ", "type": "ERROR"}],
    }
}
JOINED = {"ERSActiveDirectoryDomains": {"domains": [{"dnsName": "corp.lab", "forest": "corp.lab"}]}}
OP = f"/ers/config/activedirectory/{JP_ID}"


def join_point(groups: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "ERSActiveDirectory": {
            "id": JP_ID,
            "name": "CORP",
            "domain": "corp.lab",
            "adgroups": {"groups": groups or []},
            "advancedSettings": {"enableMachineAuth": True},
            "adScopesNames": "Default_Scope",
        }
    }


def mock_jp(
    mock: respx.MockRouter, *, joined: bool = True, groups: list[dict[str, Any]] | None = None
) -> None:
    mock.get("/ers/config/activedirectory", params={"filter": "name.EQ.CORP"}).respond(
        json=ers_page([{"id": JP_ID, "name": "CORP"}])
    )
    mock.get("/ers/config/activedirectory").respond(json=ers_page([{"id": JP_ID, "name": "CORP"}]))
    mock.get(OP).respond(json=join_point(groups))
    if joined:
        mock.put(f"{OP}/getTrustedDomains").respond(json=JOINED)
    else:
        mock.put(f"{OP}/getTrustedDomains").respond(500, json=NOT_JOINED)


async def test_get_join_point_status(mock: respx.MockRouter) -> None:
    mock_jp(mock, groups=[{"name": "corp.lab/MCP-Lab/mcp-employees", "sid": SID_EMP}])
    out = await call_tool(make_server(), "ise_get_ad_join_point", {"join_point": "CORP"})
    assert out["join"]["joined"] is True and out["join"]["domains"][0]["domain"] == "corp.lab"
    assert out["groups"] == ["corp.lab/MCP-Lab/mcp-employees"]
    assert out["policy_condition"].startswith("CORP:ExternalGroups")


async def test_get_join_point_not_joined(mock: respx.MockRouter) -> None:
    mock_jp(mock, joined=False)
    out = await call_tool(make_server(), "ise_get_ad_join_point", {"join_point": "CORP"})
    assert out["join"]["joined"] is False
    assert "ise_add_ad_groups" in out["policy_condition"]


async def test_create_join_point(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/activedirectory").respond(json=ers_page([]))
    post = mock.post("/ers/config/activedirectory").respond(
        201, headers={"Location": "https://ise.test/ers/config/activedirectory/new"}
    )
    preview, applied = await two_step("ise_create_ad_join_point", {"name": "CORP", "domain": "Corp.Lab"})
    assert preview["status"] == "preview"
    body = json.loads(post.calls.last.request.content)["ERSActiveDirectory"]
    assert body["domain"] == "corp.lab" and body["name"] == "CORP"
    assert applied["result"]["id"] == "new"


async def test_create_join_point_duplicate_domain_blocked(mock: respx.MockRouter) -> None:
    mock_jp(mock)
    preview, _ = await two_step("ise_create_ad_join_point", {"name": "OTHER", "domain": "corp.lab"})
    assert preview["status"] == "blocked"
    assert "already exists" in preview["blockers"][0]


async def test_join_single_node_uses_fqdn_and_hides_password(mock: respx.MockRouter) -> None:
    mock_jp(mock, joined=False)
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    join = mock.put(f"{OP}/join").respond(204)
    args = {"join_point": "CORP", "username": "Administrator", "password": "Sup3r-Secret", "node": "ise"}
    preview, applied = await two_step("ise_join_ad", args, mcp_enable_dangerous=True)
    assert "Sup3r-Secret" not in json.dumps(preview)
    assert preview["preview"]["password"] == "set (never shown)"
    assert applied["status"] == "applied"
    pairs = {
        p["name"]: p["value"]
        for p in json.loads(join.calls.last.request.content)["OperationAdditionalData"]["additionalData"]
    }
    assert pairs == {"username": "Administrator", "password": "Sup3r-Secret", "node": "ise.corp.lab"}
    assert "Sup3r-Secret" not in json.dumps(applied)


async def test_join_all_nodes(mock: respx.MockRouter) -> None:
    mock_jp(mock, joined=False)
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    join = mock.put(f"{OP}/joinAllNodes").respond(204)
    args = {"join_point": "CORP", "username": "Administrator", "password": "pw12345"}
    _, applied = await two_step("ise_join_ad", args, mcp_enable_dangerous=True)
    assert applied["status"] == "applied" and join.called


async def test_join_is_dangerous_tier() -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_join_ad" not in names and "ise_leave_ad" not in names
    assert {"ise_create_ad_join_point", "ise_add_ad_groups", "ise_list_ad_groups"} <= names


async def test_leave_blocked_when_not_joined(mock: respx.MockRouter) -> None:
    mock_jp(mock, joined=False)
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    args = {"join_point": "CORP", "username": "Administrator", "password": "pw12345"}
    preview, _ = await two_step("ise_leave_ad", args, mcp_enable_dangerous=True)
    assert preview["status"] == "blocked"


async def test_list_ad_groups_marks_added(mock: respx.MockRouter) -> None:
    mock_jp(mock, groups=[{"name": "corp.lab/MCP-Lab/mcp-employees", "sid": SID_EMP}])
    search = mock.put(f"{OP}/getGroupsByDomain").respond(json=DOMAIN_GROUPS)
    out = await call_tool(
        make_server(),
        "ise_list_ad_groups",
        {"join_point": "CORP", "filter": "mcp*", "response_format": "json"},
    )
    added = {r["name"]: r["added"] for r in out["results"]}
    assert added["corp.lab/MCP-Lab/mcp-employees"] is True
    assert added["corp.lab/MCP-Lab/mcp-contractors"] is False
    pairs = json.loads(search.calls.last.request.content)["OperationAdditionalData"]["additionalData"]
    assert {"name": "filter", "value": "mcp*"} in pairs and {"name": "domain", "value": "corp.lab"} in pairs


async def test_list_ad_groups_not_joined(mock: respx.MockRouter) -> None:
    mock_jp(mock, joined=False)
    mock.put(f"{OP}/getGroupsByDomain").respond(500, json=NOT_JOINED)
    async with Client(make_server()) as c:
        r = await c.call_tool("ise_list_ad_groups", {"join_point": "CORP"}, raise_on_error=False)
    assert r.is_error and "ise_join_ad" in r.content[0].text


async def test_add_groups_resolves_names(mock: respx.MockRouter) -> None:
    mock_jp(mock, groups=[{"name": "corp.lab/MCP-Lab/mcp-employees", "sid": SID_EMP}])
    mock.put(f"{OP}/getGroupsByDomain").respond(json=DOMAIN_GROUPS)
    add = mock.put(f"{OP}/addGroups").respond(204)
    args = {"join_point": "CORP", "groups": ["mcp-employees", "corp.lab/MCP-Lab/mcp-contractors"]}
    preview, applied = await two_step("ise_add_ad_groups", args)
    assert preview["preview"]["add"] == ["corp.lab/MCP-Lab/mcp-contractors"]
    assert preview["preview"]["keep"] == ["corp.lab/MCP-Lab/mcp-employees"]
    sent = json.loads(add.calls.last.request.content)["ERSActiveDirectory"]["adgroups"]["groups"]
    assert [g["sid"] for g in sent] == [SID_EMP, SID_CON]
    assert applied["status"] == "applied"


async def test_add_groups_blockers(mock: respx.MockRouter) -> None:
    mock_jp(mock)
    mock.put(f"{OP}/getGroupsByDomain").respond(json=DOMAIN_GROUPS)
    preview, _ = await two_step(
        "ise_add_ad_groups", {"join_point": "CORP", "groups": ["mcp-typo", "mcp-contractors"]}
    )
    assert preview["status"] == "blocked"
    text = " ".join(preview["blockers"])
    assert "No group 'mcp-typo'" in text and "matches several groups" in text


async def test_test_ad_user(mock: respx.MockRouter) -> None:
    mock_jp(mock, groups=[{"name": "corp.lab/MCP-Lab/mcp-employees", "sid": SID_EMP}])
    mock.put(f"{OP}/getUserGroups").respond(
        json={
            "ERSActiveDirectoryGroups": {
                "groups": [
                    {"name": "corp.lab/Users/Domain Users", "sid": "S-1-5-21-1-2-3-513"},
                    {"name": "corp.lab/MCP-Lab/mcp-employees", "sid": SID_EMP},
                ]
            }
        }
    )
    out = await call_tool(make_server(), "ise_test_ad_user", {"join_point": "CORP", "username": "alice"})
    assert out["found"] is True
    assert out["groups_usable_in_policy"] == ["corp.lab/MCP-Lab/mcp-employees"]


async def test_test_ad_user_not_found(mock: respx.MockRouter) -> None:
    mock_jp(mock)
    mock.put(f"{OP}/getUserGroups").respond(
        404, json={"ERSResponse": {"messages": [{"title": "Failed due to : No such user"}]}}
    )
    out = await call_tool(make_server(), "ise_test_ad_user", {"join_point": "CORP", "username": "ghost"})
    assert out["found"] is False


async def test_delete_join_point_blocked_while_joined(mock: respx.MockRouter) -> None:
    mock_jp(mock)
    preview, _ = await two_step("ise_delete_object", {"kind": "ad_join_point", "target": "CORP"})
    assert preview["status"] == "blocked"
    assert "ise_leave_ad first" in preview["blockers"][0]


def test_external_groups_short_name() -> None:
    attrs = [
        {
            "dictionaryName": "CORP",
            "name": "ExternalGroups",
            "allowedValues": [
                {"key": "corp.lab/MCP-Lab/mcp-employees"},
                {"key": "corp.lab/MCP-Lab/mcp-contractors"},
            ],
        }
    ]
    node = {"dictionaryName": "corp", "attributeName": "externalgroups", "operator": "equals"}
    node["attributeValue"] = "mcp-employees"
    assert check_attribute(node, attrs) == []
    assert node["attributeValue"] == "corp.lab/MCP-Lab/mcp-employees"
    bad = {**node, "attributeValue": "mcp-typo"}
    assert check_attribute(bad, attrs)


def test_eval_multi_values() -> None:
    groups = ["corp.lab/Users/Domain Users", "corp.lab/MCP-Lab/mcp-employees"]
    assert eval_multi("equals", groups, "corp.lab/MCP-Lab/mcp-employees") is True
    assert eval_multi("equals", groups, "corp.lab/MCP-Lab/mcp-contractors") is False
    assert eval_multi("notEquals", groups, "corp.lab/MCP-Lab/mcp-employees") is False
    assert eval_multi("notEquals", groups, "corp.lab/MCP-Lab/mcp-contractors") is True
    assert eval_multi("equals", [], "x") is False
    cond = {
        "conditionType": "ConditionAttributes",
        "dictionaryName": "CORP",
        "attributeName": "ExternalGroups",
        "operator": "equals",
        "attributeValue": "corp.lab/MCP-Lab/mcp-employees",
    }
    assert evaluate(cond, {"CORP:ExternalGroups": groups}, {}) is True


async def test_policy_explain_ad_user(mock: respx.MockRouter) -> None:
    mock_jp(mock, groups=[{"name": "corp.lab/MCP-Lab/mcp-contractors", "sid": SID_CON}])
    mock.put(f"{OP}/getUserGroups").respond(
        json={
            "ERSActiveDirectoryGroups": {
                "groups": [{"name": "corp.lab/MCP-Lab/mcp-contractors", "sid": SID_CON}]
            }
        }
    )
    mock.get("/api/v1/policy/network-access/condition").respond(json={"response": []})
    mock.get("/api/v1/policy/network-access/policy-set").respond(
        json={"response": [{"id": "ps1", "name": "Default", "rank": 0, "default": True, "state": "enabled"}]}
    )
    mock.get("/api/v1/policy/network-access/policy-set/global-exception").respond(json={"response": []})
    mock.get("/api/v1/policy/network-access/policy-set/ps1/exception").respond(json={"response": []})

    def rule(rank: int, name: str, group: str | None, sgt: str) -> dict[str, Any]:
        cond = (
            {
                "conditionType": "ConditionAttributes",
                "dictionaryName": "CORP",
                "attributeName": "ExternalGroups",
                "operator": "equals",
                "attributeValue": group,
            }
            if group
            else None
        )
        return {
            "rule": {
                "name": name,
                "rank": rank,
                "state": "enabled",
                "default": group is None,
                "condition": cond,
            },
            "profile": ["PermitAccess"],
            "securityGroup": sgt,
        }

    mock.get("/api/v1/policy/network-access/policy-set/ps1/authorization").respond(
        json={
            "response": [
                rule(0, "emp", "corp.lab/MCP-Lab/mcp-employees", "Employees"),
                rule(1, "con", "corp.lab/MCP-Lab/mcp-contractors", "Contractors"),
                rule(2, "Default", None, "Unknown"),
            ]
        }
    )
    out = await call_tool(
        make_server(), "ise_policy_explain", {"flow": "wired-dot1x", "ad_user": "CORP\\bob"}
    )
    assert out["verdict"].startswith("Would match 'con'"), out
    assert [r["result"] for r in out["authorization"]] == ["no-match", "match"]


AD_MAC = "02:00:5E:00:00:03"


async def test_why_auth_failed_ad_disabled_account(mock: respx.MockRouter) -> None:
    mock.get("/admin/API/mnt/FailureReasons").respond(text=FAILURE_REASONS_XML)
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{AD_MAC}/86400/50/All").respond(
        text=fixture_text("mnt_authstatus_ad.xml")
    )
    mock.get(f"/admin/API/mnt/Session/MACAddress/{AD_MAC}").respond(500, text=MISSING_SESSION)
    mock.get("/ers/config/networkdevice").respond(json=ers_page([]))
    mock_jp(mock)
    mock.get("/ers/config/activedirectory").respond(json=ers_page([{"id": JP_ID, "name": "MITCHCLOUD"}]))
    lookup = mock.put(f"{OP}/getUserGroups").respond(
        json={
            "ERSActiveDirectoryGroups": {
                "groups": [{"name": "corp.lab/MCP-Lab/mcp-netreadonly", "sid": "S-9"}]
            }
        }
    )
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": AD_MAC})
    assert "24409" in out["verdict"]
    assert out["failure"]["likely"] == FAILURE_HINTS["24409"]["likely"]
    ad = out["checks"]["active_directory"]["join_points"][0]
    assert ad["join"]["joined"] is True and ad["user"]["found"] is True
    pairs = json.loads(lookup.calls.last.request.content)["OperationAdditionalData"]["additionalData"]
    assert pairs == [{"name": "username", "value": "mcp-netro1"}]


def test_ad_hints_match_ise_catalog() -> None:
    # 24415 is "account locked out" in ISE's catalog (the old hint said "join point unreachable").
    assert "locked out" in FAILURE_HINTS["24415"]["likely"]
    assert "disabled" in FAILURE_HINTS["24409"]["likely"]
    assert "not in Active Directory" in FAILURE_HINTS["24412"]["likely"]
    assert "attributes" in FAILURE_HINTS["24419"]["likely"]


async def test_policy_explain_ignores_unadded_groups(mock: respx.MockRouter) -> None:
    # bob is in mcp-contractors, but it isn't added to the join point: ISE never sees it.
    mock_jp(mock)
    mock.put(f"{OP}/getUserGroups").respond(
        json={
            "ERSActiveDirectoryGroups": {
                "groups": [{"name": "corp.lab/MCP-Lab/mcp-contractors", "sid": SID_CON}]
            }
        }
    )
    mock.get("/api/v1/policy/network-access/condition").respond(json={"response": []})
    mock.get("/api/v1/policy/network-access/policy-set").respond(
        json={"response": [{"id": "ps1", "name": "Default", "rank": 0, "default": True, "state": "enabled"}]}
    )
    mock.get("/api/v1/policy/network-access/policy-set/global-exception").respond(json={"response": []})
    mock.get("/api/v1/policy/network-access/policy-set/ps1/exception").respond(json={"response": []})
    cond = {
        "conditionType": "ConditionAttributes",
        "dictionaryName": "CORP",
        "attributeName": "ExternalGroups",
        "operator": "contains",
        "attributeValue": "contractors",
    }
    mock.get("/api/v1/policy/network-access/policy-set/ps1/authorization").respond(
        json={
            "response": [
                {"rule": {"name": "con", "rank": 0, "state": "enabled", "condition": cond}, "profile": ["P"]},
                {
                    "rule": {"name": "Default", "rank": 1, "state": "enabled", "default": True},
                    "profile": ["D"],
                },
            ]
        }
    )
    out = await call_tool(make_server(), "ise_policy_explain", {"flow": "wired-dot1x", "ad_user": "bob"})
    assert out["verdict"].startswith("Would match 'Default'"), out


async def test_join_error_never_carries_password(mock: respx.MockRouter) -> None:
    mock_jp(mock, joined=False)
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    mock.put(f"{OP}/joinAllNodes").respond(
        500, json={"ERSResponse": {"messages": [{"title": "join failed for password Sup3r-Secret"}]}}
    )
    args = {"join_point": "CORP", "username": "Administrator", "password": "Sup3r-Secret"}
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        r1 = await c.call_tool("ise_join_ad", args)
        token = r1.structured_content["confirm"]  # type: ignore[index]
        r2 = await c.call_tool("ise_join_ad", {**args, "confirm": token}, raise_on_error=False)
    text = json.dumps([getattr(x, "text", "") for x in r2.content]) + json.dumps(r2.structured_content)
    assert "Sup3r-Secret" not in text

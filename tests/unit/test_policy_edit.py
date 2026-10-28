"""Policy editing (policy sets, authn/authz rules, rule updates) and device administration tools."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from ise_mcp._core import InvalidRequest
from ise_mcp.tools.device_admin import parse_commands
from ise_mcp.tools.policy_edit import check_attribute, condition_node, landing
from tests.unit.conftest import BASE, ers_page, make_server

NA = "/api/v1/policy/network-access"
DA = "/api/v1/policy/device-admin"
ATTRS = [
    {
        "dictionaryName": "Radius",
        "name": "NAS-Port-Type",
        "dataType": "INT",
        "allowedValues": [{"key": "Ethernet", "value": "15"}, {"key": "Virtual", "value": "5"}],
    },
    {
        "dictionaryName": "DEVICE",
        "name": "Location",
        "dataType": "STRING",
        "allowedValues": [{"key": "All Locations", "value": "Location#All Locations"}],
    },
    {"dictionaryName": "Session", "name": "ANCPolicy", "dataType": "STRING", "allowedValues": []},
    {"dictionaryName": "IdentityGroup", "name": "Name", "dataType": "STRING", "allowedValues": []},
]
LIB = {"wired_mab": {"id": "c1", "name": "Wired_MAB"}}


def attr(text: str) -> dict[str, Any]:
    return condition_node(text, LIB)


def test_check_attribute_canonicalises_and_suggests() -> None:
    node = attr("radius:nas-port-type equals ethernet")
    assert check_attribute(node, ATTRS) == []
    assert (node["dictionaryName"], node["attributeName"], node["attributeValue"]) == (
        "Radius",
        "NAS-Port-Type",
        "Ethernet",
    )
    bad = check_attribute(attr("Radius:NAS-Port-Typ equals Ethernet"), ATTRS)
    assert "Did you mean Radius:NAS-Port-Type" in bad[0]
    wrong_value = check_attribute(attr("Radius:NAS-Port-Type equals Wifi"), ATTRS)
    assert "allowed: Ethernet, Virtual" in wrong_value[0]
    free = attr("Session:ANCPolicy equals anything")
    assert check_attribute(free, ATTRS) == []


def test_device_values_drop_the_root() -> None:
    node = attr("DEVICE:Location equals Location#All Locations#Sydney")
    assert check_attribute(node, ATTRS) == []
    assert node["attributeValue"] == "All Locations#Sydney"


def test_condition_operators_with_spaces_in_attribute() -> None:
    node = condition_node("DEVICE:Device Type equals All Device Types#Switch", LIB)
    assert node["attributeName"] == "Device Type" and node["operator"] == "equals"
    assert condition_node("Radius:NAS-IP-Address ipEquals 10.0.0.1", LIB)["operator"] == "ipEquals"


def test_landing() -> None:
    assert landing(["A", "B", "Default"], 0) == {"inserted_before": "A", "inserted_after": None}
    assert landing(["A", "B", "Default"], 9) == {"inserted_before": "Default", "inserted_after": "B"}


def test_parse_commands() -> None:
    assert parse_commands(["permit show .*", "DENY_ALWAYS reload"]) == [
        {"grant": "PERMIT", "command": "show", "arguments": ".*"},
        {"grant": "DENY_ALWAYS", "command": "reload", "arguments": ""},
    ]
    with pytest.raises(InvalidRequest):
        parse_commands(["show version"])


async def two_step(name: str, args: dict[str, Any], *, dangerous: bool = False) -> tuple[Any, Any]:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=dangerous)
    async with Client(server) as c:
        preview = (await c.call_tool(name, args)).structured_content
        assert preview is not None
        if preview.get("status") != "preview":
            return preview, None
        applied = (await c.call_tool(name, {**args, "confirm": preview["confirm"]})).structured_content
        return preview, applied


def policy_mocks(mock: respx.MockRouter, base: str = NA) -> None:
    mock.get(f"{base}/policy-set").respond(
        json={
            "response": [
                {"id": "s1", "name": "Wired", "rank": 0},
                {"id": "s0", "name": "Default", "rank": 1, "default": True},
            ]
        }
    )
    mock.get(f"{base}/condition").respond(json={"response": [{"id": "c1", "name": "Wired_MAB"}]})
    for scope in ("authorization", "authentication", "policyset"):
        mock.get(f"{base}/dictionaries/{scope}").respond(json={"response": ATTRS})


async def test_create_authz_rule_network_access(mock: respx.MockRouter) -> None:
    policy_mocks(mock)
    mock.get(f"{NA}/authorization-profiles").respond(json=[{"name": "PermitAccess"}, {"name": "Quar"}])
    mock.get(f"{NA}/security-groups").respond(json=[{"name": "Employees"}])
    mock.get(f"{NA}/policy-set/s1/authorization").respond(
        json={"response": [{"rule": {"name": "Default", "rank": 0, "default": True}}]}
    )
    post = mock.post(f"{NA}/policy-set/s1/authorization").respond(
        201, json={"response": {"rule": {"id": "r9", "name": "Printers", "rank": 0}}}
    )
    preview, applied = await two_step(
        "ise_create_authz_rule",
        {
            "policy_set": "wired",
            "name": "Printers",
            "conditions": ["Wired_MAB", "Radius:NAS-Port-Type equals ethernet"],
            "profiles": ["permitaccess"],
            "sgt": "employees",
        },
    )
    assert preview["preview"]["inserted_before"] == "Default"
    assert preview["preview"]["condition"] == "(Wired_MAB AND Radius:NAS-Port-Type equals Ethernet)"
    body = json.loads(post.calls.last.request.content)
    assert body["rule"]["condition"]["conditionType"] == "ConditionAndBlock"
    assert body["securityGroup"] == "Employees" and body["profile"] == ["PermitAccess"]
    assert applied["result"] == {"id": "r9", "name": "Printers", "rank": 0}


async def test_create_authz_rule_blocks_unknown_profile(mock: respx.MockRouter) -> None:
    policy_mocks(mock)
    mock.get(f"{NA}/authorization-profiles").respond(json=[{"name": "PermitAccess"}])
    mock.get(f"{NA}/policy-set/s1/authorization").respond(json={"response": []})
    preview, _ = await two_step(
        "ise_create_authz_rule",
        {"policy_set": "Wired", "name": "X", "conditions": ["Wired_MAB"], "profiles": ["PermitAcess"]},
    )
    assert preview["status"] == "blocked"
    assert "did you mean PermitAccess" in preview["blockers"][0]


async def test_create_device_admin_rule(mock: respx.MockRouter) -> None:
    policy_mocks(mock, DA)
    mock.get(f"{DA}/command-sets").respond(json=[{"name": "ShowOnly"}])
    mock.get(f"{DA}/shell-profiles").respond(json=[{"name": "Priv15"}])
    mock.get(f"{DA}/policy-set/s1/authorization").respond(json={"response": []})
    post = mock.post(f"{DA}/policy-set/s1/authorization").respond(201, json={"response": {}})
    _, applied = await two_step(
        "ise_create_authz_rule",
        {
            "kind": "device-admin",
            "policy_set": "Wired",
            "name": "NetOps",
            "conditions": ["IdentityGroup:Name equals User Identity Groups:NetOps"],
            "command_sets": ["showonly"],
            "shell_profile": "priv15",
        },
    )
    body = json.loads(post.calls.last.request.content)
    assert body["commands"] == ["ShowOnly"] and body["profile"] == "Priv15"
    assert applied["status"] == "applied"


async def test_device_admin_rule_rejects_network_access_results(mock: respx.MockRouter) -> None:
    policy_mocks(mock, DA)
    mock.get(f"{DA}/policy-set/s1/authorization").respond(json={"response": []})
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool(
            "ise_create_authz_rule",
            {
                "kind": "device-admin",
                "policy_set": "Wired",
                "name": "X",
                "conditions": ["Wired_MAB"],
                "profiles": ["PermitAccess"],
            },
            raise_on_error=False,
        )
    assert r.is_error and "command_sets" in r.content[0].text


async def test_create_policy_set(mock: respx.MockRouter) -> None:
    policy_mocks(mock)
    mock.get(f"{NA}/service-names").respond(json=[{"name": "Default Network Access"}])
    post = mock.post(f"{NA}/policy-set").respond(
        201, json={"response": {"id": "n1", "name": "Lab", "rank": 0}}
    )
    preview, applied = await two_step(
        "ise_create_policy_set",
        {"name": "Lab", "conditions": ["DEVICE:Location equals Location#All Locations#Lab"]},
    )
    assert preview["preview"]["inserted_before"] == "Wired"
    body = json.loads(post.calls.last.request.content)
    assert body["serviceName"] == "Default Network Access"
    assert body["condition"]["attributeValue"] == "All Locations#Lab"
    assert applied["result"]["id"] == "n1"
    blocked, _ = await two_step(
        "ise_create_policy_set", {"name": "Lab", "conditions": ["Wired_MAB"], "allowed_protocols": "Nope"}
    )
    assert blocked["status"] == "blocked"


SERVICES = [
    {"name": "Default Network Access", "serviceType": "allowedProtocols", "isLocalAuthorization": None},
    {"name": "mcp_r96_seq", "serviceType": "serverSequence", "isLocalAuthorization": False},
]


async def test_create_policy_set_on_server_sequence_proxies(mock: respx.MockRouter) -> None:
    # #158: ISE answers 400 "Mismatch between proxy attribute to service name" unless isProxy follows it.
    policy_mocks(mock)
    mock.get(f"{NA}/service-names").respond(json=SERVICES)
    post = mock.post(f"{NA}/policy-set").respond(
        201, json={"response": {"id": "n2", "name": "mcp_proxy_set", "rank": 0}}
    )
    preview, applied = await two_step(
        "ise_create_policy_set",
        {"name": "mcp_proxy_set", "conditions": ["Wired_MAB"], "allowed_protocols": "MCP_R96_SEQ"},
    )
    assert preview["status"] == "preview", preview
    assert preview["preview"]["proxy"] is True
    assert any("proxies" in s and "mcp_r96_seq" in s for s in preview["side_effects"])
    body = json.loads(post.calls.last.request.content)
    assert body["serviceName"] == "mcp_r96_seq" and body["isProxy"] is True
    assert applied["status"] == "applied"
    # An allowed-protocols service stays a non-proxy set.
    await two_step("ise_create_policy_set", {"name": "mcp_local_set", "conditions": ["Wired_MAB"]})
    assert json.loads(post.calls.last.request.content)["isProxy"] is False


async def test_update_policy_set_service_switches_is_proxy_both_ways(mock: respx.MockRouter) -> None:
    policy_mocks(mock)
    mock.get(f"{NA}/service-names").respond(json=SERVICES)
    ps = {
        "id": "s1",
        "name": "Wired",
        "rank": 0,
        "state": "enabled",
        "serviceName": "Default Network Access",
        "isProxy": False,
    }
    get = mock.get(f"{NA}/policy-set/s1").respond(json={"response": ps})
    put = mock.put(f"{NA}/policy-set/s1").respond(json={"response": ps})
    preview, applied = await two_step(
        "ise_update_policy_set", {"policy_set": "Wired", "allowed_protocols": "mcp_r96_seq"}
    )
    assert preview["preview"]["changes"]["isProxy"] == {"from": False, "to": True}
    assert any("proxies" in s for s in preview["side_effects"])
    sent = json.loads(put.calls.last.request.content)
    assert sent["serviceName"] == "mcp_r96_seq" and sent["isProxy"] is True
    assert applied["status"] == "applied"
    # And back: a proxy set moved to an allowed-protocols service sends isProxy false.
    proxied = {**ps, "serviceName": "mcp_r96_seq", "isProxy": True}
    get.respond(json={"response": proxied})
    preview, _ = await two_step(
        "ise_update_policy_set", {"policy_set": "Wired", "allowed_protocols": "Default Network Access"}
    )
    assert preview["preview"]["changes"]["isProxy"] == {"from": True, "to": False}
    assert any("stops proxying" in s for s in preview["side_effects"])
    sent = json.loads(put.calls.last.request.content)
    assert sent["serviceName"] == "Default Network Access" and sent["isProxy"] is False


async def test_create_authn_rule(mock: respx.MockRouter) -> None:
    policy_mocks(mock)
    mock.get(f"{NA}/identity-stores").respond(json=[{"name": "Internal Endpoints"}])
    mock.get(f"{NA}/policy-set/s1/authentication").respond(
        json={"response": [{"rule": {"name": "Default", "rank": 0, "default": True}}]}
    )
    post = mock.post(f"{NA}/policy-set/s1/authentication").respond(201, json={"response": {}})
    await two_step(
        "ise_create_authn_rule",
        {
            "policy_set": "Wired",
            "name": "MAB",
            "conditions": ["Wired_MAB"],
            "identity_source": "internal endpoints",
            "if_user_not_found": "CONTINUE",
        },
    )
    body = json.loads(post.calls.last.request.content)
    assert body["identitySourceName"] == "Internal Endpoints" and body["ifUserNotFound"] == "CONTINUE"


async def test_update_policy_rule(mock: respx.MockRouter) -> None:
    policy_mocks(mock)
    rule = {
        "rule": {
            "id": "r1",
            "name": "Printers",
            "rank": 0,
            "state": "enabled",
            "hitCounts": 3,
            "condition": {
                "conditionType": "ConditionReference",
                "name": "Wired_MAB",
                "id": "c1",
                "link": {"href": "x"},
            },
        },
        "profile": ["PermitAccess"],
        "link": {"href": "x"},
    }
    default = {"rule": {"id": "r2", "name": "Default", "rank": 1, "default": True}, "profile": ["DenyAccess"]}
    mock.get(f"{NA}/policy-set/s1/authorization").respond(json={"response": [rule, default]})
    mock.get(f"{NA}/policy-set/s1/authorization/r1").respond(json={"response": rule})
    mock.get(f"{NA}/policy-set/s1/authorization/r2").respond(json={"response": default})
    put = mock.put(f"{NA}/policy-set/s1/authorization/r1").respond(
        200, json={"response": {**rule, "rule": {**rule["rule"], "state": "disabled"}}}
    )
    preview, applied = await two_step(
        "ise_update_policy_rule", {"policy_set": "Wired", "rule": "printers", "state": "disabled"}
    )
    assert preview["preview"]["changes"] == {"rule.state": {"from": "enabled", "to": "disabled"}}
    sent = json.loads(put.calls.last.request.content)
    assert "link" not in sent and "hitCounts" not in sent["rule"] and "link" not in sent["rule"]["condition"]
    assert applied["result"]["state"] == "disabled"
    blocked, _ = await two_step(
        "ise_update_policy_rule", {"policy_set": "Wired", "rule": "Default", "rank": 0}
    )
    assert blocked["status"] == "blocked"


async def test_update_policy_set_state(mock: respx.MockRouter) -> None:
    policy_mocks(mock)
    ps = {"id": "s1", "name": "Wired", "rank": 0, "state": "enabled", "serviceName": "Default Network Access"}
    mock.get(f"{NA}/policy-set/s1").respond(json={"response": ps})
    put = mock.put(f"{NA}/policy-set/s1").respond(200, json={"response": {**ps, "state": "monitor"}})
    preview, applied = await two_step("ise_update_policy_set", {"policy_set": "Wired", "state": "monitor"})
    assert preview["preview"]["changes"] == {"state": {"from": "enabled", "to": "monitor"}}
    assert json.loads(put.calls.last.request.content)["state"] == "monitor"
    assert applied["result"]["state"] == "monitor"


# --- C71 (#151): a re-send of the current state is no_change, not an error --------------------------

DEFAULT_DENY = {
    "rule": {"id": "r2", "name": "Default", "rank": 1, "state": "enabled", "default": True},
    "profile": ["DenyAccess"],
}
AUTHN_MAB = {
    "rule": {
        "id": "a1",
        "name": "mcp-test-mab",
        "rank": 0,
        "state": "enabled",
        "condition": {"conditionType": "ConditionReference", "name": "Wired_MAB", "id": "c1"},
    },
    "identitySourceName": "Internal Endpoints",
    "ifUserNotFound": "CONTINUE",
    "ifAuthFail": "REJECT",
    "ifProcessFail": "DROP",
}


def noop_rule_mocks(mock: respx.MockRouter) -> tuple[respx.Route, respx.Route]:
    policy_mocks(mock)
    mock.get(f"{NA}/authorization-profiles").respond(json=[{"name": "PermitAccess"}, {"name": "DenyAccess"}])
    mock.get(f"{NA}/policy-set/s1/authorization").respond(json={"response": [DEFAULT_DENY]})
    mock.get(f"{NA}/policy-set/s1/authorization/r2").respond(json={"response": DEFAULT_DENY})
    mock.get(f"{NA}/policy-set/s1/authentication").respond(json={"response": [AUTHN_MAB]})
    mock.get(f"{NA}/policy-set/s1/authentication/a1").respond(json={"response": AUTHN_MAB})
    authz_put = mock.put(f"{NA}/policy-set/s1/authorization/r2").respond(json={"response": DEFAULT_DENY})
    authn_put = mock.put(f"{NA}/policy-set/s1/authentication/a1").respond(json={"response": AUTHN_MAB})
    return authz_put, authn_put


async def test_update_policy_rule_default_already_deny_is_no_change(mock: respx.MockRouter) -> None:
    authz_put, _ = noop_rule_mocks(mock)
    out, applied = await two_step(
        "ise_update_policy_rule", {"policy_set": "Wired", "rule": "Default", "profiles": ["DenyAccess"]}
    )
    assert out["status"] == "no_change", out
    assert "confirm" not in out and applied is None and not authz_put.called
    assert "authorization rule Default in Wired already as requested" in out["summary"]
    # A real difference still previews with a token.
    preview, applied = await two_step(
        "ise_update_policy_rule", {"policy_set": "Wired", "rule": "Default", "profiles": ["PermitAccess"]}
    )
    assert preview["status"] == "preview" and preview["confirm"]
    assert preview["preview"]["changes"] == {"profile": {"from": ["DenyAccess"], "to": ["PermitAccess"]}}
    assert applied["status"] == "applied" and authz_put.called


async def test_update_authn_rule_if_user_not_found_unchanged_is_no_change(mock: respx.MockRouter) -> None:
    _, authn_put = noop_rule_mocks(mock)
    args = {
        "policy_set": "Wired",
        "rule": "mcp-test-mab",
        "section": "authentication",
        "if_user_not_found": "CONTINUE",
    }
    out, applied = await two_step("ise_update_policy_rule", args)
    assert out["status"] == "no_change", out
    assert "confirm" not in out and applied is None and not authn_put.called
    preview, _ = await two_step("ise_update_policy_rule", {**args, "if_user_not_found": "REJECT"})
    assert preview["status"] == "preview" and preview["confirm"]
    assert preview["preview"]["changes"] == {"ifUserNotFound": {"from": "CONTINUE", "to": "REJECT"}}


async def test_update_policy_set_unchanged_state_is_no_change(mock: respx.MockRouter) -> None:
    policy_mocks(mock)
    ps = {"id": "s1", "name": "Wired", "rank": 0, "state": "enabled", "serviceName": "Default Network Access"}
    mock.get(f"{NA}/policy-set/s1").respond(json={"response": ps})
    put = mock.put(f"{NA}/policy-set/s1").respond(json={"response": ps})
    out, applied = await two_step("ise_update_policy_set", {"policy_set": "Wired", "state": "enabled"})
    assert out["status"] == "no_change", out
    assert "confirm" not in out and applied is None and not put.called
    assert "already as requested" in out["summary"]


async def test_update_policy_tools_without_fields_are_still_an_error(mock: respx.MockRouter) -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        rule = await c.call_tool(
            "ise_update_policy_rule", {"policy_set": "Wired", "rule": "Default"}, raise_on_error=False
        )
        pset = await c.call_tool("ise_update_policy_set", {"policy_set": "Wired"}, raise_on_error=False)
    for r in (rule, pset):
        assert r.is_error and "Nothing to change" in str(r.content[0].text)  # type: ignore[union-attr]
    # Refused before any policy request reaches ISE.
    assert not [c for c in mock.calls if "/policy/" in c.request.url.path]


async def test_set_command_set_create_and_replace(mock: respx.MockRouter) -> None:
    lookup = mock.get("/ers/config/tacacscommandsets", params={"filter": "name.EQ.ShowOnly"}).respond(
        json=ers_page([])
    )
    post = mock.post("/ers/config/tacacscommandsets").respond(
        201, headers={"Location": f"{BASE}/ers/config/tacacscommandsets/cs1"}
    )
    args = {"name": "ShowOnly", "commands": ["PERMIT show .*", "DENY_ALWAYS reload"]}
    _, applied = await two_step("ise_set_command_set", args)
    body = json.loads(post.calls.last.request.content)["TacacsCommandSets"]
    assert body["commands"]["commandList"][1] == {
        "grant": "DENY_ALWAYS",
        "command": "reload",
        "arguments": "",
    }
    assert applied["result"]["id"] == "cs1"
    lookup.respond(json=ers_page([{"id": "cs1", "name": "ShowOnly"}]))
    existing = {
        "id": "cs1",
        "name": "ShowOnly",
        "permitUnmatched": False,
        "commands": {"commandList": [{"grant": "PERMIT", "command": "show", "arguments": ".*"}]},
    }
    mock.get("/ers/config/tacacscommandsets/cs1").respond(json={"TacacsCommandSets": existing})
    put = mock.put("/ers/config/tacacscommandsets/cs1").respond(200, json={})
    preview, _ = await two_step("ise_set_command_set", args)
    assert "commands" in str(preview["preview"]["changes"])
    assert put.called


async def test_shell_profile_name_and_attributes(mock: respx.MockRouter) -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool(
            "ise_set_shell_profile", {"name": "bad-name", "privilege": 15}, raise_on_error=False
        )
    assert r.is_error and "letters, digits" in r.content[0].text
    mock.get("/ers/config/tacacsprofile", params={"filter": "name.EQ.Priv15"}).respond(json=ers_page([]))
    post = mock.post("/ers/config/tacacsprofile").respond(
        201, headers={"Location": f"{BASE}/ers/config/tacacsprofile/p1"}
    )
    await two_step("ise_set_shell_profile", {"name": "Priv15", "privilege": 15, "idle_timeout": 30})
    attrs = json.loads(post.calls.last.request.content)["TacacsProfile"]["sessionAttributes"]
    assert {"type": "MANDATORY", "name": "priv-lvl", "value": "15"} in attrs["sessionAttributeList"]
    assert {"type": "MANDATORY", "name": "idletime", "value": "30"} in attrs["sessionAttributeList"]


async def test_update_node_services(mock: respx.MockRouter) -> None:
    node = {"hostname": "ise", "roles": ["Standalone"], "services": ["Session", "Profiler"]}
    mock.get("/api/v1/deployment/node", name="nodes").respond(json={"response": [node]})
    put = mock.put("/api/v1/deployment/node/ise").respond(200, json={"success": {"message": "ok"}})
    preview, applied = await two_step("ise_update_node_services", {"enable": ["DeviceAdmin"]}, dangerous=True)
    assert preview["preview"]["to"] == ["Session", "Profiler", "DeviceAdmin"]
    assert applied["status"] == "applied"
    assert json.loads(put.calls.last.request.content) == {
        "roles": ["Standalone"],
        "services": ["Session", "Profiler", "DeviceAdmin"],
    }
    blocked, _ = await two_step("ise_update_node_services", {"disable": ["Session"]}, dangerous=True)
    assert blocked["status"] == "blocked"
    assert any("only node running Session" in b for b in blocked["blockers"])


async def test_list_dictionary_attributes(mock: respx.MockRouter) -> None:
    mock.get(f"{NA}/dictionaries/authorization").respond(json={"response": ATTRS})
    mock.get(f"{NA}/dictionaries/nope/attribute").respond(404, json={"message": "not found"})
    async with Client(make_server()) as c:
        r = await c.call_tool("ise_list_dictionary_attributes", {"dictionary": "radius"})
        data = r.structured_content
        assert data["results"] == [
            {"attribute": "Radius:NAS-Port-Type", "type": "INT", "allowed": "Ethernet, Virtual"}
        ]
        r = await c.call_tool("ise_list_dictionary_attributes", {"dictionary": "nope"})
        assert "dictionaries are" in r.structured_content["note"]


async def test_authz_rule_accepts_custom_attribute_missing_from_dictionary(mock: respx.MockRouter) -> None:
    policy_mocks(mock)
    mock.get("/api/v1/endpoint-custom-attribute").respond(
        json=[{"attributeName": "assetTier", "attributeType": "String"}]
    )
    mock.get(f"{NA}/authorization-profiles").respond(json=[{"name": "PermitAccess"}])
    mock.get(f"{NA}/policy-set/s1/authorization").respond(
        json={"response": [{"rule": {"name": "Default", "rank": 0, "default": True}}]}
    )
    post = mock.post(f"{NA}/policy-set/s1/authorization").respond(201, json={"response": {"rule": {}}})
    preview, _ = await two_step(
        "ise_create_authz_rule",
        {
            "policy_set": "wired",
            "name": "Tier",
            "conditions": ["EndPoints:assettier equals gold"],
            "profiles": ["PermitAccess"],
        },
    )
    assert preview["status"] == "preview", preview
    assert preview["preview"]["condition"] == "EndPoints:assetTier equals gold"
    sent = json.loads(post.calls.last.request.content)["rule"]["condition"]
    assert sent["dictionaryName"] == "EndPoints" and sent["attributeName"] == "assetTier"
    bad, _ = await two_step(
        "ise_create_authz_rule",
        {
            "policy_set": "wired",
            "name": "Tier",
            "conditions": ["EndPoints:nope equals x"],
            "profiles": ["PermitAccess"],
        },
    )
    assert bad["status"] == "blocked"


EXT = {"dictionaryName": "CORP", "name": "ExternalGroups", "dataType": "STRING", "allowedValues": []}
EXT_RULE = {
    "policy_set": "wired",
    "name": "Staff",
    "conditions": ["CORP:ExternalGroups equals corp.lab/Users/staff"],
    "profiles": ["PermitAccess"],
}


def authz_mocks(mock: respx.MockRouter) -> respx.Route:
    """policy_mocks with an authorization dictionary route the test can re-program."""
    policy_mocks(mock)
    mock.get(f"{NA}/authorization-profiles").respond(json=[{"name": "PermitAccess"}])
    mock.get(f"{NA}/policy-set/s1/authorization").respond(json={"response": []})
    return mock.get(f"{NA}/dictionaries/authorization")


async def test_unknown_attribute_refetches_a_stale_dictionary(
    mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("ise_mcp.tools.policy_edit.DICT_RECHECK_AGE", 0.0)
    route = authz_mocks(mock)
    route.side_effect = [
        httpx.Response(200, json={"response": ATTRS}),
        httpx.Response(200, json={"response": [*ATTRS, EXT]}),
    ]
    async with Client(make_server(mcp_enable_writes=True)) as c:
        out = (await c.call_tool("ise_create_authz_rule", EXT_RULE)).structured_content
    assert out is not None and out["status"] == "preview", out
    assert route.call_count == 2


async def test_unknown_attribute_trusts_a_seconds_old_dictionary(mock: respx.MockRouter) -> None:
    route = authz_mocks(mock)
    route.respond(json={"response": ATTRS})
    async with Client(make_server(mcp_enable_writes=True)) as c:
        out = (await c.call_tool("ise_create_authz_rule", EXT_RULE)).structured_content
    assert out is not None and out["status"] == "blocked"
    assert "Unknown attribute CORP:ExternalGroups" in out["blockers"][0]
    assert route.call_count == 1


async def test_known_attributes_never_refetch(
    mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("ise_mcp.tools.policy_edit.DICT_RECHECK_AGE", 0.0)
    route = authz_mocks(mock)
    route.respond(json={"response": ATTRS})
    args = {**EXT_RULE, "conditions": ["Radius:NAS-Port-Type equals Wifi"]}
    async with Client(make_server(mcp_enable_writes=True)) as c:
        out = (await c.call_tool("ise_create_authz_rule", args)).structured_content
    assert out is not None and out["status"] == "blocked"
    assert "allowed: Ethernet, Virtual" in out["blockers"][0]
    assert route.call_count == 1

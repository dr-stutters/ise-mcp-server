from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from ise_mcp._core import InvalidRequest
from ise_mcp._core.formatting import MASK
from ise_mcp.tools.policy_edit import condition_node
from ise_mcp.tools.writes import masked_changes
from tests.unit.conftest import BASE, ers_page, make_server

LIB = {"wired_mab": {"id": "c1", "name": "Wired_MAB"}}


def test_condition_node() -> None:
    assert condition_node("wired_mab", LIB) == {
        "conditionType": "ConditionReference",
        "isNegate": False,
        "id": "c1",
        "name": "Wired_MAB",
    }
    node = condition_node("NOT IdentityGroup:Name equals User Identity Groups:Employee", LIB)
    assert node == {
        "conditionType": "ConditionAttributes",
        "isNegate": True,
        "dictionaryName": "IdentityGroup",
        "attributeName": "Name",
        "operator": "equals",
        "attributeValue": "User Identity Groups:Employee",
    }
    assert condition_node("Radius:NAS-Port-Type NOTEQUALS Virtual", LIB)["operator"] == "notEquals"
    with pytest.raises(InvalidRequest):
        condition_node("gibberish", LIB)


def test_masked_changes() -> None:
    cur = {"authenticationSettings": {"radiusSharedSecret": "old"}, "description": "a"}
    new = {"authenticationSettings": {"radiusSharedSecret": "new"}, "description": "b"}
    out = masked_changes(cur, new)
    assert out["authenticationSettings.radiusSharedSecret"] == {"from": "********", "to": "********"}
    assert out["description"] == {"from": "a", "to": "b"}


async def two_step(name: str, args: dict[str, Any], **settings: Any) -> tuple[Any, Any]:
    server = make_server(mcp_enable_writes=True, **settings)
    async with Client(server) as c:
        r1 = await c.call_tool(name, args)
        preview = r1.structured_content
        assert preview is not None
        if preview.get("status") != "preview":
            return preview, None
        r2 = await c.call_tool(name, {**args, "confirm": preview["confirm"]})
        return preview, r2.structured_content


async def test_create_nad_preview_and_apply(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.sw1"}).respond(json=ers_page([]))
    post = mock.post("/ers/config/networkdevice").respond(
        201, headers={"Location": f"{BASE}/ers/config/networkdevice/new-id"}
    )
    preview, applied = await two_step(
        "ise_create_nad",
        {
            "name": "sw1",
            "ips": ["10.0.0.1", "10.1.0.0/24"],
            "radius_secret": "TopSecret1",
            "snmp_ro_community": "commXYZ",
        },
    )
    assert "TopSecret1" not in json.dumps(preview) and "commXYZ" not in json.dumps(preview)
    assert preview["preview"]["authenticationSettings"]["radiusSharedSecret"] == "********"
    assert applied["result"]["id"] == "new-id"
    body = json.loads(post.calls.last.request.content)["NetworkDevice"]
    assert body["NetworkDeviceIPList"] == [
        {"ipaddress": "10.0.0.1", "mask": 32},
        {"ipaddress": "10.1.0.0", "mask": 24},
    ]
    assert body["authenticationSettings"]["radiusSharedSecret"] == "TopSecret1"
    assert body["snmpsettings"]["roCommunity"] == "commXYZ"


async def test_create_nad_blocked_when_exists(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.sw1"}).respond(
        json=ers_page([{"id": "x", "name": "sw1"}])
    )
    preview, _ = await two_step("ise_create_nad", {"name": "sw1", "ips": ["10.0.0.1"], "radius_secret": "s"})
    assert preview["status"] == "blocked"


async def test_create_nad_needs_a_secret(mock: respx.MockRouter) -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool("ise_create_nad", {"name": "sw1", "ips": ["10.0.0.1"]}, raise_on_error=False)
    assert r.is_error


async def test_update_nad_changes_only_given_fields(mock: respx.MockRouter) -> None:
    current = {
        "NetworkDevice": {
            "id": "n1",
            "name": "sw1",
            "description": "old",
            "authenticationSettings": {"radiusSharedSecret": "old-secret", "networkProtocol": "RADIUS"},
            "NetworkDeviceIPList": [{"ipaddress": "10.0.0.1", "mask": 32}],
            "link": {"href": "x"},
        }
    }
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.sw1"}).respond(
        json=ers_page([{"id": "n1", "name": "sw1"}])
    )
    mock.get("/ers/config/networkdevice/n1").respond(json=current)
    put = mock.put("/ers/config/networkdevice/n1").respond(json={"UpdatedFieldsList": {}})
    preview, applied = await two_step("ise_update_nad", {"device": "sw1", "radius_secret": "new-secret"})
    assert "new-secret" not in json.dumps(preview) and "old-secret" not in json.dumps(preview)
    assert list(preview["preview"]["changes"]) == ["authenticationSettings.radiusSharedSecret"]
    assert applied["status"] == "applied"
    body = json.loads(put.calls.last.request.content)["NetworkDevice"]
    assert body["authenticationSettings"]["radiusSharedSecret"] == "new-secret"
    assert body["description"] == "old" and "link" not in body


async def test_internal_user_password_never_echoed(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/identitygroup").respond(json=ers_page([{"id": "g1", "name": "Employee"}]))
    mock.get("/ers/config/internaluser", params={"filter": "name.EQ.bob"}).respond(json=ers_page([]))
    post = mock.post("/ers/config/internaluser").respond(
        201, headers={"Location": f"{BASE}/ers/config/internaluser/u1"}
    )
    preview, applied = await two_step(
        "ise_create_internal_user", {"name": "bob", "password": "Pa55word!x", "groups": ["employee"]}
    )
    assert "Pa55word" not in json.dumps(preview) and "Pa55word" not in json.dumps(applied)
    body = json.loads(post.calls.last.request.content)["InternalUser"]
    assert body["identityGroups"] == "g1" and body["password"] == "Pa55word!x"


async def test_unknown_group_is_an_error(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/identitygroup").respond(json=ers_page([{"id": "g1", "name": "Employee"}]))
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool(
            "ise_create_internal_user",
            {"name": "bob", "password": "x", "groups": ["Nope"]},
            raise_on_error=False,
        )
    assert r.is_error and "ise_list_identity_groups" in r.content[0].text


async def test_confirm_refused_when_target_changed(mock: respx.MockRouter) -> None:
    state = {"description": "v1"}

    def get_nad(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"NetworkDevice": {"id": "n1", "name": "sw1", **state}})

    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.sw1"}).respond(
        json=ers_page([{"id": "n1", "name": "sw1"}])
    )
    mock.get("/ers/config/networkdevice/n1").mock(side_effect=get_nad)
    put = mock.put("/ers/config/networkdevice/n1").respond(json={})
    async with Client(make_server(mcp_enable_writes=True)) as c:
        args = {"device": "sw1", "description": "mine"}
        preview = (await c.call_tool("ise_update_nad", args)).structured_content
        state["description"] = "someone else"
        r = await c.call_tool("ise_update_nad", {**args, "confirm": preview["confirm"]}, raise_on_error=False)
    assert r.is_error and "changed since the preview" in r.content[0].text
    assert not put.called


async def test_delete_profile_blocked_when_in_use(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/authorizationprofile/name/P1").respond(
        json={"AuthorizationProfile": {"id": "p1", "name": "P1"}}
    )
    mock.get("/ers/config/authorizationprofile/p1").respond(
        json={"AuthorizationProfile": {"id": "p1", "name": "P1"}}
    )
    mock.get("/api/v1/policy/network-access/policy-set").respond(
        json={"response": [{"id": "s1", "name": "Wired"}]}
    )
    mock.get("/api/v1/policy/network-access/policy-set/s1/authorization").respond(
        json={"response": [{"rule": {"name": "R1", "rank": 0}, "profile": ["P1"]}]}
    )
    mock.get("/api/v1/policy/network-access/policy-set/s1/authentication").respond(json={"response": []})
    mock.get("/api/v1/policy/network-access/policy-set/s1/exception").respond(json={"response": []})
    preview, _ = await two_step("ise_delete_object", {"kind": "authz_profile", "target": "P1"})
    assert preview["status"] == "blocked"
    assert "Wired / R1" in preview["blockers"][0]


async def test_writes_hidden_when_disabled() -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_create_nad" not in names and "ise_list_nads" in names


async def test_update_user_does_not_send_password_placeholder(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/internaluser", params={"filter": "name.EQ.bob"}).respond(
        json=ers_page([{"id": "u1", "name": "bob"}])
    )
    mock.get("/ers/config/internaluser/u1").respond(
        json={
            "InternalUser": {
                "id": "u1",
                "name": "bob",
                "enabled": True,
                "password": "*******",
                "passwordIDStore": "Internal Users",
            }
        }
    )
    put = mock.put("/ers/config/internaluser/u1").respond(json={})
    _, applied = await two_step("ise_update_internal_user", {"user": "bob", "enabled": False})
    body = json.loads(put.calls.last.request.content)["InternalUser"]
    assert "password" not in body and body["enabled"] is False
    assert applied["status"] == "applied"


async def test_set_endpoint_description_keeps_static_group(mock: respx.MockRouter) -> None:
    mac = "AA:BB:CC:00:00:01"
    mock.get("/ers/config/endpoint", params={"filter": f"mac.EQ.{mac}"}).respond(
        json=ers_page([{"id": "e1"}])
    )
    mock.get("/ers/config/endpoint/e1").respond(
        json={"ERSEndPoint": {"id": "e1", "mac": mac, "groupId": "g1", "staticGroupAssignment": True}}
    )
    put = mock.put("/ers/config/endpoint/e1").respond(json={})
    preview, _ = await two_step("ise_set_endpoint", {"mac": mac, "description": "printer"})
    assert list(preview["preview"]["changes"]) == ["description"]
    assert json.loads(put.calls.last.request.content)["ERSEndPoint"]["staticGroupAssignment"] is True


async def test_delete_sgt_in_matrix_blocked(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/sgt", params={"filter": "name.EQ.Dev"}).respond(
        json=ers_page([{"id": "s1", "name": "Dev"}])
    )
    mock.get("/ers/config/sgt/s1").respond(json={"Sgt": {"id": "s1", "name": "Dev", "value": 9}})
    mock.get("/ers/config/egressmatrixcell", params={"filter": "sgtSrcName.EQ.Dev"}).respond(
        json=ers_page([{"id": "c1"}])
    )
    mock.get("/ers/config/egressmatrixcell", params={"filter": "sgtDstName.EQ.Dev"}).respond(
        json=ers_page([])
    )
    preview, _ = await two_step("ise_delete_object", {"kind": "sgt", "target": "Dev"})
    assert preview["status"] == "blocked" and "egress matrix" in preview["blockers"][0]


def test_masked_changes_replace_flags_removed_secret() -> None:
    cur = {"tacacsSettings": {"sharedSecret": "s"}, "description": "a"}
    out = masked_changes(cur, {"tacacsSettings": {}, "description": "a"}, replace=True)
    assert out == {"tacacsSettings.sharedSecret": {"from": MASK, "to": None, "removed": True}}
    dropped = masked_changes(cur, {"description": "a"}, replace=True)["tacacsSettings"]
    assert dropped == {"from": {"sharedSecret": MASK}, "to": None, "removed": True}


async def test_update_authz_profile_preview_shows_removed_dacl(mock: respx.MockRouter) -> None:
    """Core 0.12.4 replace=True: dacl='' drops daclName from the ERS PUT; the preview must say so."""
    profile = {"id": "p1", "name": "P1", "accessType": "ACCESS_ACCEPT", "daclName": "PERMIT_ALL_IPV4_TRAFFIC"}
    mock.get("/ers/config/authorizationprofile/name/P1").respond(json={"AuthorizationProfile": profile})
    mock.get("/ers/config/authorizationprofile/p1").respond(json={"AuthorizationProfile": profile})
    mock.get("/api/v1/policy/network-access/policy-set").respond(json={"response": []})
    put = mock.put("/ers/config/authorizationprofile/p1").respond(json={})
    preview, _ = await two_step("ise_update_authz_profile", {"profile": "P1", "dacl": ""})
    assert preview["preview"]["changes"] == {
        "daclName": {"from": "PERMIT_ALL_IPV4_TRAFFIC", "to": None, "removed": True}
    }
    assert "daclName" not in json.loads(put.calls.last.request.content)["AuthorizationProfile"]


async def test_update_user_preview_does_not_list_kept_password(mock: respx.MockRouter) -> None:
    """The password placeholder is left out of the PUT but ISE keeps the password: not a removal."""
    mock.get("/ers/config/internaluser", params={"filter": "name.EQ.bob"}).respond(
        json=ers_page([{"id": "u1", "name": "bob"}])
    )
    user = {
        "id": "u1",
        "name": "bob",
        "enabled": True,
        "password": "*******",
        "passwordIDStore": "Internal Users",
    }
    mock.get("/ers/config/internaluser/u1").respond(json={"InternalUser": user})
    async with Client(make_server(mcp_enable_writes=True)) as c:
        preview = (
            await c.call_tool("ise_update_internal_user", {"user": "bob", "enabled": False})
        ).structured_content
    assert preview["preview"]["changes"] == {"enabled": {"from": True, "to": False}}

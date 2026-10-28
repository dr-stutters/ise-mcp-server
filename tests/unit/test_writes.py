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
from tests.unit.conftest import BASE, ers_page, fixture_json, make_server, mock_no_policy

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
    mock_no_policy(mock, own_sets=("network-access",))
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
    mock_no_policy(mock)
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


async def test_create_authz_profile_av_pairs(mock: respx.MockRouter) -> None:
    """Advanced attributes, e.g. the Catalyst Center admin role (catc D89): ERS's misspelled keys."""
    mock.get("/ers/config/authorizationprofile/name/mcp-catc-observer").respond(404)
    mock.get("/ers/config/authorizationprofile", params={"filter": "name.EQ.mcp-catc-observer"}).respond(
        json=ers_page([])
    )
    post = mock.post("/ers/config/authorizationprofile").respond(
        201, headers={"Location": f"{BASE}/ers/config/authorizationprofile/new-id"}
    )
    mock.get("/api/v1/policy/network-access/dictionaries").respond(json={"response": [{"name": "Cisco"}]})
    mock.get("/api/v1/policy/network-access/dictionaries/Cisco/attribute").respond(
        json={"response": [{"name": "cisco-av-pair", "directionType": "BOTH", "dictionaryName": "Cisco"}]}
    )
    args = {"name": "mcp-catc-observer", "av_pairs": ["Cisco:cisco-av-pair=Role=OBSERVER-ROLE"]}
    preview, done = await two_step("ise_create_authz_profile", args)
    assert preview["status"] == "preview" and done["status"] == "applied"
    sent = json.loads(post.calls.last.request.content)["AuthorizationProfile"]
    assert sent["advancedAttributes"] == [
        {
            "leftHandSideDictionaryAttribue": {
                "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
                "dictionaryName": "Cisco",
                "attributeName": "cisco-av-pair",
            },
            "rightHandSideAttribueValue": {
                "AdvancedAttributeValueType": "AttributeValue",
                "value": "Role=OBSERVER-ROLE",
            },
        }
    ]
    assert sent["accessType"] == "ACCESS_ACCEPT"


async def test_create_authz_profile_bad_av_pair(mock: respx.MockRouter) -> None:
    server = make_server(mcp_enable_writes=True)
    async with Client(server) as c:
        res = await c.call_tool(
            "ise_create_authz_profile",
            {"name": "x", "av_pairs": ["cisco-av-pair=Role=X"]},
            raise_on_error=False,
        )
    assert res.is_error and "Dictionary:attribute=value" in res.content[0].text  # type: ignore[union-attr]


# --- ise_update_nad remove_radius / remove_tacacs (I84) ----------------------------------------


def mock_dual_nad(mock: respx.MockRouter, *, keep_on_put: str | None = None) -> tuple[dict[str, Any], Any]:
    """The recorded NAD (RADIUS + TACACS+). A PUT replaces what GET returns next, unless keep_on_put names
    a settings object ISE keeps anyway (to test the read-back)."""
    nad = fixture_json("ers_networkdevice.json")["NetworkDevice"]
    nad_id, name = nad["id"], nad["name"]
    state: dict[str, Any] = {"nad": nad}

    def put(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)["NetworkDevice"]
        if keep_on_put:
            sent[keep_on_put] = state["nad"][keep_on_put]
        state["nad"] = {**sent, "link": nad["link"]}
        return httpx.Response(200, json={"UpdatedFieldsList": {}})

    mock.get("/ers/config/networkdevice", params={"filter": f"name.EQ.{name}"}).respond(
        json=ers_page([{"id": nad_id, "name": name}])
    )
    mock.get(f"/ers/config/networkdevice/{nad_id}").mock(
        side_effect=lambda _r: httpx.Response(200, json={"NetworkDevice": state["nad"]})
    )
    route = mock.put(f"/ers/config/networkdevice/{nad_id}").mock(side_effect=put)
    return nad, route


async def test_update_nad_remove_radius_keeps_tacacs(mock: respx.MockRouter) -> None:
    nad, put = mock_dual_nad(mock)
    original_tacacs = json.dumps(nad["tacacsSettings"], sort_keys=True)
    preview, applied = await two_step("ise_update_nad", {"device": nad["name"], "remove_radius": True})
    assert preview["status"] == "preview"
    assert preview["preview"]["removed"] == ["RADIUS removed (secret was set)"]
    assert any("11007" in s and "192.0.2.50/32" in s for s in preview["side_effects"])
    change = preview["preview"]["changes"]["authenticationSettings"]
    assert change["removed"] is True and change["to"] is None
    assert "REDACTED" not in json.dumps(preview)  # the stored keys never show
    assert applied["status"] == "applied"
    body = json.loads(put.calls.last.request.content)["NetworkDevice"]
    assert "authenticationSettings" not in body
    assert json.dumps(body["tacacsSettings"], sort_keys=True) == original_tacacs
    assert body["snmpsettings"] == nad["snmpsettings"] and "link" not in body


async def test_update_nad_remove_tacacs_keeps_radius(mock: respx.MockRouter) -> None:
    nad, put = mock_dual_nad(mock)
    preview, applied = await two_step("ise_update_nad", {"device": nad["name"], "remove_tacacs": True})
    assert preview["preview"]["removed"] == ["TACACS+ removed (secret was set)"]
    assert any("TACACS+" in s and "local login" in s for s in preview["side_effects"])
    assert applied["status"] == "applied"
    body = json.loads(put.calls.last.request.content)["NetworkDevice"]
    assert "tacacsSettings" not in body
    assert body["authenticationSettings"] == nad["authenticationSettings"]


async def test_update_nad_remove_last_protocol_blocked(mock: respx.MockRouter) -> None:
    nad, put = mock_dual_nad(mock)
    preview, _ = await two_step(
        "ise_update_nad", {"device": nad["name"], "remove_radius": True, "remove_tacacs": True}
    )
    assert preview["status"] == "blocked"
    assert any("ise_delete_nad" in b for b in preview["blockers"])
    assert not put.called


async def test_update_nad_remove_only_protocol_blocked(mock: respx.MockRouter) -> None:
    nad, put = mock_dual_nad(mock)
    del nad["tacacsSettings"]  # a RADIUS-only device
    preview, _ = await two_step("ise_update_nad", {"device": nad["name"], "remove_radius": True})
    assert preview["status"] == "blocked"
    assert any("neither RADIUS nor TACACS+" in b and "ise_delete_nad" in b for b in preview["blockers"])
    assert not put.called


async def test_update_nad_switch_protocol_allowed(mock: respx.MockRouter) -> None:
    nad, put = mock_dual_nad(mock)
    del nad["tacacsSettings"]
    preview, applied = await two_step(
        "ise_update_nad", {"device": nad["name"], "remove_radius": True, "tacacs_secret": "NewTac1"}
    )
    assert preview["status"] == "preview" and "NewTac1" not in json.dumps(preview)
    body = json.loads(put.calls.last.request.content)["NetworkDevice"]
    assert "authenticationSettings" not in body and body["tacacsSettings"]["sharedSecret"] == "NewTac1"


@pytest.mark.parametrize(
    ("flag", "secret_arg"), [("remove_radius", "radius_secret"), ("remove_tacacs", "tacacs_secret")]
)
async def test_update_nad_remove_with_secret_blocked(
    mock: respx.MockRouter, flag: str, secret_arg: str
) -> None:
    nad, put = mock_dual_nad(mock)
    preview, _ = await two_step("ise_update_nad", {"device": nad["name"], flag: True, secret_arg: "s3cret"})
    assert preview["status"] == "blocked"
    assert any(flag in b and secret_arg in b for b in preview["blockers"])
    assert "s3cret" not in json.dumps(preview)
    assert not put.called


async def test_update_nad_remove_missing_protocol_blocked(mock: respx.MockRouter) -> None:
    nad, put = mock_dual_nad(mock)
    del nad["tacacsSettings"]
    preview, _ = await two_step("ise_update_nad", {"device": nad["name"], "remove_tacacs": True})
    assert preview["status"] == "blocked"
    assert any("no TACACS+ shared secret" in b for b in preview["blockers"])


async def test_update_nad_remove_reports_when_ise_keeps_it(mock: respx.MockRouter) -> None:
    nad, put = mock_dual_nad(mock, keep_on_put="authenticationSettings")
    server = make_server(mcp_enable_writes=True)
    async with Client(server) as c:
        args = {"device": nad["name"], "remove_radius": True}
        preview = (await c.call_tool("ise_update_nad", args)).structured_content
        r = await c.call_tool("ise_update_nad", {**args, "confirm": preview["confirm"]}, raise_on_error=False)
    assert put.called
    assert r.is_error and "still has RADIUS" in r.content[0].text

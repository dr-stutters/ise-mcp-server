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


# --- I73: internal user lifecycle fields and bulk -------------------------------------------------

USER_GET = {
    "id": "u1",
    "name": "bob",
    "description": "",
    "enabled": True,
    "email": "",
    "accountNameAlias": "",
    "password": "*******",
    "firstName": "",
    "lastName": "",
    "changePassword": False,
    "identityGroups": "g1",
    "passwordNeverExpires": False,
    "daysForPasswordExpiration": 60,
    "expiryDateEnabled": False,
    "expiryDate": "",
    "dateModified": "2026-10-21",
    "dateCreated": "2026-10-21",
    "customAttributes": {},
    "passwordIDStore": "Internal Users",
    "link": {"rel": "self", "href": f"{BASE}/ers/config/internaluser/u1"},
}


def mock_user(mock: respx.MockRouter, user: dict[str, Any] | None = None) -> None:
    u = user or USER_GET
    mock.get("/ers/config/internaluser", params={"filter": f"name.EQ.{u['name']}"}).respond(
        json=ers_page([{"id": u["id"], "name": u["name"]}])
    )
    mock.get(f"/ers/config/internaluser/{u['id']}").respond(json={"InternalUser": u})


async def test_create_user_lifecycle_fields(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/identitygroup").respond(json=ers_page([{"id": "g1", "name": "Contractors"}]))
    mock.get("/ers/config/internaluser", params={"filter": "name.EQ.carol"}).respond(json=ers_page([]))
    post = mock.post("/ers/config/internaluser").respond(
        201, headers={"Location": f"{BASE}/ers/config/internaluser/u9"}
    )
    preview, applied = await two_step(
        "ise_create_internal_user",
        {
            "name": "carol",
            "password": "Pa55word!x",
            "enable_password": "En4ble!secret",
            "groups": ["contractors"],
            "expiry_date": "2099-01-31",
            "change_password_on_login": True,
            "password_never_expires": False,
            "custom_attributes": {"costCentre": "4711"},
            "account_name_alias": "carol@example.com",
        },
    )
    text = json.dumps(preview) + json.dumps(applied)
    assert "Pa55word" not in text and "En4ble" not in text
    shown = preview["preview"]
    assert shown["credentials_set"] == ["password", "enable"]
    assert shown["expiryDate"] == "2099-01-31" and shown["changePassword"] is True
    assert shown["passwordNeverExpires"] is False  # a flag, not masked
    body = json.loads(post.calls.last.request.content)["InternalUser"]
    assert body["password"] == "Pa55word!x" and body["enablePassword"] == "En4ble!secret"
    assert body["expiryDateEnabled"] is True and body["expiryDate"] == "2099-01-31"
    assert body["changePassword"] is True and body["passwordNeverExpires"] is False
    assert body["customAttributes"] == {"costCentre": "4711"}
    assert body["accountNameAlias"] == "carol@example.com" and body["identityGroups"] == "g1"
    assert applied["result"]["id"] == "u9"


async def test_create_user_bad_or_past_expiry(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/internaluser", params={"filter": "name.EQ.carol"}).respond(json=ers_page([]))
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool(
            "ise_create_internal_user",
            {"name": "carol", "password": "x", "expiry_date": "31/01/2099"},
            raise_on_error=False,
        )
        assert r.is_error and "YYYY-MM-DD" in r.content[0].text
        past = (
            await c.call_tool(
                "ise_create_internal_user", {"name": "carol", "password": "x", "expiry_date": "2001-01-01"}
            )
        ).structured_content
    assert past["status"] == "blocked" and "in the past" in past["blockers"][0]


async def test_create_ad_backed_user_needs_no_password(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/activedirectory").respond(json=ers_page([{"id": "j1", "name": "CORP-AD"}]))
    mock.get("/ers/config/ldap").respond(404)
    mock.get("/ers/config/internaluser", params={"filter": "name.EQ.dave"}).respond(json=ers_page([]))
    post = mock.post("/ers/config/internaluser").respond(
        201, headers={"Location": f"{BASE}/ers/config/internaluser/u2"}
    )
    preview, _ = await two_step("ise_create_internal_user", {"name": "dave", "password_store": "corp-ad"})
    assert preview["preview"]["passwordIDStore"] == "CORP-AD"
    body = json.loads(post.calls.last.request.content)["InternalUser"]
    assert body["passwordIDStore"] == "CORP-AD" and "password" not in body


async def test_create_user_store_checks(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/activedirectory").respond(json=ers_page([{"id": "j1", "name": "CORP-AD"}]))
    mock.get("/ers/config/ldap").respond(json=ers_page([]))
    mock.get("/ers/config/internaluser", params={"filter": "name.EQ.dave"}).respond(json=ers_page([]))
    async with Client(make_server(mcp_enable_writes=True)) as c:
        nopw = (await c.call_tool("ise_create_internal_user", {"name": "dave"})).structured_content
        assert nopw["status"] == "blocked" and "password is required" in nopw["blockers"][0]
        ad = (
            await c.call_tool(
                "ise_create_internal_user",
                {"name": "dave", "password_store": "CORP-AD", "change_password_on_login": True},
            )
        ).structured_content
        assert ad["status"] == "blocked" and "Internal Users' password" in ad["blockers"][0]
        r = await c.call_tool(
            "ise_create_internal_user", {"name": "dave", "password_store": "Nope"}, raise_on_error=False
        )
    assert r.is_error and "ise_list_identity_sources" in r.content[0].text


async def test_update_user_sets_enable_password_masked(mock: respx.MockRouter) -> None:
    mock_user(mock)
    put = mock.put("/ers/config/internaluser/u1").respond(json={})
    preview, applied = await two_step(
        "ise_update_internal_user", {"user": "bob", "enable_password": "En4ble!secret"}
    )
    assert "En4ble" not in json.dumps(preview) and "En4ble" not in json.dumps(applied)
    assert preview["preview"]["changes"] == {"enablePassword": {"from": None, "to": MASK}}
    body = json.loads(put.calls.last.request.content)["InternalUser"]
    assert body["enablePassword"] == "En4ble!secret"
    assert "password" not in body and "passwordIDStore" not in body  # stored password kept
    assert applied["status"] == "applied"


async def test_update_user_password_does_not_send_enable_placeholder(mock: respx.MockRouter) -> None:
    mock_user(mock, {**USER_GET, "enablePassword": "*******"})
    put = mock.put("/ers/config/internaluser/u1").respond(json={})
    await two_step("ise_update_internal_user", {"user": "bob", "password": "N3wPass!word"})
    body = json.loads(put.calls.last.request.content)["InternalUser"]
    assert body["password"] == "N3wPass!word" and "enablePassword" not in body
    assert body["passwordIDStore"] == "Internal Users"


async def test_update_user_expiry_and_flags(mock: respx.MockRouter) -> None:
    mock_user(mock, {**USER_GET, "expiryDateEnabled": True, "expiryDate": "2099-01-31"})
    put = mock.put("/ers/config/internaluser/u1").respond(json={})
    preview, _ = await two_step(
        "ise_update_internal_user",
        {
            "user": "bob",
            "expiry_date": "never",
            "change_password_on_login": True,
            "password_never_expires": True,
            "custom_attributes": {"costCentre": "42"},
        },
    )
    changes = preview["preview"]["changes"]
    assert changes["expiryDateEnabled"] == {"from": True, "to": False}
    assert changes["changePassword"] == {"from": False, "to": True}
    assert changes["passwordNeverExpires"] == {"from": False, "to": True}
    assert "customAttributes.costCentre" in changes
    body = json.loads(put.calls.last.request.content)["InternalUser"]
    assert body["expiryDateEnabled"] is False and body["expiryDate"] == ""
    assert body["passwordNeverExpires"] is True and body["customAttributes"] == {"costCentre": "42"}


async def test_update_user_past_expiry_is_a_side_effect(mock: respx.MockRouter) -> None:
    mock_user(mock)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        preview = (
            await c.call_tool("ise_update_internal_user", {"user": "bob", "expiry_date": "2001-01-01"})
        ).structured_content
    assert preview["status"] == "preview"
    assert any("expired from now on" in s for s in preview["side_effects"])


def _bulk_users(n: int, **extra: Any) -> list[dict[str, Any]]:
    return [{"name": f"mcp-test-u{i}", **extra} for i in range(n)]


async def test_bulk_create_users_one_preview_partial_failure(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/identitygroup").respond(json=ers_page([{"id": "g1", "name": "Contractors"}]))
    for i in range(7):
        found = [{"id": "x", "name": "mcp-test-u6"}] if i == 6 else []
        mock.get("/ers/config/internaluser", params={"filter": f"name.EQ.mcp-test-u{i}"}).respond(
            json=ers_page(found)
        )

    def post(request: httpx.Request) -> httpx.Response:
        name = json.loads(request.content)["InternalUser"]["name"]
        if name == "mcp-test-u3":
            return httpx.Response(
                400,
                json={"ERSResponse": {"messages": [{"title": "Password Pa55word!x fails the policy"}]}},
            )
        return httpx.Response(201, headers={"Location": f"{BASE}/ers/config/internaluser/{name}-id"})

    route = mock.post("/ers/config/internaluser").mock(side_effect=post)
    users = _bulk_users(
        7, password="Pa55word!x", groups=["Contractors"], expiry_date="2099-01-31", enable_password="En4ble!x"
    )
    preview, applied = await two_step("ise_bulk_internal_users", {"action": "create", "users": users})
    assert "Pa55word" not in json.dumps(preview) and "En4ble" not in json.dumps(preview)
    details = preview["preview"]
    assert details["users_in_run"] == 6 and len(details["sample"]) == 5
    assert details["left_out_conflicts"]["names"] == ["mcp-test-u6"]
    assert details["sample"][0]["credentials_set"] == ["password", "enable"]
    assert route.call_count == 6  # one ERS call per user, the conflict left out
    assert applied["result"]["succeeded"] == 5 and applied["result"]["failed"] == 1
    failed = [r for r in applied["result"]["results"] if r["status"] == "failed"]
    assert failed[0]["name"] == "mcp-test-u3" and "Pa55word" not in json.dumps(applied)


async def test_bulk_create_users_problems_block(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/identitygroup").respond(json=ers_page([{"id": "g1", "name": "Contractors"}]))
    mock.get("/ers/config/internaluser").respond(json=ers_page([]))
    users = [
        {"name": "a", "password": "x", "groups": ["Nope"]},
        {"name": "b", "password": "x", "expiry_date": "tomorrow"},
        {"name": "c"},
        {"name": "c", "password": "y"},
    ]
    preview, _ = await two_step("ise_bulk_internal_users", {"action": "create", "users": users})
    assert preview["status"] == "blocked"
    text = " ".join(preview["blockers"])
    assert "more than once" in text and "a: No identity group" in text
    assert "b: expiry_date" in text and "c: a password is required" in text


async def test_bulk_users_max_items(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/internaluser").respond(json=ers_page([]))
    preview, _ = await two_step(
        "ise_bulk_internal_users",
        {"action": "create", "users": _bulk_users(3, password="x"), "max_items": 2},
    )
    assert preview["status"] == "blocked" and "max_items=2" in preview["blockers"][0]


async def test_bulk_update_users_diff_and_unchanged(mock: respx.MockRouter) -> None:
    mock_user(mock)
    mock_user(
        mock, {**USER_GET, "id": "u2", "name": "eve", "expiryDateEnabled": True, "expiryDate": "2099-01-31"}
    )
    mock.get("/ers/config/internaluser", params={"filter": "name.EQ.ghost"}).respond(json=ers_page([]))
    put1 = mock.put("/ers/config/internaluser/u1").respond(json={})
    put2 = mock.put("/ers/config/internaluser/u2").respond(json={})
    users = [
        {"name": "bob", "expiry_date": "2099-01-31"},
        {"name": "eve", "expiry_date": "2099-01-31"},
        {"name": "ghost", "enabled": False},
    ]
    preview, applied = await two_step("ise_bulk_internal_users", {"action": "update", "users": users})
    details = preview["preview"]
    assert details["users_in_run"] == 1 and details["left_out_unchanged"] == ["eve"]
    assert details["left_out_conflicts"]["names"] == ["ghost"]
    assert details["sample"][0]["changes"]["expiryDate"] == {"from": "", "to": "2099-01-31"}
    assert put1.called and not put2.called
    body = json.loads(put1.calls.last.request.content)["InternalUser"]
    assert "password" not in body and "link" not in body
    assert applied["result"]["results"] == [{"name": "bob", "status": "updated"}]


async def test_bulk_delete_users(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/internaluser", params={"filter": "name.EQ.mcp-test-u0"}).respond(
        json=ers_page([{"id": "d0", "name": "mcp-test-u0"}])
    )
    mock.get("/ers/config/internaluser", params={"filter": "name.EQ.mcp-test-u1"}).respond(
        json=ers_page([{"id": "d1", "name": "mcp-test-u1"}])
    )
    d0 = mock.delete("/ers/config/internaluser/d0").respond(204)
    d1 = mock.delete("/ers/config/internaluser/d1").respond(404, json={"ERSResponse": {}})
    preview, applied = await two_step(
        "ise_bulk_internal_users", {"action": "delete", "users": _bulk_users(2)}
    )
    assert preview["preview"]["users_in_run"] == 2 and preview["blast_radius"] == 2
    assert d0.called and d1.called
    result = applied["result"]
    assert result["succeeded"] == 1 and result["failed"] == 1

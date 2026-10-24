"""I80: vendor attributes (av_pairs) checked against ISE's dictionaries, the Catalyst SD-WAN user group
(Viptela-Group-Name) in authorization profiles and viptela-group-name in TACACS+ shell profiles.

Dictionary fixtures are recorded from ISE 3.5 (2026-10-24): it ships no Viptela dictionary."""

from __future__ import annotations

import json
from typing import Any

import respx
from fastmcp import Client

from tests.unit.conftest import BASE, ers_page, fixture_text, make_server
from tests.unit.test_device_admin import fake_ers
from tests.unit.test_writes import two_step

DICTS = "/api/v1/policy/network-access/dictionaries"
DICTIONARIES = json.loads(fixture_text("ise35_network_access_dictionaries.json"))
AIRESPACE = json.loads(fixture_text("ise35_dictionary_airespace_attributes.json"))
CISCO = {
    "response": [
        {"name": "cisco-av-pair", "directionType": "BOTH", "dataType": "STRING", "dictionaryName": "Cisco"}
    ]
}
VIPTELA = {
    "response": [
        {
            "name": "Viptela-Group-Name",
            "directionType": "OUT",
            "dataType": "STRING",
            "dictionaryName": "Viptela",
            "allowedValues": [],
        }
    ]
}


def with_viptela() -> dict[str, Any]:
    entry = {"name": "Viptela", "description": "Dictionary for Vendor Viptela", "version": "0"}
    return {**DICTIONARIES, "response": [*DICTIONARIES["response"], entry]}


def adv(dictionary: str, attribute: str, value: str) -> dict[str, Any]:
    return {
        "leftHandSideDictionaryAttribue": {
            "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
            "dictionaryName": dictionary,
            "attributeName": attribute,
        },
        "rightHandSideAttribueValue": {"AdvancedAttributeValueType": "AttributeValue", "value": value},
    }


def new_profile(mock: respx.MockRouter, name: str) -> respx.Route:
    mock.get(f"/ers/config/authorizationprofile/name/{name}").respond(404)
    mock.get("/ers/config/authorizationprofile", params={"filter": f"name.EQ.{name}"}).respond(
        json=ers_page([])
    )
    return mock.post("/ers/config/authorizationprofile").respond(
        201, headers={"Location": f"{BASE}/ers/config/authorizationprofile/new-id"}
    )


def existing_profile(mock: respx.MockRouter, profile: dict[str, Any]) -> respx.Route:
    name, pid = profile["name"], profile["id"]
    mock.get(f"/ers/config/authorizationprofile/name/{name}").respond(json={"AuthorizationProfile": profile})
    mock.get(f"/ers/config/authorizationprofile/{pid}").respond(json={"AuthorizationProfile": profile})
    mock.get("/api/v1/policy/network-access/policy-set").respond(json={"response": []})
    return mock.put(f"/ers/config/authorizationprofile/{pid}").respond(json={})


# --- authorization profiles ----------------------------------------------------------------------


async def test_sdwan_group_blocked_without_viptela_dictionary(mock: respx.MockRouter) -> None:
    """ISE 3.5 as shipped: the preview is blocked and names the one-time GUI step."""
    post = new_profile(mock, "sdwan-netadmin")
    mock.get(DICTS).respond(json=DICTIONARIES)
    preview, done = await two_step(
        "ise_create_authz_profile", {"name": "sdwan-netadmin", "sdwan_group": "netadmin"}
    )
    assert preview["status"] == "blocked" and done is None
    (blocker,) = preview["blockers"]
    assert "RADIUS Vendors" in blocker and "41916" in blocker and "Viptela-Group-Name" in blocker
    assert not post.called


async def test_sdwan_group_created_when_dictionary_exists(mock: respx.MockRouter) -> None:
    post = new_profile(mock, "sdwan-netadmin")
    mock.get(DICTS).respond(json=with_viptela())
    mock.get(f"{DICTS}/Viptela/attribute").respond(json=VIPTELA)
    mock.get(f"{DICTS}/Cisco/attribute").respond(json=CISCO)
    args = {
        "name": "sdwan-netadmin",
        "sdwan_group": "netadmin",
        # an explicit Viptela-Group-Name in av_pairs is replaced by sdwan_group, not duplicated
        "av_pairs": ["cisco:Cisco-AV-Pair=shell:priv-lvl=15", "viptela:viptela-group-name=basic"],
    }
    preview, done = await two_step("ise_create_authz_profile", args)
    assert preview["status"] == "preview" and done["status"] == "applied"
    sent = json.loads(post.calls.last.request.content)["AuthorizationProfile"]
    # dictionary and attribute names are canonicalised to ISE's spelling
    assert sent["advancedAttributes"] == [
        adv("Cisco", "cisco-av-pair", "shell:priv-lvl=15"),
        adv("Viptela", "Viptela-Group-Name", "netadmin"),
    ]


async def test_viptela_attribute_missing_from_dictionary(mock: respx.MockRouter) -> None:
    new_profile(mock, "p")
    mock.get(DICTS).respond(json=with_viptela())
    mock.get(f"{DICTS}/Viptela/attribute").respond(json={"response": []})
    preview, _ = await two_step("ise_create_authz_profile", {"name": "p", "sdwan_group": "operator"})
    assert preview["status"] == "blocked"
    assert "no attribute 'Viptela-Group-Name'" in preview["blockers"][0]
    assert "ID 1" in preview["blockers"][0]


async def test_av_pairs_allowed_values_and_unknown_names(mock: respx.MockRouter) -> None:
    new_profile(mock, "p")
    mock.get(DICTS).respond(json=DICTIONARIES)
    mock.get(f"{DICTS}/Airespace/attribute").respond(json=AIRESPACE)
    args = {
        "name": "p",
        "av_pairs": [
            "Airespace:Airespace-QOS-Level=Diamond",
            "Airespace:Airespace-ACL-Nme=GUEST",
            "Aruba-X:Aruba-User-Role=guest",
        ],
    }
    preview, _ = await two_step("ise_create_authz_profile", args)
    assert preview["status"] == "blocked"
    qos, acl, aruba = preview["blockers"]
    assert "Silver, Gold, Platinum, Bronze" in qos and "'Diamond'" in qos
    assert "Did you mean Airespace-ACL-Name" in acl
    assert "no dictionary 'Aruba-X'" in aruba and "Aruba" in aruba


async def test_av_pairs_allowed_value_canonicalised(mock: respx.MockRouter) -> None:
    post = new_profile(mock, "p")
    mock.get(DICTS).respond(json=DICTIONARIES)
    mock.get(f"{DICTS}/Airespace/attribute").respond(json=AIRESPACE)
    _, done = await two_step(
        "ise_create_authz_profile", {"name": "p", "av_pairs": ["Airespace:Airespace-QOS-Level=gold"]}
    )
    assert done["status"] == "applied"
    sent = json.loads(post.calls.last.request.content)["AuthorizationProfile"]
    assert sent["advancedAttributes"] == [adv("Airespace", "Airespace-QOS-Level", "Gold")]


async def test_in_only_attribute_blocked(mock: respx.MockRouter) -> None:
    new_profile(mock, "p")
    mock.get(DICTS).respond(json=DICTIONARIES)
    in_only = {"response": [{"name": "NAS-Port-Type", "directionType": "IN", "dictionaryName": "Radius"}]}
    mock.get(f"{DICTS}/Radius/attribute").respond(json=in_only)
    preview, _ = await two_step(
        "ise_create_authz_profile", {"name": "p", "av_pairs": ["Radius:NAS-Port-Type=Virtual"]}
    )
    assert preview["status"] == "blocked" and "IN attribute" in preview["blockers"][0]


async def test_av_pairs_unchecked_when_openapi_down(mock: respx.MockRouter) -> None:
    """OpenAPI off (ERS only): nothing is blocked, the preview says ISE checks on apply."""
    post = new_profile(mock, "p")
    mock.get(DICTS).respond(503)
    preview, done = await two_step(
        "ise_create_authz_profile", {"name": "p", "sdwan_group": "netadmin"}, retries=0
    )
    assert preview["status"] == "preview"
    assert any("not checked" in s for s in preview["side_effects"])
    assert done["status"] == "applied" and post.called


async def test_bad_sdwan_group_name() -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        res = await c.call_tool(
            "ise_create_authz_profile", {"name": "p", "sdwan_group": "net admin"}, raise_on_error=False
        )
    assert res.is_error and "Catalyst SD-WAN user group" in res.content[0].text  # type: ignore[union-attr]


async def test_update_sdwan_group_keeps_other_attributes(mock: respx.MockRouter) -> None:
    profile = {
        "id": "p1",
        "name": "sdwan-admins",
        "accessType": "ACCESS_ACCEPT",
        "advancedAttributes": [
            adv("Cisco", "cisco-av-pair", "shell:priv-lvl=15"),
            adv("Viptela", "Viptela-Group-Name", "basic"),
        ],
    }
    put = existing_profile(mock, profile)
    mock.get(DICTS).respond(json=with_viptela())
    viptela = mock.get(f"{DICTS}/Viptela/attribute").respond(json=VIPTELA)
    cisco = mock.get(f"{DICTS}/Cisco/attribute").respond(json=CISCO)
    preview, done = await two_step(
        "ise_update_authz_profile", {"profile": "sdwan-admins", "sdwan_group": "netadmin"}
    )
    assert preview["status"] == "preview" and done["status"] == "applied"
    assert "advancedAttributes" in preview["preview"]["changes"]
    sent = json.loads(put.calls.last.request.content)["AuthorizationProfile"]
    assert sent["advancedAttributes"] == [
        adv("Cisco", "cisco-av-pair", "shell:priv-lvl=15"),
        adv("Viptela", "Viptela-Group-Name", "netadmin"),
    ]
    # only the new entry is checked; the profile's existing attributes are ISE's own
    assert viptela.called and not cisco.called


async def test_update_remove_sdwan_group_and_clear_av_pairs(mock: respx.MockRouter) -> None:
    profile = {
        "id": "p1",
        "name": "sdwan-admins",
        "accessType": "ACCESS_ACCEPT",
        "advancedAttributes": [
            adv("Cisco", "cisco-av-pair", "shell:priv-lvl=15"),
            adv("Viptela", "Viptela-Group-Name", "basic"),
        ],
    }
    put = existing_profile(mock, profile)
    dicts = mock.get(DICTS).respond(json=DICTIONARIES)
    _, done = await two_step("ise_update_authz_profile", {"profile": "sdwan-admins", "sdwan_group": ""})
    assert done["status"] == "applied" and not dicts.called
    sent = json.loads(put.calls.last.request.content)["AuthorizationProfile"]
    assert sent["advancedAttributes"] == [adv("Cisco", "cisco-av-pair", "shell:priv-lvl=15")]

    preview, done = await two_step("ise_update_authz_profile", {"profile": "sdwan-admins", "av_pairs": []})
    assert preview["preview"]["changes"]["advancedAttributes"]["removed"] is True
    assert "advancedAttributes" not in json.loads(put.calls.last.request.content)["AuthorizationProfile"]


async def test_get_authz_profile_shows_av_pairs(mock: respx.MockRouter) -> None:
    profile = {
        "id": "p1",
        "name": "sdwan-admins",
        "accessType": "ACCESS_ACCEPT",
        "advancedAttributes": [adv("Viptela", "Viptela-Group-Name", "netadmin")],
    }
    existing_profile(mock, profile)
    async with Client(make_server()) as c:
        out = (await c.call_tool("ise_get_authz_profile", {"profile": "sdwan-admins"})).structured_content
    assert out is not None and out["av_pairs"] == ["Viptela:Viptela-Group-Name=netadmin"]


# --- TACACS+ shell profiles ------------------------------------------------------------------------


async def test_shell_profile_sdwan_group(mock: respx.MockRouter) -> None:
    fake_ers(mock, {"tacacsprofile": []})
    post = mock.post("/ers/config/tacacsprofile").respond(
        201, headers={"Location": f"{BASE}/ers/config/tacacsprofile/new-id"}
    )
    preview, done = await two_step(
        "ise_set_shell_profile", {"name": "SDWAN_netadmin", "sdwan_group": "netadmin"}
    )
    assert preview["preview"]["attributes"] == {"viptela-group-name": "netadmin"}
    assert done["status"] == "applied"
    sent = json.loads(post.calls.last.request.content)["TacacsProfile"]
    assert sent["sessionAttributes"]["sessionAttributeList"] == [
        {"type": "MANDATORY", "name": "viptela-group-name", "value": "netadmin"}
    ]


async def test_shell_profile_sdwan_group_clash() -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        res = await c.call_tool(
            "ise_set_shell_profile",
            {"name": "x", "sdwan_group": "netadmin", "attributes": {"Viptela-Group-Name": "basic"}},
            raise_on_error=False,
        )
    assert res.is_error and "viptela-group-name" in res.content[0].text  # type: ignore[union-attr]

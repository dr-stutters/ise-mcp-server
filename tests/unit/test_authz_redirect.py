"""I85: web redirection and common tasks on ise_create_authz_profile / ise_update_authz_profile, and their
round trip through ise_export_config / ise_import_config. Bodies follow the ERS 3.5
ers.authorizationprofile model (webRedirection: WebRedirectionType, acl, portalName,
staticIPHostNameFQDN, displayCertificatesRenewalMessages)."""

from __future__ import annotations

import copy
import json
from typing import Any

import respx
from fastmcp import Client

from ise_mcp.client import IseApp
from tests.unit.conftest import BASE, ers_page, make_server, make_settings
from tests.unit.test_config_export import _uuid, lab_objects, serve
from tests.unit.test_config_import import export_of, router
from tests.unit.test_writes import two_step

PORTALS = {
    "sponsoredguestportal": ["Sponsored Guest Portal (default)"],
    "selfregportal": ["Self-Registered Guest Portal (default)"],
    "hotspotportal": ["Hotspot Guest Portal (default)"],
    "byodportal": ["BYOD Portal (default)"],
    "sponsorportal": ["Sponsor Portal (default)"],
    "mydeviceportal": ["My Devices Portal (default)"],
}
CWA = {
    "WebRedirectionType": "CentralizedWebAuth",
    "acl": "ACL-REDIRECT",
    "portalName": "Sponsored Guest Portal (default)",
    "displayCertificatesRenewalMessages": True,
}


def mock_portals(mock: respx.MockRouter) -> None:
    for i, (resource, names) in enumerate(PORTALS.items()):
        mock.get(f"/ers/config/{resource}").respond(
            json=ers_page([{"id": f"{i}-{n}", "name": n} for n in names])
        )


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


def sent(route: respx.Route) -> dict[str, Any]:
    body: dict[str, Any] = json.loads(route.calls.last.request.content)["AuthorizationProfile"]
    return body


async def test_create_cwa_redirect_profile(mock: respx.MockRouter) -> None:
    mock_portals(mock)
    post = new_profile(mock, "mcp-cwa-redirect")
    args = {
        "name": "mcp-cwa-redirect",
        # Lower case: matched to ISE's spelling of the portal name.
        "redirect": {
            "type": "CentralizedWebAuth",
            "acl": "ACL-REDIRECT",
            "portal": "sponsored guest portal (default)",
        },
    }
    preview, done = await two_step("ise_create_authz_profile", args)
    assert preview["status"] == "preview" and not preview.get("blockers")
    assert preview["preview"]["webRedirection"] == CWA
    assert any("ACL-REDIRECT" in s and "switch/WLC" in s for s in preview["side_effects"])
    assert done["status"] == "applied"
    body = sent(post)
    assert body["webRedirection"] == CWA
    assert body["accessType"] == "ACCESS_ACCEPT" and body["authzProfileType"] == "SWITCH"


async def test_create_hotspot_with_static_host_and_common_tasks(mock: respx.MockRouter) -> None:
    mock_portals(mock)
    post = new_profile(mock, "mcp-iot")
    mock.get("/ers/config/downloadableacl", params={"filter": "name.EQ.mcp-v6"}).respond(
        json=ers_page([{"id": "d6", "name": "mcp-v6"}])
    )
    args = {
        "name": "mcp-iot",
        "redirect": {
            "type": "HotSpot",
            "acl": "ACL-REDIRECT",
            "portal": "Hotspot Guest Portal (default)",
            "static_host": "guest.example.com",
        },
        "interface_template": "IOT_TEMPLATE",
        "auto_smart_port": "CISCO_PHONE_EVENT",
        "macsec_policy": "SHOULD_SECURE",
        "neat": True,
        "airespace_acl": "WLC-IOT",
        "ipv6_dacl": "mcp-v6",
        "track_movement": True,
    }
    preview, done = await two_step("ise_create_authz_profile", args)
    assert done["status"] == "applied"
    body = sent(post)
    assert body["webRedirection"] == {
        "WebRedirectionType": "HotSpot",
        "acl": "ACL-REDIRECT",
        "portalName": "Hotspot Guest Portal (default)",
        "staticIPHostNameFQDN": "guest.example.com",
    }  # displayCertificatesRenewalMessages only for CWA
    assert {k: body[k] for k in ("interfaceTemplate", "autoSmartPort", "macSecPolicy", "airespaceACL")} == {
        "interfaceTemplate": "IOT_TEMPLATE",
        "autoSmartPort": "CISCO_PHONE_EVENT",
        "macSecPolicy": "SHOULD_SECURE",
        "airespaceACL": "WLC-IOT",
    }
    assert body["neat"] is True and body["trackMovement"] is True and body["ipv6DaclName"] == "mcp-v6"
    effects = " ".join(preview["side_effects"])
    assert "cisp enable" in effects and "IOT_TEMPLATE" in effects


async def test_create_portal_type_mismatch_is_blocked(mock: respx.MockRouter) -> None:
    mock_portals(mock)
    post = new_profile(mock, "mcp-cwa-redirect")
    args = {
        "name": "mcp-cwa-redirect",
        "redirect": {
            "type": "CentralizedWebAuth",
            "acl": "ACL-REDIRECT",
            "portal": "Hotspot Guest Portal (default)",
        },
    }
    async with Client(make_server(mcp_enable_writes=True)) as c:
        out = (await c.call_tool("ise_create_authz_profile", args)).structured_content
    assert out["status"] == "blocked"
    assert any(
        "is a hotspot portal" in b and "sponsored-guest or self-registration" in b for b in out["blockers"]
    )
    assert not post.called


async def test_create_unknown_portal_lists_the_right_kind(mock: respx.MockRouter) -> None:
    mock_portals(mock)
    new_profile(mock, "mcp-byod")
    args = {
        "name": "mcp-byod",
        "redirect": {"type": "NativeSupplicanProvisioning", "acl": "R", "portal": "Nope"},
    }
    async with Client(make_server(mcp_enable_writes=True)) as c:
        out = (await c.call_tool("ise_create_authz_profile", args)).structured_content
    assert out["status"] == "blocked"
    assert out["blockers"] == [
        "No BYOD portal named 'Nope' (have: 'BYOD Portal (default)'); see ise_list_guest_portals"
    ]


async def test_create_web_auth_with_redirect_warns(mock: respx.MockRouter) -> None:
    mock_portals(mock)
    new_profile(mock, "p")
    args = {
        "name": "p",
        "web_auth": True,
        "redirect": {
            "type": "CentralizedWebAuth",
            "acl": "R",
            "portal": "Self-Registered Guest Portal (default)",
        },
    }
    async with Client(make_server(mcp_enable_writes=True)) as c:
        out = (await c.call_tool("ise_create_authz_profile", args)).structured_content
    assert out["status"] == "preview"
    assert out["preview"]["webAuth"] is True
    assert any("local web auth" in s for s in out["side_effects"])


async def test_update_adds_redirect_and_removes_fields(mock: respx.MockRouter) -> None:
    mock_portals(mock)
    profile = {
        "id": "p1",
        "name": "mcp-guest",
        "accessType": "ACCESS_ACCEPT",
        "authzProfileType": "SWITCH",
        "interfaceTemplate": "OLD_TEMPLATE",
        "macSecPolicy": "MUST_SECURE",
        "neat": False,
        "trackMovement": False,
    }
    put = existing_profile(mock, profile)
    args = {
        "profile": "mcp-guest",
        "redirect": {
            "type": "CentralizedWebAuth",
            "acl": "ACL-REDIRECT",
            "portal": "Sponsored Guest Portal (default)",
        },
        "interface_template": "",
        "macsec_policy": "",
        "track_movement": True,
    }
    preview, done = await two_step("ise_update_authz_profile", args)
    changes = preview["preview"]["changes"]
    assert changes["interfaceTemplate"] == {"from": "OLD_TEMPLATE", "to": None, "removed": True}
    assert changes["macSecPolicy"]["removed"] is True
    assert changes["trackMovement"] == {"from": False, "to": True}
    assert done["status"] == "applied"
    body = sent(put)
    assert body["webRedirection"] == CWA and body["trackMovement"] is True
    assert "interfaceTemplate" not in body and "macSecPolicy" not in body


async def test_update_redirect_replaced_whole_and_removed(mock: respx.MockRouter) -> None:
    mock_portals(mock)
    profile = {
        "id": "p2",
        "name": "mcp-cwa",
        "accessType": "ACCESS_ACCEPT",
        "webRedirection": {**CWA, "staticIPHostNameFQDN": "old.example.com"},
    }
    put = existing_profile(mock, profile)
    args = {
        "profile": "mcp-cwa",
        "redirect": {"type": "HotSpot", "acl": "ACL-HS", "portal": "Hotspot Guest Portal (default)"},
    }
    _, done = await two_step("ise_update_authz_profile", args)
    assert done["status"] == "applied"
    # No stale static host or CWA-only flag carried over to the hotspot redirect.
    assert sent(put)["webRedirection"] == {
        "WebRedirectionType": "HotSpot",
        "acl": "ACL-HS",
        "portalName": "Hotspot Guest Portal (default)",
    }
    preview, _ = await two_step("ise_update_authz_profile", {"profile": "mcp-cwa", "redirect": ""})
    assert preview["preview"]["changes"]["webRedirection"]["removed"] is True


# The built-in Cisco_WebAuth profile as a raw ERS GET on ISE 3.5 returns it (#130).
CISCO_WEBAUTH = {
    "id": "cwa-builtin",
    "name": "Cisco_WebAuth",
    "description": "Default Profile used to redirect users to the CWA portal.",
    "accessType": "ACCESS_ACCEPT",
    "authzProfileType": "SWITCH",
    "webRedirection": {
        "WebRedirectionType": "CentralizedWebAuth",
        "acl": "ACL_WEBAUTH_REDIRECT",
        "portalName": "Self-Registered Guest Portal (default)",
        "displayCertificatesRenewalMessages": False,
    },
    "trackMovement": False,
    "serviceTemplate": False,
    "easywiredSessionCandidate": False,
    "voiceDomainPermission": False,
    "neat": False,
    "webAuth": False,
    "profileName": "Cisco",
}


async def test_redirect_bodies_use_ise_acl_key(mock: respx.MockRouter) -> None:
    """#130: ISE 3.5 ERS refuses webRedirection.ACL (400 'JSON invalidity'); POST and PUT send 'acl'."""
    mock_portals(mock)
    post = new_profile(mock, "mcp-cwa-static")
    redirect = {
        "type": "CentralizedWebAuth",
        "acl": "ACL_WEBAUTH_REDIRECT",
        "portal": "Self-Registered Guest Portal (default)",
        "static_host": "guest.example.com",
    }
    _, done = await two_step("ise_create_authz_profile", {"name": "mcp-cwa-static", "redirect": redirect})
    assert done["status"] == "applied"
    wr = sent(post)["webRedirection"]
    assert "ACL" not in wr
    assert wr == {
        "WebRedirectionType": "CentralizedWebAuth",
        "acl": "ACL_WEBAUTH_REDIRECT",
        "portalName": "Self-Registered Guest Portal (default)",
        "staticIPHostNameFQDN": "guest.example.com",
        "displayCertificatesRenewalMessages": True,
    }
    # Same key set as ISE's own GET (plus the static host).
    assert set(wr) - {"staticIPHostNameFQDN"} == set(CISCO_WEBAUTH["webRedirection"])

    put = existing_profile(mock, copy.deepcopy(CISCO_WEBAUTH))
    _, done = await two_step(
        "ise_update_authz_profile", {"profile": "Cisco_WebAuth", "redirect": {**redirect, "acl": "ACL-NEW"}}
    )
    assert done["status"] == "applied"
    assert sent(put)["webRedirection"] == {
        "WebRedirectionType": "CentralizedWebAuth",
        "acl": "ACL-NEW",
        "portalName": "Self-Registered Guest Portal (default)",
        "staticIPHostNameFQDN": "guest.example.com",
        "displayCertificatesRenewalMessages": False,  # kept from the profile
    }


async def test_update_same_redirect_as_get_is_no_change(mock: respx.MockRouter) -> None:
    """Re-sending the redirect a GET returns (acl, displayCertificatesRenewalMessages=false) is no change."""
    mock_portals(mock)
    put = existing_profile(mock, copy.deepcopy(CISCO_WEBAUTH))
    same = {
        "type": "CentralizedWebAuth",
        "acl": "ACL_WEBAUTH_REDIRECT",
        "portal": "Self-Registered Guest Portal (default)",
    }
    async with Client(make_server(mcp_enable_writes=True)) as c:
        res = (
            await c.call_tool("ise_update_authz_profile", {"profile": "Cisco_WebAuth", "redirect": same})
        ).structured_content
    assert res["status"] == "no_change" and "confirm" not in res  # C71
    # Only the ACL changes: the diff names webRedirection.acl, nothing else.
    preview, _ = await two_step(
        "ise_update_authz_profile",
        {"profile": "Cisco_WebAuth", "redirect": {**same, "acl": "ACL-OTHER"}},
    )
    changes = preview["preview"]["changes"]
    assert set(changes) == {"webRedirection.acl"}
    assert "displayCertificatesRenewalMessages" not in json.dumps(changes)
    assert put.call_count == 1


async def test_update_portal_mismatch_is_blocked(mock: respx.MockRouter) -> None:
    mock_portals(mock)
    put = existing_profile(mock, {"id": "p3", "name": "mcp-hs", "accessType": "ACCESS_ACCEPT"})
    args = {
        "profile": "mcp-hs",
        "redirect": {"type": "HotSpot", "acl": "R", "portal": "BYOD Portal (default)"},
    }
    async with Client(make_server(mcp_enable_writes=True)) as c:
        out = (await c.call_tool("ise_update_authz_profile", args)).structured_content
    assert out["status"] == "blocked"
    assert any("is a BYOD portal" in b for b in out["blockers"])
    assert not put.called


async def test_client_provisioning_portal_left_to_ise(mock: respx.MockRouter) -> None:
    """ERS has no client provisioning portal collection: ISE checks it on apply."""
    mock_portals(mock)
    mock.get("/ers/config/byodportal").respond(404)  # a collection that does not answer is skipped
    new_profile(mock, "mcp-posture")
    args = {
        "name": "mcp-posture",
        "redirect": {
            "type": "ClientProvisioning",
            "acl": "ACL-POSTURE",
            "portal": "Client Provisioning Portal (default)",
        },
    }
    async with Client(make_server(mcp_enable_writes=True)) as c:
        out = (await c.call_tool("ise_create_authz_profile", args)).structured_content
    assert out["status"] == "preview"
    assert out["preview"]["webRedirection"]["portalName"] == "Client Provisioning Portal (default)"
    assert any("checked by ISE on apply" in s for s in out["side_effects"])


# --- export / import round trip ---------------------------------------------------------------------


def cwa_profile() -> dict[str, Any]:
    return {
        "id": _uuid(40),
        "name": "mcp-cwa-redirect",
        "accessType": "ACCESS_ACCEPT",
        "authzProfileType": "SWITCH",
        "webRedirection": {**CWA, "staticIPHostNameFQDN": "guest.example.com"},
        "interfaceTemplate": "IOT_TEMPLATE",
        "autoSmartPort": "CISCO_PHONE_EVENT",
        "macSecPolicy": "SHOULD_SECURE",
        "neat": True,
        "webAuth": False,
        "airespaceACL": "WLC-GUEST",
        "ipv6DaclName": "mcp-test-dacl",
        "trackMovement": True,
    }


async def test_export_import_round_trips_the_new_fields() -> None:
    source = lab_objects()
    source["authorizationprofile"].append(cwa_profile())
    doc = await export_of(source, ["authz_profiles"])
    exported = next(p for p in doc["authz_profiles"] if p["name"] == "mcp-cwa-redirect")
    for key in (
        "webRedirection",
        "interfaceTemplate",
        "autoSmartPort",
        "macSecPolicy",
        "neat",
        "airespaceACL",
    ):
        assert exported[key] == cwa_profile()[key]
    assert exported["ipv6DaclName"] == "mcp-test-dacl" and exported["trackMovement"] is True

    # A target whose copy lost the redirect and the common tasks: the import puts them back.
    target = lab_objects()
    stripped = {
        k: v
        for k, v in cwa_profile().items()
        if k not in ("webRedirection", "interfaceTemplate", "macSecPolicy", "neat", "trackMovement")
    }
    target["authorizationprofile"].append(copy.deepcopy(stripped))
    with router() as r:
        serve(r, target)
        put = r.put(f"/ers/config/authorizationprofile/{_uuid(40)}").respond(json={})
        app = IseApp(make_settings())
        try:
            from ise_mcp.tools.config_import import plan_import

            plan = await plan_import(app, doc, only=["mcp-cwa-redirect"])
            assert [(s.op, s.name) for s in plan.steps] == [("update", "mcp-cwa-redirect")]
            changed = {k.split(".")[0] for k in plan.steps[0].changes or {}}
            assert changed >= {
                "webRedirection",
                "interfaceTemplate",
                "macSecPolicy",
                "neat",
                "trackMovement",
            }
            await plan.steps[0].run()
        finally:
            await app.aclose()
    body = json.loads(put.calls.last.request.content)["AuthorizationProfile"]
    assert body["webRedirection"] == cwa_profile()["webRedirection"]
    assert body["interfaceTemplate"] == "IOT_TEMPLATE" and body["neat"] is True

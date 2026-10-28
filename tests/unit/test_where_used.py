"""ise_where_used (I64) on the recorded policy fixtures plus a synthetic egress matrix and NAD list."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from ise_mcp._core.testing import call_tool
from ise_mcp.tools.where_used import condition_hits, delete_blockers, group_matcher, ndg_matcher
from tests.unit.conftest import ers_page, fixture_json, make_server
from tests.unit.test_writes import two_step

NA = "/api/v1/policy/network-access"
DA = "/api/v1/policy/device-admin"
DEFAULT_SET = "d303293e-f4ba-4578-80eb-a01249fc5ae2"
NON_CISCO_PHONES = "c9260a79-93b2-4f07-92d6-dde2f20fe70f"


def attr(dn: str, an: str, val: str) -> dict[str, Any]:
    return {
        "conditionType": "ConditionAttributes",
        "isNegate": False,
        "dictionaryName": dn,
        "attributeName": an,
        "operator": "equals",
        "attributeValue": val,
    }


LAB_SET = {
    "id": "s-lab",
    "name": "Lab-Wired",
    "rank": 0,
    "state": "enabled",
    "serviceName": "Lab_Protocols",
    "condition": {
        "conditionType": "ConditionAndBlock",
        "isNegate": False,
        "children": [
            attr("DEVICE", "Location", "All Locations#Lab"),
            attr("Radius", "NAS-Port-Type", "Ethernet"),
        ],
    },
}
LAB_AUTHN = [
    {
        "rule": {"id": "a1", "name": "Lab-dot1x", "rank": 0, "state": "enabled", "condition": None},
        "identitySourceName": "Lab_EAPTLS_Seq",
    }
]
LAB_AUTHZ = [
    {
        "rule": {
            "id": "z1",
            "name": "Lab-Employees",
            "rank": 0,
            "state": "enabled",
            "condition": {
                "conditionType": "ConditionAndBlock",
                "isNegate": False,
                "children": [
                    {
                        "conditionType": "ConditionReference",
                        "isNegate": False,
                        "name": "Lab_Employee",
                        "id": "lc1",
                    },
                    attr("CORP", "ExternalGroups", "example.com/Lab/Employees"),
                ],
            },
        },
        "profile": ["Lab_Permit"],
        "securityGroup": "Employees",
    }
]
# The bulk library: a library condition on a user identity group, used by the lab rule above.
LIBRARY = [
    {
        "id": "lc1",
        "name": "Lab_Employee",
        "conditionType": "LibraryConditionAttributes",
        "dictionaryName": "IdentityGroup",
        "attributeName": "Name",
        "operator": "equals",
        "attributeValue": "User Identity Groups:Employee",
    },
    {
        "id": "195babd4-83a8-4334-8c4b-71f11c54cbc3",
        "name": "Wireless_802.1X",
        "conditionType": "LibraryConditionAndBlock",
        "children": [attr("Radius", "NAS-Port-Type", "Wireless - IEEE 802.11")],
    },
]
# A built-in condition missing from the bulk list: resolve_references fetches it by id.
BY_ID = {
    NON_CISCO_PHONES: {
        "id": NON_CISCO_PHONES,
        "name": "Non_Cisco_Profiled_Phones",
        "conditionType": "LibraryConditionAttributes",
        "dictionaryName": "IdentityGroup",
        "attributeName": "Name",
        "operator": "equals",
        "attributeValue": "Endpoint Identity Groups:Profiled:Non-Cisco-IP-Phone",
    }
}

ERS: dict[str, list[dict[str, Any]]] = {
    "authorizationprofile": [
        {"id": "p1", "name": "Lab_Permit", "daclName": "LAB_DACL"},
        {"id": "p2", "name": "Other", "ipv6DaclName": "LAB_DACL"},
        {"id": "p3", "name": "PermitAccess"},
    ],
    "downloadableacl": [{"id": "d1", "name": "LAB_DACL"}],
    "sgt": [{"id": "t1", "name": "Employees", "value": 4}],
    "sgacl": [{"id": "acl1", "name": "Permit_Web"}],
    "identitygroup": [{"id": "g1", "name": "Employee"}],
    "endpointgroup": [
        {"id": "e1", "name": "Cisco-IP-Phone"},
        {"id": "e2", "name": "Non-Cisco-IP-Phone"},
        {"id": "e3", "name": "Blocked List"},
    ],
    "networkdevicegroup": [{"id": "n1", "name": "Location#All Locations#Lab"}],
    "allowedprotocols": [
        {"id": "ap1", "name": "Default Network Access"},
        {"id": "ap2", "name": "Lab_Protocols"},
    ],
    "idstoresequence": [
        {
            "id": "q1",
            "name": "Lab_EAPTLS_Seq",
            "idSeqItem": [{"idstore": "Internal Users", "order": 1}, {"idstore": "CORP", "order": 2}],
            "certificateAuthenticationProfile": "Lab_CertProfile",
        },
        {"id": "q2", "name": "All_User_ID_Stores", "idSeqItem": [{"idstore": "Internal Users", "order": 1}]},
    ],
    "certificateprofile": [{"id": "c1", "name": "Lab_CertProfile"}],
    "activedirectory": [{"id": "j1", "name": "CORP", "domain": "example.com"}],
    "egressmatrixcell": [
        {"id": "m1", "name": "Employees-Servers", "src": "Employees", "dst": "Servers", "sgacls": ["acl1"]},
        {"id": "m2", "name": "Guests-Employees", "src": "Guests", "dst": "Employees", "sgacls": []},
    ],
    "networkdevice": [
        {"id": "nad1", "name": "lab-sw1", "NetworkDeviceGroupList": ["Location#All Locations#Lab"]},
        {"id": "nad2", "name": "core-sw1", "NetworkDeviceGroupList": ["Location#All Locations"]},
    ],
    "internaluser": [],
}


def fake_ers(mock: respx.MockRouter) -> None:
    def listing(request: httpx.Request, res: str) -> httpx.Response:
        items = ERS.get(res, [])
        filt = request.url.params.get("filter", "")
        field, _, value = filt.partition(".EQ.")
        key = {"name": "name", "sgtSrcName": "src", "sgtDstName": "dst"}.get(field)
        if key:
            items = [i for i in items if i.get(key) == value]
        elif filt:
            items = []
        return httpx.Response(200, json=ers_page([{"id": i["id"], "name": i["name"]} for i in items]))

    def get(request: httpx.Request, res: str, oid: str) -> httpx.Response:
        for i in ERS.get(res, []):
            if i["id"] == oid:
                return httpx.Response(200, json={"Obj": i})
        return httpx.Response(404, json={})

    def by_name(request: httpx.Request, res: str, name: str) -> httpx.Response:
        for i in ERS.get(res, []):
            if i["name"] == name:
                return httpx.Response(200, json={"Obj": i})
        return httpx.Response(404, json={})

    mock.get(path__regex=r"^/ers/config/(?P<res>[a-z]+)$").mock(side_effect=listing)
    mock.get(path__regex=r"^/ers/config/(?P<res>[a-z]+)/name/(?P<name>[^/]+)$").mock(side_effect=by_name)
    mock.get(path__regex=r"^/ers/config/(?P<res>[a-z]+)/(?P<oid>[^/]+)$").mock(side_effect=get)


def mock_policy(mock: respx.MockRouter, *, device_admin: int = 200) -> None:
    sets = fixture_json("policy_sets.json")
    sets["response"] = [LAB_SET, *sets["response"]]
    mock.get(f"{NA}/policy-set").respond(json=sets)
    mock.get(f"{NA}/policy-set/global-exception").respond(json={"response": []})
    mock.get(f"{NA}/policy-set/{DEFAULT_SET}/authentication").respond(json=fixture_json("authn_rules.json"))
    mock.get(f"{NA}/policy-set/{DEFAULT_SET}/authorization").respond(json=fixture_json("authz_rules.json"))
    mock.get(f"{NA}/policy-set/{DEFAULT_SET}/exception").respond(json={"response": []})
    mock.get(f"{NA}/policy-set/s-lab/authentication").respond(json={"response": LAB_AUTHN})
    mock.get(f"{NA}/policy-set/s-lab/authorization").respond(json={"response": LAB_AUTHZ})
    mock.get(f"{NA}/policy-set/s-lab/exception").respond(json={"response": []})
    mock.get(f"{NA}/condition").respond(json={"response": LIBRARY})

    def one_condition(request: httpx.Request, cid: str) -> httpx.Response:
        if cid in BY_ID:
            return httpx.Response(200, json={"response": BY_ID[cid]})
        return httpx.Response(404, json={})

    mock.get(path__regex=rf"^{NA}/condition/(?P<cid>[^/]+)$").mock(side_effect=one_condition)
    if device_admin == 200:
        mock.get(f"{DA}/policy-set").respond(json={"response": []})
        mock.get(f"{DA}/policy-set/global-exception").respond(json={"response": []})
        mock.get(f"{DA}/condition").respond(json={"response": []})
    else:
        mock.get(f"{DA}/policy-set").respond(
            device_admin, json={"message": "Device Admin service is disabled"}
        )
        mock.get(f"{DA}/condition").respond(device_admin, json={})
    mock.get("/api/v1/endpoint").respond(json=[])
    fake_ers(mock)


async def where(kind: str, name: str) -> dict[str, Any]:
    out = await call_tool(make_server(), "ise_where_used", {"kind": kind, "name": name})
    assert isinstance(out, dict)
    return out


def labels(out: dict[str, Any], where_: str | None = None) -> list[str]:
    return [r.get("label") for r in out["references"] if where_ is None or r["where"] == where_]


# --- pure matchers --------------------------------------------------------------------------------


def test_group_and_ndg_matchers() -> None:
    phones = group_matcher("endpoint_group", "cisco-ip-phone")
    assert phones(attr("IdentityGroup", "Name", "Endpoint Identity Groups:Profiled:Cisco-IP-Phone"))
    assert not phones(attr("IdentityGroup", "Name", "User Identity Groups:Cisco-IP-Phone"))
    assert not phones(attr("Radius", "Name", "Endpoint Identity Groups:Cisco-IP-Phone"))
    lab = ndg_matcher("Location#All Locations#Lab")
    assert lab(attr("DEVICE", "Location", "All Locations#Lab"))
    assert lab(attr("DEVICE", "Location", "Location#All Locations#Lab"))
    assert not lab(attr("DEVICE", "Device Type", "All Locations#Lab"))
    assert not lab(attr("DEVICE", "Location", "All Locations#Lab2"))


def test_condition_hits_follows_library_once() -> None:
    lib = {
        "x": {
            "id": "x",
            "name": "X",
            "conditionType": "LibraryConditionAndBlock",
            "children": [
                {"conditionType": "ConditionReference", "id": "x", "name": "X"},  # a cycle is not followed
                attr("IdentityGroup", "Name", "User Identity Groups:Employee"),
            ],
        },
    }
    tree = {"conditionType": "ConditionReference", "id": "x", "name": "X"}
    assert condition_hits(tree, lib, group_matcher("identity_group", "Employee")) == ["X"]
    direct = attr("IdentityGroup", "Name", "User Identity Groups:Employee")
    assert condition_hits(direct, lib, group_matcher("identity_group", "Employee")) == [None]


def test_delete_blockers_shape() -> None:
    result = {
        "kind": "sgt",
        "members": {"internal_users": 2},
        "references": [
            {"where": "egress cell", "cell": "A-B"},
            {"where": "authorization rule", "label": "Wired / R1"},
            {"where": "authorization rule", "label": "Wired / R2", "via": "Cond"},
        ],
        "incomplete": ["device-admin policy sets not readable: 404"],
    }
    blockers, warnings = delete_blockers(result)
    assert blockers == [
        "2 internal user(s) are in this group",
        "1 egress matrix cell(s) use this SGT",
        "Used by authorization rule(s): Wired / R1, Wired / R2 (via Cond)",
    ]
    assert warnings == ["Not checked (device-admin policy sets not readable: 404)"]


# --- the tool on the fixtures ---------------------------------------------------------------------


async def test_authz_profile_rules(mock: respx.MockRouter) -> None:
    mock_policy(mock)
    out = await where("authz_profile", "PermitAccess")
    assert out["object"] == {"name": "PermitAccess", "id": "p3"}
    assert labels(out) == [
        "Default / Compliant_Devices_Access",
        "Default / Employee_EAP-TLS",
        "Default / Wi-Fi_Guest_Access",
        "Default / Basic_Authenticated_Access",
    ]
    assert {r["field"] for r in out["references"]} == {"profile"}
    assert "incomplete" not in out


async def test_sgt_rules_and_egress_cells(mock: respx.MockRouter) -> None:
    mock_policy(mock)
    out = await where("sgt", "Employees")
    assert labels(out, "authorization rule") == ["Lab-Wired / Lab-Employees"]
    cells = [(r["cell"], r["field"]) for r in out["references"] if r["where"] == "egress cell"]
    assert cells == [("Employees-Servers", "source"), ("Guests-Employees", "destination")]
    assert out["by_where"] == {"authorization rule": 1, "egress cell": 2}


async def test_sgacl_and_dacl(mock: respx.MockRouter) -> None:
    mock_policy(mock)
    out = await where("sgacl", "Permit_Web")
    assert [r["cell"] for r in out["references"]] == ["Employees-Servers"]
    out = await where("dacl", "LAB_DACL")
    assert [(r["profile"], r["field"]) for r in out["references"]] == [
        ("Lab_Permit", "daclName"),
        ("Other", "ipv6DaclName"),
    ]


async def test_endpoint_group_direct_and_via_builtin_condition(mock: respx.MockRouter) -> None:
    mock_policy(mock)
    out = await where("endpoint_group", "Cisco-IP-Phone")
    assert labels(out) == ["Default / Profiled Cisco IP Phones"]
    assert "via" not in out["references"][0]
    out = await where("endpoint_group", "Non-Cisco-IP-Phone")
    rule = next(r for r in out["references"] if r["where"] == "authorization rule")
    assert (
        rule["label"] == "Default / Profiled Non Cisco IP Phones"
        and rule["via"] == "Non_Cisco_Profiled_Phones"
    )
    blocked = await where("endpoint_group", "Blocked List")
    assert labels(blocked) == ["Default / Wireless Block List Default"]


async def test_identity_group_through_library_condition(mock: respx.MockRouter) -> None:
    mock_policy(mock)
    out = await where("identity_group", "Employee")
    rule = next(r for r in out["references"] if r["where"] == "authorization rule")
    assert rule["label"] == "Lab-Wired / Lab-Employees" and rule["via"] == "Lab_Employee"
    assert labels(out, "library condition") == ["Lab_Employee"]


async def test_ndg_policy_set_and_nads(mock: respx.MockRouter) -> None:
    mock_policy(mock)
    out = await where("ndg", "Location#All Locations#Lab")
    assert labels(out, "policy set") == ["Lab-Wired"]
    assert [r["nad"] for r in out["references"] if r["where"] == "network device"] == ["lab-sw1"]


async def test_library_condition_kind(mock: respx.MockRouter) -> None:
    mock_policy(mock)
    out = await where("condition", "Wireless_802.1X")
    assert out["object"]["id"] == "195babd4-83a8-4334-8c4b-71f11c54cbc3"
    assert labels(out) == ["Default / Dot1X", "Default / Employee_EAP-TLS", "Default / Employee_Onboarding"]
    assert [r["where"] for r in out["references"]][0] == "authentication rule"


async def test_allowed_protocols_and_identity_sources(mock: respx.MockRouter) -> None:
    mock_policy(mock)
    out = await where("allowed_protocols", "Default Network Access")
    assert labels(out) == ["Default"] and out["references"][0]["field"] == "serviceName"
    out = await where("identity_sequence", "All_User_ID_Stores")
    assert labels(out) == ["Default / Dot1X", "Default / Default"]
    assert {r["where"] for r in out["references"]} == {"authentication rule"}
    out = await where("cert_profile", "Lab_CertProfile")
    assert [(r["where"], r.get("sequence")) for r in out["references"]] == [
        ("identity sequence", "Lab_EAPTLS_Seq")
    ]


async def test_ad_join_point_and_group(mock: respx.MockRouter) -> None:
    mock_policy(mock)
    out = await where("ad_group", "CORP:Employees")
    assert labels(out) == ["Lab-Wired / Lab-Employees"]
    assert (await where("ad_group", "OTHER:Employees"))["count"] == 0
    out = await where("ad_join_point", "CORP")
    assert {r["where"] for r in out["references"]} == {"identity sequence", "authorization rule"}


async def test_unreadable_device_admin_is_reported(mock: respx.MockRouter) -> None:
    mock_policy(mock, device_admin=500)
    out = await where("identity_group", "Employee")
    assert out["used"] is True
    assert any("device-admin policy sets not readable" in i for i in out["incomplete"])


async def test_unknown_object(mock: respx.MockRouter) -> None:
    mock_policy(mock)
    with pytest.raises(ToolError, match="No library condition"):
        await call_tool(make_server(), "ise_where_used", {"kind": "condition", "name": "nope"})


async def test_delete_endpoint_group_blocked_by_rule(mock: respx.MockRouter) -> None:
    """ise_delete_object now blocks on policy that matches the group, not just on members."""
    mock_policy(mock)
    preview, _ = await two_step("ise_delete_object", {"kind": "endpoint_group", "target": "Blocked List"})
    assert preview["status"] == "blocked"
    assert preview["blockers"] == ["Used by authorization rule(s): Default / Wireless Block List Default"]


async def test_delete_sgt_lists_rules_and_cells(mock: respx.MockRouter) -> None:
    mock_policy(mock)
    preview, _ = await two_step("ise_delete_object", {"kind": "sgt", "target": "Employees"})
    assert preview["blockers"] == [
        "2 egress matrix cell(s) use this SGT",
        "Used by authorization rule(s): Lab-Wired / Lab-Employees",
    ]

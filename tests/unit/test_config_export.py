"""I42: ise_export_config / ise_diff_config (export shape, stable ordering, masking, names, diff)."""

from __future__ import annotations

import copy
import datetime as dt
import json
import random
from pathlib import Path
from typing import Any

import pytest
import respx
from fastmcp import Client

from ise_mcp._core import InvalidRequest
from ise_mcp.client import IseApp
from ise_mcp.tools.config_export import (
    HEADER,
    condition_text,
    diff_exports,
    export_config,
    load_export,
    resolve_path,
    resolve_scope,
    to_yaml,
)
from tests.unit.conftest import BASE, ers_page, fixture_json, make_server, make_settings, xml

NA = "/api/v1/policy/network-access/policy-set"
NOW = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.UTC)
SECRETS = ("REDACTED-radius-secret", "tacacs-secret-xyz", "community-ro-xyz")


def _uuid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def _nad() -> dict[str, Any]:
    nad = copy.deepcopy(fixture_json("ers_networkdevice.json")["NetworkDevice"])
    nad["tacacsSettings"] = {"sharedSecret": SECRETS[1], "connectModeOptions": "OFF"}
    nad["snmpsettings"] = {"version": "TWO_C", "roCommunity": SECRETS[2], "pollingInterval": 3600}
    nad["NetworkDeviceIPList"] = [
        {"ipaddress": "192.0.2.60", "mask": 32},
        {"ipaddress": "192.0.2.50", "mask": 32},
    ]
    return nad


def lab_objects() -> dict[str, list[dict[str, Any]]]:
    """ERS objects by resource (full detail shape), with ids and links like ISE returns them."""
    link = {"rel": "self", "href": "https://192.0.2.10/ers/config/x", "type": "application/json"}
    return {
        "authorizationprofile": [
            {
                "id": _uuid(1),
                "name": "mcp-test-permit",
                "accessType": "ACCESS_ACCEPT",
                "daclName": "mcp-test-dacl",
                "description": "",
                "link": link,
            },
            {"id": _uuid(2), "name": "DenyAccess", "accessType": "ACCESS_REJECT", "link": link},
        ],
        "downloadableacl": [
            {
                "id": _uuid(3),
                "name": "mcp-test-dacl",
                "dacl": "permit udp any any eq 53\npermit ip any any\n",
                "daclType": "IPV4",
                "link": link,
            },
        ],
        "networkdevice": [_nad()],
        "networkdevicegroup": [
            {"id": _uuid(5), "name": "Location#All Locations", "othername": "Location", "link": link},
            {
                "id": _uuid(6),
                "name": "Device Type#All Device Types",
                "othername": "Device Type",
                "link": link,
            },
        ],
        "identitygroup": [
            {
                "id": _uuid(7),
                "name": "mcp-test-group",
                "parent": "NAC Group:NAC:IdentityGroups:User Identity Groups",
            },
        ],
        "endpointgroup": [
            {"id": _uuid(8), "name": "Profiled", "systemDefined": True},
            {"id": _uuid(9), "name": "Workstation", "parentId": _uuid(8), "systemDefined": True},
        ],
        "sgt": [
            {"id": _uuid(10), "name": "Employees", "value": 4, "generationId": "7", "link": link},
            {"id": _uuid(11), "name": "Dev_Servers", "value": 12, "generationId": "3", "link": link},
        ],
        "sgacl": [
            {"id": _uuid(12), "name": "Permit IP", "aclcontent": "permit ip", "generationId": "0"},
            {"id": _uuid(13), "name": "Deny IP", "aclcontent": "deny ip", "generationId": "0"},
        ],
        "egressmatrixcell": [
            {
                "id": _uuid(14),
                "name": "ANY-ANY",
                "sourceSgtId": _uuid(99),
                "destinationSgtId": _uuid(99),
                "defaultRule": "PERMIT_IP",
                "sgacls": [_uuid(12)],
                "matrixCellStatus": "ENABLED",
                "matrixId": "m",
            },
            {
                "id": _uuid(15),
                "name": "Employees-Dev_Servers",
                "sourceSgtId": _uuid(10),
                "destinationSgtId": _uuid(11),
                "defaultRule": "DENY_IP",
                "sgacls": [_uuid(13), _uuid(12)],
                "matrixCellStatus": "ENABLED",
                "matrixId": "m",
            },
        ],
        "tacacscommandsets": [
            {
                "id": _uuid(16),
                "name": "mcp-test-show",
                "permitUnmatched": False,
                "commands": {"commandList": [{"grant": "PERMIT", "command": "show", "arguments": ".*"}]},
            },
        ],
        "tacacsprofile": [
            {
                "id": _uuid(17),
                "name": "mcp_test_priv15",
                "sessionAttributes": {
                    "sessionAttributeList": [{"type": "MANDATORY", "name": "priv-lvl", "value": "15"}]
                },
            },
        ],
    }


def serve(mock: respx.MockRouter, objects: dict[str, list[dict[str, Any]]], *, shuffle: bool = False) -> None:
    rnd = random.Random(42)
    for resource, objs in objects.items():
        listed = [{"id": o["id"], "name": o.get("name"), "description": o.get("description")} for o in objs]
        if shuffle:
            rnd.shuffle(listed)
        mock.get(f"/ers/config/{resource}").respond(json=ers_page(listed))
        for o in objs:
            mock.get(f"/ers/config/{resource}/{o['id']}").respond(json={"Wrapped": o})
    sets = copy.deepcopy(fixture_json("policy_sets.json"))
    ps_id = sets["response"][0]["id"]
    authn = copy.deepcopy(fixture_json("authn_rules.json"))
    authz = copy.deepcopy(fixture_json("authz_rules.json"))
    if shuffle:
        rnd.shuffle(authn["response"])
        rnd.shuffle(authz["response"])
    mock.get(NA).respond(json=sets)
    mock.get(f"{NA}/{ps_id}/authentication").respond(json=authn)
    mock.get(f"{NA}/{ps_id}/authorization").respond(json=authz)
    mock.get(f"{NA}/{ps_id}/exception").respond(json={"response": []})
    mock.get(f"{NA}/global-exception").respond(json={"response": []})
    mock.get("/api/v1/policy/device-admin/policy-set").respond(404, json={"message": "Device Admin is off"})
    mock.get("/api/v1/endpoint-custom-attribute").respond(
        json={
            "response": [
                {"attributeName": "zone", "attributeType": "String"},
                {"attributeName": "asset", "attributeType": "Int"},
            ]
        }
    )


async def _export(mock: respx.MockRouter, scope: list[str] | None = None, **kw: Any) -> str:
    serve(mock, lab_objects(), **kw)
    app = IseApp(make_settings())
    try:
        return to_yaml(await export_config(app, resolve_scope(scope), now=NOW))
    finally:
        await app.aclose()


# --- export -------------------------------------------------------------------------------------


async def test_export_round_trip_and_header(mock: respx.MockRouter) -> None:
    text = await _export(mock)
    data = load_export(text)
    assert to_yaml(data) == text  # parse + dump is byte-identical
    header = data[HEADER]
    assert header["format"] == 1 and header["exported_at"] == "2026-01-02T03:04:05Z"
    assert header["ise_version"] == "3.5.0.527" and header["sections"] == resolve_scope(None)
    assert header["counts"]["nads"] == 1 and header["counts"]["policy_sets"] == 1
    assert header["digest"].startswith("sha256:")
    assert "policy_sets.device-admin" in header["skipped"]
    for volatile in ("hitCounts", "generationId", "matrixId", "href", "00000000-0000-4000"):
        assert volatile not in text


async def test_export_is_stable_under_shuffled_input() -> None:
    outputs = []
    for shuffle in (False, True):
        with respx.mock(base_url=BASE, assert_all_called=False) as router:
            router.get("/admin/API/mnt/Version").respond(
                text=xml("<product><version>3.5.0.527</version></product>")
            )
            router.get("/api/v1/deployment/node").respond(json={"response": []})
            outputs.append(await _export(router, shuffle=shuffle))
            assert router.calls.call_count > 20  # this router served the data
    assert outputs[1] == outputs[0]


async def test_export_masks_secrets(mock: respx.MockRouter) -> None:
    text = await _export(mock, ["nads"])
    for s in SECRETS:
        assert s not in text
    nad = load_export(text)["nads"][0]
    assert nad["authenticationSettings"]["radiusSharedSecret"] == "********"
    assert nad["tacacsSettings"]["sharedSecret"] == "********"
    assert nad["snmpsettings"]["roCommunity"] == "********"
    assert nad["authenticationSettings"]["enableMultiSecret"] == "false"  # a flag, not a secret
    assert [i["ipaddress"] for i in nad["NetworkDeviceIPList"]] == ["192.0.2.50", "192.0.2.60"]


async def test_export_resolves_names(mock: respx.MockRouter) -> None:
    data = load_export(await _export(mock))
    cells = data["egress_matrix"]
    assert cells[0] == {
        "source": "ANY",
        "destination": "ANY",
        "defaultRule": "PERMIT_IP",
        "matrixCellStatus": "ENABLED",
        "sgacls": ["Permit IP"],
    }
    assert (cells[1]["source"], cells[1]["destination"], cells[1]["sgacls"]) == (
        "Employees",
        "Dev_Servers",
        ["Deny IP", "Permit IP"],  # SGACL order kept
    )
    groups = {g["name"]: g for g in data["endpoint_groups"]}
    assert groups["Workstation"]["parent"] == "Profiled" and "parentId" not in groups["Workstation"]
    assert [p["name"] for p in data["authz_profiles"]] == ["DenyAccess", "mcp-test-permit"]
    assert data["authz_profiles"][1]["daclName"] == "mcp-test-dacl"
    assert data["dacls"][0]["dacl"] == ["permit udp any any eq 53", "permit ip any any"]
    assert [a["attributeName"] for a in data["custom_attributes"]] == ["asset", "zone"]
    ps = data["policy_sets"]["network-access"]["sets"][0]
    assert ps["name"] == "Default" and ps["default"] is True and "condition" not in ps
    authz = ps["authorization"]
    assert [r["rank"] for r in authz] == sorted(r["rank"] for r in authz)
    assert authz[0]["condition"] == {
        "and": ["Wireless_Access", "IdentityGroup:Name equals Endpoint Identity Groups:Blocked List"]
    }
    assert authz[0]["profile"] == ["Block_Wireless_Access"]
    assert ps["authentication"][0]["condition"] == {"or": ["Wired_MAB", "Wireless_MAB"]}


def test_condition_text() -> None:
    assert condition_text(None) is None
    ref = {"conditionType": "ConditionReference", "isNegate": True, "name": "Wired_MAB", "id": "x"}
    assert condition_text(ref) == "NOT Wired_MAB"
    attr = {
        "conditionType": "ConditionAttributes",
        "isNegate": False,
        "dictionaryName": "Radius",
        "attributeName": "NAS-Port-Type",
        "operator": "equals",
        "attributeValue": "Ethernet",
    }
    assert condition_text(attr) == "Radius:NAS-Port-Type equals Ethernet"
    block = {"conditionType": "LibraryConditionOrBlock", "isNegate": True, "children": [ref, attr]}
    assert condition_text(block) == {"not": {"or": ["NOT Wired_MAB", "Radius:NAS-Port-Type equals Ethernet"]}}


def test_resolve_scope() -> None:
    assert resolve_scope(["trustsec", "nads"]) == ["nads", "sgts", "sgacls", "egress_matrix"]
    assert resolve_scope(["device-admin"]) == ["command_sets", "shell_profiles"]
    with pytest.raises(InvalidRequest, match="Unknown export section"):
        resolve_scope(["firewall"])


def test_load_export_refuses_other_yaml() -> None:
    with pytest.raises(InvalidRequest, match="Not an ISE config export"):
        load_export("a: 1\n")
    with pytest.raises(InvalidRequest, match="format"):
        load_export(f"{HEADER}:\n  format: 99\n")


# --- diff ---------------------------------------------------------------------------------------


def _doc(**sections: Any) -> dict[str, Any]:
    return {HEADER: {"format": 1, "sections": list(sections), "exported_at": "t"}, **sections}


def _rules(*names: str) -> list[dict[str, Any]]:
    return [
        {"name": n, "rank": i, "state": "enabled", "profile": ["PermitAccess"]} for i, n in enumerate(names)
    ]


def _policy(*names: str) -> dict[str, Any]:
    return {"network-access": {"sets": [{"name": "Wired", "rank": 0, "authorization": _rules(*names)}]}}


def test_diff_no_change() -> None:
    doc = _doc(policy_sets=_policy("A", "B", "Default"), sgts=[{"name": "Employees", "value": 4}])
    out = diff_exports(doc, copy.deepcopy(doc))
    assert out["unchanged"] is True and out["sections"] == {}
    assert out["summary"] == {"added": 0, "removed": 0, "moved": 0, "changed": 0}


def test_diff_add_remove_change() -> None:
    old = _doc(
        sgts=[{"name": "Employees", "value": 4}, {"name": "Guests", "value": 6}],
        dacls=[{"name": "d", "dacl": ["permit udp any any eq 53", "deny ip any any"]}],
    )
    new = _doc(
        sgts=[{"name": "Employees", "value": 5, "description": "x"}, {"name": "Contractors", "value": 7}],
        dacls=[{"name": "d", "dacl": ["permit udp any any eq 53", "permit ip any any"]}],
    )
    out = diff_exports(old, new)
    assert out["sections"]["sgts"] == {
        "added": ["Contractors"],
        "removed": ["Guests"],
        "changed": {"Employees": {"description": {"from": None, "to": "x"}, "value": {"from": 4, "to": 5}}},
    }
    assert out["sections"]["dacls"]["changed"]["d"] == {
        "dacl": {"added": ["permit ip any any"], "removed": ["deny ip any any"]}
    }
    assert out["summary"] == {"added": 1, "removed": 1, "moved": 0, "changed": 2}


def test_diff_rule_move_and_change() -> None:
    old = _doc(policy_sets=_policy("A", "B", "C", "Default"))
    new_policy = _policy("B", "A", "C", "Default")
    new_policy["network-access"]["sets"][0]["authorization"][2]["state"] = "disabled"
    out = diff_exports(old, _doc(policy_sets=new_policy))
    rules = out["sections"]["policy_rules"]
    assert len(rules["moved"]) == 1  # one of A/B moved; the rest kept their order
    (moved,) = rules["moved"]
    assert moved in ("network-access/Wired/authorization/A", "network-access/Wired/authorization/B")
    assert rules["changed"] == {
        "network-access/Wired/authorization/C": {"state": {"from": "enabled", "to": "disabled"}}
    }
    assert "policy_sets" not in out["sections"]


def test_diff_insert_is_not_a_move() -> None:
    out = diff_exports(
        _doc(policy_sets=_policy("A", "B", "Default")), _doc(policy_sets=_policy("A", "N", "B", "Default"))
    )
    assert out["sections"] == {"policy_rules": {"added": ["network-access/Wired/authorization/N"]}}


def test_diff_compares_only_common_sections() -> None:
    out = diff_exports(_doc(sgts=[]), _doc(sgts=[], nads=[{"name": "sw1"}]))
    assert out["unchanged"] is True and "nads" in out["not_compared"]


def test_diff_truncates() -> None:
    old = _doc(sgts=[])
    new = _doc(sgts=[{"name": f"s{i}", "value": i} for i in range(30)])
    out = diff_exports(old, new, max_changes=10)
    assert len(out["sections"]["sgts"]["added"]) == 10 and "30 differences" in out["truncated"]


# --- tools and files ----------------------------------------------------------------------------


async def test_tools_export_to_path_and_diff_live(mock: respx.MockRouter, tmp_path: Path) -> None:
    serve(mock, lab_objects())
    server = make_server(export_dir=str(tmp_path))
    async with Client(server) as c:
        inline = await c.call_tool("ise_export_config", {"scope": ["trustsec"]})
        text = inline.content[0].text  # type: ignore[union-attr]
        assert load_export(text)[HEADER]["sections"] == ["sgts", "sgacls", "egress_matrix"]
        res = await c.call_tool("ise_export_config", {"scope": ["trustsec"], "path": "base.yaml"})
        meta = json.loads(res.content[0].text)  # type: ignore[union-attr]
        assert meta["path"] == str(tmp_path / "base.yaml") and meta["counts"]["sgts"] == 2
        same = await c.call_tool("ise_diff_config", {"before": "base.yaml"})
        assert same.structured_content["unchanged"] is True  # type: ignore[index]
        mock.get(f"/ers/config/sgt/{_uuid(10)}").respond(
            json={"Sgt": {"id": _uuid(10), "name": "Employees", "value": 40}}
        )
        changed = await c.call_tool("ise_diff_config", {"before": "base.yaml"})
        assert changed.structured_content["sections"] == {  # type: ignore[index]
            "sgts": {"changed": {"Employees": {"value": {"from": 4, "to": 40}}}}
        }
        bad = await c.call_tool("ise_export_config", {"path": "../escape.yaml"}, raise_on_error=False)
        assert bad.is_error and "outside ISE_EXPORT_DIR" in bad.content[0].text  # type: ignore[union-attr]


def test_write_paths(tmp_path: Path) -> None:
    from ise_mcp.tools.config_export import write_export

    unconfined = make_settings()
    with pytest.raises(InvalidRequest, match="absolute path"):
        resolve_path(unconfined, "rel.yaml")
    with pytest.raises(InvalidRequest, match=".yaml or .yml"):
        resolve_path(unconfined, str(tmp_path / "x.txt"))
    other = tmp_path / "other.yaml"
    other.write_text("important: true\n")
    with pytest.raises(InvalidRequest, match="not overwriting"):
        write_export(unconfined, str(other), f"{HEADER}:\n  format: 1\n")
    assert other.read_text() == "important: true\n"
    out = write_export(unconfined, str(tmp_path / "e.yaml"), f"{HEADER}:\n  format: 1\n")
    assert write_export(unconfined, str(out), f"{HEADER}:\n  format: 1\n  sections: []\n") == out

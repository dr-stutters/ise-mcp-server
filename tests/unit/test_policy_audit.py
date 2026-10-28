"""ise_policy_audit / ise_unused_objects (I65) on the recorded policy fixtures, the recorded default
allowed-protocols service, and synthetic sets for each finding kind."""

from __future__ import annotations

import copy
import time
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from ise_mcp._core.testing import call_tool
from ise_mcp.tools.policy_audit import _ndg_terms, shadowed_by
from tests.unit import test_where_used as wu
from tests.unit.conftest import fixture_json, make_server
from tests.unit.test_where_used import DA, NA, attr

DEFAULT_AP = fixture_json("ers_allowedprotocols_default.json")["AllowedProtocols"]
CLEAN_AP = {
    "id": "ap2",
    "name": "Lab_Protocols",
    "processHostLookup": True,
    "allowPapAscii": False,
    "allowEapMd5": False,
    "allowLeap": False,
    "allowMsChapV1": False,
    "allowEapTls": True,
    "allowEapTtls": False,
    "eapTtls": {"eapTtlsMsChapV1": True},  # ignored: EAP-TTLS itself is off
    "allowWeakCiphersForEap": False,
    "requireMessageAuth": True,
}
DA_AP = {
    "id": "926901b0-8c01-11e6-996c-525400b48521",
    "name": "Default Device Admin",
    "allowPapAscii": True,
    "allowChap": True,
    "allowMsChapV1": True,
}


def emp() -> dict[str, Any]:
    return attr("IdentityGroup", "Name", "User Identity Groups:Employee")


def wired() -> dict[str, Any]:
    return attr("Radius", "NAS-Port-Type", "Ethernet")


def posture() -> dict[str, Any]:
    return attr("Session", "PostureStatus", "Compliant")


def and_(*children: dict[str, Any]) -> dict[str, Any]:
    return {"conditionType": "ConditionAndBlock", "isNegate": False, "children": list(children)}


def rule(
    rid: str, name: str, rank: int, cond: Any, *, hits: int = 5, state: str = "enabled", **kw: Any
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "rule": {
            "id": rid,
            "name": name,
            "rank": rank,
            "state": state,
            "default": kw.pop("default", False),
            "hitCounts": hits,
            "condition": cond,
        }
    }
    entry.update(kw)
    return entry


EMPTY_SET = {
    "id": "s-empty",
    "name": "Nowhere-Wired",
    "rank": 1,
    "state": "enabled",
    "default": False,
    "hitCounts": 10,
    "serviceName": "Default Network Access",
    "condition": attr("DEVICE", "Location", "All Locations#Nowhere"),
}
DISABLED_SET = {
    "id": "s-off",
    "name": "Old-VPN",
    "rank": 2,
    "state": "disabled",
    "default": False,
    "hitCounts": 0,
    "serviceName": "Lab_Protocols",
    "condition": attr("DEVICE", "Device Type", "All Device Types#VPN"),
}
SHADOWED_SET = {
    "id": "s-dup",
    "name": "Lab-Wired-Copy",
    "rank": 3,
    "state": "enabled",
    "default": False,
    "hitCounts": 0,
    "serviceName": "Lab_Protocols",
    "condition": copy.deepcopy(wu.LAB_SET["condition"]),
}
EMPTY_AUTHZ = [
    rule("e0", "Any-Employee", 0, emp()),
    rule("e1", "Employee-Wired", 1, and_(emp(), wired()), hits=0),
    rule("e2", "Same-As-First", 2, emp(), hits=1),
    rule("e3", "Posture-OK", 3, posture()),
    rule("e4", "Posture-OK-Wired", 4, and_(wired(), posture())),
    rule("e5", "Old", 5, wired(), state="disabled", hits=0),
    rule("e6", "Watch", 6, wired(), state="monitor", hits=0),
    rule("e9", "Default", 7, None, default=True, profile=["PermitAccess"]),
]
EMPTY_AUTHN = [
    rule(
        "a9",
        "Default",
        0,
        None,
        default=True,
        identitySourceName="All_User_ID_Stores",
        ifUserNotFound="CONTINUE",
    ),
]


@pytest.fixture
def ers(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[dict[str, Any]]]:
    data = copy.deepcopy(wu.ERS)
    data["allowedprotocols"] = [DEFAULT_AP, CLEAN_AP, DA_AP]
    data["authorizationprofile"].append({"id": "p4", "name": "Broken", "daclName": "GONE_DACL"})
    data["authorizationprofile"].append(
        {"id": "p5", "name": "Builtin_dACL", "daclName": "PERMIT_ALL_IPV4_TRAFFIC"}
    )
    data["downloadableacl"].append({"id": "d2", "name": "SPARE_DACL"})
    data["sgt"] += [{"id": "t2", "name": "Spare", "value": 99}, {"id": "t0", "name": "Unknown", "value": 0}]
    data["internaluser"] = [
        {"id": "u1", "name": "svc-backup", "enabled": True, "expiryDateEnabled": False},
        {
            "id": "u2",
            "name": "contractor",
            "enabled": True,
            "expiryDateEnabled": True,
            "expiryDate": "2027-01-01",
        },
        {"id": "u3", "name": "leaver", "enabled": False},
    ]
    data["networkdevicegroup"] += [
        {"id": "n2", "name": "Location#All Locations"},
        {"id": "n3", "name": "Device Type#All Device Types"},
    ]
    monkeypatch.setattr(wu, "ERS", data)
    return data


def mock_audit(mock: respx.MockRouter) -> None:
    wu.mock_policy(mock)
    sets = fixture_json("policy_sets.json")
    default = {**sets["response"][0], "rank": 4}
    lab = {**wu.LAB_SET, "default": False, "hitCounts": 7}
    mock.get(f"{NA}/policy-set").respond(
        json={"response": [lab, EMPTY_SET, DISABLED_SET, SHADOWED_SET, default]}
    )
    mock.get(f"{NA}/policy-set/s-empty/authentication").respond(json={"response": EMPTY_AUTHN})
    mock.get(f"{NA}/policy-set/s-empty/authorization").respond(json={"response": EMPTY_AUTHZ})
    for ps in ("s-empty", "s-off", "s-dup"):
        mock.get(f"{NA}/policy-set/{ps}/exception").respond(json={"response": []})
    for ps in ("s-off", "s-dup"):
        mock.get(f"{NA}/policy-set/{ps}/authentication").respond(json={"response": []})
        mock.get(f"{NA}/policy-set/{ps}/authorization").respond(json={"response": []})


async def audit(**args: Any) -> dict[str, Any]:
    out = await call_tool(make_server(), "ise_policy_audit", args)
    assert isinstance(out, dict)
    return out


def found(out: dict[str, Any], check: str) -> list[dict[str, Any]]:
    return [f for f in out["findings"] if f["check"] == check]


# --- pure helpers ---------------------------------------------------------------------------------


def test_shadowed_by_cases() -> None:
    earlier = [{"name": "A", "rank": 0, "condition": emp()}]
    assert shadowed_by(earlier, and_(wired(), emp()), {})[1:] == (  # type: ignore[index]
        "certain",
        "its conditions are a subset of this rule's AND-ed conditions",
    )
    assert shadowed_by(earlier, emp(), {})[2] == "it has the same condition"  # type: ignore[index]
    assert shadowed_by(earlier, wired(), {}) is None
    assert shadowed_by([{"name": "Any", "condition": None}], wired(), {})[2].startswith("it has no condition")  # type: ignore[index]
    # Order of AND children doesn't matter; an OR block is not a subset of its own children.
    assert shadowed_by([{"name": "B", "condition": and_(wired(), emp())}], and_(emp(), wired()), {})
    either = {"conditionType": "ConditionOrBlock", "isNegate": False, "children": [emp(), wired()]}
    assert shadowed_by([{"name": "B", "condition": and_(emp(), wired())}], either, {}) is None
    # A negated earlier condition is not the same as the plain one.
    neg = {**emp(), "isNegate": True}
    assert shadowed_by([{"name": "N", "condition": neg}], emp(), {}) is None


def test_shadow_behind_dynamic_condition_is_possible() -> None:
    lib = {
        "lc": {"id": "lc", "name": "Compliant", **posture(), "conditionType": "LibraryConditionAttributes"}
    }
    ref = {"conditionType": "ConditionReference", "id": "lc", "name": "Compliant", "isNegate": False}
    hit = shadowed_by([{"name": "P", "condition": ref}], and_(ref, wired()), lib)
    assert hit is not None and hit[1] == "possible"
    profiled = attr("IdentityGroup", "Name", "Endpoint Identity Groups:Profiled:Cisco-IP-Phone")
    assert shadowed_by([{"name": "Ph", "condition": profiled}], profiled, {})[1] == "possible"  # type: ignore[index]


def test_ndg_terms_required_and_optional() -> None:
    types = {"location", "device type"}
    loc = attr("DEVICE", "Location", "All Locations#Lab")
    either = {"conditionType": "ConditionOrBlock", "isNegate": False, "children": [loc, wired()]}
    assert _ndg_terms(and_(loc, wired()), {}, types) == [("Location", "equals", ["All Locations#Lab"], True)]
    assert _ndg_terms(either, {}, types)[0][3] is False
    assert _ndg_terms({**loc, "isNegate": True}, {}, types) == []
    assert _ndg_terms(attr("DEVICE", "Model Name", "C9300"), {}, types) == []


# --- the audit ------------------------------------------------------------------------------------


async def test_full_audit_ranks_findings(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    mock_audit(mock)
    out = await audit()
    sev = [f["severity"] for f in out["findings"]]
    assert sev == sorted(sev, key=["high", "medium", "low", "info"].index)
    assert set(out["by_check"]) == {
        "disabled",
        "zero_hits",
        "shadowed",
        "permissive_default",
        "weak_protocols",
        "dangling_dacl",
        "empty_ndg",
        "user_expiry",
    }
    assert out["summary"]["high"] >= 3 and "incomplete" not in out
    assert all(f["fix"]["tool"].startswith("ise_") for f in out["findings"])


async def test_disabled_and_zero_hits(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    mock_audit(mock)
    out = await audit(checks=["disabled", "zero_hits"])
    disabled = {(f["policy_set"], f.get("rule")) for f in found(out, "disabled")}
    assert ("Old-VPN", None) in disabled and ("Nowhere-Wired", "Old") in disabled
    assert ("Default", "Employee_EAP-TLS") in disabled  # the recorded default set's disabled rules
    zero = {(f["policy_set"], f.get("rule")) for f in found(out, "zero_hits")}
    assert ("Nowhere-Wired", "Employee-Wired") in zero
    assert ("Lab-Wired-Copy", None) in zero  # the set itself; a disabled set is not also zero_hits
    assert ("Old-VPN", None) not in zero
    assert not any(f.get("rule") in ("Watch", "Default") for f in found(out, "zero_hits"))
    fix = next(f for f in found(out, "disabled") if f.get("rule") == "Old")["fix"]
    assert fix["tool"] == "ise_update_policy_rule" and fix["args"]["state"] == "enabled"


async def test_shadowed_rules_and_sets(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    mock_audit(mock)
    out = await audit(checks=["shadowed"])
    rows = {
        (f["policy_set"], f.get("rule")): (f["shadowed_by"], f["certainty"]) for f in found(out, "shadowed")
    }
    assert rows == {
        ("Nowhere-Wired", "Employee-Wired"): ("Any-Employee", "certain"),
        ("Nowhere-Wired", "Same-As-First"): ("Any-Employee", "certain"),
        ("Nowhere-Wired", "Posture-OK-Wired"): ("Posture-OK", "possible"),
        ("Lab-Wired-Copy", None): ("Lab-Wired", "certain"),
    }
    one = next(f for f in found(out, "shadowed") if f.get("rule") == "Employee-Wired")
    assert one["severity"] == "medium" and one["fix"]["args"]["rank"] == 0


async def test_permissive_defaults(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    mock_audit(mock)
    out = await audit(checks=["permissive_default"])
    rows = {(f["policy_set"], f["where"], f["severity"]) for f in found(out, "permissive_default")}
    # The recorded Default set returns DenyAccess: not a finding.
    assert rows == {
        ("Nowhere-Wired", "authorization rule", "high"),
        ("Nowhere-Wired", "authentication rule", "medium"),
    }
    authz = next(f for f in found(out, "permissive_default") if f["where"] == "authorization rule")
    assert authz["fix"]["args"]["profiles"] == ["DenyAccess"]


async def test_weak_protocols_on_recorded_default_service(
    mock: respx.MockRouter, ers: dict[str, Any]
) -> None:
    mock_audit(mock)
    out = await audit(checks=["weak_protocols"])
    rows = {(f["service"], f["flag"]): f["severity"] for f in found(out, "weak_protocols")}
    assert rows == {
        ("Default Network Access", "allowEapMd5"): "high",
        ("Default Network Access", "allowPapAscii"): "medium",
        ("Default Network Access", "requireMessageAuth"): "medium",
        ("Default Network Access", "eapTtls.eapTtlsMsChapV1"): "low",
        ("Default Network Access", "eapTtls.eapTtlsEapMd5"): "low",
        ("Default Network Access", "eapTtls.eapTtlsPapAscii"): "low",
    }
    md5 = next(f for f in found(out, "weak_protocols") if f["flag"] == "allowEapMd5")
    assert md5["used_by"] == ["Nowhere-Wired", "Default"]
    assert md5["fix"]["tool"] == "ise_set_allowed_protocols" and "MAB" in md5["detail"]


async def test_dangling_dacl(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    mock_audit(mock)
    out = await audit(checks=["dangling_dacl"])
    assert [(f["profile"], f["field"]) for f in found(out, "dangling_dacl")] == [("Broken", "daclName")]
    assert found(out, "dangling_dacl")[0]["fix"] == {
        "tool": "ise_update_authz_profile",
        "args": {"profile": "Broken", "dacl": "<an existing dACL>"},
        "or": "ise_set_dacl to create 'GONE_DACL'",
    }


async def test_empty_ndg(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    mock_audit(mock)
    out = await audit(checks=["empty_ndg"])
    rows = [(f["policy_set"], f["device_group"], f["severity"]) for f in found(out, "empty_ndg")]
    # Lab-Wired has lab-sw1; the disabled Old-VPN set is skipped.
    assert rows == [("Nowhere-Wired", "Location#All Locations#Nowhere", "medium")]
    assert "no such device group exists" in found(out, "empty_ndg")[0]["detail"]


async def test_user_expiry(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    mock_audit(mock)
    out = await audit(checks=["user_expiry"])
    assert [f["user"] for f in found(out, "user_expiry")] == ["svc-backup"]
    assert found(out, "user_expiry")[0]["severity"] == "info"


async def test_one_policy_set(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    mock_audit(mock)
    out = await audit(policy_set="nowhere-wired")
    assert {f.get("policy_set") for f in out["findings"]} == {"Nowhere-Wired", None}
    assert {tuple(f["used_by"]) for f in found(out, "weak_protocols")} == {("Nowhere-Wired",)}
    assert "dangling_dacl" not in out["by_check"] and "user_expiry" not in out["by_check"]
    with pytest.raises(ToolError, match="No network-access policy set 'nope'"):
        await audit(policy_set="nope")


async def test_device_admin(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    wu.mock_policy(mock)
    tacacs = {
        "id": "da1",
        "name": "Switches",
        "rank": 0,
        "state": "enabled",
        "default": True,
        "hitCounts": 3,
        "serviceName": "Default Device Admin",
        "condition": None,
    }
    mock.get(f"{DA}/policy-set").respond(json={"response": [tacacs]})
    mock.get(f"{DA}/policy-set/da1/authentication").respond(json={"response": []})
    mock.get(f"{DA}/policy-set/da1/exception").respond(json={"response": []})
    mock.get(f"{DA}/policy-set/da1/authorization").respond(
        json={
            "response": [
                rule(
                    "t9",
                    "Default",
                    0,
                    None,
                    default=True,
                    commands=["PermitAllCommands"],
                    profile="Default Shell Profile",
                )
            ]
        }
    )
    out = await audit(kind="device-admin", checks=["permissive_default", "weak_protocols"])
    assert [(f["check"], f["severity"], f.get("flag")) for f in out["findings"]] == [
        ("permissive_default", "high", None),
        ("weak_protocols", "high", "allowMsChapV1"),  # TACACS+ PAP is not flagged
    ]
    assert out["findings"][0]["fix"]["args"]["command_sets"] == ["DenyAllCommands"]


async def test_unreadable_policy_is_incomplete(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    wu.mock_policy(mock, device_admin=500)
    out = await audit(kind="device-admin")
    assert out["count"] == 1 and out["findings"][0]["check"] == "user_expiry"
    assert any("device-admin policy sets not readable" in i for i in out["incomplete"])


async def test_scale_50_sets_by_30_rules(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    wu.mock_policy(mock)
    sets = [
        {
            "id": f"s{i}",
            "name": f"Set-{i}",
            "rank": i,
            "state": "enabled",
            "hitCounts": 1,
            "serviceName": "Lab_Protocols",
            "condition": attr("Radius", "Called-Station-ID", f"ssid-{i}"),
        }
        for i in range(50)
    ]
    mock.get(f"{NA}/policy-set").respond(json={"response": sets})
    rules = [
        rule(f"r{j}", f"Rule-{j}", j, attr("Radius", "NAS-Port-Id", f"Gi1/0/{j % 15}")) for j in range(30)
    ]
    route = mock.get(url__regex=rf".*{NA}/policy-set/s\d+/(authentication|authorization|exception)$").mock(
        side_effect=lambda request: httpx.Response(
            200, json={"response": rules if request.url.path.endswith("authorization") else []}
        )
    )
    t0 = time.perf_counter()
    out = await audit(checks=["shadowed", "zero_hits", "disabled"], limit=20)
    assert time.perf_counter() - t0 < 5
    assert route.call_count == 150  # each section read once
    assert out["by_check"] == {"shadowed": 50 * 15}  # rules 15..29 repeat 0..14
    assert len(out["findings"]) == 20 and "of 750 findings" in out["truncated"]


# --- unused objects -------------------------------------------------------------------------------


async def test_unused_objects(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    wu.mock_policy(mock)
    out = await call_tool(make_server(), "ise_unused_objects", {"kinds": ["dacl", "sgt", "authz_profile"]})
    assert isinstance(out, dict)
    assert [r["name"] for r in out["unused"]["dacl"]] == ["SPARE_DACL"]
    assert [r["name"] for r in out["unused"]["sgt"]] == ["Spare"]
    assert out["built_in_unused"]["sgt"] == ["Unknown"]
    assert [r["name"] for r in out["unused"]["authz_profile"]] == ["Other", "Broken", "Builtin_dACL"]
    assert out["counts"]["dacl"] == {"checked": 2, "unused": 1}
    assert out["unused"]["dacl"][0]["fix"] == {
        "tool": "ise_delete_object",
        "args": {"kind": "dacl", "target": "SPARE_DACL"},
    }
    assert any(n.startswith("sgt:") for n in out["not_checked"])


async def test_unused_reads_policy_once(mock: respx.MockRouter, ers: dict[str, Any]) -> None:
    wu.mock_policy(mock)
    sets = mock.get(f"{NA}/policy-set").respond(json=fixture_json("policy_sets.json"))
    out = await call_tool(
        make_server(),
        "ise_unused_objects",
        {"kinds": ["identity_group", "endpoint_group"], "include_builtin": True},
    )
    assert isinstance(out, dict)
    assert sets.call_count == 1
    assert "Employee" not in [
        r["name"] for r in out.get("unused", {}).get("identity_group", [])
    ]  # a library condition uses it
    assert "Cisco-IP-Phone" not in [r["name"] for r in out.get("unused", {}).get("endpoint_group", [])]

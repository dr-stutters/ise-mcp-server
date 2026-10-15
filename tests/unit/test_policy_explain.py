from __future__ import annotations

import json
from typing import Any

import respx
from stutters_mcp_core.testing import call_tool

from ise_mcp.tools.policy_explain import eval_operator, evaluate
from tests.unit.conftest import make_server


def attr(dn: str, an: str, op: str, val: str, negate: bool = False) -> dict[str, Any]:
    return {
        "conditionType": "ConditionAttributes",
        "isNegate": negate,
        "dictionaryName": dn,
        "attributeName": an,
        "operator": op,
        "attributeValue": val,
    }


def block(kind: str, *children: dict[str, Any], negate: bool = False) -> dict[str, Any]:
    return {"conditionType": f"Condition{kind}Block", "isNegate": negate, "children": list(children)}


def test_eval_operator() -> None:
    assert eval_operator("equals", "Ethernet", "ethernet") is True
    assert eval_operator("notEquals", "Ethernet", "Wireless") is True
    assert eval_operator("startsWith", "mcp-test-x", "mcp-test-") is True
    assert eval_operator("endsWith", "host.corp", ".corp") is True
    assert eval_operator("contains", "abc", "b") is True
    assert eval_operator("in", "b", "a,b,c") is True and eval_operator("in", "z", "a,b") is False
    assert eval_operator("greaterThan", "10", "5") is True
    assert eval_operator("greaterThan", "x", "5") is None  # non-numeric -> unknown
    assert eval_operator("matches", "mcp-99", r"mcp-\d+") is True
    assert eval_operator("someFutureOp", "a", "b") is None


def test_evaluate_and_or_negate() -> None:
    attrs = {"Radius:NAS-Port-Type": "Ethernet", "DEVICE:Location": "All Locations#mcp-test-lab"}
    and_cond = block(
        "And",
        attr("DEVICE", "Location", "equals", "All Locations#mcp-test-lab"),
        attr("Radius", "NAS-Port-Type", "equals", "Ethernet"),
    )
    assert evaluate(and_cond, attrs, {}) is True
    # one child false -> AND false
    and_cond["children"][1]["attributeValue"] = "Wireless"
    assert evaluate(and_cond, attrs, {}) is False
    # OR with a true child -> true even if another is unknown
    or_cond = block(
        "Or",
        attr("Radius", "Service-Type", "equals", "Call Check"),  # not supplied -> unknown
        attr("Radius", "NAS-Port-Type", "equals", "Ethernet"),  # true
    )
    assert evaluate(or_cond, attrs, {}) is True
    # negate flips a known result
    assert evaluate(attr("Radius", "NAS-Port-Type", "equals", "Ethernet", negate=True), attrs, {}) is False


def test_evaluate_unknown_when_attr_missing_or_ref_unresolved() -> None:
    attrs = {"Radius:NAS-Port-Type": "Ethernet"}
    assert evaluate(attr("Session", "PostureStatus", "equals", "Compliant"), attrs, {}) is None
    ref = {"conditionType": "ConditionReference", "name": "Wired_MAB", "id": "ref1"}
    assert evaluate(ref, attrs, {}) is None  # library not provided
    # resolve the reference
    lib = {"ref1": attr("Radius", "NAS-Port-Type", "equals", "Ethernet")}
    assert evaluate(ref, attrs, lib) is True
    assert evaluate(None, attrs, {}) is True  # DEFAULT / ANY


def _mock_policy(mock: respx.MockRouter) -> None:
    sets = {
        "response": [
            {
                "id": "s-dis",
                "name": "disabled-set",
                "rank": 0,
                "state": "disabled",
                "default": False,
                "condition": attr("Radius", "NAS-Port-Type", "equals", "Ethernet"),
            },
            {
                "id": "s-wired",
                "name": "mcp-test-wired",
                "rank": 1,
                "state": "enabled",
                "default": False,
                "condition": block("And", attr("Radius", "NAS-Port-Type", "equals", "Ethernet")),
            },
            {
                "id": "s-def",
                "name": "Default",
                "rank": 2,
                "state": "enabled",
                "default": True,
                "condition": None,
            },
        ]
    }
    mock.get("/api/v1/policy/network-access/policy-set").respond(json=sets)
    mock.get("/api/v1/policy/network-access/condition").respond(json={"response": []})
    mock.get("/api/v1/policy/network-access/policy-set/global-exception").respond(json={"response": []})
    authz = {
        "response": [
            {
                "rule": {
                    "id": "r-posture",
                    "name": "posture-rule",
                    "rank": 0,
                    "state": "enabled",
                    "default": False,
                    "condition": attr("Session", "PostureStatus", "equals", "Compliant"),
                },
                "profile": ["PostureRemediation"],
                "securityGroup": None,
            },
            {
                "rule": {
                    "id": "r-mab",
                    "name": "mab-permit",
                    "rank": 1,
                    "state": "enabled",
                    "default": False,
                    "condition": attr("IdentityGroup", "Name", "equals", "mcp-test-endpoints"),
                },
                "profile": ["mcp-test-permit"],
                "securityGroup": "Employees",
            },
            {
                "rule": {
                    "id": "r-def",
                    "name": "Default",
                    "rank": 2,
                    "state": "enabled",
                    "default": True,
                    "condition": None,
                },
                "profile": ["DenyAccess"],
                "securityGroup": None,
            },
        ]
    }
    for section in ("authentication", "authorization", "exception"):
        body = authz if section == "authorization" else {"response": []}
        mock.get(f"/api/v1/policy/network-access/policy-set/s-wired/{section}").respond(json=body)


async def test_policy_explain_matches_rule(mock: respx.MockRouter) -> None:
    _mock_policy(mock)
    out = await call_tool(
        make_server(),
        "ise_policy_explain",
        {
            "attributes": {
                "Radius:NAS-Port-Type": "Ethernet",
                "IdentityGroup:Name": "mcp-test-endpoints",
            }
        },
    )
    out = out if isinstance(out, dict) else json.loads(str(out))
    assert out["policy_set"] == "mcp-test-wired"
    assert "mab-permit" in out["verdict"] and "mcp-test-permit" in out["verdict"]
    # the posture rule outranks it and is unknown -> result is flagged uncertain
    assert out["note"] and "UNCERTAIN" in out["note"]
    posture = next(r for r in out["authorization"] if r["name"] == "posture-rule")
    assert posture["result"] == "unknown" and posture["unknown_because"]


async def test_policy_explain_default_set_and_rule(mock: respx.MockRouter) -> None:
    _mock_policy(mock)
    # attributes that match neither posture nor the mab group -> falls to Default DenyAccess.
    mock.get("/api/v1/policy/network-access/policy-set/s-def/authorization").respond(
        json={
            "response": [
                {
                    "rule": {
                        "id": "d",
                        "name": "Default",
                        "default": True,
                        "rank": 0,
                        "state": "enabled",
                        "condition": None,
                    },
                    "profile": ["DenyAccess"],
                }
            ]
        }
    )
    mock.get("/api/v1/policy/network-access/policy-set/s-def/authentication").respond(json={"response": []})
    mock.get("/api/v1/policy/network-access/policy-set/s-def/exception").respond(json={"response": []})
    out = await call_tool(
        make_server(),
        "ise_policy_explain",
        {"attributes": {"Radius:NAS-Port-Type": "Wireless"}, "policy_set": "Default"},
    )
    out = out if isinstance(out, dict) else json.loads(str(out))
    assert out["policy_set"] == "Default"
    assert "DenyAccess" in out["verdict"]


def test_evaluate_unknown_for_attr_vs_attr_and_missing_value() -> None:
    attrs = {"Radius:Called-Station-ID": "aa", "Radius:Calling-Station-ID": "aa"}
    # dictionaryValue set => compare against another attribute, not a literal => unknown
    cond = attr("Radius", "Called-Station-ID", "equals", "")
    cond["attributeValue"] = None
    cond["dictionaryValue"] = "Radius:Calling-Station-ID"
    assert evaluate(cond, attrs, {}) is None
    # no literal and no dictionaryValue => unknown, never the string "None"
    bare = attr("Radius", "Called-Station-ID", "equals", "")
    bare["attributeValue"] = None
    assert evaluate(bare, attrs, {}) is None


async def test_policy_explain_no_set_matched_is_uncertain(mock: respx.MockRouter) -> None:
    # One enabled set with an unknown condition and no default set -> uncertain, not a flat "no match".
    sets = {
        "response": [
            {
                "id": "s1",
                "name": "only-set",
                "rank": 0,
                "state": "enabled",
                "default": False,
                "condition": attr("Session", "PostureStatus", "equals", "Compliant"),
            }
        ]
    }
    mock.get("/api/v1/policy/network-access/policy-set").respond(json=sets)
    mock.get("/api/v1/policy/network-access/condition").respond(json={"response": []})
    out = await call_tool(
        make_server(), "ise_policy_explain", {"attributes": {"Radius:NAS-Port-Type": "Ethernet"}}
    )
    out = out if isinstance(out, dict) else json.loads(str(out))
    assert "confirmed to match" in out["verdict"]
    assert out["note"] and "UNCERTAIN" in out["note"]


async def test_policy_explain_global_exception_wins(mock: respx.MockRouter) -> None:
    _mock_policy(mock)
    # a global exception that matches the request should win over the set's own rules
    mock.get("/api/v1/policy/network-access/policy-set/global-exception").respond(
        json={
            "response": [
                {
                    "rule": {
                        "id": "g1",
                        "name": "block-byod",
                        "rank": 0,
                        "state": "enabled",
                        "default": False,
                        "condition": attr("IdentityGroup", "Name", "equals", "BYOD"),
                    },
                    "profile": ["DenyAccess"],
                    "securityGroup": None,
                }
            ]
        }
    )
    out = await call_tool(
        make_server(),
        "ise_policy_explain",
        {"attributes": {"Radius:NAS-Port-Type": "Ethernet", "IdentityGroup:Name": "BYOD"}},
    )
    out = out if isinstance(out, dict) else json.loads(str(out))
    assert "block-byod" in out["verdict"] and "DenyAccess" in out["verdict"]
    first = out["authorization"][0]
    assert first["section"] == "global-exception" and first["result"] == "match"

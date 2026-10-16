from __future__ import annotations

import json

import respx

from ise_mcp._core.testing import call_tool
from tests.unit.conftest import ers_page, make_server


def _out(o: object) -> dict:  # type: ignore[type-arg]
    return o if isinstance(o, dict) else json.loads(str(o))


async def test_list_profiler_profiles_name_filter(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/profilerprofile", params={"filter": "name.CONTAINS.Cisco"}).respond(
        json=ers_page(
            [
                {"id": "1", "name": "Cisco-Device", "description": "Policy for Cisco-Device"},
                {"id": "2", "name": "Cisco-IP-Phone", "description": "Policy for Cisco IP Phones"},
            ]
        )
    )
    out = _out(
        await call_tool(
            make_server(),
            "ise_list_profiler_profiles",
            {"name": "Cisco", "response_format": "json"},
        )
    )
    names = [r["name"] for r in out["results"]]
    assert names == ["Cisco-Device", "Cisco-IP-Phone"]


async def test_list_posture_policies(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/posture/policy").respond(
        json={
            "response": [
                {
                    "id": "p1",
                    "name": "AV_Win",
                    "enable": True,
                    "osNameList": ["Windows All"],
                    "postureType": "Agent",
                    "complianceModule": "4.x",
                    "requirementList": [{"id": "r1", "enforcement": "MANDATORY"}],
                    "roleList": [{"id": "g1"}],
                },
                {
                    "id": "p2",
                    "name": "AV_Mac_disabled",
                    "enable": False,
                    "osNameList": ["Mac OSX"],
                    "postureType": "Temporal Agent",
                    "requirementList": [],
                },
            ]
        }
    )
    out = _out(await call_tool(make_server(), "ise_list_posture_policies", {"response_format": "json"}))
    assert {r["name"] for r in out["results"]} == {"AV_Win", "AV_Mac_disabled"}
    win = next(r for r in out["results"] if r["name"] == "AV_Win")
    assert win["enabled"] is True and win["requirements"] == 1 and win["enforcement"] == ["MANDATORY"]
    # enabled_only drops the disabled one
    out2 = _out(
        await call_tool(
            make_server(), "ise_list_posture_policies", {"enabled_only": True, "response_format": "json"}
        )
    )
    assert [r["name"] for r in out2["results"]] == ["AV_Win"]


async def test_list_posture_requirements(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/posture/requirement").respond(
        json={
            "response": [
                {
                    "id": "rq1",
                    "name": "AM_Def_Win",
                    "osNameList": ["Windows All"],
                    "postureType": "Agent",
                    "ruleList": [{"name": "am_win"}],
                    "conditionEvaluationOption": "ALL_SUCCEED",
                    "remediation": {"name": "Message Text Only"},
                }
            ]
        }
    )
    out = _out(await call_tool(make_server(), "ise_list_posture_requirements", {"response_format": "json"}))
    row = out["results"][0]
    assert row["name"] == "AM_Def_Win" and row["rules"] == ["am_win"]
    assert row["evaluation"] == "ALL_SUCCEED" and row["remediation"] == "Message Text Only"

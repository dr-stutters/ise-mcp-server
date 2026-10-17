from __future__ import annotations

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from ise_mcp._core.testing import call_tool
from tests.unit.conftest import MISSING_SESSION, ers_page, fixture_json, fixture_text, make_server, xml


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


# --- profiler (I40) ------------------------------------------------------------------------------

MAC = "02:00:5E:00:00:01"
PROFILED = "02:00:5E:00:00:10"
IPHONE = "0ac944f0-8c00-11e6-996c-525400b48521"
APPLE = "09663280-8c00-11e6-996c-525400b48521"

RULE = {
    "policyId": "r-1",
    "name": "mcp-prof-printers",
    "status": True,
    "rulePriority": 20,
    "profilingType": "CUSTOM",
    "condition": {
        "conditionType": "ConditionAttributes",
        "isNegate": False,
        "dictionaryName": "DHCP",
        "attributeName": "dhcpClassIdentifier",
        "operator": "contains",
        "attributeValue": "Hewlett-Packard",
    },
    "profileLabel": {
        "MFCInfoEndpointType": ["Printer"],
        "MFCInfoHardwareManufacturer": ["HP"],
        "MFCInfoHardwareModel": [],
        "MFCInfoOperatingSystem": [],
    },
    "matchedEndpoints": 3,
}
PHONE_RULE = {
    **RULE,
    "policyId": "r-2",
    "name": "mcp-prof-phones",
    "rulePriority": 10,
    "profileLabel": {"MFCInfoEndpointType": ["Mobile Phone"]},
    "matchedEndpoints": 1,
}


async def two_step(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(server) as c:
        preview = (await c.call_tool(name, args)).structured_content
        if preview.get("status") != "preview":
            return preview, None
        applied = (await c.call_tool(name, {**args, "confirm": preview["confirm"]})).structured_content
        return preview, applied


def _chain(mock: respx.MockRouter) -> None:
    mock.get(f"/ers/config/profilerprofile/{IPHONE}").respond(
        json={"ProfilerProfile": {"id": IPHONE, "name": "Apple-iPhone", "parentId": APPLE}}
    )
    mock.get(f"/ers/config/profilerprofile/{APPLE}").respond(
        json={"ProfilerProfile": {"id": APPLE, "name": "Apple-Device", "description": "Generic"}}
    )


async def test_list_profiling_rules(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/profiler/policy").respond(json=[RULE, PHONE_RULE])
    out = _out(await call_tool(make_server(), "ise_list_profiling_rules", {"response_format": "json"}))
    rows = out["results"]
    assert [r["name"] for r in rows] == ["mcp-prof-phones", "mcp-prof-printers"]  # by priority
    printers = rows[1]
    assert printers["condition"] == "DHCP:dhcpClassIdentifier contains Hewlett-Packard"
    assert printers["labels"] == {"endpoint_type": ["Printer"], "manufacturer": ["HP"]}
    assert printers["matched_endpoints"] == 3 and printers["id"] == "r-1"


async def test_profiler_status(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(
        json={
            "response": [
                {"hostname": "psn1", "roles": ["Standalone"], "services": ["Session", "Profiler"]},
                {"hostname": "pxg1", "roles": [], "services": ["pxGrid"]},
            ]
        }
    )
    mock.get("/api/v1/profile/psn1").respond(json=fixture_json("profiler_probe_config.json"))
    mock.get("/admin/API/mnt/Session/ProfilerCount").respond(
        text=xml("<sessionCount><count>5</count></sessionCount>")
    )
    mock.get("/api/v1/profiler/policy").respond(json=[RULE])
    mock.get("/api/v1/profiler/cloud/connection").respond(
        json={"deploymentId": None, "region": None, "status": None, "telemetryEnabled": True}
    )
    out = _out(await call_tool(make_server(), "ise_profiler_status", {}))
    (psn,) = out["profiler_nodes"]
    assert psn["node"] == "psn1"
    assert set(psn["enabled"]) == {"radius", "dhcp", "nmap", "snmpQuery", "activeDirectory"}
    assert psn["enabled"]["radius"] == "on" and psn["enabled"]["dhcp"]["port"] == 67
    assert set(psn["disabled"]) == {"dhcpSpan", "http", "dns", "netflow", "snmpTrap", "pxgrid"}
    assert out["nodes_without_profiler_service"] == ["pxg1"]
    assert out["profiler_sessions"] == "5"
    assert out["custom_profiling_rules"] == {"total": 1, "enabled": 1}
    assert out["cloud_profiler"]["registered"] is False and out["cloud_profiler"]["telemetry_enabled"]
    assert "FeedService" in out["feed_service"]


async def test_explain_profile_matched_policy_and_chain(mock: respx.MockRouter) -> None:
    mock.get(f"/api/v1/endpoint/{PROFILED}").respond(json=fixture_json("openapi_endpoint_profiled.json"))
    mock.get(f"/admin/API/mnt/Session/MACAddress/{PROFILED}").respond(500, text=MISSING_SESSION)
    mock.get("/api/v1/profiler/policy").respond(json=[RULE, PHONE_RULE])
    _chain(mock)
    out = _out(await call_tool(make_server(), "ise_explain_profile", {"mac": "0200.5e00.0010"}))
    assert out["profile"] == "Apple-iPhone"
    assert out["policy_chain"] == ["Apple-iPhone", "Apple-Device"]
    assert out["labels"] == {"endpoint_type": ["Mobile Phone"], "manufacturer": ["Apple Inc."], "os": ["iOS"]}
    assert out["endpoint_attributes"] == {"ipAddress": "192.0.2.77"}
    assert [r["name"] for r in out["custom_rules_with_its_labels"]] == ["mcp-prof-phones"]
    assert any("Apple-iPhone (under Apple-Device)" in w for w in out["why"])
    assert out["last_session"] == "no session in MnT"
    assert "TotalCertaintyFactor" in out["not_available_over_rest"]


async def test_explain_profile_unknown_with_session(mock: respx.MockRouter) -> None:
    ep = {**fixture_json("openapi_endpoint_profiled.json"), "mac": MAC, "profileId": ""}
    ep.update(mfcInfoOperatingSystem=None, mfcInfoEndpointType=None, mfcInfoHardwareManufacturer=None)
    mock.get(f"/api/v1/endpoint/{MAC}").respond(json=ep)
    mock.get(f"/admin/API/mnt/Session/MACAddress/{MAC}").respond(text=fixture_text("mnt_session.xml"))
    mock.get("/api/v1/profiler/policy").respond(json=[])
    out = _out(await call_tool(make_server(), "ise_explain_profile", {"mac": MAC}))
    assert out["profile"] == "Unknown (not profiled)" and "policy_chain" not in out
    assert out["last_session"]["endpoint_policy"] == "Unknown"
    assert out["last_session"]["profile_sent_to_nad"] == "Unknown"
    assert any("ise_profiler_status" in w for w in out["why"])


async def test_explain_profile_static_and_missing(mock: respx.MockRouter) -> None:
    ep = {**fixture_json("openapi_endpoint_profiled.json"), "staticProfileAssignment": True}
    mock.get(f"/api/v1/endpoint/{PROFILED}").respond(json=ep)
    mock.get(f"/admin/API/mnt/Session/MACAddress/{PROFILED}").respond(500, text=MISSING_SESSION)
    mock.get("/api/v1/profiler/policy").respond(json=[])
    _chain(mock)
    out = _out(await call_tool(make_server(), "ise_explain_profile", {"mac": PROFILED}))
    assert out["static_profile_assignment"] is True
    assert any("statically" in w for w in out["why"])

    mock.get(f"/api/v1/endpoint/{MAC}").respond(404, json={"message": "not found"})
    mock.get(f"/admin/API/mnt/Session/MACAddress/{MAC}").respond(500, text=MISSING_SESSION)
    out = _out(await call_tool(make_server(), "ise_explain_profile", {"mac": MAC}))
    assert out["endpoint"] == "not in the ISE endpoint database"


async def test_set_profiling_rule_create(mock: respx.MockRouter) -> None:
    created = {**RULE, "name": "mcp-prof-new", "policyId": "r-9", "matchedEndpoints": 0}
    mock.get("/api/v1/profiler/policy", params={"name": "mcp-prof-new"}).mock(
        side_effect=[
            httpx.Response(200, json=[]),  # preview
            httpx.Response(200, json=[]),  # confirm (re-plans)
            httpx.Response(200, json=[created]),  # read back after the POST
        ]
    )
    mock.get("/api/v1/profiler/endpoint-custom-dictionary").respond(
        json=fixture_json("profiler_custom_dictionary.json")
    )
    mock.get("/api/v1/profiler/policy", params={}).respond(json=[RULE, PHONE_RULE])  # for the priority
    post = mock.post("/api/v1/profiler/policy").respond(200, text="created")
    args = {
        "name": "mcp-prof-new",
        "conditions": ["dhcp:DHCPCLASSIDENTIFIER contains Hewlett-Packard", "MAC:oui contains HP"],
        "endpoint_type": ["Printer"],
        "manufacturer": ["HP"],
    }
    preview, applied = await two_step("ise_set_profiling_rule", args)
    assert preview["status"] == "preview", preview
    assert preview["preview"]["condition"] == (
        "(DHCP:dhcpClassIdentifier contains Hewlett-Packard AND MAC:oui contains HP)"
    )
    sent = json.loads(post.calls.last.request.content)
    assert isinstance(sent, list) and sent[0]["profilingType"] == "CUSTOM" and sent[0]["status"] is True
    assert sent[0]["profileLabel"] == {
        "MFCInfoEndpointType": ["Printer"],
        "MFCInfoHardwareManufacturer": ["HP"],
        "MFCInfoHardwareModel": [],
        "MFCInfoOperatingSystem": [],
    }
    assert sent[0]["condition"]["conditionType"] == "ConditionAndBlock"
    assert sent[0]["rulePriority"] == 30  # after the existing rules (20)
    assert applied["result"]["id"] == "r-9"


async def test_set_profiling_rule_unknown_attribute_blocks(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/profiler/policy", params={"name": "mcp-prof-bad"}).respond(json=[])
    mock.get("/api/v1/profiler/policy", params={}).respond(json=[])
    mock.get("/api/v1/profiler/endpoint-custom-dictionary").respond(
        json=fixture_json("profiler_custom_dictionary.json")
    )
    preview, _ = await two_step(
        "ise_set_profiling_rule",
        {"name": "mcp-prof-bad", "conditions": ["DHCP:classid contains x"], "endpoint_type": ["Printer"]},
    )
    assert preview["status"] == "blocked"
    assert "DHCP has no attribute 'classid'" in preview["blockers"][0]
    preview, _ = await two_step(
        "ise_set_profiling_rule",
        {"name": "mcp-prof-bad", "conditions": ["Radius:NAS-Port-Type equals x"], "os": ["iOS"]},
    )
    assert "dictionary 'Radius'" in preview["blockers"][0] or "RADIUS has no" in preview["blockers"][0]


async def test_set_profiling_rule_update(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/profiler/policy", params={"name": "mcp-prof-printers"}).respond(json=[RULE])
    put = mock.put("/api/v1/profiler/policy").respond(200, text="updated")
    preview, applied = await two_step(
        "ise_set_profiling_rule", {"name": "mcp-prof-printers", "model": ["LaserJet"], "enabled": False}
    )
    changes = preview["preview"]["changes"]
    assert changes["status"] == {"from": True, "to": False}
    assert changes["profileLabel.MFCInfoHardwareModel"]["to"] == ["LaserJet"]
    assert "3 endpoint(s)" in preview["side_effects"][0]
    sent = json.loads(put.calls.last.request.content)
    assert sent[0]["policyId"] == "r-1" and "matchedEndpoints" not in sent[0]
    assert sent[0]["profileLabel"]["MFCInfoEndpointType"] == ["Printer"]  # untouched label kept
    assert applied["status"] == "applied"


async def test_set_profiling_rule_refuses_non_custom(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/profiler/policy", params={"name": "ml-rule"}).respond(
        json=[{**RULE, "name": "ml-rule", "profilingType": "ML"}]
    )
    preview, _ = await two_step("ise_set_profiling_rule", {"name": "ml-rule", "enabled": False})
    assert preview["status"] == "blocked" and "only CUSTOM" in preview["blockers"][0]


async def test_delete_profiling_rule(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/profiler/policy", params={"name": "mcp-prof-printers"}).respond(json=[RULE])
    delete = mock.delete("/api/v1/profiler/policy").respond(200, text="deleted")
    preview, applied = await two_step("ise_delete_profiling_rule", {"name": "mcp-prof-printers"})
    assert preview["blast_radius"] == 3 and "lose its labels" in preview["side_effects"][0]
    assert json.loads(delete.calls.last.request.content) == ["r-1"]
    assert applied["result"] == {"deleted": "mcp-prof-printers", "id": "r-1"}


async def test_reprofile_endpoint(mock: respx.MockRouter) -> None:
    mock.get(f"/admin/API/mnt/Session/MACAddress/{MAC}").respond(text=fixture_text("mnt_session.xml"))
    ep = {**fixture_json("openapi_endpoint_profiled.json"), "mac": MAC}
    mock.get(f"/api/v1/endpoint/{MAC}").respond(json=ep)
    _chain(mock)
    coa = mock.get(f"/admin/API/mnt/CoA/Reauth/ise/{MAC}/0").respond(
        text=xml('<remoteCoA requestType="reauth"><results>true</results></remoteCoA>')
    )
    preview, applied = await two_step("ise_reprofile_endpoint", {"mac": "02-00-5e-00-00-01"})
    assert preview["preview"]["current_profile"] == "Apple-iPhone"
    assert preview["preview"]["profile_at_last_auth"] == "Unknown"
    assert preview["preview"]["acs_server"] == "ise"
    assert (
        applied["result"]["coa_acknowledged"] is True
        and "ise_explain_profile" in applied["result"]["next_step"]
    )
    assert coa.called


async def test_reprofile_needs_dangerous_tier() -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_reprofile_endpoint" not in names
    assert {"ise_set_profiling_rule", "ise_delete_profiling_rule", "ise_explain_profile"} <= names


async def test_captured_rule_shape(mock: respx.MockRouter) -> None:
    """A rule as ISE 3.5 returns it (no isNegate, null labels): listed and updated cleanly."""
    (captured,) = fixture_json("profiler_rules.json")
    mock.get("/api/v1/profiler/policy", params={"name": "mcp-prof-captured"}).respond(json=[captured])
    mock.get("/api/v1/profiler/policy", params={}).respond(json=[captured])
    out = _out(await call_tool(make_server(), "ise_list_profiling_rules", {"response_format": "json"}))
    (row,) = out["results"]
    assert row["labels"] == {"endpoint_type": ["mcp-prof-test"], "os": ["mcp-prof-os"]}
    assert row["condition"].startswith("(MAC:oui contains") and "matched_endpoints" not in row
    put = mock.put("/api/v1/profiler/policy").respond(200, text="ok")
    preview, _ = await two_step("ise_set_profiling_rule", {"name": "mcp-prof-captured", "enabled": True})
    assert preview["preview"]["changes"] == {"status": {"from": False, "to": True}}
    sent = json.loads(put.calls.last.request.content)[0]
    assert sent["condition"] == captured["condition"] and sent["policyId"] == captured["policyId"]

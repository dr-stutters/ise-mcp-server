"""I61 (#102): profiler endpoint SNMP scans (respx). The lab ISE 3.5 answered `GET /scan` with a bare `[]` and
`GET /psn-groups` with `{"psnGroups": [], "psns": [<fqdn>]}` (2026-10-28); the scan entities, history rows
and action results below follow the 3.5 OpenAPI 'Profiler' group (EndPointSNMPScanEntity,
SNMPScanAttributes, ScanHistory, SNMPScanResponseWrapper). Addresses are documentation ranges."""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ise_mcp._core.testing import call_tool
from ise_mcp.tools.snmp_scan import build_schedule, parse_targets, scan_enabled, scan_running, scope_size
from tests.unit.conftest import make_server

SCANS = "/api/v1/profiler/snmp/scan"
PSN = "psn1.example.com"
COMMUNITY = "Iot-Comm-2026"
ENV = "ISE_SNMP_COMMUNITY"
SID = "6f1b8c2e-0000-4000-8000-000000000001"


def scan(**over: Any) -> dict[str, Any]:
    details: dict[str, Any] = {
        "id": SID,
        "name": "mcp-iot-printers",
        "description": "printers",
        "isEnabled": True,
        "scanSource": PSN,
        "networkScope": {
            "subnets": [{"subnetIp": "192.0.2.0", "mask": 24}],
            "ipRanges": [],
            "excludedIps": [],
        },
        "scheduleTime": {"scheduleType": "NO_SCHEDULE"},
        "snmpAuthData": [{"snmpVersion": "snmpV2", "roCommunity": "******"}],
    }
    details.update(over)
    return {
        "id": details["id"],
        "name": details["name"],
        "jobStatus": "COMPLETED",
        "scanStatus": details["isEnabled"],
        "scanStartTime": 1793170800000,
        "scanEndTime": 1793170860000,
        "scannedIp": 254,
        "discoveredIp": 3,
        "scanDetails": details,
        "history": [],
    }


HISTORY = [
    {
        "scanHistoryID": "h1",
        "scanTime": 1793170800000,
        "scanResult": "SUCCESS",
        "psnFqdn": PSN,
        "scannedIp": 254,
        "discovered": 3,
        "ipNotReachable": 251,
        "snmpAuthFailed": 0,
        "snmpNullResponse": 0,
        "scanErrorDetails": [],
    },
    {
        "scanHistoryID": "h0",
        "scanTime": 1793084400000,
        "scanResult": "FAILURE",
        "psnFqdn": PSN,
        "scannedIp": 254,
        "discovered": 0,
        "ipNotReachable": 250,
        "snmpAuthFailed": 4,
        "snmpNullResponse": 0,
        "scanErrorDetails": ["SNMP authentication failed for 192.0.2.20"],
    },
]


def base(mock: respx.MockRouter, scans: list[dict[str, Any]]) -> None:
    mock.get(SCANS).respond(json=scans)
    mock.get("/api/v1/profiler/snmp/psn-groups").respond(json={"psnGroups": [], "psns": [PSN]})


async def two_step(tool: str, args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    server = make_server(mcp_enable_writes=True)
    async with Client(server) as c:
        preview = (await c.call_tool(tool, args)).structured_content
        assert preview is not None
        if preview.get("status") != "preview":
            return preview, None
        done = (await c.call_tool(tool, {**args, "confirm": preview["confirm"]})).structured_content
        return preview, done


# --- helpers --------------------------------------------------------------------------------------


def test_parse_targets_forms() -> None:
    subnets, ranges = parse_targets(["192.0.2.0/24", "198.51.100.7"])
    assert subnets == [{"subnetIp": "192.0.2.0", "mask": 24}, {"subnetIp": "198.51.100.7", "mask": 32}]
    assert ranges == []
    subnets, ranges = parse_targets(["192.0.2.10-192.0.2.20", "192.0.2.30"])
    assert subnets == [] and ranges[-1] == {"startIp": "192.0.2.30", "endIp": "192.0.2.30"}
    assert scope_size({"ipRanges": ranges, "excludedIps": ["192.0.2.11"]}) == 11


@pytest.mark.parametrize(
    "targets, words",
    [
        (["192.0.2.0/24", "192.0.2.10-192.0.2.20"], "not both"),
        (["10.0.0.0/16"], "/21 or smaller"),
        (["printer.example.com"], "is not a subnet"),
        (["192.0.2.20-192.0.2.10"], "is not a subnet"),
    ],
)
def test_parse_targets_refuses(targets: list[str], words: str) -> None:
    with pytest.raises(Exception, match=words):
        parse_targets(targets)


def test_schedule_forms() -> None:
    assert build_schedule("daily", "2:30 AM", None) == ({"scheduleType": "DAILY", "time": "02:30 am"}, [])
    assert build_schedule("weekly", "11:00 pm", "monday")[0]["time"] == "Monday 11:00 pm"
    assert build_schedule("monthly", "01:00 am", "15")[0]["time"] == "15 01:00 am"
    assert build_schedule("weekly", "11:00 pm", None)[1]
    assert build_schedule("daily", "23:00", None)[1]


# --- ise_snmp_scan_history ------------------------------------------------------------------------


async def test_list_scans(mock: respx.MockRouter) -> None:
    base(mock, [scan(), scan(name="mcp-iot-cameras", isEnabled=False, id="c2")])
    out = await call_tool(make_server(), "ise_snmp_scan_history", {"response_format": "json"})
    rows = {r["name"]: r for r in out["results"]}
    assert rows["mcp-iot-printers"]["targets"] == "192.0.2.0/24"
    assert rows["mcp-iot-printers"]["schedule"] == "none" and rows["mcp-iot-printers"]["enabled"] is True
    assert rows["mcp-iot-cameras"]["enabled"] is False
    assert "******" not in json.dumps(out)


async def test_history_renders_runs(mock: respx.MockRouter) -> None:
    base(mock, [scan()])
    mock.get(f"/api/v1/profiler/snmp/scan-history/{SID}").respond(json=HISTORY)
    out = await call_tool(
        make_server(), "ise_snmp_scan_history", {"name": "mcp-iot-printers", "response_format": "json"}
    )
    assert [r["result"] for r in out["runs"]] == ["SUCCESS", "FAILURE"]  # newest first
    assert out["runs"][0]["time"] == "2026-10-28T07:00:00Z"
    assert out["last_result"] == "SUCCESS" and out["totals"]["discovered"] == 3
    assert out["scan"]["credentials"] == [{"snmpVersion": "snmpV2", "roCommunity": "********"}]  # masked
    assert "ise_explain_profile" in out["explain"]
    assert any("auth failures" in h for h in out["hints"])


async def test_history_links_endpoints(mock: respx.MockRouter) -> None:
    base(mock, [scan()])
    run = {**HISTORY[0], "endpoints": [{"macAddress": "00:00:5E:00:53:01", "ip": "192.0.2.20"}]}
    mock.get(f"/api/v1/profiler/snmp/scan-history/{SID}").respond(json={"response": [run]})
    out = await call_tool(
        make_server(), "ise_snmp_scan_history", {"name": "mcp-iot-printers", "response_format": "json"}
    )
    assert out["endpoints"] == [
        {"mac": "00:00:5E:00:53:01", "next": "ise_explain_profile(mac='00:00:5E:00:53:01')"}
    ]


async def test_history_unknown_scan(mock: respx.MockRouter) -> None:
    base(mock, [])
    with pytest.raises(ToolError, match="No SNMP scan"):
        await call_tool(make_server(), "ise_snmp_scan_history", {"name": "nope"})


# --- ise_set_snmp_scan ----------------------------------------------------------------------------


async def test_create_scan(mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV, COMMUNITY)
    base(mock, [])
    post = mock.post(SCANS).respond(200, json={"message": "created", "scanId": SID})
    args = {
        "name": "mcp-iot-printers",
        "targets": ["192.0.2.0/24"],
        "exclude": ["192.0.2.1"],
        "community_env": ENV,
        "schedule": "daily",
        "schedule_time": "02:00 am",
    }
    preview, done = await two_step("ise_set_snmp_scan", args)
    assert preview["status"] == "preview", preview
    assert preview["action"] == f"Create SNMP scan mcp-iot-printers (192.0.2.0/24) on {PSN}"
    p = preview["preview"]
    assert p["addresses"] == 255 and p["scan"]["schedule"] == "daily 02:00 am"
    assert p["scan"]["credentials"] == [
        {"snmpVersion": "snmpV2", "roCommunity": f"(from {ENV}, never shown)"}
    ]
    assert COMMUNITY not in json.dumps(preview)
    body = json.loads(post.calls.last.request.content)
    assert body == {
        "name": "mcp-iot-printers",
        "description": "",
        "isEnabled": True,
        "scanSource": PSN,
        "networkScope": {
            "subnets": [{"subnetIp": "192.0.2.0", "mask": 24}],
            "ipRanges": [],
            "excludedIps": ["192.0.2.1"],
        },
        "scheduleTime": {"scheduleType": "DAILY", "time": "02:00 am"},
        "snmpAuthData": [{"snmpVersion": "snmpV2", "roCommunity": COMMUNITY}],
    }
    assert done is not None and done["result"]["id"] == SID
    assert COMMUNITY not in json.dumps(done)


async def test_create_needs_credentials(mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV, raising=False)
    base(mock, [])
    post = mock.post(SCANS).respond(200, json={})
    out, _ = await two_step("ise_set_snmp_scan", {"name": "x", "targets": ["192.0.2.0/24"]})
    assert out["status"] == "blocked" and any("needs credentials" in b for b in out["blockers"])
    out, _ = await two_step(
        "ise_set_snmp_scan", {"name": "x", "targets": ["192.0.2.0/24"], "community_env": ENV}
    )
    assert out["status"] == "blocked" and any("is not set on this server" in b for b in out["blockers"])
    assert not post.called


async def test_env_name_must_be_snmp(mock: respx.MockRouter) -> None:
    base(mock, [])
    with pytest.raises(ToolError, match="ISE_SNMP_"):
        await two_step(
            "ise_set_snmp_scan", {"name": "x", "targets": ["192.0.2.0/24"], "community_env": "ISE_PASSWORD"}
        )


async def test_create_v3(mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ISE_SNMP_V3_AUTH", "auth-pass-2026")
    monkeypatch.setenv("ISE_SNMP_V3_PRIV", "priv-pass-2026")
    base(mock, [])
    post = mock.post(SCANS).respond(200, json={"message": "created", "scanId": SID})
    preview, _ = await two_step(
        "ise_set_snmp_scan",
        {
            "name": "mcp-iot-bms",
            "targets": ["198.51.100.10-198.51.100.40"],
            "snmp_version": "v3",
            "v3_username": "ise-scan",
            "v3_auth_protocol": "SHA-256",
            "v3_auth_password_env": "ISE_SNMP_V3_AUTH",
            "v3_privacy_protocol": "AES",
            "v3_privacy_password_env": "ISE_SNMP_V3_PRIV",
        },
    )
    assert preview["status"] == "preview", preview
    assert "pass-2026" not in json.dumps(preview)
    auth = json.loads(post.calls.last.request.content)["snmpAuthData"]
    assert auth == [
        {
            "snmpVersion": "snmpV3",
            "username": "ise-scan",
            "securityLevel": "authPriv",
            "authProtocol": "SHA-256",
            "authPassword": "auth-pass-2026",
            "privacyProtocol": "AES",
            "privacyPassword": "priv-pass-2026",
        }
    ]


async def test_update_scope_diff(mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV, COMMUNITY)
    base(mock, [scan()])
    put = mock.put(f"{SCANS}/{SID}").respond(200, json={"message": "updated", "scanId": SID})
    preview, done = await two_step(
        "ise_set_snmp_scan",
        {"name": "mcp-iot-printers", "targets": ["192.0.2.0/25"], "community_env": ENV},
    )
    assert preview["status"] == "preview", preview
    changes = preview["preview"]["changes"]
    assert "targets" in json.dumps(changes) and "192.0.2.0/25" in json.dumps(changes)
    assert (
        preview["preview"]["method"] == "PUT"
        and preview["preview"]["credentials"] == "replaced (never shown)"
    )
    body = json.loads(put.calls.last.request.content)
    assert body["id"] == SID and body["networkScope"]["subnets"] == [{"subnetIp": "192.0.2.0", "mask": 25}]
    assert body["snmpAuthData"] == [{"snmpVersion": "snmpV2", "roCommunity": COMMUNITY}]
    assert done is not None and done["result"]["updated"] == "mcp-iot-printers"


async def test_update_without_credentials_is_blocked(mock: respx.MockRouter) -> None:
    base(mock, [scan()])  # ISE returned the community masked
    put = mock.put(f"{SCANS}/{SID}").respond(200, json={})
    out, _ = await two_step("ise_set_snmp_scan", {"name": "mcp-iot-printers", "description": "new"})
    assert out["status"] == "blocked" and any("stored SNMP credentials" in b for b in out["blockers"])
    assert not put.called


async def test_update_reuses_returned_credentials(mock: respx.MockRouter) -> None:
    base(mock, [scan(snmpAuthData=[{"snmpVersion": "snmpV2", "roCommunity": COMMUNITY}])])
    put = mock.put(f"{SCANS}/{SID}").respond(200, json={"message": "updated"})
    preview, _ = await two_step("ise_set_snmp_scan", {"name": "mcp-iot-printers", "description": "new"})
    assert preview["status"] == "preview", preview
    assert COMMUNITY not in json.dumps(preview)
    assert json.loads(put.calls.last.request.content)["snmpAuthData"][0]["roCommunity"] == COMMUNITY


async def test_disable_only_uses_status_call(mock: respx.MockRouter) -> None:
    base(mock, [scan()])
    put = mock.put(f"{SCANS}/{SID}").respond(200, json={})
    status = mock.post(f"{SCANS}/status").respond(json={"result": [{"id": SID, "status": "success"}]})
    preview, done = await two_step("ise_set_snmp_scan", {"name": "mcp-iot-printers", "enabled": False})
    assert preview["status"] == "preview", preview
    assert preview["action"] == "Update SNMP scan mcp-iot-printers: disable it"
    assert json.loads(status.calls.last.request.content) == {"status": "disable", "ids": [SID]}
    assert not put.called
    assert done is not None and done["result"]["result"] == [
        {"name": "mcp-iot-printers", "status": "success"}
    ]


async def test_set_unchanged_is_no_change(mock: respx.MockRouter) -> None:
    base(mock, [scan()])
    put = mock.put(f"{SCANS}/{SID}").respond(200, json={})
    out, _ = await two_step(
        "ise_set_snmp_scan",
        {"name": "mcp-iot-printers", "targets": ["192.0.2.0/24"], "enabled": True, "schedule": "none"},
    )
    assert out["status"] == "no_change", out
    assert "confirm" not in out and not put.called


# --- ise_run_snmp_scan ----------------------------------------------------------------------------


async def test_start_scan(mock: respx.MockRouter) -> None:
    base(mock, [scan()])
    action = mock.post(f"{SCANS}/action").respond(json={"result": [{"id": SID, "status": "success"}]})
    preview, done = await two_step("ise_run_snmp_scan", {"names": ["mcp-iot-printers"], "action": "start"})
    assert preview["status"] == "preview", preview
    assert preview["preview"]["scans"][0]["addresses"] == 256
    assert any("UDP/161" in s for s in preview["side_effects"])
    assert json.loads(action.calls.last.request.content) == {"action": "start", "ids": [SID]}
    assert done is not None and done["result"]["result"] == [
        {"name": "mcp-iot-printers", "status": "success"}
    ]
    assert "ise_snmp_scan_history" in done["result"]["next"]


async def test_stop_several_and_failure_reason(mock: respx.MockRouter) -> None:
    base(mock, [scan(), scan(name="mcp-iot-cameras", id="c2")])
    mock.post(f"{SCANS}/action").respond(
        json={
            "result": [
                {"id": SID, "status": "success"},
                {"id": "c2", "status": "failure", "failureReason": "Scan is not running"},
            ]
        }
    )
    _, done = await two_step(
        "ise_run_snmp_scan", {"names": ["mcp-iot-printers", "mcp-iot-cameras"], "action": "stop"}
    )
    assert done is not None
    assert done["result"]["result"][1] == {
        "name": "mcp-iot-cameras",
        "status": "failure",
        "failure_reason": "Scan is not running",
    }


async def test_start_refusals(mock: respx.MockRouter) -> None:
    base(mock, [scan(), scan(name="mcp-iot-cameras", id="c2", isEnabled=False)])
    action = mock.post(f"{SCANS}/action").respond(json={"result": []})
    out, _ = await two_step(
        "ise_run_snmp_scan", {"names": ["mcp-iot-printers", "mcp-iot-cameras"], "action": "start"}
    )
    assert out["status"] == "blocked"
    assert any("one SNMP scan at a time" in b for b in out["blockers"])
    assert any("is disabled" in b for b in out["blockers"])
    assert not action.called


async def test_enable_already_enabled_is_no_change(mock: respx.MockRouter) -> None:
    base(mock, [scan()])
    status = mock.post(f"{SCANS}/status").respond(json={"result": []})
    out, _ = await two_step("ise_run_snmp_scan", {"names": ["mcp-iot-printers"], "action": "enable"})
    assert out["status"] == "no_change", out
    assert not status.called


async def test_tools_are_write_tier() -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_snmp_scan_history" in names
    assert not {"ise_set_snmp_scan", "ise_run_snmp_scan"} & names


V3_SCAN = scan(
    snmpAuthData=[
        {
            "snmpVersion": "snmpV3",
            "username": "ise-scan",
            "securityLevel": "authPriv",
            "authProtocol": "SHA",
            "authPassword": "******",
            "privacyProtocol": "AES",
            "privacyPassword": "******",
        }
    ]
)


async def test_v3_scan_enable_toggle_needs_no_credentials(mock: respx.MockRouter) -> None:
    base(mock, [V3_SCAN])
    status = mock.post(f"{SCANS}/status").respond(json={"result": [{"id": SID, "status": "success"}]})
    out, _ = await two_step("ise_set_snmp_scan", {"name": "mcp-iot-printers", "enabled": True})
    assert out["status"] == "no_change", out
    preview, _ = await two_step("ise_set_snmp_scan", {"name": "mcp-iot-printers", "enabled": False})
    assert preview["status"] == "preview", preview
    assert json.loads(status.calls.last.request.content) == {"status": "disable", "ids": [SID]}


# --- #161: enabled state from the top-level status; delete kind -----------------------------------


def raw_disabled() -> dict[str, Any]:
    """The lab ISE 3.5's GET /scan entity after POST /scan/status disable (2026-10-28, #161): top-level
    status DISABLED while scanDetails.isEnabled and scanStatus stay true; jobStatus null when idle."""
    s = scan()
    s.update(status="DISABLED", jobStatus=None, scanStatus=True, psnGroup=PSN)
    s["scanDetails"]["id"] = None
    return s


def test_scan_enabled_prefers_top_level_status() -> None:
    assert scan_enabled(raw_disabled()) is False
    assert scan_enabled({**raw_disabled(), "status": "ENABLED"}) is True
    assert scan_enabled(scan()) is True  # no top-level status: isEnabled
    assert scan_enabled({"scanStatus": False}) is False
    assert scan_enabled({}) is None


async def test_disabled_scan_lists_and_answers_no_change(mock: respx.MockRouter) -> None:
    base(mock, [raw_disabled()])
    status = mock.post(f"{SCANS}/status").respond(json={"result": []})
    out = await call_tool(make_server(), "ise_snmp_scan_history", {"response_format": "json"})
    assert out["results"][0]["enabled"] is False
    noop, _ = await two_step("ise_set_snmp_scan", {"name": "mcp-iot-printers", "enabled": False})
    assert noop["status"] == "no_change", noop
    noop, _ = await two_step("ise_run_snmp_scan", {"names": ["mcp-iot-printers"], "action": "disable"})
    assert noop["status"] == "no_change", noop
    blocked, _ = await two_step("ise_run_snmp_scan", {"names": ["mcp-iot-printers"], "action": "start"})
    assert blocked["status"] == "blocked" and any("is disabled" in b for b in blocked["blockers"])
    assert not status.called


def test_scan_running() -> None:
    assert not scan_running(raw_disabled())  # start 1793170800000 < end
    assert scan_running({**scan(), "jobStatus": "IN_PROGRESS"})
    assert scan_running({**scan(), "jobStatus": "Running"})
    assert scan_running({**scan(), "scanEndTime": None})
    assert not scan_running({"jobStatus": "COMPLETED"})


async def test_delete_scan_preview_and_body(mock: respx.MockRouter) -> None:
    base(mock, [raw_disabled()])
    per_id = mock.delete(f"{SCANS}/{SID}").respond(405)
    route = mock.delete(SCANS).respond(
        json={"result": [{"id": None, "status": "success", "failureReason": None}]}
    )
    preview, done = await two_step("ise_delete_object", {"kind": "snmp_scan", "target": "mcp-iot-printers"})
    assert preview["status"] == "preview", preview
    assert preview["action"] == "Delete SNMP scan mcp-iot-printers"
    assert preview["preview"]["path"] == SCANS and preview["preview"]["body"] == {"ids": [SID]}
    assert preview["preview"]["enabled"] is False
    assert "******" not in json.dumps(preview)
    assert done is not None
    assert json.loads(route.calls.last.request.content) == {"ids": [SID]}
    assert not per_id.called
    assert done["result"] == {
        "deleted": "mcp-iot-printers",
        "id": SID,
        "result": [{"name": "mcp-iot-printers", "status": "success"}],
    }


async def test_delete_scan_blocked_while_running(mock: respx.MockRouter) -> None:
    base(mock, [{**scan(), "status": "ENABLED", "jobStatus": "IN_PROGRESS"}])
    route = mock.delete(SCANS).respond(json={"result": []})
    out, _ = await two_step("ise_delete_object", {"kind": "snmp_scan", "target": "mcp-iot-printers"})
    assert out["status"] == "blocked", out
    assert any("is running" in b and "action='stop'" in b for b in out["blockers"])
    assert not route.called


async def test_delete_scan_failure_and_unknown(mock: respx.MockRouter) -> None:
    base(mock, [raw_disabled()])
    mock.delete(SCANS).respond(
        json={"result": [{"id": SID, "status": "failure", "failureReason": "Scan is in use"}]}
    )
    server = make_server(mcp_enable_writes=True)
    async with Client(server) as c:
        preview = (
            await c.call_tool("ise_delete_object", {"kind": "snmp_scan", "target": "mcp-iot-printers"})
        ).structured_content
        assert preview is not None
        with pytest.raises(ToolError, match="Scan is in use"):
            await c.call_tool(
                "ise_delete_object",
                {"kind": "snmp_scan", "target": "mcp-iot-printers", "confirm": preview["confirm"]},
            )
        with pytest.raises(ToolError, match="No SNMP scan"):
            await c.call_tool("ise_delete_object", {"kind": "snmp_scan", "target": "nope"})

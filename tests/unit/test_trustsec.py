"""TrustSec device report (I55) and NAD TrustSec settings."""

from __future__ import annotations

import json
from typing import Any

import respx
from fastmcp import Client

from ise_mcp._core.formatting import MASK
from ise_mcp._core.testing import call_tool
from ise_mcp.tools.trustsec import device_report_row, report_time
from tests.unit.conftest import ers_page, make_server
from tests.unit.test_writes import two_step

REPORT = "/api/v1/trustsec/policy/device-report"


def report(
    name: str, status: str, policy: str, updated: str, state: str = "SGACL_DOWNLOAD"
) -> dict[str, Any]:
    return {
        "name": name,
        "ipAddress": "198.18.128.154",
        "state": state,
        "status": status,
        "policyUpdatedTime": policy,
        "statusUpdatedTime": updated,
        "policyVersionId": "7",
        "pushId": "p-1",
        "pullId": "q-1",
    }


def test_report_time_formats() -> None:
    assert report_time("2026-10-18T03:04:05Z") is not None
    assert report_time("2026-10-18 03:04:05.123") is not None
    assert report_time(1760756645000) == report_time(1760756645)
    assert report_time("") is None
    assert report_time("yesterday") is None


def test_device_report_row_current_and_stale() -> None:
    row = device_report_row(report("sw1", "UPDATE_SUCCESS", "2026-10-18T03:00:00Z", "2026-10-18T03:01:00Z"))
    assert row["current"] is True and row["hint"] is None
    assert row["last_step"] == "SGACLs downloaded"
    stale = device_report_row(report("sw1", "UPDATE_SUCCESS", "2026-10-18T03:05:00Z", "2026-10-18T03:01:00Z"))
    assert stale["current"] is False and "ise_push_trustsec_matrix" in stale["hint"]
    failed = device_report_row(
        report(
            "sw1", "ENV_REQUEST_FAILED", "2026-10-18T03:00:00Z", "2026-10-18T03:01:00Z", "ENVDATA_DOWNLOAD"
        ),
    )
    assert failed["current"] is False and "cts credentials" in failed["hint"]
    unknown_time = device_report_row(report("sw1", "COA_ACK", "", "", "COA_SENT"))
    assert unknown_time["current"] is None and unknown_time["last_step"] == "CoA sent"


async def test_device_report_all(mock: respx.MockRouter) -> None:
    mock.get(REPORT).respond(
        json={
            "version": "1.0.0",
            "response": [
                report("sw2", "COA_TIMED_OUT", "2026-10-18T03:00:00Z", "2026-10-18T03:00:30Z", "COA_SENT"),
                report("sw1", "UPDATE_SUCCESS", "2026-10-18T03:00:00Z", "2026-10-18T03:01:00Z"),
            ],
        }
    )
    out = await call_tool(make_server(), "ise_trustsec_device_report", {"response_format": "json"})
    assert [r["device"] for r in out["results"]] == ["sw1", "sw2"]
    assert out["results"][0]["current"] is True
    assert out["results"][1]["current"] is False and "CoA" in out["results"][1]["hint"]
    md = await call_tool(make_server(), "ise_trustsec_device_report", {})
    assert "| device |" in str(md) and "sw1" in str(md)


async def test_device_report_nobody_reported(mock: respx.MockRouter) -> None:
    mock.get(REPORT).respond(json={"version": "1.0.0", "response": None})
    out = await call_tool(make_server(), "ise_trustsec_device_report", {"response_format": "json"})
    assert out["results"] == [] and "cts policy-server" in out["note"] and "RADIUS" in out["note"]


def nad_routes(mock: respx.MockRouter) -> None:
    nad = {"NetworkDevice": {"id": "n1", "name": "mcp-test-sw1", "NetworkDeviceIPList": []}}
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.sw1"}).respond(json=ers_page([]))
    mock.get("/ers/config/networkdevice", params={"filter": "name.CONTAINS.sw1"}).respond(
        json=ers_page([{"id": "n1", "name": "mcp-test-sw1"}])
    )
    mock.get("/ers/config/networkdevice/n1").respond(json=nad)


async def test_device_report_one_partial_name(mock: respx.MockRouter) -> None:
    nad_routes(mock)
    mock.get(f"{REPORT}/network-device/mcp-test-sw1").respond(
        json={
            "version": "1.0.0",
            "response": report(
                "mcp-test-sw1", "UPDATE_SUCCESS", "2026-10-18T03:00:00Z", "2026-10-18T03:01:00Z"
            ),
        }
    )
    out = await call_tool(
        make_server(), "ise_trustsec_device_report", {"nad": "sw1", "response_format": "json"}
    )
    assert out["results"][0]["device"] == "mcp-test-sw1" and out["results"][0]["current"] is True
    assert "mcp-test-sw1" in out["resolved_from"]


async def test_device_report_one_never_downloaded(mock: respx.MockRouter) -> None:
    nad_routes(mock)
    mock.get(f"{REPORT}/network-device/mcp-test-sw1").respond(404)
    async with Client(make_server()) as c:
        r = await c.call_tool("ise_trustsec_device_report", {"nad": "sw1"}, raise_on_error=False)
    assert r.is_error and "never downloaded" in r.content[0].text and "HTTPS" in r.content[0].text


async def test_update_nad_trustsec_credentials(mock: respx.MockRouter) -> None:
    nad = {
        "NetworkDevice": {
            "id": "n1",
            "name": "mcp-test-sw1",
            "authenticationSettings": {"networkProtocol": "RADIUS", "radiusSharedSecret": "radius-secret-1"},
            "NetworkDeviceIPList": [{"ipaddress": "198.18.128.154", "mask": 32}],
            "NetworkDeviceGroupList": ["Location#All Locations"],
        }
    }
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.mcp-test-sw1"}).respond(
        json=ers_page([{"id": "n1", "name": "mcp-test-sw1"}])
    )
    mock.get("/ers/config/networkdevice/n1").respond(json=nad)
    put = mock.put("/ers/config/networkdevice/n1").respond(200, json={"UpdatedFieldsList": {}})
    preview, applied = await two_step(
        "ise_update_nad",
        {"device": "mcp-test-sw1", "trustsec_id": "mcp-test-sw1", "trustsec_password": "cts-pass-1"},
    )
    changes = preview["preview"]["changes"]
    added = changes["trustsecsettings"]["to"]
    assert added["deviceAuthenticationSettings"] == {"sgaDeviceId": "mcp-test-sw1", "sgaDevicePassword": MASK}
    assert added["sgaNotificationAndUpdates"]["sendConfigurationToDeviceUsing"] == "ENABLE_USING_COA"
    assert added["sgaNotificationAndUpdates"]["sendConfigurationToDevice"] is True
    assert "cts-pass-1" not in json.dumps(preview)
    assert applied["status"] == "applied"
    body = json.loads(put.calls.last.request.content)["NetworkDevice"]
    assert body["trustsecsettings"]["deviceAuthenticationSettings"]["sgaDevicePassword"] == "cts-pass-1"
    deployment = body["trustsecsettings"]["deviceConfigurationDeployment"]
    assert deployment == {"includeWhenDeployingSGTUpdates": False}


async def test_update_nad_trustsec_needs_both_first_time(mock: respx.MockRouter) -> None:
    nad = {"NetworkDevice": {"id": "n1", "name": "mcp-test-sw1", "NetworkDeviceIPList": []}}
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.mcp-test-sw1"}).respond(
        json=ers_page([{"id": "n1", "name": "mcp-test-sw1"}])
    )
    mock.get("/ers/config/networkdevice/n1").respond(json=nad)
    preview, _ = await two_step("ise_update_nad", {"device": "mcp-test-sw1", "trustsec_password": "x-pass-1"})
    assert preview["status"] == "blocked" and "both" in preview["blockers"][0]


async def test_update_nad_trustsec_push_on_existing(mock: respx.MockRouter) -> None:
    existing = {
        "deviceAuthenticationSettings": {"sgaDeviceId": "mcp-test-sw1", "sgaDevicePassword": "cts-pass-1"},
        "sgaNotificationAndUpdates": {
            "sendConfigurationToDevice": False,
            "downloadSGACLListsEveryXSeconds": 3600,
        },
        "deviceConfigurationDeployment": {"includeWhenDeployingSGTUpdates": False},
    }
    nad = {
        "NetworkDevice": {
            "id": "n1",
            "name": "mcp-test-sw1",
            "NetworkDeviceIPList": [],
            "trustsecsettings": existing,
        }
    }
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.mcp-test-sw1"}).respond(
        json=ers_page([{"id": "n1", "name": "mcp-test-sw1"}])
    )
    mock.get("/ers/config/networkdevice/n1").respond(json=nad)
    put = mock.put("/ers/config/networkdevice/n1").respond(200, json={"UpdatedFieldsList": {}})
    preview, applied = await two_step("ise_update_nad", {"device": "mcp-test-sw1", "trustsec_push": True})
    changes = preview["preview"]["changes"]
    assert changes == {
        "trustsecsettings.sgaNotificationAndUpdates.sendConfigurationToDevice": {"from": False, "to": True},
        "trustsecsettings.sgaNotificationAndUpdates.sendConfigurationToDeviceUsing": {
            "from": None,
            "to": "ENABLE_USING_COA",
        },
    }
    assert applied["status"] == "applied"
    body = json.loads(put.calls.last.request.content)["NetworkDevice"]["trustsecsettings"]
    assert body["sgaNotificationAndUpdates"]["downloadSGACLListsEveryXSeconds"] == 3600  # kept
    assert body["deviceAuthenticationSettings"]["sgaDevicePassword"] == "cts-pass-1"  # kept

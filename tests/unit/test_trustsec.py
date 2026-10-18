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
    assert r.is_error and "never reported" in r.content[0].text and "PUSH ID" in r.content[0].text


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


def nad_with_trustsec() -> dict[str, Any]:
    return {
        "NetworkDevice": {
            "id": "n1",
            "name": "mcp-test-sw1",
            "NetworkDeviceIPList": [{"ipaddress": "198.18.128.154", "mask": 32}],
            "trustsecsettings": {
                "deviceAuthenticationSettings": {
                    "sgaDeviceId": "mcp-test-sw1",
                    "sgaDevicePassword": "cts-pass-1",
                },
                "sgaNotificationAndUpdates": {"sendConfigurationToDevice": True},
                "deviceConfigurationDeployment": {"includeWhenDeployingSGTUpdates": False},
            },
        }
    }


def mock_nad(mock: respx.MockRouter, nad: dict[str, Any]) -> respx.Route:
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.mcp-test-sw1"}).respond(
        json=ers_page([{"id": "n1", "name": "mcp-test-sw1"}])
    )
    mock.get("/ers/config/networkdevice/n1").respond(json=nad)
    return mock.put("/ers/config/networkdevice/n1").respond(200, json={"UpdatedFieldsList": {}})


async def test_update_nad_trustsec_rest_credentials(mock: respx.MockRouter) -> None:
    put = mock_nad(mock, nad_with_trustsec())
    preview, applied = await two_step(
        "ise_update_nad",
        {"device": "mcp-test-sw1", "trustsec_rest_user": "sw1-rest", "trustsec_rest_password": "rest-pass-1"},
    )
    assert preview["preview"]["changes"] == {
        "trustsecsettings.deviceAuthenticationSettings.restApiUsername": {"from": None, "to": "sw1-rest"},
        "trustsecsettings.deviceAuthenticationSettings.restApiPassword": {"from": None, "to": MASK},
    }
    assert "rest-pass-1" not in json.dumps(preview)
    assert applied["status"] == "applied"
    auth = json.loads(put.calls.last.request.content)["NetworkDevice"]["trustsecsettings"][
        "deviceAuthenticationSettings"
    ]
    assert auth == {
        "sgaDeviceId": "mcp-test-sw1",
        "sgaDevicePassword": "cts-pass-1",  # kept
        "restApiUsername": "sw1-rest",
        "restApiPassword": "rest-pass-1",
    }


async def test_update_nad_trustsec_rest_needs_both_first_time(mock: respx.MockRouter) -> None:
    mock_nad(mock, nad_with_trustsec())
    preview, _ = await two_step(
        "ise_update_nad", {"device": "mcp-test-sw1", "trustsec_rest_user": "sw1-rest"}
    )
    assert preview["status"] == "blocked"
    assert "trustsec_rest_password" in preview["blockers"][0]
    # Once set, the password can be rotated alone.
    nad = nad_with_trustsec()
    nad["NetworkDevice"]["trustsecsettings"]["deviceAuthenticationSettings"]["restApiUsername"] = "sw1-rest"
    mock_nad(mock, nad)
    preview, _ = await two_step("ise_update_nad", {"device": "mcp-test-sw1", "trustsec_rest_password": "p-2"})
    assert preview["status"] == "preview"


async def test_update_nad_rest_credentials_need_trustsec(mock: respx.MockRouter) -> None:
    nad = {"NetworkDevice": {"id": "n1", "name": "mcp-test-sw1", "NetworkDeviceIPList": []}}
    mock_nad(mock, nad)
    preview, _ = await two_step(
        "ise_update_nad",
        {"device": "mcp-test-sw1", "trustsec_rest_user": "sw1-rest", "trustsec_rest_password": "rest-pass-1"},
    )
    assert preview["status"] == "blocked" and "trustsec_id" in preview["blockers"][0]


GENERAL = "/api/v1/trustsec/general-settings"
SETTINGS_OFF = {
    "httpsServerConfig": {"enableHttps": False, "enableAuditLog": False},
    "allowMultipleSGACLs": False,
    "configuredGenerateSgtAutomatically": "true",
    "nextTag": "16/0010",
}


async def test_get_trustsec_settings(mock: respx.MockRouter) -> None:
    mock.get(GENERAL).respond(json=SETTINGS_OFF)
    mock.get("/api/v1/trustsec/https-server").respond(
        json={
            "response": [
                {
                    "name": "ise",
                    "hostName": "ise.mitchcloud.lab",
                    "ipAddresses": ["198.18.134.35"],
                    "port": 9063,
                    "serverType": "PSN",
                    "index": 0,
                }
            ]
        }
    )
    out = await call_tool(make_server(), "ise_get_trustsec_settings", {})
    assert out["https_server"] is False and out["multiple_sgacls"] is False
    assert out["auto_sgt_numbering"] is True and out["next_sgt"] == "16/0010"
    assert out["https_servers"] == [
        {
            "name": "ise",
            "host": "ise.mitchcloud.lab",
            "ips": ["198.18.134.35"],
            "port": 9063,
            "type": "PSN",
            "index": 0,
        }
    ]


HTTPS_SERVERS = "/api/v1/trustsec/https-server"
PSN_NODE = {
    "hostname": "ise",
    "fqdn": "ise.mitchcloud.lab",
    "nicInterfaces": [{"nicCards": "eth0", "ipv4Address": "198.18.134.35", "ipv6Addresses": []}],
    "roles": ["Standalone"],
}


async def test_set_trustsec_settings_enable_https_adds_psn_server(mock: respx.MockRouter) -> None:
    # ISE 3.5 answers HTTP 500 to enableHttps=true while its HTTPS server list is empty: the tool adds the
    # PSNs on 9063 first (what the GUI makes you do by hand).
    mock.get(GENERAL).respond(json=SETTINGS_OFF)
    mock.get(HTTPS_SERVERS).respond(json={"response": []})
    mock.get("/api/v1/trustsec/deployment/node").respond(json={"response": [PSN_NODE]})
    post = mock.post(HTTPS_SERVERS).respond(json={"id": "h1", "name": "ise.mitchcloud.lab", "port": 9063})
    put = mock.put(GENERAL).respond(json={"success": {"message": "ok"}})
    preview, applied = await two_step("ise_set_trustsec_settings", {"https_server": True})
    assert preview["preview"]["changes"] == {"httpsServerConfig.enableHttps": {"from": False, "to": True}}
    assert preview["preview"]["current"]["https_server"] is False
    assert preview["preview"]["https_servers_added"] == [
        {
            "name": "ise",
            "host": "ise.mitchcloud.lab",
            "ips": ["198.18.134.35"],
            "port": 9063,
            "type": "PSN",
            "index": None,
        }
    ]
    assert any("9063" in s for s in preview["side_effects"])
    assert applied["status"] == "applied"
    assert json.loads(post.calls.last.request.content) == {
        "name": "ise",
        "hostName": "ise.mitchcloud.lab",
        "ipAddresses": ["198.18.134.35"],
        "ipv4Addresses": ["198.18.134.35"],
        "ipv6Addresses": [],
        "port": 9063,
        "serverType": "PSN",
        "CtsCertificates": [],
    }
    assert json.loads(put.calls.last.request.content) == {
        "allowMultipleSGACLs": False,
        "httpsServerConfig": {"enableHttps": True, "enableAuditLog": False},
    }
    assert applied["result"]["https_servers_added"][0]["id"] == "h1"


async def test_set_trustsec_settings_enable_https_with_servers(mock: respx.MockRouter) -> None:
    mock.get(GENERAL).respond(json=SETTINGS_OFF)
    mock.get(HTTPS_SERVERS).respond(json={"response": [{"name": "ise.mitchcloud.lab", "port": 9063}]})
    post = mock.post(HTTPS_SERVERS).respond(json={})
    put = mock.put(GENERAL).respond(json={"success": {"message": "ok"}})
    preview, applied = await two_step("ise_set_trustsec_settings", {"https_server": True})
    assert "https_servers_added" not in preview["preview"]
    assert applied["status"] == "applied" and not post.called and put.called


async def test_set_trustsec_settings_multiple_sgacls_keeps_https(mock: respx.MockRouter) -> None:
    on = {**SETTINGS_OFF, "httpsServerConfig": {"enableHttps": True, "enableAuditLog": True}}
    mock.get(GENERAL).respond(json=on)
    put = mock.put(GENERAL).respond(json={})
    preview, applied = await two_step("ise_set_trustsec_settings", {"multiple_sgacls": True})
    assert preview["preview"]["changes"] == {"allowMultipleSGACLs": {"from": False, "to": True}}
    assert "side_effects" not in preview
    assert applied["status"] == "applied"
    assert json.loads(put.calls.last.request.content)["httpsServerConfig"] == {
        "enableHttps": True,
        "enableAuditLog": True,
    }


async def test_set_trustsec_settings_nothing_to_change(mock: respx.MockRouter) -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool("ise_set_trustsec_settings", {}, raise_on_error=False)
    assert r.is_error and "Nothing to change" in str(r.content[0].text)  # type: ignore[union-attr]


async def test_update_nad_trustsec_push_id(mock: respx.MockRouter) -> None:
    put = mock_nad(mock, nad_with_trustsec())
    preview, applied = await two_step("ise_update_nad", {"device": "mcp-test-sw1", "trustsec_push_id": True})
    assert preview["preview"]["changes"] == {"trustsecsettings.pushIdSupport": {"from": None, "to": "true"}}
    assert applied["status"] == "applied"
    body = json.loads(put.calls.last.request.content)["NetworkDevice"]["trustsecsettings"]
    assert body["pushIdSupport"] == "true"
    assert body["deviceAuthenticationSettings"]["sgaDevicePassword"] == "cts-pass-1"  # kept

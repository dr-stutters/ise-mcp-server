from __future__ import annotations

import json
import re
from datetime import UTC, datetime

import pytest
import respx
from fastmcp.exceptions import ToolError

from ise_mcp._core import InvalidRequest
from ise_mcp._core.testing import call_tool
from ise_mcp.tools.activity import is_coa_record, parse_until
from tests.unit.conftest import FAILURE_REASONS_XML, ers_page, make_server, xml

SW_IP = "192.0.2.154"
NAD_ID = "11111111-2222-3333-4444-555555555555"

AUTH_LIST = xml(
    '<activeList noOfActiveSession="3">'
    f"<activeSession><user_name>52:54:00:61:3D:9E</user_name><calling_station_id>52:54:00:61:3D:9E"
    f"</calling_station_id><nas_ip_address>{SW_IP}</nas_ip_address><audit_session_id>A1</audit_session_id>"
    "<server>ise</server></activeSession>"
    f"<activeSession><user_name>alice</user_name><calling_station_id>52:54:00:A2:D7:F0</calling_station_id>"
    f"<nas_ip_address>{SW_IP}</nas_ip_address><audit_session_id>A2</audit_session_id><server>ise</server>"
    "</activeSession>"
    "<activeSession><user_name>bob</user_name><calling_station_id>02:00:5E:00:00:01</calling_station_id>"
    "<nas_ip_address>10.16.104.82</nas_ip_address><framed_ip_address>10.250.0.11</framed_ip_address>"
    "<audit_session_id>A3</audit_session_id><server>ise</server></activeSession></activeList>"
)
EMPTY_LIST = xml('<activeList noOfActiveSession="0"/>')


def auth_status(mac: str, *records: str) -> str:
    return xml(
        f'<authStatusOutputList><authStatusList key="{mac}">{"".join(records)}</authStatusList>'
        "</authStatusOutputList>"
    )


def rec(
    mac: str,
    *,
    passed: bool,
    time: str,
    reason: str = "",
    user: str = "",
    nad: str = "mcp-test-sw1",
    nas_ip: str = SW_IP,
    msg: str = "5400",
) -> str:
    return (
        f"<authStatusElements><passed>{str(passed).lower()}</passed><failed>{str(not passed).lower()}"
        f"</failed><user_name>{user}</user_name><calling_station_id>{mac}</calling_station_id>"
        f"<nas_ip_address>{nas_ip}</nas_ip_address><network_device_name>{nad}</network_device_name>"
        f"<failure_reason>{reason}</failure_reason><acs_timestamp>{time}</acs_timestamp>"
        f"<authentication_method>mab</authentication_method><message_code>{msg}</message_code>"
        "</authStatusElements>"
    )


def body(out: object) -> dict:  # type: ignore[type-arg]
    return out if isinstance(out, dict) else json.loads(str(out))


def mock_nad(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.mcp-test-sw1"}).respond(
        json=ers_page([{"id": NAD_ID, "name": "mcp-test-sw1"}])
    )
    mock.get(f"/ers/config/networkdevice/{NAD_ID}").respond(
        json={
            "NetworkDevice": {
                "id": NAD_ID,
                "name": "mcp-test-sw1",
                "NetworkDeviceIPList": [{"ipaddress": SW_IP, "mask": 32}],
            }
        }
    )


def test_parse_until() -> None:
    assert parse_until("2026-10-15T08:00:00Z") == datetime(2026, 10, 15, 8, tzinfo=UTC)
    assert parse_until("2026-10-15 10:00:00+02:00") == datetime(2026, 10, 15, 8, tzinfo=UTC)
    assert parse_until("2026-10-15T08:00:00") == datetime(2026, 10, 15, 8, tzinfo=UTC)
    with pytest.raises(InvalidRequest):
        parse_until("yesterday")


def test_is_coa_record() -> None:
    assert is_coa_record({"message_code": "5417"})
    assert is_coa_record({"failure_reason": "11213 No response received from Network Access Device"})
    assert not is_coa_record({"message_code": "5400", "failure_reason": "22040 Wrong password"})


async def test_auth_list_window_and_summary(mock: respx.MockRouter) -> None:
    route = mock.get(url__regex=r".*/Session/AuthList/.*").respond(text=AUTH_LIST)
    out = body(
        await call_tool(
            make_server(),
            "ise_get_auth_list",
            {"since_minutes": 90, "until": "2026-10-15T08:00:00Z", "response_format": "json"},
        )
    )
    path = route.calls.last.request.url.raw_path.decode()
    assert path.endswith("/Session/AuthList/2026-10-15%2006%3A30%3A00/2026-10-15%2008%3A00%3A00")
    assert out["total"] == 3
    assert out["by_nas_ip"] == {SW_IP: 2, "10.16.104.82": 1}
    assert out["window_utc"] == {"start": "2026-10-15 06:30:00", "end": "2026-10-15 08:00:00"}


async def test_auth_list_nad_and_user_filter_with_detail(mock: respx.MockRouter) -> None:
    mock.get(url__regex=r".*/Session/AuthList/.*").respond(text=AUTH_LIST)
    mock_nad(mock)
    mock.get("/admin/API/mnt/Session/MACAddress/52:54:00:A2:D7:F0").respond(
        text=xml(
            "<sessionParameters><calling_station_id>52:54:00:A2:D7:F0</calling_station_id>"
            "<network_device_name>mcp-test-sw1</network_device_name><authentication_method>dot1x"
            "</authentication_method><selected_azn_profiles>mcp-test-permit</selected_azn_profiles>"
            "<other_attr_string>ISEPolicySetName=mcp-test-wired:!:AuthorizationPolicyMatchedRule=r1"
            "</other_attr_string></sessionParameters>"
        )
    )
    out = body(
        await call_tool(
            make_server(),
            "ise_get_auth_list",
            {"nad": "mcp-test-sw1", "user": "ALI", "detail": True, "response_format": "json"},
        )
    )
    assert out["total"] == 1
    row = out["results"][0]
    assert row["method"] == "dot1x" and row["authz_profiles"] == "mcp-test-permit"
    assert row["matched_policy"]["policy_set"] == "mcp-test-wired"
    assert out["nad_filter"] == "mcp-test-sw1"
    assert out["page_by_method"] == {"dot1x": 1}


async def test_auth_list_empty_window_notes(mock: respx.MockRouter) -> None:
    mock.get(url__regex=r".*/Session/AuthList/.*").respond(text=EMPTY_LIST)
    out = body(await call_tool(make_server(), "ise_get_auth_list", {"response_format": "json"}))
    assert out["total"] == 0
    assert "ise_recent_auth_failures" in out["note"]


async def test_auth_list_mnt_error_is_reported(mock: respx.MockRouter) -> None:
    mock.get(url__regex=r".*/Session/AuthList/.*").respond(
        500,
        text=xml(
            "<mnt-rest-result><http-code>500</http-code><cpm-code>34110</cpm-code><internal-error-info>"
            "Invalid start time format</internal-error-info></mnt-rest-result>"
        ),
    )
    with pytest.raises(ToolError, match="Invalid start time format"):
        await call_tool(make_server(), "ise_get_auth_list", {})


def mock_failures(mock: respx.MockRouter) -> None:
    mock.get("/admin/API/mnt/FailureReasons").respond(text=FAILURE_REASONS_XML)
    mock.get(url__regex=r".*/Session/AuthList/.*").respond(text=AUTH_LIST)
    mock.get("/api/v1/endpoint").respond(
        json=[{"mac": "02:00:5E:00:00:02"}, {"mac": "52:54:00:61:3D:9E"}, {"mac": "not-a-mac"}]
    )
    statuses = {
        "52:54:00:61:3D:9E": auth_status(
            "52:54:00:61:3D:9E",
            rec("52:54:00:61:3D:9E", passed=True, time="2026-10-15T07:59:00Z"),
            rec(
                "52:54:00:61:3D:9E",
                passed=False,
                time="2026-10-15T07:58:00Z",
                reason="22040 Wrong password",
                user="alice",
            ),
        ),
        "52:54:00:A2:D7:F0": auth_status(
            "52:54:00:A2:D7:F0",
            rec(
                "52:54:00:A2:D7:F0",
                passed=False,
                time="2026-10-15T07:50:00Z",
                reason="22040 Wrong password",
                user="alice",
            ),
        ),
        "02:00:5E:00:00:01": auth_status(
            "02:00:5E:00:00:01",
            rec(
                "02:00:5E:00:00:01",
                passed=False,
                time="2026-10-15T07:40:00Z",
                msg="5417",
                reason="11213 No response received from Network Access Device",
                nad="radius-client",
                nas_ip="10.16.104.82",
            ),
        ),
        "02:00:5E:00:00:02": auth_status(
            "02:00:5E:00:00:02",
            rec(
                "02:00:5E:00:00:02",
                passed=False,
                time="2026-10-15T07:30:00Z",
                user="INVALID",
                reason="22056 Subject not found in the applicable identity store(s)",
                nad="radius-client",
                nas_ip="10.16.104.82",
            ),
        ),
        "AA:AA:AA:AA:AA:AA": xml("<authStatusOutputList/>"),
    }

    def respond(request):  # type: ignore[no-untyped-def]
        mac = re.search(r"MACAddress/([^/]+)/", request.url.path).group(1)  # type: ignore[union-attr]
        return respx.MockResponse(200, text=statuses[mac])

    mock.get(url__regex=r".*/AuthStatus/MACAddress/.*").mock(side_effect=respond)


async def test_recent_failures_grouped(mock: respx.MockRouter) -> None:
    mock_failures(mock)
    out = body(
        await call_tool(
            make_server(),
            "ise_recent_auth_failures",
            {"macs": ["aaaa.aaaa.aaaa"], "since_minutes": 120},
        )
    )
    assert out["failed_attempts"] == 3
    reasons = {r["code"]: r for r in out["by_reason"]}
    assert reasons["22040"]["count"] == 2
    assert reasons["22040"]["users"] == ["alice"]
    assert reasons["22040"]["likely"]
    assert "22056" in reasons
    assert "11213" not in reasons and out["coa_failures_excluded"] == 1
    assert out["coverage"]["macs_checked"] == 5
    assert out["coverage"]["from"] == {"given": 1, "auth_list": 3, "endpoint_db": 1}
    assert [r["time"] for r in out["results"]] == sorted((r["time"] for r in out["results"]), reverse=True)
    # MnT's history leaves out repeated successful logins: a failing MAC may have passed since.
    assert "may have passed since" in out["history_note"] and "ise_find_session" in out["history_note"]


async def test_recent_failures_nad_filter_and_cap(mock: respx.MockRouter) -> None:
    mock_failures(mock)
    mock_nad(mock)
    out = body(
        await call_tool(
            make_server(),
            "ise_recent_auth_failures",
            {"nad": "mcp-test-sw1", "max_lookups": 2, "include_coa": True},
        )
    )
    assert out["coverage"]["macs_checked"] == 2 and out["coverage"]["capped"] is True
    assert "max_lookups" in out["coverage"]["note"]
    assert set(out["by_nad"]) == {"mcp-test-sw1"}
    assert out["failed_attempts"] == 2


async def test_recent_failures_rejects_bad_mac(mock: respx.MockRouter) -> None:
    with pytest.raises(ToolError, match="not a MAC address"):
        await call_tool(make_server(), "ise_recent_auth_failures", {"macs": ["nope"]})


async def test_recent_failures_none_found(mock: respx.MockRouter) -> None:
    mock.get("/admin/API/mnt/FailureReasons").respond(text=FAILURE_REASONS_XML)
    mock.get(url__regex=r".*/Session/AuthList/.*").respond(text=EMPTY_LIST)
    mock.get("/api/v1/endpoint").respond(json=[])
    out = body(await call_tool(make_server(), "ise_recent_auth_failures", {}))
    assert out["failed_attempts"] == 0
    assert "Silent drops" in out["note"]
    assert "history_note" not in out  # nothing listed, nothing to have passed since


async def test_recent_failures_tolerates_lookup_errors_and_flags_truncation(mock: respx.MockRouter) -> None:
    mock.get("/admin/API/mnt/FailureReasons").respond(text=FAILURE_REASONS_XML)
    mock.get(url__regex=r".*/Session/AuthList/.*").respond(text=EMPTY_LIST)
    busy = "52:54:00:00:00:01"
    many = auth_status(
        busy,
        *(
            rec(busy, passed=False, time=f"2026-10-15T07:{i:02d}:00Z", reason="22040 Wrong password")
            for i in range(50)
        ),
    )
    sep = "(:|%3A)"
    mock.get(url__regex=rf".*/AuthStatus/MACAddress/52{sep}54{sep}00{sep}00{sep}00{sep}01/.*").respond(
        text=many
    )
    mock.get(url__regex=rf".*/AuthStatus/MACAddress/52{sep}54{sep}00{sep}00{sep}00{sep}02/.*").respond(503)
    out = body(
        await call_tool(
            make_server(),
            "ise_recent_auth_failures",
            {"macs": [busy, "52:54:00:00:00:02"], "include_endpoint_db": False},
        )
    )
    assert out["failed_attempts"] == 50
    assert out["coverage"]["truncated_macs"] == [busy]
    assert out["coverage"]["lookup_errors"][0].startswith("52:54:00:00:00:02")
    assert out["coverage"]["capped"] is False

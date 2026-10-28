"""ise_nad_radius_stats: per-NAD latency and timeouts from MnT auth history.

Record shape follows the live ISE 3.5 AuthStatus capture (2026-10-24): `response_time` in ms,
`acs_server` = the PSN, `message_code` 5200 on success; addresses are documentation ranges.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

import pytest
import respx
from fastmcp.exceptions import ToolError

from ise_mcp._core.testing import call_tool
from ise_mcp.tools.activity import MAC_LESS_NOTE
from ise_mcp.tools.radius import compare, slow_nads, summarise, timeout_reason
from tests.unit.conftest import FAILURE_REASONS_XML, ers_page, make_server, xml

HQ_IP = "192.0.2.154"
BR1_IP = "198.51.100.12"
EMPTY = xml("<authStatusOutputList/>")


def ago(minutes: int) -> str:
    return (datetime.now(UTC) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def rec(
    mac: str,
    *,
    minutes_ago: int,
    ms: int | None,
    nad: str,
    nas_ip: str,
    method: str = "dot1x",
    passed: bool = True,
    reason: str = "",
    msg: str = "5200",
    psn: str = "ise-psn1",
) -> str:
    rt = f"<response_time>{ms}</response_time>" if ms is not None else ""
    return (
        f"<authStatusElements><passed>{str(passed).lower()}</passed>"
        f"<failed>{str(not passed).lower()}</failed>"
        f"<user_name>u</user_name><nas_ip_address>{nas_ip}</nas_ip_address>"
        f"<failure_reason>{reason}</failure_reason><calling_station_id>{mac}</calling_station_id>"
        f"<network_device_name>{nad}</network_device_name><acs_server>{psn}</acs_server>"
        f"<authentication_method>{method}</authentication_method><acs_timestamp>{ago(minutes_ago)}"
        f"</acs_timestamp><message_code>{msg}</message_code>{rt}</authStatusElements>"
    )


def status(mac: str, *records: str) -> str:
    return xml(
        f'<authStatusOutputList><authStatusList key="{mac}">{"".join(records)}</authStatusList>'
        "</authStatusOutputList>"
    )


def auth_list(*pairs: tuple[str, str]) -> str:
    rows = "".join(
        f"<activeSession><calling_station_id>{mac}</calling_station_id><nas_ip_address>{ip}</nas_ip_address>"
        "<server>ise-psn1</server></activeSession>"
        for mac, ip in pairs
    )
    return xml(f'<activeList noOfActiveSession="{len(pairs)}">{rows}</activeList>')


def body(out: object) -> dict:  # type: ignore[type-arg]
    return out if isinstance(out, dict) else json.loads(str(out))


M1, M2, M3, M4 = (f"52:54:00:00:00:0{i}" for i in range(1, 5))


def mock_mnt(mock: respx.MockRouter, statuses: dict[str, str], sessions: str) -> None:
    mock.get(url__regex=r".*/Session/AuthList/.*").respond(text=sessions)
    mock.get("/admin/API/mnt/FailureReasons").respond(text=FAILURE_REASONS_XML)

    def respond(request):  # type: ignore[no-untyped-def]
        mac = re.search(r"MACAddress/([^/]+)/", request.url.path).group(1)  # type: ignore[union-attr]
        return respx.MockResponse(200, text=statuses.get(mac, EMPTY))

    mock.get(url__regex=r".*/AuthStatus/MACAddress/.*").mock(side_effect=respond)


def branch_slow(mock: respx.MockRouter) -> None:
    """hq-sw1 answers EAP in ~100 ms; br1-edge (over the WAN) takes ~1.5 s and has one 5411."""
    mock_mnt(
        mock,
        {
            M1: status(
                M1,
                rec(M1, minutes_ago=5, ms=110, nad="hq-sw1", nas_ip=HQ_IP),
                rec(M1, minutes_ago=15, ms=90, nad="hq-sw1", nas_ip=HQ_IP),
            ),
            M2: status(M2, rec(M2, minutes_ago=8, ms=20, nad="hq-sw1", nas_ip=HQ_IP, method="mab")),
            M3: status(
                M3,
                rec(M3, minutes_ago=4, ms=1500, nad="br1-edge", nas_ip=BR1_IP),
                rec(
                    M3,
                    minutes_ago=6,
                    ms=None,
                    nad="br1-edge",
                    nas_ip=BR1_IP,
                    passed=False,
                    reason="5411 Supplicant stopped responding to ISE",
                    msg="5400",
                ),
                # A CoA result: not a login, never counted.
                rec(M3, minutes_ago=7, ms=5, nad="br1-edge", nas_ip=BR1_IP, msg="5205"),
            ),
            M4: status(M4, rec(M4, minutes_ago=9, ms=25, nad="br1-edge", nas_ip=BR1_IP, method="mab")),
        },
        auth_list((M1, HQ_IP), (M2, HQ_IP), (M3, BR1_IP), (M4, BR1_IP)),
    )


async def test_branch_eap_latency_and_timeouts_stand_out(mock: respx.MockRouter) -> None:
    branch_slow(mock)
    out = body(
        await call_tool(
            make_server(), "ise_nad_radius_stats", {"since_minutes": 30, "include_endpoint_db": False}
        )
    )
    rows = {r["nad"]: r for r in out["results"]}
    br1, hq = rows["br1-edge"], rows["hq-sw1"]
    assert out["results"][0]["nad"] == "br1-edge"  # slowest first
    assert br1["requests"] == 3 and br1["failed"] == 1 and br1["timeouts"] == 1
    assert br1["timeout_reasons"] == {"5411 Supplicant stopped responding to ISE": 1}
    assert br1["eap_avg_ms"] == 1500 and br1["mab_avg_ms"] == 25
    assert br1["nas_ips"] == [BR1_IP] and br1["psns"] == {"ise-psn1": 3}
    assert hq["eap_avg_ms"] == 100 and hq["max_ms"] == 110 and hq["timeouts"] == 0
    assert out["coa_records_excluded"] == 1
    assert out["slow_nads"] == [{"nad": "br1-edge", "method": "eap", "avg_ms": 1500, "others_median_ms": 100}]
    assert "br1-edge: EAP takes 1500 ms" in out["verdict"]
    assert "timeouts" in out["verdict"] and "path between those NADs and the PSN" in out["verdict"]
    assert out["coverage"]["macs_checked"] == 4 and not out["coverage"]["capped"]
    assert "not_available" in out


async def test_nad_filter_by_ip(mock: respx.MockRouter) -> None:
    branch_slow(mock)
    mock.get("/ers/config/networkdevice").respond(json=ers_page([]))
    out = body(
        await call_tool(
            make_server(),
            "ise_nad_radius_stats",
            {"nad": BR1_IP, "since_minutes": 30, "include_endpoint_db": False},
        )
    )
    assert [r["nad"] for r in out["results"]] == ["br1-edge"]
    assert out["nad_filter"] == BR1_IP
    assert out["coverage"]["macs_checked"] == 2  # only the sessions through br1


async def test_compare_previous_window(mock: respx.MockRouter) -> None:
    mock_mnt(
        mock,
        {
            M1: status(
                M1,
                rec(M1, minutes_ago=5, ms=900, nad="br1-edge", nas_ip=BR1_IP),
                rec(M1, minutes_ago=45, ms=120, nad="br1-edge", nas_ip=BR1_IP),
                rec(M1, minutes_ago=90, ms=9999, nad="br1-edge", nas_ip=BR1_IP),  # outside both windows
            ),
            M2: status(
                M2,
                rec(M2, minutes_ago=10, ms=105, nad="hq-sw1", nas_ip=HQ_IP),
                rec(M2, minutes_ago=40, ms=95, nad="hq-sw1", nas_ip=HQ_IP),
            ),
        },
        auth_list((M1, BR1_IP), (M2, HQ_IP)),
    )
    out = body(
        await call_tool(
            make_server(),
            "ise_nad_radius_stats",
            {"since_minutes": 30, "compare_previous": True, "include_endpoint_db": False},
        )
    )
    assert out["records"] == 2 and out["previous_records"] == 2
    eap = {c["nad"]: c for c in out["changes"] if c["metric"] == "eap_avg_ms"}
    assert eap["br1-edge"] == {
        "nad": "br1-edge",
        "metric": "eap_avg_ms",
        "now_ms": 900,
        "before_ms": 120,
        "delta_ms": 780,
        "rose": True,
    }
    assert "rose" not in eap["hq-sw1"]
    assert "br1-edge: eap_avg_ms rose from 120 to 900 ms" in out["verdict"]


async def test_compare_previous_caps_window(mock: respx.MockRouter) -> None:
    with pytest.raises(ToolError, match="at most 5040"):
        await call_tool(
            make_server(), "ise_nad_radius_stats", {"since_minutes": 6000, "compare_previous": True}
        )


async def test_nothing_in_window(mock: respx.MockRouter) -> None:
    mock_mnt(mock, {}, auth_list())
    out = body(await call_tool(make_server(), "ise_nad_radius_stats", {"include_endpoint_db": False}))
    assert out["results"] == [] and out["records"] == 0
    assert out["verdict"].startswith("No authentication record")


def test_timeout_reason_from_code_and_catalog() -> None:
    catalog = {"99999": {"reason": "Request timed out waiting for the NAD"}}
    assert timeout_reason({"passed": "false", "failure_reason": "5440 Endpoint abandoned"}, {}) == (
        "5440 Endpoint abandoned"
    )
    assert timeout_reason({"passed": "false", "message_code": "99999"}, catalog) == (
        "Request timed out waiting for the NAD"
    )
    assert timeout_reason({"passed": "false", "failure_reason": "22040 Wrong password"}, {}) is None
    assert timeout_reason({"passed": "true", "failure_reason": "5411 x"}, {}) is None


def test_slow_needs_a_real_gap() -> None:
    # 30 ms vs 10 ms MAB is 3x but only 20 ms apart: noise, not a slow path.
    rows = summarise(
        [
            {
                "network_device_name": "a",
                "authentication_method": "mab",
                "response_time": "30",
                "passed": "true",
            },
            {
                "network_device_name": "b",
                "authentication_method": "mab",
                "response_time": "10",
                "passed": "true",
            },
        ],
        {},
    )
    assert slow_nads(rows) == []
    assert compare(rows, {}) == []


# MAC-less RADIUS (#84): a router's `test aaa` / device-admin login carries no Calling-Station-Id, so it
# is never in the per-MAC history; only the user's latest MnT session (Session/UserName) can show it.
EDGE_IP = "192.0.2.14"
PROBE = "mcp-probe"


def user_session(*, minutes_ago: int, passed: bool, ms: int = 91) -> str:
    """Shaped like tests/fixtures/mnt_session.xml, without a MAC (router login)."""
    reason = "" if passed else "<failure_reason>22040 Wrong password</failure_reason>"
    return xml(
        f"<sessionParameters><passed>{int(passed)}</passed><failed>{int(not passed)}</failed>"
        f"<user_name>{PROBE}</user_name><nas_ip_address>{EDGE_IP}</nas_ip_address>"
        "<calling_station_id></calling_station_id><network_device_name>mcp-br1</network_device_name>"
        "<acs_server>ise-psn1</acs_server><authentication_protocol>PAP_ASCII</authentication_protocol>"
        f"<auth_acs_timestamp>{ago(minutes_ago)}</auth_acs_timestamp>{reason}"
        f"<message_code>{5200 if passed else 5400}</message_code><response_time>{ms}</response_time>"
        "<service_type>Login</service_type></sessionParameters>"
    )


async def test_nothing_found_says_mac_less_radius_is_not_covered(mock: respx.MockRouter) -> None:
    mock_mnt(mock, {}, auth_list())
    out = body(await call_tool(make_server(), "ise_nad_radius_stats", {"include_endpoint_db": False}))
    note = out["coverage"]["mac_less_radius"]
    assert note == MAC_LESS_NOTE
    assert "test aaa" in note and "user=" in note and "Live Logs" in note
    assert "only when the NAD also sent RADIUS accounting" in note and "leaves no MnT record" in note
    assert "mac_less_radius" in out["verdict"]
    assert "users_checked" not in out["coverage"]


async def test_user_session_covers_mac_less_router_login(mock: respx.MockRouter) -> None:
    mock_mnt(mock, {}, auth_list())
    mock.get(f"/admin/API/mnt/Session/UserName/{PROBE}").respond(
        text=user_session(minutes_ago=3, passed=False)
    )
    mock.get("/ers/config/networkdevice").respond(json=ers_page([]))
    out = body(
        await call_tool(
            make_server(),
            "ise_nad_radius_stats",
            {"user": PROBE, "nad": EDGE_IP, "since_minutes": 15, "include_endpoint_db": False},
        )
    )
    [row] = out["results"]
    assert row["nad"] == "mcp-br1" and row["nas_ips"] == [EDGE_IP]
    assert row["requests"] == 1 and row["failed"] == 1 and row["timeouts"] == 0
    assert row["other_avg_ms"] == 91 and row["endpoints"] == 0
    assert out["coverage"]["users_checked"] == {PROBE: "session in the window"}
    assert out["coverage"]["macs_checked"] == 0
    assert "mac_less_radius" not in out["coverage"]


async def test_user_session_outside_window_or_missing(mock: respx.MockRouter) -> None:
    from tests.unit.conftest import MISSING_SESSION

    mock_mnt(mock, {}, auth_list())
    route = mock.get(f"/admin/API/mnt/Session/UserName/{PROBE}")
    route.respond(text=user_session(minutes_ago=120, passed=True))
    args = {"user": PROBE, "since_minutes": 15, "include_endpoint_db": False}
    out = body(await call_tool(make_server(), "ise_nad_radius_stats", args))
    assert out["records"] == 0
    assert out["coverage"]["users_checked"][PROBE].startswith("latest session outside the window")
    assert "mac_less_radius" in out["coverage"]
    route.respond(500, text=MISSING_SESSION)
    out = body(await call_tool(make_server(), "ise_nad_radius_stats", args))
    assert out["coverage"]["users_checked"] == {PROBE: "no MnT session"}
    assert out["coverage"]["mac_less_radius"] == MAC_LESS_NOTE

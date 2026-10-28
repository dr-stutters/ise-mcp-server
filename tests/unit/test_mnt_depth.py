"""I75: MnT accounting totals (AcctStatus) and stale-session delete (Session/Delete)."""

from __future__ import annotations

from typing import Any

import respx
from fastmcp import Client

from ise_mcp.specs import MNT_DOC
from ise_mcp.tools.mnt_depth import accounting_rows, duration
from ise_mcp.xmlutil import parse_xml
from tests.unit.conftest import MISSING_SESSION, fixture_text, make_server, xml

MAC = "02:00:5E:00:00:01"
SESSION_PATH = f"/admin/API/mnt/Session/MACAddress/{MAC}"
DELETE_PATH = f"/admin/API/mnt/Session/Delete/MACAddress/{MAC}"
# Shape recorded live on ISE 3.5: an unknown MAC gets an empty acctStatusList.
EMPTY_ACCT = xml(
    '<acctStatusOutputList><acctStatusList macAddress="02:00:5E:00:00:01"/></acctStatusOutputList>'
)
ZERO_ACCT = xml(
    '<acctStatusOutputList><acctStatusList macAddress="02:00:5E:00:00:01"><acctStatusElements>'
    "<calling_station_id>02:00:5E:00:00:01</calling_station_id><audit_session_id>0A01</audit_session_id>"
    "<paks_in>0</paks_in><paks_out>0</paks_out><bytes_in>0</bytes_in><bytes_out>0</bytes_out>"
    "<session_time>95229</session_time><server>ise</server></acctStatusElements></acctStatusList>"
    "</acctStatusOutputList>"
)


def ended_session() -> str:
    return (
        fixture_text("mnt_session.xml")
        .replace("<acct_status_type>Start<", "<acct_status_type>Stop<")
        .replace(
            "<acct_acs_timestamp>2026-10-14T12:21:15.088Z<", "<acct_acs_timestamp>2026-10-14T13:00:00.000Z<"
        )
    )


async def call(name: str, args: dict[str, Any], **settings: Any) -> Any:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True, **settings)
    async with Client(server) as c:
        return (await c.call_tool(name, args)).structured_content


async def two_step(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(server) as c:
        preview = (await c.call_tool(name, args)).structured_content
        if preview.get("status") != "preview":
            return preview, None
        applied = (await c.call_tool(name, {**args, "confirm": preview["confirm"]})).structured_content
        return preview, applied


def test_duration() -> None:
    assert duration(95229) == "1d 2h 27m 9s"
    assert duration(61) == "1m 1s"
    assert duration(0) == "0s"


def test_accounting_rows_parse_fixture() -> None:
    _, data = parse_xml(fixture_text("mnt_acctstatus.xml"))
    rows = accounting_rows(data)
    assert len(rows) == 2
    assert rows[0] == {
        "mac": MAC,
        "audit_session_id": "0A000001000000C098542DB2",
        "psn": "ise",
        "packets_in": 1520,
        "packets_out": 1311,
        "bytes_in": 182400,
        "bytes_out": 953020,
        "session_time_seconds": 95229,
        "session_time": "1d 2h 27m 9s",
    }


async def test_get_accounting_totals(mock: respx.MockRouter) -> None:
    route = mock.get(f"/admin/API/mnt/AcctStatus/MACAddress/{MAC}/3600").respond(
        text=fixture_text("mnt_acctstatus.xml")
    )
    out = await call("ise_get_accounting", {"mac": "02-00-5e-00-00-01", "minutes": 60})
    assert route.called
    assert out["mac"] == MAC and len(out["sessions"]) == 2
    assert out["totals"]["bytes_in"] == 184000 and out["totals"]["bytes_out"] == 954000
    assert out["totals"]["packets_in"] == 1530 and out["totals"]["session_time_seconds"] == 95290
    assert "note" not in out


async def test_get_accounting_unknown_mac_is_empty(mock: respx.MockRouter) -> None:
    mock.get(f"/admin/API/mnt/AcctStatus/MACAddress/{MAC}/86400").respond(text=EMPTY_ACCT)
    out = await call("ise_get_accounting", {"mac": MAC})
    assert out["sessions"] == [] and "totals" not in out
    assert "no accounting" in out["note"]


async def test_get_accounting_zero_counters_note(mock: respx.MockRouter) -> None:
    mock.get(f"/admin/API/mnt/AcctStatus/MACAddress/{MAC}/86400").respond(text=ZERO_ACCT)
    out = await call("ise_get_accounting", {"mac": MAC})
    assert out["totals"]["bytes_in"] == 0
    assert "newinfo periodic" in out["note"]


async def test_delete_session_hidden_without_dangerous() -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_delete_session" not in names and "ise_get_accounting" in names


async def test_delete_ended_session_preview_and_confirm(mock: respx.MockRouter) -> None:
    mock.get(SESSION_PATH).mock(
        side_effect=[
            respx.MockResponse(200, text=ended_session()),  # preview
            respx.MockResponse(200, text=ended_session()),  # confirm re-plans
            respx.MockResponse(500, text=MISSING_SESSION),  # after the delete
        ]
    )
    delete = mock.delete(DELETE_PATH).respond(
        text=xml("<mnt-rest-result><http-code>200</http-code></mnt-rest-result>")
    )
    preview, applied = await two_step("ise_delete_session", {"mac": MAC})
    assert preview["status"] == "preview"
    assert preview["preview"]["network_device_name"] == "mcp-test-radius-client"
    assert "accounting Stop at 2026-10-14T13:00:00.000Z" in preview["preview"]["why_stale"]
    assert applied["result"]["deleted"] is True
    assert delete.call_count == 1


async def test_delete_active_session_blocked(mock: respx.MockRouter) -> None:
    mock.get(SESSION_PATH).respond(text=fixture_text("mnt_session.xml"))
    delete = mock.delete(DELETE_PATH).respond(200)
    out = await call("ise_delete_session", {"mac": MAC})
    assert out["status"] == "blocked"
    assert any("ise_coa_disconnect" in b for b in out["blockers"])
    assert not delete.called


async def test_delete_active_session_when_nad_confirmed_gone(mock: respx.MockRouter) -> None:
    mock.get(SESSION_PATH).respond(text=fixture_text("mnt_session.xml"))
    out = await call("ise_delete_session", {"mac": MAC, "nad_confirmed_gone": True})
    assert out["status"] == "preview"
    assert "no session for this MAC" in out["preview"]["why_stale"]


async def test_delete_no_session_blocked(mock: respx.MockRouter) -> None:
    mock.get(SESSION_PATH).respond(500, text=MISSING_SESSION)
    out = await call("ise_delete_session", {"mac": MAC})
    assert out["status"] == "blocked"
    assert any("nothing to delete" in b for b in out["blockers"])


async def test_delete_protected_mac_blocked(mock: respx.MockRouter) -> None:
    mock.get(SESSION_PATH).respond(text=ended_session())
    out = await call("ise_delete_session", {"mac": MAC}, protect_macs="02-00-5e-00-00-01")
    assert out["status"] == "blocked"
    assert any("ISE_PROTECT_MACS" in b for b in out["blockers"])


async def test_delete_reports_session_still_there(mock: respx.MockRouter) -> None:
    mock.get(SESSION_PATH).respond(text=ended_session())
    mock.delete(DELETE_PATH).respond(200)
    _, applied = await two_step("ise_delete_session", {"mac": MAC})
    assert applied["result"]["deleted"] is False and "still returns" in applied["result"]["note"]


def test_mnt_spec_describes_new_calls() -> None:
    paths = MNT_DOC["paths"]
    assert "get" in paths["/admin/API/mnt/AcctStatus/MACAddress/{mac}/{seconds}"]
    assert "delete" in paths["/admin/API/mnt/Session/Delete/MACAddress/{mac}"]

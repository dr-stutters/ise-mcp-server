"""ise_coa_bulk (I66) and the detail filters on ise_list_active_sessions, on a mocked 50-session
ActiveList built from the recorded MnT fixtures' shapes."""

from __future__ import annotations

import json
from typing import Any

import respx
from fastmcp import Client

from ise_mcp.tools.coa_bulk import ndg_matches, port_matches, sgt_matches, ssid_of
from tests.unit.conftest import MISSING_SESSION, ers_page, make_server, xml

SWITCH = "192.0.2.50"  # the lab switch: two sessions
OTHER = "192.0.2.60"  # 48 more sessions elsewhere


def mac(i: int) -> str:
    return f"02:00:5E:00:01:{i:02X}"


def active_list(rows: list[dict[str, str]]) -> str:
    body = "".join(
        "<activeSession>" + "".join(f"<{k}>{v}</{k}>" for k, v in r.items()) + "</activeSession>"
        for r in rows
    )
    return xml(f'<activeList noOfActiveSession="{len(rows)}">{body}</activeList>')


def row(i: int, nas_ip: str, user: str | None = None) -> dict[str, str]:
    return {
        "user_name": user or f"user{i}",
        "calling_station_id": mac(i),
        "nas_ip_address": nas_ip,
        "audit_session_id": f"C0000201000000{i:02X}",
        "server": "ise",
        "framed_ip_address": f"198.51.100.{i + 1}",
    }


FIFTY = [row(1, SWITCH, "alice"), row(2, SWITCH, "bob")] + [row(i, OTHER) for i in range(3, 51)]


def session_xml(
    i: int,
    nas_ip: str,
    *,
    profiles: str | None = "PermitAccess",
    sgt: str | None = None,
    policy_set: str | None = "Wired",
    called: str | None = None,
    stop: bool = False,
    user: str | None = None,
    nad: str = "mcp-test-switch",
) -> str:
    fields = {
        "user_name": user or f"user{i}",
        "nas_ip_address": nas_ip,
        "calling_station_id": mac(i),
        "network_device_name": nad,
        "acs_server": "ise",
        "framed_ip_address": f"198.51.100.{i + 1}",
        "audit_session_id": f"C0000201000000{i:02X}",
        "nas_port_id": f"GigabitEthernet1/0/{i}",
        "auth_acs_timestamp": "2026-10-27T10:00:00.000Z",
        "acct_acs_timestamp": "2026-10-27T10:00:01.000Z",
        "acct_status_type": "Stop" if stop else "Start",
    }
    if profiles:
        fields["selected_azn_profiles"] = profiles
        fields["authentication_method"] = "dot1x"
    if sgt:
        fields["cts_security_group"] = sgt
    if called:
        fields["called_station_id"] = called
    if policy_set:
        fields["other_attr_string"] = f"ISEPolicySetName={policy_set}:!:AuthorizationPolicyMatchedRule=r1:!:"
    return xml(
        "<sessionParameters>" + "".join(f"<{k}>{v}</{k}>" for k, v in fields.items()) + "</sessionParameters>"
    )


def mock_sessions(mock: respx.MockRouter, rows: list[dict[str, str]], **per: dict[str, Any]) -> None:
    """ActiveList plus a detail per session; `per` overrides session_xml kwargs by MAC."""
    mock.get("/admin/API/mnt/Session/ActiveList").respond(text=active_list(rows))
    for r in rows:
        m = r["calling_station_id"]
        kw = per.get(m, {})
        mock.get(f"/admin/API/mnt/Session/MACAddress/{m}").respond(
            text=session_xml(int(m[-2:], 16), r["nas_ip_address"], user=r["user_name"], **kw)
        )


def mock_nad_by_ip(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/networkdevice", params={"filter": f"ipaddress.EQ.{SWITCH}"}).respond(
        json=ers_page([{"id": "n1", "name": "mcp-test-switch"}])
    )
    mock.get("/ers/config/networkdevice/n1").respond(json=nad_detail("n1", "mcp-test-switch", SWITCH))


def nad_detail(nid: str, name: str, ip: str, groups: list[str] | None = None) -> dict[str, Any]:
    return {
        "NetworkDevice": {
            "id": nid,
            "name": name,
            "NetworkDeviceIPList": [{"ipaddress": ip, "mask": 32}],
            "NetworkDeviceGroupList": groups or ["Location#All Locations", "Device Type#All Device Types"],
        }
    }


def reauth_route(mock: respx.MockRouter, i: int, ok: bool = True) -> respx.Route:
    return mock.get(f"/admin/API/mnt/CoA/Reauth/ise/{mac(i)}/0").respond(
        text=xml(f'<remoteCoA requestType="reauth"><results>{str(ok).lower()}</results></remoteCoA>')
    )


async def run(args: dict[str, Any], *, apply: bool = True, **settings: Any) -> tuple[Any, Any]:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True, **settings)
    async with Client(server) as c:
        preview = (await c.call_tool("ise_coa_bulk", args)).structured_content
        if preview.get("status") != "preview" or not apply:
            return preview, None
        applied = (
            await c.call_tool("ise_coa_bulk", {**args, "confirm": preview["confirm"]})
        ).structured_content
        return preview, applied


async def test_hidden_without_dangerous() -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_coa_bulk" not in names


async def test_scope_nad_two_of_fifty(mock: respx.MockRouter) -> None:
    mock_sessions(mock, FIFTY)
    mock_nad_by_ip(mock)
    r1, r2 = reauth_route(mock, 1), reauth_route(mock, 2)
    preview, applied = await run({"scope": "nad", "value": SWITCH})
    assert preview["status"] == "preview"
    assert preview["blast_radius"] == 2
    sessions = preview["preview"]["sessions"]
    assert {s["mac"] for s in sessions} == {mac(1), mac(2)}
    assert sessions[0]["port"].startswith("GigabitEthernet1/0/") and sessions[0]["nad"] == "mcp-test-switch"
    assert applied["result"]["sent"] == 2 and applied["result"]["acknowledged"] == 2
    assert r1.called and r2.called


async def test_cap_refuses_more_than_max(mock: respx.MockRouter) -> None:
    mock.get("/admin/API/mnt/Session/ActiveList").respond(text=active_list(FIFTY))
    mock.get("/ers/config/networkdevice", params={"filter": f"ipaddress.EQ.{OTHER}"}).respond(
        json=ers_page([{"id": "n2", "name": "edge"}])
    )
    mock.get("/ers/config/networkdevice/n2").respond(json=nad_detail("n2", "edge", OTHER))
    preview, _ = await run({"scope": "nad", "value": OTHER})
    assert preview["status"] == "blocked"
    assert any("48 live sessions" in b and "max=25" in b for b in preview["blockers"])


async def test_blast_radius_limit_applies(mock: respx.MockRouter) -> None:
    mock_sessions(mock, FIFTY)
    mock_nad_by_ip(mock)
    preview, _ = await run({"scope": "nad", "value": SWITCH}, mcp_max_blast_radius=1)
    assert preview["status"] == "blocked"
    assert "blast" in json.dumps(preview).lower()


async def test_empty_scope_message(mock: respx.MockRouter) -> None:
    mock_sessions(mock, FIFTY[:2])
    preview, _ = await run({"scope": "user", "value": "nobody"})
    assert preview["status"] == "blocked"
    assert any("No live session matches user='nobody'" in b for b in preview["blockers"])


async def test_scope_user_exact(mock: respx.MockRouter) -> None:
    rows = [row(1, SWITCH, "alice"), row(2, SWITCH, "alice2")]
    mock_sessions(mock, rows)
    reauth_route(mock, 1)
    preview, applied = await run({"scope": "user", "value": "ALICE"})
    assert preview["blast_radius"] == 1
    assert applied["result"]["results"][0]["mac"] == mac(1)


async def test_scope_ndg(mock: respx.MockRouter) -> None:
    mock_sessions(mock, FIFTY)
    mock.get("/ers/config/networkdevice").respond(
        json=ers_page([{"id": "n1", "name": "mcp-test-switch"}, {"id": "n2", "name": "edge"}])
    )
    mock.get("/ers/config/networkdevice/n1").respond(
        json=nad_detail("n1", "mcp-test-switch", SWITCH, ["Location#All Locations#Sydney"])
    )
    mock.get("/ers/config/networkdevice/n2").respond(
        json=nad_detail("n2", "edge", OTHER, ["Location#All Locations#Perth"])
    )
    preview, _ = await run({"scope": "ndg", "value": "sydney"}, apply=False)
    assert preview["status"] == "preview" and preview["blast_radius"] == 2
    assert preview["preview"]["nads_in_group"] == ["mcp-test-switch"]
    missing, _ = await run({"scope": "ndg", "value": "Brisbane"}, apply=False)
    assert missing["status"] == "blocked" and "ise_list_ndgs" in json.dumps(missing["blockers"])


async def test_scope_authz_profile_with_fallback_and_undetermined(mock: respx.MockRouter) -> None:
    rows = [row(1, SWITCH), row(2, SWITCH), row(3, OTHER), row(4, OTHER)]
    mock_sessions(
        mock,
        rows,
        **{
            mac(1): {"profiles": "Employee_dACL,PermitAccess"},
            mac(2): {"profiles": None},  # accounting-only latest event: auth record says Employee_dACL
            mac(3): {"profiles": "Guest"},
            mac(4): {"profiles": None},  # nothing anywhere: undetermined
        },
    )
    hist = (
        '<authStatusOutputList><authStatusList key="{m}"><authStatusElements><passed>true</passed>'
        "<calling_station_id>{m}</calling_station_id><acs_timestamp>2026-10-27T09:59:00Z</acs_timestamp>"
        "<selected_azn_profiles>{p}</selected_azn_profiles><message_code>5200</message_code>"
        "</authStatusElements></authStatusList></authStatusOutputList>"
    )
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{mac(2)}/86400/5/All").respond(
        text=xml(hist.format(m=mac(2), p="Employee_dACL"))
    )
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{mac(4)}/86400/5/All").respond(
        text=xml("<authStatusOutputList/>")
    )
    preview, _ = await run({"scope": "authz_profile", "value": "employee_dacl"}, apply=False)
    assert preview["status"] == "preview"
    assert {s["mac"] for s in preview["preview"]["sessions"]} == {mac(1), mac(2)}
    assert [u["mac"] for u in preview["preview"]["undetermined"]] == [mac(4)]
    assert any("left out" in s for s in preview["side_effects"])


async def test_scope_sgt_policy_set_ssid(mock: respx.MockRouter) -> None:
    rows = [row(1, SWITCH), row(2, SWITCH), row(3, OTHER)]
    mock_sessions(
        mock,
        rows,
        **{
            mac(1): {"sgt": "Employees", "policy_set": "Wired", "called": "AA-BB-CC-DD-EE-01:corp"},
            mac(2): {
                "sgt": "Contractors (5/0005)",
                "policy_set": "Wireless",
                "called": "AA-BB-CC-DD-EE-02:guest",
            },
            mac(3): {"sgt": "Employees", "policy_set": "Wireless", "called": "AA-BB-CC-DD-EE-03:corp"},
        },
    )
    sgt, _ = await run({"scope": "sgt", "value": "Employees"}, apply=False)
    assert {s["mac"] for s in sgt["preview"]["sessions"]} == {mac(1), mac(3)}
    tag, _ = await run({"scope": "sgt", "value": "5"}, apply=False)
    assert [s["mac"] for s in tag["preview"]["sessions"]] == [mac(2)]
    ps, _ = await run({"scope": "policy_set", "value": "wireless"}, apply=False)
    assert {s["mac"] for s in ps["preview"]["sessions"]} == {mac(2), mac(3)}
    ssid, _ = await run({"scope": "ssid", "value": "corp"}, apply=False)
    assert {s["mac"] for s in ssid["preview"]["sessions"]} == {mac(1), mac(3)}


async def test_ended_sessions_excluded(mock: respx.MockRouter) -> None:
    mock_sessions(mock, FIFTY[:2], **{mac(2): {"stop": True}})
    mock_nad_by_ip(mock)
    preview, _ = await run({"scope": "nad", "value": SWITCH}, apply=False)
    assert preview["blast_radius"] == 1
    assert preview["preview"]["skipped"][0]["mac"] == mac(2)
    assert "ended" in preview["preview"]["skipped"][0]["reason"]


async def test_protected_mac_refuses_bulk(mock: respx.MockRouter) -> None:
    mock_sessions(mock, FIFTY[:2])
    mock_nad_by_ip(mock)
    preview, _ = await run({"scope": "nad", "value": SWITCH}, protect_macs=mac(2))
    assert preview["status"] == "blocked"
    assert any("protected-MAC" in b for b in preview["blockers"])


async def test_partial_failures_get_a_row_each(mock: respx.MockRouter) -> None:
    rows = [row(1, SWITCH), row(2, SWITCH), row(3, SWITCH)]
    mock_sessions(mock, rows)
    mock_nad_by_ip(mock)
    reauth_route(mock, 1)
    reauth_route(mock, 2, ok=False)
    mock.get(f"/admin/API/mnt/CoA/Reauth/ise/{mac(3)}/0").respond(500, text=MISSING_SESSION)
    _, applied = await run({"scope": "nad", "value": SWITCH})
    res = applied["result"]
    assert res["sent"] == 3 and res["acknowledged"] == 1 and res["not_acknowledged"] == 2
    by_mac = {r["mac"]: r for r in res["results"]}
    assert by_mac[mac(1)]["coa_acknowledged"] is True
    assert by_mac[mac(2)]["coa_acknowledged"] is False and "note" in by_mac[mac(2)]
    assert by_mac[mac(3)]["coa_acknowledged"] is False and "error" in by_mac[mac(3)]
    assert "retry" in res["note"]


async def test_disconnect_is_session_terminate(mock: respx.MockRouter) -> None:
    mock_sessions(mock, FIFTY[:1])
    mock_nad_by_ip(mock)
    disc = mock.get(f"/admin/API/mnt/CoA/Disconnect/ise/{mac(1)}/0/{SWITCH}/198.51.100.2").respond(
        text=xml('<remoteCoA requestType="disconnect"><results>true</results></remoteCoA>')
    )
    preview, applied = await run({"scope": "nad", "value": SWITCH, "action": "disconnect"})
    assert "end" in preview["side_effects"][0]
    assert applied["result"]["acknowledged"] == 1 and disc.called


async def test_confirm_refused_when_sessions_change(mock: respx.MockRouter) -> None:
    mock_sessions(mock, FIFTY[:2])
    mock_nad_by_ip(mock)
    coa = reauth_route(mock, 1)
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(server) as c:
        args = {"scope": "nad", "value": SWITCH}
        preview = (await c.call_tool("ise_coa_bulk", args)).structured_content
        mock_sessions(mock, FIFTY[:1])  # one session left before the confirm
        out = await c.call_tool("ise_coa_bulk", {**args, "confirm": preview["confirm"]}, raise_on_error=False)
    assert out.is_error or (out.structured_content or {}).get("status") != "applied"
    assert not coa.called


async def test_list_active_sessions_detail_filters(mock: respx.MockRouter) -> None:
    rows = [row(1, SWITCH), row(2, SWITCH), row(3, OTHER)]
    mock_sessions(
        mock,
        rows,
        **{
            mac(1): {"profiles": "Employee_dACL"},
            mac(2): {"profiles": "Guest"},
            mac(3): {"profiles": "Employee_dACL"},
        },
    )
    mock.get("/ers/config/networkdevice").respond(json=ers_page([]))
    mock.get("/admin/API/mnt/Session/PostureCount").respond(
        text=xml("<sessionCount><count>0</count></sessionCount>")
    )
    mock.get("/admin/API/mnt/Session/ProfilerCount").respond(
        text=xml("<sessionCount><count>3</count></sessionCount>")
    )
    async with Client(make_server()) as c:
        out = (
            await c.call_tool(
                "ise_list_active_sessions", {"authz_profile": "Employee_dACL", "response_format": "json"}
            )
        ).structured_content
        assert {r["mac"] for r in out["results"]} == {mac(1), mac(3)}
        port = (
            await c.call_tool("ise_list_active_sessions", {"port": "Gi1/0/2", "response_format": "json"})
        ).structured_content
        assert [r["mac"] for r in port["results"]] == [mac(2)]
        assert port["results"][0]["port"] == "GigabitEthernet1/0/2"


def test_matchers() -> None:
    assert port_matches("Gi1/0/5", "GigabitEthernet1/0/5")
    assert not port_matches("Gi1/0/5", "GigabitEthernet1/0/50")
    assert sgt_matches("employees", "Employees (4/0004)") and sgt_matches("4", "Employees (4/0004)")
    assert not sgt_matches("40", "Employees (4/0004)")
    assert ndg_matches("Location#All Locations", "Location#All Locations#Sydney")
    assert ndg_matches("sydney", "Location#All Locations#Sydney")
    assert not ndg_matches("syd", "Location#All Locations#Sydney")
    assert ssid_of({"called_station_id": "AA:BB:CC:DD:EE:FF:corp-wifi"}) == "corp-wifi"
    assert ssid_of({"called_station_id": "AA-BB-CC-DD-EE-FF:corp"}) == "corp"
    assert ssid_of({"called_station_id": "AA-BB-CC-DD-EE-FF"}) is None

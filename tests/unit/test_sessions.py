from __future__ import annotations

import json

import pytest
import respx

from ise_mcp._core.testing import call_tool
from tests.unit.conftest import (
    FAILURE_REASONS_XML,
    MISSING_SESSION,
    ers_page,
    fixture_json,
    fixture_text,
    make_server,
    xml,
)

MAC_OK = "02:00:5E:00:00:01"
MAC_BAD = "02:00:5E:00:00:02"
NAD_ID = "b47cd5b0-c7c9-11f1-a449-d6ebb9f74d33"
USER_ID = "a7d01d23-88c0-41bb-a98f-ee7291872321"


def text_of(out: object) -> dict:  # type: ignore[type-arg]
    return out if isinstance(out, dict) else json.loads(str(out))


def mock_common(mock: respx.MockRouter) -> None:
    mock.get("/admin/API/mnt/FailureReasons").respond(text=FAILURE_REASONS_XML)
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{MAC_BAD}/86400/50/All").respond(
        text=fixture_text("mnt_authstatus_fail.xml")
    )
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{MAC_OK}/86400/50/All").respond(
        text=fixture_text("mnt_authstatus_pass.xml")
    )
    mock.get(f"/admin/API/mnt/Session/MACAddress/{MAC_OK}").respond(text=fixture_text("mnt_session.xml"))
    mock.get(f"/admin/API/mnt/Session/MACAddress/{MAC_BAD}").respond(500, text=MISSING_SESSION)
    mock.get("/ers/config/networkdevice", params={"filter": "ipaddress.EQ.192.0.2.50"}).respond(
        json=ers_page([{"id": NAD_ID, "name": "mcp-test-radius-client"}])
    )
    mock.get(f"/ers/config/networkdevice/{NAD_ID}").respond(json=fixture_json("ers_networkdevice.json"))
    mock.get("/ers/config/internaluser", params={"filter": "name.EQ.mcp-test-user"}).respond(
        json=ers_page([{"id": USER_ID, "name": "mcp-test-user"}])
    )
    mock.get(f"/ers/config/internaluser/{USER_ID}").respond(
        json={
            "InternalUser": {
                "id": USER_ID,
                "name": "mcp-test-user",
                "enabled": False,
                "identityGroups": "g1",
                "password": "secret-pw",
                "passwordIDStore": "Internal Users",
            }
        }
    )
    mock.get("/ers/config/identitygroup").respond(json=ers_page([{"id": "g1", "name": "Employees"}]))


async def test_active_sessions(mock: respx.MockRouter) -> None:
    mock.get("/admin/API/mnt/Session/ActiveList").respond(text=fixture_text("mnt_activelist.xml"))
    mock.get("/admin/API/mnt/Session/PostureCount").respond(
        text=xml("<sessionCount><count>0</count></sessionCount>")
    )
    mock.get("/admin/API/mnt/Session/ProfilerCount").respond(
        text=xml("<sessionCount><count>3</count></sessionCount>")
    )
    mock.get("/ers/config/networkdevice", params={"filter": "ipaddress.EQ.192.0.2.50"}).respond(
        json=ers_page([{"id": NAD_ID, "name": "mcp-test-radius-client"}])
    )
    mock.get(f"/ers/config/networkdevice/{NAD_ID}").respond(json=fixture_json("ers_networkdevice.json"))
    out = text_of(await call_tool(make_server(), "ise_list_active_sessions", {"response_format": "json"}))
    assert out["active_sessions"] == "1"
    assert out["profiler_sessions"] == "3"
    assert out["results"][0]["mac"] == MAC_OK
    assert out["results"][0]["nad"] == "mcp-test-radius-client"
    # a NAD given by (part of) its name filters by its IPs
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.radius-client"}).respond(
        json=ers_page([])
    )
    mock.get("/ers/config/networkdevice", params={"filter": "name.CONTAINS.radius-client"}).respond(
        json=ers_page([{"id": NAD_ID, "name": "mcp-test-radius-client"}])
    )
    out = text_of(
        await call_tool(
            make_server(), "ise_list_active_sessions", {"nad": "radius-client", "response_format": "json"}
        )
    )
    assert out["returned"] == 1 and out["nad_filter"].startswith("mcp-test-radius-client (partial match")


async def test_active_sessions_empty(mock: respx.MockRouter) -> None:
    mock.get("/admin/API/mnt/Session/ActiveList").respond(text=xml('<activeList noOfActiveSession="0"/>'))
    mock.get("/admin/API/mnt/Session/PostureCount").respond(
        text=xml("<sessionCount><count>0</count></sessionCount>")
    )
    mock.get("/admin/API/mnt/Session/ProfilerCount").respond(
        text=xml("<sessionCount><count>0</count></sessionCount>")
    )
    out = text_of(await call_tool(make_server(), "ise_list_active_sessions", {"response_format": "json"}))
    assert out["results"] == []


async def test_find_session_policy(mock: respx.MockRouter) -> None:
    mock_common(mock)
    out = await call_tool(make_server(), "ise_find_session", {"mac": "02-00-5e-00-00-01"})
    assert out["found"] is True
    assert out["session"]["matched_policy"] == {
        "policy_set": "Default",
        "authentication_rule": "Dot1X",
        "authorization_rule": "Basic_Authenticated_Access",
    }
    assert "other_attr_string" not in out["session"]


async def test_find_session_none(mock: respx.MockRouter) -> None:
    mock_common(mock)
    out = await call_tool(make_server(), "ise_find_session", {"mac": MAC_BAD})
    assert out["found"] is False


async def test_auth_history_decodes(mock: respx.MockRouter) -> None:
    mock_common(mock)
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{MAC_BAD}/3600/20/All").respond(
        text=fixture_text("mnt_authstatus_fail.xml")
    )
    out = await call_tool(
        make_server(), "ise_get_auth_history", {"mac": MAC_BAD, "minutes": 60, "include_steps": True}
    )
    attempt = out["attempts"][0]
    assert attempt["result"] == "FAIL"
    assert attempt["failure"]["code"] == "22040"
    assert attempt["failure"]["resolution"] == "Check the user for credentials."
    assert "22040 Wrong password" in attempt["steps"]


async def test_failure_reason_search(mock: respx.MockRouter) -> None:
    mock_common(mock)
    out = text_of(await call_tool(make_server(), "ise_list_failure_reasons", {"query": "shared secrets"}))
    assert [r["code"] for r in out["results"]] == ["11036"]
    assert "likely" in out["results"][0]
    out = text_of(await call_tool(make_server(), "ise_list_failure_reasons", {"query": "22056"}))
    assert out["results"][0]["reason"].startswith("Subject not found")


async def test_why_auth_failed_wrong_password(mock: respx.MockRouter) -> None:
    mock_common(mock)
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": MAC_BAD})
    assert "FAILED" in out["verdict"]
    assert out["failure"]["code"] == "22040"
    assert out["checks"]["network_device"]["name"] == "mcp-test-radius-client"
    assert out["checks"]["internal_user"]["enabled"] is False
    assert "secret-pw" not in json.dumps(out)
    assert "REDACTED" not in json.dumps(out)


async def test_why_auth_failed_passed(mock: respx.MockRouter) -> None:
    mock_common(mock)
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": MAC_OK})
    assert out["verdict"].startswith("No login failures")
    assert out["matched_policy"]["authorization_rule"] == "Basic_Authenticated_Access"


async def test_why_auth_failed_no_records(mock: respx.MockRouter) -> None:
    mac = "02:00:5E:00:00:09"
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{mac}/86400/50/All").respond(
        text=xml(f'<authStatusOutputList><authStatusList key="{mac}"/></authStatusOutputList>')
    )
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{mac}/604800/5/All").respond(
        text=xml(f'<authStatusOutputList><authStatusList key="{mac}"/></authStatusOutputList>')
    )
    mock.get(f"/admin/API/mnt/Session/MACAddress/{mac}").respond(500, text=MISSING_SESSION)
    mock.get(f"/api/v1/endpoint/{mac}").respond(404, json={"message": "not found"})
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": mac})
    assert "no authentication record" in out["verdict"]
    # Never seen at all: a drop or a wrong MAC lead, but an abandoned EAP conversation is named too.
    assert "never reached ISE" in out["verdict"] and "abandoned" in out["verdict"]
    assert out["likely_causes"][0].startswith("ISE dropped the request")
    assert out["endpoint_known_to_ise"] is False
    assert any("ise_get_nad" in s for s in out["next_steps"])


async def test_why_auth_failed_username_without_session(mock: respx.MockRouter) -> None:
    mock_common(mock)
    mock.get("/admin/API/mnt/Session/UserName/mcp-test-user").respond(500, text=MISSING_SESSION)
    out = await call_tool(make_server(), "ise_why_auth_failed", {"username": "mcp-test-user"})
    assert "Give the endpoint MAC" in out["verdict"]
    assert out["internal_user"]["exists_in_internal_users"] is True


async def test_endpoint_360(mock: respx.MockRouter) -> None:
    mock_common(mock)
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{MAC_OK}/86400/5/All").respond(
        text=fixture_text("mnt_authstatus_pass.xml")
    )
    mock.get(f"/api/v1/endpoint/{MAC_OK}").respond(
        json={"id": "e1", "mac": MAC_OK, "groupId": "grp1", "staticGroupAssignment": True, "profileId": "p1"}
    )
    mock.get("/ers/config/endpointgroup").respond(
        json=ers_page([{"id": "grp1", "name": "mcp-test-endpoints"}])
    )
    mock.get("/ers/config/profilerprofile/p1").respond(
        json={"ProfilerProfile": {"id": "p1", "name": "Cisco-Device"}}
    )
    mock.get("/ers/config/ancendpoint").respond(json=ers_page([]))
    mock.get("/api/v1/endpoint/getRejected").respond(json={"response": [MAC_OK.lower()]})
    out = await call_tool(make_server(), "ise_endpoint_360", {"mac": MAC_OK})
    assert "rejected" in out["rejected"]
    assert out["endpoint"]["group"] == "mcp-test-endpoints"
    assert out["endpoint"]["profile"] == "Cisco-Device"
    assert out["session"]["matched_policy"]["policy_set"] == "Default"
    assert out["recent_auths"][0]["result"] == "PASS"
    assert out["anc_policy"] == "none"


COA_NAK = (
    "<authStatusElements><passed>false</passed><failed>true</failed><user_name></user_name>"
    "<nas_ip_address>192.0.2.50</nas_ip_address><failure_reason></failure_reason>"
    f"<calling_station_id>{MAC_OK}</calling_station_id>"
    "<network_device_name>mcp-test-radius-client</network_device_name><acs_server>ise</acs_server>"
    "<acs_timestamp>2026-10-14T13:00:00.000Z</acs_timestamp><execution_steps>11204,11220</execution_steps>"
    "<response>{RadiusPacketType=CoANAK; cisco-av-pair=reauthenticate-type=rerun; "
    "cisco-av-pair=command=reauthenticate; cisco-av-pair=audit-session-id=X; cisco-command-code=2; }"
    "</response><message_code>5417</message_code></authStatusElements>"
)


def _with_coa(only_coa: bool = False) -> str:
    text = fixture_text("mnt_authstatus_pass.xml")
    head, sep, rest = text.partition("<authStatusElements>")
    if only_coa:
        return head + COA_NAK + "</authStatusList></authStatusOutputList>"
    return head + COA_NAK + sep + rest


async def test_why_auth_failed_ignores_coa_records(mock: respx.MockRouter) -> None:
    mock_common(mock)
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{MAC_OK}/86400/50/All").respond(text=_with_coa())
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": MAC_OK})
    assert out["verdict"].startswith("No login failures"), out["verdict"]
    assert "CoA" in out["verdict"]
    assert out["coa_failures"]["count"] == 1
    assert "NAK" in out["coa_failures"]["meaning"]
    assert out["attempts_in_window"]["coa_records"] == 1


async def test_why_auth_failed_only_coa(mock: respx.MockRouter) -> None:
    mock_common(mock)
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{MAC_OK}/86400/50/All").respond(
        text=_with_coa(only_coa=True)
    )
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": MAC_OK})
    assert out["verdict"].startswith("No login attempt"), out["verdict"]


async def test_auth_history_labels_coa_and_compacts_reply(mock: respx.MockRouter) -> None:
    mock_common(mock)
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{MAC_OK}/86400/20/All").respond(text=_with_coa())
    out = await call_tool(make_server(), "ise_get_auth_history", {"mac": MAC_OK})
    coa, login = out["attempts"][0], out["attempts"][1]
    assert coa["kind"] == "coa"
    assert coa["reply"] == "RadiusPacketType=CoANAK; reauthenticate-type=rerun; command=reauthenticate"
    assert "kind" not in login
    assert "Class=" not in login.get("reply", "")
    assert "response" not in login
    assert "Repeated successful logins may be missing" in out["history_note"]
    assert "ise_find_session" in out["history_note"]


def test_compact_reply_drops_key_material() -> None:
    from ise_mcp.tools.sessions import compact_reply

    raw = (
        "{Class=CACS:1; EAP-Key-Name=0d:8c; cisco-av-pair=ACS:CiscoSecure-Defined-ACL=#ACSACL#-IP-x-1; "
        "cisco-av-pair=cts:security-group-tag=0008-00; MS-MPPE-Send-Key=****; LicenseTypes=1; }"
    )
    assert compact_reply(raw) == "ACS:CiscoSecure-Defined-ACL=#ACSACL#-IP-x-1; cts:security-group-tag=0008-00"
    assert compact_reply("{Class=x; }") is None
    assert compact_reply(None) is None


def test_compact_reply_keeps_semicolons_in_values() -> None:
    from ise_mcp.tools.sessions import compact_reply

    raw = "{Reply-Message=Access denied; call helpdesk; Class=CACS:1; State=abc; x; Filter-Id=f1; }"
    assert compact_reply(raw) == "Reply-Message=Access denied; call helpdesk; Filter-Id=f1"


async def test_get_nad_fuzzy_and_candidates(mock: respx.MockRouter) -> None:
    from fastmcp.exceptions import ToolError

    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.radius"}).respond(json=ers_page([]))
    mock.get("/ers/config/networkdevice", params={"filter": "name.CONTAINS.radius"}).respond(
        json=ers_page([{"id": NAD_ID, "name": "mcp-test-radius-client"}])
    )
    mock.get(f"/ers/config/networkdevice/{NAD_ID}").respond(json=fixture_json("ers_networkdevice.json"))
    out = text_of(await call_tool(make_server(), "ise_get_nad", {"device": "radius"}))
    assert "using 'mcp-test-radius-client'" in out["resolved_from"]
    # two candidates: not guessed, both named in the error
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.sw"}).respond(json=ers_page([]))
    mock.get("/ers/config/networkdevice", params={"filter": "name.CONTAINS.sw"}).respond(
        json=ers_page([{"id": "a", "name": "sw1"}, {"id": "b", "name": "sw2"}])
    )
    try:
        await call_tool(make_server(), "ise_get_nad", {"device": "sw"})
        raise AssertionError("expected an error")
    except ToolError as e:
        assert "'sw1', 'sw2'" in str(e)


# --- an empty window: abandoned EAP, a live session, nothing at all (#59) ------------------------
# Recorded live on 2026-10-21 (lab mcp-cml-ise, catc Wave 6 part D, D45 case 2). The EAP-TLS client
# 52:54:00:62:C6:B2 passed through NAD mcp-test-sw1 at 10:13:34Z; its supplicant was then switched to
# PEAP with a bad identity and it abandoned the conversation (ISE answered with challenges). MnT kept
# no record: ise_why_auth_failed(minutes=10) said 'the RADIUS request never reached ISE'.

EAPTLS_MAC = "52:54:00:62:C6:B2"
SW1_NAD = {
    "NetworkDevice": {
        "id": "8e5c6540-c9cb-11f1-b4ef-aecc499b6f77",
        "name": "mcp-test-sw1",
        "NetworkDeviceIPList": [{"ipaddress": "198.18.128.154", "mask": 32}],
        "NetworkDeviceGroupList": ["Location#All Locations#mcp-test-lab"],
        "authenticationSettings": {"radiusSharedSecret": "secret-sw1-long-xx"},
    }
}
EMPTY_WINDOW = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><authStatusOutputList>'
    f'<authStatusList key="{EAPTLS_MAC}"/></authStatusOutputList>'
)


def mock_eaptls(mock: respx.MockRouter, *, minutes: int, session: str | None) -> None:
    base = f"/admin/API/mnt/AuthStatus/MACAddress/{EAPTLS_MAC}"
    mock.get(f"{base}/{minutes * 60}/50/All").respond(text=EMPTY_WINDOW)
    mock.get(f"{base}/604800/5/All").respond(text=fixture_text("mnt_authstatus_eaptls_7d.xml"))
    if session is None:
        mock.get(f"/admin/API/mnt/Session/MACAddress/{EAPTLS_MAC}").respond(500, text=MISSING_SESSION)
    else:
        mock.get(f"/admin/API/mnt/Session/MACAddress/{EAPTLS_MAC}").respond(text=session)
    mock.get(f"/api/v1/endpoint/{EAPTLS_MAC}").respond(json={"mac": EAPTLS_MAC, "id": "ep-1"})
    nid = SW1_NAD["NetworkDevice"]["id"]
    mock.get("/ers/config/networkdevice", params={"filter": "ipaddress.EQ.198.18.128.154"}).respond(
        json=ers_page([{"id": nid, "name": "mcp-test-sw1"}])
    )
    mock.get(f"/ers/config/networkdevice/{nid}").respond(json=SW1_NAD)


def ended_session() -> str:
    """The 10:13:34Z session after the switch tore it down (accounting Stop at the failed reauth)."""
    s = fixture_text("mnt_session_eaptls_live.xml")
    s = s.replace("2026-10-21T10:52:20.238Z", "2026-10-21T10:13:34.659Z")
    s = s.replace("2026-10-21T11:40:30.870Z", "2026-10-21T10:30:21.000Z")
    return s.replace("<acct_status_type>Accounting-On<", "<acct_status_type>Stop<")


@pytest.mark.parametrize("ended", [False, True], ids=["no-session", "ended-session"])
async def test_why_auth_failed_abandoned_eap_is_not_never_reached(
    mock: respx.MockRouter, ended: bool
) -> None:
    # MnT has no session for the MAC, or only the ended one.
    mock_eaptls(mock, minutes=10, session=ended_session() if ended else None)
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": EAPTLS_MAC.lower(), "minutes": 10})
    assert "never reached ISE" not in out["verdict"]
    assert "No record is not proof that RADIUS never arrived" in out["verdict"]
    assert "last passed at 2026-10-21T10:13:34.659Z through mcp-test-sw1 (dot1x EAP-TLS)" in out["verdict"]
    assert out["likely_causes"][0].startswith("the client started EAP and abandoned it mid-way")
    assert out["likely_causes"][2].startswith("less likely after that pass")
    assert out["last_record"]["nad"] == "mcp-test-sw1" and out["nad_now"] == "mcp-test-sw1"
    assert out["endpoint_known_to_ise"] is True
    steps = " ".join(out["next_steps"])
    assert "show aaa servers" in steps and "show dot1x interface" in steps and "cml_capture" in steps
    assert "ise_get_nad" not in steps  # the NAD is known to cover the switch
    assert "secret-sw1" not in json.dumps(out)


async def test_why_auth_failed_live_session_recent_login(mock: respx.MockRouter) -> None:
    """MnT's history left out the client's later logins (the newest record stayed 10:13:34Z while the
    session shows an authentication at 10:52:20Z): a live session inside the window is a pass."""
    from datetime import UTC, datetime, timedelta

    recent = (datetime.now(UTC) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    session = fixture_text("mnt_session_eaptls_live.xml").replace("2026-10-21T10:52:20.238Z", recent)
    mock_eaptls(mock, minutes=60, session=session)
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": EAPTLS_MAC, "minutes": 60})
    assert "But MnT has a live session for it, authenticated at" in out["verdict"]
    assert "198.18.128.154 GigabitEthernet1/0/3" in out["verdict"] and "Nothing failed" in out["verdict"]
    assert out["session"]["active"] is True and "likely_causes" not in out


async def test_why_auth_failed_still_on_an_older_session(mock: respx.MockRouter) -> None:
    mock_eaptls(mock, minutes=60, session=fixture_text("mnt_session_eaptls_live.xml"))
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": EAPTLS_MAC, "minutes": 60})
    assert (
        "still on its session authenticated at 2026-10-21T10:52:20.238Z through mcp-test-sw1"
        in out["verdict"]
    )
    assert out["likely_causes"][0].endswith("it is still connected on that session")


# --- the history leaves out repeated successful logins; the session doesn't ----------------------
# Same recording: 4 h of history held 2 records and the newest is 10:13:34Z, while the live session
# shows an authentication at 10:52:20Z. The newest login comes from the session.

WEEK = 10080
LIVE_AUTH = "2026-10-21T10:52:20.238Z"
NEWEST_RECORD = "2026-10-21T10:13:34.659Z"
LIVE_WHERE = "its live session through 198.18.128.154 GigabitEthernet1/0/3"


def mock_week(mock: respx.MockRouter, *, history: str, session: str | None) -> None:
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{EAPTLS_MAC}/{WEEK * 60}/50/All").respond(text=history)
    if session is None:
        mock.get(f"/admin/API/mnt/Session/MACAddress/{EAPTLS_MAC}").respond(500, text=MISSING_SESSION)
    else:
        mock.get(f"/admin/API/mnt/Session/MACAddress/{EAPTLS_MAC}").respond(text=session)
    mock.get("/admin/API/mnt/FailureReasons").respond(text=FAILURE_REASONS_XML)
    mock.get("/api/v1/policy/network-access/policy-set").respond(json={"response": []})
    nid = SW1_NAD["NetworkDevice"]["id"]
    mock.get("/ers/config/networkdevice", params={"filter": "ipaddress.EQ.198.18.128.154"}).respond(
        json=ers_page([{"id": nid, "name": "mcp-test-sw1"}])
    )
    mock.get(f"/ers/config/networkdevice/{nid}").respond(json=SW1_NAD)


def history_with_failure(at: str) -> str:
    """The recorded history plus a failed EAP-TLS attempt at `at`."""
    text = fixture_text("mnt_authstatus_eaptls_7d.xml")
    start = text.index("<authStatusElements>")
    end = text.index("</authStatusElements>") + len("</authStatusElements>")
    failed = (
        text[start:end]
        .replace(">true</passed>", ">false</passed>")
        .replace(">false</failed>", ">true</failed>")
        .replace(
            "<failure_reason></failure_reason>",
            "<failure_reason>12520 EAP-TLS failed SSL/TLS handshake because the client rejected the ISE "
            "local-certificate</failure_reason>",
        )
        .replace(NEWEST_RECORD, at)
    )
    return text[:start] + failed + text[start:]


async def test_why_auth_failed_newest_pass_comes_from_the_session(mock: respx.MockRouter) -> None:
    mock_week(
        mock,
        history=fixture_text("mnt_authstatus_eaptls_7d.xml"),
        session=fixture_text("mnt_session_eaptls_live.xml"),
    )
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": EAPTLS_MAC, "minutes": WEEK})
    verdict = out["verdict"]
    assert verdict.startswith(f"No login failures: the newest login PASSED at {LIVE_AUTH} ({LIVE_WHERE})")
    assert f"The history's latest record is older ({NEWEST_RECORD}" in verdict
    assert "MnT's history leaves out repeated successful logins" in verdict
    assert out["newest_login"] == {
        "time": LIVE_AUTH,
        "user": "mcp-eaptls-client",
        "nas_ip": "198.18.128.154",
        "nas_port": "GigabitEthernet1/0/3",
        "active": True,
    }
    assert out["latest_attempt"]["time"] == NEWEST_RECORD
    assert "session" not in out  # it is live


async def test_why_auth_failed_session_no_newer_than_the_history(mock: respx.MockRouter) -> None:
    # The session of the newest record itself, since ended: nothing was left out.
    mock_week(mock, history=fixture_text("mnt_authstatus_eaptls_7d.xml"), session=ended_session())
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": EAPTLS_MAC, "minutes": WEEK})
    assert out["verdict"] == (
        f"No login failures: the latest login PASSED at {NEWEST_RECORD} "
        "(authorization profile mcp-test-permit)."
    )
    assert "newest_login" not in out
    assert out["session"].startswith("no active session now")


@pytest.mark.parametrize(
    ("failed_at", "start", "newer"),
    [
        # failed after the newest record, passed later (only the session shows it)
        (
            "2026-10-21T10:30:00.000Z",
            "The latest recorded login FAILED at 2026-10-21T10:30:00.000Z: 12520",
            True,
        ),
        # failed after the session's authentication: still the latest
        ("2026-10-21T11:00:00.000Z", "The latest login FAILED at 2026-10-21T11:00:00.000Z: 12520", False),
        # failed before the newest record, which passed, and the session is newer still
        ("2026-10-21T10:00:00.000Z", f"The latest login PASSED at {LIVE_AUTH} ({LIVE_WHERE}; MnT's", True),
    ],
    ids=["passed-since", "failure-is-latest", "older-failure"],
)
async def test_why_auth_failed_failure_against_the_session(
    mock: respx.MockRouter, failed_at: str, start: str, newer: bool
) -> None:
    mock_week(
        mock, history=history_with_failure(failed_at), session=fixture_text("mnt_session_eaptls_live.xml")
    )
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": EAPTLS_MAC, "minutes": WEEK})
    assert out["verdict"].startswith(start), out["verdict"]
    assert out["failure"]["code"] == "12520"
    assert ("newest_login" in out) is newer
    if failed_at == "2026-10-21T10:30:00.000Z":
        assert (
            f"The endpoint has passed since: {LIVE_WHERE} shows a successful authentication at {LIVE_AUTH}"
            in out["verdict"]
        )
    if newer:
        assert "leaves out repeated successful logins" in out["verdict"]
        assert out["newest_login"]["time"] == LIVE_AUTH


async def test_why_auth_failed_only_coa_then_a_pass_the_history_left_out(mock: respx.MockRouter) -> None:
    coa = COA_NAK.replace(MAC_OK, EAPTLS_MAC).replace("2026-10-14T13:00:00.000Z", "2026-10-21T10:40:00.000Z")
    history = xml(
        f'<authStatusOutputList><authStatusList key="{EAPTLS_MAC}">{coa}</authStatusList>'
        "</authStatusOutputList>"
    )
    mock_week(mock, history=history, session=fixture_text("mnt_session_eaptls_live.xml"))
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": EAPTLS_MAC, "minutes": WEEK})
    verdict = out["verdict"]
    assert verdict.startswith(f"No login record for {EAPTLS_MAC} in the last {WEEK} minutes, only 1 CoA")
    assert f"but {LIVE_WHERE} shows a successful authentication at {LIVE_AUTH}, after them" in verdict
    assert "has not authenticated since" not in verdict
    assert out["coa_failures"]["count"] == 1


def mock_360(mock: respx.MockRouter, *, history: str, session: str) -> None:
    mock.get(f"/admin/API/mnt/AuthStatus/MACAddress/{EAPTLS_MAC}/86400/5/All").respond(text=history)
    mock.get(f"/admin/API/mnt/Session/MACAddress/{EAPTLS_MAC}").respond(text=session)
    mock.get(f"/api/v1/endpoint/{EAPTLS_MAC}").respond(json={"mac": EAPTLS_MAC, "id": "ep-1"})
    mock.get("/ers/config/endpointgroup").respond(json=ers_page([]))
    mock.get("/ers/config/ancendpoint").respond(json=ers_page([]))
    mock.get("/api/v1/endpoint/getRejected").respond(json={"response": []})


@pytest.mark.parametrize("session_newer", [True, False], ids=["session-newer", "session-not-newer"])
async def test_endpoint_360_newest_login_from_the_session(
    mock: respx.MockRouter, session_newer: bool
) -> None:
    from ise_mcp.tools.sessions import HISTORY_GAP_NOTE

    session = fixture_text("mnt_session_eaptls_live.xml") if session_newer else ended_session()
    mock_360(mock, history=fixture_text("mnt_authstatus_eaptls_7d.xml"), session=session)
    out = await call_tool(make_server(), "ise_endpoint_360", {"mac": EAPTLS_MAC})
    assert out["recent_auths"][0]["time"] == NEWEST_RECORD
    if session_newer:
        assert out["newest_login"] == {
            "time": LIVE_AUTH,
            "user": "mcp-eaptls-client",
            "nas_ip": "198.18.128.154",
            "nas_port": "GigabitEthernet1/0/3",
            "active": True,
        }
        assert out["history_note"] == HISTORY_GAP_NOTE
    else:
        assert "newest_login" not in out and "history_note" not in out


@pytest.mark.parametrize(("minutes_ago", "noted"), [(5, True), (2 * 1440, False)], ids=["in-window", "older"])
async def test_endpoint_360_empty_history_and_a_session(
    mock: respx.MockRouter, minutes_ago: int, noted: bool
) -> None:
    """No record in 24 h: only a session authentication inside the window is a login the history left out."""
    from datetime import UTC, datetime, timedelta

    auth_at = (datetime.now(UTC) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    session = fixture_text("mnt_session_eaptls_live.xml").replace(LIVE_AUTH, auth_at)
    mock_360(mock, history=EMPTY_WINDOW, session=session)
    out = await call_tool(make_server(), "ise_endpoint_360", {"mac": EAPTLS_MAC})
    assert out["recent_auths"] == "none in the last 24 hours"
    assert ("newest_login" in out) is noted and ("history_note" in out) is noted
    if noted:
        assert out["newest_login"]["time"] == auth_at

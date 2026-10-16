from __future__ import annotations

import json

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
    mock.get(f"/api/v1/endpoint/{mac}").respond(404, json={"message": "not found"})
    out = await call_tool(make_server(), "ise_why_auth_failed", {"mac": mac})
    assert "no authentication record" in out["verdict"]
    assert out["endpoint_known_to_ise"] is False


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

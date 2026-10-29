"""I31: guest types, sponsor groups, portals, and the guest-account lifecycle run as a sponsor."""

from __future__ import annotations

import base64
import copy
import json
from typing import Any

import pytest
import respx
from fastmcp import Client
from pydantic import ValidationError

from ise_mcp._core.preflight import run_preflight
from ise_mcp._core.testing import call_tool
from ise_mcp.preflight import preflight
from ise_mcp.tools.guest import match_names, new_password, valid_days
from tests.unit.conftest import BASE, ers_page, fixture_json, make_server, make_settings
from tests.unit.test_writes import two_step

SPONSOR = {"sponsor_username": "sponsor1", "sponsor_password": "sponsor-secret"}
FIX = fixture_json("ers_guest.json")
GUEST = FIX["guestuser"]
GID = GUEST["GuestUser"]["id"]
DAILY = FIX["guesttype_daily"]
DAILY_ID = DAILY["GuestType"]["id"]
SG = FIX["sponsorgroup"]
SG_ID = SG["SponsorGroup"]["id"]
PORTAL = FIX["sponsorportal"]
PORTAL_ID = PORTAL["SponsorPortal"]["id"]
SPONSOR_AUTH = "Basic " + base64.b64encode(b"sponsor1:sponsor-secret").decode()


def guest(**changes: Any) -> dict[str, Any]:
    g: dict[str, Any] = copy.deepcopy(GUEST)
    g["GuestUser"].update(changes)
    return g


def mock_config(mock: respx.MockRouter) -> None:
    """Admin-side lookups the guest tools make: guest type, locations, the sponsor portal."""
    mock.get("/ers/config/guesttype", params={"filter": "name.EQ.Daily (default)"}).respond(
        json=ers_page([{"id": DAILY_ID, "name": "Daily (default)"}])
    )
    mock.get(f"/ers/config/guesttype/{DAILY_ID}").respond(json=DAILY)
    mock.get("/ers/config/guestlocation").respond(json=ers_page([{"id": "l1", "name": "San Jose"}]))
    mock.get("/ers/config/sponsorportal").respond(
        json=ers_page([{"id": PORTAL_ID, "name": "Sponsor Portal (default)"}])
    )


def mock_guest(mock: respx.MockRouter, body: dict[str, Any] | None = None) -> None:
    body = body or GUEST
    mock.get("/ers/config/guestuser/name/mcp-guest-alice").respond(json=body)
    mock.get(f"/ers/config/guestuser/{GID}").respond(json=body)


# --- settings, status, check -------------------------------------------------------------------


def test_sponsor_password_is_secret_and_zone_checked() -> None:
    s = make_settings(**SPONSOR, guest_timezone="Europe/London")
    assert "sponsor-secret" not in repr(s)
    assert s.sponsor_password is not None and s.sponsor_password.get_secret_value() == "sponsor-secret"
    with pytest.raises(ValidationError, match="IANA"):
        make_settings(guest_timezone="Mars/Olympus")


async def test_status_without_sponsor(mock: respx.MockRouter) -> None:
    out = await call_tool(make_server(), "ise_status", {})
    assert out["ise"]["guest_sponsor"]["configured"] is False
    assert "ISE_SPONSOR_USERNAME" in out["ise"]["guest_sponsor"]["detail"]


async def test_status_with_sponsor_masks_password(mock: respx.MockRouter) -> None:
    route = mock.get("/ers/config/guestuser").respond(json=ers_page([]))
    out = await call_tool(make_server(**SPONSOR), "ise_status", {})
    sponsor = out["ise"]["guest_sponsor"]
    assert sponsor == {
        **sponsor,
        "configured": True,
        "username": "sponsor1",
        "password_set": True,
        "ok": True,
    }
    assert "sponsor-secret" not in json.dumps(out)
    assert route.calls.last.request.headers["authorization"] == SPONSOR_AUTH


async def test_status_sponsor_refused(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/guestuser").respond(401)
    out = await call_tool(make_server(**SPONSOR), "ise_status", {})
    assert out["ise"]["guest_sponsor"]["ok"] is False
    assert "programmatic interface" in out["ise"]["guest_sponsor"]["hint"]


@pytest.mark.parametrize(
    ("sponsor", "status", "outcome"),
    [(False, 200, "skip"), (True, 200, "ok"), (True, 401, "fail"), (True, 500, "warn")],
)
async def test_check_sponsor_row(sponsor: bool, status: int, outcome: str) -> None:
    with respx.mock(base_url=BASE, assert_all_called=False) as r:
        r.get("/api/v1/deployment/node").respond(json={"response": [{"hostname": "ise"}]})
        r.get("/ers/config/op/systemconfig/iseversion").respond(
            json={"OperationResult": {"resultValue": [{"name": "version", "value": "3.5.0.527"}]}}
        )
        r.get("/admin/API/mnt/Version").respond(text="<product><version>3.5.0.527</version></product>")
        r.get("/ers/config/adminuser").respond(403)
        r.get("/ers/config/guestuser").respond(status, json=ers_page([]))
        settings = make_settings(**(SPONSOR if sponsor else {}))
        report = await run_preflight(settings, preflight, server="s", product="ISE", env_prefix="ISE_")
    (row,) = [c for c in report["instances"][0]["checks"] if c["check"] == "sponsor"]
    assert row["outcome"] == outcome
    assert "sponsor-secret" not in json.dumps(report)
    if outcome == "fail":
        assert "programmatic interface" in row["hint"]


# --- reads ---------------------------------------------------------------------------------------


async def test_guest_tools_need_sponsor(mock: respx.MockRouter) -> None:
    server = make_server()
    async with Client(server) as c:
        r = await c.call_tool("ise_list_guest_users", {}, raise_on_error=False)
    assert r.is_error and "ISE_SPONSOR_USERNAME" in r.content[0].text


async def test_list_guest_users_as_sponsor_without_passwords(mock: respx.MockRouter) -> None:
    listing = mock.get("/ers/config/guestuser").respond(
        json=ers_page([{"id": GID, "name": "mcp-guest-alice"}])
    )
    mock_guest(mock)
    out = await call_tool(
        make_server(**SPONSOR), "ise_list_guest_users", {"name": "alice", "response_format": "json"}
    )
    (row,) = out["results"]
    assert row["username"] == "mcp-guest-alice" and row["sponsor"] == "mcp-guest-sponsor"
    assert row["valid_to"] == "10/18/2026 06:12" and row["status_meaning"].startswith("Created")
    assert "should-never-leak" not in json.dumps(out)
    req = listing.calls.last.request
    assert req.headers["authorization"] == SPONSOR_AUTH
    assert "name.CONTAINS.alice" in str(req.url)


async def test_get_guest_user_not_found_explains_scope(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/guestuser/name/nobody").respond(404)
    async with Client(make_server(**SPONSOR)) as c:
        r = await c.call_tool("ise_get_guest_user", {"user": "nobody"}, raise_on_error=False)
    assert r.is_error and "manage permission" in r.content[0].text


async def test_list_config_reads(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/guesttype").respond(json=ers_page([{"id": DAILY_ID, "name": "Daily (default)"}]))
    mock.get(f"/ers/config/guesttype/{DAILY_ID}").respond(json=DAILY)
    mock.get("/ers/config/identitygroup").respond(
        json=ers_page([{"id": "aa178bd0-8bff-11e6-996c-525400b48521", "name": "GuestType_Daily (default)"}])
    )
    mock.get("/ers/config/sponsorgroup").respond(json=ers_page([{"id": SG_ID, "name": "mcp-guest-sponsors"}]))
    mock.get(f"/ers/config/sponsorgroup/{SG_ID}").respond(json=SG)
    mock.get("/ers/config/idstoresequence").respond(
        json=ers_page([{"id": "92faba60-8c01-11e6-996c-525400b48521", "name": "Sponsor_Portal_Sequence"}])
    )
    mock.get("/ers/config/sponsorportal").respond(
        json=ers_page([{"id": PORTAL_ID, "name": "Sponsor Portal (default)"}])
    )
    mock.get(f"/ers/config/sponsorportal/{PORTAL_ID}").respond(json=PORTAL)
    mock.get("/ers/config/guestlocation").respond(json=ers_page([{"id": "l1", "name": "San Jose"}]))
    mock.get("/ers/config/guestssid").respond(json=ers_page([]))
    server = make_server()
    types = await call_tool(server, "ise_list_guest_types", {"response_format": "json"})
    assert types["results"][0]["identity_group"] == "GuestType_Daily (default)"
    assert types["results"][0]["max_duration"] == "5 days"
    groups = await call_tool(server, "ise_list_sponsor_groups", {"response_format": "json"})
    g = groups["results"][0]
    assert g["manage"] == "own" and g["rest_access"] is True and g["ad_members"]
    # I44: markdown keeps id and description (the rows have more than 10 keys)
    md_types = str(await call_tool(server, "ise_list_guest_types", {}))
    assert DAILY_ID in md_types and "just 1-5 days" in md_types
    md_groups = str(await call_tool(server, "ise_list_sponsor_groups", {}))
    assert SG_ID in md_groups and "test sponsors" in md_groups
    portals = await call_tool(
        server, "ise_list_guest_portals", {"kind": "sponsor", "response_format": "json"}
    )
    assert portals["results"][0]["auth_source"] == "Sponsor_Portal_Sequence"
    locs = await call_tool(server, "ise_get_guest_locations", {})
    assert locs["locations"] == ["San Jose"] and "ISE_GUEST_TIMEZONE" in locs["guest_timezone"]


# --- guest lifecycle -----------------------------------------------------------------------------


async def test_create_guest_returns_password_once(mock: respx.MockRouter) -> None:
    mock_config(mock)
    mock.get("/ers/config/guestuser/name/mcp-guest-bob").respond(404)
    post = mock.post("/ers/config/guestuser").respond(
        201, headers={"Location": f"{BASE}/ers/config/guestuser/new-guest-id"}
    )
    args = {
        "username": "mcp-guest-bob",
        "guest_type": "Daily (default)",
        "first_name": "Bob",
        "start": "2026-10-17 09:00",
        "end": "2026-10-19 09:00",
    }
    preview, done = await two_step("ise_create_guest_user", args, **SPONSOR)
    p = preview["preview"]
    assert p["valid_from"] == "10/17/2026 09:00" and p["valid_to"] == "10/19/2026 09:00"
    assert p["duration"] == "2 day(s)" and "returned once" in p["password"]
    assert not post.called or len(post.calls) == 1
    result = done["result"]
    assert result["id"] == "new-guest-id" and len(result["password"]) == 10
    sent = json.loads(post.calls.last.request.content)["GuestUser"]
    assert sent["portalId"] == PORTAL_ID
    assert sent["guestAccessInfo"] == {
        "validDays": 2,
        "fromDate": "10/17/2026 09:00",
        "toDate": "10/19/2026 09:00",
        "location": "San Jose",
    }
    assert sent["guestInfo"]["password"] == result["password"]
    assert post.calls.last.request.headers["authorization"] == SPONSOR_AUTH
    assert result["password"] not in json.dumps(preview)


async def test_create_guest_default_window_and_blockers(mock: respx.MockRouter) -> None:
    mock_config(mock)
    mock_guest(mock)
    preview, _ = await two_step(
        "ise_create_guest_user",
        {
            "username": "mcp-guest-alice",
            "guest_type": "Daily (default)",
            "start": "2026-10-17",
            "end": "2026-10-30",
        },
        **SPONSOR,
    )
    assert preview["status"] == "blocked"
    text = json.dumps(preview["blockers"])
    assert "already exists" in text and "maximum of 5 day(s)" in text
    mock.get("/ers/config/guestuser/name/mcp-guest-carol").respond(404)
    preview = await call_tool(
        make_server(mcp_enable_writes=True, **SPONSOR, guest_timezone="America/Los_Angeles"),
        "ise_create_guest_user",
        {"username": "mcp-guest-carol", "guest_type": "Daily (default)"},
    )
    assert preview["preview"]["duration"] == "1 day(s)"
    assert preview["preview"]["time_basis"] == "America/Los_Angeles"


async def test_extend_guest(mock: respx.MockRouter) -> None:
    mock_config(mock)
    mock_guest(mock)
    put = mock.put(f"/ers/config/guestuser/{GID}").respond(json={"UpdatedFieldsList": {}})
    preview, done = await two_step("ise_extend_guest_user", {"user": "mcp-guest-alice", "days": 2}, **SPONSOR)
    assert preview["preview"]["valid_to"] == {"from": "10/18/2026 06:12", "to": "10/20/2026 06:12"}
    assert done["status"] == "applied"
    sent = json.loads(put.calls.last.request.content)["GuestUser"]
    assert (
        sent["guestAccessInfo"]["toDate"] == "10/20/2026 06:12" and sent["guestAccessInfo"]["validDays"] == 3
    )
    assert sent["portalId"] == PORTAL_ID
    for gone in ("status", "sponsorUserName", "sponsorUserId", "link"):
        assert gone not in sent
    assert "password" not in sent["guestInfo"] and "creationTime" not in sent["guestInfo"]
    over, _ = await two_step("ise_extend_guest_user", {"user": "mcp-guest-alice", "days": 10}, **SPONSOR)
    assert over["status"] == "blocked" and "maximum" in json.dumps(over["blockers"])


async def test_suspend_and_reinstate(mock: respx.MockRouter) -> None:
    mock_guest(mock)
    suspend = mock.put(f"/ers/config/guestuser/suspend/{GID}").respond(204)
    _, done = await two_step(
        "ise_suspend_guest_user", {"user": "mcp-guest-alice", "reason": "left early"}, **SPONSOR
    )
    assert done["status"] == "applied"
    body = json.loads(suspend.calls.last.request.content)
    assert body["OperationAdditionalData"]["additionalData"] == [{"name": "reason", "value": "left early"}]
    blocked, _ = await two_step("ise_reinstate_guest_user", {"user": "mcp-guest-alice"}, **SPONSOR)
    assert blocked["status"] == "blocked"


async def test_reinstate_suspended_and_block_double_suspend(mock: respx.MockRouter) -> None:
    mock_guest(mock, guest(status="SUSPENDED", statusReason="x"))
    reinstate = mock.put(f"/ers/config/guestuser/reinstate/{GID}").respond(204)
    _, done = await two_step("ise_reinstate_guest_user", {"user": "mcp-guest-alice"}, **SPONSOR)
    assert done["status"] == "applied" and reinstate.called
    again, _ = await two_step("ise_suspend_guest_user", {"user": "mcp-guest-alice"}, **SPONSOR)
    assert again["status"] == "blocked"


async def test_update_and_delete_guest(mock: respx.MockRouter) -> None:
    mock_config(mock)
    mock_guest(mock)
    put = mock.put(f"/ers/config/guestuser/{GID}").respond(json={})
    preview, _ = await two_step(
        "ise_update_guest_user", {"user": "mcp-guest-alice", "company": "New Co"}, **SPONSOR
    )
    assert preview["preview"]["changes"]["guestInfo.company"]["to"] == "New Co"
    assert json.loads(put.calls.last.request.content)["GuestUser"]["guestInfo"]["company"] == "New Co"
    delete = mock.delete(f"/ers/config/guestuser/{GID}").respond(204)
    preview, done = await two_step("ise_delete_guest_user", {"user": "mcp-guest-alice"}, **SPONSOR)
    assert "should-never-leak" not in json.dumps(preview)
    assert done["status"] == "applied" and delete.called


# --- sponsor groups and guest types --------------------------------------------------------------


def mock_choices(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/sponsorgroupmember").respond(
        json=ers_page(
            [
                {"id": "m1", "name": "ALL_ACCOUNTS (default)"},
                {"id": "m2", "name": "CORP:corp.example.com/MCP-Lab/mcp-guest-sponsors"},
                {"id": "m3", "name": "mcp-guest-sponsors-int"},
            ]
        )
    )
    mock.get("/ers/config/guesttype").respond(json=ers_page([{"id": DAILY_ID, "name": "Daily (default)"}]))
    mock.get("/ers/config/guestlocation").respond(json=ers_page([{"id": "l1", "name": "San Jose"}]))


async def test_create_sponsor_group_maps_ad_group(mock: respx.MockRouter) -> None:
    mock_choices(mock)
    mock.get("/ers/config/sponsorgroup", params={"filter": "name.EQ.mcp-guest-new"}).respond(
        json=ers_page([])
    )
    post = mock.post("/ers/config/sponsorgroup").respond(
        201, headers={"Location": f"{BASE}/ers/config/sponsorgroup/sg-new"}
    )
    args = {
        "name": "mcp-guest-new",
        "member_groups": ["mcp-guest-sponsors"],
        "guest_types": ["daily (default)"],
        "locations": ["San Jose"],
        "rest_access": True,
    }
    preview, done = await two_step("ise_set_sponsor_group", args)
    assert preview["preview"]["members"] == ["CORP:corp.example.com/MCP-Lab/mcp-guest-sponsors"]
    assert done["status"] == "applied"
    sent = json.loads(post.calls.last.request.content)["SponsorGroup"]
    assert sent["otherPermissions"]["canAccessViaRest"] is True and sent["managePermission"] == "OWNACCOUNTS"
    assert sent["guestTypes"] == ["Daily (default)"]


async def test_sponsor_group_blockers_and_update(mock: respx.MockRouter) -> None:
    mock_choices(mock)
    mock.get("/ers/config/sponsorgroup", params={"filter": "name.EQ.mcp-guest-sponsors"}).respond(
        json=ers_page([{"id": SG_ID, "name": "mcp-guest-sponsors"}])
    )
    mock.get(f"/ers/config/sponsorgroup/{SG_ID}").respond(json=SG)
    blocked, _ = await two_step(
        "ise_set_sponsor_group", {"name": "mcp-guest-sponsors", "member_groups": ["nope"]}
    )
    assert blocked["status"] == "blocked" and "ise_add_ad_groups" in json.dumps(blocked["blockers"])
    put = mock.put(f"/ers/config/sponsorgroup/{SG_ID}").respond(json={})
    preview, _ = await two_step("ise_set_sponsor_group", {"name": "mcp-guest-sponsors", "manage": "all"})
    assert preview["preview"]["changes"]["managePermission"]["to"] == "ALLACCOUNTS"
    sent = json.loads(put.calls.last.request.content)["SponsorGroup"]
    assert sent["memberGroups"] == SG["SponsorGroup"]["memberGroups"]  # untouched fields kept


async def test_create_guest_type_copies_daily_identity_group(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/guesttype", params={"filter": "name.EQ.mcp-guest-type"}).respond(json=ers_page([]))
    mock.get("/ers/config/guesttype", params={"filter": "name.EQ.Daily (default)"}).respond(
        json=ers_page([{"id": DAILY_ID, "name": "Daily (default)"}])
    )
    mock.get(f"/ers/config/guesttype/{DAILY_ID}").respond(json=DAILY)
    mock.get("/ers/config/identitygroup").respond(json=ers_page([]))
    mock.get("/ers/config/sponsorgroup").respond(json=ers_page([{"id": SG_ID, "name": "mcp-guest-sponsors"}]))
    post = mock.post("/ers/config/guesttype").respond(
        201, headers={"Location": f"{BASE}/ers/config/guesttype/t1"}
    )
    args = {
        "name": "mcp-guest-type",
        "default_duration": 4,
        "max_duration": 8,
        "duration_unit": "hours",
        "sponsor_groups": ["mcp-guest-sponsors"],
    }
    _, done = await two_step("ise_set_guest_type", args)
    assert done["status"] == "applied"
    sent = json.loads(post.calls.last.request.content)["GuestType"]
    assert sent["accessTime"]["durationTimeUnit"] == "HOURS" and sent["accessTime"]["maxAccountDuration"] == 8
    assert sent["loginOptions"]["identityGroupId"] == "aa178bd0-8bff-11e6-996c-525400b48521"
    assert sent["sponsorGroups"] == ["mcp-guest-sponsors"]
    bad, _ = await two_step("ise_set_guest_type", {**args, "default_duration": 9})
    assert bad["status"] == "blocked"


async def test_delete_default_sponsor_group_blocked(mock: respx.MockRouter) -> None:
    default = copy.deepcopy(SG)
    default["SponsorGroup"].update(isDefaultGroup=True, name="ALL_ACCOUNTS (default)")
    mock.get("/ers/config/sponsorgroup", params={"filter": "name.EQ.ALL_ACCOUNTS (default)"}).respond(
        json=ers_page([{"id": SG_ID, "name": "ALL_ACCOUNTS (default)"}])
    )
    mock.get(f"/ers/config/sponsorgroup/{SG_ID}").respond(json=default)
    preview, _ = await two_step(
        "ise_delete_object", {"kind": "sponsor_group", "target": "ALL_ACCOUNTS (default)"}
    )
    assert preview["status"] == "blocked" and "default" in json.dumps(preview["blockers"])


# --- helpers -------------------------------------------------------------------------------------


def test_helpers() -> None:
    from datetime import datetime

    for _ in range(50):
        pw = new_password()
        assert len(pw) == 10 and not set(pw) & set("lIO01") and sum(c.isdigit() for c in pw) >= 4
        assert any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)

    assert valid_days(datetime(2026, 10, 16, 23, 0), datetime(2026, 10, 17, 1, 0)) == 1
    names, problems = match_names(["MCP-GUEST-SPONSORS"], ["CORP:c.com/OU/mcp-guest-sponsors", "x"], "g")
    assert names == ["CORP:c.com/OU/mcp-guest-sponsors"] and not problems
    _, problems = match_names(["dup"], ["A:x/dup", "B:y/dup"], "g")
    assert "several" in problems[0]


async def test_sponsor_401_names_the_sponsor_not_the_admin(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/guestuser").respond(401)
    async with Client(make_server(**SPONSOR)) as c:
        r = await c.call_tool("ise_list_guest_users", {}, raise_on_error=False)
    text = r.content[0].text
    assert r.is_error and "sponsor1" in text and "programmatic interface" in text
    assert "sponsor-secret" not in text


# --- service desk (I72) --------------------------------------------------------------------------

# Synthetic resetpassword answer, shaped like the ERS SDK's OperationResult for PUT resetpassword/{id}.
RESET = {"OperationResult": {"resultValue": [{"name": "password", "value": "Kx48273fRq"}]}}


async def test_reset_guest_password_returns_it_once(
    mock: respx.MockRouter, caplog: pytest.LogCaptureFixture
) -> None:
    mock_guest(mock)
    put = mock.put(f"/ers/config/guestuser/resetpassword/{GID}").respond(json=RESET)
    with caplog.at_level("INFO", logger="stutters_mcp_core.audit"):
        preview, done = await two_step("ise_reset_guest_password", {"user": "mcp-guest-alice"}, **SPONSOR)
    assert preview["status"] == "preview" and "returned once" in preview["preview"]["password"]
    assert not json.dumps(preview).count("Kx48273fRq") and "should-never-leak" not in json.dumps(preview)
    assert done["result"]["password"] == "Kx48273fRq" and done["result"]["username"] == "mcp-guest-alice"
    assert put.calls.last.request.headers["authorization"] == SPONSOR_AUTH
    assert "applied" in caplog.text and "Kx48273fRq" not in caplog.text


async def test_reset_password_without_value_and_blocked_when_pending(mock: respx.MockRouter) -> None:
    mock_guest(mock)
    mock.put(f"/ers/config/guestuser/resetpassword/{GID}").respond(204)
    _, done = await two_step("ise_reset_guest_password", {"user": "mcp-guest-alice"}, **SPONSOR)
    assert done["result"]["password"] is None and "ise_notify_guest" in done["result"]["note"]
    mock_guest(mock, guest(status="PENDING_APPROVAL"))
    blocked, _ = await two_step("ise_reset_guest_password", {"user": "mcp-guest-alice"}, **SPONSOR)
    assert blocked["status"] == "blocked" and "ise_approve_guest" in json.dumps(blocked["blockers"])


async def test_notify_guest_email_and_sms(mock: respx.MockRouter) -> None:
    mock_config(mock)
    mock_guest(mock)
    email = mock.put(f"/ers/config/guestuser/email/{GID}/portalId/{PORTAL_ID}").respond(204)
    preview, done = await two_step(
        "ise_notify_guest",
        {"user": "mcp-guest-alice", "via": "email", "sender_email": "desk@example.com"},
        **SPONSOR,
    )
    assert preview["preview"]["to"] == "alice@example.com" and done["status"] == "applied"
    assert json.loads(email.calls.last.request.content)["OperationAdditionalData"]["additionalData"] == [
        {"name": "senderEmail", "value": "desk@example.com"}
    ]
    assert email.calls.last.request.headers["authorization"] == SPONSOR_AUTH
    # The fixture guest has no phone number: SMS is blocked with the fix.
    blocked, _ = await two_step("ise_notify_guest", {"user": "mcp-guest-alice", "via": "sms"}, **SPONSOR)
    assert blocked["status"] == "blocked" and "phone" in json.dumps(blocked["blockers"])
    with_phone = copy.deepcopy(GUEST)
    with_phone["GuestUser"]["guestInfo"]["phoneNumber"] = "+15555550100"
    mock_guest(mock, with_phone)
    sms = mock.put(f"/ers/config/guestuser/sms/{GID}/portalId/{PORTAL_ID}").respond(204)
    _, done = await two_step("ise_notify_guest", {"user": "mcp-guest-alice", "via": "sms"}, **SPONSOR)
    assert done["status"] == "applied" and sms.called and not sms.calls.last.request.content


async def test_approve_and_deny_pending_guest(mock: respx.MockRouter) -> None:
    pending = guest(status="PENDING_APPROVAL")
    listing = mock.get("/ers/config/guestuser").respond(
        json=ers_page([{"id": GID, "name": "mcp-guest-alice"}])
    )
    mock_guest(mock, pending)
    out = await call_tool(
        make_server(**SPONSOR),
        "ise_list_guest_users",
        {"status": "PENDING_APPROVAL", "response_format": "json"},
    )
    assert "status.EQ.PENDING_APPROVAL" in str(listing.calls.last.request.url)
    assert "ise_approve_guest" in out["results"][0]["status_meaning"]
    approve = mock.put(f"/ers/config/guestuser/approve/{GID}").respond(204)
    preview, done = await two_step("ise_approve_guest", {"user": "mcp-guest-alice"}, **SPONSOR)
    assert preview["action"].startswith("Approve")
    assert done["status"] == "applied" and approve.calls.last.request.headers["authorization"] == SPONSOR_AUTH
    deny = mock.put(f"/ers/config/guestuser/deny/{GID}").respond(204)
    _, done = await two_step("ise_approve_guest", {"user": "mcp-guest-alice", "approve": False}, **SPONSOR)
    assert done["status"] == "applied" and deny.called


async def test_approve_blocked_unless_pending(mock: respx.MockRouter) -> None:
    mock_guest(mock)
    blocked, _ = await two_step("ise_approve_guest", {"user": "mcp-guest-alice"}, **SPONSOR)
    assert blocked["status"] == "blocked" and "not waiting" in json.dumps(blocked["blockers"])


def test_reset_password_value_shapes() -> None:
    from ise_mcp.tools.guest import reset_password_value

    assert reset_password_value(RESET) == "Kx48273fRq"
    assert reset_password_value({"OperationResult": {"resultValue": [{"value": "abc"}]}}) == "abc"
    assert (
        reset_password_value({"OperationResult": {"resultValue": {"name": "password", "value": "x"}}}) == "x"
    )
    assert reset_password_value(None) is None and reset_password_value({}) is None

"""Live (I31): guest types, sponsor groups, portals, and a guest account's whole lifecycle as a sponsor.

Needs ISE_SPONSOR_USERNAME / ISE_SPONSOR_PASSWORD: a sponsor (internal or AD user) in a sponsor group with
REST access ("Access Cisco ISE guest accounts using the programmatic interface") that may use the
'Daily (default)' guest type and manages at least its own accounts. ISE_LIVE_SPONSOR_GROUP names that
group for the read check (optional). Creates and deletes only mcp-guest-* objects. See docs/live-tests.md.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator

import pytest

from tests.live.conftest import Session, live_env, live_server

pytestmark = pytest.mark.live

GUEST_TYPE = "Daily (default)"


@pytest.fixture
async def sponsor_ise(ise: Session) -> AsyncIterator[Session]:
    status = await ise.call("ise_status", {})
    sponsor = status["ise"]["guest_sponsor"]
    if not sponsor.get("configured"):
        pytest.skip("ISE_SPONSOR_USERNAME / ISE_SPONSOR_PASSWORD not set (see docs/live-tests.md)")
    assert sponsor.get("ok"), sponsor
    yield ise


async def test_guest_config_reads(sponsor_ise: Session) -> None:
    types = await sponsor_ise.call("ise_list_guest_types", {"response_format": "json"})
    assert GUEST_TYPE in {t["name"] for t in types["results"]}
    groups = await sponsor_ise.call("ise_list_sponsor_groups", {"response_format": "json"})
    wanted = live_env("ISE_LIVE_SPONSOR_GROUP")
    if wanted:
        (row,) = [g for g in groups["results"] if g["name"] == wanted]
        assert row["rest_access"] is True
    portals = await sponsor_ise.call("ise_list_guest_portals", {"response_format": "json"})
    assert {"sponsor", "sponsored_guest"} <= {p["kind"] for p in portals["results"]}
    locations = await sponsor_ise.call("ise_get_guest_locations", {})
    assert locations["locations"]


async def test_guest_lifecycle(sponsor_ise: Session) -> None:
    ise = sponsor_ise
    name = f"mcp-guest-live-{secrets.token_hex(3)}"
    try:
        created = await ise.apply(
            "ise_create_guest_user",
            {
                "username": name,
                "guest_type": GUEST_TYPE,
                "first_name": "Live",
                "last_name": "Test",
                "company": "MCP",
                "reason_for_visit": "I31 live test",
            },
        )
        result = created["applied"]["result"]
        password = result["password"]
        assert password and result["id"]
        assert password not in str(created["preview"])

        got = await ise.call("ise_get_guest_user", {"user": name})
        assert got["status"] == "AWAITING_INITIAL_LOGIN" and got["sponsor"]
        assert password not in str(got)
        listed = await ise.call("ise_list_guest_users", {"name": name, "response_format": "json"})
        assert [r["username"] for r in listed["results"]] == [name]
        assert password not in str(listed)

        old_end = got["valid_to"]
        await ise.apply("ise_extend_guest_user", {"user": name, "days": 1})
        extended = await ise.call("ise_get_guest_user", {"user": name})
        assert extended["valid_to"] != old_end and extended["valid_days"] == got["valid_days"] + 1
        too_long = await ise.call("ise_extend_guest_user", {"user": name, "days": 30})
        assert too_long["status"] == "blocked"

        await ise.apply("ise_update_guest_user", {"user": name, "company": "MCP Suite"})
        assert (await ise.call("ise_get_guest_user", {"user": name}))["company"] == "MCP Suite"

        await ise.apply("ise_suspend_guest_user", {"user": name, "reason": "I31 live test"})
        suspended = await ise.call("ise_get_guest_user", {"user": name})
        assert suspended["status"] == "SUSPENDED" and suspended["status_reason"] == "I31 live test"
        assert (await ise.call("ise_suspend_guest_user", {"user": name}))["status"] == "blocked"

        await ise.apply("ise_reinstate_guest_user", {"user": name})
        assert (await ise.call("ise_get_guest_user", {"user": name}))["status"] != "SUSPENDED"

        await ise.apply("ise_delete_guest_user", {"user": name})
        gone = await ise.call("ise_get_guest_user", {"user": name}, ok=False)
        assert "error" in gone
    finally:
        left = await ise.call("ise_get_guest_user", {"user": name}, ok=False)
        if "error" not in left:
            await ise.apply("ise_delete_guest_user", {"user": name})


async def test_guest_type_and_sponsor_group_writes(sponsor_ise: Session) -> None:
    ise = sponsor_ise
    gtype, group = "mcp-guest-type-live", "mcp-guest-sg-live"
    locations = (await ise.call("ise_get_guest_locations", {}))["locations"]
    try:
        await ise.apply(
            "ise_set_guest_type",
            {"name": gtype, "default_duration": 4, "max_duration": 8, "duration_unit": "hours"},
        )
        types = await ise.call("ise_list_guest_types", {"response_format": "json"})
        (row,) = [t for t in types["results"] if t["name"] == gtype]
        assert row["max_duration"] == "8 hours"
        await ise.apply("ise_set_guest_type", {"name": gtype, "max_duration": 12})

        groups = await ise.call("ise_list_sponsor_groups", {"response_format": "json"})
        members = [m for g in groups["results"] for m in g["members"]]
        await ise.apply(
            "ise_set_sponsor_group",
            {
                "name": group,
                "member_groups": [members[0]],
                "guest_types": [gtype],
                "locations": locations[:1],
                "description": "I31 live test",
            },
        )
        groups = await ise.call("ise_list_sponsor_groups", {"response_format": "json"})
        (row,) = [g for g in groups["results"] if g["name"] == group]
        assert row["guest_types"] == [gtype] and row["rest_access"] is False and row["manage"] == "own"
    finally:
        for kind, target in (("sponsor_group", group), ("guest_type", gtype)):
            out = await ise.call("ise_delete_object", {"kind": kind, "target": target}, ok=False)
            if out.get("status") == "preview":
                await ise.call(
                    "ise_delete_object", {"kind": kind, "target": target, "confirm": out["confirm"]}
                )


async def test_without_sponsor_guest_tools_explain() -> None:
    from fastmcp import Client

    server = live_server(sponsor_username=None, sponsor_password=None)
    async with Client(server) as c:
        r = await c.call_tool("ise_list_guest_users", {}, raise_on_error=False)
    assert r.is_error and "ISE_SPONSOR_USERNAME" in str(r.content)

"""Live (I4): custom attributes, endpoint bulk create/update/delete, and an authz rule on a custom
attribute matched by a real client behind a switch (needs ISE_LIVE_SWITCH_MAC and the switch test policy;
see docs/live-tests.md). Everything is mcp-test-*
and removed at the end."""

from __future__ import annotations

import asyncio

import pytest

from tests.live.conftest import DOCS, Session, live_env

pytestmark = pytest.mark.live

ATTR = "mcpTestTier"
MACS = ["02:00:5E:00:01:10", "02:00:5E:00:01:11", "02:00:5E:00:01:12"]
SWITCH_MAC = live_env("ISE_LIVE_SWITCH_MAC")


async def ensure_attr(ise: Session) -> None:
    attrs = await ise.call("ise_list_custom_attributes", {"response_format": "json"})
    if ATTR not in {a["name"] for a in attrs["results"]}:
        await ise.apply("ise_set_custom_attribute", {"name": ATTR, "attribute_type": "String"})


async def remove_attr(ise: Session) -> None:
    attrs = await ise.call("ise_list_custom_attributes", {"response_format": "json"})
    if ATTR in {a["name"] for a in attrs["results"]}:
        await ise.apply("ise_set_custom_attribute", {"name": ATTR, "delete": True})


async def bulk_delete(ise: Session, macs: list[str]) -> None:
    preview = await ise.call(
        "ise_bulk_endpoints", {"action": "delete", "endpoints": [{"mac": m} for m in macs]}
    )
    if preview["status"] == "preview":
        await ise.call(
            "ise_bulk_endpoints",
            {"action": "delete", "endpoints": [{"mac": m} for m in macs], "confirm": preview["confirm"]},
        )


async def test_bulk_lifecycle(ise: Session) -> None:
    await ensure_attr(ise)
    await bulk_delete(ise, MACS)
    try:
        items = [
            {
                "mac": m,
                "group": "mcp-test-endpoints",
                "description": "mcp-test bulk",
                "custom_attributes": {ATTR: "bronze"},
            }
            for m in MACS
        ]
        done = await ise.apply("ise_bulk_endpoints", {"action": "create", "endpoints": items})
        assert done["preview"]["preview"]["endpoints_in_request"] == 3
        result = done["applied"]["result"]
        assert result["succeeded"] == 3 and result["failed"] == 0, result

        again = await ise.call("ise_bulk_endpoints", {"action": "create", "endpoints": items})
        assert again["status"] == "blocked" and "already exists" in str(again)

        upd = await ise.apply(
            "ise_bulk_endpoints",
            {"action": "update", "endpoints": [{"mac": MACS[0], "custom_attributes": {ATTR: "silver"}}]},
        )
        assert upd["applied"]["result"]["succeeded"] == 1
        e360 = await ise.call("ise_endpoint_360", {"mac": MACS[0]})
        assert e360["endpoint"]["custom"][ATTR] == "silver"
        assert e360["endpoint"]["group"] == "mcp-test-endpoints"
        assert e360["endpoint"]["description"] == "mcp-test bulk"  # update kept the other fields

        bad = await ise.call(
            "ise_bulk_endpoints",
            {"action": "update", "endpoints": [{"mac": MACS[1], "custom_attributes": {"mcpTestNope": "x"}}]},
        )
        assert bad["status"] == "blocked" and "not defined" in str(bad)
    finally:
        await bulk_delete(ise, MACS)
    gone = await ise.call("ise_bulk_endpoints", {"action": "delete", "endpoints": [{"mac": MACS[0]}]})
    assert gone["status"] == "blocked"


async def latest_auth(ise: Session, mac: str) -> dict:  # type: ignore[type-arg]
    hist = await ise.call("ise_get_auth_history", {"mac": mac, "minutes": 10})
    return next((a for a in hist.get("attempts", []) if a.get("result") == "PASS"), {})


REASON = f"ISE_LIVE_SWITCH_MAC not set (needs a switch and client; see {DOCS})"


@pytest.mark.skipif(not SWITCH_MAC, reason=REASON)
async def test_authz_rule_on_custom_attribute(ise: Session) -> None:
    mac = str(SWITCH_MAC)
    await ensure_attr(ise)
    for _ in range(12):  # a new custom attribute can take a moment to reach the policy dictionary
        attrs = await ise.call(
            "ise_list_dictionary_attributes",
            {"dictionary": "EndPoints", "response_format": "json", "limit": 200},
        )
        if any(a["attribute"] == f"EndPoints:{ATTR}" for a in attrs["results"]):
            break
        await asyncio.sleep(5)
    await ise.apply("ise_set_endpoint", {"mac": mac, "custom_attributes": {ATTR: "gold"}})
    rule = {
        "policy_set": "mcp-test-wired",
        "name": "mcp-test-mab-tier",
        "conditions": ["Wired_MAB", f"EndPoints:{ATTR} equals gold"],
        "profiles": ["mcp-test-permit"],
        "sgt": "Developers",
        "rank": 1,
    }
    await ise.apply("ise_create_authz_rule", rule)
    try:
        await ise.apply("ise_coa_reauth", {"mac": mac, "reauth_type": "rerun"})
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 120
        while True:
            latest = await latest_auth(ise, mac)
            if latest.get("sgt") == "Developers":
                break
            assert loop.time() < deadline, f"the custom-attribute rule never matched: {latest}"
            await asyncio.sleep(5)
        session = await ise.call("ise_find_session", {"mac": mac})
        policy = session.get("session", {}).get("matched_policy", {})
        assert policy.get("authorization_rule") in (None, "mcp-test-mab-tier"), policy
    finally:
        await ise.apply(
            "ise_delete_policy_rule", {"policy_set": "mcp-test-wired", "rule": "mcp-test-mab-tier"}
        )
        await ise.apply("ise_set_endpoint", {"mac": mac, "custom_attributes": {ATTR: ""}})
        await ise.apply("ise_coa_reauth", {"mac": mac, "reauth_type": "rerun"})


async def test_zz_remove_custom_attribute(ise: Session) -> None:
    await remove_attr(ise)
    attrs = await ise.call("ise_list_custom_attributes", {"response_format": "json"})
    assert ATTR not in {a["name"] for a in attrs["results"]}

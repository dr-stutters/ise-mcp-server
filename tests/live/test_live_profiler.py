"""Live profiler tests (I40). They create, change and delete only `mcp-prof-*` custom profiling rules. The
reprofile test sends a CoA to a real endpoint, so it runs only when ISE_LIVE_REPROFILE_MAC names one."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from tests.live.conftest import Session, live_env, need_env
from tests.live.test_live_writes import RUN

pytestmark = pytest.mark.live

RULE = f"mcp-prof-{RUN}"


async def _rule(ise: Session, name: str) -> dict[str, Any] | None:
    out = await ise.call("ise_list_profiling_rules", {"name": name, "response_format": "json"})
    return next((r for r in out["results"] if r["name"] == name), None)


async def test_profiler_status(ise: Session) -> None:
    out = await ise.call("ise_profiler_status", {})
    if not out["profiler_nodes"]:
        pytest.skip("no node runs the Profiler service")
    for node in out["profiler_nodes"]:
        assert set(node["enabled"]) | set(node["disabled"]) >= {"radius", "dhcp", "snmpQuery"}
    assert "FeedService" in out["feed_service"]
    assert out["custom_profiling_rules"]["total"] >= 0


async def test_profiling_rule_lifecycle(ise: Session) -> None:
    try:
        made = await ise.apply(
            "ise_set_profiling_rule",
            {
                "name": RULE,
                # Matches nothing real: the OUI text is not a vendor name.
                "conditions": [
                    "MAC:oui contains mcp-prof-no-such-vendor",
                    "DHCP:dhcpClassIdentifier contains mcp-prof",
                ],
                "match": "all",
                "endpoint_type": ["mcp-prof-test"],
                "enabled": False,
            },
        )
        assert made["applied"]["result"]["name"] == RULE
        row = await _rule(ise, RULE)
        assert row and row["type"] == "CUSTOM" and row["enabled"] is False
        assert row["labels"] == {"endpoint_type": ["mcp-prof-test"]}
        assert "MAC:oui contains mcp-prof-no-such-vendor" in row["condition"]

        upd = await ise.apply("ise_set_profiling_rule", {"name": RULE, "os": ["mcp-prof-os"], "priority": 90})
        assert "profileLabel.MFCInfoOperatingSystem" in upd["preview"]["preview"]["changes"]
        row = await _rule(ise, RULE)
        assert (
            row
            and row["labels"]["os"] == ["mcp-prof-os"]
            and row["labels"]["endpoint_type"] == ["mcp-prof-test"]
        )
        assert isinstance(row["priority"], int)  # ISE keeps priorities as a contiguous rank

        bad = await ise.call(
            "ise_set_profiling_rule", {"name": RULE, "conditions": ["DHCP:no-such-attribute equals x"]}
        )
        assert bad["status"] == "blocked"
    finally:
        if await _rule(ise, RULE):
            await ise.apply("ise_delete_profiling_rule", {"name": RULE})
    assert await _rule(ise, RULE) is None


async def _some_endpoint(ise: Session) -> str:
    mac = live_env("ISE_LIVE_SWITCH_MAC")
    if mac:
        return mac
    sessions = await ise.call("ise_list_active_sessions", {"response_format": "json"})
    macs = [s["mac"] for s in sessions["results"] if s.get("mac")]
    if not macs:
        pytest.skip("no active session to explain (set ISE_LIVE_SWITCH_MAC)")
    return str(macs[0])


async def test_explain_profile(ise: Session) -> None:
    mac = await _some_endpoint(ise)
    out = await ise.call("ise_explain_profile", {"mac": mac})
    assert out["profile"] and out["why"]
    assert "TotalCertaintyFactor" in out["not_available_over_rest"]
    session = out["last_session"]
    if isinstance(session, dict) and session.get("endpoint_policy") and out.get("policy_chain"):
        # The profile in MnT's last authentication is the endpoint's profile or an older one.
        assert out["profile"] == session["endpoint_policy"] or any(
            "last authentication" in w for w in out["why"]
        )
    if out.get("policy_chain"):
        assert out["policy_chain"][0] == out["profile"]


async def test_explain_profile_unknown_mac(ise: Session) -> None:
    out = await ise.call("ise_explain_profile", {"mac": "02:00:5E:FF:FF:FC"})
    assert out["endpoint"] == "not in the ISE endpoint database"


async def test_reprofile_endpoint(ise: Session) -> None:
    mac = need_env("ISE_LIVE_REPROFILE_MAC", "an endpoint with a live session that may be sent a CoA reauth")
    before = await ise.call("ise_find_session", {"mac": mac})
    if not before.get("found"):
        pytest.skip(f"{mac} has no active session")
    res = await ise.apply("ise_reprofile_endpoint", {"mac": mac})
    assert res["preview"]["preview"]["current_profile"]
    assert res["applied"]["result"]["coa_acknowledged"] is True, res["applied"]
    # The NAD re-authenticates the session: MnT records a newer authentication within a few seconds.
    t0 = str(before.get("session", before).get("auth_acs_timestamp") or "")
    for _ in range(15):
        await asyncio.sleep(2)
        out = await ise.call("ise_explain_profile", {"mac": mac})
        last = out["last_session"]
        if isinstance(last, dict) and str(last.get("auth_acs_timestamp") or "") > t0:
            break
    else:
        pytest.fail(f"no new authentication for {mac} after the reprofile CoA")

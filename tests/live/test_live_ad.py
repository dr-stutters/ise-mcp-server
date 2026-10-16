"""Live (I11): the lab's AD join point (MITCHCLOUD -> mitchcloud.lab, seeded by scripts/seed_lab.py --ad).
Join/leave was run by hand (see the notes); these checks are read-only plus a blocked preview."""

from __future__ import annotations

import pytest

from tests.live.conftest import Session

pytestmark = pytest.mark.live

JP = "MITCHCLOUD"
EMPLOYEES = "mitchcloud.lab/MCP-Lab/mcp-employees"


async def joined(ise: Session) -> dict:  # type: ignore[type-arg]
    out = await ise.call("ise_get_ad_join_point", {"join_point": JP}, ok=False)
    if "error" in out or not out.get("join", {}).get("joined"):
        pytest.skip(f"{JP} is not set up/joined on this ISE (seed_lab.py --ad)")
    return out


async def test_join_point_and_groups(ise: Session) -> None:
    jp = await joined(ise)
    assert EMPLOYEES in jp["groups"]
    groups = await ise.call(
        "ise_list_ad_groups", {"join_point": JP, "filter": "mcp*", "response_format": "json"}
    )
    rows = {r["name"]: r["added"] for r in groups["results"]}
    assert rows.get(EMPLOYEES) is True
    again = await ise.call("ise_add_ad_groups", {"join_point": JP, "groups": ["mcp-employees"]})
    assert again["status"] == "blocked"


async def test_user_lookup_and_policy_explain(ise: Session) -> None:
    await joined(ise)
    alice = await ise.call("ise_test_ad_user", {"join_point": JP, "username": "mcp-alice"})
    assert EMPLOYEES in alice["groups_usable_in_policy"]
    ghost = await ise.call("ise_test_ad_user", {"join_point": JP, "username": "mcp-test-nobody"})
    assert ghost["found"] is False
    out = await ise.call(
        "ise_policy_explain", {"nad": "mcp-test-sw1", "flow": "wired-dot1x", "ad_user": "mcp-alice"}
    )
    if out.get("policy_set") != "mcp-test-wired":
        pytest.skip("lab policy set mcp-test-wired not seeded")
    assert "mcp-test-ad-employees" in out["verdict"]

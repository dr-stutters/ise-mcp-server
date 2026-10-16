"""Live (I11): an existing, joined AD join point and one of its groups. Read-only plus a blocked preview.

Needs ISE_LIVE_AD_JOIN_POINT (a joined join point), ISE_LIVE_AD_GROUP (a group already added to it, as
ISE shows it: <domain>/<OU path>/<group>) and, for the user lookup, ISE_LIVE_AD_USER (a member of that
group). See docs/live-tests.md."""

from __future__ import annotations

import pytest

from tests.live.conftest import DOCS, Session, live_env, need_env

pytestmark = pytest.mark.live

JP = live_env("ISE_LIVE_AD_JOIN_POINT")
GROUP = live_env("ISE_LIVE_AD_GROUP")


async def joined(ise: Session) -> dict:  # type: ignore[type-arg]
    need_env("ISE_LIVE_AD_JOIN_POINT", "a joined AD join point")
    need_env("ISE_LIVE_AD_GROUP", "an AD group already added to the join point")
    out = await ise.call("ise_get_ad_join_point", {"join_point": JP}, ok=False)
    if "error" in out or not out.get("join", {}).get("joined"):
        pytest.skip(f"ISE_LIVE_AD_JOIN_POINT={JP} is not set up/joined on this ISE")
    return out


async def test_join_point_and_groups(ise: Session) -> None:
    jp = await joined(ise)
    assert GROUP in jp["groups"]
    short = GROUP.rsplit("/", 1)[-1]
    groups = await ise.call(
        "ise_list_ad_groups", {"join_point": JP, "filter": f"{short}*", "response_format": "json"}
    )
    rows = {r["name"]: r["added"] for r in groups["results"]}
    assert rows.get(GROUP) is True
    again = await ise.call("ise_add_ad_groups", {"join_point": JP, "groups": [short]})
    assert again["status"] == "blocked"


async def test_user_lookup_and_policy_explain(ise: Session) -> None:
    await joined(ise)
    user = need_env("ISE_LIVE_AD_USER", "an AD user in ISE_LIVE_AD_GROUP")
    found = await ise.call("ise_test_ad_user", {"join_point": JP, "username": user})
    assert GROUP in found["groups_usable_in_policy"]
    ghost = await ise.call("ise_test_ad_user", {"join_point": JP, "username": "mcp-test-nobody"})
    assert ghost["found"] is False
    out = await ise.call(
        "ise_policy_explain", {"nad": "mcp-test-sw1", "flow": "wired-dot1x", "ad_user": user}
    )
    if out.get("policy_set") != "mcp-test-wired":
        pytest.skip(f"switch test policy (mcp-test-wired on mcp-test-sw1) not present; see {DOCS}")
    assert "mcp-test-ad-employees" in out["verdict"]  # the switch policy's rule for ISE_LIVE_AD_GROUP

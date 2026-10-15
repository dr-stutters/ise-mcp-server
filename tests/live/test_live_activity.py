"""Live: on-demand recent auth activity (I3). Run `uv run python scripts/seed_lab.py` first so MnT has a
pass (02:00:5E:00:00:01), a 22040 (…:02) and a 22056 (…:03) from NAD mcp-test-radius-client."""

from __future__ import annotations

import pytest

from tests.live.conftest import Session

pytestmark = pytest.mark.live

SEED_NAD = "mcp-test-radius-client"


async def test_auth_list_by_nad_and_user(ise: Session) -> None:
    out = await ise.call(
        "ise_get_auth_list",
        {"since_minutes": 120, "nad": SEED_NAD, "detail": True, "response_format": "json"},
    )
    if not out["total"]:
        pytest.skip("no session from the seed NAD in the last 2 hours (run scripts/seed_lab.py)")
    assert all(r["nad"] == SEED_NAD for r in out["results"] if "nad" in r)
    by_user = await ise.call(
        "ise_get_auth_list", {"since_minutes": 120, "user": "mcp-test-user", "response_format": "json"}
    )
    assert by_user["total"] >= 1
    assert all("mcp-test-user" in r["user"] for r in by_user["results"])


async def test_recent_failures_seed(ise: Session) -> None:
    out = await ise.call(
        "ise_recent_auth_failures",
        {"since_minutes": 120, "nad": SEED_NAD, "macs": ["02:00:5E:00:00:02", "02:00:5E:00:00:03"]},
    )
    codes = {r["code"] for r in out["by_reason"]}
    if not codes:
        pytest.skip("no seed failures in the last 2 hours (run scripts/seed_lab.py)")
    assert {"22040", "22056"} <= codes
    assert out["coverage"]["from"]["given"] == 2
    users = await ise.call(
        "ise_recent_auth_failures",
        {"since_minutes": 120, "user": "mcp-test-user", "macs": ["02:00:5E:00:00:02"]},
    )
    assert {r["code"] for r in users["by_reason"]} == {"22040"}

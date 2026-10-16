"""Live (I5): seed a few hundred mcp-test-scale-* NADs, check the list/lookup tools stay fast and don't
fan out per item, then delete them. Opt in with ISE_LIVE_SCALE=1 (takes a few minutes)."""

from __future__ import annotations

import os
import secrets
import time

import pytest

from ise_mcp._core.testing import live_settings
from ise_mcp.client import IseApp
from ise_mcp.config import Settings
from ise_mcp.tools._common import gather_limited
from tests.live.conftest import Session

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("ISE_LIVE_SCALE") != "1", reason="set ISE_LIVE_SCALE=1"),
]
N = 300
PREFIX = "mcp-test-scale-"


def nad_body(i: int, secret: str) -> dict:  # type: ignore[type-arg]
    return {
        "NetworkDevice": {
            "name": f"{PREFIX}{i:03d}",
            "description": "mcp-test I5 scale",
            "NetworkDeviceIPList": [
                {"ipaddress": f"192.0.2.{i % 250 + 1}" if i < 250 else f"198.51.100.{i - 249}", "mask": 32}
            ],
            "authenticationSettings": {"networkProtocol": "RADIUS", "radiusSharedSecret": secret},
        }
    }


async def cleanup(app: IseApp) -> int:
    page = await app.ers_pager.fetch_page(
        app.ers, "/ers/config/networkdevice", {"filter": f"name.STARTSW.{PREFIX}"}, limit=1000
    )
    ids = [str(i["id"]) for i in page.items]
    await gather_limited(ids, lambda i: app.ers_request("DELETE", f"/ers/config/networkdevice/{i}"))
    return len(ids)


async def test_scale_nads(ise: Session) -> None:
    app = IseApp(live_settings(Settings, "ISE_"))
    secret = secrets.token_hex(8)
    try:
        await cleanup(app)
        await gather_limited(range(N), lambda i: app.ers_create("networkdevice", nad_body(i, secret)))
        t0 = time.perf_counter()
        out = await ise.call("ise_list_nads", {"name": PREFIX, "limit": 500, "response_format": "json"})
        listed = time.perf_counter() - t0
        assert out["total"] == N and out["returned"] == N
        assert "detail threshold" in out["detail_note"]
        assert listed < 20, listed
        small = await ise.call("ise_list_nads", {"name": PREFIX, "limit": 20, "response_format": "json"})
        assert small["returned"] == 20 and small["results"][0]["ips"]
        t0 = time.perf_counter()
        nad = await ise.call("ise_get_nad", {"device": "198.51.100.10"})
        assert nad["name"] == f"{PREFIX}259"
        assert time.perf_counter() - t0 < 10
    finally:
        removed = await cleanup(app)
        await app.aclose()
    assert removed == N

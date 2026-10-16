"""Live: IP-SGT mappings and SXP connections (needs the SXP service on the node). The peer is
ISE_LIVE_SXP_PEER, an unused address in your network, so no real device is touched (see
docs/live-tests.md)."""

from __future__ import annotations

import pytest

from tests.live.conftest import Session, live_env, need_env

pytestmark = pytest.mark.live

PEER = live_env("ISE_LIVE_SXP_PEER")
NET = "10.99.250.0/24"


async def test_ip_sgt_and_sxp_lifecycle(ise: Session) -> None:
    need_env("ISE_LIVE_SXP_PEER", "an unused IP address to use as the SXP peer")
    nodes = await ise.call("ise_list_nodes", {"response_format": "json"})
    if not any("SXP" in (n.get("services") or []) for n in nodes["results"]):
        pytest.skip("SXP service is not enabled on any node")
    try:
        await ise.apply("ise_set_sxp_connection", {"peer_ip": PEER, "peer_name": "mcp-test-sxp-peer"})
        conns = await ise.call("ise_list_sxp_connections", {"peer_ip": PEER, "response_format": "json"})
        assert conns["results"][0]["peer_role"] == "LISTENER"
        res = await ise.apply("ise_set_sxp_connection", {"peer_ip": PEER, "peer_role": "BOTH"})
        assert "sxpMode" in res["preview"]["preview"]["changes"]

        await ise.apply("ise_set_ip_sgt", {"ip": NET, "sgt": "Developers", "sxp_domains": ["default"]})
        binds = await ise.call("ise_list_sxp_bindings", {"domain": "default", "response_format": "json"})
        row = next(b for b in binds["results"] if b["ip"] == NET.split("/")[0] or b["ip"] == NET)
        assert row["sgt"].startswith("Developers")
        res = await ise.apply("ise_set_ip_sgt", {"ip": NET, "sgt": "12"})
        assert res["preview"]["preview"]["changes"]["sgt"]["to"] == "Development_Servers"
        again = await ise.call("ise_set_ip_sgt", {"ip": NET, "sgt": "Development_Servers"})
        assert again["status"] == "blocked"
    finally:
        out = await ise.call("ise_delete_trustsec_object", {"kind": "ip_sgt", "target": NET}, ok=False)
        if isinstance(out, dict) and out.get("status") == "preview":
            await ise.apply("ise_delete_trustsec_object", {"kind": "ip_sgt", "target": NET})
        out = await ise.call(
            "ise_delete_trustsec_object", {"kind": "sxp_connection", "target": PEER}, ok=False
        )
        if isinstance(out, dict) and out.get("status") == "preview":
            await ise.apply("ise_delete_trustsec_object", {"kind": "sxp_connection", "target": PEER})

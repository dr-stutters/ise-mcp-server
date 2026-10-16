"""Live regression for the client-side policy evaluator (I13): its prediction for the MAB path
should match the actual matched rule. Needs the switch test policy (mcp-test-wired; docs/live-tests.md)."""

from __future__ import annotations

import pytest

from ise_mcp._core.testing import call_tool, live_settings
from ise_mcp.config import Settings
from ise_mcp.server import create_server

pytestmark = pytest.mark.live


async def test_policy_explain_predicts_mab_path() -> None:
    settings = live_settings(Settings, "ISE_")  # skips when ISE_URL / credentials are not configured
    out = await call_tool(
        create_server(settings),
        "ise_policy_explain",
        {
            "attributes": {
                "Radius:NAS-Port-Type": "Ethernet",
                "DEVICE:Location": "All Locations#mcp-test-lab",
                "Normalised Radius:RadiusFlowType": "WiredMAB",
            }
        },
    )
    out = out if isinstance(out, dict) else __import__("json").loads(str(out))
    if out.get("policy_set") != "mcp-test-wired":
        pytest.skip("switch test policy mcp-test-wired not present (see docs/live-tests.md)")
    # Wired_MAB resolves, the 802.1X rules are no-match, so the MAB permit rule is the prediction.
    assert "mcp-test-mab-permit" in out["verdict"]
    names = {r["name"]: r["result"] for r in out["authorization"]}
    assert names.get("mcp-test-eaptls") == "no-match"
    assert names.get("mcp-test-mab-permit") == "match"

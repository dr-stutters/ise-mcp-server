"""Live regression for the client-side policy evaluator (I13): its prediction for the lab's MAB path
should match the actual matched rule. Needs the mcp-test-wired policy set (lab_policy.py up)."""

from __future__ import annotations

import pytest
from stutters_mcp_core.testing import call_tool

from ise_mcp.config import Settings
from ise_mcp.server import create_server

pytestmark = pytest.mark.live


async def test_policy_explain_predicts_mab_path() -> None:
    settings = Settings(_env_file=".env")  # type: ignore[call-arg]
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
        pytest.skip("lab policy set mcp-test-wired not present (run scripts/lab_policy.py up)")
    # Wired_MAB resolves, the 802.1X rules are no-match, so the MAB permit rule is the prediction.
    assert "mcp-test-mab-permit" in out["verdict"]
    names = {r["name"]: r["result"] for r in out["authorization"]}
    assert names.get("mcp-test-eaptls") == "no-match"
    assert names.get("mcp-test-mab-permit") == "match"

"""Live I42: export, change one mcp-test-* authorization rule, diff (only that rule shows), restore.

The rule lives in a disabled mcp-test-exp-* policy set created and deleted here, so no traffic is affected."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest
import yaml

from tests.live.conftest import Session

pytestmark = pytest.mark.live

RUN = secrets.token_hex(3)


async def test_full_export_is_stable_and_masked(ise: Session) -> None:
    first = await ise.call("ise_export_config", {})
    second = await ise.call("ise_export_config", {})
    assert isinstance(first, str) and first.startswith("ise_export:")

    def body(text: str) -> str:
        return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("exported_at:"))

    assert body(first) == body(second)  # unchanged ISE -> byte-identical apart from the export time
    data = yaml.safe_load(first)
    assert data["ise_export"]["sections"][0] == "policy_sets"
    for nad in data.get("nads") or []:
        secret = (nad.get("authenticationSettings") or {}).get("radiusSharedSecret")
        assert secret in (None, "********"), nad["name"]
    assert "hitCounts" not in first and "/ers/config/" not in first


async def test_diff_shows_only_the_changed_rule(ise: Session, tmp_path: Path) -> None:
    ps, rule = f"mcp-test-exp-{RUN}", "mcp-test-exp-rule"
    baseline = str(tmp_path / "baseline.yaml")
    try:
        await ise.apply(
            "ise_create_policy_set",
            {"name": ps, "conditions": ["Wired_MAB"], "state": "disabled", "description": "mcp-test"},
        )
        await ise.apply(
            "ise_create_authz_rule",
            {
                "policy_set": ps,
                "name": rule,
                "conditions": ["Radius:NAS-Port-Type equals Ethernet"],
                "profiles": ["PermitAccess"],
            },
        )
        saved = await ise.call("ise_export_config", {"scope": ["policy"], "path": baseline})
        assert saved["path"] == baseline and saved["counts"]["policy_sets"] >= 2
        same = await ise.call("ise_diff_config", {"before": baseline})
        assert same["unchanged"] is True, same["sections"]

        await ise.apply(
            "ise_update_policy_rule",
            {"policy_set": ps, "rule": rule, "state": "monitor", "profiles": ["DenyAccess"]},
        )
        diff = await ise.call("ise_diff_config", {"before": baseline})
        key = f"network-access/{ps}/authorization/{rule}"
        assert diff["sections"] == {
            "policy_rules": {
                "changed": {
                    key: {
                        "profile": {"added": ["DenyAccess"], "removed": ["PermitAccess"]},
                        "state": {"from": "enabled", "to": "monitor"},
                    }
                }
            }
        }, diff["sections"]
        assert diff["summary"] == {"added": 0, "removed": 0, "moved": 0, "changed": 1}
    finally:
        await ise.apply("ise_delete_policy_set", {"policy_set": ps})
    gone = await ise.call("ise_diff_config", {"before": baseline})
    assert gone["sections"] == {"policy_sets": {"removed": [f"network-access/{ps}"]}}, gone["sections"]

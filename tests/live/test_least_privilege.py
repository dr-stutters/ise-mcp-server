"""Least-privilege contract (I16 / core G3): run the read tier as a dedicated read-only ISE admin.

Skipped unless ISE_RO_USERNAME / ISE_RO_PASSWORD are set (the `mcp-test-ro` account from
docs/least-privilege.md, which describes how to create it). It logs in as that
account with MCP caller role `ro`, calls every read tool, and fails on any appliance denial or on a
write tool being visible to `ro`.
"""

from __future__ import annotations

import pytest

from ise_mcp._core.testing.least_privilege import assert_read_tier_works, readonly_live_settings
from ise_mcp.config import Settings
from ise_mcp.server import create_server

pytestmark = pytest.mark.live

# Seeded mcp-test-* objects (docs/live-tests.md), so the sampled read tools resolve.
SAMPLES = {
    "ise_get_nad": {"name": "mcp-test-radius-client"},
    "ise_get_internal_user": {"name": "mcp-test-user"},
    "ise_endpoint_360": {"mac": "02:00:5E:00:00:01"},
    "ise_get_policy_set": {"name": "Default"},
    "ise_why_auth_failed": {"mac": "02:00:5E:00:00:02"},
}
# Spec/escape-hatch tools and ones that need a live RADIUS window are not part of the role contract.
SKIP = {"ise_api_call", "ise_get_definition", "ise_search_spec"}


async def test_read_tier_as_readonly_user() -> None:
    settings = readonly_live_settings(Settings, "ISE_")  # pytest.skip when ISE_RO_* unset
    report = await assert_read_tier_works(create_server(settings), SAMPLES, skip=SKIP)
    print("\n" + report.summary())

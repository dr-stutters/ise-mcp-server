"""Live: the ise_troubleshoot_endpoint_access prompt's ISE steps on a real client (CML ise-access).
Set ISE_LIVE_SWITCH_MAC to the client's MAC (52:54:00:61:3D:9E in the recipe lab)."""

from __future__ import annotations

import os
import re

import pytest

from tests.live.conftest import Session

pytestmark = pytest.mark.live
MAC = os.environ.get("ISE_LIVE_SWITCH_MAC", "")


@pytest.mark.skipif(not MAC, reason="ISE_LIVE_SWITCH_MAC not set (needs the CML ise-access lab)")
async def test_troubleshoot_prompt_steps(ise: Session) -> None:
    rendered = await ise.client.get_prompt(
        "ise_troubleshoot_endpoint_access", {"mac": MAC, "switch": "mcp-cml-ise/sw1", "minutes": "60"}
    )
    text = rendered.messages[0].content.text  # type: ignore[union-attr]
    tools = {t.name for t in await ise.client.list_tools()}
    for ref in set(re.findall(r"`(ise_[a-z0-9_]+)`", text)):
        assert ref in tools, ref
    why = await ise.call("ise_why_auth_failed", {"mac": MAC, "minutes": 60})
    assert why["mac"] == MAC.upper() and why["verdict"]
    e360 = await ise.call("ise_endpoint_360", {"mac": MAC})
    session = e360.get("session")
    if isinstance(session, dict) and session.get("nas_ip_address"):
        nad = await ise.call("ise_get_nad", {"device": session["nas_ip_address"]})
        assert nad["name"]


@pytest.mark.skipif(not MAC, reason="ISE_LIVE_SWITCH_MAC not set (needs the CML ise-access lab)")
async def test_quarantine_prompt_ise_half(ise: Session) -> None:
    """The ise_quarantine_host steps on the real client: ANC on, quarantine profile/SGT in the session,
    ANC off. The switch-side checks (quarantine dACL + SGT 255 in 'show access-session') are manual."""
    rendered = await ise.client.get_prompt(
        "ise_quarantine_host",
        {
            "reason": "mcp-test live",
            "mac": MAC,
            "anc_policy": "mcp-test-quarantine",
            "switch": "mcp-cml-ise/sw1",
        },
    )
    text = rendered.messages[0].content.text  # type: ignore[union-attr]
    tools = {t.name for t in await ise.client.list_tools()}
    for ref in set(re.findall(r"`(ise_[a-z0-9_]+)`", text)):
        assert ref in tools, ref
    found = await ise.call("ise_find_session", {"mac": MAC})
    if not found.get("found"):
        pytest.skip("no live session for the client")
    try:
        await ise.apply("ise_apply_anc", {"mac": MAC, "policy": "mcp-test-quarantine"})
        listed = await ise.call("ise_list_anc_endpoints", {"mac": MAC, "response_format": "json"})
        assert listed["results"][0]["policy"] == "mcp-test-quarantine"
        e360 = await ise.call("ise_endpoint_360", {"mac": MAC})
        assert e360["anc_policy"] == "mcp-test-quarantine"
    finally:
        await ise.apply("ise_clear_anc", {"mac": MAC})
    listed = await ise.call("ise_list_anc_endpoints", {"mac": MAC, "response_format": "json"})
    assert listed["results"] == []

"""I45: prompt ise_onboard_nad (NAD + groups, switch AAA preview, test login, session, undo, G98 coverage)."""

import os
from pathlib import Path

import pytest
from fastmcp import Client

from ise_mcp._core.testing import compare_snapshots, render_prompts
from tests.unit.conftest import make_server
from tests.unit.test_contract import PROMPT_SAMPLES

SNAPSHOTS = Path(__file__).parent.parent / "snapshots" / "prompts"
SAMPLE = PROMPT_SAMPLES["ise_onboard_nad"]


async def render(args: dict[str, str], **settings: object) -> str:
    async with Client(make_server(mcp_enable_writes=True, **settings)) as c:
        r = await c.get_prompt("ise_onboard_nad", args)
    text = r.messages[0].content.text  # type: ignore[union-attr]
    return " ".join(text.split())  # line wrapping is not part of the contract


async def test_prompt_hidden_on_a_read_only_server() -> None:
    async with Client(make_server()) as c:
        names = {p.name for p in await c.list_prompts()}
    assert "ise_onboard_nad" not in names


async def test_prompt_renders_the_full_flow_on_a_cml_switch() -> None:
    text = await render(SAMPLE, mcp_enable_dangerous=True)
    # Before: the NAD, the switch's current AAA, the local-login guard.
    assert '`ise_get_nad` with device="192.0.2.21"' in text and "`ise_update_nad`" in text
    assert '`cml_run_commands` with lab="lab", nodes=["sw1"]' in text
    assert "local privilege-15 username" in text
    # Groups and the NAD.
    assert '`ise_create_ndg` with path="Location#All Locations#SYD"' in text
    assert 'path="Device Type#All Device Types#Switch"' in text
    assert '`ise_create_nad` with name="syd-acc-sw01", ips=["192.0.2.21/32"]' in text
    assert "radius_secret=<from the user>, tacacs_secret=<from the user>" in text
    # Switch AAA lines: RADIUS with CoA, TACACS+ on the vty lines only, local fallback.
    for line in (
        "aaa group server radius ISE-RADIUS",
        "aaa server radius dynamic-author",
        "radius-server dead-criteria time 5 tries 3",
        "aaa authentication login ISE-ADMIN group ISE-TACACS local",
        "line vty 0 15 login authentication ISE-ADMIN",
    ):
        assert line in text, line
    assert '`cml_configure_node` with lab="lab", node="sw1", lines=[the lines above], save=false' in text
    assert "never pass confirm yourself" in text
    # Test login, session.
    assert "test aaa group ISE-RADIUS alice <password> new-code" in text
    assert '`ise_get_auth_list` with nad="syd-acc-sw01", since_minutes=15, user="alice"' in text
    assert '`ise_admin_policy_explain` with user="alice", nad="syd-acc-sw01"' in text
    assert "LOCAL account on the console" in text
    assert '`ise_find_session` with mac="AA:BB:CC:DD:EE:FF"' in text
    # Undo: the switch's 'no' lines and ise_delete_nad (dangerous on).
    assert "no aaa group server radius ISE-RADIUS" in text and "no tacacs server ISE-PSN1" in text
    assert '`ise_delete_nad` with device="syd-acc-sw01"' in text
    assert '`ise_delete_object` kind="ndg"' in text
    # G98: the site's inventory against ISE's NADs.
    assert '`catc_list_devices` with site="Global/SYD/Bldg-1"' in text
    assert 'stale_within="Location#All Locations#SYD"' in text
    # The management-VRF wording (#73): allowed and explained, not the default.
    assert "common lab and data-centre pattern" in text and "Loopback0" in text
    assert "ip radius source-interface Vlan10" in text and "address ipv4 192.0.2.10" in text


async def test_without_dangerous_the_nad_undo_is_a_gui_step() -> None:
    text = await render({"name": "sw1", "ip": "192.0.2.21"})
    assert "`ise_delete_nad`" not in text
    assert "Administration > Network Resources > Network Devices" in text


async def test_catc_switch_radius_only_without_site() -> None:
    text = await render(
        {"name": "sw1", "switch": "edge-sw-01", "vrf": "Mgmt-vrf", "ise_address": "192.0.2.10"}
    )
    assert '`catc_run_show_commands` with devices=["edge-sw-01"]' in text
    assert '`catc_get_device` with device="edge-sw-01"' in text
    assert "`catc_update_site_aaa_settings`" in text and "`catc_provision_devices`" in text
    assert '`catc_create_template` with name="ise-onboard-sw1"' in text and "`catc_deploy_template`" in text
    assert "ip vrf forwarding Mgmt-vrf" in text and "client 192.0.2.10 vrf Mgmt-vrf server-key" in text
    assert "address ipv4 192.0.2.10 auth-port 1812" in text and "`ise_list_nodes`" not in text
    # protocols=radius: no TACACS+ lines; admin logins stay local.
    assert "tacacs" not in text.lower().replace("radius|tacacs", "")
    assert "radius_secret=<from the user>," in text and "tacacs_secret" not in text
    # No site: the coverage check is this switch alone, with its RADIUS server.
    assert '`ise_audit_nads` with expected=[{"name": "sw1", "ip": "<the NAD IP from step 1>"' in text
    assert '"aaa_server": "192.0.2.10"' in text and "check_stale=false" in text
    assert "ask which location group" in text


@pytest.mark.parametrize(
    "args",
    [
        {"name": "sw1; reload"},
        {"name": "sw1", "ip": "not-an-ip"},
        {"name": "sw1", "location": "SYD<script>"},
        {"name": "sw1", "source_interface": "Vlan10; reload"},
        {"name": "sw1", "vrf": "a b"},
        {"name": "sw1", "ise_address": "ise.example.com"},
        {"name": "sw1", "site": "Global/<x>"},
        {"name": "sw1", "test_user": "a b"},
        {"name": "sw1", "device_type": ""},
    ],
)
async def test_prompt_validates(args: dict[str, str]) -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        with pytest.raises(Exception):  # noqa: B017 - FastMCP wraps the InvalidRequest
            await c.get_prompt("ise_onboard_nad", args)


async def test_prompt_snapshot() -> None:
    # Core's prompt snapshot kit, for this prompt (all tiers on); UPDATE_PROMPT_SNAPSHOTS=1 accepts a change.
    rendered = await render_prompts(
        make_server(mcp_enable_writes=True, mcp_enable_dangerous=True), samples=PROMPT_SAMPLES
    )
    update = os.environ.get("UPDATE_PROMPT_SNAPSHOTS", "").lower() in {"1", "true", "yes"}
    problems = compare_snapshots({"ise_onboard_nad": rendered["ise_onboard_nad"]}, SNAPSHOTS, update=update)
    assert not problems, "\n".join(problems)

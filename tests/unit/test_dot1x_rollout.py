"""I87: prompt ise_phased_8021x_rollout (readiness gate, monitor, low-impact, closed per location NDG)."""

import re

import pytest
from fastmcp import Client

from ise_mcp.tools.dot1x_rollout import WRITE_TOOLS
from tests.unit.conftest import make_server
from tests.unit.test_contract import EXTERNAL, PROMPT_SAMPLES

NAME = "ise_phased_8021x_rollout"
SAMPLE = PROMPT_SAMPLES[NAME]
PHASES = ("readiness", "monitor", "low-impact", "closed")


async def render(args: dict[str, str], **settings: object) -> str:
    async with Client(make_server(**settings)) as c:
        r = await c.get_prompt(NAME, args)
    text = r.messages[0].content.text  # type: ignore[union-attr]
    return " ".join(text.split())  # line wrapping is not part of the contract


async def test_prompt_registers_as_read_tier() -> None:
    async with Client(make_server()) as c:
        prompts = {p.name: p for p in await c.list_prompts()}
    assert NAME in prompts
    p = prompts[NAME]
    assert (p.meta or {}).get("tier") == "read"
    assert {a.name for a in p.arguments or []} == {
        "ndg",
        "phase",
        "policy_set",
        "days",
        "switch",
        "interfaces",
        "name_prefix",
    }


async def test_readiness_changes_nothing() -> None:
    text = await render({"ndg": "Location#All Locations#SYD#Bldg-1", "days": "2"}, mcp_enable_writes=True)
    assert 'location "Location#All Locations#SYD#Bldg-1", phase: readiness' in text
    assert "no tool in this run changes anything" in text
    assert '`ise_list_nads` with group="SYD#Bldg-1", detail=true' in text
    assert "`ise_get_auth_list` with nad=<NAD>, since_minutes=2880, detail=true" in text
    assert "`ise_recent_auth_failures` with nad=<NAD>, since_minutes=2880" in text
    assert "`ise_list_endpoints` with static_only=true" in text
    for cls in ("ready", "fallback", "no-profile", "failing"):
        assert cls in text
    # The fix is named, not made: no write tool is referenced in a readiness run.
    for tool in WRITE_TOOLS:
        assert f"`{tool}`" not in text, tool
    assert "`ise_snapshot`" not in text
    # Catalyst Center leg (no switch given: the NDG's switches).
    assert "`catc_list_devices` with ip=<each NAD IP>" in text
    assert '"show access-session", "show authentication sessions"' in text
    assert "`catc_get_device_config` with device=<each switch>" in text


async def test_monitor_phase() -> None:
    text = await render({"ndg": "SYD", "phase": "monitor", "policy_set": "Wired"}, mcp_enable_writes=True)
    assert '`ise_get_policy_set` with policy_set="Wired"' in text
    assert '`ise_snapshot` with site="SYD"' in text
    assert 'rule="Default", profiles=["PermitAccess"]' in text
    assert 'section="authentication", if_user_not_found="CONTINUE"' in text
    assert "authentication convert-to new-style" in text and "device-tracking policy IPDT_POLICY" in text
    assert "no access-session closed" in text
    assert "`ise_compare_snapshot` with before=<the step 4 blob>" in text


async def test_low_impact_phase_creates_dacls_and_profiles() -> None:
    text = await render({"ndg": "SYD#Bldg-1", "phase": "low-impact"}, mcp_enable_writes=True)
    assert '`ise_set_dacl` with name="Bldg-1-PERMIT-ALL", aces=["permit ip any any"]' in text
    assert 'name="Bldg-1-LIMITED"' in text and '"deny ip any any"' in text
    assert '`ise_create_authz_profile` with name="Bldg-1-LowImpact-Permit"' in text
    assert '`ise_update_authz_profile` with profile=<it>, dacl="Bldg-1-PERMIT-ALL"' in text
    assert 'rule="Default", profiles=["Bldg-1-LowImpact-Limited"]' in text
    assert "ip access-group ACL-DEFAULT in" in text and "permit udp any eq bootpc any eq bootps" in text
    assert "Gate for low-impact" in text


async def test_closed_phase_denies_default_and_gates() -> None:
    text = await render(SAMPLE, mcp_enable_writes=True)
    assert "since_minutes=4320" in text
    assert "Gate for closed: no fallback and no no-profile rows left" in text
    assert 'rule="Default", profiles=["DenyAccess"]' in text
    assert "access-session closed" in text
    assert "`ise_set_endpoint`" in text  # the gate's fixes, each a preview
    # The CML node: show commands through cml_run_commands, the config only printed.
    assert '`cml_run_commands` with lab="lab", nodes=["sw1"]' in text
    assert "this prompt does not call it" in text


async def test_name_prefix_and_catc_template_preview_only() -> None:
    text = await render(
        {"ndg": "mcp-phased", "phase": "closed", "switch": "sw1", "name_prefix": "mcp-phased"},
        mcp_enable_writes=True,
    )
    assert '`catc_run_show_commands` with devices=["sw1"]' in text
    assert "`catc_create_template` with project=<a template project the user names>" in text
    assert 'name="mcp-phased-dot1x-closed", software_type="IOS-XE"' in text
    assert "`catc_preview_template`" in text
    assert "Stop there" in text


@pytest.mark.parametrize("phase", PHASES)
async def test_never_instructs_an_unconfirmed_write(phase: str) -> None:
    text = await render({**SAMPLE, "phase": phase}, mcp_enable_writes=True, mcp_enable_dangerous=True)
    # Switch config is never pushed by the prompt: the push tools are not referenced as calls.
    for push in ("catc_deploy_template", "cml_configure_node", "catc_provision_devices"):
        assert f"`{push}`" not in text, push
    assert "never deploys switch config" in text
    assert not re.search(r"confirm\s*=", text)  # no confirm token is ever passed
    writes = [t for t in WRITE_TOOLS if f"`{t}`" in text]
    if writes:
        assert "WITHOUT confirm" in text and "never pass confirm yourself" in text


async def test_read_only_server_gives_gui_steps() -> None:
    text = await render({"ndg": "SYD", "phase": "closed"})
    assert "Write tools are not enabled on this server" in text
    for tool in WRITE_TOOLS:
        assert f"`{tool}`" not in text, tool
    assert "ise_update_policy_rule (write tier, not enabled on this server" in text
    assert "`ise_snapshot`" in text  # reads still run


@pytest.mark.parametrize(
    "args",
    [
        {"ndg": ""},
        {"ndg": "SYD<script>"},
        {"ndg": "SYD", "phase": "enforce"},
        {"ndg": "SYD", "days": "8"},
        {"ndg": "SYD", "switch": "sw1; reload"},
        {"ndg": "SYD", "interfaces": "Gi1/0/1\nshutdown"},
        {"ndg": "SYD", "policy_set": "Wired`x`"},
        {"ndg": "SYD", "name_prefix": "-bad"},
    ],
)
async def test_prompt_validates(args: dict[str, str]) -> None:
    async with Client(make_server()) as c:
        with pytest.raises(Exception):  # noqa: B017 - FastMCP wraps the InvalidRequest / validation error
            await c.get_prompt(NAME, args)


@pytest.mark.parametrize("phase", PHASES)
async def test_every_named_tool_exists(phase: str) -> None:
    # Every tool the prompt names (meta `tools` and backticked in the body) is an ISE tool registered on an
    # all-tiers server or a tool in the peer server's committed manifest (cml_* has none: `uses` only).
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(server) as c:
        own = {t.name for t in await c.list_tools()}
        prompt = next(p for p in await c.list_prompts() if p.name == NAME)
        rendered = await c.get_prompt(NAME, {**SAMPLE, "phase": phase, "switch": ""})
    body = rendered.messages[0].content.text  # type: ignore[union-attr]
    named = set((prompt.meta or {}).get("tools", [])) | set(
        re.findall(r"`((?:ise|catc|cml)_[a-z0-9_]+)`", body)
    )
    peers = {name for tools in EXTERNAL.values() for name in tools}
    missing = sorted(n for n in named if not n.startswith("cml_") and n not in own and n not in peers)
    assert not missing, missing

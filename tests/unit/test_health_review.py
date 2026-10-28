"""I47: prompt ise_deployment_health_review (health, certs, licence, pxGrid, AD, SXP, admins, peers, NADs)."""

import os
import re
from pathlib import Path

import pytest
from fastmcp import Client

from ise_mcp._core.testing import compare_snapshots, render_prompts
from tests.unit.conftest import make_server
from tests.unit.test_contract import EXTERNAL, PROMPT_SAMPLES, SNAPSHOT_PROMPTS

NAME = "ise_deployment_health_review"
SNAPSHOTS = Path(__file__).parent.parent / "snapshots" / "prompts"
SAMPLE = PROMPT_SAMPLES[NAME]


async def render(args: dict[str, str], **settings: object) -> str:
    async with Client(make_server(**settings)) as c:
        r = await c.get_prompt(NAME, args)
    text = r.messages[0].content.text  # type: ignore[union-attr]
    return " ".join(text.split())  # line wrapping is not part of the contract


async def test_prompt_is_read_tier() -> None:
    async with Client(make_server()) as c:
        prompts = {p.name: p for p in await c.list_prompts()}
    assert NAME in prompts
    assert (prompts[NAME].meta or {}).get("tier") == "read"


async def test_prompt_renders_every_section() -> None:
    text = await render(SAMPLE, mcp_enable_writes=True, mcp_enable_dangerous=True)
    assert "Read only: no tool here changes anything" in text
    assert "`ise_deployment_health` with cert_warn_days=60" in text
    # ISE certificates, licence, pxGrid, AD, SXP.
    assert '`ise_list_certificates` with kind="system", expiring_within_days=60' in text
    assert 'kind="trusted", expiring_within_days=60' in text
    assert "`ise_get_license_status`" in text
    assert "`ise_pxgrid_status` with probe=true" in text and "`ise_list_pxgrid_clients`" in text
    assert "`ise_list_identity_sources`" in text and "`ise_get_ad_join_point`" in text
    assert "`ise_list_sxp_connections`" in text and "`ise_list_sxp_bindings`" in text
    assert "show cts sxp connections brief" in text
    # Admins (I74).
    assert "`admins` section" in text and "`ise_list_admin_users` with detail=true" in text
    assert "more than 3 enabled Super Admins" in text and "break-glass" in text
    assert "`ise_list_admin_groups` with external_only=true" in text
    # Cross-platform certificate rows, skipped when not connected.
    assert "`fmc_list_certificates` with expiring_within_days=60" in text
    assert "`catc_get_policy_servers`" in text and "trustState" in text
    assert "skipped (server not connected)" in text
    # NAD coverage from the Catalyst Center site inventory.
    assert '`catc_list_devices` with site="Global/SYD/Bldg-1", role="ACCESS"' in text
    assert "`ise_audit_nads` with expected=<those rows as they are> and check_stale=false" in text
    # Ranked report and renewal paths per platform.
    assert "critical > high > medium > low > info" in text
    assert "sorted by days left" in text
    for ref in (
        "`ise_generate_csr`",
        "`ise_export_csr`",
        "`ise_bind_certificate`",
        "`ise_import_trusted_cert`",
        "`win_sign_csr`",
        "`fmc_enroll_certificate`",
        "`fmc_import_certificate_files`",
        "`catc_accept_ise_certificate`",
    ):
        assert ref in text, ref
    assert "never pass confirm" not in text  # nothing to confirm: the review runs no write


async def test_read_only_server_names_fixes_without_references() -> None:
    text = await render({})
    assert "`ise_deployment_health` with cert_warn_days=90" in text
    assert "`ise_bind_certificate`" not in text
    assert "ise_bind_certificate (dangerous tier, not enabled on this server)" in text
    assert "ise_generate_csr (write tier, not enabled on this server)" in text
    assert "`ise_export_csr`" in text  # read tier: always there
    # No site: the NAD audit runs alone and says coverage needs a site.
    assert "`catc_list_devices`" not in text
    assert "`ise_audit_nads` without `expected`" in text and "site=..." in text


async def test_role_is_optional_and_case_insensitive() -> None:
    text = await render({"site": "Global/SYD", "role": "border router"})
    assert '`catc_list_devices` with site="Global/SYD", role="BORDER ROUTER"' in text
    text = await render({"site": "Global/SYD"})
    assert '`catc_list_devices` with site="Global/SYD" (skip' in text


@pytest.mark.parametrize(
    "args",
    [
        {"site": "Global/<script>"},
        {"site": "Global/SYD", "role": "EDGE"},
        {"cert_warn_days": "0"},
        {"cert_warn_days": "1000"},
    ],
)
async def test_prompt_validates(args: dict[str, str]) -> None:
    async with Client(make_server()) as c:
        with pytest.raises(Exception):  # noqa: B017 - FastMCP wraps the InvalidRequest / validation error
            await c.get_prompt(NAME, args)


async def test_every_named_tool_exists() -> None:
    # Every tool the prompt names (meta `tools` and backticked in the body) is an ISE tool registered on
    # an all-tiers server or a tool in the peer server's committed manifest (win_* has no manifest).
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(server) as c:
        own = {t.name for t in await c.list_tools()}
        prompt = next(p for p in await c.list_prompts() if p.name == NAME)
        body = (await c.get_prompt(NAME, SAMPLE)).messages[0].content.text  # type: ignore[union-attr]
    named = set((prompt.meta or {}).get("tools", [])) | set(
        re.findall(r"`((?:ise|fmc|catc|win)_[a-z0-9_]+)`", body)
    )
    peers = {name for tools in EXTERNAL.values() for name in tools}
    missing = sorted(n for n in named if not n.startswith("win_") and n not in own and n not in peers)
    assert not missing, missing
    assert {"fmc_list_certificates", "catc_get_policy_servers", "catc_list_devices"} <= named


async def test_prompt_snapshot() -> None:
    # Core's prompt snapshot kit, for this prompt (all tiers on); UPDATE_PROMPT_SNAPSHOTS=1 accepts a change.
    rendered = await render_prompts(
        make_server(mcp_enable_writes=True, mcp_enable_dangerous=True), samples=PROMPT_SAMPLES
    )
    update = os.environ.get("UPDATE_PROMPT_SNAPSHOTS", "").lower() in {"1", "true", "yes"}
    problems = compare_snapshots({n: rendered[n] for n in SNAPSHOT_PROMPTS}, SNAPSHOTS, update=update)
    assert not problems, "\n".join(problems)

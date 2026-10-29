"""I48: prompt ise_guest_onboarding (sponsor checks, CWA policy check, create, credentials, verify)."""

import os
import re
from pathlib import Path

import pytest
from fastmcp import Client

from ise_mcp._core.testing import compare_snapshots, render_prompts
from tests.unit.conftest import make_server
from tests.unit.test_contract import PROMPT_SAMPLES, SNAPSHOT_PROMPTS

NAME = "ise_guest_onboarding"
SNAPSHOTS = Path(__file__).parent.parent / "snapshots" / "prompts"
SAMPLE = PROMPT_SAMPLES[NAME]


async def render(args: dict[str, str], **settings: object) -> str:
    async with Client(make_server(mcp_enable_writes=True, **settings)) as c:
        r = await c.get_prompt(NAME, args)
    text = r.messages[0].content.text  # type: ignore[union-attr]
    return " ".join(text.split())  # line wrapping is not part of the contract


async def test_prompt_is_write_tier() -> None:
    async with Client(make_server()) as c:
        assert NAME not in {p.name for p in await c.list_prompts()}
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prompts = {p.name: p for p in await c.list_prompts()}
    assert NAME in prompts
    assert (prompts[NAME].meta or {}).get("tier") == "write"


async def test_prompt_renders_the_full_flow() -> None:
    text = await render(SAMPLE)
    # Preview-first writes and the password rule.
    assert "never pass confirm yourself" in text
    assert "Never repeat it, summarise it" in text and '"(delivered by email)"' in text
    # Readiness: sponsor, type, location, portal, existing account.
    assert "`ise_status`: `guest_sponsor` must be set" in text
    assert "`ise_list_sponsor_groups`" in text and "rest_access=true" in text
    assert '`ise_list_guest_types`: "Daily (default)" exists' in text
    assert 'the location "San Jose" exists' in text
    assert '`ise_list_guest_portals` with kind="sponsored_guest"' in text
    assert '`ise_list_guest_users` with name="visitor01"' in text
    # CWA policy before and after the portal login.
    assert '`ise_list_authz_profiles` with name="WebAuth"' in text and "CentralizedWebAuth" in text
    assert '`ise_policy_explain` with nad="wlc1", flow="wireless-mab"' in text
    assert "Wi-Fi_Redirect_to_Guest_Login" in text and "If User not found = CONTINUE" in text
    assert (
        'attributes={"Network Access:UseCase": "Guest Flow", '
        '"IdentityGroup:Name": "Endpoint Identity Groups:GuestEndpoints"}'
    ) in text
    # The account as the sponsor, preview first, no password argument.
    assert (
        '`ise_create_guest_user` with username="visitor01", guest_type="Daily (default)", '
        'location="San Jose", email="visitor01@example.com", phone="+15555550123"'
    ) in text
    assert "no password: ISE's guest password policy makes one" in text
    # Credentials by ISE.
    assert '`ise_notify_guest` with user="visitor01", via="email" WITHOUT confirm' in text
    assert "SMTP Server" in text and "`ise_reset_guest_password`" in text
    # Verification: session, auth history (CWA sequence, CoA), status.
    assert '`ise_find_session` with mac="AA:BB:CC:DD:EE:FF"' in text
    assert '`ise_get_auth_history` with mac="AA:BB:CC:DD:EE:FF", include_steps=true' in text
    assert "kind=coa" in text and "AWAITING_INITIAL_LOGIN" in text and "ACTIVE" in text
    assert "`ise_why_auth_failed`" in text
    # Report and the named (not run) cleanup.
    assert "`ise_suspend_guest_user`" in text and "`ise_delete_guest_user`" in text
    assert "never the password" in text


async def test_minimal_args_wired_and_hand_over() -> None:
    text = await render({"username": "visitor02", "notify": "none", "access": "wired"})
    assert "the guest type the user picks" in text
    assert "guest_type=<the type picked>" in text
    assert "`ise_notify_guest`" not in text
    assert "notify=none: the sponsor hands them over" in text
    assert 'flow="wired-mab"' in text and "Wired_MAB" in text and "plug into a guest port" in text
    assert "no nad (the guest's WLC or switch is unknown" in text
    # No MAC: the session is found by username and the history MAC comes from it.
    assert '`ise_find_session` with username="visitor02"' in text
    assert "mac=<the calling station id from the session above>" in text
    assert "(handed over by the sponsor)" in text and "delivered by none" not in text


async def test_sms_needs_a_phone() -> None:
    text = await render({"username": "visitor03", "notify": "sms", "phone": "+15555550199"})
    assert '`ise_notify_guest` with user="visitor03", via="sms"' in text
    assert 'the mobile "+15555550199"' in text and "SMS gateway" in text


@pytest.mark.parametrize(
    "args",
    [
        {"username": "bad name!"},
        {"username": "v1", "notify": "email"},  # no email
        {"username": "v1", "notify": "sms", "email": "a@example.com"},  # no phone
        {"username": "v1", "email": "not-an-email"},
        {"username": "v1", "phone": "5551234", "notify": "none"},
        {"username": "v1", "notify": "none", "mac": "zz:zz"},
        {"username": "v1", "notify": "none", "guest_type": "Daily`; drop"},
        {"username": "v1", "notify": "none", "nad": "wlc 1; rm"},
        {"username": "v1", "notify": "none", "access": "vpn"},
    ],
)
async def test_prompt_validates(args: dict[str, str]) -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        with pytest.raises(Exception):  # noqa: B017 - FastMCP wraps the InvalidRequest / validation error
            await c.get_prompt(NAME, args)


async def test_every_named_tool_exists() -> None:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(server) as c:
        own = {t.name for t in await c.list_tools()}
        prompt = next(p for p in await c.list_prompts() if p.name == NAME)
        body = (await c.get_prompt(NAME, SAMPLE)).messages[0].content.text  # type: ignore[union-attr]
    named = set((prompt.meta or {}).get("tools", [])) | set(re.findall(r"`(ise_[a-z0-9_]+)`", body))
    assert not sorted(named - own), sorted(named - own)
    assert {"ise_create_guest_user", "ise_notify_guest", "ise_find_session", "ise_policy_explain"} <= named


async def test_prompt_snapshot() -> None:
    # Core's prompt snapshot kit (all tiers on); UPDATE_PROMPT_SNAPSHOTS=1 accepts a change.
    rendered = await render_prompts(
        make_server(mcp_enable_writes=True, mcp_enable_dangerous=True), samples=PROMPT_SAMPLES
    )
    update = os.environ.get("UPDATE_PROMPT_SNAPSHOTS", "").lower() in {"1", "true", "yes"}
    problems = compare_snapshots({n: rendered[n] for n in SNAPSHOT_PROMPTS}, SNAPSHOTS, update=update)
    assert not problems, "\n".join(problems)

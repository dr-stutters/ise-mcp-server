"""I69: ise_incident_timeline window-only mode (no host indicator, more sources); the host path stays."""

import os
from pathlib import Path

import pytest
from fastmcp import Client

from ise_mcp._core.testing import compare_snapshots, render_prompts
from ise_mcp.tools.workflows import ad_group_events_script
from tests.unit.conftest import make_server
from tests.unit.test_contract import PROMPT_SAMPLES, SNAPSHOT_PROMPTS

SNAPSHOTS = Path(__file__).parent.parent / "snapshots" / "prompts"


async def render(args: dict[str, str], **settings: object) -> str:
    async with Client(make_server(**settings)) as c:
        r = await c.get_prompt("ise_incident_timeline", args)
    text = r.messages[0].content.text  # type: ignore[union-attr]
    return " ".join(text.split())  # line wrapping is not part of the contract


async def test_window_only_lists_every_source_in_the_window() -> None:
    text = await render(
        {
            "window_start": "2026-10-29T09:10Z",
            "window_end": "2026-10-29 19:20+10:00",  # the same instant as 09:20Z
            "nad": "192.0.2.21",
            "firewall": "ftd1",
            "switch": "edge-sw-01",
        }
    )
    assert "window 2026-10-29T09:10:00Z to 2026-10-29T09:20:00Z" in text
    # ISE: the auth list takes the window itself (length + end), failures a look-back to now.
    assert '`ise_get_auth_list` with since_minutes=10, until="2026-10-29T09:20:00Z", nad="192.0.2.21"' in text
    assert "`ise_recent_auth_failures` with since_minutes=<minutes from 2026-10-29T09:10:00Z" in text
    assert "configuration change audit is not available over REST" in text
    assert '`fmc_run_show_command` with device="ftd1", command="show logging"' in text
    assert "`fmc_recent_activity` with since_minutes=" in text and 'device="ftd1"' in text
    assert '`catc_run_show_commands` with devices=["edge-sw-01"], commands=["show logging"]' in text
    assert "`catc_recent_activity` with hours=" in text
    assert "`cml_list_lab_events`" in text and "keep only events in the window" in text
    assert '`netbox_change_history` with since="2026-10-29T09:10:00Z", until="2026-10-29T09:20:00Z"' in text
    assert "`win_run_powershell_json`" in text and "Id=4728,4729" in text
    assert "skipped if not connected" in text
    # No host-path steps.
    assert "`ise_get_auth_history`" not in text and "`ise_find_session`" not in text


async def test_window_only_on_a_cml_switch_and_lab() -> None:
    text = await render(
        {"window_start": "2026-10-29T09:10:00Z", "switch": "mcp-lab/sw1", "lab": "mcp lab (2)"}
    )
    assert '`cml_run_commands` with lab="mcp-lab", nodes=["sw1"], commands=["show logging"]' in text
    assert '`cml_list_lab_events` for lab="mcp lab (2)"' in text
    # Open-ended window: look-backs to now, the AD script with placeholders the model fills.
    assert "to now (UTC)" in text
    assert 'since="2026-10-29T09:10:00Z":' in text  # netbox, no until
    assert "START and END" in text and "Parse('START')" in text


async def test_no_arguments_is_window_only_over_the_last_minutes() -> None:
    text = await render({"minutes": "30"})  # read-only server: the prompt is read tier
    assert "window the last 30 minutes" in text
    assert "`ise_get_auth_list` with since_minutes=30" in text
    assert "`catc_recent_activity` with hours=0.5" in text
    assert 'since="30m"' in text
    assert "`cml_list_labs`" in text


async def test_host_path_unchanged() -> None:
    text = await render({"mac": "aa:bb:cc:dd:ee:ff", "minutes": "120"})
    assert "over the last 120 minutes" in text
    assert '`ise_get_auth_history` with mac="AA:BB:CC:DD:EE:FF" and minutes=120' in text
    assert "`fmc_list_deployments`" in text and "`catc_list_issues`" in text
    assert "`ise_get_auth_list`" not in text and "`cml_list_lab_events`" not in text


async def test_host_path_with_a_window() -> None:
    text = await render(
        {"username": "alice", "window_start": "2026-10-29T09:10Z", "window_end": "2026-10-29T09:20Z"}
    )
    assert 'user "alice" from 2026-10-29T09:10:00Z to 2026-10-29T09:20:00Z' in text
    assert "Drop rows outside the window" in text


@pytest.mark.parametrize(
    ("args", "match"),
    [
        ({"window_start": "09:10"}, "ISO 8601"),
        ({"window_start": "2026-10-29T09:10Z; rm -rf"}, "ISO 8601"),
        ({"window_end": "2026-10-29T09:20Z"}, "needs a window_start"),
        ({"window_start": "2026-10-29T09:20Z", "window_end": "2026-10-29T09:10Z"}, "after window_start"),
        ({"window_start": "2026-10-01T00:00Z", "window_end": "2026-10-29T00:00Z"}, "at most 7 days"),
        ({"window_start": "2026-13-01T00:00Z"}, "window_start"),
        ({"firewall": "ftd1; show run"}, "firewall"),
        ({"lab": "x'); Remove-Item"}, "lab"),
        ({"nad": 'a" b'}, "nad"),
    ],
)
async def test_bad_arguments_are_refused(args: dict[str, str], match: str) -> None:
    async with Client(make_server()) as c:
        with pytest.raises(Exception, match=match):
            await c.get_prompt("ise_incident_timeline", args)


def test_ad_script_is_the_fixed_query() -> None:
    script = ad_group_events_script("2026-10-29T09:10:00Z", "2026-10-29T09:20:00Z")
    assert script.startswith("Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4728,4729;")
    assert "Set-" not in script and "Remove-" not in script and "Invoke-" not in script


async def test_prompt_snapshot() -> None:
    # Core's prompt snapshot kit (the window-only sample); UPDATE_PROMPT_SNAPSHOTS=1 accepts a change.
    rendered = await render_prompts(
        make_server(mcp_enable_writes=True, mcp_enable_dangerous=True), samples=PROMPT_SAMPLES
    )
    update = os.environ.get("UPDATE_PROMPT_SNAPSHOTS", "").lower() in {"1", "true", "yes"}
    problems = compare_snapshots({n: rendered[n] for n in SNAPSHOT_PROMPTS}, SNAPSHOTS, update=update)
    assert not problems, "\n".join(problems)

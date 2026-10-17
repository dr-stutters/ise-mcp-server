"""Live device admin (I41): ise_admin_policy_explain and ise_test_command_set predictions against a real
TACACS+ login and command authorization on a switch.

Needs a switch that is a NAD on this ISE with a TACACS+ secret and VTY login/exec/command authorization
(`aaa authorization commands 15`) towards ISE (only level-15 commands reach ISE, so every command
tested here is a level-15 one), reachable over SSH from the test host, the DeviceAdmin
service on ISE, and `ssh` + `sshpass` locally. See docs/live-tests.md (ISE_LIVE_DADM_*).

The test builds its own `mcp-dadm-*` objects (identity groups, users, command sets, a shell profile and a
device-admin policy set that matches only `mcp-dadm-*` users on that NAD, so other admins are untouched),
logs in as each user, runs commands, compares, and deletes everything again.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import shutil
from typing import Any

import pytest

from tests.live.conftest import Session, need_env

pytestmark = pytest.mark.live

RUN = secrets.token_hex(3)
PS = f"mcp-dadm-ps-{RUN}"
SHELL = f"mcp_dadm_priv15_{RUN}"
PASSWORD = f"Mcp{secrets.token_hex(6)}9z"

# Command sets: two realistic roles and a probe set whose lines pin down ISE's matching semantics.
SETS: dict[str, tuple[list[str], bool]] = {
    "netops": (["PERMIT show .*", "PERMIT configure terminal", "PERMIT exit", "DENY_ALWAYS reload"], False),
    "helpdesk": (["PERMIT show .*", "PERMIT exit"], False),
    "probe": (
        [
            "PERMIT show start",  # argument regexes are anchored: no match for 'startup-config'
            "PERMIT show running-config.*1/0/1",  # by position: compared with 'running-config' only
            "PERMIT write TERMINAL",  # arguments are case-insensitive
            "PERMIT con*e terminal",  # command-name wildcard
            "PERMIT more .*",
            "DENY_ALWAYS more system:running-config",  # DENY_ALWAYS later in the same set still wins
            "PERMIT exit",
        ],
        False,
    ),
}
USERS = {"alice": "netops", "bob": "helpdesk", "carol": "probe"}
COMMANDS = {
    "alice": ["show running-config", "configure terminal", "reload cancel"],
    "bob": ["show running-config", "configure terminal", "reload cancel"],
    "carol": [
        "show startup-config",
        "show running-config interface GigabitEthernet1/0/1",
        "write terminal",
        "configure terminal",
        "more system:running-config",
        "more nvram:startup-config",
    ],
}
# 'reload cancel' goes through the same command authorization as 'reload' (command 'reload', any
# arguments) but does nothing when permitted. Never run anything disruptive unless predicted deny.
DISRUPTIVE = {"reload"}


def name(kind: str, role: str) -> str:
    """mcp-dadm-<role>-<run> for groups and users, ...-cs for command sets."""
    return f"mcp-dadm-{role}-{RUN}" + ("-cs" if kind == "cs" else "")


async def ssh_command(host: str, user: str, command: str) -> str:
    """One SSH exec session: TACACS+ authentication, exec authorization, then command authorization."""
    proc = await asyncio.create_subprocess_exec(
        "sshpass",
        "-e",
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "PreferredAuthentications=password,keyboard-interactive",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "LogLevel=ERROR",
        f"{user}@{host}",
        command,
        env={**os.environ, "SSHPASS": PASSWORD},
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await asyncio.wait_for(proc.communicate(), 60)
    return out.decode(errors="replace")


def device_verdict(output: str) -> str:
    """IOS-XE prints nothing for a command that fails authorization in an SSH exec session (no
    'Command authorization failed' there), so every command tested here is one that always prints."""
    low = output.lower()
    if "permission denied" in low:
        return "login-failed"
    if not output.strip() or "authorization failed" in low:
        return "deny"
    if "% invalid" in low or "invalid autocommand" in low:
        return f"unclear: {output.strip()[:200]!r}"
    return "permit"


async def apply_quiet(ise: Session, tool: str, args: dict[str, Any]) -> None:
    prev = await ise.call(tool, args, ok=False)
    if isinstance(prev, dict) and prev.get("confirm"):
        await ise.call(tool, {**args, "confirm": prev["confirm"]}, ok=False)


async def setup(ise: Session, nad: str) -> None:
    for role in SETS:
        await ise.apply("ise_create_group", {"kind": "identity", "name": name("group", role)})
    for user, role in USERS.items():
        await ise.apply(
            "ise_create_internal_user",
            {"name": name("user", user), "password": PASSWORD, "groups": [name("group", role)]},
        )
    for role, (lines, unmatched) in SETS.items():
        await ise.apply(
            "ise_set_command_set",
            {"name": name("cs", role), "commands": lines, "permit_unmatched": unmatched},
        )
    await ise.apply("ise_set_shell_profile", {"name": SHELL, "privilege": 15})
    await ise.apply(
        "ise_create_policy_set",
        {
            "kind": "device-admin",
            "name": PS,
            "conditions": [
                f"Network Access:NetworkDeviceName equals {nad}",
                "TACACS:User startsWith mcp-dadm-",
            ],
            "rank": 0,
        },
    )
    for role in SETS:
        await ise.apply(
            "ise_create_authz_rule",
            {
                "kind": "device-admin",
                "policy_set": PS,
                "name": f"mcp-dadm-{role}",
                "conditions": [f"IdentityGroup:Name equals User Identity Groups:{name('group', role)}"],
                "command_sets": [name("cs", role)],
                "shell_profile": SHELL,
            },
        )


async def teardown(ise: Session) -> None:
    await apply_quiet(ise, "ise_delete_policy_set", {"policy_set": PS, "kind": "device-admin"})
    for user in USERS:
        await apply_quiet(ise, "ise_delete_object", {"kind": "internal_user", "target": name("user", user)})
    for role in SETS:
        await apply_quiet(ise, "ise_delete_object", {"kind": "command_set", "target": name("cs", role)})
        await apply_quiet(ise, "ise_delete_object", {"kind": "identity_group", "target": name("group", role)})
    await apply_quiet(ise, "ise_delete_object", {"kind": "shell_profile", "target": SHELL})


async def test_admin_explain_matches_device(ise: Session) -> None:
    nad = need_env(
        "ISE_LIVE_DADM_NAD", "a NAD with a TACACS+ secret whose device authorizes commands via ISE"
    )
    host = need_env("ISE_LIVE_DADM_HOST", "SSH address of that device")
    if not (shutil.which("ssh") and shutil.which("sshpass")):
        pytest.skip("ssh and sshpass are needed for the device logins")
    try:
        await setup(ise, nad)
        await asyncio.sleep(5)  # ISE replicates new policy to the PSN's runtime
        mismatches: list[str] = []
        seen: dict[str, dict[str, str]] = {}
        for user, role in USERS.items():
            username = name("user", user)
            explain = await ise.call(
                "ise_admin_policy_explain", {"user": username, "nad": nad, "command": COMMANDS[user]}
            )
            assert explain["policy_set"] == PS, explain
            assert f"mcp-dadm-{role}" in explain["verdict"], explain
            tested = await ise.call(
                "ise_test_command_set",
                {"policy_set": PS, "rule": f"mcp-dadm-{role}", "command": COMMANDS[user]},
            )
            for predicted, offline in zip(explain["commands"], tested["results"], strict=True):
                assert predicted["verdict"] == offline["verdict"], (predicted, offline)
                command = predicted["command"]
                if command.split()[0] in DISRUPTIVE and predicted["verdict"] != "deny":
                    mismatches.append(
                        f"{user}: refusing to run {command!r}, predicted {predicted['verdict']}"
                    )
                    continue
                actual = device_verdict(await ssh_command(host, username, command))
                seen.setdefault(user, {})[command] = actual
                if actual != predicted["verdict"]:
                    mismatches.append(
                        f"{user} {command!r}: predicted {predicted['verdict']} ({predicted['because']}), "
                        f"device said {actual}"
                    )
        assert not mismatches, f"{mismatches}\nall device results: {seen}"
        # The expected matrix, so a silent change in both predictor and device behaviour still shows up.
        assert seen["alice"] == {
            "show running-config": "permit",
            "configure terminal": "permit",
            "reload cancel": "deny",
        }
        assert seen["bob"]["configure terminal"] == "deny"
        assert seen["carol"] == {
            "show startup-config": "deny",
            "show running-config interface GigabitEthernet1/0/1": "deny",
            "write terminal": "permit",
            "configure terminal": "permit",
            "more system:running-config": "deny",
            "more nvram:startup-config": "permit",
        }
        # Hit counts are the only API-side evidence of TACACS+ logins (no live-log REST API).
        hits: dict[str, Any] = {}
        for _ in range(12):
            got = await ise.call("ise_get_policy_set", {"policy_set": PS, "kind": "device-admin"})
            hits = {r["name"]: r.get("hits") for r in got["authorization"]}
            if all((hits.get(f"mcp-dadm-{role}") or 0) > 0 for role in SETS):
                break
            await asyncio.sleep(10)
        assert all((hits.get(f"mcp-dadm-{role}") or 0) > 0 for role in SETS), hits
        audit = await ise.call("ise_audit_nads", {"limit": 500})
        row = next(r for r in audit["results"] if r["name"] == nad)
        assert row["tacacs"]["shared_secret_set"] is True and "single_connect" in row["tacacs"]
        assert PS in (row["tacacs"].get("may_match_first") or []), row
    finally:
        await teardown(ise)


async def test_tacacs_server_and_sequence_lifecycle(ise: Session) -> None:
    """Create, update and delete a TACACS+ external server and sequence (nothing is contacted: the
    server address is in TEST-NET-1 and no policy set proxies to the sequence)."""
    # TACACS+ server and sequence names allow only letters, digits and "_".
    server, seq = f"mcp_dadm_srv_{RUN}", f"mcp_dadm_seq_{RUN}"
    try:
        await ise.apply(
            "ise_set_tacacs_server",
            {
                "name": server,
                "host": "192.0.2.49",
                "shared_secret": secrets.token_hex(8),
                "single_connect": False,
            },
        )
        upd = await ise.apply("ise_set_tacacs_server", {"name": server, "timeout_seconds": 10})
        assert upd["preview"]["preview"]["changes"]["timeout"]["to"] == 10
        await ise.apply(
            "ise_set_tacacs_server_sequence", {"name": seq, "servers": [server], "suffix_strip": "@"}
        )
        got = await ise.call("ise_get_tacacs_servers", {})
        row = next(x for x in got["servers"] if x["name"] == server)
        assert row["shared_secret_set"] is True and row["timeout"] == 10 and row["single_connect"] is False
        srow = next(x for x in got["sequences"] if x["name"] == seq)
        assert srow["servers"] == [server] and srow["suffix_strip"] == "@" and "missing_servers" not in srow
        blocked = await ise.call("ise_delete_object", {"kind": "tacacs_server", "target": server})
        assert blocked["status"] == "blocked" and seq in blocked["blockers"][0]
    finally:
        await apply_quiet(ise, "ise_delete_object", {"kind": "tacacs_sequence", "target": seq})
        await apply_quiet(ise, "ise_delete_object", {"kind": "tacacs_server", "target": server})
    left = await ise.call("ise_get_tacacs_servers", {})
    assert server not in str(left) and seq not in str(left)

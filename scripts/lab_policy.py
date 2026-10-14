"""Build or remove the ISE side of the CML 'ise-access' lab (cml-mcp-server recipe) through the MCP tools,
the way a model would (preview, then confirm).

    uv run python scripts/lab_policy.py up      # NAD + NDG, dACLs, profiles, policy sets, ANC, TACACS+
    uv run python scripts/lab_policy.py down    # remove everything 'up' created (reverse order)

What 'up' creates (all named mcp-test-*; idempotent: existing objects are left alone):
- NDG Location#All Locations#mcp-test-lab; NAD mcp-test-sw1 198.18.128.154 (RADIUS + TACACS+ key ***REDACTED***,
  the lab switch's key)
- dACLs mcp-test-permit-dacl / mcp-test-quarantine-dacl; authz profiles mcp-test-permit / mcp-test-quarantine
- network-access policy set mcp-test-wired (DEVICE:Location = the lab NDG AND NAS-Port-Type Ethernet):
  authn mcp-test-mab (Internal Endpoints, CONTINUE) and mcp-test-dot1x (Internal Users); authz
  mcp-test-anc-quarantine (Session:ANCPolicy = mcp-test-quarantine -> quarantine + SGT Quarantined_Systems),
  mcp-test-dot1x-netops (802.1X + group mcp-test-netops -> permit + SGT Employees),
  mcp-test-mab-permit (Wired_MAB -> permit + SGT Employees)
- ANC policy mcp-test-quarantine (QUARANTINE)
- identity group mcp-test-netops, user mcp-test-netops1 (password from MCP_LAB_USER_PASSWORD, default
  ***REDACTED***), command set mcp-test-show-only, shell profile mcp_test_priv15, device-admin policy
  set mcp-test-devadmin with rule mcp-test-netops
The Device Admin service is NOT turned on here (dangerous; ise_update_node_services enable=['DeviceAdmin']).
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from fastmcp import Client
from stutters_mcp_core.testing import live_settings

from ise_mcp.config import Settings
from ise_mcp.server import create_server

LAB_NDG = "Location#All Locations#mcp-test-lab"
PASSWORD = os.environ.get("MCP_LAB_USER_PASSWORD", "***REDACTED***")

UP: list[tuple[str, dict[str, Any]]] = [
    ("ise_create_ndg", {"path": LAB_NDG, "description": "mcp-test CML lab"}),
    (
        "ise_create_nad",
        {
            "name": "mcp-test-sw1",
            "ips": ["198.18.128.154"],
            "radius_secret": "***REDACTED***",
            "tacacs_secret": "***REDACTED***",
            "groups": [LAB_NDG, "Device Type#All Device Types"],
            "description": "mcp-test CML sw1",
        },
    ),
    (
        "ise_set_dacl",
        {
            "name": "mcp-test-permit-dacl",
            "aces": [
                "permit udp any any eq 67",
                "permit udp any any eq 53",
                "permit icmp any any",
                "permit ip any any",
            ],
            "ip_version": "IPV4",
            "description": "mcp-test",
        },
    ),
    (
        "ise_set_dacl",
        {
            "name": "mcp-test-quarantine-dacl",
            "aces": ["permit udp any any eq 67", "permit udp any any eq 53", "deny ip any any"],
            "ip_version": "IPV4",
            "description": "mcp-test",
        },
    ),
    (
        "ise_create_authz_profile",
        {"name": "mcp-test-permit", "access": "accept", "dacl": "mcp-test-permit-dacl"},
    ),
    (
        "ise_create_authz_profile",
        {"name": "mcp-test-quarantine", "access": "accept", "dacl": "mcp-test-quarantine-dacl"},
    ),
    ("ise_create_anc_policy", {"name": "mcp-test-quarantine", "actions": ["QUARANTINE"]}),
    ("ise_create_group", {"kind": "identity", "name": "mcp-test-netops", "description": "mcp-test"}),
    (
        "ise_create_internal_user",
        {"name": "mcp-test-netops1", "password": PASSWORD, "groups": ["mcp-test-netops"]},
    ),
    (
        "ise_create_policy_set",
        {
            "name": "mcp-test-wired",
            "conditions": [f"DEVICE:Location equals {LAB_NDG}", "Radius:NAS-Port-Type equals Ethernet"],
            "description": "mcp-test CML lab",
        },
    ),
    (
        "ise_create_authn_rule",
        {
            "policy_set": "mcp-test-wired",
            "name": "mcp-test-mab",
            "conditions": ["Wired_MAB"],
            "identity_source": "Internal Endpoints",
            "if_user_not_found": "CONTINUE",
        },
    ),
    (
        "ise_create_authn_rule",
        {
            "policy_set": "mcp-test-wired",
            "name": "mcp-test-dot1x",
            "conditions": ["Wired_802.1X"],
            "identity_source": "Internal Users",
            "rank": 1,
        },
    ),
    (
        "ise_create_authz_rule",
        {
            "policy_set": "mcp-test-wired",
            "name": "mcp-test-mab-permit",
            "conditions": ["Wired_MAB"],
            "profiles": ["mcp-test-permit"],
            "sgt": "Employees",
        },
    ),
    (
        "ise_create_authz_rule",
        {
            "policy_set": "mcp-test-wired",
            "name": "mcp-test-dot1x-netops",
            "conditions": ["Wired_802.1X", "IdentityGroup:Name equals User Identity Groups:mcp-test-netops"],
            "profiles": ["mcp-test-permit"],
            "sgt": "Employees",
        },
    ),
    (
        "ise_create_authz_rule",
        {
            "policy_set": "mcp-test-wired",
            "name": "mcp-test-anc-quarantine",
            "conditions": ["Session:ANCPolicy equals mcp-test-quarantine"],
            "profiles": ["mcp-test-quarantine"],
            "sgt": "Quarantined_Systems",
            "rank": 0,
        },
    ),
    (
        "ise_set_command_set",
        {
            "name": "mcp-test-show-only",
            "commands": ["PERMIT show .*", "PERMIT exit", "PERMIT terminal .*", "DENY_ALWAYS reload"],
            "description": "mcp-test",
        },
    ),
    (
        "ise_set_shell_profile",
        {"name": "mcp_test_priv15", "privilege": 15, "idle_timeout": 30, "description": "mcp-test"},
    ),
    (
        "ise_create_policy_set",
        {
            "kind": "device-admin",
            "name": "mcp-test-devadmin",
            "conditions": [f"DEVICE:Location equals {LAB_NDG}"],
        },
    ),
    (
        "ise_create_authz_rule",
        {
            "kind": "device-admin",
            "policy_set": "mcp-test-devadmin",
            "name": "mcp-test-netops",
            "conditions": ["IdentityGroup:Name equals User Identity Groups:mcp-test-netops"],
            "command_sets": ["mcp-test-show-only"],
            "shell_profile": "mcp_test_priv15",
        },
    ),
]

DOWN: list[tuple[str, dict[str, Any]]] = [
    ("ise_delete_policy_set", {"policy_set": "mcp-test-devadmin", "kind": "device-admin"}),
    ("ise_delete_policy_set", {"policy_set": "mcp-test-wired"}),
    ("ise_delete_object", {"kind": "command_set", "target": "mcp-test-show-only"}),
    ("ise_delete_object", {"kind": "shell_profile", "target": "mcp_test_priv15"}),
    ("ise_delete_object", {"kind": "internal_user", "target": "mcp-test-netops1"}),
    ("ise_delete_object", {"kind": "identity_group", "target": "mcp-test-netops"}),
    ("ise_delete_object", {"kind": "anc_policy", "target": "mcp-test-quarantine"}),
    ("ise_delete_object", {"kind": "authz_profile", "target": "mcp-test-permit"}),
    ("ise_delete_object", {"kind": "authz_profile", "target": "mcp-test-quarantine"}),
    ("ise_delete_object", {"kind": "dacl", "target": "mcp-test-permit-dacl"}),
    ("ise_delete_object", {"kind": "dacl", "target": "mcp-test-quarantine-dacl"}),
    ("ise_delete_nad", {"device": "mcp-test-sw1"}),
    ("ise_delete_object", {"kind": "ndg", "target": LAB_NDG}),
]


async def run(c: Client, tool: str, args: dict[str, Any]) -> None:  # type: ignore[type-arg]
    r = await c.call_tool(tool, args, raise_on_error=False)
    data = r.structured_content
    if r.is_error or not isinstance(data, dict):
        text = r.content[0].text if r.content else ""
        print(f"- {tool}: skipped ({text[:160]})")
        return
    if data.get("status") == "blocked":
        print(f"- {tool}: skipped ({'; '.join(data.get('blockers') or [])[:160]})")
        return
    r = await c.call_tool(tool, {**args, "confirm": data["confirm"]}, raise_on_error=False)
    print(f"- {tool}: {'FAILED ' + r.content[0].text[:200] if r.is_error else data.get('action')}")


async def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("up", "down"):
        sys.exit(__doc__)
    settings = live_settings(Settings, "ISE_", mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(create_server(settings), timeout=300) as c:
        for tool, args in UP if sys.argv[1] == "up" else DOWN:
            await run(c, tool, args)


if __name__ == "__main__":
    asyncio.run(main())

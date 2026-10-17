"""Live I43: import a seed of mcp-test-imp-* objects, export them, wipe them with prune, import the export
again and check the diff is empty; then wipe them for good.

Everything is named mcp-test-imp-<run> / mcp_test_imp_<run> and limited with `only`, so nothing else on
the ISE is touched. The policy sets are created disabled."""

from __future__ import annotations

import random
import secrets
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.live.conftest import Session

pytestmark = pytest.mark.live

RUN = secrets.token_hex(3)
DASH, UNDER = f"mcp-test-imp-{RUN}", f"mcp_test_imp_{RUN}"
ONLY = [f"{DASH}*", f"{UNDER}*"]
SECTIONS = [
    "policy_sets",
    "authz_profiles",
    "dacls",
    "nads",
    "ndgs",
    "identity_groups",
    "endpoint_groups",
    "custom_attributes",
    "sgts",
    "sgacls",
    "egress_matrix",
    "command_sets",
    "shell_profiles",
]
SECRETS = {f"{DASH}-nad": {"radius": f"Imp-{RUN}-radius-secret", "tacacs": f"Imp-{RUN}-tacacs"}}


def seed() -> dict[str, Any]:
    location = f"All Locations#{DASH}"
    authn_default = {
        "name": "Default",
        "rank": 1,
        "state": "enabled",
        "default": True,
        "identitySourceName": "All_User_ID_Stores",
        "ifAuthFail": "REJECT",
        "ifProcessFail": "DROP",
        "ifUserNotFound": "REJECT",
    }
    return {
        "ise_export": {"format": 1, "sections": SECTIONS},
        "ndgs": [{"name": f"Location#{location}", "description": "mcp-test", "othername": "Location"}],
        "identity_groups": [
            {
                "name": f"{DASH}-users",
                "description": "mcp-test",
                "parent": "NAC Group:NAC:IdentityGroups:User Identity Groups",
            }
        ],
        "endpoint_groups": [{"name": f"{DASH}-eps", "description": "mcp-test"}],
        "custom_attributes": [{"attributeName": f"{UNDER}_attr", "attributeType": "String"}],
        "sgts": [
            {"name": f"{UNDER}_sgt", "description": "mcp-test", "value": random.randint(60_000, 65_000)}
        ],
        "sgacls": [
            {"name": f"{UNDER}_acl", "description": "mcp-test", "aclcontent": ["permit icmp", "deny ip"]}
        ],
        "egress_matrix": [
            {
                "source": f"{UNDER}_sgt",
                "destination": f"{UNDER}_sgt",
                "defaultRule": "NONE",  # with multiple SGACLs off, ISE takes one SGACL and no catch-all
                "matrixCellStatus": "ENABLED",
                "sgacls": [f"{UNDER}_acl"],
            }
        ],
        "dacls": [
            {
                "name": f"{DASH}-dacl",
                "description": "mcp-test",
                "dacl": ["permit udp any any eq 53", "deny ip any any"],
                "daclType": "IPV4",
            }
        ],
        "authz_profiles": [
            {
                "name": f"{DASH}-profile",
                "accessType": "ACCESS_ACCEPT",
                "authzProfileType": "SWITCH",
                "daclName": f"{DASH}-dacl",
                "profileName": "Cisco",
            }
        ],
        "command_sets": [
            {
                "name": f"{DASH}-cmds",
                "description": "mcp-test",
                "permitUnmatched": False,
                "commands": {"commandList": [{"grant": "PERMIT", "command": "show", "arguments": ".*"}]},
            }
        ],
        "shell_profiles": [
            {
                "name": f"{UNDER}_shell",
                "description": "mcp-test",
                "sessionAttributes": {
                    "sessionAttributeList": [{"type": "MANDATORY", "name": "priv-lvl", "value": "1"}]
                },
            }
        ],
        "nads": [
            {
                "name": f"{DASH}-nad",
                "description": "mcp-test",
                "NetworkDeviceGroupList": [
                    "Device Type#All Device Types",
                    "IPSEC#Is IPSEC Device",
                    f"Location#{location}",
                ],
                "NetworkDeviceIPList": [{"ipaddress": "192.0.2.200", "mask": 32}],
                "authenticationSettings": {"networkProtocol": "RADIUS", "radiusSharedSecret": "********"},
                "tacacsSettings": {"sharedSecret": "********", "connectModeOptions": "OFF"},
                "profileName": "Cisco",
                "coaPort": 1700,
            }
        ],
        "policy_sets": {
            "network-access": {
                "sets": [
                    {
                        "name": DASH,
                        "rank": 0,
                        "state": "disabled",
                        "description": "mcp-test",
                        "condition": f"DEVICE:Location equals {location}",
                        "serviceName": "Default Network Access",
                        "authentication": [
                            {
                                "name": f"{DASH}-mab",
                                "rank": 0,
                                "state": "enabled",
                                "condition": "Wired_MAB",
                                "identitySourceName": "Internal Endpoints",
                                "ifAuthFail": "REJECT",
                                "ifProcessFail": "DROP",
                                "ifUserNotFound": "CONTINUE",
                            },
                            authn_default,
                        ],
                        "authorization": [
                            {
                                "name": f"{DASH}-permit",
                                "rank": 0,
                                "state": "enabled",
                                "condition": {"and": ["Wired_MAB", "Radius:NAS-Port-Type equals Ethernet"]},
                                "profile": [f"{DASH}-profile"],
                                "securityGroup": f"{UNDER}_sgt",
                            },
                            {
                                "name": "Default",
                                "rank": 1,
                                "state": "enabled",
                                "default": True,
                                "profile": ["DenyAccess"],
                            },
                        ],
                    }
                ]
            },
            "device-admin": {
                "sets": [
                    {
                        "name": f"{DASH}-da",
                        "rank": 0,
                        "state": "disabled",
                        "description": "mcp-test",
                        "condition": f"DEVICE:Location equals {location}",
                        "serviceName": "Default Device Admin",
                        "authentication": [{**authn_default, "rank": 0}],
                        "authorization": [
                            {
                                "name": f"{DASH}-netops",
                                "rank": 0,
                                "state": "enabled",
                                "condition": f"DEVICE:Location equals {location}",
                                "commands": [f"{DASH}-cmds"],
                                "profile": f"{UNDER}_shell",
                            },
                            {
                                "name": "Default",
                                "rank": 1,
                                "state": "enabled",
                                "default": True,
                                "commands": ["DenyAllCommands"],
                                "profile": "Deny All Shell Profile",
                            },
                        ],
                    }
                ]
            },
        },
    }


def empty() -> dict[str, Any]:
    """An export with every section and none of the test objects: with prune + only, a wipe."""
    doc: dict[str, Any] = {"ise_export": {"format": 1, "sections": SECTIONS}}
    for s in SECTIONS:
        doc[s] = []
    doc["policy_sets"] = {"network-access": {"sets": []}, "device-admin": {"sets": []}}
    return doc


async def _import(ise: Session, doc: dict[str, Any] | str, **kw: Any) -> dict[str, Any]:
    text = doc if isinstance(doc, str) else yaml.safe_dump(doc, sort_keys=False)
    return await ise.apply("ise_import_config", {"source": text, "only": ONLY, **kw})


async def test_import_round_trip(ise: Session, tmp_path: Path) -> None:
    baseline = str(tmp_path / "baseline.yaml")
    try:
        doc = seed()  # once: the SGT value is random
        first = await _import(ise, doc, secrets=SECRETS)
        summary = first["preview"]["preview"]["summary"]
        assert summary["create"] >= 16 and summary["update"] >= 2, first["preview"]
        assert SECRETS[f"{DASH}-nad"]["radius"] not in str(first)
        # The same import again has nothing left to do.
        again = await ise.call(
            "ise_import_config", {"source": yaml.safe_dump(doc), "only": ONLY, "secrets": SECRETS}
        )
        assert again["status"] == "blocked" and "Nothing to do" in again["blockers"][0], again

        await ise.call("ise_export_config", {"path": baseline})
        wipe = await _import(ise, empty(), prune=True)
        assert wipe["preview"]["preview"]["summary"]["delete"] >= 14, wipe["preview"]
        gone = await ise.call("ise_diff_config", {"before": baseline})
        assert gone["summary"]["removed"] >= 14 and gone["summary"]["added"] == 0, gone

        blocked = await ise.call("ise_import_config", {"source": baseline, "only": ONLY})
        assert blocked["status"] == "blocked" and any("radius secret" in b for b in blocked["blockers"]), (
            blocked
        )
        await _import(ise, baseline, secrets=SECRETS)  # a path works as the source too
        diff = await ise.call("ise_diff_config", {"before": baseline})
        assert diff["unchanged"] is True, diff["sections"]
    finally:
        await _wipe(ise)


async def _wipe(ise: Session) -> None:
    text = yaml.safe_dump(empty())
    preview = await ise.call("ise_import_config", {"source": text, "only": ONLY, "prune": True}, ok=False)
    if preview.get("status") == "preview":
        await ise.call(
            "ise_import_config", {"source": text, "only": ONLY, "prune": True, "confirm": preview["confirm"]}
        )
    after = await ise.call("ise_import_config", {"source": text, "only": ONLY, "prune": True}, ok=False)
    assert after.get("status") == "blocked" and "Nothing to do" in str(after.get("blockers")), after

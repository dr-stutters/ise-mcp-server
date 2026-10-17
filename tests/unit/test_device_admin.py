"""Device admin (I41): the command-set matcher, ise_test_command_set, ise_admin_policy_explain, TACACS+
external servers/sequences and the TACACS+ part of ise_audit_nads, against an in-memory ERS fake."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from ise_mcp._core import InvalidRequest
from ise_mcp._core.testing import call_tool
from ise_mcp.tools.device_admin import (
    command_verdict,
    line_matches,
    match_command_set,
    split_command,
    wildcard_match,
)
from tests.unit.conftest import ers_page, make_server


def cset(name: str, lines: list[str], permit_unmatched: bool = False) -> dict[str, Any]:
    out = []
    for line in lines:
        grant, cmd, *args = line.split(" ", 2)
        out.append({"grant": grant, "command": cmd, "arguments": args[0] if args else ""})
    return {"name": name, "permitUnmatched": permit_unmatched, "commands": {"commandList": out}}


# --- pure matcher -------------------------------------------------------------------------------


def test_split_command_drops_cr() -> None:
    assert split_command("show running-config <cr>") == ("show", ["running-config"])
    assert split_command("  reload ") == ("reload", [])
    with pytest.raises(InvalidRequest):
        split_command("   ")


def test_wildcard_command_names() -> None:
    # The admin guide's examples: 'show' matches Sh??, S*, S*w, not Sho?? or S*p.
    for pat in ("Sh??", "S*", "S*w", "show", "SHOW"):
        assert wildcard_match(pat, "show"), pat
    for pat in ("Sho??", "S*p", "sho"):
        assert not wildcard_match(pat, "show"), pat
    assert wildcard_match("con*e", "configure") and not wildcard_match("c.nfigure", "configure")


def test_arguments_positional_anchored_case_insensitive() -> None:
    e = {"command": "show", "arguments": "start"}
    assert line_matches(e, "show", ["startup-config"]) is False  # anchored
    assert line_matches({"command": "show", "arguments": "start.*"}, "show", ["startup-config"]) is True
    assert line_matches({"command": "write", "arguments": "TERMINAL"}, "write", ["terminal"]) is True
    # a regex can't span arguments: compared with 'running-config' only
    spanning = {"command": "show", "arguments": "running-config.*1/0/1"}
    assert line_matches(spanning, "show", ["running-config", "interface", "Gi1/0/1"]) is False
    # extra request arguments are ignored; no arguments field matches any arguments
    assert line_matches({"command": "show", "arguments": "running-config"}, "show", ["running-config", "all"])
    assert line_matches({"command": "reload", "arguments": ""}, "reload", ["cancel"]) is True
    # a pattern position the request doesn't have is compared with ''
    assert line_matches({"command": "show", "arguments": ".*"}, "show", []) is True
    assert line_matches({"command": "show", "arguments": "version"}, "show", []) is False
    assert line_matches({"command": "show", "arguments": "(["}, "show", ["x"]) is None  # invalid regex


def test_set_first_match_and_deny_always_wins() -> None:
    probe = cset("probe", ["PERMIT more .*", "DENY_ALWAYS more system:running-config", "DENY show .*"])
    r = match_command_set(probe, "more system:running-config")
    assert r["result"] == "deny_always" and r["matched_line"] == 2 and "line 1" in r["note"]
    assert match_command_set(probe, "more nvram:startup-config")["result"] == "permit"
    assert match_command_set(probe, "show clock") == {
        "command_set": "probe",
        "result": "deny",
        "matched_line": 3,
        "line": "DENY show .*",
    }
    assert match_command_set(probe, "reload")["result"] == "unmatched"
    assert match_command_set(cset("open", [], permit_unmatched=True), "reload")["result"] == "permit"


def test_verdict_across_sets() -> None:
    netops = cset("netops", ["PERMIT show .*", "PERMIT configure terminal", "DENY_ALWAYS reload"])
    helpdesk = cset("helpdesk", ["PERMIT show .*"])
    permit_all = cset("PermitAll", [], permit_unmatched=True)
    assert command_verdict([netops], "configure terminal")["verdict"] == "permit"
    assert command_verdict([helpdesk], "configure terminal")["verdict"] == "deny"
    # DENY_ALWAYS in one set beats a permit-unmatched set
    v = command_verdict([permit_all, netops], "reload")
    assert v["verdict"] == "deny" and "DENY_ALWAYS in netops line 3" in v["because"]
    # a plain DENY loses to another set's permit
    deny_show = cset("deny-show", ["DENY show .*"])
    assert command_verdict([deny_show, helpdesk], "show version")["verdict"] == "permit"
    assert command_verdict([deny_show], "show version")["verdict"] == "deny"
    assert "no command set" in command_verdict([], "show version")["because"]


# --- ERS / OpenAPI fake -------------------------------------------------------------------------

WRAPPERS = {
    "networkdevice": "NetworkDevice",
    "internaluser": "InternalUser",
    "identitygroup": "IdentityGroup",
    "tacacscommandsets": "TacacsCommandSets",
    "tacacsprofile": "TacacsProfile",
    "tacacsexternalservers": "TacacsExternalServer",
    "tacacsserversequence": "TacacsServerSequence",
}


def fake_ers(mock: respx.MockRouter, store: dict[str, list[dict[str, Any]]]) -> None:
    def listing(request: httpx.Request, res: str) -> httpx.Response:
        items = store.get(res, [])
        filt = request.url.params.get("filter", "")
        if filt.startswith("name.EQ."):
            items = [i for i in items if i["name"] == filt.removeprefix("name.EQ.")]
        elif filt.startswith("ipaddress.EQ."):
            ip = filt.removeprefix("ipaddress.EQ.")
            items = [
                i for i in items if any(e.get("ipaddress") == ip for e in i.get("NetworkDeviceIPList") or [])
            ]
        elif filt:
            items = []
        return httpx.Response(200, json=ers_page([{"id": i["id"], "name": i["name"]} for i in items]))

    def get(request: httpx.Request, res: str, oid: str) -> httpx.Response:
        for i in store.get(res, []):
            if i["id"] == oid:
                return httpx.Response(200, json={WRAPPERS[res]: i})
        return httpx.Response(404, json={})

    mock.get(path__regex=r"^/ers/config/(?P<res>[a-z]+)$").mock(side_effect=listing)
    mock.get(path__regex=r"^/ers/config/(?P<res>[a-z]+)/(?P<oid>[^/]+)$").mock(side_effect=get)


def attr(dn: str, an: str, op: str, val: str) -> dict[str, Any]:
    return {
        "conditionType": "ConditionAttributes",
        "isNegate": False,
        "dictionaryName": dn,
        "attributeName": an,
        "operator": op,
        "attributeValue": val,
    }


def entry(rid: str, name: str, rank: int, cond: Any, **result: Any) -> dict[str, Any]:
    rule = {"id": rid, "name": name, "rank": rank, "state": "enabled", "default": cond is None}
    return {"rule": {**rule, "condition": cond, "hitCounts": 7}, **result}


NAD = {
    "id": "n1",
    "name": "access-sw1",
    "NetworkDeviceIPList": [{"ipaddress": "192.0.2.10", "mask": 32}],
    "NetworkDeviceGroupList": ["Location#All Locations#lab", "Device Type#All Device Types"],
    "tacacsSettings": {"sharedSecret": "tacacs-secret-0123456789", "connectModeOptions": "ON_LEGACY"},
    "authenticationSettings": {"radiusSharedSecret": "radius-secret-0123456789"},
}


def store() -> dict[str, list[dict[str, Any]]]:
    return {
        "networkdevice": [NAD],
        "identitygroup": [
            {"id": "g1", "name": "NetOps", "parent": "NAC Group:NAC:IdentityGroups:User Identity Groups"},
            {"id": "g2", "name": "Helpdesk", "parent": "NAC Group:NAC:IdentityGroups:User Identity Groups"},
        ],
        "internaluser": [
            {"id": "u1", "name": "alice", "enabled": True, "identityGroups": "g1"},
            {"id": "u2", "name": "bob", "enabled": True, "identityGroups": "g2"},
        ],
        "tacacscommandsets": [
            {
                "id": "c1",
                **cset("netops-cmds", ["PERMIT show .*", "PERMIT configure terminal", "DENY_ALWAYS reload"]),
            },
            {"id": "c2", **cset("helpdesk-cmds", ["PERMIT show .*"])},
        ],
        "tacacsprofile": [
            {
                "id": "p1",
                "name": "priv15",
                "sessionAttributes": {
                    "sessionAttributeList": [{"type": "MANDATORY", "name": "priv-lvl", "value": "15"}]
                },
            }
        ],
    }


def mock_device_admin_policy(mock: respx.MockRouter) -> None:
    base = "/api/v1/policy/device-admin"
    sets = [
        {
            "id": "s-other",
            "name": "other-site",
            "rank": 0,
            "state": "enabled",
            "default": False,
            "condition": attr("DEVICE", "Location", "equals", "All Locations#elsewhere"),
        },
        {
            "id": "s-lab",
            "name": "lab-admin",
            "rank": 1,
            "state": "enabled",
            "default": False,
            "condition": attr("Network Access", "NetworkDeviceName", "equals", "access-sw1"),
        },
        {"id": "s-def", "name": "Default", "rank": 2, "state": "enabled", "default": True, "condition": None},
    ]
    mock.get(f"{base}/policy-set").respond(json={"response": sets})
    mock.get(f"{base}/condition").respond(json={"response": []})
    mock.get(f"{base}/policy-set/global-exception").respond(json={"response": []})
    mock.get(f"{base}/policy-set/s-lab/exception").respond(json={"response": []})
    mock.get(f"{base}/policy-set/s-lab/authentication").respond(
        json={"response": [entry("a1", "Default", 0, None, identitySourceName="Internal Users")]}
    )
    mock.get(f"{base}/policy-set/s-lab/authorization").respond(
        json={
            "response": [
                entry(
                    "r1",
                    "netops",
                    0,
                    attr("IdentityGroup", "Name", "equals", "User Identity Groups:NetOps"),
                    commands=["netops-cmds"],
                    profile="priv15",
                ),
                entry(
                    "r2",
                    "helpdesk",
                    1,
                    attr("IdentityGroup", "Name", "equals", "User Identity Groups:Helpdesk"),
                    commands=["helpdesk-cmds"],
                    profile="priv15",
                ),
                entry(
                    "r3", "Default", 2, None, commands=["DenyAllCommands"], profile="Deny All Shell Profile"
                ),
            ]
        }
    )


def as_dict(out: Any) -> dict[str, Any]:
    return out if isinstance(out, dict) else json.loads(str(out))


async def test_admin_explain_alice_and_bob(mock: respx.MockRouter) -> None:
    fake_ers(mock, store())
    mock_device_admin_policy(mock)
    server = make_server()
    cmds = ["show running-config", "configure terminal", "reload"]
    alice = as_dict(
        await call_tool(
            server, "ise_admin_policy_explain", {"user": "alice", "nad": "192.0.2.10", "command": cmds}
        )
    )
    assert alice["policy_set"] == "lab-admin" and alice["identity_source"] == "Internal Users"
    assert [s["result"] for s in alice["set_selection"]] == ["no-match", "match"]
    assert "netops" in alice["verdict"] and alice["shell_profile"]["attributes"] == {"priv-lvl": "15"}
    assert alice["authorization"][0]["hits"] == 7
    assert [c["verdict"] for c in alice["commands"]] == ["permit", "permit", "deny"]
    assert alice["assumed_attributes"]["IdentityGroup:Name"] == ["User Identity Groups:NetOps"]
    bob = as_dict(
        await call_tool(
            server, "ise_admin_policy_explain", {"user": "bob", "nad": "access-sw1", "command": cmds}
        )
    )
    assert "helpdesk" in bob["verdict"]
    assert [c["verdict"] for c in bob["commands"]] == ["permit", "deny", "deny"]


async def test_admin_explain_unknown_user_falls_to_default(mock: respx.MockRouter) -> None:
    fake_ers(mock, store())
    mock_device_admin_policy(mock)
    out = as_dict(
        await call_tool(
            make_server(),
            "ise_admin_policy_explain",
            {"user": "mallory", "nad": "access-sw1", "command": ["show clock"]},
        )
    )
    assert "Deny All Shell Profile" in out["verdict"] and "denied" in out["verdict"]
    assert any("not an internal user" in n for n in out["notes"])
    assert any("UNCERTAIN" in n for n in out["notes"])  # the group rules are unknown without groups
    assert out["commands"][0]["verdict"] == "deny"  # DenyAllCommands isn't in the store -> no sets
    # Passing the group makes it certain
    out = as_dict(
        await call_tool(
            make_server(),
            "ise_admin_policy_explain",
            {
                "user": "mallory",
                "nad": "access-sw1",
                "attributes": {"IdentityGroup:Name": ["User Identity Groups:Helpdesk"]},
            },
        )
    )
    assert "helpdesk" in out["verdict"]


async def test_command_set_test_by_rule_and_draft(mock: respx.MockRouter) -> None:
    fake_ers(mock, store())
    mock_device_admin_policy(mock)
    server = make_server()
    out = as_dict(
        await call_tool(
            server,
            "ise_test_command_set",
            {
                "policy_set": "lab-admin",
                "rule": "helpdesk",
                "command": ["show version", "configure terminal"],
            },
        )
    )
    assert out["from_rule"]["rule"] == "helpdesk" and out["command_sets"] == ["helpdesk-cmds"]
    assert [r["verdict"] for r in out["results"]] == ["permit", "deny"]
    draft = as_dict(
        await call_tool(
            server,
            "ise_test_command_set",
            {
                "command": ["reload", "show clock"],
                "command_sets": ["helpdesk-cmds"],
                "draft": ["DENY_ALWAYS reload"],
            },
        )
    )
    assert draft["command_sets"] == ["helpdesk-cmds", "(draft)"]
    reload = draft["results"][0]
    assert reload["verdict"] == "deny" and "(draft)" in reload["because"]
    async with Client(server) as c:
        r = await c.call_tool(
            "ise_test_command_set", {"command": ["x"], "command_sets": ["nope"]}, raise_on_error=False
        )
    assert r.is_error and "No command set named nope" in str(r.content)


async def test_tacacs_servers_and_sequences(mock: respx.MockRouter) -> None:
    s = store()
    s["tacacsexternalservers"] = [
        {
            "id": "t1",
            "name": "legacy_acs",
            "hostIP": "192.0.2.50",
            "connectionPort": 49,
            "timeout": 20,
            "singleConnect": False,
            "sharedSecret": "very-secret-value",
        },
    ]
    s["tacacsserversequence"] = [
        {
            "id": "q1",
            "name": "proxy",
            "serverList": "legacy_acs,gone",
            "localAccounting": False,
            "remoteAccounting": True,
            "prefixStrip": False,
            "suffixStrip": True,
            "suffixDelimiter": "@",
        },
    ]
    fake_ers(mock, s)
    out = as_dict(await call_tool(make_server(), "ise_get_tacacs_servers", {}))
    assert out["servers"][0]["shared_secret_set"] is True and "very-secret" not in json.dumps(out)
    seq = out["sequences"][0]
    assert seq["servers"] == ["legacy_acs", "gone"] and seq["missing_servers"] == ["gone"]
    assert seq["suffix_strip"] == "@"
    writes = make_server(mcp_enable_writes=True)
    new = as_dict(
        await call_tool(
            writes,
            "ise_set_tacacs_server",
            {"name": "new_acs", "host": "192.0.2.51", "shared_secret": "s3cret-abc"},
        )
    )
    assert new["status"] == "preview" and "s3cret" not in json.dumps(new)
    assert new["preview"]["shared_secret_set"] is True and new["preview"]["port"] == 49
    upd = as_dict(
        await call_tool(writes, "ise_set_tacacs_server", {"name": "legacy_acs", "single_connect": True})
    )
    assert upd["preview"]["changes"]["singleConnect"] == {"from": False, "to": True}
    blocked = as_dict(await call_tool(writes, "ise_set_tacacs_server", {"name": "half", "host": "192.0.2.9"}))
    assert blocked["status"] == "blocked"
    seq_new = as_dict(
        await call_tool(writes, "ise_set_tacacs_server_sequence", {"name": "p2", "servers": ["LEGACY_ACS"]})
    )
    assert seq_new["preview"]["servers"] == ["legacy_acs"]


async def test_audit_nads_tacacs_section(mock: respx.MockRouter) -> None:
    s = store()
    twin = {
        **NAD,
        "id": "n2",
        "name": "access-sw2",
        "NetworkDeviceIPList": [{"ipaddress": "192.0.2.11", "mask": 32}],
        "tacacsSettings": {"sharedSecret": "tacacs-secret-0123456789"},
        "NetworkDeviceGroupList": ["Location#All Locations#elsewhere-not", "Device Type#All Device Types"],
    }
    radius_only = {
        "id": "n3",
        "name": "radius-only",
        "NetworkDeviceIPList": [{"ipaddress": "192.0.2.12", "mask": 32}],
        "authenticationSettings": {"radiusSharedSecret": "radius-secret-abcdefghij"},
        "NetworkDeviceGroupList": ["Location#All Locations#lab"],
    }
    s["networkdevice"] = [NAD, twin, radius_only]
    fake_ers(mock, s)
    mock_device_admin_policy(mock)
    mock.get("/api/v1/deployment/node", name="nodes").respond(
        json={"response": [{"hostname": "ise1", "services": ["Session"]}]}
    )
    out = as_dict(await call_tool(make_server(), "ise_audit_nads", {}))
    rows = {r["name"]: r for r in out["results"]}
    assert rows["access-sw1"]["tacacs"] == {
        "shared_secret_set": True,
        "single_connect": "legacy",
        "device_admin_policy_set": "lab-admin",
    }
    assert rows["access-sw2"]["tacacs"]["device_admin_policy_set"] == "Default"
    assert any("only the default device-admin policy set" in f for f in rows["access-sw2"]["findings"])
    assert any("TACACS+ secret reused" in f for f in rows["access-sw1"]["findings"])
    assert "tacacs" not in rows["radius-only"]
    summary = out["tacacs"]
    assert summary["devices"] == 2 and summary["single_connect"] == 1
    assert summary["no_device_admin_policy_set"] == ["access-sw2"]
    assert "DeviceAdmin" in summary["findings"][0]
    assert "tacacs-secret" not in json.dumps(out)


async def test_delete_tacacs_server_blocked_while_in_sequence(mock: respx.MockRouter) -> None:
    s = store()
    s["tacacsexternalservers"] = [
        {"id": "t1", "name": "legacy_acs", "hostIP": "192.0.2.50", "sharedSecret": "x"}
    ]
    s["tacacsserversequence"] = [{"id": "q1", "name": "proxy", "serverList": "Legacy_ACS"}]
    fake_ers(mock, s)
    out = as_dict(
        await call_tool(
            make_server(mcp_enable_writes=True),
            "ise_delete_object",
            {"kind": "tacacs_server", "target": "legacy_acs"},
        )
    )
    assert out["status"] == "blocked" and "proxy" in out["blockers"][0]

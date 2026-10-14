"""Live Phase 2 tests: policy editing and device admin against the lab ISE, plus (when the CML
'ise-access' lab is up and scripts/lab_policy.py up has run) the real-switch flow: session, CoA and ANC
quarantine through the switch.

The switch flow needs ISE_LIVE_SWITCH_MAC=<client MAC> (the CML client's MAC changes when it is wiped).
Everything the ISE-only tests create is disabled or unused while it exists and deleted at the end."""

from __future__ import annotations

import asyncio
import os
import secrets

import pytest

from tests.live.conftest import Session

pytestmark = pytest.mark.live

RUN = secrets.token_hex(3)


async def test_policy_set_lifecycle(ise: Session) -> None:
    name = f"mcp-test-ps-{RUN}"
    typo = await ise.call(
        "ise_create_policy_set", {"name": name, "conditions": ["Radius:NAS-Port-Typ equals Ethernet"]}
    )
    assert typo["status"] == "blocked" and "Did you mean Radius:NAS-Port-Type" in typo["blockers"][0]
    bad_value = await ise.call(
        "ise_create_policy_set", {"name": name, "conditions": ["Radius:NAS-Port-Type equals Wifi"]}
    )
    assert bad_value["status"] == "blocked" and "allowed:" in bad_value["blockers"][0]
    try:
        await ise.apply(
            "ise_create_policy_set",
            {
                "name": name,
                "conditions": ["DEVICE:Location equals Location#All Locations", "Wired_MAB"],
                "state": "disabled",
                "description": "mcp-test",
            },
        )
        await ise.apply(
            "ise_create_authn_rule",
            {
                "policy_set": name,
                "name": "mcp-test-mab",
                "conditions": ["Wired_MAB"],
                "identity_source": "Internal Endpoints",
                "if_user_not_found": "CONTINUE",
            },
        )
        await ise.apply(
            "ise_create_authz_rule",
            {
                "policy_set": name,
                "name": "mcp-test-permit",
                "conditions": ["Radius:NAS-Port-Type equals Ethernet"],
                "profiles": ["PermitAccess"],
                "sgt": "Employees",
            },
        )
        upd = await ise.apply(
            "ise_update_policy_rule",
            {
                "policy_set": name,
                "rule": "mcp-test-permit",
                "state": "monitor",
                "profiles": ["DenyAccess"],
                "sgt": "",
            },
        )
        assert upd["applied"]["result"]["state"] == "monitor"
        await ise.apply("ise_update_policy_set", {"policy_set": name, "description": "mcp-test updated"})
        got = await ise.call("ise_get_policy_set", {"policy_set": name})
        assert got["policy_set"]["state"] == "disabled"
        assert got["policy_set"]["condition"].startswith(
            "(DEVICE:Location equals All Locations AND Wired_MAB"
        )
        rule = next(r for r in got["authorization"] if r["name"] == "mcp-test-permit")
        assert (
            rule["profile"] == ["DenyAccess"] and "securityGroup" not in rule and rule["state"] == "monitor"
        )
        authn = next(r for r in got["authentication"] if r["name"] == "mcp-test-mab")
        assert authn["identitySourceName"] == "Internal Endpoints" and authn["ifUserNotFound"] == "CONTINUE"
        default = await ise.call("ise_update_policy_rule", {"policy_set": name, "rule": "Default", "rank": 0})
        assert default["status"] == "blocked"
    finally:
        await ise.apply("ise_delete_policy_set", {"policy_set": name})


async def test_device_admin_lifecycle(ise: Session) -> None:
    cs, sp, ps = f"mcp-test-cs-{RUN}", f"mcp_test_sp_{RUN}", f"mcp-test-da-{RUN}"
    try:
        await ise.apply(
            "ise_set_command_set", {"name": cs, "commands": ["PERMIT show .*", "DENY_ALWAYS reload"]}
        )
        replaced = await ise.apply("ise_set_command_set", {"name": cs, "commands": ["PERMIT show version"]})
        assert "commands" in str(replaced["preview"]["preview"]["changes"])
        sets = await ise.call("ise_list_command_sets", {"name": cs})
        assert sets["results"][0]["commands"] == ["PERMIT show version"]
        await ise.apply("ise_set_shell_profile", {"name": sp, "privilege": 1})
        await ise.apply("ise_set_shell_profile", {"name": sp, "privilege": 15, "idle_timeout": 10})
        profiles = await ise.call("ise_list_shell_profiles", {"name": sp})
        assert profiles["results"][0]["attributes"] == {"priv-lvl": "15", "idletime": "10"}
        await ise.apply(
            "ise_create_policy_set",
            {
                "kind": "device-admin",
                "name": ps,
                "conditions": ["DEVICE:Location equals All Locations"],
                "state": "disabled",
            },
        )
        await ise.apply(
            "ise_create_authz_rule",
            {
                "kind": "device-admin",
                "policy_set": ps,
                "name": "mcp-test-ro",
                "conditions": ["IdentityGroup:Name equals User Identity Groups:Employee"],
                "command_sets": [cs],
                "shell_profile": sp,
            },
        )
        used = await ise.call("ise_delete_object", {"kind": "command_set", "target": cs})
        assert used["status"] == "blocked" and "device-admin rule" in used["blockers"][0]
        got = await ise.call("ise_get_policy_set", {"policy_set": ps, "kind": "device-admin"})
        rule = next(r for r in got["authorization"] if r["name"] == "mcp-test-ro")
        assert rule["commands"] == [cs] and rule["profile"] == sp
    finally:
        pending = await ise.call(
            "ise_delete_policy_set", {"policy_set": ps, "kind": "device-admin"}, ok=False
        )
        if isinstance(pending, dict) and pending.get("confirm"):
            await ise.apply("ise_delete_policy_set", {"policy_set": ps, "kind": "device-admin"})
        for kind, target in (("command_set", cs), ("shell_profile", sp)):
            prev = await ise.call("ise_delete_object", {"kind": kind, "target": target}, ok=False)
            if isinstance(prev, dict) and prev.get("confirm"):
                await ise.apply("ise_delete_object", {"kind": kind, "target": target})


async def test_dictionary_attributes(ise: Session) -> None:
    rows = await ise.call("ise_list_dictionary_attributes", {"dictionary": "Session", "name": "ANCPolicy"})
    assert rows["results"][0]["attribute"] == "Session:ANCPolicy"
    da = await ise.call("ise_list_dictionary_attributes", {"kind": "device-admin", "dictionary": "TACACS"})
    assert da["results"]


SWITCH_MAC = os.environ.get("ISE_LIVE_SWITCH_MAC")


async def wait_for_profile(ise: Session, mac: str, profile: str, wait_s: float = 120) -> dict[str, object]:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait_s
    while True:
        hist = await ise.call("ise_get_auth_history", {"mac": mac, "minutes": 60})
        latest = next((a for a in hist.get("attempts", []) if a.get("authz_profiles")), None)
        if latest and latest["authz_profiles"] == profile:
            return latest
        assert loop.time() < deadline, f"{mac} never got {profile}: {hist.get('attempts', [])[:2]}"
        await asyncio.sleep(5)


SKIP_REASON = "set ISE_LIVE_SWITCH_MAC (CML ise-access lab up, lab_policy.py up, client sending traffic)"


@pytest.mark.skipif(not SWITCH_MAC, reason=SKIP_REASON)
async def test_switch_session_coa_and_anc(ise: Session) -> None:
    mac = str(SWITCH_MAC)
    found = await ise.call("ise_find_session", {"mac": mac})
    assert found["found"], "the client has no session: make it send traffic (ping 10.10.10.1)"
    assert found["session"]["nas_ip_address"] == "198.18.128.154"
    # The latest MnT session record can be a CoA/accounting event without policy names, so check the
    # authorization result through the auth history instead.
    await wait_for_profile(ise, mac, "mcp-test-permit", wait_s=10)
    coa = await ise.apply("ise_coa_reauth", {"mac": mac, "reauth_type": "rerun"})
    assert coa["applied"]["result"]["coa_acknowledged"] is True
    anc = await ise.apply("ise_apply_anc", {"mac": mac, "policy": "mcp-test-quarantine"})
    assert anc["preview"]["preview"]["authz_rules_matching_it"] == [
        "mcp-test-wired / mcp-test-anc-quarantine"
    ]
    try:
        latest = await wait_for_profile(ise, mac, "mcp-test-quarantine")
        assert latest["sgt"] == "Quarantined_Systems"
        e360 = await ise.call("ise_endpoint_360", {"mac": mac})
        assert e360["anc_policy"] == "mcp-test-quarantine"
    finally:
        await ise.apply("ise_clear_anc", {"mac": mac})

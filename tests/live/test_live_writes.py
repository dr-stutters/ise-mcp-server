"""Live write tests: create, verify, update and delete mcp-test-* objects through the write tools.
Everything created here is removed again (the finally blocks use the delete tools)."""

from __future__ import annotations

import json
import secrets
from typing import Any

import pytest
from fastmcp import Client

from tests.live.conftest import live_server

pytestmark = pytest.mark.live

RUN = secrets.token_hex(3)


class Session:
    def __init__(self, client: Client) -> None:  # type: ignore[type-arg]
        self.client = client

    async def call(self, name: str, args: dict[str, Any], *, ok: bool = True) -> Any:
        r = await self.client.call_tool(name, args, raise_on_error=False)
        text = "\n".join(getattr(x, "text", "") for x in r.content)
        if ok:
            assert not r.is_error, f"{name} failed: {text}"
        if r.is_error:
            return {"error": text}
        if r.structured_content is not None:
            return r.structured_content
        try:
            return json.loads(text)
        except ValueError:
            return text

    async def apply(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        preview = await self.call(name, args)
        assert preview["status"] == "preview", preview
        done = await self.call(name, {**args, "confirm": preview["confirm"]})
        assert done["status"] == "applied", done
        return {"preview": preview, "applied": done}


@pytest.fixture
async def ise() -> Any:
    server = live_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(server) as c:
        yield Session(c)


async def test_nad_lifecycle_and_masking(ise: Session) -> None:
    name = f"mcp-test-nad-{RUN}"
    secret, tacacs, community = f"Rad-{RUN}-secret-xyz", f"Tac-{RUN}-secret", f"comm{RUN}"
    args = {
        "name": name,
        "ips": ["192.0.2.0/28"],
        "radius_secret": secret,
        "tacacs_secret": tacacs,
        "snmp_ro_community": community,
        "description": "mcp-test",
    }
    try:
        res = await ise.apply("ise_create_nad", args)
        assert secret not in json.dumps(res) and community not in json.dumps(res)
        got = await ise.call("ise_get_nad", {"device": name})
        text = json.dumps(got)
        for s in (secret, tacacs, community):
            assert s not in text
        assert got["NetworkDeviceIPList"] == [{"ipaddress": "192.0.2.0", "mask": 28}]
        again = await ise.call("ise_create_nad", args)
        assert again["status"] == "blocked"
        by_ip = await ise.call("ise_get_nad", {"device": "192.0.2.5"})
        assert by_ip["name"] == name
        upd = await ise.apply(
            "ise_update_nad",
            {"device": name, "radius_secret": "New-" + secret, "description": "mcp-test updated"},
        )
        changes = upd["preview"]["preview"]["changes"]
        assert changes["authenticationSettings.radiusSharedSecret"] == {"from": "********", "to": "********"}
        assert secret not in json.dumps(upd)
        assert (await ise.call("ise_get_nad", {"device": name}))["description"] == "mcp-test updated"
    finally:
        nad = await ise.call("ise_get_nad", {"device": name}, ok=False)
        if "id" in nad:
            await ise.apply(
                "ise_api_call",
                {"method": "DELETE", "path": f"/ers/config/networkdevice/{nad['id']}", "source": "ers"},
            )
    gone = await ise.call("ise_get_nad", {"device": name}, ok=False)
    assert "error" in gone


async def test_identity_lifecycle(ise: Session) -> None:
    group, user = f"mcp-test-grp-{RUN}", f"mcp-test-user-{RUN}"
    password = f"Mcp-{RUN}-Passw0rd!"
    try:
        await ise.apply("ise_create_group", {"kind": "identity", "name": group, "description": "mcp-test"})
        res = await ise.apply(
            "ise_create_internal_user", {"name": user, "password": password, "groups": [group]}
        )
        assert password not in json.dumps(res)
        got = await ise.call("ise_get_internal_user", {"user": user})
        assert got["groups"] == [group] and got["enabled"] is True
        await ise.apply("ise_update_internal_user", {"user": user, "enabled": False})
        assert (await ise.call("ise_get_internal_user", {"user": user}))["enabled"] is False
        upd = await ise.apply("ise_update_internal_user", {"user": user, "password": password + "2"})
        assert password not in json.dumps(upd)
    finally:
        await ise.apply("ise_delete_object", {"kind": "internal_user", "target": user})
        await ise.apply("ise_delete_object", {"kind": "identity_group", "target": group})


async def test_endpoint_lifecycle(ise: Session) -> None:
    group, mac = f"mcp-test-epg-{RUN}", "02:00:5E:10:" + RUN[:2].upper() + ":" + RUN[2:4].upper()
    try:
        await ise.apply("ise_create_group", {"kind": "endpoint", "name": group})
        await ise.apply("ise_set_endpoint", {"mac": mac, "group": group, "description": "mcp-test"})
        out = await ise.call("ise_endpoint_360", {"mac": mac})
        assert out["endpoint"]["group"] == group
        upd = await ise.apply("ise_set_endpoint", {"mac": mac, "group": group, "description": "mcp-test 2"})
        assert upd["preview"]["action"].startswith("Update endpoint")
    finally:
        await ise.apply("ise_delete_object", {"kind": "endpoint", "target": mac})
        await ise.apply("ise_delete_object", {"kind": "endpoint_group", "target": group})


async def test_authz_results_lifecycle(ise: Session) -> None:
    dacl, profile = f"mcp-test-dacl-{RUN}", f"mcp-test-profile-{RUN}"
    try:
        await ise.apply(
            "ise_set_dacl", {"name": dacl, "aces": ["permit udp any any eq 53", "deny ip any any"]}
        )
        await ise.apply("ise_set_dacl", {"name": dacl, "aces": ["permit ip any any"]})
        assert (await ise.call("ise_get_dacl", {"dacl": dacl}))["aces"] == ["permit ip any any"]
        await ise.apply(
            "ise_create_authz_profile", {"name": profile, "vlan": "100", "dacl": dacl, "reauth_seconds": 3600}
        )
        await ise.apply("ise_update_authz_profile", {"profile": profile, "vlan": "200"})
        got = await ise.call("ise_get_authz_profile", {"profile": profile})
        assert got["vlan"]["nameID"] == "200" and got["daclName"] == dacl
        blocked = await ise.call("ise_delete_object", {"kind": "dacl", "target": dacl})
        assert blocked["status"] == "blocked"
    finally:
        await ise.apply("ise_delete_object", {"kind": "authz_profile", "target": profile})
        await ise.apply("ise_delete_object", {"kind": "dacl", "target": dacl})


async def test_trustsec_lifecycle(ise: Session) -> None:
    sgt_a, sgt_b = f"mcp_test_a_{RUN}", f"mcp_test_b_{RUN}"
    try:
        await ise.apply("ise_set_sgt", {"name": sgt_a, "description": "mcp-test"})
        await ise.apply("ise_set_sgt", {"name": sgt_b})
        await ise.apply(
            "ise_set_egress_policy",
            {"source_sgt": sgt_a, "destination_sgt": sgt_b, "sgacls": ["Deny IP"], "default_rule": "NONE"},
        )
        matrix = await ise.call("ise_get_egress_matrix", {"source": sgt_a, "response_format": "json"})
        assert matrix["results"][0]["sgacls"] == ["Deny IP"]
        upd = await ise.apply(
            "ise_set_egress_policy",
            {"source_sgt": sgt_a, "destination_sgt": sgt_b, "sgacls": ["Permit IP"], "default_rule": "NONE"},
        )
        assert upd["preview"]["action"].startswith("Update egress cell")
    finally:
        matrix = await ise.call("ise_get_egress_matrix", {"source": sgt_a, "response_format": "json"})
        for cell in matrix.get("results", []):
            await ise.apply(
                "ise_api_call",
                {"method": "DELETE", "path": f"/ers/config/egressmatrixcell/{cell['id']}", "source": "ers"},
            )
        await ise.apply("ise_delete_object", {"kind": "sgt", "target": sgt_a})
        await ise.apply("ise_delete_object", {"kind": "sgt", "target": sgt_b})


async def test_authz_rule_lifecycle(ise: Session) -> None:
    rule = f"mcp-test-rule-{RUN}"
    try:
        res = await ise.apply(
            "ise_create_authz_rule",
            {
                "policy_set": "Default",
                "name": rule,
                "rank": 0,
                "enabled": False,
                "profiles": ["DenyAccess"],
                "conditions": [
                    "Wired_MAB",
                    "IdentityGroup:Name equals Endpoint Identity Groups:Blocked List",
                ],
            },
        )
        assert res["preview"]["preview"]["inserted_before"]
        ps = await ise.call("ise_get_policy_set", {"policy_set": "Default"})
        mine = [r for r in ps["authorization"] if r["name"] == rule]
        assert mine and mine[0]["state"] == "disabled"
        assert "Wired_MAB AND IdentityGroup:Name equals" in mine[0]["condition"]
    finally:
        ps = await ise.call("ise_get_policy_set", {"policy_set": "Default"})
        for r in ps["authorization"]:
            if r["name"] == rule:
                ps_id = ps["policy_set"]["id"]
                path = f"/api/v1/policy/network-access/policy-set/{ps_id}/authorization/{r['id']}"
                await ise.apply("ise_api_call", {"method": "DELETE", "path": path})

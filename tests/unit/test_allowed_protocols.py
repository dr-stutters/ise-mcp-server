"""I71: ise_set_allowed_protocols presets, update diff and the weak-protocol refusal."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import pytest
import respx
from fastmcp import Client

from ise_mcp.tools.allowed_protocols import PRESETS, PROTOCOLS, preset_body, protocol_table
from tests.unit.conftest import BASE, fixture_text, make_server

NA = "/api/v1/policy/network-access"
DA = "/api/v1/policy/device-admin"
AP = "/ers/config/allowedprotocols"
DEFAULT = json.loads(fixture_text("ers_allowedprotocols_default.json"))
DEFAULT_ID = DEFAULT["AllowedProtocols"]["id"]
# Every top-level field the ERS data model marks required (ise_get_definition ers.allowedprotocols).
REQUIRED = {
    "allowChap", "allowEapFast", "allowEapMd5", "allowEapTls", "allowEapTtls", "allowLeap", "allowMsChapV1",
    "allowMsChapV2", "allowPapAscii", "allowPeap", "allowPreferredEapProtocol", "allowTeap",
    "allowWeakCiphersForEap", "eapTlsLBit", "fiveG", "name", "processHostLookup", "requireMessageAuth",
}  # fmt: skip


def by_name(mock: respx.MockRouter, name: str, obj: dict[str, Any] | None) -> None:
    route = mock.get(f"{AP}/name/{quote(name, safe='')}")
    if obj is None:
        route.respond(404, json={"ERSResponse": {"messages": [{"title": "Resource not found"}]}})
    else:
        route.respond(json={"AllowedProtocols": obj})


def policy_sets(
    mock: respx.MockRouter, na: list[dict[str, Any]], da: list[dict[str, Any]] | None = None
) -> None:
    mock.get(f"{NA}/policy-set").respond(json={"response": na})
    mock.get(f"{DA}/policy-set").respond(json={"response": da or []})


async def call(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        preview = (await c.call_tool(name, args)).structured_content
        if preview.get("status") != "preview":
            return preview, None
        applied = (await c.call_tool(name, {**args, "confirm": preview["confirm"]})).structured_content
        return preview, applied


async def error(args: dict[str, Any]) -> str:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool("ise_set_allowed_protocols", args, raise_on_error=False)
    assert r.is_error
    return str(r.content[0].text)


@pytest.mark.parametrize(
    ("preset", "on"),
    [
        ("eap-tls-only", {"eap-tls"}),
        ("peap-mschapv2", {"peap"}),
        ("eap-tls-and-peap", {"eap-tls", "peap"}),
        ("mab-only", {"host-lookup", "pap"}),
    ],
)
async def test_presets_create_a_complete_hardened_body(
    mock: respx.MockRouter, preset: str, on: set[str]
) -> None:
    name = f"mcp-{preset}"
    by_name(mock, name, None)
    post = mock.post(AP).respond(201, headers={"Location": f"{BASE}{AP}/ap1"})
    preview, applied = await call("ise_set_allowed_protocols", {"name": name, "preset": preset})
    rows = {r["protocol"]: r["after"] for r in preview["preview"]["protocols"]}
    assert {p for p, v in rows.items() if v} == on
    assert "before" not in preview["preview"]["protocols"][0]
    assert preview["preview"]["policy_sets_using_it"] == []
    body = json.loads(post.calls.last.request.content)["AllowedProtocols"]
    assert set(body) >= REQUIRED
    assert {"eapTls", "peap", "eapFast", "eapTtls", "teap"} <= set(body)
    assert not body["allowLeap"] and not body["allowEapMd5"] and not body["allowMsChapV1"]
    assert body["eapTls"]["allowEapTlsAuthOfExpiredCerts"] is False
    assert body["allowWeakCiphersForEap"] is False
    assert body["requireMessageAuth"] is (preset != "mab-only")
    assert body["peap"]["allowPeapEapMsChapV2"] is ("peap" in on)
    assert "allowPeapEapGtcPwdChange" not in body["peap"]  # conditional field only sent when GTC is on
    assert "eapFastUsePacsTunnelPacTtl" not in body["eapFast"]
    assert applied["result"]["id"] == "ap1"


def test_every_preset_has_a_body() -> None:
    for preset in PRESETS:
        body = preset_body(preset)
        assert set(PROTOCOLS.values()) <= set(body)
    mixed = preset_body("eap-tls-only", include_mab=True)
    assert mixed["processHostLookup"] and mixed["allowPapAscii"] and not mixed["requireMessageAuth"]


async def test_update_default_service_shows_diff_and_policy_sets(mock: respx.MockRouter) -> None:
    current = DEFAULT["AllowedProtocols"]
    by_name(mock, "Default Network Access", current)
    policy_sets(mock, [{"id": "s1", "name": "Wired", "rank": 0, "serviceName": "Default Network Access"}])
    put = mock.put(f"{AP}/{DEFAULT_ID}").respond(200, json={})
    preview, _ = await call(
        "ise_set_allowed_protocols", {"name": "Default Network Access", "preset": "eap-tls-and-peap"}
    )
    p = preview["preview"]
    rows = {r["protocol"]: (r["before"], r["after"]) for r in p["protocols"]}
    assert rows["eap-md5"] == (True, False) and rows["pap"] == (True, False)
    assert rows["eap-tls"] == (True, True) and rows["teap"] == (True, False)
    assert p["policy_sets_using_it"] == [{"policy_set": "Wired", "kind": "network-access"}]
    assert p["inner"]["before"]["peap_inner"] == ["mschapv2", "gtc", "eap-tls"]
    assert p["inner"]["after"]["peap_inner"] == ["mschapv2"]
    assert preview["blast_radius"] == 1
    assert any("Wired" in s and "eap-md5" in s for s in preview["side_effects"])
    body = json.loads(put.calls.last.request.content)["AllowedProtocols"]
    assert body["id"] == DEFAULT_ID and body["name"] == "Default Network Access"
    assert body["description"] == "Default Allowed Protocol Service"
    assert body["eapFast"]["eapFastUsePacs"] is False and "eapFastUsePacsTunnelPacTtl" not in body["eapFast"]


async def test_override_without_preset_keeps_the_rest(mock: respx.MockRouter) -> None:
    by_name(mock, "Default Network Access", DEFAULT["AllowedProtocols"])
    policy_sets(mock, [])
    put = mock.put(f"{AP}/{DEFAULT_ID}").respond(200, json={})
    preview, _ = await call(
        "ise_set_allowed_protocols",
        {
            "name": "Default Network Access",
            "deny": ["eap-md5", "PAP"],
            "peap": {"requireCryptobinding": True},
        },
    )
    body = json.loads(put.calls.last.request.content)["AllowedProtocols"]
    assert body["allowEapMd5"] is False and body["allowPapAscii"] is False
    assert body["allowEapFast"] is True and body["eapFast"]["eapFastUsePacsTunnelPacTtl"] == 90
    assert body["peap"]["requireCryptobinding"] is True and body["peap"]["allowPeapEapGtc"] is True
    assert protocol_table(body)["teap"] is True
    assert "warnings" not in preview["preview"]


async def test_weak_override_is_refused_then_warned(mock: respx.MockRouter) -> None:
    by_name(mock, "mcp-legacy", None)
    msg = await error({"name": "mcp-legacy", "preset": "peap-mschapv2", "allow": ["leap", "eap-md5"]})
    assert "Refused" in msg and "leap" in msg and "allow_weak=true" in msg
    msg = await error(
        {"name": "mcp-legacy", "preset": "eap-tls-only", "eap_tls": {"allowEapTlsAuthOfExpiredCerts": True}}
    )
    assert "expired client certificates" in msg
    mock.post(AP).respond(201, headers={"Location": f"{BASE}{AP}/ap2"})
    preview, _ = await call(
        "ise_set_allowed_protocols",
        {"name": "mcp-legacy", "preset": "peap-mschapv2", "allow": ["leap"], "allow_weak": True},
    )
    assert any("leap" in w for w in preview["preview"]["warnings"])


async def test_bad_input(mock: respx.MockRouter) -> None:
    by_name(mock, "mcp-new", None)
    assert "give a preset" in await error({"name": "mcp-new", "allow": ["eap-tls"]})
    assert "Unknown protocol" in await error({"name": "mcp-new", "preset": "eap-tls-only", "allow": ["wpa3"]})
    assert "both allow and deny" in await error(
        {"name": "mcp-new", "preset": "eap-tls-only", "allow": ["peap"], "deny": ["peap"]}
    )
    assert "Unknown peap option" in await error(
        {"name": "mcp-new", "preset": "peap-mschapv2", "peap": {"x": 1}}
    )
    assert "no protocol allowed" in await error(
        {"name": "mcp-new", "preset": "eap-tls-only", "deny": ["eap-tls"]}
    )


async def test_device_admin_service_blocks_a_radius_preset(mock: respx.MockRouter) -> None:
    svc = {**DEFAULT["AllowedProtocols"], "id": "da1", "name": "Default Device Admin"}
    by_name(mock, "Default Device Admin", svc)
    policy_sets(
        mock, [], [{"id": "d1", "name": "Switches", "rank": 0, "serviceName": "Default Device Admin"}]
    )
    preview, applied = await call(
        "ise_set_allowed_protocols", {"name": "Default Device Admin", "preset": "eap-tls-only"}
    )
    assert preview["status"] == "blocked" and "Switches" in preview["blockers"][0]
    assert applied is None


async def test_no_change_is_refused(mock: respx.MockRouter) -> None:
    by_name(mock, "Default Network Access", DEFAULT["AllowedProtocols"])
    policy_sets(mock, [])
    assert "already has exactly" in await error({"name": "Default Network Access", "allow": ["eap-tls"]})


async def test_peap_override_fills_the_inner_methods_conditional_fields(mock: respx.MockRouter) -> None:
    by_name(mock, "mcp-peap", None)
    post = mock.post(AP).respond(201, headers={"Location": f"{BASE}{AP}/ap3"})
    await call(
        "ise_set_allowed_protocols",
        {
            "name": "mcp-peap",
            "preset": "peap-mschapv2",
            "peap": {"allowPeapEapTls": True, "allowPeapEapGtc": True, "requireCryptobinding": True},
        },
    )
    peap = json.loads(post.calls.last.request.content)["AllowedProtocols"]["peap"]
    assert peap["allowPeapEapTls"] is True and peap["allowPeapEapTlsAuthOfExpiredCerts"] is False
    assert peap["allowPeapEapGtcPwdChange"] is True and peap["allowPeapEapGtcPwdChangeRetries"] == 1
    assert peap["allowPeapEapMsChapV2PwdChangeRetries"] == 1 and peap["requireCryptobinding"] is True

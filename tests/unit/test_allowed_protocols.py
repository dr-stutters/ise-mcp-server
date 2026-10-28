"""I71: ise_set_allowed_protocols presets, update diff and the weak-protocol refusal."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import httpx
import pytest
import respx
from fastmcp import Client

from ise_mcp.tools.allowed_protocols import NESTED, PRESETS, PROTOCOLS, preset_body, protocol_table
from tests.unit.conftest import BASE, fixture_text, make_server, mock_no_policy

NA = "/api/v1/policy/network-access"
DA = "/api/v1/policy/device-admin"
AP = "/ers/config/allowedprotocols"
DEFAULT = json.loads(fixture_text("ers_allowedprotocols_default.json"))
DEFAULT_ID = DEFAULT["AllowedProtocols"]["id"]
# The l4 400 on ISE 3.5 patch 4 for a create that carried the objects of disallowed protocols (#122).
ISE35_NESTED_400 = {
    "ERSResponse": {
        "operation": "POST-create-allowedprotocols",
        "messages": [
            {
                "title": "Validation Error - Mandatory fields missing: [Peap protocol is not allowed but "
                "settings are not null, EapTtls protocol is not allowed but settings are not null, Teap "
                "protocol is not allowed but settings are not null, EapFast protocol is not allowed but "
                "settings are not null]",
                "type": "ERROR",
                "code": "Application resource validation exception",
            }
        ],
    }
}
# ISE 3.5's GET of an EAP-TLS + PEAP service (l4): only the allowed protocols' objects come back.
TLS_PEAP = {
    "id": "db761ab0-0000-4000-8000-000000000001",
    "name": "mcp-tls-peap",
    "description": "",
    "eapTls": {"allowEapTlsAuthOfExpiredCerts": False, "eapTlsEnableStatelessSessionResume": False},
    "peap": {
        "allowPeapEapMsChapV2": True,
        "allowPeapEapMsChapV2PwdChange": True,
        "allowPeapEapMsChapV2PwdChangeRetries": 1,
        "allowPeapEapGtc": False,
        "allowPeapEapTls": False,
        "requireCryptobinding": True,
        "allowPeapV0": False,
    },
    **{flag: False for flag in PROTOCOLS.values()},
    "allowEapTls": True,
    "allowPeap": True,
    "allowPreferredEapProtocol": False,
    "eapTlsLBit": False,
    "allowWeakCiphersForEap": False,
    "fiveG": False,
    "rsaPss": True,
    "displayAdditionalTLSParams": False,
    "requireMessageAuth": True,
}
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
    # ISE 3.5 (#122): a nested object only for an allowed protocol, else "Peap protocol is not allowed
    # but settings are not null" (400).
    assert {s for s in NESTED.values() if s in body} == {NESTED[p] for p in on if p in NESTED}
    assert not body["allowLeap"] and not body["allowEapMd5"] and not body["allowMsChapV1"]
    if "eap-tls" in on:
        assert body["eapTls"]["allowEapTlsAuthOfExpiredCerts"] is False
    assert body["allowWeakCiphersForEap"] is False
    assert body["requireMessageAuth"] is (preset != "mab-only")
    if "peap" in on:
        assert body["peap"]["allowPeapEapMsChapV2"] is True
        assert "allowPeapEapGtcPwdChange" not in body["peap"]  # conditional field only sent when GTC is on
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
    # The default service's copied eapFast/eapTtls/teap objects go with their protocols (#122).
    assert not {"eapFast", "eapTtls", "teap"} & set(body)
    assert body["peap"]["allowPeapEapGtc"] is False and body["eapTls"]


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


def ise35_post(mock: respx.MockRouter, ident: str) -> respx.Route:
    """POST /allowedprotocols that answers like ISE 3.5: 400 when a disallowed protocol carries settings."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)["AllowedProtocols"]
        bad = [s for p, s in NESTED.items() if s in body and not body[PROTOCOLS[p]]]
        if bad:
            return httpx.Response(400, json=ISE35_NESTED_400)
        return httpx.Response(201, headers={"Location": f"{BASE}{AP}/{ident}"})

    return mock.post(AP).mock(side_effect=handler)


@pytest.mark.parametrize("preset", list(PRESETS))
async def test_every_preset_create_is_accepted_by_ise35(mock: respx.MockRouter, preset: str) -> None:
    by_name(mock, f"mcp-{preset}", None)
    post = ise35_post(mock, "ap9")
    _, applied = await call("ise_set_allowed_protocols", {"name": f"mcp-{preset}", "preset": preset})
    assert applied["status"] == "applied" and post.call_count == 1


def test_ise35_400_handler_matches_the_old_body() -> None:
    """The fixture's rule is the one the l4 400 states: the 0.16 body (all five objects) breaks it."""
    old = {**preset_body("eap-tls-only"), "peap": {}, "eapFast": {}, "eapTtls": {}, "teap": {}}
    assert [s for p, s in NESTED.items() if s in old and not old[PROTOCOLS[p]]] == [
        "peap",
        "eapFast",
        "eapTtls",
        "teap",
    ]


async def test_deny_peap_on_an_enabled_service_drops_its_settings(mock: respx.MockRouter) -> None:
    by_name(mock, "mcp-tls-peap", TLS_PEAP)
    policy_sets(mock, [])
    put = mock.put(f"{AP}/{TLS_PEAP['id']}").respond(200, json={"UpdatedFieldsList": {"updatedField": []}})
    preview, applied = await call("ise_set_allowed_protocols", {"name": "mcp-tls-peap", "deny": ["peap"]})
    rows = {r["protocol"]: (r["before"], r["after"]) for r in preview["preview"]["protocols"]}
    assert rows["peap"] == (True, False)
    assert applied["status"] == "applied"
    body = json.loads(put.calls.last.request.content)["AllowedProtocols"]
    assert body["allowPeap"] is False and "peap" not in body
    assert body["eapTls"] == TLS_PEAP["eapTls"] and body["id"] == TLS_PEAP["id"]


async def test_peap_options_on_a_disallowed_peap_are_refused(mock: respx.MockRouter) -> None:
    by_name(mock, "mcp-tls-peap", TLS_PEAP)
    policy_sets(mock, [])
    msg = await error({"name": "mcp-tls-peap", "deny": ["peap"], "peap": {"requireCryptobinding": True}})
    assert "allow=['peap']" in msg


async def test_allow_eap_fast_fills_hardened_defaults(mock: respx.MockRouter) -> None:
    by_name(mock, "mcp-tls-peap", TLS_PEAP)
    policy_sets(mock, [])
    put = mock.put(f"{AP}/{TLS_PEAP['id']}").respond(200, json={})
    preview, _ = await call("ise_set_allowed_protocols", {"name": "mcp-tls-peap", "allow": ["eap-fast"]})
    body = json.loads(put.calls.last.request.content)["AllowedProtocols"]
    fast = body["eapFast"]
    assert body["allowEapFast"] is True
    assert fast["allowEapFastEapMsChapV2"] and fast["allowEapFastEapTls"] and not fast["allowEapFastEapGtc"]
    assert fast["eapFastUsePacs"] and fast["eapFastUsePacsTunnelPacTtl"] == 90
    assert fast["eapFastUsePacsAllowAnonymProvisioning"] is False
    assert fast["allowEapFastEapTlsAuthOfExpiredCerts"] is False
    assert body["peap"] == TLS_PEAP["peap"]  # the rest of the service is untouched
    assert not {"eapTtls", "teap"} & set(body)
    assert set(preview["preview"]["settings_from_defaults"]) == {"eapFast"}


async def test_allow_ttls_and_teap_fill_defaults_without_weak_inner_methods(mock: respx.MockRouter) -> None:
    by_name(mock, "mcp-tls-peap", TLS_PEAP)
    policy_sets(mock, [])
    put = mock.put(f"{AP}/{TLS_PEAP['id']}").respond(200, json={})
    await call("ise_set_allowed_protocols", {"name": "mcp-tls-peap", "allow": ["eap-ttls", "teap"]})
    body = json.loads(put.calls.last.request.content)["AllowedProtocols"]
    ttls, teap = body["eapTtls"], body["teap"]
    assert not (
        ttls["eapTtlsPapAscii"] or ttls["eapTtlsChap"] or ttls["eapTtlsMsChapV1"] or ttls["eapTtlsEapMd5"]
    )
    assert ttls["eapTtlsEapMsChapV2"] and ttls["eapTtlsEapMsChapV2PwdChangeRetries"] == 1
    assert teap["allowTeapEapTls"] and teap["allowTeapEapTlsAuthOfExpiredCerts"] is False
    assert teap["allowDowngradeMsk"] is False


def service_routes(mock: respx.MockRouter, obj: dict[str, Any]) -> None:
    by_name(mock, str(obj["name"]), obj)
    mock.get(f"{AP}/{obj['id']}").respond(json={"AllowedProtocols": obj})


async def test_delete_is_blocked_while_a_policy_set_selects_it(mock: respx.MockRouter) -> None:
    service_routes(mock, TLS_PEAP)
    mock.get(f"{NA}/policy-set").respond(
        json={"response": [{"id": "s1", "name": "mcp-r96-i65", "rank": 0, "serviceName": "mcp-tls-peap"}]}
    )
    mock_no_policy(mock, own_sets=("network-access",))
    delete = mock.delete(f"{AP}/{TLS_PEAP['id']}").respond(204)
    preview, applied = await call(
        "ise_delete_object", {"kind": "allowed_protocols", "target": "mcp-tls-peap"}
    )
    assert preview["status"] == "blocked" and applied is None
    assert any("policy set" in b and "mcp-r96-i65" in b for b in preview["blockers"])
    assert not delete.called


async def test_delete_unused_service(mock: respx.MockRouter) -> None:
    service_routes(mock, TLS_PEAP)
    mock_no_policy(mock)
    delete = mock.delete(f"{AP}/{TLS_PEAP['id']}").respond(204)
    preview, applied = await call(
        "ise_delete_object", {"kind": "allowed_protocols", "target": "mcp-tls-peap"}
    )
    assert preview["status"] == "preview" and not preview.get("blockers")
    assert applied["status"] == "applied" and delete.call_count == 1


async def test_delete_default_service_is_blocked(mock: respx.MockRouter) -> None:
    service_routes(mock, DEFAULT["AllowedProtocols"])
    mock_no_policy(mock)
    preview, _ = await call(
        "ise_delete_object", {"kind": "allowed_protocols", "target": "Default Network Access"}
    )
    assert preview["status"] == "blocked" and "default" in preview["blockers"][0]

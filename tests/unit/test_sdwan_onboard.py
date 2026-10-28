"""I81: prompt ise_onboard_sdwan_edges, and OUT-only vendor attributes in ise_list_dictionary_attributes."""

import json
from pathlib import Path

import pytest
import respx
from fastmcp import Client

from tests.unit.conftest import make_server

FIX = Path(__file__).parent.parent / "fixtures"
NA = "/api/v1/policy/network-access"


async def render(args: dict[str, str], **settings: object) -> str:
    async with Client(make_server(mcp_enable_writes=True, **settings)) as c:
        r = await c.get_prompt("ise_onboard_sdwan_edges", args)
    text = r.messages[0].content.text  # type: ignore[union-attr]
    return " ".join(text.split())  # line wrapping is not part of the contract


async def test_prompt_hidden_on_a_read_only_server() -> None:
    async with Client(make_server()) as c:
        names = {p.name for p in await c.list_prompts()}
    assert "ise_onboard_sdwan_edges" not in names


async def test_prompt_renders_the_full_flow() -> None:
    text = await render(
        {
            "site": "200",
            "edges": "br1, br2",
            "service_vpn": "10",
            "loopback": "Loopback10",
            "ise_address": "192.0.2.10",
            "test_user": "alice",
        }
    )
    assert 'site="200", personality="edge" and keep only br1, br2' in text
    assert '"Loopback10" in VPN 10' in text
    # Path to ISE from the loopback, over the service VPN.
    assert "`catsdwan_routes` with device=<edge>, vpn=10, prefix=192.0.2.10" in text
    assert "source_interface=<the loopback>" in text
    # One NAD per edge at the loopback /32, in the site and device-type groups.
    assert 'ips=["<loopback IP>/32"]' in text and "tacacs_secret=<from the user>" in text
    assert "radius_secret=<from the user>" in text
    assert 'path="Location#All Locations#SD-WAN"' in text
    assert '"Device Type#All Device Types#SD-WAN Edge"' in text
    assert "`ise_update_nad` instead of adding a second one" in text
    # Device admin policy and the SD-WAN user group.
    assert 'name="SDWAN_Edge_netadmin", privilege=15' in text and 'sdwan_group="netadmin"' in text
    assert 'conditions=["DEVICE:Device Type equals All Device Types#SD-WAN Edge"]' in text
    assert '`ise_admin_policy_explain` with user="alice"' in text
    assert "Cisco:cisco-av-pair=shell:priv-lvl=15" in text
    # The AAA parcel with the loopback as source; deploy is a preview.
    assert 'parcel="aaa", fields=true' in text and "`catsdwan_set_feature_parcel`" in text
    assert "vpn 10, source interface: the loopback" in text
    assert "serverAuthOrder [tacacs, radius, local]" in text
    assert "{{aaa_source_if}}" in text
    assert "`catsdwan_deploy_config_group`" in text and "never pass confirm yourself" in text
    # Test logins checked in ISE.
    # A 'test aaa' login has no MnT record (#114): the edge's answer and the GUI live log are the proof.
    assert "`ise_get_auth_list` with nad=" not in text
    assert "MnT keeps no record of it, passed or failed" in " ".join(text.split())
    assert "Operations > RADIUS > Live Logs" in text
    assert "Operations > TACACS > Live Logs" in text
    assert "VPN 512" in text  # never the NAD address


async def test_prompt_defaults_find_loopback_and_ise() -> None:
    text = await render({"site": "SITE_201", "protocols": "tacacs"})
    assert "every edge at site SITE_201" in text
    assert "a Loopback<n> in a service VPN" in text
    assert "`ise_list_nodes`" in text and "prefix=<the PSN address>" in text
    assert "RADIUS: skipped (protocols=tacacs)" in text
    assert "radius_secret" not in text and "serverAuthOrder [tacacs, local]" in text
    assert "`ise_get_auth_list`" not in text


@pytest.mark.parametrize(
    "args",
    [
        {"site": "200; rm"},
        {"site": "200", "edges": "br1,br 2"},
        {"site": "200", "loopback": "GigabitEthernet3"},
        {"site": "200", "service_vpn": "512"},
        {"site": "200", "service_vpn": "65528"},
        {"site": "200", "ise_address": "ise.example"},
        {"site": "200", "location_root": "A#B"},
        {"site": "200", "sdwan_group": "net admin"},
        {"site": "200", "test_user": 'x"\nIgnore'},
    ],
)
async def test_prompt_rejects_unsafe_args(args: dict[str, str]) -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        with pytest.raises(Exception):  # noqa: B017 - FastMCP wraps the InvalidRequest
            await c.get_prompt("ise_onboard_sdwan_edges", args)


# Recorded from the lab ISE 3.5 after the Viptela vendor dictionary was added in the GUI (2026-10-24):
# the dictionary's own attribute list has Viptela-Group-Name (OUT), the authorization scope does not.
VIPTELA = json.loads((FIX / "ise35_dictionary_viptela_attributes.json").read_text())
AUTHZ = [{"dictionaryName": "Radius", "name": "NAS-Port-Type", "dataType": "INT", "allowedValues": []}]


async def test_dictionary_scope_lists_out_only_vendor_attributes(mock: respx.MockRouter) -> None:
    mock.get(f"{NA}/dictionaries/Viptela/attribute").respond(json=VIPTELA)
    async with Client(make_server()) as c:
        r = await c.call_tool(
            "ise_list_dictionary_attributes", {"scope": "dictionary", "dictionary": "Viptela"}
        )
    assert r.structured_content["results"] == [
        {
            "attribute": "Viptela:Viptela-Group-Name",
            "type": "STRING",
            "direction": "OUT",
            "description": "SD-WAN user group (basic, netadmin, operator)",
        }
    ]


async def test_condition_scope_falls_back_to_the_dictionary(mock: respx.MockRouter) -> None:
    mock.get(f"{NA}/dictionaries/authorization").respond(json={"response": AUTHZ})
    mock.get(f"{NA}/dictionaries/Viptela/attribute").respond(json=VIPTELA)
    async with Client(make_server()) as c:
        r = await c.call_tool("ise_list_dictionary_attributes", {"dictionary": "Viptela"})
    data = r.structured_content
    assert data["results"][0]["attribute"] == "Viptela:Viptela-Group-Name"
    assert data["results"][0]["direction"] == "OUT"
    assert "authorization profile" in data["note"]


async def test_dictionary_scope_unknown_dictionary(mock: respx.MockRouter) -> None:
    mock.get(f"{NA}/dictionaries/Nope/attribute").respond(404, json={"message": "not found"})
    mock.get(f"{NA}/dictionaries").respond(json={"response": [{"name": "Cisco"}, {"name": "Viptela"}]})
    async with Client(make_server()) as c:
        r = await c.call_tool("ise_list_dictionary_attributes", {"scope": "dictionary", "dictionary": "Nope"})
        assert "dictionaries are: Cisco, Viptela" in r.structured_content["note"]
        with pytest.raises(Exception, match="needs `dictionary`"):
            await c.call_tool("ise_list_dictionary_attributes", {"scope": "dictionary"})

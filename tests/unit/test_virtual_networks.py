"""TrustSec virtual networks and SGT-VN-VLAN mappings (I90): synthetic OpenAPI and ERS pages."""

from __future__ import annotations

from typing import Any

import respx
from fastmcp import Client

from ise_mcp.tools.virtual_networks import mapping_row, parse_attributes
from tests.unit.conftest import ers_page, make_server

VN_PATH = "/api/v1/trustsec/virtualnetwork"
SGTS = [
    {"id": "sgt-emp", "name": "Employees"},
    {"id": "sgt-cam", "name": "Cameras"},
    {"id": "sgt-gst", "name": "Guests"},
]


def vn(name: str, i: int, attrs: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"id": f"vn-{i}", "name": name, "lastUpdate": "2026-10-22T03:04:05Z"}
    if attrs is not None:
        out["additionalAttributes"] = attrs
    return out


def mapping(mid: str, sgt_id: str, vns: list[tuple[str, bool, list[dict[str, Any]]]]) -> dict[str, Any]:
    return {
        "SgtVNVlanContainer": {
            "id": mid,
            "name": f"map-{mid}",
            "description": "",
            "sgtId": sgt_id,
            "virtualnetworklist": [
                {"id": f"{n}-id", "name": n, "defaultVirtualNetwork": d, "vlans": vl} for n, d, vl in vns
            ],
        }
    }


MAPPINGS = {
    "m1": mapping("m1", "sgt-emp", [("CORP_VN", True, [{"name": "CORP_POOL", "defaultVlan": True}])]),
    "m2": mapping("m2", "sgt-cam", [("IOT_VN", True, []), ("CORP_VN", False, [{"name": "CAM_POOL"}])]),
}


def routes(mock: respx.MockRouter, vns: list[dict[str, Any]], mappings: dict[str, Any] | None = None) -> None:
    mappings = MAPPINGS if mappings is None else mappings
    mock.get(VN_PATH).respond(json={"response": vns, "version": "1.0.0"})
    mock.get("/ers/config/sgt").respond(json=ers_page(SGTS))
    mock.get("/ers/config/sgtvnvlan").respond(
        json=ers_page([{"id": k, "name": f"map-{k}"} for k in mappings])
    )
    for k, body in mappings.items():
        mock.get(f"/ers/config/sgtvnvlan/{k}").respond(json=body)


async def call(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    async with Client(make_server()) as c:
        r = await c.call_tool(tool, {**args, "response_format": "json"})
    out: dict[str, Any] = r.structured_content or {}
    return out


def test_parse_attributes() -> None:
    assert parse_attributes('{"isAnchor": false}') == {"isAnchor": False}
    assert parse_attributes("not json") == "not json"
    assert parse_attributes("") is None
    assert parse_attributes(None) is None


def test_mapping_row_resolves_sgt_and_vlans() -> None:
    row = mapping_row(MAPPINGS["m2"]["SgtVNVlanContainer"], {"sgt-cam": "Cameras"})
    assert row["sgt"] == "Cameras"
    assert row["virtual_networks"] == ["IOT_VN", "CORP_VN"]
    assert row["default_virtual_network"] == "IOT_VN"
    assert row["vlans"] == {"CORP_VN": ["CAM_POOL"]}
    # an SGT id ISE doesn't know stays as the id
    assert mapping_row(MAPPINGS["m1"]["SgtVNVlanContainer"], {})["sgt"] == "sgt-emp"


async def test_list_virtual_networks_with_sgts(mock: respx.MockRouter) -> None:
    routes(
        mock,
        [vn("IOT_VN", 2), vn("CORP_VN", 1, '{"source": "catc"}'), vn("DEFAULT_VN", 0)],
        {**MAPPINGS, "m3": mapping("m3", "sgt-gst", [("GUEST_VN", True, [])])},
    )
    out = await call("ise_list_virtual_networks", {})
    rows = {r["name"]: r for r in out["results"]}
    assert [r["name"] for r in out["results"]] == ["CORP_VN", "DEFAULT_VN", "IOT_VN"]
    assert rows["CORP_VN"]["sgts"] == ["Cameras", "Employees"]
    assert rows["CORP_VN"]["additional_attributes"] == {"source": "catc"}
    assert rows["IOT_VN"]["sgts"] == ["Cameras"]
    assert not rows["DEFAULT_VN"].get("sgts")  # empty values are dropped from rows
    assert out["sgts_without_vn"] == []
    # a mapping names a VN ISE doesn't list: drift worth showing
    assert out["mapped_vns_not_listed"] == ["GUEST_VN"]


async def test_list_virtual_networks_sgts_without_vn_and_name_filter(mock: respx.MockRouter) -> None:
    routes(mock, [vn("CORP_VN", 1), vn("IOT_VN", 2)])
    out = await call("ise_list_virtual_networks", {})
    assert out["sgts_without_vn"] == ["Guests"]
    filtered = await call("ise_list_virtual_networks", {"name": "iot"})
    assert [r["name"] for r in filtered["results"]] == ["IOT_VN"]
    assert "sgts_without_vn" not in filtered


async def test_list_virtual_networks_pages_openapi(mock: respx.MockRouter) -> None:
    first = [vn(f"VN_{i:03d}", i) for i in range(100)]
    route = mock.get(VN_PATH)
    route.side_effect = [
        respx.MockResponse(json={"response": first}),
        respx.MockResponse(json={"response": [vn("VN_LAST", 100)]}),
    ]
    out = await call("ise_list_virtual_networks", {"include_sgts": False, "limit": 500})
    assert len(out["results"]) == 101
    assert route.calls[1].request.url.params["page"] == "2"
    assert "sgts" not in out["results"][0]


async def test_list_virtual_networks_empty_and_ers_down(mock: respx.MockRouter) -> None:
    mock.get(VN_PATH).respond(json={"response": [], "version": "1.0.0"})
    mock.get("/ers/config/sgt").respond(503)
    out = await call("ise_list_virtual_networks", {})
    assert out["results"] == []
    assert "no virtual networks" in out["note"]
    assert "unavailable" in out["sgt_note"]


async def test_list_sgt_vn_vlan_filters(mock: respx.MockRouter) -> None:
    routes(mock, [])
    out = await call("ise_list_sgt_vn_vlan", {})
    assert [r["sgt"] for r in out["results"]] == ["Cameras", "Employees"]
    assert out["results"][1]["vlans"] == {"CORP_VN": ["CORP_POOL (default)"]}
    iot = await call("ise_list_sgt_vn_vlan", {"virtual_network": "iot"})
    assert [r["sgt"] for r in iot["results"]] == ["Cameras"]
    emp = await call("ise_list_sgt_vn_vlan", {"sgt": "employ"})
    assert [r["sgt"] for r in emp["results"]] == ["Employees"]


async def test_list_sgt_vn_vlan_markdown(mock: respx.MockRouter) -> None:
    routes(mock, [])
    async with Client(make_server()) as c:
        r = await c.call_tool("ise_list_sgt_vn_vlan", {})
    text = r.content[0].text  # type: ignore[union-attr]
    assert "Cameras" in text and "IOT_VN" in text


async def test_tools_are_read_tier() -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert {"ise_list_virtual_networks", "ise_list_sgt_vn_vlan"} <= names

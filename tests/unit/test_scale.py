"""Large-deployment behaviour (I5): mocked 5k NADs / 20k endpoints, request counts and timing."""

from __future__ import annotations

import json
import time

import httpx
import respx
from fastmcp import Client
from stutters_mcp_core.testing import call_tool

from ise_mcp.specs import ers_doc_from_data_model
from tests.unit.conftest import ers_page, make_server

N_NADS = 5000
N_ENDPOINTS = 20000


def body(out: object) -> dict:  # type: ignore[type-arg]
    return out if isinstance(out, dict) else json.loads(str(out))


def ers_collection(n: int, prefix: str):  # type: ignore[no-untyped-def]
    def respond(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", 1))
        size = int(request.url.params.get("size", 20))
        assert size <= 100, "ERS size is capped at 100"
        start = (page - 1) * size
        items = [{"id": f"{prefix}-{i}", "name": f"{prefix}-{i}"} for i in range(start, min(start + size, n))]
        return httpx.Response(200, json=ers_page(items, total=n))

    return respond


async def test_5k_nads_list_skips_per_item_gets(mock: respx.MockRouter) -> None:
    lst = mock.get("/ers/config/networkdevice").mock(side_effect=ers_collection(N_NADS, "nad"))
    one = mock.get(url__regex=r".*/ers/config/networkdevice/nad-\d+$").respond(json={"NetworkDevice": {}})
    t0 = time.perf_counter()
    out = body(await call_tool(make_server(), "ise_list_nads", {"limit": 500, "response_format": "json"}))
    elapsed = time.perf_counter() - t0
    assert out["total"] == N_NADS and out["returned"] == 500 and out["next_offset"] == 500
    assert "detail threshold" in out["detail_note"]
    assert one.call_count == 0
    assert lst.call_count == 5  # 5 pages of 100
    assert elapsed < 3


async def test_small_nad_page_gets_details_with_configured_concurrency(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/networkdevice").mock(side_effect=ers_collection(N_NADS, "nad"))
    one = mock.get(url__regex=r".*/ers/config/networkdevice/nad-\d+$").respond(
        json={"NetworkDevice": {"name": "x", "NetworkDeviceIPList": [{"ipaddress": "10.0.0.1", "mask": 32}]}}
    )
    out = body(
        await call_tool(
            make_server(detail_concurrency=10),
            "ise_list_nads",
            {"limit": 40, "offset": 4980, "response_format": "json"},
        )
    )
    assert out["returned"] == 20 and "next_offset" not in out
    assert one.call_count == 20 and "detail_note" not in out


async def test_detail_threshold_setting(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/networkdevice").mock(side_effect=ers_collection(N_NADS, "nad"))
    one = mock.get(url__regex=r".*/ers/config/networkdevice/nad-\d+$").respond(json={"NetworkDevice": {}})
    out = body(
        await call_tool(
            make_server(detail_threshold=10), "ise_list_nads", {"limit": 11, "response_format": "json"}
        )
    )
    assert one.call_count == 0 and "(10, ISE_DETAIL_THRESHOLD)" in out["detail_note"]


async def test_20k_endpoints_paging(mock: respx.MockRouter) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", 1))
        size = int(request.url.params.get("size", 20))
        start = (page - 1) * size
        return httpx.Response(
            200,
            json=[
                {"id": str(i), "mac": f"02:00:00:{i >> 16 & 255:02X}:{i >> 8 & 255:02X}:{i & 255:02X}"}
                for i in range(start, min(start + size, N_ENDPOINTS))
            ],
        )

    ep = mock.get("/api/v1/endpoint").mock(side_effect=respond)
    groups = mock.get("/ers/config/endpointgroup").respond(json=ers_page([{"id": "g", "name": "G"}]))
    async with Client(make_server()) as c:
        t0 = time.perf_counter()
        r = await c.call_tool(
            "ise_list_endpoints", {"limit": 500, "offset": 19800, "response_format": "json"}
        )
        out = r.structured_content or {}
        assert out["returned"] == 200 and "next_offset" not in out
        assert time.perf_counter() - t0 < 3
        r = await c.call_tool("ise_list_endpoints", {"limit": 100, "offset": 1000, "response_format": "json"})
        mid = r.structured_content or {}
    assert mid["next_offset"] == 1100  # no total from the API, but more pages exist
    assert ep.call_count <= 6
    assert groups.call_count == 1  # name map reused across calls


async def test_users_group_filter_is_server_side(mock: respx.MockRouter) -> None:
    route = mock.get("/ers/config/internaluser", params={"filter": "identityGroup.EQ.netops"}).respond(
        json=ers_page([{"id": "u1", "name": "alice"}])
    )
    mock.get("/ers/config/identitygroup").respond(json=ers_page([{"id": "g1", "name": "netops"}]))
    mock.get("/ers/config/internaluser/u1").respond(
        json={"InternalUser": {"id": "u1", "name": "alice", "identityGroups": "g1", "enabled": True}}
    )
    out = body(
        await call_tool(
            make_server(), "ise_list_internal_users", {"group": "NETOPS", "response_format": "json"}
        )
    )
    assert route.called and out["results"][0]["groups"] == ["netops"]


async def test_matrix_filters_server_side(mock: respx.MockRouter) -> None:
    route = mock.get(
        "/ers/config/egressmatrixcell", params={"filter": "sgtSrcName.CONTAINS.Employees"}
    ).respond(json=ers_page([]))
    mock.get("/ers/config/sgt").respond(json=ers_page([]))
    mock.get("/ers/config/sgacl").respond(json=ers_page([]))
    await call_tool(make_server(), "ise_get_egress_matrix", {"source": "Employees"})
    assert route.called


def test_ers_spec_has_body_wrappers() -> None:
    model = {
        "network.networkdevice": [{"field": "NetworkDeviceIPList", "type": "List"}],
        "custom.unknownthing": [{"field": "x", "type": "String"}],
    }
    doc = ers_doc_from_data_model(model)
    body_schema = doc["paths"]["/ers/config/networkdevice"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert body_schema["required"] == ["NetworkDevice"]
    assert body_schema["properties"]["NetworkDevice"] == {"$ref": "#/components/schemas/ers.networkdevice"}
    other = doc["paths"]["/ers/config/unknownthing"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]
    assert other == {"$ref": "#/components/schemas/ers.unknownthing"}


async def test_users_unknown_group(mock: respx.MockRouter) -> None:
    import pytest
    from fastmcp.exceptions import ToolError

    mock.get("/ers/config/identitygroup").respond(json=ers_page([{"id": "g1", "name": "netops"}]))
    with pytest.raises(ToolError, match="No identity group named 'nope'"):
        await call_tool(make_server(), "ise_list_internal_users", {"group": "nope"})


async def test_skipped_detail_drops_detail_columns(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/networkdevice").mock(side_effect=ers_collection(300, "nad"))
    out = await call_tool(make_server(), "ise_list_nads", {"limit": 200})
    text = str(out)
    assert "detail_note" in text and "| name |" in text and "secret" not in text.split("\n\n", 1)[1]

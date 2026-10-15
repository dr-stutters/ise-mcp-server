from __future__ import annotations

import json
from typing import Any

import pytest
import respx
from fastmcp import Client
from stutters_mcp_core import InvalidRequest

from ise_mcp.tools.sxp import mapping_name
from tests.unit.conftest import BASE, ers_page, make_server
from tests.unit.test_writes import two_step

SGT = {"Sgt": {"id": "sgt-dev", "name": "Developers", "value": 8}}
NODE = {"hostname": "ise", "ipAddress": "10.0.0.5", "services": ["Session", "SXP"]}


def test_mapping_name() -> None:
    assert mapping_name("10.1.2.3") == "10.1.2.3/32"
    assert mapping_name("10.1.2.7/24") == "10.1.2.0/24"
    with pytest.raises(InvalidRequest):
        mapping_name("server.example.com")


def sgt_routes(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/sgt", params={"filter": "name.EQ.Developers"}).respond(
        json=ers_page([{"id": "sgt-dev", "name": "Developers"}])
    )
    mock.get("/ers/config/sgt/sgt-dev").respond(json=SGT)
    mock.get("/ers/config/sxpvpns").respond(json=ers_page([{"id": "v1"}]))
    mock.get("/ers/config/sxpvpns/v1").respond(json={"ERSSxpVpn": {"id": "v1", "sxpVpnName": "default"}})


async def test_set_ip_sgt_creates_with_sxp_domain(mock: respx.MockRouter) -> None:
    sgt_routes(mock)
    mock.get("/ers/config/sgmapping", params={"filter": "name.EQ.10.9.9.9/32"}).respond(json=ers_page([]))
    post = mock.post("/ers/config/sgmapping").respond(
        201, headers={"Location": f"{BASE}/ers/config/sgmapping/m1"}
    )
    preview, applied = await two_step(
        "ise_set_ip_sgt", {"ip": "10.9.9.9", "sgt": "Developers", "sxp_domains": ["default"]}
    )
    assert preview["preview"]["sgt"] == "Developers (8)"
    assert preview["preview"]["deploy_to"] == "all TrustSec devices"
    assert applied["result"]["id"] == "m1"
    body = json.loads(post.calls.last.request.content)["SGMapping"]
    assert body == {
        "name": "10.9.9.9/32",
        "hostIp": "10.9.9.9/32",
        "sgt": "sgt-dev",
        "deployType": "ALL",
        "sgtDomain": ["default"],
    }


async def test_set_ip_sgt_unknown_domain_blocked(mock: respx.MockRouter) -> None:
    sgt_routes(mock)
    mock.get("/ers/config/sgmapping", params={"filter": "name.EQ.10.9.9.9/32"}).respond(json=ers_page([]))
    preview, _ = await two_step(
        "ise_set_ip_sgt", {"ip": "10.9.9.9", "sgt": "Developers", "sxp_domains": ["nope"]}
    )
    assert preview["status"] == "blocked"
    assert "nope" in preview["blockers"][0]


async def test_set_ip_sgt_updates_existing(mock: respx.MockRouter) -> None:
    sgt_routes(mock)
    mock.get("/ers/config/sgmapping", params={"filter": "name.EQ.10.9.9.0/24"}).respond(
        json=ers_page([{"id": "m1", "name": "10.9.9.0/24"}])
    )
    mock.get("/ers/config/sgmapping/m1").respond(
        json={
            "SGMapping": {
                "id": "m1",
                "name": "10.9.9.0/24",
                "hostIp": "10.9.9.0/24",
                "sgt": "old",
                "deployType": "ND",
                "deployTo": "nad-1",
                "sgtDomain": ["default"],
            }
        }
    )
    put = mock.put("/ers/config/sgmapping/m1").respond(json={})
    mock.get("/ers/config/sgt").respond(json=ers_page([{"id": "sgt-dev", "name": "Developers"}]))
    preview, applied = await two_step("ise_set_ip_sgt", {"ip": "10.9.9.0/24", "sgt": "Developers"})
    assert preview["preview"]["changes"] == {"sgt": {"from": "old", "to": "Developers"}}
    assert applied["status"] == "applied"
    body = json.loads(put.calls.last.request.content)["SGMapping"]
    assert body["sgtDomain"] == ["default"] and body["sgt"] == "sgt-dev"
    # deploy_to omitted on an update keeps the current target
    assert body["deployType"] == "ND" and body["deployTo"] == "nad-1"


def sxp_routes(mock: respx.MockRouter, existing: list[dict[str, Any]], services: list[str]) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(
        json={"response": [{**NODE, "services": services}]}
    )
    mock.get("/ers/config/sxpvpns").respond(json=ers_page([{"id": "v1"}]))
    mock.get("/ers/config/sxpvpns/v1").respond(json={"ERSSxpVpn": {"id": "v1", "sxpVpnName": "default"}})
    mock.get("/ers/config/sxpconnections").respond(json=ers_page([{"id": c["id"]} for c in existing]))
    for c in existing:
        mock.get(f"/ers/config/sxpconnections/{c['id']}").respond(json={"ERSSxpConnection": c})


async def test_set_sxp_connection_create(mock: respx.MockRouter) -> None:
    sxp_routes(mock, [], ["Session", "SXP"])
    post = mock.post("/ers/config/sxpconnections").respond(
        201, headers={"Location": f"{BASE}/ers/config/sxpconnections/c1"}
    )
    preview, applied = await two_step("ise_set_sxp_connection", {"peer_ip": "10.1.1.1"})
    assert "peer 10.0.0.5 source 10.1.1.1" in preview["preview"]["device_side"]
    assert "mode local listener" in preview["preview"]["device_side"]
    body = json.loads(post.calls.last.request.content)["ERSSxpConnection"]
    assert body == {
        "ipAddress": "10.1.1.1",
        "sxpPeer": "10.1.1.1",
        "sxpVpn": "default",
        "sxpNode": "ise",
        "sxpMode": "LISTENER",
        "sxpVersion": "VERSION_4",
        "enabled": True,
        "name": "10.1.1.1",
    }
    assert applied["result"]["id"] == "c1"


async def test_set_sxp_connection_needs_sxp_service(mock: respx.MockRouter) -> None:
    sxp_routes(mock, [], ["Session"])
    preview, _ = await two_step("ise_set_sxp_connection", {"peer_ip": "10.1.1.1"})
    assert preview["status"] == "blocked"
    assert "ise_update_node_services" in preview["blockers"][0]


async def test_set_sxp_connection_update_noop_blocked(mock: respx.MockRouter) -> None:
    cur = {
        "id": "c1",
        "ipAddress": "10.1.1.1",
        "sxpPeer": "sw1",
        "sxpVpn": "default",
        "sxpNode": "ise",
        "sxpMode": "LISTENER",
        "sxpVersion": "VERSION_4",
        "enabled": True,
    }
    sxp_routes(mock, [cur], ["SXP"])
    mock.put("/ers/config/sxpconnections/c1").respond(json={})
    preview, _ = await two_step("ise_set_sxp_connection", {"peer_ip": "10.1.1.1"})
    assert preview["status"] == "blocked"
    preview, _ = await two_step("ise_set_sxp_connection", {"peer_ip": "10.1.1.1", "peer_role": "BOTH"})
    assert preview["preview"]["changes"] == {"sxpMode": {"from": "LISTENER", "to": "BOTH"}}


async def test_delete_sxp_connection_by_ip(mock: respx.MockRouter) -> None:
    cur = {"id": "c1", "ipAddress": "10.1.1.1", "sxpVpn": "default"}
    sxp_routes(mock, [cur], ["SXP"])
    delete = mock.delete("/ers/config/sxpconnections/c1").respond(204)
    preview, applied = await two_step(
        "ise_delete_trustsec_object", {"kind": "sxp_connection", "target": "10.1.1.1"}
    )
    assert preview["action"] == "Delete SXP connection to 10.1.1.1"
    assert applied["status"] == "applied" and delete.called


async def test_list_sxp_bindings(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/sxplocalbindings").respond(json=ers_page([{"id": "b1"}]))
    mock.get("/ers/config/sxplocalbindings/b1").respond(
        json={
            "ERSSxpLocalBindings": {
                "id": "b1",
                "ipAddressOrHost": "10.9.9.9",
                "sxpVpn": "default,dc",
                "sgt": "Developers (8/0008)",
                "vns": "",
            }
        }
    )
    mock.get("/ers/config/sxpvpns").respond(json=ers_page([]))
    async with Client(make_server()) as c:
        r = await c.call_tool("ise_list_sxp_bindings", {"domain": "dc", "response_format": "json"})
    out = r.structured_content
    assert out is not None
    assert out["results"][0]["domains"] == ["default", "dc"]


async def test_push_trustsec_matrix(mock: respx.MockRouter) -> None:
    push = mock.put("/api/v1/trustsec/coa/push").respond(json={"success": {"message": "ok"}})
    preview, applied = await two_step(
        "ise_push_trustsec_matrix", {"coa_type": "SGACL"}, mcp_enable_dangerous=True
    )
    assert preview["status"] == "preview"
    assert json.loads(push.calls.last.request.content) == {"coaType": "SGACL"}
    assert applied["status"] == "applied"

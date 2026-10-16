from __future__ import annotations

import respx

from ise_mcp._core.spec import build_index
from ise_mcp._core.testing import call_tool
from ise_mcp.specs import MNT_DOC, ers_doc_from_data_model
from tests.unit.conftest import make_server

DATA_MODEL = {
    "network.networkdevice": [
        {
            "field": "authenticationSettings",
            "type": "authenticationSettings",
            "required": "Yes",
            "description": "",
            "defaultValue": "",
            "childNodes": [
                {
                    "field": "keyInputFormat",
                    "type": "enum",
                    "required": "Yes",
                    "defaultValue": "ASCII",
                    "description": "allowed values:ASCII,HEXADECIMAL",
                },
                {
                    "field": "radiusSharedSecret",
                    "type": "String",
                    "required": "No",
                    "description": "",
                    "defaultValue": "",
                },
            ],
        },
        {"field": "coaPort", "type": "Integer", "required": "Yes", "defaultValue": "1700", "description": ""},
        {
            "field": "NetworkDeviceGroupList",
            "type": "List",
            "required": "Yes",
            "defaultValue": "",
            "description": "",
        },
        {},
    ],
}

OPENAPI_GROUP = {
    "openapi": "3.0.1",
    "info": {"version": "1.0.0"},
    "paths": {
        "/api/v1/endpoint": {
            "get": {"operationId": "list", "summary": "Get all endpoints", "responses": {"200": {}}}
        }
    },
}


def test_ers_doc() -> None:
    doc = ers_doc_from_data_model(DATA_MODEL, "3.5")
    idx = build_index(doc, source="ers")
    methods = {(o.method, o.path) for o in idx.operations}
    assert ("POST", "/ers/config/networkdevice") in methods
    assert ("DELETE", "/ers/config/networkdevice/{id}") in methods
    schema = idx.schemas["ers.networkdevice"]
    assert "coaPort" in schema["fields"] and "name" in schema["required"]
    child = idx.schemas["ers.networkdevice.authenticationSettings"]
    assert "ASCII|HEXADECIMAL" in child["fields"]["keyInputFormat"]


def test_mnt_doc_indexes() -> None:
    idx = build_index(MNT_DOC, source="mnt")
    assert any(o.path.endswith("/Session/MACAddress/{mac}") for o in idx.operations)


async def test_spec_tools_merge_surfaces(mock: respx.MockRouter) -> None:
    mock.get("/api/swagger-resources").respond(json=[{"name": "Endpoints"}, {"name": "Broken"}])
    mock.get("/api/v3/api-docs", params={"group": "Endpoints"}).respond(json=OPENAPI_GROUP)
    mock.get("/api/v3/api-docs", params={"group": "Broken"}).respond(500, text="boom")
    mock.get("/ers/data-model.json").respond(json=DATA_MODEL)
    server = make_server()
    out = await call_tool(server, "ise_search_spec", {"query": "endpoint"})
    assert any(r["name"] == "GET /api/v1/endpoint" for r in out["results"])
    out = await call_tool(server, "ise_search_spec", {"query": "networkdevice", "source": "ers"})
    assert any(r["name"] == "POST /ers/config/networkdevice" for r in out["results"])
    out = await call_tool(server, "ise_search_spec", {"query": "session", "source": "mnt"})
    assert out["results"]


async def test_api_call_routes_to_surface(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/sgt").respond(json={"SearchResult": {"total": 0, "resources": []}})
    out = await call_tool(make_server(), "ise_api_call", {"path": "/ers/config/sgt", "source": "ers"})
    assert "SearchResult" in str(out)

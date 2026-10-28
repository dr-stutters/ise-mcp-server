"""I91 (#100): pxGrid Direct connectors (respx). The lab ISE 3.5 answered `GET /connector-config` with
`{"response": [], "version": "1.0.0"}` (2026-10-28); the connector entities below follow the 3.5 OpenAPI
'pxGrid Direct' group (ConnectorConfigInfo, ConnectorConfigInfoConnector, FetchUrl, ApiKeyProperties,
AttributeMapping, Schedule, TestConnectorResponse, SyncNowConfigGetResponse) and are synthetic. URLs use
example.com; the token is a made-up value."""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ise_mcp._core.testing import call_tool
from ise_mcp.tools.pxgrid_direct import connector_view
from tests.unit.conftest import make_server

CONFIG = "/api/v1/pxgrid-direct/connector-config"
NAME = "mcp-netbox-dcim"
URL = "https://netbox.example.com/api/dcim/devices/?limit=1000"
ENV = "ISE_PXGRID_DIRECT_NETBOX_TOKEN"
TOKEN = "nb-0123456789abcdef-made-up"
ATTRS = {"role": "role", "site": "site"}


def connector(**over: Any) -> dict[str, Any]:
    c: dict[str, Any] = {
        "connectorName": NAME,
        "connectorType": "urlfetcher",
        "protocol": "http",
        "description": "",
        "enabled": True,
        "skipCertificateValidations": False,
        "coaType": "nocoa",
        "url": {"bulkUrl": URL, "authenticationType": "apikey"},
        "flexibleUrl": {
            "bulk": {
                "url": URL,
                "method": "GET",
                "authenticationType": "apikey",
                "apiKeyProperties": {"keyType": "header", "headerName": "Authorization", "key": "******"},
            }
        },
        "attributes": {
            "topLevelObject": "results",
            "uniqueIdentifier": "id",
            "correlationIdentifier": "mac",
            "attributeMapping": [
                {"name": "role", "dictionaryName": "role", "includeInDictionary": True},
                {"name": "site", "dictionaryName": "site", "includeInDictionary": True},
            ],
        },
        "fullsyncSchedule": {"interval": 24, "intervalUnit": "hours", "startDate": "2026-10-28T20:00:00"},
    }
    c.update(over)
    return c


def listing(mock: respx.MockRouter, items: list[dict[str, Any]]) -> None:
    mock.get(CONFIG).respond(json={"response": [{"connector": c} for c in items], "version": "1.0.0"})


CREATE = {
    "name": NAME,
    "bulk_url": URL,
    "secret_env": ENV,
    "top_level_object": "results",
    "unique_id": "id",
    "correlation_id": "mac",
    "attributes": ATTRS,
    "start": "2026-10-28T20:00:00",
}


async def two_step(tool: str, args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    server = make_server(mcp_enable_writes=True)
    async with Client(server) as c:
        preview = (await c.call_tool(tool, args)).structured_content
        assert preview is not None
        if preview.get("status") != "preview":
            return preview, None
        done = (await c.call_tool(tool, {**args, "confirm": preview["confirm"]})).structured_content
        return preview, done


# --- ise_set_pxgrid_direct_connector -------------------------------------------------------------


async def test_create_from_env_token_never_shown(
    mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV, TOKEN)
    listing(mock, [])
    route = mock.post(CONFIG).respond(201, json={"response": {"connector": {"connectorName": NAME}}})
    preview, done = await two_step("ise_set_pxgrid_direct_connector", CREATE)
    assert preview["status"] == "preview", preview
    assert preview["action"] == f"Create pxGrid Direct connector {NAME}"
    p = preview["preview"]
    assert p["bulk_url"] == URL and p["auth"] == "apikey" and p["credential_set"] is True
    assert p["attributes"] == ATTRS and p["correlation_id"] == "mac"
    assert p["full_sync"] == "every 24 hours from 2026-10-28T20:00:00"
    assert any("Trusted Certificates" in s for s in preview["side_effects"])
    assert TOKEN not in json.dumps(preview)
    assert done is not None and TOKEN not in json.dumps(done)
    sent = json.loads(route.calls.last.request.content)["connector"]
    assert sent["connectorType"] == "urlfetcher" and sent["coaType"] == "nocoa"
    assert sent["flexibleUrl"]["bulk"]["apiKeyProperties"] == {
        "keyType": "header",
        "headerName": "Authorization",
        "key": f"Token {TOKEN}",
    }
    assert sent["attributes"]["attributeMapping"][0] == {
        "name": "role",
        "dictionaryName": "role",
        "includeInDictionary": True,
    }
    assert sent["skipCertificateValidations"] is False


async def test_create_basic_auth(mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ISE_PXGRID_DIRECT_CMDB_PW", TOKEN)
    listing(mock, [])
    route = mock.post(CONFIG).respond(201, json={})
    args = {**CREATE, "secret_env": "ISE_PXGRID_DIRECT_CMDB_PW", "username": "ise-reader", "coa": "reauth"}
    preview, done = await two_step("ise_set_pxgrid_direct_connector", args)
    assert preview["preview"]["auth"] == "basic" and preview["preview"]["username"] == "ise-reader"
    assert done is not None
    sent = json.loads(route.calls.last.request.content)["connector"]
    assert sent["url"]["userName"] == "ise-reader" and sent["url"]["password"] == TOKEN
    assert sent["flexibleUrl"]["bulk"]["basicAuthProperties"]["password"] == TOKEN
    assert sent["coaType"] == "reauth"


async def test_create_refuses_other_env_vars(mock: respx.MockRouter) -> None:
    listing(mock, [])
    with pytest.raises(ToolError, match="ISE_PXGRID_DIRECT_"):
        await call_tool(
            make_server(mcp_enable_writes=True),
            "ise_set_pxgrid_direct_connector",
            {**CREATE, "secret_env": "ISE_PASSWORD"},
        )


async def test_create_missing_fields_blocked(mock: respx.MockRouter) -> None:
    listing(mock, [])
    route = mock.post(CONFIG).respond(201, json={})
    out, _ = await two_step("ise_set_pxgrid_direct_connector", {"name": NAME, "bulk_url": URL})
    assert out["status"] == "blocked", out
    assert {b.split(" ")[0] for b in out["blockers"]} == {"unique_id", "correlation_id", "attributes"}
    assert not route.called


async def test_update_identical_is_no_change(mock: respx.MockRouter) -> None:
    listing(mock, [connector()])
    put = mock.put(f"{CONFIG}/{NAME}").respond(json={})
    args = {k: v for k, v in CREATE.items() if k not in ("secret_env", "start")}
    out, done = await two_step("ise_set_pxgrid_direct_connector", args)
    assert out["status"] == "no_change", out
    assert "confirm" not in out and done is None and not put.called


async def test_update_mapping_keeps_saved_token(mock: respx.MockRouter) -> None:
    listing(mock, [connector()])
    put = mock.put(f"{CONFIG}/{NAME}").respond(json={})
    preview, done = await two_step(
        "ise_set_pxgrid_direct_connector",
        {"name": NAME, "attributes": {"role": "role", "tenant": "tenant"}},
    )
    assert preview["status"] == "preview", preview
    changes = preview["preview"]["changes"]
    assert "attributes.tenant" in changes or "attributes" in changes, changes
    assert "credential" not in changes
    assert done is not None
    sent = json.loads(put.calls.last.request.content)["connector"]
    assert [m["dictionaryName"] for m in sent["attributes"]["attributeMapping"]] == ["role", "tenant"]
    assert sent["flexibleUrl"] == connector()["flexibleUrl"]  # untouched: the saved key goes back as is


async def test_update_url_sends_masked_key_back_unprefixed(mock: respx.MockRouter) -> None:
    listing(mock, [connector()])
    put = mock.put(f"{CONFIG}/{NAME}").respond(json={})
    new_url = "https://netbox.example.com/api/dcim/devices/?limit=500"
    preview, done = await two_step("ise_set_pxgrid_direct_connector", {"name": NAME, "bulk_url": new_url})
    assert preview["status"] == "preview", preview
    assert done is not None
    bulk = json.loads(put.calls.last.request.content)["connector"]["flexibleUrl"]["bulk"]
    assert bulk["url"] == new_url
    assert bulk["apiKeyProperties"]["key"] == "******"  # ISE's mask as returned, never 'Token ******'


async def test_update_scheme_with_masked_key_needs_secret(mock: respx.MockRouter) -> None:
    listing(mock, [connector()])
    put = mock.put(f"{CONFIG}/{NAME}").respond(json={})
    server = make_server(mcp_enable_writes=True)
    async with Client(server) as c:
        out = (
            await c.call_tool("ise_set_pxgrid_direct_connector", {"name": NAME, "token_scheme": "Bearer"})
        ).structured_content
    assert out is not None and "confirm" not in out, out
    assert "secret_env" in json.dumps(out)
    assert not put.called


async def test_update_new_token_counts_as_change(
    mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV, TOKEN)
    listing(mock, [connector()])
    put = mock.put(f"{CONFIG}/{NAME}").respond(json={})
    preview, done = await two_step("ise_set_pxgrid_direct_connector", {"name": NAME, "secret_env": ENV})
    assert preview["status"] == "preview", preview
    assert preview["preview"]["changes"]["credential"] == {"from": "******", "to": "******"}
    assert TOKEN not in json.dumps(preview)
    assert done is not None
    sent = json.loads(put.calls.last.request.content)["connector"]
    assert sent["flexibleUrl"]["bulk"]["apiKeyProperties"]["key"] == f"Token {TOKEN}"
    assert sent["flexibleUrl"]["bulk"]["url"] == URL


async def test_update_skip_cert_warns(mock: respx.MockRouter) -> None:
    listing(mock, [connector()])
    mock.put(f"{CONFIG}/{NAME}").respond(json={})
    preview, _ = await two_step(
        "ise_set_pxgrid_direct_connector", {"name": NAME, "skip_cert_validation": True}
    )
    assert preview["preview"]["changes"]["skip_cert_validation"] == {"from": False, "to": True}
    assert any("certificate" in s for s in preview["side_effects"])


# --- ise_pxgrid_direct_status / ise_test_pxgrid_direct -------------------------------------------


async def test_status_lists_connectors_with_sync(mock: respx.MockRouter) -> None:
    listing(mock, [connector()])
    mock.get(f"/api/v1/pxgrid-direct/syncNowStatus/{NAME}").respond(
        json={"response": {"connector": {"connectorName": NAME, "syncStatus": "SYNC COMPLETED"}}}
    )
    out = await call_tool(make_server(), "ise_pxgrid_direct_status", {})
    row = out["connectors"][0]
    assert row["name"] == NAME and row["sync_status"] == "SYNC COMPLETED" and row["sync_completed"] is True
    assert row["credential_set"] is True and "******" not in json.dumps(out)


async def test_status_one_record(mock: respx.MockRouter) -> None:
    listing(mock, [connector()])
    mock.get(f"/api/v1/pxgrid-direct/syncNowStatus/{NAME}").respond(
        json={"response": {"connector": {"connectorName": NAME, "syncStatus": "INPROGRESS"}}}
    )
    rec = {"id": 42, "mac": "00:00:5E:00:53:01", "role": "printer", "site": "branch-1"}
    mock.get(f"/api/v1/pxgrid-direct/push/{NAME}/42").respond(json={"data": [rec]})
    mock.get(f"/api/v1/pxgrid-direct/push/{NAME}/43").respond(404, json={"message": "not found"})
    out = await call_tool(make_server(), "ise_pxgrid_direct_status", {"name": NAME, "unique_id": "42"})
    assert out["record"] == rec and out["sync_completed"] is False
    assert f"'{NAME}:<attribute>" in out["next"]
    missing = await call_tool(make_server(), "ise_pxgrid_direct_status", {"name": NAME, "unique_id": "43"})
    assert missing.get("record") is None and "no record" in missing["record_note"]


async def test_status_unknown_connector(mock: respx.MockRouter) -> None:
    listing(mock, [])
    with pytest.raises(ToolError, match="No pxGrid Direct connector"):
        await call_tool(make_server(), "ise_pxgrid_direct_status", {"name": "nope"})


async def test_test_connector_masks_echoed_token(
    mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV, TOKEN)
    listing(mock, [connector()])
    data = {"count": 2, "results": [{"id": 42, "mac": "00:00:5E:00:53:01"}, {"id": 43, "mac": None}]}
    route = mock.post("/api/v1/pxgrid-direct/test-connector").respond(
        json={
            "connectorName": NAME,
            "status": "SUCCESS",
            "data": json.dumps(data),
            "error": None,
            "echo": f"Token {TOKEN}",
        }
    )
    out = await call_tool(make_server(), "ise_test_pxgrid_direct", {"name": NAME, "secret_env": ENV})
    assert out["passed"] is True and out["records"] == 2 and out["source_count"] == 2
    assert out["first_record"]["id"] == 42
    assert TOKEN not in json.dumps(out)
    sent = json.loads(route.calls.last.request.content)
    assert sent["authType"] == "apikey" and sent["authValues"]["key"] == f"Token {TOKEN}"
    assert sent["responseParsing"] == "results" and sent["uniqueID"] == "id" and sent["url"] == URL


async def test_test_connector_failure_hint(mock: respx.MockRouter) -> None:
    listing(mock, [connector()])
    mock.post("/api/v1/pxgrid-direct/test-connector").respond(
        json={"connectorName": NAME, "status": "FAILURE", "error": "401 Unauthorized"}
    )
    out = await call_tool(make_server(), "ise_test_pxgrid_direct", {"name": NAME})
    assert out["passed"] is False and out["error"] == "401 Unauthorized"
    assert "secret_env" in out["hint"]


# --- ise_delete_object kind='pxgrid_direct_connector' --------------------------------------------


async def test_delete_preview_and_apply(mock: respx.MockRouter) -> None:
    listing(mock, [connector()])
    route = mock.delete(f"{CONFIG}/{NAME}").respond(204)
    preview, done = await two_step("ise_delete_object", {"kind": "pxgrid_direct_connector", "target": NAME})
    assert preview["status"] == "preview", preview
    assert preview["action"] == f"Delete pxGrid Direct connector {NAME}"
    assert preview["preview"]["path"] == f"{CONFIG}/{NAME}" and preview["preview"]["method"] == "DELETE"
    assert any("stop matching" in s for s in preview["side_effects"])
    assert done is not None and done["result"] == {"deleted": NAME}
    assert route.called


async def test_delete_unknown(mock: respx.MockRouter) -> None:
    listing(mock, [])
    with pytest.raises(ToolError, match="No pxGrid Direct connector"):
        await call_tool(
            make_server(mcp_enable_writes=True),
            "ise_delete_object",
            {"kind": "pxgrid_direct_connector", "target": NAME},
        )


def test_view_never_holds_credentials() -> None:
    v = connector_view(connector())
    assert v["credential_set"] is True and v["token_header"] == "Authorization"
    assert "******" not in json.dumps(v)

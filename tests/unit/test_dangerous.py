from __future__ import annotations

import json
from typing import Any

import respx
from fastmcp import Client

from tests.unit.conftest import MISSING_SESSION, ers_page, fixture_text, make_server, xml

MAC = "02:00:5E:00:00:01"


async def two_step(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(server) as c:
        preview = (await c.call_tool(name, args)).structured_content
        if preview.get("status") != "preview":
            return preview, None
        applied = (await c.call_tool(name, {**args, "confirm": preview["confirm"]})).structured_content
        return preview, applied


async def test_dangerous_hidden_without_flag() -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_coa_reauth" not in names and "ise_create_nad" in names


async def test_coa_reauth(mock: respx.MockRouter) -> None:
    mock.get(f"/admin/API/mnt/Session/MACAddress/{MAC}").respond(text=fixture_text("mnt_session.xml"))
    coa = mock.get(f"/admin/API/mnt/CoA/Reauth/ise/{MAC}/0").respond(
        text=xml('<remoteCoA requestType="reauth"><results>true</results></remoteCoA>')
    )
    preview, applied = await two_step("ise_coa_reauth", {"mac": "02-00-5e-00-00-01"})
    assert preview["preview"]["network_device_name"] == "mcp-test-radius-client"
    assert applied["result"]["coa_acknowledged"] is True
    assert coa.called


async def test_coa_disconnect_unacknowledged(mock: respx.MockRouter) -> None:
    mock.get(f"/admin/API/mnt/Session/MACAddress/{MAC}").respond(text=fixture_text("mnt_session.xml"))
    coa = mock.get(f"/admin/API/mnt/CoA/Disconnect/ise/{MAC}/1/192.0.2.50/10.250.0.11").respond(
        text=xml('<remoteCoA requestType="disconnect"><results>false</results></remoteCoA>')
    )
    preview, applied = await two_step("ise_coa_disconnect", {"mac": MAC, "disconnect_type": "port_bounce"})
    assert "port goes down" in preview["side_effects"][0]
    assert applied["result"]["coa_acknowledged"] is False and "note" in applied["result"]
    assert coa.called


async def test_coa_blocked_without_session(mock: respx.MockRouter) -> None:
    mock.get(f"/admin/API/mnt/Session/MACAddress/{MAC}").respond(500, text=MISSING_SESSION)
    preview, _ = await two_step("ise_coa_reauth", {"mac": MAC})
    assert preview["status"] == "blocked"


async def test_apply_and_clear_anc(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/ancpolicy", params={"filter": "name.EQ.Quarantine"}).respond(
        json=ers_page([{"id": "a1", "name": "Quarantine"}])
    )
    mock.get("/ers/config/ancpolicy/a1").respond(
        json={"ErsAncPolicy": {"id": "a1", "name": "Quarantine", "actions": ["QUARANTINE"]}}
    )
    mock.get(f"/admin/API/mnt/Session/MACAddress/{MAC}").respond(500, text=MISSING_SESSION)
    apply = mock.put("/ers/config/ancendpoint/apply").respond(204)
    preview, applied = await two_step("ise_apply_anc", {"mac": MAC, "policy": "Quarantine"})
    assert preview["preview"]["actions"] == ["QUARANTINE"]
    assert applied["status"] == "applied"
    sent = json.loads(apply.calls.last.request.content)["OperationAdditionalData"]["additionalData"]
    assert {"name": "macAddress", "value": MAC} in sent and {
        "name": "policyName",
        "value": "Quarantine",
    } in sent

    mock.get("/ers/config/ancendpoint").respond(json=ers_page([]))
    preview, _ = await two_step("ise_clear_anc", {"mac": MAC})
    assert preview["status"] == "blocked"


async def test_delete_default_rule_blocked(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/policy/network-access/policy-set").respond(
        json={"response": [{"id": "s1", "name": "Wired"}]}
    )
    mock.get("/api/v1/policy/network-access/policy-set/s1/authorization").respond(
        json={
            "response": [
                {"rule": {"id": "r1", "name": "Printers", "rank": 0}},
                {"rule": {"id": "r2", "name": "Default", "rank": 1, "default": True}},
            ]
        }
    )
    mock.get("/api/v1/policy/network-access/policy-set/s1/authentication").respond(json={"response": []})
    mock.get("/api/v1/policy/network-access/policy-set/s1/exception").respond(json={"response": []})
    delete = mock.delete("/api/v1/policy/network-access/policy-set/s1/authorization/r1").respond(204)
    preview, _ = await two_step("ise_delete_policy_rule", {"policy_set": "Wired", "rule": "Default"})
    assert preview["status"] == "blocked"
    preview, applied = await two_step("ise_delete_policy_rule", {"policy_set": "Wired", "rule": "Printers"})
    assert "fall through to 'Default'" in preview["side_effects"][0]
    assert applied["status"] == "applied" and delete.called


async def test_delete_policy_set_default_blocked(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/policy/network-access/policy-set").respond(
        json={"response": [{"id": "s0", "name": "Default", "default": True}]}
    )
    for section in ("authorization", "authentication", "exception"):
        mock.get(f"/api/v1/policy/network-access/policy-set/s0/{section}").respond(json={"response": []})
    preview, _ = await two_step("ise_delete_policy_set", {"policy_set": "Default"})
    assert preview["status"] == "blocked"


async def test_delete_system_cert_in_use_blocked(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/certs/system-certificate/ise").respond(
        json={"response": [{"id": "c1", "friendlyName": "Default", "usedBy": "EAP Authentication, Admin"}]}
    )
    preview, _ = await two_step("ise_delete_certificate", {"cert_id": "c1", "kind": "system", "node": "ise"})
    assert preview["status"] == "blocked"


async def test_delete_nad(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.sw1"}).respond(
        json=ers_page([{"id": "n1", "name": "sw1"}])
    )
    mock.get("/ers/config/networkdevice/n1").respond(
        json={
            "NetworkDevice": {
                "id": "n1",
                "name": "sw1",
                "authenticationSettings": {"radiusSharedSecret": "zzz-secret"},
            }
        }
    )
    delete = mock.delete("/ers/config/networkdevice/n1").respond(204)
    preview, applied = await two_step("ise_delete_nad", {"device": "sw1"})
    assert "zzz-secret" not in json.dumps(preview)
    assert "11007" in preview["side_effects"][0]
    assert applied["status"] == "applied" and delete.called

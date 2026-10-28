"""I89: random and changing MAC (RCM) and endpoint ownership (LSD settings)."""

from __future__ import annotations

import json

import respx

from ise_mcp._core.testing import call_tool
from tests.unit.conftest import make_server
from tests.unit.test_writes import two_step

LSD = "/api/v1/lsd/updateLsdSettings"


async def test_get_mac_randomization_on(mock: respx.MockRouter) -> None:
    # Shape recorded from ISE 3.5: a flat object, no "response" wrapper.
    mock.get(LSD).respond(json={"enableEPO": True, "enableRCM": True})
    out = await call_tool(make_server(), "ise_get_mac_randomization", {})
    assert out["endpoint_ownership"] is True and out["rcm"] is True
    assert out["rcm_effective"] is True and "note" not in out


async def test_get_mac_randomization_epo_off(mock: respx.MockRouter) -> None:
    mock.get(LSD).respond(json={"response": {"enableEPO": False, "enableRCM": True}})
    out = await call_tool(make_server(), "ise_get_mac_randomization", {})
    assert out["endpoint_ownership"] is False and out["rcm_effective"] is False
    assert "RCM as off" in out["note"]


async def test_get_mac_randomization_unexpected(mock: respx.MockRouter) -> None:
    from fastmcp import Client

    mock.get(LSD).respond(json={"something": "else"})
    async with Client(make_server()) as c:
        r = await c.call_tool("ise_get_mac_randomization", {}, raise_on_error=False)
    assert r.is_error and "Unexpected LSD settings" in str(r.content[0].text)  # type: ignore[union-attr]


async def test_set_rcm_on_preview_and_apply(mock: respx.MockRouter) -> None:
    mock.get(LSD).respond(json={"enableEPO": True, "enableRCM": False})
    put = mock.put(LSD).respond(json={"enableEPO": True, "enableRCM": True})
    preview, applied = await two_step("ise_set_mac_randomization", {"rcm": True})
    assert preview["status"] == "preview"
    assert preview["preview"]["changes"] == {"enableRCM": {"from": False, "to": True}}
    assert preview["preview"]["request"] == {"enableEPO": True, "enableRCM": True}
    assert any("new random MAC" in s for s in preview["side_effects"])
    assert applied["status"] == "applied"
    # Both fields always go in the PUT, the unchanged one at its current value.
    assert json.loads(put.calls.last.request.content) == {"enableEPO": True, "enableRCM": True}


async def test_set_noop(mock: respx.MockRouter) -> None:
    mock.get(LSD).respond(json={"enableEPO": True, "enableRCM": True})
    put = mock.put(LSD).respond(json={})
    preview, applied = await two_step("ise_set_mac_randomization", {"endpoint_ownership": True, "rcm": True})
    assert preview["status"] == "no_change" and applied is None
    assert "confirm" not in preview and not put.called


async def test_set_epo_off_with_rcm_on_blocked(mock: respx.MockRouter) -> None:
    mock.get(LSD).respond(json={"enableEPO": True, "enableRCM": True})
    put = mock.put(LSD).respond(json={})
    preview, applied = await two_step("ise_set_mac_randomization", {"endpoint_ownership": False, "rcm": True})
    assert preview["status"] == "blocked" and applied is None
    assert any("RCM needs endpoint ownership" in b for b in preview["blockers"])
    assert not put.called


async def test_set_epo_off_turns_rcm_off(mock: respx.MockRouter) -> None:
    mock.get(LSD).respond(json={"enableEPO": True, "enableRCM": True})
    put = mock.put(LSD).respond(json={"enableEPO": False, "enableRCM": False})
    preview, applied = await two_step("ise_set_mac_randomization", {"endpoint_ownership": False})
    assert preview["preview"]["changes"] == {
        "enableEPO": {"from": True, "to": False},
        "enableRCM": {"from": True, "to": False},
    }
    assert any("ISE forces enableRCM off" in s for s in preview["side_effects"])
    assert any("no longer linked" in s for s in preview["side_effects"])
    assert applied["status"] == "applied"
    assert json.loads(put.calls.last.request.content) == {"enableEPO": False, "enableRCM": False}


async def test_set_needs_writes(mock: respx.MockRouter) -> None:
    from fastmcp import Client

    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_get_mac_randomization" in names and "ise_set_mac_randomization" not in names

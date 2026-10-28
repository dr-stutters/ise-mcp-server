"""#90: ise_delete_object kind='egress_cell' (one explicit TrustSec matrix cell, never ANY-ANY)."""

from __future__ import annotations

import respx
from fastmcp import Client

from tests.unit.conftest import ers_page, make_server
from tests.unit.test_egress_default import (
    DEFAULT_CELL,
    DENY_ACL,
    EMP_ID,
    EMP_SRV_CELL,
    SRV_ID,
    any_any,
    cell,
    mock_matrix,
)
from tests.unit.test_writes import two_step


def mock_pair(mock: respx.MockRouter, src: tuple[str, str], dst: tuple[str, str], hits: list[str]) -> None:
    for sid, name in (src, dst):
        mock.get("/ers/config/sgt", params={"filter": f"name.EQ.{name}"}).respond(
            json=ers_page([{"id": sid, "name": name}])
        )
    mock.get(
        "/ers/config/egressmatrixcell",
        params={"filter": [f"sgtSrcName.EQ.{src[1]}", f"sgtDstName.EQ.{dst[1]}"]},
    ).respond(json=ers_page([{"id": h} for h in hits]))


EMP_SRV = cell(EMP_SRV_CELL, "Employees-Servers", EMP_ID, SRV_ID, "MONITOR", "NONE", [DENY_ACL])


async def test_delete_egress_cell_by_sgt_names(mock: respx.MockRouter) -> None:
    mock_matrix(mock, [any_any(), EMP_SRV], sessions=False)
    mock_pair(mock, (EMP_ID, "Employees"), (SRV_ID, "Servers"), [EMP_SRV_CELL])
    delete = mock.delete(f"/ers/config/egressmatrixcell/{EMP_SRV_CELL}").respond(204)
    preview, applied = await two_step(
        "ise_delete_object", {"kind": "egress_cell", "target": "Employees -> Servers"}
    )
    assert preview["status"] == "preview", preview
    assert preview["action"] == "Delete egress cell Employees -> Servers: Deny IP then NONE (MONITOR)"
    d = preview["preview"]
    assert d["source_sgt"] == "Employees" and d["destination_sgt"] == "Servers"
    assert d["sgacls"] == ["Deny IP"] and d["status"] == "MONITOR" and d["default_rule"] == "NONE"
    side = " ".join(preview["side_effects"])
    assert "ANY-ANY default" in side and "ise_push_trustsec_matrix" in side
    assert applied is not None and delete.called


async def test_delete_egress_cell_by_id(mock: respx.MockRouter) -> None:
    mock_matrix(mock, [any_any(), EMP_SRV], sessions=False)
    delete = mock.delete(f"/ers/config/egressmatrixcell/{EMP_SRV_CELL}").respond(204)
    preview, applied = await two_step("ise_delete_object", {"kind": "egress_cell", "target": EMP_SRV_CELL})
    assert preview["status"] == "preview", preview
    assert preview["preview"]["source_sgt"] == "Employees"
    assert preview["preview"]["destination_sgt"] == "Servers"
    assert applied is not None and delete.call_count == 1


def mock_no_any_sgt(mock: respx.MockRouter) -> respx.Route:
    """Live ISE (3.5): ERS lists no SGT named ANY (#143). Added before mock_matrix so it wins."""
    return mock.get("/ers/config/sgt", params={"filter": "name.EQ.ANY"}).respond(json=ers_page([]))


async def test_delete_egress_cell_any_any_blocked(mock: respx.MockRouter) -> None:
    sgt_lookup = mock_no_any_sgt(mock)
    mock_matrix(mock, [any_any(), EMP_SRV], sessions=False)
    delete = mock.delete(f"/ers/config/egressmatrixcell/{DEFAULT_CELL}").respond(204)
    for target in ("ANY-ANY", "ANY->ANY", "any->any", " any - any ", "ANY -> ANY", DEFAULT_CELL):
        preview, applied = await two_step("ise_delete_object", {"kind": "egress_cell", "target": target})
        assert preview["status"] == "blocked", (target, preview)
        assert "ANY-ANY is the matrix default" in " ".join(preview["blockers"])
        assert "ise_set_default_egress_rule" in " ".join(preview["blockers"])
        assert preview["preview"]["source_sgt"] == "ANY" and preview["preview"]["destination_sgt"] == "ANY"
        assert applied is None
    assert not delete.called
    assert not sgt_lookup.called


async def test_delete_egress_cell_any_any_unfiltered_fallback(mock: respx.MockRouter) -> None:
    """If the sgtSrcName filter finds nothing, the default cell is found by name in a full scan."""
    mock_no_any_sgt(mock)
    mock.get("/ers/config/egressmatrixcell", params={"filter": "sgtSrcName.EQ.ANY"}).respond(
        json=ers_page([])
    )
    mock_matrix(mock, [EMP_SRV, any_any()], sessions=False)
    delete = mock.delete(f"/ers/config/egressmatrixcell/{DEFAULT_CELL}").respond(204)
    preview, applied = await two_step("ise_delete_object", {"kind": "egress_cell", "target": "ANY-ANY"})
    assert preview["status"] == "blocked", preview
    assert preview["preview"]["id"] == DEFAULT_CELL
    assert applied is None and not delete.called


async def test_delete_egress_cell_any_any_unreadable(mock: respx.MockRouter) -> None:
    mock_no_any_sgt(mock)
    mock.get("/ers/config/egressmatrixcell", params={"filter": "sgtSrcName.EQ.ANY"}).respond(
        json=ers_page([])
    )
    mock_matrix(mock, [EMP_SRV], sessions=False)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool(
            "ise_delete_object", {"kind": "egress_cell", "target": "ANY-ANY"}, raise_on_error=False
        )
        assert r.is_error and "ANY-ANY default egress cell could not be read" in str(r.content)


async def test_delete_egress_cell_missing_or_malformed(mock: respx.MockRouter) -> None:
    mock_matrix(mock, [any_any()], sessions=False)
    mock_pair(mock, (EMP_ID, "Employees"), (SRV_ID, "Servers"), [])
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool(
            "ise_delete_object", {"kind": "egress_cell", "target": "Employees->Servers"}, raise_on_error=False
        )
        assert r.is_error and "No egress cell Employees -> Servers" in str(r.content)
        r = await c.call_tool(
            "ise_delete_object", {"kind": "egress_cell", "target": "Employees-Servers"}, raise_on_error=False
        )
        assert r.is_error and "SOURCE->DESTINATION" in str(r.content)

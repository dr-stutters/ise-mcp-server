"""I86: egress cell MONITOR status, the status filter on the matrix, and the ANY-ANY default rule."""

from __future__ import annotations

import json
from typing import Any

import respx

from ise_mcp._core.testing import call_tool
from tests.unit.conftest import ers_page, fixture_text, make_server
from tests.unit.test_writes import two_step

ANY_ID = "a0000000-0000-4000-8000-00000000ffff"
EMP_ID = "a0000000-0000-4000-8000-000000000004"
SRV_ID = "a0000000-0000-4000-8000-000000000010"
TSD_ID = "a0000000-0000-4000-8000-000000000002"
DENY_ACL = "b0000000-0000-4000-8000-000000000001"
PERMIT_ACL = "b0000000-0000-4000-8000-000000000002"
DEFAULT_CELL = "c0000000-0000-4000-8000-000000000000"
EMP_SRV_CELL = "c0000000-0000-4000-8000-000000000001"
MAC = "02:00:5E:00:00:01"

SGTS = [
    {"id": ANY_ID, "name": "ANY", "value": 65535},
    {"id": TSD_ID, "name": "TrustSec_Devices", "value": 2},
    {"id": EMP_ID, "name": "Employees", "value": 4},
    {"id": SRV_ID, "name": "Servers", "value": 16},
]


def cell(cid: str, name: str, src: str, dst: str, status: str, rule: str, acls: list[str]) -> dict[str, Any]:
    return {
        "id": cid,
        "name": name,
        "description": "",
        "sourceSgtId": src,
        "destinationSgtId": dst,
        "matrixCellStatus": status,
        "defaultRule": rule,
        "sgacls": acls,
    }


def any_any(rule: str = "PERMIT_IP", status: str = "ENABLED") -> dict[str, Any]:
    return cell(DEFAULT_CELL, "ANY-ANY", ANY_ID, ANY_ID, status, rule, [PERMIT_ACL])


def mock_matrix(mock: respx.MockRouter, cells: list[dict[str, Any]], *, sessions: bool = True) -> None:
    mock.get("/ers/config/sgt").respond(json=ers_page([{"id": s["id"], "name": s["name"]} for s in SGTS]))
    for s in SGTS:
        mock.get(f"/ers/config/sgt/{s['id']}").respond(json={"Sgt": s})
    mock.get("/ers/config/sgacl").respond(
        json=ers_page([{"id": DENY_ACL, "name": "Deny IP"}, {"id": PERMIT_ACL, "name": "Permit IP"}])
    )
    default = [c for c in cells if c["name"] == "ANY-ANY"]
    mock.get("/ers/config/egressmatrixcell", params={"filter": "sgtSrcName.EQ.ANY"}).respond(
        json=ers_page([{"id": c["id"], "name": c["name"]} for c in default])
    )
    mock.get("/ers/config/egressmatrixcell").respond(
        json=ers_page([{"id": c["id"], "name": c["name"]} for c in cells])
    )
    for c in cells:
        mock.get(f"/ers/config/egressmatrixcell/{c['id']}").respond(json={"EgressMatrixCell": c})
        mock.put(f"/ers/config/egressmatrixcell/{c['id']}").respond(json={})
    if sessions:
        mock.get("/admin/API/mnt/Session/ActiveList").respond(text=fixture_text("mnt_activelist.xml"))
        session = fixture_text("mnt_session.xml").replace(
            "</sessionParameters>", "<cts_security_group>Employees</cts_security_group></sessionParameters>"
        )
        mock.get(f"/admin/API/mnt/Session/MACAddress/{MAC}").respond(text=session)


async def test_matrix_status_filter(mock: respx.MockRouter) -> None:
    cells = [
        any_any(),
        cell(EMP_SRV_CELL, "Employees-Servers", EMP_ID, SRV_ID, "MONITOR", "NONE", [DENY_ACL]),
        cell(
            "c0000000-0000-4000-8000-000000000002", "Servers-Employees", SRV_ID, EMP_ID, "ENABLED", "NONE", []
        ),
    ]
    mock_matrix(mock, cells, sessions=False)
    out = await call_tool(
        make_server(), "ise_get_egress_matrix", {"status": "MONITOR", "response_format": "json"}
    )
    assert [(r["source"], r["destination"], r["status"]) for r in out["results"]] == [
        ("Employees (4)", "Servers (16)", "MONITOR")
    ]
    assert out["results"][0]["sgacls"] == ["Deny IP"]


async def test_set_egress_policy_monitor_status(mock: respx.MockRouter) -> None:
    current = cell(EMP_SRV_CELL, "Employees-Servers", EMP_ID, SRV_ID, "ENABLED", "NONE", [DENY_ACL])
    mock_matrix(mock, [any_any(), current], sessions=False)
    mock.get("/ers/config/sgt", params={"filter": "name.EQ.Employees"}).respond(
        json=ers_page([{"id": EMP_ID, "name": "Employees"}])
    )
    mock.get("/ers/config/sgt", params={"filter": "name.EQ.Servers"}).respond(
        json=ers_page([{"id": SRV_ID, "name": "Servers"}])
    )
    mock.get(
        "/ers/config/egressmatrixcell",
        params={"filter": ["sgtSrcName.EQ.Employees", "sgtDstName.EQ.Servers"]},
    ).respond(json=ers_page([{"id": EMP_SRV_CELL, "name": "Employees-Servers"}]))
    put = mock.put(f"/ers/config/egressmatrixcell/{EMP_SRV_CELL}").respond(json={})
    args = {
        "source_sgt": "Employees",
        "destination_sgt": "Servers",
        "sgacls": ["Deny IP"],
        "status": "MONITOR",
    }
    preview, applied = await two_step("ise_set_egress_policy", args)
    assert preview["status"] == "preview", preview
    assert "(MONITOR)" in preview["action"]
    assert any("Cell status ENABLED -> MONITOR" in s for s in preview["side_effects"])
    assert any("ise_push_trustsec_matrix" in s for s in preview["side_effects"])
    assert applied is not None
    body = json.loads(put.calls.last.request.content)["EgressMatrixCell"]
    assert body["matrixCellStatus"] == "MONITOR" and body["sgacls"] == [DENY_ACL]


async def test_set_egress_policy_keeps_status_and_enabled_alias(mock: respx.MockRouter) -> None:
    current = cell(EMP_SRV_CELL, "Employees-Servers", EMP_ID, SRV_ID, "MONITOR", "NONE", [DENY_ACL])
    mock_matrix(mock, [any_any(), current], sessions=False)
    mock.get("/ers/config/sgt", params={"filter": "name.EQ.Employees"}).respond(
        json=ers_page([{"id": EMP_ID, "name": "Employees"}])
    )
    mock.get("/ers/config/sgt", params={"filter": "name.EQ.Servers"}).respond(
        json=ers_page([{"id": SRV_ID, "name": "Servers"}])
    )
    mock.get(
        "/ers/config/egressmatrixcell",
        params={"filter": ["sgtSrcName.EQ.Employees", "sgtDstName.EQ.Servers"]},
    ).respond(json=ers_page([{"id": EMP_SRV_CELL, "name": "Employees-Servers"}]))
    mock.put(f"/ers/config/egressmatrixcell/{EMP_SRV_CELL}").respond(json={})
    base = {"source_sgt": "Employees", "destination_sgt": "Servers", "sgacls": ["Deny IP"]}
    # No status: an existing MONITOR cell stays in MONITOR (only the SGACL/catch-all change).
    preview, _ = await two_step("ise_set_egress_policy", {**base, "default_rule": "DENY_IP"})
    assert "(MONITOR)" in preview["action"]
    assert "matrixCellStatus" not in preview["preview"]["changes"]
    # The deprecated flag still works ...
    preview, _ = await two_step("ise_set_egress_policy", {**base, "enabled": False})
    assert "(DISABLED)" in preview["action"]
    # ... and contradicting it is refused.
    server = make_server(mcp_enable_writes=True)
    from fastmcp import Client

    async with Client(server) as c:
        r = await c.call_tool(
            "ise_set_egress_policy", {**base, "enabled": True, "status": "MONITOR"}, raise_on_error=False
        )
        assert r.is_error and "contradicts" in str(r.content)
        r = await c.call_tool(
            "ise_set_egress_policy",
            {"source_sgt": "ANY", "destination_sgt": "ANY", "sgacls": []},
            raise_on_error=False,
        )
        assert r.is_error and "ise_set_default_egress_rule" in str(r.content)


async def test_default_rule_tier() -> None:
    from fastmcp import Client

    async with Client(make_server(mcp_enable_writes=True)) as c:
        assert "ise_set_default_egress_rule" not in {t.name for t in await c.list_tools()}
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        assert "ise_set_default_egress_rule" in {t.name for t in await c.list_tools()}


async def test_default_rule_deny_preview_and_apply(mock: respx.MockRouter) -> None:
    cells = [
        any_any(status="MONITOR"),
        cell(EMP_SRV_CELL, "Employees-Servers", EMP_ID, SRV_ID, "MONITOR", "NONE", [DENY_ACL]),
    ]
    mock_matrix(mock, cells)
    put = mock.put(f"/ers/config/egressmatrixcell/{DEFAULT_CELL}").respond(json={})
    preview, applied = await two_step(
        "ise_set_default_egress_rule", {"rule": "DENY_IP"}, mcp_enable_dangerous=True
    )
    assert preview["status"] == "preview", preview
    d = preview["preview"]
    assert d["explicit_cells"] == 1 and d["explicit_cells_by_status"] == {"MONITOR": 1}
    assert d["sgts"] == 3  # ANY is not a real SGT
    # 3 x 3 ordered pairs, one has a cell; the Employees source (a live session) is listed first.
    assert d["pairs_without_cell"] == 8
    assert d["pairs_without_cell_list"][0].startswith("Employees (4) -> ")
    assert "Employees (4) -> Servers (16)" not in d["pairs_without_cell_list"]
    assert d["sessions"] == {"active_sessions": 1, "by_sgt": {"Employees": 1}}
    assert d["from"] == {"default_rule": "PERMIT_IP", "sgacls": ["Permit IP"], "status": "MONITOR"}
    side = " ".join(preview["side_effects"])
    assert "8 SGT pair(s) without an explicit cell is DENIED" in side
    assert "TrustSec_Devices" in side and "ise_push_trustsec_matrix" in side
    assert "not in MONITOR first" not in side  # it was in MONITOR
    assert preview["blast_radius"] == 1
    assert applied is not None
    body = json.loads(put.calls.last.request.content)["EgressMatrixCell"]
    assert body["defaultRule"] == "DENY_IP" and body["matrixCellStatus"] == "ENABLED"
    assert body["sgacls"] == [] and body["name"] == "ANY-ANY"


async def test_default_rule_monitor_and_warnings(mock: respx.MockRouter) -> None:
    tsd = cell("c0000000-0000-4000-8000-000000000009", "TSD-TSD", TSD_ID, TSD_ID, "ENABLED", "PERMIT_IP", [])
    mock_matrix(mock, [any_any(), tsd])
    preview, _ = await two_step(
        "ise_set_default_egress_rule",
        {"rule": "DENY_IP", "status": "MONITOR", "sgacls": ["Deny IP"]},
        mcp_enable_dangerous=True,
    )
    side = " ".join(preview["side_effects"])
    assert "is counted (MONITOR) but passes" in side
    assert "TrustSec_Devices -> TrustSec_Devices cell" not in side
    assert preview["preview"]["to"]["sgacls"] == ["Deny IP"]
    # Straight to ENABLED from an enforced PERMIT default: the preview says MONITOR comes first.
    preview, _ = await two_step("ise_set_default_egress_rule", {"rule": "DENY_IP"}, mcp_enable_dangerous=True)
    assert "not in MONITOR first" in " ".join(preview["side_effects"])


async def test_default_rule_no_change_blocked(mock: respx.MockRouter) -> None:
    mock_matrix(mock, [any_any()])
    preview, applied = await two_step(
        "ise_set_default_egress_rule",
        {"rule": "PERMIT_IP", "sgacls": ["Permit IP"]},
        mcp_enable_dangerous=True,
    )
    assert preview["status"] == "blocked" and "already PERMIT_IP" in preview["blockers"][0]
    assert applied is None


async def test_default_rule_sessions_unreadable(mock: respx.MockRouter) -> None:
    mock_matrix(mock, [any_any(rule="DENY_IP")], sessions=False)
    mock.get("/admin/API/mnt/Session/ActiveList").respond(500, text="boom")
    preview, _ = await two_step(
        "ise_set_default_egress_rule", {"rule": "PERMIT_IP"}, mcp_enable_dangerous=True
    )
    assert preview["status"] == "preview"
    assert "error" in preview["preview"]["sessions"]
    assert preview.get("blast_radius") is None
    assert "permitted again" in " ".join(preview["side_effects"])


async def test_default_rule_disabled_cell_counts_as_uncovered(mock: respx.MockRouter) -> None:
    # A DISABLED cell is not enforced: its pair falls to the default like a pair with no cell.
    cells = [
        any_any(status="MONITOR"),
        cell(EMP_SRV_CELL, "Employees-Servers", EMP_ID, SRV_ID, "DISABLED", "NONE", [DENY_ACL]),
        cell("c0000000-0000-4000-8000-000000000009", "TSD-TSD", TSD_ID, TSD_ID, "DISABLED", "PERMIT_IP", []),
    ]
    mock_matrix(mock, cells)
    preview, _ = await two_step("ise_set_default_egress_rule", {"rule": "DENY_IP"}, mcp_enable_dangerous=True)
    d = preview["preview"]
    assert d["explicit_cells"] == 2 and d["explicit_cells_by_status"] == {"DISABLED": 2}
    assert d["pairs_without_cell"] == 9
    assert "Employees (4) -> Servers (16)" in d["pairs_without_cell_list"]
    assert "2 DISABLED cell(s)" in d["disabled_cells_note"]
    assert "No enabled TrustSec_Devices" in " ".join(preview["side_effects"])

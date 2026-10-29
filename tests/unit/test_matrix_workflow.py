"""I76 slice S: ise_get_egress_matrix reads the matrix work-process settings and warns when the cells
may not be the matrix a device enforces (multiple matrices, staging/production, DEFCON)."""

from __future__ import annotations

import copy
from typing import Any

import respx

from ise_mcp._core.testing import call_tool
from tests.unit.conftest import ers_page, fixture_json, make_server
from tests.unit.test_egress_default import EMP_ID, EMP_SRV_CELL, SRV_ID, any_any, cell, mock_matrix

WORKFLOW = "/api/v1/trustsec/matrix-workflow-settings"
NAD_ID = "d0000000-0000-4000-8000-000000000001"


def workflow(mode: str = "SINGLE_MATRIX", *, staging: bool = False, defcons: bool = False) -> dict[str, Any]:
    """The live single-matrix answer (MatrixWorkflowSettingsResponse) with the given switches."""
    body = copy.deepcopy(fixture_json("matrix_workflow_settings.json"))
    body["response"]["matrixMode"] = mode
    body["response"]["approvalWorkflow"]["enableApprovalWorkflow"] = staging
    body["response"]["useDefcons"] = defcons
    return body


def mock_cells(mock: respx.MockRouter) -> None:
    mock_matrix(
        mock,
        [any_any(), cell(EMP_SRV_CELL, "Employees-Servers", EMP_ID, SRV_ID, "ENABLED", "DENY_IP", [])],
        sessions=False,
    )


def mock_nad(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/networkdevice/name/sw1").respond(
        json={"NetworkDevice": {"id": NAD_ID, "name": "sw1"}}
    )
    mock.get("/ers/config/networkdevice").respond(json=ers_page([{"id": NAD_ID, "name": "sw1"}]))
    mock.get(f"/ers/config/networkdevice/{NAD_ID}").respond(
        json={"NetworkDevice": {"id": NAD_ID, "name": "sw1"}}
    )


async def matrix(args: dict[str, Any] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = await call_tool(
        make_server(), "ise_get_egress_matrix", {"response_format": "json", **(args or {})}
    )
    return out


async def test_single_matrix_no_warning(mock: respx.MockRouter) -> None:
    mock_cells(mock)
    out = await matrix({"source": "Employees"})
    assert out["matrix"] == {"mode": "SINGLE_MATRIX", "work_process": False, "defcons": False}
    assert "warnings" not in out and "matrix_required" not in out
    assert [(r["source"], r["destination"]) for r in out["results"]] == [("Employees (4)", "Servers (16)")]


async def test_multiple_matrices_warns(mock: respx.MockRouter) -> None:
    mock_cells(mock)
    mock.get(WORKFLOW, name="matrix_workflow").respond(json=workflow("MULTIPLE_MATRICES"))
    out = await matrix({"source": "Employees"})
    assert out["matrix"]["mode"] == "MULTIPLE_MATRICES"
    assert len(out["warnings"]) == 1 and "multiple-matrix mode" in out["warnings"][0]
    assert "Production/default matrix" in out["warnings"][0]
    assert "matrix_required" not in out  # no NAD named: a warning, not a question
    assert out["results"]  # the cells are still answered


async def test_multiple_matrices_with_nad_asks_for_matrix(mock: respx.MockRouter) -> None:
    mock_cells(mock)
    mock_nad(mock)
    mock.get(WORKFLOW, name="matrix_workflow").respond(json=workflow("MULTIPLE_MATRICES"))
    out = await matrix({"source": "Employees", "destination": "Servers", "nad": "sw1"})
    assert out["nad"] == "sw1"
    assert "'sw1'" in out["matrix_required"]
    assert "Name the matrix 'sw1' belongs to" in out["warnings"][0]


async def test_single_matrix_with_nad_no_question(mock: respx.MockRouter) -> None:
    mock_cells(mock)
    mock_nad(mock)
    out = await matrix({"nad": "sw1"})
    assert out["nad"] == "sw1" and "matrix_required" not in out and "warnings" not in out


async def test_staging_and_defcon_warn(mock: respx.MockRouter) -> None:
    mock_cells(mock)
    mock.get(WORKFLOW, name="matrix_workflow").respond(json=workflow(staging=True, defcons=True))
    out = await matrix()
    assert out["matrix"] == {"mode": "SINGLE_MATRIX", "work_process": True, "defcons": True}
    text = " ".join(out["warnings"])
    assert "staging/production work process is on" in text and "DEFCON" in text
    assert "matrix_required" not in out


async def test_workflow_unreadable_still_answers(mock: respx.MockRouter) -> None:
    mock_cells(mock)
    for code in (404, 403):
        mock.get(WORKFLOW, name="matrix_workflow").respond(code, json={"message": "nope"})
        out = await matrix({"source": "Employees"})
        assert out["results"], code
        assert "could not be read" in out["matrix_note"], code
        assert "matrix" not in out and "warnings" not in out


async def test_markdown_shows_warning(mock: respx.MockRouter) -> None:
    mock_cells(mock)
    mock.get(WORKFLOW, name="matrix_workflow").respond(json=workflow("MULTIPLE_MATRICES"))
    out = await call_tool(make_server(), "ise_get_egress_matrix", {"source": "Employees"})
    assert "multiple-matrix mode" in str(out)

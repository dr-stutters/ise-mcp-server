from __future__ import annotations

import json
import re

import httpx
import respx

from ise_mcp.tools.endpoint_bulk import check_custom_values
from tests.unit.conftest import ers_page
from tests.unit.test_writes import two_step

GROUP_ID = "11111111-1111-1111-1111-111111111111"
TASK = "t-1"


def mock_common(mock: respx.MockRouter, existing: set[str]) -> None:
    mock.get("/api/v1/endpoint-custom-attribute").respond(
        json=[
            {"attributeName": "assetTier", "attributeType": "String"},
            {"attributeName": "floor", "attributeType": "Int"},
        ]
    )
    mock.get("/ers/config/endpointgroup").respond(json=ers_page([{"id": GROUP_ID, "name": "IoT"}]))

    def endpoint(request: httpx.Request) -> httpx.Response:
        mac = request.url.path.rsplit("/", 1)[-1].replace("%3A", ":")
        if mac in existing:
            return httpx.Response(200, json={"id": "x", "mac": mac})
        return httpx.Response(404, json={"message": "not found"})

    mock.get(url__regex=r".*/api/v1/endpoint/[0-9A-F:%]+$").mock(side_effect=endpoint)


def test_check_custom_values() -> None:
    defs = {"assetTier": "String", "floor": "Int", "ok": "Boolean"}
    assert check_custom_values({"assetTier": "gold", "floor": "3", "ok": "TRUE"}, defs) == []
    problems = check_custom_values({"assettier": "x", "floor": "three", "ok": "maybe"}, defs)
    assert "did you mean assetTier" in problems[0]
    assert "Int" in problems[1] and "Boolean" in problems[2]


async def test_bulk_create_skips_conflicts_and_reports_partial_failure(mock: respx.MockRouter) -> None:
    mock_common(mock, existing={"02:00:5E:00:01:01"})
    post = mock.post("/api/v1/endpoint/bulk").respond(json={"id": TASK})
    states = iter(
        [
            {"id": TASK, "executionStatus": "IN_PROGRESS", "resourcesCount": 2, "successCount": 0},
            {
                "id": TASK,
                "executionStatus": "COMPLETED_WITH_FAILURE",
                "resourcesCount": 2,
                "successCount": 1,
                "failCount": 1,
                "detailStatus": [
                    {"resourceExecutionStatus": "SUCCESS", "detail": "02:00:5E:00:01:02"},
                    {"resourceExecutionStatus": "FAIL", "rootCause": "boom", "detail": "02:00:5E:00:01:03"},
                ],
            },
        ]
    )
    mock.get(f"/api/v1/task/{TASK}").mock(side_effect=lambda r: httpx.Response(200, json=next(states)))
    args = {
        "action": "create",
        "endpoints": [
            {"mac": "02-00-5e-00-01-01", "group": "IoT"},
            {"mac": "0200.5e00.0102", "group": "iot", "custom_attributes": {"assetTier": "gold"}},
            {"mac": "02:00:5E:00:01:03", "description": "cam"},
            {"mac": "02:00:5e:00:01:03", "description": "cam"},
        ],
    }
    preview, applied = await two_step("ise_bulk_endpoints", args)
    p = preview["preview"]
    assert p["endpoints_in_request"] == 2
    assert p["left_out_conflicts"] == {"reason": "already exists", "count": 1, "macs": ["02:00:5E:00:01:01"]}
    assert p["duplicates_merged"] == ["02:00:5E:00:01:03"]
    body = json.loads(post.calls.last.request.content)
    assert body[0] == {
        "mac": "02:00:5E:00:01:02",
        "name": "02:00:5E:00:01:02",
        "groupId": GROUP_ID,
        "staticGroupAssignment": True,
        "customAttributes": {"assetTier": "gold"},
    }
    assert body[1]["description"] == "cam"
    result = applied["result"]
    assert result["status"] == "COMPLETED_WITH_FAILURE" and result["failed"] == 1
    assert result["failures"] == [{"item": "02:00:5E:00:01:03", "reason": "boom"}]


async def test_bulk_blockers(mock: respx.MockRouter) -> None:
    mock_common(mock, existing=set())
    preview, _ = await two_step(
        "ise_bulk_endpoints",
        {
            "action": "update",
            "max_items": 1,
            "endpoints": [
                {"mac": "02:00:5E:00:01:01", "group": "Nope", "custom_attributes": {"floor": "x"}},
                {"mac": "02:00:5E:00:01:02", "custom_attributes": {"bogus": "1"}},
            ],
        },
    )
    assert preview["status"] == "blocked"
    text = json.dumps(preview)
    assert "exceed max_items=1" in text and "No endpoint group named 'Nope'" in text
    assert "floor is Int" in text and "'bogus' is not defined" in text


async def test_bulk_delete_unknown_is_nothing_to_do(mock: respx.MockRouter) -> None:
    mock_common(mock, existing=set())
    preview, _ = await two_step(
        "ise_bulk_endpoints", {"action": "delete", "endpoints": [{"mac": "02:00:5E:00:01:09"}]}
    )
    assert preview["status"] == "blocked" and "unknown to ISE" in json.dumps(preview)


async def test_bulk_delete_no_wait(mock: respx.MockRouter) -> None:
    mock_common(mock, existing={"02:00:5E:00:01:01"})
    route = mock.delete("/api/v1/endpoint/bulk").respond(json={"id": TASK})
    _, applied = await two_step(
        "ise_bulk_endpoints", {"action": "delete", "wait": False, "endpoints": [{"mac": "02:00:5E:00:01:01"}]}
    )
    assert json.loads(route.calls.last.request.content) == {"endpoints": ["02:00:5E:00:01:01"]}
    assert applied["result"]["task_id"] == TASK and "ise_get_task" in applied["result"]["note"]


async def test_custom_attribute_create_and_delete(mock: respx.MockRouter) -> None:
    mock_common(mock, existing=set())
    create = mock.post("/api/v1/endpoint-custom-attribute").respond(201, text='"Created"')
    _, applied = await two_step("ise_set_custom_attribute", {"name": "site", "attribute_type": "Int"})
    assert json.loads(create.calls.last.request.content) == {"attributeName": "site", "attributeType": "Int"}
    assert applied["status"] == "applied"
    dup, _ = await two_step("ise_set_custom_attribute", {"name": "assetTier"})
    assert dup["status"] == "blocked"
    delete = mock.delete("/api/v1/endpoint-custom-attribute/floor").respond(200, text="ok")
    preview, applied = await two_step("ise_set_custom_attribute", {"name": "floor", "delete": True})
    assert "EndPoints:floor" in json.dumps(preview) and delete.called


async def test_release_rejected(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/endpoint/getRejected").respond(json={"response": ["02:00:5E:00:01:01"]})
    put = mock.put("/api/v1/endpoint/releaseRejectedEndpoints").respond(json={"response": "ok"})
    preview, applied = await two_step(
        "ise_release_rejected_endpoint", {"macs": ["02:00:5e:00:01:01", "02:00:5E:00:01:02"]}
    )
    assert preview["preview"] == {"release": ["02:00:5E:00:01:01"], "not_rejected": ["02:00:5E:00:01:02"]}
    assert json.loads(put.calls.last.request.content) == {"identifiers": ["02:00:5E:00:01:01"]}


async def test_set_endpoint_custom_attributes(mock: respx.MockRouter) -> None:
    mock_common(mock, existing=set())
    mock.get("/ers/config/endpoint", params={"filter": "mac.EQ.02:00:5E:00:01:01"}).respond(
        json=ers_page([{"id": "e1", "name": "02:00:5E:00:01:01"}])
    )
    mock.get("/ers/config/endpoint/e1").respond(
        json={
            "ERSEndPoint": {
                "id": "e1",
                "mac": "02:00:5E:00:01:01",
                "description": "cam",
                "customAttributes": {"customAttributes": {"floor": "2"}},
            }
        }
    )
    put = mock.put("/ers/config/endpoint/e1").respond(json={})
    preview, _ = await two_step(
        "ise_set_endpoint", {"mac": "02:00:5E:00:01:01", "custom_attributes": {"assetTier": "gold"}}
    )
    changes = preview["preview"]["changes"]
    assert any(re.search("assetTier", k) for k in changes)
    sent = json.loads(put.calls.last.request.content)["ERSEndPoint"]
    assert sent["customAttributes"]["customAttributes"] == {"floor": "2", "assetTier": "gold"}
    bad, _ = await two_step("ise_set_endpoint", {"mac": "02:00:5E:00:01:01", "custom_attributes": {"x": "1"}})
    assert bad["status"] == "blocked"


async def test_bulk_conflicting_duplicates_blocked(mock: respx.MockRouter) -> None:
    mock_common(mock, existing=set())
    preview, _ = await two_step(
        "ise_bulk_endpoints",
        {
            "action": "create",
            "endpoints": [
                {"mac": "02:00:5E:00:01:01", "description": "a"},
                {"mac": "02:00:5E:00:01:01", "description": "b"},
            ],
        },
    )
    assert preview["status"] == "blocked" and "different settings" in json.dumps(preview)


def test_rejected_macs() -> None:
    from ise_mcp.tools.endpoint_bulk import rejected_macs

    items = ["02-00-5e-00-01-01", {"mac": "0200.5e00.0102"}, {"description": "02:00:5E:00:01:03"}]
    assert rejected_macs(items) == {"02:00:5E:00:01:01", "02:00:5E:00:01:02"}

"""#167: ISE 3.5 keeps one condition library for both policy kinds.

A time condition created at POST /api/v1/policy/network-access/time-condition comes back, with the same
id, from GET /api/v1/policy/device-admin/time-condition too (recorded on the lab ISE 3.5: the shape in
tests/fixtures/policy_time_condition_shared.json, names and ids synthetic). The export writes it once
(kind `shared`), the import creates it once and finds it under either kind, the delete falls back to the
other kind's path on ISE's 400, a time PUT never promises a description change ISE ignores, and the
where-used list names each rule once."""

from __future__ import annotations

import copy
import json
from typing import Any

import respx

from ise_mcp.client import IseApp
from ise_mcp.tools.config_import import apply_plan, plan_import
from ise_mcp.tools.where_used import _one_hit
from tests.unit.conftest import BASE, fixture_json, make_settings
from tests.unit.test_conditions import (
    DA,
    HOURS_ID,
    NA,
    TIMES,
    conditions_mocks,
    export_doc,
    two_step,
)
from tests.unit.test_config_export import lab_objects, serve
from tests.unit.test_config_import import router

SHARED_TIME = fixture_json("policy_time_condition_shared.json")["response"]
SHARED_ID = SHARED_TIME["id"]


def shared_target(*, with_time: bool = True) -> dict[str, list[dict[str, Any]]]:
    """Lab objects where the device-admin lists return the network-access time condition (same id)."""
    objs = lab_objects()
    times = [copy.deepcopy(SHARED_TIME)] if with_time else []
    objs["na:time-condition"] = [*objs["na:time-condition"], *times]
    objs["da:time-condition"] = copy.deepcopy(times)
    objs["da:condition"] = []
    objs["da:network-condition"] = []
    return objs


def serve_da_policy_off(r: respx.MockRouter) -> None:
    for scope in ("authorization", "authentication", "policyset"):
        r.get(f"{DA}/dictionaries/{scope}").respond(json={"response": []})


# --- export -------------------------------------------------------------------------------------


async def test_export_writes_a_shared_time_condition_once() -> None:
    doc = await export_doc(shared_target(), ["conditions"])
    rows = [r for r in doc["conditions"] if r["name"] == "mcp-all-week"]
    assert rows == [
        {
            "name": "mcp-all-week",
            "description": "Lab time condition (all week, all day)",
            "kind": "shared",
            "time": {"start": "00:00", "end": "23:59"},
            "type": "time",
        }
    ]
    # Conditions only one kind lists keep that kind.
    assert {r["kind"] for r in doc["conditions"] if r["name"] != "mcp-all-week"} == {"network-access"}


# --- import -------------------------------------------------------------------------------------


def old_style(doc: dict[str, Any]) -> dict[str, Any]:
    """The 0.21 export: the shared condition once per kind."""
    out = copy.deepcopy(doc)
    entry = next(o for o in out["conditions"] if o["name"] == "mcp-all-week")
    entry["kind"] = "network-access"
    out["conditions"].append({**entry, "kind": "device-admin"})
    return out


async def test_import_creates_a_shared_condition_once_then_nothing_to_do() -> None:
    doc = await export_doc(shared_target(), ["conditions"])
    for source in (doc, old_style(doc)):
        with router() as r:
            serve(r, shared_target(with_time=False))
            serve_da_policy_off(r)
            na_post = r.post(f"{NA}/time-condition").respond(
                201, json={"response": {"id": SHARED_ID, "name": "mcp-all-week"}}
            )
            da_post = r.post(f"{DA}/time-condition").respond(400, json={"message": "already exists"})
            app = IseApp(make_settings())
            try:
                plan = await plan_import(app, source, sections=["conditions"], only=["mcp-all-week"])
                assert plan.blockers == []
                assert [(s.op, s.name) for s in plan.steps] == [("create", "shared/mcp-all-week")]
                await apply_plan(plan)
            finally:
                await app.aclose()
        assert na_post.call_count == 1 and not da_post.called
        sent = json.loads(na_post.calls.last.request.content)
        assert sent["name"] == "mcp-all-week" and sent["hoursRange"] == {
            "startTime": "00:00",
            "endTime": "23:59",
        }
        # Re-plan against the target that now lists it under both kinds: nothing to do.
        with router() as r:
            serve(r, shared_target())
            serve_da_policy_off(r)
            app = IseApp(make_settings())
            try:
                again = await plan_import(app, source, sections=["conditions"], only=["mcp-all-week"])
            finally:
                await app.aclose()
        assert again.steps == [] and again.blockers == [] and again.skipped["conditions"] == 1


async def test_import_finds_the_condition_under_the_other_kind() -> None:
    """An export entry for device-admin matches the target's network-access-only object by name: an update
    (not a create ISE would refuse as a duplicate name)."""
    doc = await export_doc(shared_target(), ["conditions"])
    entry = next(o for o in doc["conditions"] if o["name"] == "mcp-all-week")
    entry["kind"] = "device-admin"
    entry["time"] = {"days": ["Monday", "Friday"], "start": "00:00", "end": "23:59"}
    target = shared_target()
    target["da:time-condition"] = []
    with router() as r:
        serve(r, target)
        serve_da_policy_off(r)
        put = r.put(f"{NA}/time-condition/{SHARED_ID}").respond(json={"response": SHARED_TIME})
        r.post(url__regex=rf"{BASE}/api/v1/policy/.*/time-condition$").respond(400)
        app = IseApp(make_settings())
        try:
            plan = await plan_import(app, doc, sections=["conditions"], only=["mcp-all-week"])
            assert [(s.op, s.name) for s in plan.steps] == [("update", "device-admin/mcp-all-week")]
            assert plan.steps[0].changes == {"time.days": {"from": None, "to": ["Monday", "Friday"]}}
            await apply_plan(plan)
        finally:
            await app.aclose()
    assert json.loads(put.calls.last.request.content)["weekDays"] == ["Monday", "Friday"]


async def test_import_refuses_two_different_definitions_of_one_name() -> None:
    doc = old_style(await export_doc(shared_target(), ["conditions"]))
    doc["conditions"][-1]["time"] = {"days": ["Monday"]}
    with router() as r:
        serve(r, shared_target(with_time=False))
        app = IseApp(make_settings())
        try:
            plan = await plan_import(app, doc, sections=["conditions"], only=["mcp-all-week"])
        finally:
            await app.aclose()
    assert plan.steps == []
    assert any("different definitions" in b and "one condition of a name" in b for b in plan.blockers)


async def test_import_time_description_only_is_a_note_not_an_update() -> None:
    doc = await export_doc(shared_target(), ["conditions"])
    next(o for o in doc["conditions"] if o["name"] == "mcp-all-week")["description"] = "Changed"
    with router() as r:
        serve(r, shared_target())
        serve_da_policy_off(r)
        app = IseApp(make_settings())
        try:
            plan = await plan_import(app, doc, sections=["conditions"], only=["mcp-all-week"])
        finally:
            await app.aclose()
    assert plan.steps == [] and plan.skipped["conditions"] == 1
    assert any("description left as it is" in n for n in plan.notes)


# --- delete -------------------------------------------------------------------------------------


async def test_delete_retries_the_other_kind_on_400(mock: respx.MockRouter) -> None:
    mock.get(f"{DA}/time-condition").respond(json={"response": copy.deepcopy(TIMES)})
    for res in ("condition", "network-condition"):
        mock.get(f"{DA}/{res}").respond(json={"response": []})
    conditions_mocks(mock)
    na = mock.delete(f"{NA}/time-condition/{HOURS_ID}").respond(
        400, json={"message": "Failed to process request"}
    )
    da = mock.delete(f"{DA}/time-condition/{HOURS_ID}").respond(204)
    preview, applied = await two_step("ise_delete_condition", {"name": "mcp-business-hours"})
    assert not preview.get("blockers")
    assert na.called and da.called
    assert applied is not None and applied["status"] == "applied"
    assert applied["result"]["deleted"] == "mcp-business-hours"


async def test_delete_raises_the_first_error_when_both_kinds_refuse(mock: respx.MockRouter) -> None:
    conditions_mocks(mock)
    mock.delete(f"{NA}/time-condition/{HOURS_ID}").respond(400, json={"message": "Failed to process request"})
    mock.delete(f"{DA}/time-condition/{HOURS_ID}").respond(400, json={"message": "Something else"})
    from fastmcp import Client

    from tests.unit.conftest import make_server

    async with Client(make_server(mcp_enable_writes=True)) as c:
        preview = (
            await c.call_tool("ise_delete_condition", {"name": "mcp-business-hours"})
        ).structured_content
        assert preview is not None
        res = await c.call_tool(
            "ise_delete_condition",
            {"name": "mcp-business-hours", "confirm": preview["confirm"]},
            raise_on_error=False,
        )
    assert res.is_error and "Failed to process request" in str(res.content)


# --- time PUT and description -------------------------------------------------------------------


TIME_ARGS = {
    "name": "mcp-business-hours",
    "type": "time",
    "time": {
        "days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
        "start": "08:00",
        "end": "18:00",
        "exclude": {"dates": {"start": "2026-12-25", "end": "2026-12-26"}},
    },
}


async def test_time_description_only_is_no_change_with_a_note(mock: respx.MockRouter) -> None:
    conditions_mocks(mock)
    put = mock.put(f"{NA}/time-condition/{HOURS_ID}").respond(json={"response": TIMES[0]})
    preview, _ = await two_step("ise_set_condition", {**TIME_ARGS, "description": "New words"})
    assert preview["status"] == "no_change" and "confirm" not in preview
    assert "ISE keeps a time condition's description" in json.dumps(preview)
    assert not put.called


async def test_time_update_leaves_description_out_of_the_diff(mock: respx.MockRouter) -> None:
    conditions_mocks(mock)
    put = mock.put(f"{NA}/time-condition/{HOURS_ID}").respond(json={"response": TIMES[0]})
    args = copy.deepcopy(TIME_ARGS)
    args["time"]["end"] = "20:00"
    preview, applied = await two_step("ise_set_condition", {**args, "description": "New words"})
    assert preview["preview"]["changes"] == {"time.end": {"from": "18:00", "to": "20:00"}}
    assert any("ISE keeps a time condition's description" in s for s in preview["side_effects"])
    sent = json.loads(put.calls.last.request.content)
    assert sent["description"] == "Weekday business hours"  # what ISE keeps anyway
    assert applied is not None and applied["status"] == "applied"


async def test_update_falls_back_to_the_other_kind_on_400(mock: respx.MockRouter) -> None:
    conditions_mocks(mock)
    na = mock.put(f"{NA}/time-condition/{HOURS_ID}").respond(
        400, json={"message": "Failed to process request"}
    )
    da = mock.put(f"{DA}/time-condition/{HOURS_ID}").respond(json={"response": TIMES[0]})
    args = copy.deepcopy(TIME_ARGS)
    args["time"]["end"] = "20:00"
    _, applied = await two_step("ise_set_condition", args)
    assert na.called and da.called and applied is not None and applied["status"] == "applied"


# --- where used ---------------------------------------------------------------------------------


def test_one_hit_prefers_the_direct_match() -> None:
    assert _one_hit([]) == []
    assert _one_hit([None, "mcp-business-hours"]) == [None]
    assert _one_hit(["a", "b"]) == ["a"]


async def test_delete_blocker_names_a_rule_once(mock: respx.MockRouter) -> None:
    """The rule's reference matches by id, and so does the time condition ISE returns for that id: before
    #167 the rule was listed twice ('Wired / Contractors, Wired / Contractors (via ...)')."""
    mock.get(f"{NA}/condition/{HOURS_ID}").respond(json={"response": TIMES[0]})
    conditions_mocks(mock, used_by_rule=HOURS_ID)
    preview, applied = await two_step("ise_delete_condition", {"name": "mcp-business-hours"})
    assert applied is None
    used = [b for b in preview["blockers"] if b.startswith("Used by authorization rule")]
    assert used == ["Used by authorization rule(s): Wired / Contractors"]

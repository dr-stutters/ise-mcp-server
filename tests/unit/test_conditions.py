"""I57: ise_set_condition / ise_delete_condition (library, time-and-date and network conditions) and the
`conditions` section of ise_export_config / ise_import_config.

The built-in library conditions in tests/fixtures/policy_conditions.json are as ISE 3.5 returns them; the
lab had no time or network conditions to record, so those fixtures follow the 3.5 OpenAPI schema
(TimeAndDateCondition, DeviceCondition)."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp import Client

from ise_mcp.client import IseApp
from ise_mcp.tools.conditions import TimeSpec, ndg_from_api, ndg_to_api, time_body
from ise_mcp.tools.config_export import export_config, load_export, to_yaml
from ise_mcp.tools.config_import import apply_plan, plan_import
from tests.unit.conftest import BASE, ers_page, fixture_json, make_server, make_settings
from tests.unit.test_config_export import COND_ATTRS, lab_objects, serve
from tests.unit.test_config_import import GIVEN, empty_objects, router

NA = "/api/v1/policy/network-access"
DA = "/api/v1/policy/device-admin"
LIBRARY = fixture_json("policy_conditions.json")["response"]
TIMES = fixture_json("policy_time_conditions.json")["response"]
NETWORKS = fixture_json("policy_network_conditions.json")["response"]
HOURS_ID = TIMES[0]["id"]


def rule_using(cond_id: str | None, name: str) -> dict[str, Any]:
    cond = None
    if cond_id:
        cond = {"conditionType": "ConditionReference", "isNegate": False, "id": cond_id, "name": name}
    return {
        "rule": {"id": "r1", "name": "Contractors", "rank": 0, "state": "enabled", "condition": cond},
        "profile": ["PermitAccess"],
    }


def conditions_mocks(mock: respx.MockRouter, *, used_by_rule: str | None = None) -> None:
    """The three condition lists, the dictionaries, NADs/NDGs, and a policy for the where-used walk
    (one set whose authorization rule uses `used_by_rule`, a condition id)."""
    mock.get(f"{NA}/condition").respond(json={"response": copy.deepcopy(LIBRARY)})
    mock.get(f"{NA}/time-condition").respond(json={"response": copy.deepcopy(TIMES)})
    mock.get(f"{NA}/network-condition").respond(json={"response": copy.deepcopy(NETWORKS)})
    for c in LIBRARY:
        mock.get(f"{NA}/condition/condition-by-name/{c['name']}").respond(json={"response": c})
    mock.get(url__regex=rf"{BASE}{NA}/condition/[0-9a-f-]+$").respond(404, json={"message": "not found"})
    for scope in ("authorization", "authentication", "policyset"):
        mock.get(f"{NA}/dictionaries/{scope}").respond(json={"response": COND_ATTRS})
    mock.get("/ers/config/networkdevice").respond(json=ers_page([{"id": "n1", "name": "mcp-test-sw1"}]))
    mock.get("/ers/config/networkdevicegroup").respond(
        json=ers_page(
            [
                {"id": "g1", "name": "Location#All Locations"},
                {"id": "g2", "name": "Location#All Locations#Lab"},
            ]
        )
    )
    mock.get(f"{NA}/policy-set").respond(json={"response": [{"id": "s1", "name": "Wired", "rank": 0}]})
    rules = [rule_using(used_by_rule, "x")] if used_by_rule else []
    mock.get(f"{NA}/policy-set/s1/authorization").respond(json={"response": rules})
    for section in ("authentication", "exception"):
        mock.get(f"{NA}/policy-set/s1/{section}").respond(json={"response": []})
    mock.get(f"{NA}/policy-set/global-exception").respond(json={"response": []})
    mock.get(f"{DA}/policy-set").respond(404, json={"message": "Device Admin is off"})


async def two_step(name: str, args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        preview = (await c.call_tool(name, args)).structured_content
        assert preview is not None
        if preview.get("status") != "preview" or preview.get("blockers"):
            return preview, None
        applied = (await c.call_tool(name, {**args, "confirm": preview["confirm"]})).structured_content
        assert applied is not None
        return preview, applied


# --- pure helpers -------------------------------------------------------------------------------


def test_ndg_round_trip() -> None:
    assert ndg_to_api("Location#All Locations#Lab") == "Location,All Locations#Lab"
    assert ndg_to_api("Location#All Locations#Lab,Gi1/0/1") == "Location,All Locations#Lab,Gi1/0/1"
    assert ndg_to_api("Location,All Locations#Lab") == "Location,All Locations#Lab"  # ISE form as given
    assert ndg_from_api("Location,All Locations#Lab") == "Location#All Locations#Lab"
    assert ndg_from_api("Location,All Locations#Lab,Gi1/0/1") == "Location#All Locations#Lab,Gi1/0/1"


def test_time_body_and_validation() -> None:
    body, blockers = time_body(
        TimeSpec(
            days=["mon", "Tuesday", "wed"],
            start="08:00",
            end="18:00",
            exclude={"dates": {"start": "2026-12-25", "end": "2026-12-25"}},
        )
    )
    assert blockers == []
    assert body == {
        "conditionType": "TimeAndDateCondition",
        "isNegate": False,
        "weekDays": ["Monday", "Tuesday", "Wednesday"],
        "hoursRange": {"startTime": "08:00", "endTime": "18:00"},
        "datesRangeException": {"startDate": "2026-12-25", "endDate": "2026-12-25"},
    }
    every_day, _ = time_body(TimeSpec())
    assert len(every_day["weekDays"]) == 7
    _, bad = time_body(
        TimeSpec(days=["Funday"], start="8am", dates={"start": "2026-02-01", "end": "2026-01-01"})
    )
    assert any("not a week day" in b for b in bad)
    assert any("both start and end" in b for b in bad)
    assert any("end before they start" in b for b in bad)


# --- ise_set_condition ----------------------------------------------------------------------------


async def test_create_time_condition(mock: respx.MockRouter) -> None:
    conditions_mocks(mock)
    post = mock.post(f"{NA}/time-condition").respond(
        201, json={"response": {"id": "t-new", "name": "mcp-after-hours"}}
    )
    preview, applied = await two_step(
        "ise_set_condition",
        {
            "name": "mcp-after-hours",
            "type": "time",
            "time": {"days": ["Saturday", "Sunday"], "start": "00:00", "end": "23:59"},
            "description": "Weekends",
        },
    )
    assert preview["status"] == "preview" and not preview.get("blockers"), preview
    assert preview["preview"]["time"] == {"days": ["Saturday", "Sunday"], "start": "00:00", "end": "23:59"}
    sent = json.loads(post.calls.last.request.content)
    assert sent["conditionType"] == "TimeAndDateCondition" and sent["weekDays"] == ["Saturday", "Sunday"]
    assert sent["name"] == "mcp-after-hours" and sent["description"] == "Weekends"
    assert applied is not None and applied["result"] == {"id": "t-new", "name": "mcp-after-hours"}


async def test_create_library_condition_canonicalises(mock: respx.MockRouter) -> None:
    conditions_mocks(mock)
    post = mock.post(f"{NA}/condition").respond(
        201, json={"response": {"id": "c-new", "name": "mcp-wired-web"}}
    )
    preview, applied = await two_step(
        "ise_set_condition",
        {
            "name": "mcp-wired-web",
            "type": "library",
            "conditions": ["radius:service-type equals outbound", {"not": "Wired_802.1X"}],
            "match": "any",
        },
    )
    assert preview["preview"]["condition"] == "(Radius:Service-Type equals Outbound OR NOT Wired_802.1X)"
    sent = json.loads(post.calls.last.request.content)
    assert sent["conditionType"] == "LibraryConditionOrBlock"
    first, second = sent["children"]
    assert (first["dictionaryName"], first["attributeName"], first["attributeValue"]) == (
        "Radius",
        "Service-Type",
        "Outbound",
    )
    assert second == {
        "conditionType": "ConditionReference",
        "isNegate": True,
        "id": "58f909ca-7df3-4abd-bf52-f53769a2471c",
        "name": "Wired_802.1X",
    }
    assert applied is not None and applied["status"] == "applied"


async def test_library_condition_blockers(mock: respx.MockRouter) -> None:
    conditions_mocks(mock)
    preview, _ = await two_step(
        "ise_set_condition",
        {"name": "mcp-bad", "type": "library", "conditions": ["Radius:NAS-Port-Typo equals Ethernet"]},
    )
    assert any("Did you mean Radius:NAS-Port-Type" in b for b in preview["blockers"])
    only_ref, _ = await two_step(
        "ise_set_condition", {"name": "mcp-alias", "type": "library", "conditions": ["Wired_802.1X"]}
    )
    assert any("just another library condition" in b for b in only_ref["blockers"])
    # A name already used by a condition of another type
    clash, _ = await two_step(
        "ise_set_condition",
        {
            "name": "MCP-BUSINESS-HOURS",
            "type": "library",
            "conditions": ["Radius:NAS-Port-Type equals Ethernet"],
        },
    )
    assert any("is a time condition" in b for b in clash["blockers"])


async def test_update_library_condition_diff_and_users(mock: respx.MockRouter) -> None:
    conditions_mocks(mock, used_by_rule="00000000-0000-4000-8000-000000000081")
    put = mock.put(f"{NA}/condition/condition-by-name/mcp-test-lab-switches").respond(
        json={"response": {"id": "00000000-0000-4000-8000-000000000081", "name": "mcp-test-lab-switches"}}
    )
    preview, applied = await two_step(
        "ise_set_condition",
        {
            "name": "mcp-test-lab-switches",
            "type": "library",
            "conditions": [
                "Radius:NAS-Port-Type equals Ethernet",
                "DEVICE:Location equals Location#All Locations#Lab",
            ],
        },
    )
    assert preview["preview"]["changes"] == {
        "condition": {
            "from": "(Radius:NAS-Port-Type equals Ethernet AND DEVICE:Location equals All Locations)",
            "to": "(Radius:NAS-Port-Type equals Ethernet AND DEVICE:Location equals All Locations#Lab)",
        }
    }
    assert any("Wired / Contractors" in s for s in preview["side_effects"])
    sent = json.loads(put.calls.last.request.content)
    assert sent["id"] == "00000000-0000-4000-8000-000000000081"
    assert sent["conditionType"] == "LibraryConditionAndBlock"
    assert sent["description"] == "Wired requests from lab switches"  # kept when not given
    assert applied is not None and applied["status"] == "applied"


async def test_update_time_condition_and_no_change(mock: respx.MockRouter) -> None:
    conditions_mocks(mock)
    put = mock.put(f"{NA}/time-condition/{HOURS_ID}").respond(json={"response": TIMES[0]})
    same = {
        "name": "mcp-business-hours",
        "type": "time",
        "time": {
            "days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
            "start": "08:00",
            "end": "18:00",
            "exclude": {"dates": {"start": "2026-12-25", "end": "2026-12-26"}},
        },
    }
    unchanged, _ = await two_step("ise_set_condition", same)
    assert unchanged["status"] == "no_change" and "confirm" not in unchanged
    later = copy.deepcopy(same)
    later["time"]["end"] = "20:00"
    preview, applied = await two_step("ise_set_condition", later)
    assert preview["preview"]["changes"] == {"time.end": {"from": "18:00", "to": "20:00"}}
    sent = json.loads(put.calls.last.request.content)
    assert sent["id"] == HOURS_ID and sent["hoursRange"] == {"startTime": "08:00", "endTime": "20:00"}
    assert applied is not None and applied["status"] == "applied"


async def test_network_condition_body_and_blockers(mock: respx.MockRouter) -> None:
    conditions_mocks(mock)
    post = mock.post(f"{NA}/network-condition").respond(
        201, json={"response": {"id": "n-new", "name": "mcp-lab"}}
    )
    preview, applied = await two_step(
        "ise_set_condition",
        {
            "name": "mcp-lab",
            "type": "network",
            "network": {
                "nads": ["mcp-test-sw1"],
                "ips": ["198.51.100.0/24"],
                "ndgs": ["Location#All Locations#Lab"],
            },
        },
    )
    assert not preview.get("blockers"), preview
    sent = json.loads(post.calls.last.request.content)
    assert sent == {
        "conditionType": "DeviceCondition",
        "deviceList": ["mcp-test-sw1"],
        "ipAddrList": ["198.51.100.0/24"],
        "deviceGroupList": ["Location,All Locations#Lab"],
        "name": "mcp-lab",
        "description": "",
    }
    assert applied is not None
    bad, _ = await two_step(
        "ise_set_condition",
        {
            "name": "mcp-lab2",
            "type": "network",
            "network": {"nads": ["sw-missing"], "ips": ["300.1.1.1"], "macs": ["aa:bb:cc:dd:ee:ff"]},
        },
    )
    text = " | ".join(bad["blockers"])
    assert "No NAD named 'sw-missing'" in text and "'300.1.1.1' is not an IP" in text
    assert "network.macs doesn't apply to match=device" in text


async def test_wrong_spec_for_type_is_refused(mock: respx.MockRouter) -> None:
    conditions_mocks(mock)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        res = await c.call_tool(
            "ise_set_condition",
            {"name": "x", "type": "time", "conditions": ["Wired_802.1X"]},
            raise_on_error=False,
        )
    assert res.is_error and "type=time takes `time`" in str(res.content)


# --- ise_delete_condition -----------------------------------------------------------------------


async def test_delete_blocked_while_referenced(mock: respx.MockRouter) -> None:
    conditions_mocks(mock, used_by_rule=HOURS_ID)
    preview, applied = await two_step("ise_delete_condition", {"name": "mcp-business-hours"})
    assert applied is None
    assert any("authorization rule" in b and "Wired / Contractors" in b for b in preview["blockers"])


async def test_delete_unused(mock: respx.MockRouter) -> None:
    conditions_mocks(mock)
    delete = mock.delete(f"{NA}/time-condition/{HOURS_ID}").respond(204)
    preview, applied = await two_step("ise_delete_condition", {"name": "mcp-business-hours"})
    assert preview["preview"]["type"] == "time" and not preview.get("blockers")
    assert delete.called and applied is not None and applied["result"]["deleted"] == "mcp-business-hours"


async def test_delete_is_write_tier() -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_set_condition" not in names and "ise_delete_condition" not in names
    async with Client(make_server(mcp_enable_writes=True)) as c:
        tools = {t.name: t for t in await c.list_tools()}
    assert tools["ise_delete_condition"].annotations is not None
    assert tools["ise_delete_condition"].annotations.destructive_hint is True


# --- rules can use time conditions by name ------------------------------------------------------


async def test_authz_rule_accepts_a_time_condition(mock: respx.MockRouter) -> None:
    conditions_mocks(mock)
    mock.get(f"{NA}/authorization-profiles").respond(json=[{"name": "PermitAccess"}])
    mock.get(f"{NA}/security-groups").respond(json=[])
    post = mock.post(f"{NA}/policy-set/s1/authorization").respond(
        201, json={"response": {"rule": {"id": "r9", "name": "Contractors", "rank": 0}}}
    )
    preview, _ = await two_step(
        "ise_create_authz_rule",
        {
            "policy_set": "Wired",
            "name": "Contractors",
            "conditions": ["Wired_802.1X", "mcp-business-hours"],
            "profiles": ["PermitAccess"],
        },
    )
    assert not preview.get("blockers"), preview
    children = json.loads(post.calls.last.request.content)["rule"]["condition"]["children"]
    assert children[1] == {
        "conditionType": "ConditionReference",
        "isNegate": False,
        "id": HOURS_ID,
        "name": "mcp-business-hours",
    }


# --- export / import ----------------------------------------------------------------------------


async def export_doc(objects: dict[str, list[dict[str, Any]]], sections: list[str]) -> dict[str, Any]:
    with router() as r:
        serve(r, objects)
        app = IseApp(make_settings())
        try:
            return load_export(to_yaml(await export_config(app, sections)))
        finally:
            await app.aclose()


async def test_export_conditions_section() -> None:
    doc = await export_doc(lab_objects(), ["conditions"])
    rows = {r["name"]: r for r in doc["conditions"]}
    assert [r["name"] for r in doc["conditions"]] == [
        "mcp-business-hours",
        "mcp-test-lab-nads",
        "mcp-test-lab-switches",
        "Switch_Local_Web_Authentication",
        "Wired_802.1X",
    ]
    assert rows["Wired_802.1X"]["conditions"] == ["Normalised Radius:RadiusFlowType equals Wired802_1x"]
    assert rows["mcp-test-lab-switches"] == {
        "name": "mcp-test-lab-switches",
        "description": "Wired requests from lab switches",
        "conditions": ["Radius:NAS-Port-Type equals Ethernet", "DEVICE:Location equals All Locations"],
        "kind": "network-access",
        "match": "all",
        "type": "library",
    }
    assert rows["mcp-business-hours"]["time"] == {
        "days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
        "start": "08:00",
        "end": "18:00",
        "exclude": {"dates": {"start": "2026-12-25", "end": "2026-12-26"}},
    }
    assert rows["mcp-test-lab-nads"]["network"] == {
        "match": "device",
        "nads": ["mcp-test-radius-client"],
        "ips": ["192.0.2.0/24"],
        "ndgs": ["Location#All Locations"],
    }
    assert doc["ise_export"]["counts"]["conditions"] == 5


async def test_import_round_trip_create_skip_update() -> None:
    doc = await export_doc(lab_objects(), ["ndgs", "nads", "conditions"])
    # Identical target: nothing to do.
    with router() as r:
        serve(r, lab_objects())
        app = IseApp(make_settings())
        try:
            same = await plan_import(app, doc)
        finally:
            await app.aclose()
    assert same.steps == [] and same.blockers == [] and same.skipped["conditions"] == 5
    # Empty target: every condition is created, after the NADs and device groups they name.
    with router() as r:
        serve(r, empty_objects())
        posts = {
            res: r.post(f"{NA}/{res}").respond(201, json={"response": {"id": "x"}})
            for res in ("condition", "time-condition", "network-condition")
        }
        r.post("/ers/config/networkdevicegroup").respond(
            201, headers={"Location": f"{BASE}/ers/config/networkdevicegroup/g9"}
        )
        r.post("/ers/config/networkdevice").respond(
            201, headers={"Location": f"{BASE}/ers/config/networkdevice/n9"}
        )
        app = IseApp(make_settings())
        try:
            plan = await plan_import(app, doc, secrets=GIVEN)
            assert plan.blockers == []
            sections = [s.section for s in plan.steps]
            assert sections.index("nads") < sections.index("conditions")
            assert [s.name for s in plan.steps if s.section == "conditions"] == [
                "network-access/mcp-business-hours",
                "network-access/mcp-test-lab-nads",
                "network-access/mcp-test-lab-switches",
                "network-access/Switch_Local_Web_Authentication",
                "network-access/Wired_802.1X",
            ]
            await apply_plan(plan)
        finally:
            await app.aclose()
    sent_time = json.loads(posts["time-condition"].calls.last.request.content)
    assert {k: sent_time[k] for k in ("name", "weekDays", "hoursRange", "datesRangeException")} == {
        "name": "mcp-business-hours",
        "weekDays": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
        "hoursRange": {"startTime": "08:00", "endTime": "18:00"},
        "datesRangeException": {"startDate": "2026-12-25", "endDate": "2026-12-26"},
    }
    sent_net = json.loads(posts["network-condition"].calls.last.request.content)
    assert sent_net["deviceGroupList"] == ["Location,All Locations"]
    assert posts["condition"].call_count == 3
    # A changed window on the target: one update, a PUT by id.
    target = lab_objects()
    target["na:time-condition"] = [{**TIMES[0], "hoursRange": {"startTime": "09:00", "endTime": "17:00"}}]
    with router() as r:
        serve(r, target)
        put = r.put(f"{NA}/time-condition/{HOURS_ID}").respond(json={"response": TIMES[0]})
        app = IseApp(make_settings())
        try:
            upd = await plan_import(app, doc, sections=["conditions"])
            assert [(s.op, s.name) for s in upd.steps] == [("update", "network-access/mcp-business-hours")]
            assert upd.steps[0].changes == {
                "time.end": {"from": "17:00", "to": "18:00"},
                "time.start": {"from": "09:00", "to": "08:00"},
            }
            await apply_plan(upd)
        finally:
            await app.aclose()
    assert json.loads(put.calls.last.request.content)["id"] == HOURS_ID


async def test_import_prune_and_rule_reference_to_new_condition() -> None:
    doc = await export_doc(lab_objects(), ["conditions", "policy_sets"])
    rules = doc["policy_sets"]["network-access"]["sets"][0]["authorization"]
    rules.insert(
        0,
        {
            "name": "mcp-test-hours",
            "rank": 0,
            "state": "enabled",
            "condition": "mcp-business-hours",
            "profile": ["PermitAccess"],
        },
    )
    for i, rule in enumerate(rules):
        rule["rank"] = i
    target = lab_objects()
    target["na:time-condition"] = []  # the condition is new on the target
    target["na:condition"] = [
        *LIBRARY,
        {**LIBRARY[2], "id": "00000000-0000-4000-8000-000000000099", "name": "mcp-test-old"},
    ]
    with router() as r:
        serve(r, target)
        r.get(f"{NA}/authorization-profiles").respond(
            json={
                "response": [
                    {"name": "PermitAccess"},
                    {"name": "Block_Wireless_Access"},
                    {"name": "Cisco_IP_Phones"},
                    {"name": "Non_Cisco_IP_Phones"},
                    {"name": "Cisco_Temporal_Onboard"},
                    {"name": "NSP_Onboard"},
                    {"name": "Cisco_WebAuth"},
                    {"name": "DenyAccess"},
                    {"name": "BYOD"},
                    {"name": "Guests"},
                ]
            }
        )
        r.get(f"{NA}/security-groups").respond(json={"response": []})
        app = IseApp(make_settings())
        try:
            plan = await plan_import(app, doc, only=["mcp-*"], prune=True)
            assert [(st.op, st.section, st.name) for st in plan.steps] == [
                ("create", "conditions", "network-access/mcp-business-hours"),
                ("create", "policy_rules", "network-access/Default/authorization/mcp-test-hours"),
                ("delete", "conditions", "network-access/mcp-test-old"),
            ]
            assert plan.blockers == [], plan.blockers
            # Applying: the rule's reference gets the new condition's id when its step runs.
            r.post(f"{NA}/time-condition").respond(201, json={"response": {"id": HOURS_ID}})
            r.get(f"{NA}/time-condition").respond(json={"response": TIMES})
            created = r.post(f"{NA}/policy-set/{doc_set_id()}/authorization").respond(
                201, json={"response": {"rule": {"id": "r-new"}}}
            )
            deleted = r.delete(f"{NA}/condition/00000000-0000-4000-8000-000000000099").respond(204)
            await apply_plan(plan)
        finally:
            await app.aclose()
    assert deleted.called
    cond = json.loads(created.calls.last.request.content)["rule"]["condition"]
    assert cond["id"] == HOURS_ID and cond["name"] == "mcp-business-hours"


def doc_set_id() -> str:
    return str(fixture_json("policy_sets.json")["response"][0]["id"])


@pytest.mark.parametrize("bad", [{"days": []}, {"start": "25:00", "end": "26:00"}])
def test_time_blockers(bad: dict[str, Any]) -> None:
    _, blockers = time_body(TimeSpec(**bad))
    assert blockers

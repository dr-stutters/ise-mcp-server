"""I43: ise_import_config planning (empty and populated targets, prune, only, secrets) and apply."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp import Client

from ise_mcp._core import InvalidRequest, UpstreamError
from ise_mcp.client import IseApp
from ise_mcp.tools.config_export import HEADER, export_config, load_export, resolve_scope, to_yaml
from ise_mcp.tools.config_import import (
    ImportPlan,
    Step,
    apply_plan,
    condition_api,
    given_changes,
    plan_import,
    plan_view,
)
from tests.unit.conftest import BASE, make_server, make_settings, xml
from tests.unit.test_config_export import SECRETS, _uuid, lab_objects, serve

NON_POLICY = [s for s in resolve_scope(None) if s not in ("policy_sets", "custom_attributes")]
NAD = "mcp-test-radius-client"
GIVEN = {
    NAD: {"radius": "new-radius-secret-1", "tacacs": "new-tacacs-secret-1", "snmp_ro": "new-community-1"}
}


def router() -> respx.MockRouter:
    r = respx.mock(base_url=BASE, assert_all_called=False)
    r.get("/admin/API/mnt/Version").respond(text=xml("<product><version>3.5.0.527</version></product>"))
    r.get("/api/v1/deployment/node").respond(json={"response": []})
    return r


async def export_of(objects: dict[str, list[dict[str, Any]]], sections: list[str]) -> dict[str, Any]:
    with router() as r:
        serve(r, objects)
        app = IseApp(make_settings())
        try:
            return load_export(to_yaml(await export_config(app, sections)))
        finally:
            await app.aclose()


def empty_objects() -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {k: [] for k in lab_objects()}
    out["egressmatrixcell"] = [lab_objects()["egressmatrixcell"][0]]  # ISE always has ANY-ANY
    return out


async def plan_on(target: dict[str, list[dict[str, Any]]], doc: dict[str, Any], **kw: Any) -> ImportPlan:
    with router() as r:
        serve(r, target)
        app = IseApp(make_settings())
        try:
            return await plan_import(app, doc, **kw)
        finally:
            await app.aclose()


async def test_plan_for_an_empty_target() -> None:
    doc = await export_of(lab_objects(), NON_POLICY)
    plan = await plan_on(empty_objects(), doc)
    order = [(s.op, s.section) for s in plan.steps]
    # Everything is created; the ANY -> ANY cell (always there) gets its SGACL once "Permit IP" exists.
    assert [(s.op, s.name) for s in plan.steps if s.op != "create"] == [("update", "ANY -> ANY")]
    sections = [sec for _, sec in order]
    # Dependency order: groups and TrustSec objects, then dACL -> profile, TACACS objects, NADs last.
    assert sections.index("ndgs") < sections.index("nads")
    assert sections.index("dacls") < sections.index("authz_profiles")
    assert sections.index("sgts") < sections.index("egress_matrix")
    assert [s.name for s in plan.steps if s.section == "endpoint_groups"] == ["Profiled", "Workstation"]
    assert len([o for o in order if o == ("create", "egress_matrix")]) == 1
    # The NAD's secrets are masked in the export: the plan blocks until they are given.
    assert sorted(b.split(": ", 1)[1].split(" secret")[0] for b in plan.blockers) == [
        "give its radius",
        "give its snmp_ro",
        "give its tacacs",
    ]
    ok = await plan_on(empty_objects(), doc, secrets=GIVEN)
    assert ok.blockers == []
    assert "new-radius-secret-1" not in json.dumps(plan_view(ok, doc))


async def test_plan_for_an_identical_target_is_empty() -> None:
    doc = await export_of(lab_objects(), NON_POLICY + ["policy_sets"])
    plan = await plan_on(lab_objects(), doc)
    assert plan.steps == [] and plan.blockers == []
    assert plan.skipped["nads"] == 1 and plan.skipped["policy_rules"] > 5


async def test_plan_updates_only_given_fields() -> None:
    doc = await export_of(lab_objects(), ["sgts", "dacls"])
    target = lab_objects()
    target["sgt"][0] = {**target["sgt"][0], "value": 40, "propogateToApic": True}  # not in the export
    target["downloadableacl"][0] = {**target["downloadableacl"][0], "dacl": "permit ip any any"}
    plan = await plan_on(target, doc)
    assert [(s.op, s.name, s.changes) for s in plan.steps] == [
        ("update", "Employees", {"value": {"from": 40, "to": 4}}),  # SGTs are applied before dACLs
        ("update", "mcp-test-dacl", {"dacl": {"added": ["permit udp any any eq 53"]}}),
    ]


async def test_prune_and_only() -> None:
    doc = await export_of(lab_objects(), ["sgts", "sgacls", "egress_matrix"])
    target = lab_objects()
    target["sgt"].append({"id": _uuid(50), "name": "mcp-test-extra", "value": 77})
    kept = await plan_on(target, doc)
    assert kept.steps == [] and kept.left_alone == {"sgts": ["mcp-test-extra"]}
    pruned = await plan_on(target, doc, prune=True)
    assert [(s.op, s.name) for s in pruned.steps] == [("delete", "mcp-test-extra")]
    # `only` narrows both import and prune: nothing named Employees* is extra.
    narrowed = await plan_on(target, doc, prune=True, only=["Employees*"])
    assert narrowed.steps == []


async def test_prune_deletes_in_reverse_dependency_order() -> None:
    doc = await export_of(empty_objects(), NON_POLICY)
    plan = await plan_on(lab_objects(), doc, prune=True, only=["mcp-test-*", "Dev_*", "Employees"])
    sections = [s.section for s in plan.steps]
    assert all(s.op == "delete" for s in plan.steps)
    assert sections.index("nads") < sections.index("authz_profiles") < sections.index("dacls")
    assert sections.index("egress_matrix") < sections.index("sgts")


async def test_plan_blockers() -> None:
    doc = await export_of(lab_objects(), ["sgts"])
    plan = await plan_on(lab_objects(), doc, secrets={"sw-unknown": {"radius": "x"}})
    assert any("secrets given for NADs not in this import: sw-unknown" in b for b in plan.blockers)
    partial = copy.deepcopy(doc)
    partial[HEADER]["incomplete"] = {"sgts": "first 1 of 2"}
    plan = await plan_on(lab_objects(), partial, prune=True)
    assert any("partial export" in b for b in plan.blockers)


async def test_policy_rules_create_update_and_move() -> None:
    doc = await export_of(lab_objects(), ["policy_sets"])
    rules = doc["policy_sets"]["network-access"]["sets"][0]["authorization"]
    rules[0]["state"] = "disabled"  # a change
    rules[1], rules[2] = rules[2], rules[1]  # a move
    rules[1]["rank"], rules[2]["rank"] = 1, 2
    rules.insert(3, {**copy.deepcopy(rules[3]), "name": "mcp-test-new", "rank": 3})  # a create
    for i, r in enumerate(rules):
        r["rank"] = i
    with router() as r:
        serve(r, lab_objects())
        r.get("/api/v1/policy/network-access/condition").respond(
            json={
                "response": [
                    {"id": _uuid(60 + i), "name": n}
                    for i, n in enumerate(
                        [
                            "Wireless_Access",
                            "Wired_MAB",
                            "Wireless_MAB",
                            "Wired_802.1X",
                            "Wireless_802.1X",
                            "Network_Access_Authentication_Passed",
                            "Compliance_Unknown_Devices",
                            "Non_Compliant_Devices",
                            "Compliant_Devices",
                            "BYOD_is_Registered",
                            "EAP-TLS",
                            "MAC_in_SAN",
                            "EAP-MSCHAPv2",
                            "Guest_Flow",
                            "Non_Cisco_Profiled_Phones",
                        ]
                    )
                ]
            }
        )
        r.get("/api/v1/policy/network-access/dictionaries/authorization").respond(
            json={"response": [{"dictionaryName": "IdentityGroup", "name": "Name", "dataType": "STRING"}]}
        )
        for path in ("authorization-profiles", "security-groups"):
            r.get(f"/api/v1/policy/network-access/{path}").respond(
                json={
                    "response": [
                        {"name": n}
                        for n in (
                            "Block_Wireless_Access",
                            "Cisco_IP_Phones",
                            "Non_Cisco_IP_Phones",
                            "Cisco_Temporal_Onboard",
                            "PermitAccess",
                            "NSP_Onboard",
                            "Cisco_WebAuth",
                            "DenyAccess",
                            "BYOD",
                            "Guests",
                        )
                    ]
                }
            )
        app = IseApp(make_settings())
        try:
            plan = await plan_import(app, doc)
        finally:
            await app.aclose()
    assert plan.blockers == []
    ops = {(s.op, s.name.rsplit("/", 1)[-1]): s.changes for s in plan.steps}
    assert ops[("update", rules[0]["name"])] == {"state": {"from": "enabled", "to": "disabled"}}
    assert ("create", "mcp-test-new") in ops
    moved = [k for k, v in ops.items() if v and "rank" in v]
    assert len(moved) == 1  # one of the swapped pair; the rules below the insert are not moves


def test_condition_api() -> None:
    lib = {"wired_mab": {"id": "c1", "name": "Wired_MAB"}}
    node = condition_api({"not": {"and": ["Wired_MAB", "Radius:NAS-Port-Type equals Ethernet"]}}, lib)
    assert node is not None and node["conditionType"] == "ConditionAndBlock" and node["isNegate"] is True
    assert node["children"][0] == {
        "conditionType": "ConditionReference",
        "isNegate": False,
        "id": "c1",
        "name": "Wired_MAB",
    }
    assert node["children"][1]["attributeName"] == "NAS-Port-Type"
    assert condition_api("NOT Wired_MAB", lib)["isNegate"] is True  # type: ignore[index]
    with pytest.raises(InvalidRequest):
        condition_api({"xor": []}, lib)


def test_given_changes_ignores_fields_the_export_leaves_out() -> None:
    live = {"name": "a", "value": 1, "extra": True, "nested": {"x": 1, "y": 2}}
    assert given_changes(live, {"name": "a", "nested": {"x": 1}}) == {}
    assert given_changes(live, {"name": "a", "nested": {"x": 3}}) == {"nested.x": {"from": 1, "to": 3}}


async def test_apply_stops_at_first_failure() -> None:
    calls: list[str] = []

    def step(name: str, fail: bool = False) -> Step:
        async def run() -> Any:
            calls.append(name)
            if fail:
                raise UpstreamError("ISE rejected the request (400): bad value")
            return name

        return Step("create", "sgts", name, run)

    plan = ImportPlan(steps=[step("a"), step("b", fail=True), step("c")])
    with pytest.raises(UpstreamError) as e:
        await apply_plan(plan)
    msg = str(e.value)
    assert calls == ["a", "b"]
    assert "step 2 of 3 (create sgts b)" in msg and "Applied before it (1): create sgts a" in msg
    assert "Not attempted: 1 step(s)" in msg


async def test_tool_preview_and_apply() -> None:
    doc = await export_of(lab_objects(), ["sgts"])
    target = lab_objects()
    target["sgt"] = [target["sgt"][0]]  # Dev_Servers is missing
    with router() as r:
        serve(r, target)
        created = r.post("/ers/config/sgt").respond(
            201, headers={"Location": f"{BASE}/ers/config/sgt/{_uuid(70)}"}
        )
        server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
        async with Client(server) as c:
            args = {"source": to_yaml(doc)}
            preview = (await c.call_tool("ise_import_config", args)).structured_content
            assert preview is not None and preview["status"] == "preview", preview
            assert preview["preview"]["summary"] == {"create": 1, "update": 0, "delete": 0, "unchanged": 1}
            assert preview["blast_radius"] == 1
            done = (
                await c.call_tool("ise_import_config", {**args, "confirm": preview["confirm"]})
            ).structured_content
    assert done is not None and done["status"] == "applied" and done["result"]["applied"] == 1
    sent = json.loads(created.calls.last.request.content)
    assert sent == {"Sgt": {"name": "Dev_Servers", "value": 12}}
    for s in SECRETS:
        assert s not in json.dumps(preview)


async def test_tool_is_dangerous_tier() -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_import_config" not in names and "ise_export_config" in names

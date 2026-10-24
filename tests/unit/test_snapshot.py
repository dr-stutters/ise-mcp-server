"""ise_snapshot / ise_compare_snapshot (I82) on the core snapshot contract (C53).

Shapes follow the live ISE 3.5 reads of 2026-10-24: /api/v1/deployment/node (standalone node), ERS
pxgridnode detail, ERS networkdevice with 'Location#All Locations#<site>' groups, and MnT AuthStatus
records (see test_radius). Addresses are documentation ranges.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import httpx
import respx

from ise_mcp._core.snapshot import parse
from ise_mcp._core.testing import call_tool
from ise_mcp.tools.snapshot import in_location
from tests.unit.conftest import ers_page, fixture_json, make_server
from tests.unit.test_radius import BR1_IP, HQ_IP, M1, M2, M3, M4, auth_list, mock_mnt, rec, status

CATC_CLIENT = fixture_json("ers_pxgridnode_catc.json")["PxgridNode"]
FMC_CLIENT = {"id": "iseagent-fmc-1@xgrid.cisco.com", "name": "iseagent-fmc-1", "status": "enabled"}


def nad(nid: str, name: str, ip: str, location: str) -> dict[str, Any]:
    return {
        "id": nid,
        "name": name,
        "NetworkDeviceIPList": [{"ipaddress": ip, "mask": 32}],
        "NetworkDeviceGroupList": [
            f"Location#All Locations#{location}" if location else "Location#All Locations",
            "Device Type#All Device Types",
            "IPSEC#Is IPSEC Device#No",
        ],
        "authenticationSettings": {"radiusSharedSecret": "REDACTED"},
    }


NADS = [
    nad("11111111-0000-0000-0000-000000000001", "br1-edge", BR1_IP, "br1"),
    nad("11111111-0000-0000-0000-000000000002", "hq-sw1", HQ_IP, "HQ#Floor1"),
    nad("11111111-0000-0000-0000-000000000003", "br10-edge", "198.51.100.110", "br10"),
]


def body(out: object) -> dict[str, Any]:
    return out if isinstance(out, dict) else json.loads(str(out))


def healthy_mnt() -> dict[str, str]:
    return {
        M1: status(M1, rec(M1, minutes_ago=3, ms=110, nad="hq-sw1", nas_ip=HQ_IP)),
        M2: status(M2, rec(M2, minutes_ago=5, ms=20, nad="hq-sw1", nas_ip=HQ_IP, method="mab")),
        M3: status(M3, rec(M3, minutes_ago=4, ms=900, nad="br1-edge", nas_ip=BR1_IP)),
        M4: status(
            M4,
            rec(M4, minutes_ago=6, ms=25, nad="br1-edge", nas_ip=BR1_IP, method="mab"),
            # Outside the 15-minute window: never counted.
            rec(
                M4,
                minutes_ago=40,
                ms=None,
                nad="br1-edge",
                nas_ip=BR1_IP,
                passed=False,
                msg="5400",
                reason="22056 Subject not found in the applicable identity store(s)",
            ),
        ),
    }


def degraded_mnt() -> dict[str, str]:
    """br1's RADIUS replies are dropped on the way back: EAP times out (5411), MAB fails."""
    fail = {"nad": "br1-edge", "nas_ip": BR1_IP, "passed": False, "ms": None, "msg": "5400"}
    timeout = "5411 Supplicant stopped responding to ISE"
    out = healthy_mnt()
    out[M3] = status(
        M3,
        rec(M3, minutes_ago=2, reason=timeout, **fail),  # type: ignore[arg-type]
        rec(M3, minutes_ago=4, reason=timeout, **fail),  # type: ignore[arg-type]
    )
    out[M4] = status(
        M4,
        rec(M4, minutes_ago=3, method="mab", reason="22056 Subject not found", **fail),  # type: ignore[arg-type]
    )
    return out


SESSIONS = ((M1, HQ_IP), (M2, HQ_IP), (M3, BR1_IP), (M4, BR1_IP))


def mock_ise(
    mock: respx.MockRouter,
    histories: dict[str, str],
    *,
    clients: list[dict[str, Any]] | None = None,
    nads: list[dict[str, Any]] | None = None,
) -> None:
    nads = NADS if nads is None else nads
    mock_mnt(mock, histories, auth_list(*SESSIONS))
    mock.get("/api/v1/endpoint").respond(json=[])
    nodes = fixture_json("openapi_deployment_node.json")
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=nodes)

    def nad_search(request: httpx.Request) -> httpx.Response:
        flt = request.url.params.get("filter", "")
        if flt.startswith("location.CONTAINS."):
            value = flt.removeprefix("location.CONTAINS.").lower()
            hits = [n for n in nads if any(value in g.lower() for g in n["NetworkDeviceGroupList"][:1])]
        elif flt.startswith("name.STARTSW."):
            value = flt.removeprefix("name.STARTSW.").lower()
            hits = [n for n in nads if n["name"].lower().startswith(value)]
        else:
            hits = nads
        return httpx.Response(200, json=ers_page([{"id": n["id"], "name": n["name"]} for n in hits]))

    mock.get("/ers/config/networkdevice").mock(side_effect=nad_search)
    for n in nads:
        mock.get(f"/ers/config/networkdevice/{n['id']}").respond(json={"NetworkDevice": n})
    clients = [CATC_CLIENT, FMC_CLIENT] if clients is None else clients
    mock.get("/ers/config/pxgridnode").respond(
        json=ers_page([{"id": c["id"], "name": c["name"]} for c in clients])
    )
    for c in clients:
        mock.get(f"/ers/config/pxgridnode/{c['id']}").respond(json={"PxgridNode": c})


async def snapshot(site: str = "") -> dict[str, Any]:
    return body(await call_tool(make_server(), "ise_snapshot", {"site": site}))


async def compare(before: dict[str, Any], after: dict[str, Any] | None = None) -> dict[str, Any]:
    args: dict[str, Any] = {"before": before}
    if after is not None:
        args["after"] = after
    return body(await call_tool(make_server(), "ise_compare_snapshot", args))


async def test_snapshot_blob_sections_and_no_volatile_fields(mock: respx.MockRouter) -> None:
    mock_ise(mock, healthy_mnt())
    blob = await snapshot()
    parse(blob, prefix="ise")  # valid schema 1 blob, digest intact
    assert blob["prefix"] == "ise" and blob["server"] == "ise-mcp-server" and blob["scope"] == {}
    s = blob["sections"]
    assert set(s) == {"nad_auth", "nodes", "pxgrid_clients"}
    assert s["nad_auth"]["items"] == {
        "nad:br1-edge": {"ok": True, "failure_pct": 0, "timeouts": 0},
        "nad:br10-edge": {"ok": True, "failure_pct": 0, "timeouts": 0},  # quiet NAD: stable item
        "nad:hq-sw1": {"ok": True, "failure_pct": 0, "timeouts": 0},
    }
    assert s["nad_auth"]["metrics"]["failure_pct"] == {"better": "lower", "tolerance": 10}
    assert s["nodes"]["items"] == {
        "node:ise": {
            "ok": True,
            "state": "Connected",
            "roles": "Standalone",
            "services": "DeviceAdmin,Profiler,SXP,Session,pxGrid",
        }
    }
    assert s["pxgrid_clients"]["items"]["pxgrid:pxgrid_client_1792556221"] == {
        "ok": True,
        "state": "enabled",
        "consumer": "Catalyst Center",
    }
    text = json.dumps(blob)
    for volatile in ("requests", "avg_ms", "response_time", "last_seen", "psns", "acs_timestamp"):
        assert volatile not in text


async def test_unchanged_deployment_compares_as_no_change(mock: respx.MockRouter) -> None:
    mock_ise(mock, healthy_mnt())
    before = await snapshot()
    after = await snapshot()
    out = await compare(before, after)
    assert out["verdict"] == "No change (6 items compared)."
    assert out["counts"] == {"major": 0, "minor": 0, "info": 0} and not out.get("changes")
    # An empty `after` takes a fresh snapshot of the same scope: still no change.
    fresh = await compare(before)
    assert fresh["verdict"].startswith("No change")


async def test_degraded_branch_names_the_nad_and_client(mock: respx.MockRouter) -> None:
    mock_ise(mock, healthy_mnt())
    before = await snapshot()
    mock.reset()
    mock.routes.clear()
    mock_ise(mock, degraded_mnt(), clients=[CATC_CLIENT, {**FMC_CLIENT, "status": "disabled"}])
    out = await compare(before, await snapshot())
    major = {c["item"]: c for c in out["changes"] if c["severity"] == "major"}
    assert set(major) == {"nad:br1-edge", "pxgrid:iseagent-fmc-1"}
    br1 = major["nad:br1-edge"]
    assert br1["kind"] == "degraded" and br1["section"] == "nad_auth"
    assert "healthy -> unhealthy" in br1["what"] and "failure_pct 0 -> 100" in br1["what"]
    assert "timeouts 0 -> 2" in br1["what"] and "5411 Supplicant stopped responding" in br1["what"]
    assert "state enabled -> disabled" in major["pxgrid:iseagent-fmc-1"]["what"]
    assert out["counts"]["major"] == 2 and out["unchanged_items"] == 4  # hq-sw1, br10-edge, node, catc


async def test_site_is_an_ndg_location_or_a_name_prefix(mock: respx.MockRouter) -> None:
    mock_ise(mock, healthy_mnt())
    blob = await snapshot("br1")  # location 'br1', not 'br10' (exact level match)
    assert blob["scope"] == {"site": "br1"}
    assert list(blob["sections"]["nad_auth"]["items"]) == ["nad:br1-edge"]
    nested = await snapshot("Floor1")  # any level of the location path
    assert list(nested["sections"]["nad_auth"]["items"]) == ["nad:hq-sw1"]
    by_name = await snapshot("hq-")  # no location matches: NAD name prefix
    assert list(by_name["sections"]["nad_auth"]["items"]) == ["nad:hq-sw1"]
    nothing = await snapshot("nowhere")
    assert "No NAD in NDG location 'nowhere'" in nothing["sections"]["nad_auth"]["error"]
    assert nothing["sections"]["nodes"]["items"]  # other sections still read


async def test_unreadable_section_does_not_sink_the_snapshot(mock: respx.MockRouter) -> None:
    mock_ise(mock, healthy_mnt())
    before = await snapshot()
    mock.get("/ers/config/pxgridnode").respond(500, json={"ERSResponse": {"messages": [{"title": "boom"}]}})
    after = await snapshot()
    assert "error" in after["sections"]["pxgrid_clients"] and after["sections"]["nodes"]["items"]
    out = await compare(before, after)
    assert [(c["severity"], c["kind"], c["section"]) for c in out["changes"]] == [
        ("minor", "unreadable", "pxgrid_clients")
    ]


async def test_compare_refuses_another_servers_blob(mock: respx.MockRouter) -> None:
    mock_ise(mock, healthy_mnt())
    blob = copy.deepcopy(await snapshot())
    blob["prefix"] = "catc"
    async with __import__("fastmcp").Client(make_server()) as c:
        r = await c.call_tool("ise_compare_snapshot", {"before": blob}, raise_on_error=False)
    assert r.is_error


def test_in_location() -> None:
    br1 = NADS[0]
    assert in_location(br1, "br1") and in_location(br1, "BR1")
    assert in_location(br1, "Location#All Locations#br1") and in_location(br1, "All Locations#br1")
    assert not in_location(br1, "br10") and not in_location(NADS[2], "br1")
    assert in_location(NADS[1], "HQ") and in_location(NADS[1], "hq#floor1") and in_location(NADS[1], "Floor1")

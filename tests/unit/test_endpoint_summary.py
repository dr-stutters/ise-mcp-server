"""ise_endpoint_summary (I59): device-type aggregate, endpoint-list scans (profile, identity group) with
the page cap and its note, the NDG split from active sessions, top-N and the next tool per row.

Shapes: /api/v1/endpoint/deviceType/summary is a bare list with string totals (lab ISE 3.5, 2026-10-28),
/api/v1/endpoint rows carry profileId and groupId ('' when unprofiled), /api/v1/profiler/policy is the
recorded profiler_rules.json. Synthetic counts; documentation addresses."""

from __future__ import annotations

import json
from typing import Any

import httpx
import respx

from ise_mcp._core.testing import call_tool
from ise_mcp.tools.endpoint_summary import device_type_counts, is_randomized, ndg_label
from tests.unit.conftest import ers_page, fixture_json, make_server, xml

UNKNOWN_GID = "aa0e8b20-8bff-11e6-996c-525400b48521"
PHONES_GID = "14f5cac0-8c00-11e6-996c-525400b48521"
IOT_GID = "0b1f3a40-0000-4000-8000-000000000001"
PHONE_PID = "5f2a6f30-0000-4000-8000-000000000001"
PRINTER_PID = "5f2a6f30-0000-4000-8000-000000000002"
GROUPS = [
    {"id": UNKNOWN_GID, "name": "Unknown"},
    {"id": PHONES_GID, "name": "Cisco-IP-Phone"},
    {"id": IOT_GID, "name": "mcp-iot"},
]


def mac(i: int, *, randomized: bool = False) -> str:
    first = "02" if randomized else "00"
    return f"{first}:00:5E:00:{i // 256:02X}:{i % 256:02X}"


def endpoint(i: int, *, group: str, profile: str = "", randomized: bool = False) -> dict[str, Any]:
    m = mac(i, randomized=randomized)
    return {
        "id": f"00000000-0000-4000-8000-{i:012d}",
        "name": m,
        "mac": m,
        "groupId": group,
        "profileId": profile,
        "staticGroupAssignment": False,
    }


def population() -> list[dict[str, Any]]:
    """250 endpoints: 150 unknown (10 randomized), 60 phones, 40 printers in mcp-iot."""
    eps = [endpoint(i, group=UNKNOWN_GID, randomized=i < 10) for i in range(150)]
    eps += [endpoint(1000 + i, group=PHONES_GID, profile=PHONE_PID) for i in range(60)]
    eps += [endpoint(2000 + i, group=IOT_GID, profile=PRINTER_PID) for i in range(40)]
    return eps


SUMMARY = [
    {"deviceType": "unknown", "total": "150"},
    {"deviceType": "Cisco-IP-Phone", "total": "60"},
    {"deviceType": "Printer", "total": "40"},
]


def mock_endpoints(mock: respx.MockRouter, eps: list[dict[str, Any]]) -> respx.Route:
    def page(request: httpx.Request) -> httpx.Response:
        n, size = int(request.url.params.get("page", 1)), int(request.url.params.get("size", 100))
        return httpx.Response(200, json=eps[(n - 1) * size : n * size])

    return mock.get("/api/v1/endpoint").mock(side_effect=page)


def mock_ise(mock: respx.MockRouter, *, summary: Any = None, eps: list[dict[str, Any]] | None = None) -> None:
    mock.get("/api/v1/endpoint/deviceType/summary").respond(json=SUMMARY if summary is None else summary)
    mock.get("/api/v1/profiler/policy").respond(json=fixture_json("profiler_rules.json"))
    mock.get("/ers/config/endpointgroup").respond(json=ers_page(GROUPS))
    mock.get(f"/ers/config/profilerprofile/{PHONE_PID}").respond(
        json={"ProfilerProfile": {"id": PHONE_PID, "name": "Cisco-IP-Phone-8841"}}
    )
    mock.get(f"/ers/config/profilerprofile/{PRINTER_PID}").respond(
        json={"ProfilerProfile": {"id": PRINTER_PID, "name": "HP-Printer"}}
    )
    mock_endpoints(mock, population() if eps is None else eps)


async def summary(**args: Any) -> dict[str, Any]:
    out = await call_tool(make_server(), "ise_endpoint_summary", args)
    return out if isinstance(out, dict) else json.loads(str(out))


def test_helpers() -> None:
    assert device_type_counts({"response": [{"deviceType": "x", "total": "3"}, {"total": "2"}]}) == {
        "x": 3,
        "unknown": 2,
    }
    assert is_randomized("02:00:5E:00:00:01") and is_randomized("DA-A1-19-00-00-01")
    assert not is_randomized("00:50:56:00:00:01") and not is_randomized("03:00:00:00:00:01")  # multicast
    assert ndg_label("Location#All Locations#HQ#Floor1") == "Location: HQ#Floor1"
    assert ndg_label("Device Type#All Device Types") == "Device Type: (all)"


async def test_by_device_type_one_request_top_n_and_next(mock: respx.MockRouter) -> None:
    mock_ise(mock)
    scan = mock.routes[-1]
    out = await summary(by="device_type", top=2)
    assert not scan.called  # the aggregate needs no endpoint scan
    assert out["total_endpoints"] == 250 and out["groups"] == 3
    rows = out["rows"]
    assert [(r["name"], r["endpoints"], r["share_pct"]) for r in rows] == [
        ("unknown", 150, 60.0),
        ("Cisco-IP-Phone", 60, 24.0),
    ]
    assert out["other"] == {"groups": 1, "endpoints": 40}
    assert "ise_set_profiling_rule" in rows[0]["next"] and "ise_explain_profile" in rows[0]["next"]
    assert "ise_create_group(kind='endpoint', name='Cisco-IP-Phone')" in rows[1]["next"]
    assert "ise_set_sgt" in rows[1]["next"]
    # Custom profiling rules' matched counts ride along.
    assert {r["rule"] for r in out["profiling_rules"]} >= {"mcp-prof-captured"}
    assert "ise_compare_snapshot" in out["next"]


async def test_by_identity_group_names_groups_and_counts_randomized(mock: respx.MockRouter) -> None:
    mock_ise(mock)
    out = await summary(by="identity_group")
    assert [(r["name"], r["endpoints"]) for r in out["rows"]] == [
        ("Unknown", 150),
        ("Cisco-IP-Phone", 60),
        ("mcp-iot", 40),
    ]
    assert out["scanned"] == 250 and out["truncated"] is False and "note" not in out
    assert out["randomized_macs"] == 10 and "802.1X" in out["randomized_note"]
    assert "Catch-all" in out["rows"][0]["next"]
    assert "IdentityGroup:Name equals Endpoint Identity Groups:mcp-iot" in out["rows"][2]["next"]
    assert "profiling_rules" not in out


async def test_by_profile_resolves_names_and_flags_unprofiled(mock: respx.MockRouter) -> None:
    mock_ise(mock)
    out = await summary(by="profile")
    assert [(r["name"], r["endpoints"]) for r in out["rows"]] == [
        ("(unprofiled)", 150),
        ("Cisco-IP-Phone-8841", 60),
        ("HP-Printer", 40),
    ]
    assert "Not profiled" in out["rows"][0]["next"]
    assert "EndPoints:EndPointPolicy equals HP-Printer" in out["rows"][2]["next"]


async def test_scan_cap_is_flagged(mock: respx.MockRouter) -> None:
    mock_ise(mock)
    out = await summary(by="identity_group", max_endpoints=100)
    assert out["scanned"] == 100 and out["truncated"] is True
    assert "first 100 endpoints of 250" in out["note"] and "max_endpoints" in out["note"]
    assert out["total_endpoints"] == 250  # the true total still comes from the aggregate


async def test_without_the_aggregate_scans_still_work(mock: respx.MockRouter) -> None:
    mock_ise(mock)
    mock.get("/api/v1/endpoint/deviceType/summary").respond(404, json={"message": "not found"})
    out = await summary(by="identity_group")
    assert "total_endpoints" not in out and "No device-type summary" in out["total_note"]
    assert out["scanned"] == 250 and out["truncated"] is False
    async with __import__("fastmcp").Client(make_server()) as c:
        r = await c.call_tool("ise_endpoint_summary", {"by": "device_type"}, raise_on_error=False)
    assert r.is_error and "by='profile'" in str(r.content[0])


ACTIVE = xml(
    '<activeList noOfActiveSession="4">'
    + "".join(
        f"<activeSession><calling_station_id>{m}</calling_station_id>"
        f"<nas_ip_address>{ip}</nas_ip_address></activeSession>"
        for m, ip in (
            (mac(1), "192.0.2.10"),
            (mac(2), "192.0.2.10"),
            (mac(3, randomized=True), "198.51.100.20"),
            (mac(4), "203.0.113.99"),  # no NAD covers it
        )
    )
    + "</activeList>"
)


def nad(nid: str, name: str, ip: str, location: str) -> dict[str, Any]:
    return {
        "id": nid,
        "name": name,
        "NetworkDeviceIPList": [{"ipaddress": ip, "mask": 32}],
        "NetworkDeviceGroupList": [
            f"Location#All Locations#{location}",
            "Device Type#All Device Types#Switch",
        ],
    }


async def test_by_ndg_counts_session_endpoints_per_nad_group(mock: respx.MockRouter) -> None:
    mock_ise(mock)
    nads = [
        nad("11111111-0000-0000-0000-000000000001", "hq-sw1", "192.0.2.10", "HQ#Floor1"),
        nad("11111111-0000-0000-0000-000000000002", "br1-sw1", "198.51.100.20", "br1"),
    ]
    mock.get("/admin/API/mnt/Session/ActiveList").respond(text=ACTIVE)
    mock.get("/ers/config/networkdevice").respond(
        json=ers_page([{"id": n["id"], "name": n["name"]} for n in nads])
    )
    for n in nads:
        mock.get(f"/ers/config/networkdevice/{n['id']}").respond(json={"NetworkDevice": n})
    out = await summary(by="ndg")
    rows = {r["name"]: r["endpoints"] for r in out["rows"]}
    assert rows == {
        "Device Type: Switch": 3,
        "Location: HQ#Floor1": 2,
        "Location: br1": 1,
        "(no matching NAD)": 1,
    }
    assert out["rows"][0]["name"] == "Device Type: Switch"
    assert out["endpoints_in_session"] == 4 and out["randomized_macs"] == 1
    assert "active session" in out["scope"]
    no_nad = next(r for r in out["rows"] if r["name"] == "(no matching NAD)")
    assert "ise_audit_nads" in no_nad["next"]

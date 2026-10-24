"""ise_snapshot / ise_compare_snapshot: the core snapshot contract (C53) for pre/post change checks (I82).

Three sections, one product read each, every one allowed to fail on its own:
- `nad_auth`: per NAD in scope, the failure % and timeouts over a fixed 15-minute window before the
  snapshot, from MnT auth history (the same per-MAC reads and grouping as ise_nad_radius_stats);
- `nodes`: persona, services and sync state per deployment node (OpenAPI);
- `pxgrid_clients`: state per registered pxGrid client (ERS).

Volatile values (request counts, response times, timestamps, PSN shares) stay out of the blob, so two
snapshots of an unchanged deployment compare as "No change". Nothing is stored on the server (ADR-003).
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import ipaddress
from collections import Counter
from collections.abc import Coroutine
from datetime import UTC, datetime, timedelta
from typing import Any

from fastmcp import Context

from ise_mcp._core import NotFound, ToolRegistrar, UpstreamError, get_client
from ise_mcp._core.snapshot import Metric, Section, Snapshot, register_snapshot_tools
from ise_mcp._core.targets import target_name
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list, gather_limited
from ise_mcp.tools.activity import NadFilter, candidate_macs
from ise_mcp.tools.config_export import server_version
from ise_mcp.tools.network import all_nads, nad_networks
from ise_mcp.tools.pxgrid import all_clients
from ise_mcp.tools.radius import _time, summarise
from ise_mcp.tools.sessions import auth_history, is_coa_record
from ise_mcp.tools.system import _response

WINDOW_MINUTES = 15
MAX_LOOKUPS = 60  # MACs whose history is read (one MnT call each): a snapshot takes seconds
RECORDS_PER_MAC = 50
# A NAD is unhealthy when anything timed out through it, or when at least MIN_FAILED attempts failed
# and they are at least FAILURE_LIMIT % of its attempts (one stray failure on a quiet NAD is not).
FAILURE_LIMIT = 20
MIN_FAILED = 3
NAD_METRICS = {
    "failure_pct": Metric("lower", 10),
    "timeouts": Metric("lower", 0),
}
LOCATION_ROOT = "Location#All Locations"


def locations(nad: dict[str, Any]) -> list[str]:
    """The NAD's location groups below the root, e.g. ['HQ#Floor1'] for 'Location#All Locations#HQ#Floor1'."""
    out = []
    for g in nad.get("NetworkDeviceGroupList") or []:
        text = str(g)
        if text.startswith(LOCATION_ROOT + "#"):
            out.append(text.removeprefix(LOCATION_ROOT + "#"))
    return out


def in_location(nad: dict[str, Any], site: str) -> bool:
    """`site` names one location (any level, case-insensitive) or a path below 'All Locations'."""
    want = site.strip().lower().removeprefix(LOCATION_ROOT.lower() + "#").removeprefix("all locations#")
    for loc in locations(nad):
        low = loc.lower()
        if low == want or low.startswith(want + "#") or want in low.split("#"):
            return True
    return False


class ScopeFilter(NadFilter):
    """Matches auth records from any NAD in the snapshot's scope (by NAD name, else NAS IP)."""

    def __init__(self, label: str, nads: list[dict[str, Any]]) -> None:
        super().__init__(label, [n for nad in nads for n in nad_networks(nad)], None)
        self.by_name = {str(n["name"]): nad_networks(n) for n in nads if n.get("name")}
        self.names = set(self.by_name)

    def nad_of(self, nas_ip: Any, nad_name: Any) -> str | None:
        if nad_name and str(nad_name) in self.names:
            return str(nad_name)
        try:
            addr = ipaddress.ip_address(str(nas_ip or "").strip())
        except ValueError:
            return None
        for name, nets in self.by_name.items():
            if any(addr.version == n.version and addr in n for n in nets):
                return name
        return None

    def matches(self, nas_ip: Any, nad_name: Any = None) -> bool:
        return self.nad_of(nas_ip, nad_name) is not None


async def scoped_nads(app: IseApp, site: str) -> tuple[list[dict[str, Any]], str]:
    """The NADs a snapshot covers and how they were chosen: every NAD for an empty site, else the NADs in
    that NDG location, else the NADs whose name starts with it."""
    if not site.strip():
        nads, _ = await all_nads(app)
        return nads, "every NAD"
    key = site.strip()
    leaf = key.split("#")[-1]
    page = await ers_list(
        app,
        "networkdevice",
        filters=[f"location.CONTAINS.{leaf}"],
        limit=1000,
        offset=0,
        detail=True,
        detail_cap=None,
    )
    nads = [n for n in page.items if isinstance(n, dict) and in_location(n, key)]
    if nads:
        return nads, f"location {key}"
    page = await ers_list(
        app,
        "networkdevice",
        filters=[f"name.STARTSW.{key}"],
        limit=1000,
        offset=0,
        detail=True,
        detail_cap=None,
    )
    return [n for n in page.items if isinstance(n, dict)], f"name starts with {key}"


def top_failure(records: list[dict[str, Any]]) -> str | None:
    reasons = Counter(
        str(r.get("failure_reason") or r.get("message_code") or "unknown").strip()[:120]
        for r in records
        if str(r.get("passed", "")).lower() != "true"
    )
    return reasons.most_common(1)[0][0] if reasons else None


async def nad_auth_section(app: IseApp, sec: Section, site: str, end: datetime) -> None:
    nads, how = await scoped_nads(app, site)
    if not nads:
        sec.fail(f"No NAD in NDG location {site!r} and none whose name starts with it (ise_list_nads)")
        return
    flt = ScopeFilter(how, nads)
    start = end - timedelta(minutes=WINDOW_MINUTES)
    cand = await candidate_macs(app, start, end, flt, None, MAX_LOOKUPS, include_endpoint_db=True)

    async def history(mac: str) -> list[dict[str, Any]]:
        try:
            return await auth_history(app, mac, WINDOW_MINUTES, RECORDS_PER_MAC)
        except (UpstreamError, NotFound):
            return []  # one endpoint's history must not sink the section

    by_nad: dict[str, list[dict[str, Any]]] = {name: [] for name in flt.names}
    for recs in await gather_limited(list(cand.macs), history):
        for r in recs:
            if is_coa_record(r):
                continue
            at = _time(r.get("acs_timestamp"))
            if at is None or at < start or at > end:
                continue
            if name := flt.nad_of(r.get("nas_ip_address"), r.get("network_device_name")):
                by_nad[name].append({**r, "network_device_name": name})
    failed = any(str(r.get("passed", "")).lower() != "true" for recs in by_nad.values() for r in recs)
    catalog = await app.failure_reasons() if failed else {}
    for name, recs in sorted(by_nad.items()):
        row = summarise(recs, catalog).get(name, {})
        requests, fails, timeouts = row.get("requests", 0), row.get("failed", 0), row.get("timeouts", 0)
        pct = round(100 * fails / requests) if requests else 0
        sec.item(
            f"nad:{name}"[:200],
            ok=not timeouts and not (fails >= MIN_FAILED and pct >= FAILURE_LIMIT),
            failure_pct=pct,
            timeouts=timeouts,
            top_failure=top_failure(recs),
        )


async def nodes_section(app: IseApp, sec: Section) -> None:
    nodes = _response(await app.openapi.get("/api/v1/deployment/node"))
    for n in nodes if isinstance(nodes, list) else []:
        if not isinstance(n, dict) or not n.get("hostname"):
            continue
        status = str(n.get("nodeStatus") or "")
        sec.item(
            f"node:{n['hostname']}",
            ok=status.lower() == "connected" if status else None,
            state=status or None,
            roles=",".join(sorted(str(r) for r in n.get("roles") or [])) or None,
            services=",".join(sorted(str(s) for s in n.get("services") or [])) or None,
        )


async def pxgrid_section(app: IseApp, sec: Section) -> None:
    for c in await all_clients(app):
        state = c.get("state")
        sec.item(
            f"pxgrid:{c['name']}"[:200],
            ok=True if state == "enabled" else False if state == "disabled" else None,
            state=state,
            consumer=c.get("consumer"),
        )


async def take(ctx: Context, site: str) -> Snapshot:
    app: IseApp = get_client(ctx)
    snap = Snapshot(
        "ise",
        "ise-mcp-server",
        scope={"site": site.strip()},
        server_version=server_version(),
        instance=target_name(),
    )
    end = datetime.now(UTC)
    nads = snap.section(
        "nad_auth", f"Authentications per NAD (last {WINDOW_MINUTES} min)", metrics=NAD_METRICS
    )
    nodes = snap.section("nodes", "Deployment nodes")
    pxgrid = snap.section("pxgrid_clients", "pxGrid clients")
    reads: list[tuple[Section, Coroutine[Any, Any, None]]] = [
        (nads, nad_auth_section(app, nads, site, end)),
        (nodes, nodes_section(app, nodes)),
        (pxgrid, pxgrid_section(app, pxgrid)),
    ]
    for sec, read in reads:
        try:
            await read
        except (UpstreamError, NotFound) as e:
            sec.fail(str(e))  # one unreadable section never fails the whole snapshot
    return snap


def register(reg: ToolRegistrar) -> None:
    register_snapshot_tools(
        reg,
        take,
        product="Cisco ISE",
        covers=(
            f"failure % and timeouts per NAD over the {WINDOW_MINUTES} minutes before the snapshot (MnT), "
            "node persona and sync state, pxGrid client states"
        ),
        site_doc=(
            "NDG location (e.g. 'br1' or 'HQ#Floor1') or, when no location matches, a NAD name prefix; "
            "empty = every NAD"
        ),
    )

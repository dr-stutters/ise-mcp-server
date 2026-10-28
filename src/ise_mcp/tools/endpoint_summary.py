"""ise_endpoint_summary (I59): what is on the network, by device type, profile, identity group or NDG.

The first question of a profiling visibility phase (classify before enforce) and of every IoT
segmentation design; it decides which endpoint identity groups and SGTs to create. One call instead of
paging the whole endpoint list:

- by='device_type': GET /api/v1/endpoint/deviceType/summary (ISE's own aggregate, one request; 3.3+),
  plus the matched-endpoint count of each custom profiling rule (/api/v1/profiler/policy);
- by='profile' / 'identity_group': the OpenAPI endpoint list (profileId, groupId per endpoint), read in
  pages of 100 up to `max_endpoints`; a cut scan is flagged. Profile and group ids become names;
- by='ndg': endpoints with an active session (MnT ActiveList), placed on the NAD their NAS IP belongs
  to, counted per network device group of that NAD (NDGs are a NAD attribute, not an endpoint one).

The endpoint scans also count randomized (locally administered) MACs, which never profile reliably.
Every row names the next tool. Read tier; nothing is changed.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import ipaddress
from collections import Counter
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import NotFound, ToolRegistrar, UpstreamError, get_client, object_result
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_name_map, openapi_all
from ise_mcp.tools.endpoints import is_randomized, profile_name
from ise_mcp.tools.network import all_nads, covering
from ise_mcp.xmlutil import as_list

SUMMARY_PATH = "/api/v1/endpoint/deviceType/summary"
RULES_PATH = "/api/v1/profiler/policy"
ENDPOINTS_PATH = "/api/v1/endpoint"
UNKNOWN_TYPES = {"", "unknown", "none", "null"}
UNPROFILED = "(unprofiled)"
UNKNOWN_GROUP_NAMES = {"unknown", "profiled"}  # ISE's catch-all groups: nothing classified them yet
NO_NAD = "(no matching NAD)"
SCAN_DEFAULT = 2000
Grouping = Literal["device_type", "profile", "identity_group", "ndg"]


def _resp(data: Any) -> Any:
    return data.get("response", data) if isinstance(data, dict) else data


def _int(v: Any) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return 0


def device_type_counts(data: Any) -> Counter[str]:
    """{device type: endpoints} from deviceType/summary ([{deviceType, total}], total is a string)."""
    out: Counter[str] = Counter()
    for e in _resp(data) or []:
        if isinstance(e, dict):
            name = str(e.get("deviceType") or "unknown").strip() or "unknown"
            out[name] += _int(e.get("total"))
    return out


def ndg_label(group: str) -> str:
    """'Location#All Locations#HQ#Floor1' -> 'Location: HQ#Floor1'; a type's root -> 'Location: (all)'."""
    parts = [p for p in str(group).split("#") if p]
    if not parts:
        return str(group)
    kind, rest = parts[0], parts[1:]
    if rest and rest[0].lower().startswith("all "):
        rest = rest[1:]
    return f"{kind}: {'#'.join(rest) if rest else '(all)'}"


def next_step(by: str, name: str) -> str:
    low = name.strip().lower()
    if by == "device_type":
        if low in UNKNOWN_TYPES:
            return (
                "Unclassified: check a sample with ise_explain_profile(mac), then label them with "
                "ise_set_profiling_rule(endpoint_type=[...]) or enable more probes (ise_profiler_status)"
            )
        return (
            f"ise_create_group(kind='endpoint', name='{name}') for policy to match on, then "
            f"ise_set_sgt for the {name} segment"
        )
    if by == "profile":
        if name == UNPROFILED or low == "unknown":
            return (
                "Not profiled: ise_explain_profile(mac) on a sample, then ise_set_profiling_rule, or check "
                "probes with ise_profiler_status"
            )
        return (
            f"ise_create_group(kind='endpoint', name=...) for the {name} endpoints (or match "
            f"EndPoints:EndPointPolicy equals {name} in an authorization rule), then ise_set_sgt"
        )
    if by == "identity_group":
        if low in UNKNOWN_GROUP_NAMES:
            return (
                "Catch-all group: classify these with ise_set_profiling_rule, or move known devices with "
                "ise_set_endpoint / ise_bulk_endpoints into a group of their own (ise_create_group)"
            )
        return (
            f"ise_set_sgt for the {name} segment, assigned by an authorization rule on "
            f"IdentityGroup:Name equals Endpoint Identity Groups:{name}"
        )
    if name == NO_NAD:
        return "Sessions from NAS IPs no NAD covers: ise_audit_nads / ise_create_nad"
    return (
        "ise_list_nads to see the devices in this group; ise_endpoint_summary(by='device_type') for what "
        "the endpoints are, then ise_set_sgt per segment"
    )


def ranked(counts: Counter[str], top: int, total: int | None, by: str) -> dict[str, Any]:
    base = total if total else sum(counts.values())
    rows: list[dict[str, Any]] = []
    for name, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))[:top]:
        rows.append(
            {
                "name": name,
                "endpoints": n,
                "share_pct": round(100 * n / base, 1) if base else None,
                "next": next_step(by, name),
            }
        )
    shown = sum(int(r["endpoints"]) for r in rows)
    out: dict[str, Any] = {"groups": len(counts), "rows": rows}
    if len(counts) > top:
        out["other"] = {"groups": len(counts) - top, "endpoints": sum(counts.values()) - shown}
    return out


async def device_type_summary(app: IseApp) -> Counter[str]:
    return device_type_counts(await app.openapi.get(SUMMARY_PATH))


async def rule_counts(app: IseApp) -> list[dict[str, Any]] | None:
    """Matched-endpoint count per custom/direct/ML profiling rule; None when the API isn't there."""
    try:
        data = _resp(await app.openapi.get(RULES_PATH))
    except (NotFound, UpstreamError):
        return None
    rows = [
        {"rule": r.get("name"), "type": r.get("profilingType"), "endpoints": _int(r.get("matchedEndpoints"))}
        for r in data or []
        if isinstance(r, dict) and r.get("name")
    ]
    return sorted(rows, key=lambda r: (-r["endpoints"], str(r["rule"]).lower()))


async def scan_endpoints(app: IseApp, cap: int) -> list[dict[str, Any]]:
    return [e for e in await openapi_all(app, ENDPOINTS_PATH, cap=cap) if isinstance(e, dict)][:cap]


def scan_note(scanned: int, total: int | None, cap: int) -> dict[str, Any]:
    truncated = (total is not None and scanned < total) or (total is None and scanned >= cap)
    out: dict[str, Any] = {"scanned": scanned, "truncated": truncated}
    if truncated:
        of = f"of {total} " if total is not None else ""
        out["note"] = (
            f"Counted the first {scanned} endpoints {of}(max_endpoints={cap}); shares are of the scanned "
            "endpoints. Raise max_endpoints for a full count (pages of 100, one request each)."
        )
    return out


async def by_scan(app: IseApp, by: str, top: int, cap: int, total: int | None) -> dict[str, Any]:
    eps = await scan_endpoints(app, cap)
    key = "profileId" if by == "profile" else "groupId"
    ids: Counter[str] = Counter(str(e.get(key) or "") for e in eps)
    counts: Counter[str] = Counter()
    if by == "identity_group":
        names = await ers_name_map(app, "endpointgroup")
        for gid, n in ids.items():
            counts[names.get(gid, gid or "(no group)")] += n
    else:
        # Names for the ranked ids only: one ERS read per profile, cached per server.
        order = sorted(ids.items(), key=lambda kv: -kv[1])
        for i, (pid, n) in enumerate(order):
            if not pid:
                counts[UNPROFILED] += n
            elif i < top + 1:
                counts[await profile_name(app, pid) or pid] += n
            else:
                counts[pid] += n
    out = ranked(counts, top, None, by)
    rnd = sum(1 for e in eps if is_randomized(e.get("mac") or e.get("name")))
    out["randomized_macs"] = rnd
    out.update(scan_note(len(eps), total, cap))
    return out


async def by_ndg(app: IseApp, top: int) -> dict[str, Any]:
    active = await app.mnt_get("Session/ActiveList")
    sessions = [s for s in as_list((active or {}).get("activeSession")) if isinstance(s, dict)]
    nads, complete = await all_nads(app)
    seen: dict[str, set[str]] = {}
    macs: set[str] = set()
    for s in sessions:
        mac = str(s.get("calling_station_id") or "").upper()
        ip = str(s.get("nas_ip_address") or "").strip()
        if not mac:
            continue
        macs.add(mac)
        nad = None
        try:
            ipaddress.ip_address(ip)
            hits = covering(nads, ip)
            nad = hits[0][1] if hits else None
        except ValueError:
            pass
        groups = [ndg_label(g) for g in (nad or {}).get("NetworkDeviceGroupList") or []] if nad else [NO_NAD]
        for g in groups:
            seen.setdefault(g, set()).add(mac)
    counts: Counter[str] = Counter({g: len(m) for g, m in seen.items()})
    out = ranked(counts, top, len(macs), "ndg")
    out["endpoints_in_session"] = len(macs)
    out["randomized_macs"] = sum(1 for m in macs if is_randomized(m))
    out["scope"] = (
        "Endpoints with an active session only, per NDG of the NAD they connect through; an endpoint "
        "counts once in each NDG type (Location, Device Type, ...)"
    )
    if not complete:
        out["note"] = "More NADs than could be read: some sessions may show as '(no matching NAD)'"
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Endpoint summary")
    async def ise_endpoint_summary(
        ctx: Context,
        by: Annotated[
            Grouping,
            Field(
                description="'device_type' (ISE's device-type aggregate, one request), 'profile' (endpoint "
                "profiling policy), 'identity_group' (endpoint identity group) or 'ndg' (network device "
                "group of the NAD, endpoints with an active session)"
            ),
        ] = "device_type",
        top: Annotated[int, Field(ge=1, le=200, description="Rows to show, largest first")] = 20,
        max_endpoints: Annotated[
            int,
            Field(
                ge=100,
                le=20000,
                description="by='profile'/'identity_group': endpoints read (pages of 100); a cut scan "
                "is flagged",
            ),
        ] = SCAN_DEFAULT,
    ) -> ToolResult:
        """What is on the network, in one call: endpoint counts by device type, profile, endpoint identity
        group or network device group, largest first, each row with its share and the next tool
        (ise_set_profiling_rule for unclassified endpoints, ise_create_group / ise_set_sgt to segment a
        known type). The first step of a profiling visibility phase or an IoT segmentation design
        (classify before enforce). Also: the total endpoint count, randomized (private) MACs in the
        scanned endpoints, and per custom profiling rule how many endpoints it matched. by='profile' and
        'identity_group' page the endpoint list up to max_endpoints and say when the count was cut;
        by='ndg' covers endpoints with a live session only. For one endpoint use ise_endpoint_360; for
        the endpoints themselves ise_list_endpoints(group=...)."""
        app: IseApp = get_client(ctx)
        out: dict[str, Any] = {"by": by}
        total: int | None = None
        types: Counter[str] | None = None
        try:
            types = await device_type_summary(app)
            total = sum(types.values())
        except (NotFound, UpstreamError) as e:
            if by == "device_type":
                raise UpstreamError(
                    f"ISE did not answer {SUMMARY_PATH} ({e}); it needs ISE 3.3 or later. Try "
                    "by='profile' or by='identity_group' (endpoint list scan)"
                ) from e
            out["total_note"] = f"No device-type summary ({str(e)[:120]}): total is the scanned count"
        if total is not None:
            out["total_endpoints"] = total

        if by == "device_type":
            assert types is not None
            out.update(ranked(types, top, total, by))
            out["source"] = f"GET {SUMMARY_PATH}"
        elif by in ("profile", "identity_group"):
            out.update(await by_scan(app, by, top, max_endpoints, total))
            out["source"] = f"GET {ENDPOINTS_PATH} (pages of 100)"
        else:
            out.update(await by_ndg(app, top))
            out["source"] = "MnT Session/ActiveList + ERS networkdevice"

        if by in ("device_type", "profile"):
            rules = await rule_counts(app)
            if rules:
                out["profiling_rules"] = rules[:top]
        if out.get("randomized_macs"):
            out["randomized_note"] = (
                "Randomized (locally administered) MACs change per SSID or over time and never profile "
                "reliably: identify them by user/certificate (802.1X) rather than by MAC or profile"
            )
        out["next"] = (
            "ise_snapshot records the device types, so ise_compare_snapshot shows new ones after a change"
        )
        return object_result(out)

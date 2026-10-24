"""Per-NAD RADIUS latency and timeouts as ISE saw them, from MnT auth history (pull-only, ADR-003).

ISE's REST surfaces have no per-NAD RADIUS counters: request/retry/drop totals live in the GUI reports
(Operations > Reports > Diagnostics > RADIUS Errors, Network Device Session Status) only. What MnT does
keep is every recorded attempt with `response_time` (ms, from the first request of the attempt to ISE's
final answer), the PSN that answered (`acs_server`) and the failure reason. This module groups those
records by NAD. For EAP (dot1x) the time includes every Access-Challenge round trip through the NAD to
the supplicant, so it grows with the WAN delay between a branch and the PSN; MAB is one request and
stays close to ISE's own processing time. Timeouts are the failure reasons where the NAD or supplicant
stopped answering (5411, 5440, ...). RADIUS that ISE drops silently (unknown NAD, wrong secret) and the
NAD's own retransmits leave no record at all.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
import statistics
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import (
    InvalidRequest,
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp
from ise_mcp.tools._common import gather_limited
from ise_mcp.tools.activity import MNT_TIME, candidate_macs, nad_filter
from ise_mcp.tools.sessions import auth_history, is_coa_record

MAX_WINDOW_MINUTES = 7 * 24 * 60
RECORDS_PER_MAC = 100
# Failure codes where the NAD or the supplicant stopped answering ISE (a timeout from ISE's side).
TIMEOUT_CODES = {
    "5405": "RADIUS request dropped",
    "5411": "Supplicant stopped responding to ISE",
    "5440": "Endpoint abandoned EAP session and started new",
    "12935": "Supplicant stopped responding to ISE during EAP-TLS certificate exchange",
}
_TIMEOUT_TEXT = re.compile(r"stopped responding|timed? ?out|timeout|dropped|abandoned|no response", re.I)
# A NAD is called out when its average is at least this many times the median of the others, and at
# least SLOW_MIN_MS above it (a 30 ms vs 10 ms MAB difference is noise, not a slow path).
SLOW_FACTOR = 2.0
SLOW_MIN_MS = 100
COLUMNS = ["nad", "requests", "failed", "timeouts", "avg_ms", "max_ms", "eap_avg_ms", "mab_avg_ms", "psns"]


def _time(text: Any) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(text).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _ms(value: Any) -> int | None:
    try:
        ms = int(str(value).strip())
    except ValueError:
        return None
    return ms if ms >= 0 else None


def timeout_reason(rec: dict[str, Any], catalog: dict[str, dict[str, Any]]) -> str | None:
    """The failure reason when it means the NAD or supplicant stopped answering, else None."""
    if str(rec.get("passed", "")).lower() == "true":
        return None
    reason = str(rec.get("failure_reason") or "").strip()
    code = reason.split(" ", 1)[0] if reason else str(rec.get("message_code") or "")
    if code in TIMEOUT_CODES:
        return reason or f"{code} {TIMEOUT_CODES[code]}"
    text = reason or str((catalog.get(code) or {}).get("reason") or "")
    if text and _TIMEOUT_TEXT.search(text):
        return text
    return None


def _method(rec: dict[str, Any]) -> str:
    method = str(rec.get("authentication_method") or "").lower()
    if method in ("dot1x", "mab"):
        return "eap" if method == "dot1x" else "mab"
    return method or "other"


def _latency(values: list[int]) -> dict[str, Any]:
    if not values:
        return {}
    ordered = sorted(values)
    out: dict[str, Any] = {
        "samples": len(ordered),
        "avg_ms": round(statistics.fmean(ordered)),
        "median_ms": round(statistics.median(ordered)),
        "max_ms": ordered[-1],
    }
    if len(ordered) >= 20:
        out["p95_ms"] = ordered[min(len(ordered) - 1, round(0.95 * (len(ordered) - 1)))]
    return out


def summarise(records: list[dict[str, Any]], catalog: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """MnT auth records grouped by NAD (name, else NAS IP)."""
    groups: dict[str, dict[str, Any]] = {}
    for r in records:
        key = str(r.get("network_device_name") or r.get("nas_ip_address") or "unknown")
        g = groups.setdefault(
            key,
            {
                "nas_ips": set(),
                "requests": 0,
                "failed": 0,
                "timeouts": Counter(),
                "all": [],
                "by_method": {},
                "psns": Counter(),
                "macs": set(),
                "last_seen": "",
            },
        )
        g["requests"] += 1
        if r.get("nas_ip_address"):
            g["nas_ips"].add(str(r["nas_ip_address"]))
        if str(r.get("passed", "")).lower() != "true":
            g["failed"] += 1
        if t := timeout_reason(r, catalog):
            g["timeouts"][t] += 1
        if (ms := _ms(r.get("response_time"))) is not None:
            g["all"].append(ms)
            g["by_method"].setdefault(_method(r), []).append(ms)
        if r.get("acs_server"):
            g["psns"][str(r["acs_server"])] += 1
        if r.get("calling_station_id"):
            g["macs"].add(str(r["calling_station_id"]))
        g["last_seen"] = max(g["last_seen"], str(r.get("acs_timestamp") or ""))
    out: dict[str, dict[str, Any]] = {}
    for key, g in groups.items():
        row: dict[str, Any] = {
            "nad": key,
            "nas_ips": sorted(g["nas_ips"]),
            "requests": g["requests"],
            "failed": g["failed"],
            "timeouts": sum(g["timeouts"].values()),
            **_latency(g["all"]),
            "psns": dict(g["psns"].most_common()),
            "endpoints": len(g["macs"]),
            "last_seen": g["last_seen"] or None,
        }
        for method, values in sorted(g["by_method"].items()):
            lat = _latency(values)
            row[f"{method}_avg_ms"] = lat["avg_ms"]
            row.setdefault("by_method", {})[method] = lat
        if g["timeouts"]:
            row["timeout_reasons"] = dict(g["timeouts"].most_common(5))
        out[key] = row
    return out


def slow_nads(rows: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """NADs whose average (per method, so EAP is compared with EAP) is far above the other NADs'."""
    found: list[dict[str, Any]] = []
    for field in ("eap_avg_ms", "mab_avg_ms", "other_avg_ms"):
        have = {k: r[field] for k, r in rows.items() if isinstance(r.get(field), int)}
        if len(have) < 2:
            continue
        for key, avg in have.items():
            others = statistics.median(v for k, v in have.items() if k != key)
            if avg >= SLOW_FACTOR * max(others, 1) and avg - others >= SLOW_MIN_MS:
                found.append(
                    {
                        "nad": key,
                        "method": field.removesuffix("_avg_ms"),
                        "avg_ms": avg,
                        "others_median_ms": round(others),
                    }
                )
    return found


def compare(now: dict[str, dict[str, Any]], before: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Per NAD and method: average now vs the previous window of the same length."""
    out: list[dict[str, Any]] = []
    for key, row in now.items():
        prev = before.get(key)
        if not prev:
            continue
        for field in ("eap_avg_ms", "mab_avg_ms", "other_avg_ms", "avg_ms"):
            a, b = row.get(field), prev.get(field)
            if not isinstance(a, int) or not isinstance(b, int):
                continue
            entry: dict[str, Any] = {
                "nad": key,
                "metric": field,
                "now_ms": a,
                "before_ms": b,
                "delta_ms": a - b,
            }
            if a >= SLOW_FACTOR * max(b, 1) and a - b >= SLOW_MIN_MS:
                entry["rose"] = True
            out.append(entry)
    out.sort(key=lambda e: -int(e["delta_ms"]))
    return out


def verdict(rows: dict[str, dict[str, Any]], slow: list[dict[str, Any]], rose: list[dict[str, Any]]) -> str:
    if not rows:
        return "No authentication record in the window: nothing to measure."
    lines: list[str] = []
    for s in slow:
        lines.append(
            f"{s['nad']}: {s['method'].upper()} takes {s['avg_ms']} ms on average vs "
            f"{s['others_median_ms']} ms for the other NADs"
        )
    for r in rose:
        lines.append(f"{r['nad']}: {r['metric']} rose from {r['before_ms']} to {r['now_ms']} ms")
    timeouts = [k for k, r in rows.items() if r.get("timeouts")]
    if timeouts:
        lines.append("timeouts (NAD or supplicant stopped answering) through " + ", ".join(sorted(timeouts)))
    if not lines:
        return (
            "No NAD stands out: latency is in line across NADs and nothing timed out. If users still "
            "fail, look at policy (ise_why_auth_failed) rather than the path to ISE."
        )
    return (
        "; ".join(lines)
        + ". Latency or timeouts on some NADs only point at the path between those NADs and the PSN "
        "(WAN/overlay: loss, delay, MTU on the EAP-TLS certificate exchange), not at ISE; all NADs slow "
        "points at the PSN or its identity store."
    )


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Per-NAD RADIUS latency and timeouts")
    async def ise_nad_radius_stats(
        ctx: Context,
        since_minutes: Annotated[
            int, Field(ge=1, le=MAX_WINDOW_MINUTES, description="How far back to look, in minutes")
        ] = 60,
        nad: Annotated[
            str | None, Field(description="Only this NAD: name (partial is fine), or a NAS IP")
        ] = None,
        macs: Annotated[
            list[str] | None,
            Field(description="MACs to read first (e.g. the branch's clients from 'show access-session')"),
        ] = None,
        max_lookups: Annotated[
            int, Field(ge=1, le=500, description="Most MACs to read history for (one MnT call each)")
        ] = 100,
        include_endpoint_db: Annotated[
            bool,
            Field(description="Also read MACs from the ISE endpoint database, up to max_lookups"),
        ] = True,
        compare_previous: Annotated[
            bool,
            Field(
                description="Also measure the previous window of the same length and show the change per "
                "NAD (doubles the history read; since_minutes at most 5040)"
            ),
        ] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """ISE's own view of each NAD's RADIUS traffic over a window, from MnT auth history (queried when
        called): attempts, failures, timeouts (the NAD or supplicant stopped answering: 5411, 5440,
        ...), average/median/worst response time overall and per method (EAP vs MAB), the PSN that
        answered, and the NADs that stand out against the others (or against the previous window with
        compare_previous=true). Answers "is it the network or ISE?" for a branch: EAP time includes every
        round trip through the NAD, so a slow WAN path to the PSN shows up as one NAD's EAP latency
        rising while the others stay flat; all NADs slow points at ISE. Not available over REST, so
        not shown: the NAD's retransmits and RADIUS that ISE drops silently (unknown NAD, wrong shared
        secret; check ise_audit_nads). MnT history is per MAC and leaves out repeated successful logins,
        so this reads a capped set of candidate MACs (given, sessions in the window, endpoint database)
        and reports its coverage. The window always ends now."""
        app: IseApp = get_client(ctx)
        if compare_previous and since_minutes * 2 > MAX_WINDOW_MINUTES:
            raise InvalidRequest(
                f"compare_previous reads twice the window: since_minutes can be at most "
                f"{MAX_WINDOW_MINUTES // 2} (got {since_minutes})"
            )
        end = datetime.now(UTC)
        start = end - timedelta(minutes=since_minutes)
        prev_start = start - timedelta(minutes=since_minutes) if compare_previous else start
        flt = await nad_filter(app, nad)
        cand = await candidate_macs(
            app, start, end, flt, macs, max_lookups, include_endpoint_db=include_endpoint_db
        )
        lookup_errors: list[str] = []
        read_minutes = since_minutes * (2 if compare_previous else 1)

        async def history(mac: str) -> list[dict[str, Any]]:
            try:
                return await auth_history(app, mac, read_minutes, RECORDS_PER_MAC)
            except (UpstreamError, NotFound) as e:
                lookup_errors.append(f"{mac}: {str(e)[:120]}")
                return []

        mac_list = list(cand.macs)
        per_mac = await gather_limited(mac_list, history)
        truncated = [m for m, recs in zip(mac_list, per_mac, strict=True) if len(recs) >= RECORDS_PER_MAC]
        current: list[dict[str, Any]] = []
        previous: list[dict[str, Any]] = []
        coa_skipped = 0
        for recs in per_mac:
            for r in recs:
                if is_coa_record(r):
                    coa_skipped += 1
                    continue
                if flt and not flt.matches(r.get("nas_ip_address"), r.get("network_device_name")):
                    continue
                at = _time(r.get("acs_timestamp"))
                if at is None or at < prev_start or at > end:
                    continue
                (current if at >= start else previous).append(r)
        failed = [r for r in current + previous if str(r.get("passed", "")).lower() != "true"]
        catalog = await app.failure_reasons() if failed else {}
        rows = summarise(current, catalog)
        slow = slow_nads(rows)
        changes = compare(rows, summarise(previous, catalog)) if compare_previous else []
        rose = [c for c in changes if c.get("rose") and c["metric"] != "avg_ms"]
        coverage: dict[str, Any] = {
            "macs_checked": len(cand.macs),
            "from": dict(Counter(cand.macs.values())),
            "capped": bool(cand.dropped or cand.more_in_db),
        }
        if coverage["capped"]:
            coverage["note"] = (
                "Not every candidate MAC was read: raise max_lookups or pass the branch's MACs. "
                "Endpoint-database MACs are not NAD-specific."
            )
        if truncated:
            coverage["truncated_macs"] = truncated[:20]
        if lookup_errors:
            coverage["lookup_errors"] = lookup_errors[:10]
        extra: dict[str, Any] = {
            "window_utc": {"start": start.strftime(MNT_TIME), "end": end.strftime(MNT_TIME)},
            "verdict": verdict(rows, slow, rose),
            "records": len(current),
            "slow_nads": slow,
            "coverage": coverage,
            "how_to_read": (
                "response_time is ISE's time from the attempt's first request to its final answer. EAP "
                "(dot1x) includes each challenge round trip through the NAD to the client, so it scales "
                "with the WAN delay to the PSN; MAB is one request (ISE processing). Compare a NAD with "
                "the others, or with compare_previous=true."
            ),
            "not_available": (
                "Per-NAD RADIUS counters (requests, retries, drops) are GUI reports only; NAD "
                "retransmits and requests ISE drops silently (unknown NAD 11007, wrong secret 11036) "
                "leave no MnT record. MnT also leaves out repeated successful logins."
            ),
        }
        if compare_previous:
            extra["previous_window_utc"] = {
                "start": prev_start.strftime(MNT_TIME),
                "end": start.strftime(MNT_TIME),
            }
            extra["previous_records"] = len(previous)
            extra["changes"] = changes[:50]
        if flt:
            extra["nad_filter"] = flt.label
        if coa_skipped:
            extra["coa_records_excluded"] = coa_skipped
        ordered = sorted(rows.values(), key=lambda r: (-(r.get("avg_ms") or -1), str(r["nad"])))
        return list_result(
            page_of(ordered, limit=limit, offset=offset),
            fmt=response_format,
            columns=COLUMNS,
            extra=extra,
        )

"""Recent authentication activity across endpoints, queried from MnT when called (pull-only, ADR-003).

MnT has exactly one cross-endpoint history call, `Session/AuthList/{start}/{end}`: the sessions that
authenticated in a window (UTC, 'YYYY-MM-DD HH:MM:SS'). Failed attempts are only reachable per MAC
(`AuthStatus/MACAddress/...`), so failure lookups check a capped set of candidate MACs and say which.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import contextlib
import ipaddress
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import quote

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
from ise_mcp.knowledge import FAILURE_HINTS
from ise_mcp.tools._common import gather_limited, normalize_mac, parse_ip
from ise_mcp.tools.network import nad_networks, resolve_nad
from ise_mcp.tools.sessions import auth_history, auth_row, find_session, is_coa_record
from ise_mcp.xmlutil import as_list

MNT_TIME = "%Y-%m-%d %H:%M:%S"
AUTH_LIST_COLUMNS = ["user", "mac", "nas_ip", "nad", "method", "authz_profiles", "time", "audit_session_id"]
MAX_WINDOW_MINUTES = 7 * 24 * 60
DETAIL_CAP = 100
RECORDS_PER_MAC = 50


def parse_until(until: str | None) -> datetime:
    """`until` as an aware UTC datetime (ISO 8601; naive values are taken as UTC). None -> now."""
    if until is None or not until.strip():
        return datetime.now(UTC)
    text = until.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as e:
        raise InvalidRequest(f"until={until!r} is not an ISO 8601 time (e.g. 2026-10-15T08:00:00Z)") from e
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def window(since_minutes: int, until: str | None) -> tuple[datetime, datetime]:
    end = parse_until(until)
    return end - timedelta(minutes=since_minutes), end


def mnt_time(dt: datetime) -> str:
    return quote(dt.astimezone(UTC).strftime(MNT_TIME))


class NadFilter:
    """Matches a NAS IP (and, for auth records, the NAD name) against a NAD given by name or IP."""

    def __init__(self, label: str, nets: list[Any], name: str | None) -> None:
        self.label = label
        self.nets = nets
        self.name = name

    def matches(self, nas_ip: Any, nad_name: Any = None) -> bool:
        if self.name and nad_name and str(nad_name) == self.name:
            return True
        try:
            addr = ipaddress.ip_address(str(nas_ip or "").strip())
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in self.nets)


async def nad_filter(app: IseApp, nad: str | None) -> NadFilter | None:
    if not nad or not nad.strip():
        return None
    key = nad.strip()
    if ip := parse_ip(key):
        # An IP filter matches the NAS IP itself, even when no NAD covers it (silent drops show up there).
        try:
            found = await resolve_nad(app, ip)
        except NotFound:
            found = None
        # Match the NAS IP only; `found` just confirms the address belongs to a NAD.
        del found
        return NadFilter(ip, [ipaddress.ip_network(ip)], None)
    found = await resolve_nad(app, key, fuzzy=True)
    nets = nad_networks(found)
    label = str(found.get("name"))
    if found.get("resolved_from"):
        label += f" (partial match for {key!r})"
    return NadFilter(label, nets, str(found.get("name")))


async def auth_list(app: IseApp, start: datetime, end: datetime) -> list[dict[str, Any]]:
    """MnT AuthList rows (sessions authenticated in [start, end])."""
    data = await app.mnt_get(f"Session/AuthList/{mnt_time(start)}/{mnt_time(end)}", missing_ok=False)
    if not isinstance(data, dict):
        return []
    return [s for s in as_list(data.get("activeSession")) if isinstance(s, dict)]


def _session_row(s: dict[str, Any]) -> dict[str, Any]:
    row = {
        "user": s.get("user_name"),
        "mac": s.get("calling_station_id"),
        "ip": s.get("framed_ip_address"),
        "nas_ip": s.get("nas_ip_address"),
        "psn": s.get("server"),
        "audit_session_id": s.get("audit_session_id"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


async def _session_detail(app: IseApp, row: dict[str, Any]) -> dict[str, Any]:
    mac = row.get("mac")
    if not mac:
        return row
    try:
        s = await find_session(app, mac=str(mac))
    except (UpstreamError, InvalidRequest):
        return row
    if not s or s.get("active") is False:
        return {**row, "note": "session no longer active"}
    extra = {
        "nad": s.get("network_device_name"),
        "nas_port": s.get("nas_port_id"),
        "method": s.get("authentication_method"),
        "protocol": s.get("authentication_protocol"),
        "authz_profiles": s.get("selected_azn_profiles"),
        "sgt": s.get("cts_security_group"),
        "endpoint_profile": s.get("endpoint_policy"),
        "time": s.get("auth_acs_timestamp") or s.get("acs_timestamp"),
        "matched_policy": s.get("matched_policy"),
    }
    return {**row, **{k: v for k, v in extra.items() if v not in (None, "", {})}}


def _counts(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    return dict(Counter(str(r[key]) for r in rows if r.get(key)).most_common(20))


async def _endpoint_macs(app: IseApp, cap: int) -> tuple[list[str], bool]:
    """Up to `cap` MACs from the endpoint database; (macs, more_exist)."""
    out: list[str] = []
    page = 1
    while len(out) < cap:
        data = await app.openapi.get("/api/v1/endpoint", {"page": page, "size": 100})
        data = data.get("response", data) if isinstance(data, dict) else data
        batch = [str(e["mac"]) for e in data or [] if isinstance(e, dict) and e.get("mac")]
        out += batch
        if len(batch) < 100:
            return out[:cap], len(out) > cap
        page += 1
    return out[:cap], True


class Candidates:
    """MACs to read auth history for, with where each came from and whether the budget ran out."""

    def __init__(self) -> None:
        self.macs: dict[str, str] = {}
        self.dropped = 0
        self.more_in_db = False


async def candidate_macs(
    app: IseApp,
    start: datetime,
    end: datetime,
    flt: NadFilter | None,
    given: list[str] | None,
    max_lookups: int,
    *,
    include_endpoint_db: bool,
) -> Candidates:
    """MnT history is per MAC only: the MACs given, then sessions authenticated in the window (through
    the NAD when filtered), then the endpoint database, up to `max_lookups`."""
    out = Candidates()

    def add(mac: Any, source: str) -> None:
        with contextlib.suppress(InvalidRequest):
            m = normalize_mac(str(mac))
            if m in out.macs:
                return
            if len(out.macs) < max_lookups:
                out.macs[m] = source
            else:
                out.dropped += 1

    for m in given or []:
        normalize_mac(m)  # reject bad input loudly
        add(m, "given")
    for s in await auth_list(app, start, end):
        if not flt or flt.matches(s.get("nas_ip_address")):
            add(s.get("calling_station_id"), "auth_list")
    # With the budget already spent, the endpoint database was not looked at: report it as capped.
    out.more_in_db = include_endpoint_db and len(out.macs) >= max_lookups
    if include_endpoint_db and len(out.macs) < max_lookups:
        db_macs, out.more_in_db = await _endpoint_macs(app, max_lookups + len(out.macs))
        for m in db_macs:
            add(m, "endpoint_db")
    return out


# RADIUS without a Calling-Station-Id MAC (device admin over RADIUS, VPN, a router's `test aaa`) never
# reaches the per-MAC AuthStatus history; the only MnT read not keyed by MAC is the user's latest
# session (Session/UserName). Seen live (Wave 7, 2026-10-24): an edge's `test aaa` Access-Reject left
# no per-MAC record, and the failed user had no MnT session either.
MAC_LESS_NOTE = (
    "MAC-less RADIUS (device admin, VPN, a router's 'test aaa') carries no Calling-Station-Id MAC, so "
    "MnT's per-MAC history never shows it. Pass user=<name> to read that user's latest MnT session "
    "(Session/UserName; a failed login often has none), or look in the GUI live log (Operations > "
    "RADIUS > Live Logs, filtered by the NAS IP or user)."
)


def mnt_timestamp(text: Any) -> datetime | None:
    """An MnT ISO 8601 time ('2026-10-14T12:21:14.864Z') as aware UTC; None when absent or unparseable."""
    try:
        dt = datetime.fromisoformat(str(text or "").strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _flag(value: Any) -> bool | None:
    text = str(value if value is not None else "").strip().lower()
    if text in ("true", "1"):
        return True
    if text in ("false", "0"):
        return False
    return None


def session_as_record(s: dict[str, Any]) -> dict[str, Any]:
    """An MnT Session/UserName answer in the shape of an AuthStatus record (auth time, PASS/FAIL)."""
    rec = dict(s)
    rec["acs_timestamp"] = s.get("auth_acs_timestamp") or s.get("acs_timestamp")
    failed = bool(str(s.get("failure_reason") or "").strip()) or _flag(s.get("failed")) is True
    rec["passed"] = "false" if failed or _flag(s.get("passed")) is False else "true"
    return rec


class UserRecords:
    """Records from users' latest MnT sessions, with what each lookup found."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.found: dict[str, str] = {}
        self.errors: list[str] = []


async def user_session_records(
    app: IseApp, users: list[str], start: datetime, end: datetime, skip_macs: set[str]
) -> UserRecords:
    """Each user's latest MnT session (Session/UserName/{user}) as an auth record when its
    authentication falls in [start, end]. Skips a session whose MAC was already read per MAC."""
    out = UserRecords()
    for user in users:
        try:
            data = await app.mnt_get(f"Session/UserName/{quote(user, safe='')}")
        except (UpstreamError, NotFound) as e:
            out.errors.append(f"{user}: {str(e)[:120]}")
            continue
        if not isinstance(data, dict):
            out.found[user] = "no MnT session"
            continue
        rec = session_as_record(data)
        at = mnt_timestamp(rec.get("acs_timestamp"))
        if at is None or not start <= at <= end:
            when = rec.get("acs_timestamp") or "no auth time"
            out.found[user] = f"latest session outside the window ({when})"
            continue
        mac = rec.get("calling_station_id")
        with contextlib.suppress(InvalidRequest):
            if mac and normalize_mac(str(mac)) in skip_macs:
                out.found[user] = "session already read per MAC"
                continue
        out.found[user] = "session in the window"
        out.records.append(rec)
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Sessions authenticated in a time window")
    async def ise_get_auth_list(
        ctx: Context,
        since_minutes: Annotated[
            int,
            Field(ge=1, le=MAX_WINDOW_MINUTES, description="Window length in minutes, ending at `until`"),
        ] = 60,
        until: Annotated[
            str | None,
            Field(description="End of the window, ISO 8601 (UTC if no offset); default now"),
        ] = None,
        nad: Annotated[
            str | None,
            Field(description="Only sessions through this NAD: name, or a NAS IP"),
        ] = None,
        user: Annotated[str | None, Field(description="Filter: username contains (case-insensitive)")] = None,
        detail: Annotated[
            bool,
            Field(
                description="Look up each session on this page for NAD name, port, method, authorization "
                "profile, SGT and matched policy (one MnT call per row, at most 100)"
            ),
        ] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Sessions that authenticated successfully in a time window, across all endpoints, from MnT
        (queried when called): user, MAC, IP, NAS IP and PSN, with counts by NAS IP and user. Answers
        "what connected on this switch in the last hour?" without knowing a MAC. Only sessions that
        are still known to MnT appear; failed attempts are not in this list (use
        ise_recent_auth_failures). detail=true adds method, authorization profile, SGT and the matched
        policy per row from the endpoint's current MnT session (which may be newer than the listed
        authentication) and summarises them. Drill into one endpoint with ise_endpoint_360."""
        app: IseApp = get_client(ctx)
        start, end = window(since_minutes, until)
        rows = [_session_row(s) for s in await auth_list(app, start, end)]
        flt = await nad_filter(app, nad)
        if flt:
            rows = [r for r in rows if flt.matches(r.get("nas_ip"))]
        if user:
            rows = [r for r in rows if user.lower() in str(r.get("user") or "").lower()]
        page = page_of(rows, limit=min(limit, DETAIL_CAP) if detail else limit, offset=offset)
        if detail:
            page.items = await gather_limited(page.items, lambda r: _session_detail(app, r))
        extra: dict[str, Any] = {
            "window_utc": {"start": start.strftime(MNT_TIME), "end": end.strftime(MNT_TIME)},
            "by_nas_ip": _counts(rows, "nas_ip"),
            "by_user": _counts(rows, "user"),
        }
        if flt:
            extra["nad_filter"] = flt.label
        if detail:
            items = [i for i in page.items if isinstance(i, dict)]
            extra["page_by_method"] = _counts(items, "method")
            extra["page_by_authz_profile"] = _counts(items, "authz_profiles")
        if not rows:
            extra["note"] = (
                "No session authenticated in this window. MnT only lists sessions it still holds; check "
                "older attempts per MAC with ise_get_auth_history, and failures with "
                "ise_recent_auth_failures."
            )
        return list_result(page, fmt=response_format, columns=AUTH_LIST_COLUMNS, extra=extra)

    @reg.read(title="Recent authentication failures")
    async def ise_recent_auth_failures(
        ctx: Context,
        since_minutes: Annotated[
            int, Field(ge=1, le=MAX_WINDOW_MINUTES, description="How far back to look, in minutes")
        ] = 60,
        nad: Annotated[
            str | None, Field(description="Only failures through this NAD: name, or a NAS IP")
        ] = None,
        user: Annotated[
            str | None,
            Field(
                description="Filter: username contains (case-insensitive). Also reads this exact user's "
                "latest MnT session, which covers MAC-less RADIUS (device admin, VPN, router 'test aaa')"
            ),
        ] = None,
        macs: Annotated[
            list[str] | None,
            Field(description="MACs to check first (e.g. from the switch's 'show access-session')"),
        ] = None,
        max_lookups: Annotated[
            int,
            Field(ge=1, le=500, description="Most MACs to check (one MnT call each)"),
        ] = 50,
        include_coa: Annotated[
            bool,
            Field(description="Also count failed CoA/dynamic-authorization records (not logins)"),
        ] = False,
        include_endpoint_db: Annotated[
            bool,
            Field(description="Also check MACs from the ISE endpoint database, up to max_lookups"),
        ] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """Failed authentications in the last N minutes, grouped by failure reason (decoded with likely
        cause and next step) and by NAD, queried from MnT when called. Answers "who is failing on
        switch X, and why?". MnT can only return failures per MAC, so this checks a capped set of
        candidate MACs: the ones you pass, then sessions authenticated in the window, then the endpoint
        database. The result says how many MACs were checked and whether more exist; a failing MAC
        that ISE never stored is only found when you pass it. RADIUS without a MAC (device admin, VPN,
        a router's 'test aaa') is not in the per-MAC history: pass user= to also read that user's
        latest MnT session; the result says so when nothing was found. RADIUS from an unknown NAD or with a
        wrong shared secret leaves no record at all (check ise_audit_nads). Repeated successful logins
        may be missing from MnT's history, so a MAC listed here may have passed since: ise_find_session
        has its newest authentication. The window always ends now. The list holds one row per failed
        attempt, newest first; diagnose one MAC with ise_why_auth_failed."""
        app: IseApp = get_client(ctx)
        start, end = window(since_minutes, None)
        flt = await nad_filter(app, nad)
        cand = await candidate_macs(
            app, start, end, flt, macs, max_lookups, include_endpoint_db=include_endpoint_db
        )
        candidates, dropped, more_in_db = cand.macs, cand.dropped, cand.more_in_db
        lookup_errors: list[str] = []

        async def history(mac: str) -> list[dict[str, Any]]:
            try:
                return await auth_history(app, mac, since_minutes, RECORDS_PER_MAC)
            except (UpstreamError, NotFound) as e:
                lookup_errors.append(f"{mac}: {str(e)[:120]}")
                return []

        mac_list = list(candidates)
        records_per_mac = await gather_limited(mac_list, history)
        truncated = [
            m for m, recs in zip(mac_list, records_per_mac, strict=True) if len(recs) >= RECORDS_PER_MAC
        ]
        by_user = (
            await user_session_records(app, [user.strip()], start, end, set(mac_list))
            if user and user.strip()
            else None
        )
        if by_user:
            records_per_mac.append(by_user.records)
        failures: list[dict[str, Any]] = []
        coa_skipped = 0
        for recs in records_per_mac:
            for r in recs:
                row = auth_row(r)
                if row["result"] != "FAIL":
                    continue
                if flt and not flt.matches(row.get("nas_ip"), row.get("nad")):
                    continue
                if user and user.lower() not in str(row.get("user") or "").lower():
                    continue
                if is_coa_record(r) and not include_coa:
                    coa_skipped += 1
                    continue
                failures.append(row)
        failures.sort(key=lambda r: str(r.get("time") or ""), reverse=True)
        catalog = await app.failure_reasons() if failures else {}
        groups: dict[str, dict[str, Any]] = {}
        for f in failures:
            reason = str(f.get("failure_reason") or "unknown")
            code = reason.split(" ", 1)[0]
            g = groups.setdefault(
                code,
                {
                    "code": code,
                    "reason": reason,
                    "count": 0,
                    "macs": set(),
                    "nads": Counter(),
                    "users": set(),
                },
            )
            g["count"] += 1
            g["macs"].add(f.get("mac"))
            g["nads"][str(f.get("nad") or f.get("nas_ip") or "?")] += 1
            if f.get("user"):
                g["users"].add(f["user"])
            g.setdefault("latest", f.get("time"))
        by_reason = []
        for g in sorted(groups.values(), key=lambda g: -g["count"]):
            entry: dict[str, Any] = {
                "code": g["code"],
                "reason": g["reason"],
                "count": g["count"],
                "latest": g.get("latest"),
                "macs": sorted(m for m in g["macs"] if m)[:10],
                "nads": dict(g["nads"].most_common(5)),
                "users": sorted(g["users"])[:10],
            }
            hint = FAILURE_HINTS.get(g["code"])
            if hint:
                entry["likely"] = hint["likely"]
                entry["next_step"] = hint["check"]
            elif catalog.get(g["code"]):
                entry["resolution"] = catalog[g["code"]].get("resolution")
            by_reason.append(entry)
        sources = Counter(candidates.values())
        coverage: dict[str, Any] = {
            "macs_checked": len(candidates),
            "from": dict(sources),
            "capped": bool(dropped or more_in_db),
        }
        if coverage["capped"]:
            coverage["note"] = (
                "Not every candidate MAC was checked: raise max_lookups or pass the failing MACs from "
                "the switch ('show access-session'). Endpoint-database MACs are not NAD-specific."
            )
        if truncated:
            coverage["truncated_macs"] = truncated[:20]
            coverage["truncated_note"] = (
                f"These MACs have {RECORDS_PER_MAC}+ records in the window, so older attempts were not read; "
                "use ise_get_auth_history with a shorter window."
            )
        if by_user:
            coverage["users_checked"] = by_user.found
            lookup_errors += by_user.errors
        if lookup_errors:
            coverage["lookup_errors"] = lookup_errors[:10]
        if not failures:
            coverage["mac_less_radius"] = MAC_LESS_NOTE
        extra: dict[str, Any] = {
            "window_utc": {"start": start.strftime(MNT_TIME), "end": end.strftime(MNT_TIME)},
            "failed_attempts": len(failures),
            "by_reason": by_reason,
            "by_nad": dict(Counter(str(f.get("nad") or f.get("nas_ip") or "?") for f in failures)),
            "coverage": coverage,
        }
        if failures:
            extra["history_note"] = (
                "Repeated successful logins may be missing from MnT's history, so a MAC listed here may "
                "have passed since: ise_find_session has its newest authentication."
            )
        if flt:
            extra["nad_filter"] = flt.label
        if coa_skipped:
            extra["coa_failures_excluded"] = coa_skipped
        if not failures:
            extra["note"] = (
                f"No failed attempt among the {len(candidates)} MACs checked in the last "
                f"{since_minutes} minutes. Silent drops (unknown NAD 11007, wrong shared secret 11036) "
                "leave no MnT record, and MAC-less RADIUS (device admin, VPN, router 'test aaa') is not "
                "in the per-MAC history: see coverage.mac_less_radius."
            )
        rows = [
            {k: f.get(k) for k in ("time", "mac", "user", "nad", "nas_ip", "method", "failure_reason")}
            for f in failures
        ]
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["time", "mac", "user", "nad", "nas_ip", "failure_reason"],
            extra=extra,
        )

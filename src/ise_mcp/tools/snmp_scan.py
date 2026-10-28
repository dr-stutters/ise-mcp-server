"""Profiler endpoint SNMP scans (I61, #102): ISE's active SNMP queries of IoT/OT segments.

For segments where DHCP and RADIUS say little (printers, cameras, building controllers), the profiler can
scan an address range over SNMP so the endpoints get profiled, and then an SGT. ISE 3.5 exposes the scans
under OpenAPI `/api/v1/profiler/snmp`:

- `GET/POST /scan`, `GET/PUT /scan/{id}`: the scan definitions (name, PSN or PSN group, network scope as
  subnets or IP ranges, schedule, SNMP credentials);
- `POST /scan/action` `{"action": "start"|"stop", "ids": [...]}` (ISE starts one scan at a time and stops
  several), `POST /scan/status` `{"status": "enable"|"disable", "ids": [...]}`;
- `GET /scan-history/{id}`: the runs of a scan (result, PSN, addresses scanned, discovered, unreachable, SNMP
  auth failures, null responses, errors);
- `GET /psn-groups`: the PSNs and PSN groups a scan can run on.

- `DELETE /scan` `{"ids": [...]}` (deleteSNMPScans): deletes scans; the per-id `DELETE /scan/{id}` answers 405
  on ISE 3.5. ise_delete_object(kind='snmp_scan', target=<name>) wraps it (blocked while a run is going).

Credentials never travel as tool arguments: the community (v1/v2c) or the SNMPv3 passwords come from server
environment variables named `ISE_SNMP_...` (or their `_FILE` twins), and are never shown. The enabled state
reads from the entity's top-level `status` (ENABLED/DISABLED): ISE leaves scanDetails.isEnabled true after a
disable.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import ipaddress
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    field_changes,
    get_client,
    object_result,
    preview_or_apply,
)
from ise_mcp._core.http import page_of
from ise_mcp._core.secrets import register_secret
from ise_mcp.client import IseApp
from ise_mcp.tools._common import list_result
from ise_mcp.tools.writes import fingerprint

BASE = "/api/v1/profiler/snmp"
SCANS = f"{BASE}/scan"
ACTION = f"{BASE}/scan/action"
STATUS = f"{BASE}/scan/status"
HISTORY = f"{BASE}/scan-history"
PSN_GROUPS = f"{BASE}/psn-groups"

SECRET_ENV = re.compile(r"ISE_SNMP_[A-Z0-9_]+")
SECRET_FIELDS = ("roCommunity", "authPassword", "privacyPassword")
SCHEDULES = {"none": "NO_SCHEDULE", "daily": "DAILY", "weekly": "WEEKLY", "monthly": "MONTHLY"}
WEEKDAYS = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")
TIME_RE = re.compile(r"(0?[1-9]|1[0-2]):[0-5][0-9] ?([ap]m)", re.IGNORECASE)
VERSIONS = {"v1": "snmpV1", "v2c": "snmpV2", "v3": "snmpV3"}
MIN_MASK = {4: 21, 6: 117}  # ISE scans /21../32 (IPv4) and /117../128 (IPv6) subnets
EXPLAIN_HINT = (
    "Endpoints the scan reached get SNMP attributes (sysDescr and the like) that can move their profile: "
    "ise_explain_profile(mac) shows the profile, its parent chain and labels now; "
    "ise_endpoint_summary(by='profile') shows what the segment looks like."
)


# --- helpers ------------------------------------------------------------------------------------


def secret_from_env(var: str, arg: str) -> str | None:
    """A credential from the server's environment: `var`, or the file `<var>_FILE` names."""
    if not SECRET_ENV.fullmatch(var):
        raise InvalidRequest(
            f"{arg} must name a variable starting ISE_SNMP_ (upper case, digits, '_'), not {var!r}: the "
            "tool never reads the server's other secrets."
        )
    value = os.environ.get(var)
    if not value and (file := os.environ.get(f"{var}_FILE")):
        try:
            value = Path(file).expanduser().read_text().removesuffix("\n")
        except OSError:
            raise InvalidRequest(f"{var}_FILE names a file this server can't read") from None
    if value:
        register_secret(value)
    return value or None


def _unwrap(data: Any) -> Any:
    return data.get("response", data) if isinstance(data, dict) and "response" in data else data


async def list_scans(app: IseApp) -> list[dict[str, Any]]:
    """Every SNMP scan (EndPointSNMPScanEntity). The lab ISE 3.5 answers a bare list ([] with none)."""
    data = _unwrap(await app.openapi.get(SCANS))
    return [s for s in data or [] if isinstance(s, dict)] if isinstance(data, list) else []


def details_of(scan: dict[str, Any]) -> dict[str, Any]:
    """The scan's SNMPScanAttributes (the entity nests them under scanDetails)."""
    d = scan.get("scanDetails")
    return d if isinstance(d, dict) else scan


def scan_name(scan: dict[str, Any]) -> str:
    return str(scan.get("name") or details_of(scan).get("name") or "")


def scan_id(scan: dict[str, Any]) -> str:
    return str(scan.get("id") or details_of(scan).get("id") or "")


def scan_enabled(scan: dict[str, Any]) -> bool | None:
    """Whether the scan is enabled. The top-level `status` (ENABLED/DISABLED) wins: after
    POST /scan/status disable, ISE 3.5 answers status DISABLED but leaves scanDetails.isEnabled and
    scanStatus true (#161). isEnabled / scanStatus only count when status is absent."""
    s = str(scan.get("status") or "").lower()
    state = {"enabled": True, "enable": True, "disabled": False, "disable": False}.get(s)
    if state is not None:
        return state
    d = details_of(scan)
    for v in (d.get("isEnabled"), scan.get("scanStatus")):
        if isinstance(v, bool):
            return v
    return None


# jobStatus while a run is going (the 3.5 spec gives no enum; the lab answered null when idle).
RUNNING_JOBS = {"RUNNING", "IN_PROGRESS", "INPROGRESS", "STARTED", "SCANNING", "QUEUED", "PENDING"}


def scan_running(scan: dict[str, Any]) -> bool:
    """A run is in progress: jobStatus says so, or the last start is later than the last end."""
    job = re.sub(r"[\s-]+", "_", str(scan.get("jobStatus") or "").strip()).upper()
    if job in RUNNING_JOBS:
        return True
    start, end = scan.get("scanStartTime"), scan.get("scanEndTime")
    return isinstance(start, int | float) and start > 0 and (not isinstance(end, int | float) or start > end)


async def find_scan(app: IseApp, name: str) -> dict[str, Any] | None:
    hits = [s for s in await list_scans(app) if scan_name(s) == name]
    return hits[0] if hits else None


async def require_scan(app: IseApp, name: str) -> dict[str, Any]:
    scan = await find_scan(app, name)
    if scan is None:
        raise NotFound(f"No SNMP scan {name!r} (see ise_snmp_scan_history with no name)", 404)
    return scan


def parse_targets(targets: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """'192.0.2.0/24' -> subnet, '192.0.2.10-192.0.2.20' -> IP range, '192.0.2.5' -> a /32 subnet (or a
    one-address range when the scope uses ranges). ISE takes subnets or ranges, never both."""
    subnets: list[dict[str, Any]] = []
    ranges: list[dict[str, str]] = []
    singles: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw in targets:
        t = raw.strip()
        try:
            if "-" in t:
                a, b = (ipaddress.ip_address(p.strip()) for p in t.split("-", 1))
                if a.version != b.version or int(b) < int(a):
                    raise ValueError
                ranges.append({"startIp": str(a), "endIp": str(b)})
            elif "/" in t:
                net = ipaddress.ip_network(t, strict=False)
                if net.prefixlen < MIN_MASK[net.version]:
                    raise InvalidRequest(
                        f"{t}: ISE scans subnets of /{MIN_MASK[net.version]} or smaller "
                        f"(/{MIN_MASK[net.version]}../{net.max_prefixlen}); split it"
                    )
                subnets.append({"subnetIp": str(net.network_address), "mask": net.prefixlen})
            else:
                singles.append(ipaddress.ip_address(t))
        except InvalidRequest:
            raise
        except ValueError:
            raise InvalidRequest(
                f"{raw!r} is not a subnet ('192.0.2.0/24'), a range ('192.0.2.10-192.0.2.20') or an address"
            ) from None
    if subnets and ranges:
        raise InvalidRequest("ISE takes subnets or IP ranges in one scan, not both: pick one form")
    for ip in singles:
        if ranges:
            ranges.append({"startIp": str(ip), "endIp": str(ip)})
        else:
            subnets.append({"subnetIp": str(ip), "mask": ip.max_prefixlen})
    return subnets, ranges


def scope_size(scope: dict[str, Any]) -> int | None:
    """Addresses a scope covers (excluded ones taken off), or None when ISE returned something unparsable."""
    try:
        n = sum(
            ipaddress.ip_network(f"{s['subnetIp']}/{s['mask']}", strict=False).num_addresses
            for s in scope.get("subnets") or []
        )
        n += sum(
            int(ipaddress.ip_address(r["endIp"])) - int(ipaddress.ip_address(r["startIp"])) + 1
            for r in scope.get("ipRanges") or []
        )
    except (KeyError, TypeError, ValueError):
        return None
    return max(n - len(scope.get("excludedIps") or []), 0)


def scope_view(scope: Any) -> dict[str, Any]:
    scope = scope if isinstance(scope, dict) else {}
    out = {
        "targets": [f"{s.get('subnetIp')}/{s.get('mask')}" for s in scope.get("subnets") or []]
        + [f"{r.get('startIp')}-{r.get('endIp')}" for r in scope.get("ipRanges") or []],
        "excluded": list(scope.get("excludedIps") or []),
    }
    return out


def auth_view(auth: Any) -> list[dict[str, Any]]:
    """SNMP credentials without their secrets (only whether one is stored)."""
    out = []
    for a in auth if isinstance(auth, list) else []:
        if not isinstance(a, dict):
            continue
        row = {
            k: a.get(k)
            for k in ("snmpVersion", "username", "securityLevel", "authProtocol", "privacyProtocol")
            if a.get(k) not in (None, "")
        }
        for k in SECRET_FIELDS:
            if a.get(k) not in (None, ""):
                row[k] = "(set, never shown)"
        out.append(row)
    return out


def schedule_view(sched: Any) -> str:
    sched = sched if isinstance(sched, dict) else {}
    kind = str(sched.get("scheduleType") or "NO_SCHEDULE")
    return "none" if kind == "NO_SCHEDULE" else f"{kind.lower()} {sched.get('time') or ''}".strip()


def config_view(d: dict[str, Any]) -> dict[str, Any]:
    """The comparable, secret-free view of a scan's settings (create preview, update diff)."""
    sv = scope_view(d.get("networkScope"))
    return {
        "name": d.get("name"),
        "description": d.get("description") or "",
        "enabled": d.get("isEnabled"),
        "source": d.get("scanSource"),
        "targets": sv["targets"],
        "excluded": sv["excluded"],
        "schedule": schedule_view(d.get("scheduleTime")),
        "credentials": auth_view(d.get("snmpAuthData")),
    }


def _ts(value: Any) -> str | None:
    if not isinstance(value, int | float) or value <= 0:
        return None
    secs = value / 1000 if value > 10**11 else value
    return datetime.fromtimestamp(secs, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def history_row(h: dict[str, Any]) -> dict[str, Any]:
    row = {
        "time": _ts(h.get("scanTime")) or h.get("scanTime"),
        "result": h.get("scanResult"),
        "psn": h.get("psnFqdn"),
        "scanned": h.get("scannedIp"),
        "discovered": h.get("discovered"),
        "not_reachable": h.get("ipNotReachable"),
        "snmp_auth_failed": h.get("snmpAuthFailed"),
        "snmp_null_response": h.get("snmpNullResponse"),
        "errors": h.get("scanErrorDetails") or None,
        "id": h.get("scanHistoryID"),
    }
    return {k: v for k, v in row.items() if v is not None}


def scan_row(s: dict[str, Any]) -> dict[str, Any]:
    d = details_of(s)
    hist = [h for h in s.get("history") or [] if isinstance(h, dict)]
    last = max(hist, key=lambda h: h.get("scanTime") or 0) if hist else None
    row = {
        "name": scan_name(s),
        "enabled": scan_enabled(s),
        "source": d.get("scanSource") or s.get("psnGroup"),
        "targets": ", ".join(scope_view(d.get("networkScope"))["targets"]) or None,
        "schedule": schedule_view(d.get("scheduleTime")),
        "job_status": s.get("jobStatus"),
        "last_start": _ts(s.get("scanStartTime")),
        "last_end": _ts(s.get("scanEndTime")),
        "scanned": s.get("scannedIp"),
        "discovered": s.get("discoveredIp"),
        "last_result": last.get("scanResult") if last else None,
        "id": scan_id(s),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def history_items(data: Any) -> list[dict[str, Any]]:
    """ScanHistory rows from /scan-history/{id}: a list, {"response": [...]}, or an entity with history."""
    data = _unwrap(data)
    if isinstance(data, dict):
        for key in ("history", "scanHistory", "result"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data] if any(k in data for k in ("scanResult", "scanTime")) else []
    return [h for h in data or [] if isinstance(h, dict)] if isinstance(data, list) else []


def endpoint_macs(data: Any) -> list[str]:
    """MAC addresses anywhere in a history payload (in case ISE lists the endpoints a run found)."""
    found: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for k, x in v.items():
                if k in ("mac", "macAddress", "endpointMac", "MACAddress") and isinstance(x, str):
                    found.append(x)
                else:
                    walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(data)
    return list(dict.fromkeys(found))


async def psn_choices(app: IseApp) -> tuple[list[str], list[str]]:
    try:
        data = _unwrap(await app.openapi.get(PSN_GROUPS))
    except (NotFound, UpstreamError):
        return [], []
    data = data if isinstance(data, dict) else {}
    psns = [str(p) for p in data.get("psns") or []]
    groups = [str(g.get("name") if isinstance(g, dict) else g) for g in data.get("psnGroups") or []]
    return psns, groups


def build_schedule(schedule: str, at: str | None, day: str | None) -> tuple[dict[str, Any], list[str]]:
    """ScheduleType from the tool arguments. The 3.5 spec has one `time` string: '12:00 am' for DAILY,
    the day and time for WEEKLY ('Monday 02:00 am') and MONTHLY ('15 02:00 am')."""
    errors: list[str] = []
    kind = SCHEDULES[schedule]
    if kind == "NO_SCHEDULE":
        if at or day:
            errors.append("schedule='none' takes no schedule_time or schedule_day")
        return {"scheduleType": kind}, errors
    m = TIME_RE.fullmatch((at or "").strip())
    if not m:
        errors.append(f"schedule={schedule!r} needs schedule_time in ISE's '12:00 am' form, e.g. '02:30 am'")
        return {"scheduleType": kind}, errors
    hh, mm = m.group(0).split(":")
    clock = f"{int(hh):02d}:{mm[:2]} {m.group(2).lower()}"
    if kind == "DAILY":
        if day:
            errors.append("A daily schedule takes no schedule_day")
        return {"scheduleType": kind, "time": clock}, errors
    if kind == "WEEKLY":
        wd = next((w for w in WEEKDAYS if w.lower() == str(day or "").strip().lower()), None)
        if not wd:
            errors.append("A weekly schedule needs schedule_day: Sunday .. Saturday")
            return {"scheduleType": kind}, errors
        return {"scheduleType": kind, "time": f"{wd} {clock}"}, errors
    if not str(day or "").strip().isdigit() or not 1 <= int(str(day)) <= 31:
        errors.append("A monthly schedule needs schedule_day: a day of the month, 1-31")
        return {"scheduleType": kind}, errors
    return {"scheduleType": kind, "time": f"{int(str(day))} {clock}"}, errors


def reusable_auth(auth: Any) -> list[dict[str, Any]] | None:
    """The stored credentials, when ISE returned them whole (secrets present and not masked)."""
    if not isinstance(auth, list) or not auth:
        return None
    for a in auth:
        if not isinstance(a, dict):
            return None
        secrets = [a.get(k) for k in SECRET_FIELDS if a.get(k) not in (None, "")]
        if not secrets or any("*" in str(s) for s in secrets):
            return None
    for a in auth:
        for k in SECRET_FIELDS:
            if a.get(k):
                register_secret(str(a[k]))
    return [dict(a) for a in auth]


# --- tools --------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SNMP scans and their history")
    async def ise_snmp_scan_history(
        ctx: Context,
        name: Annotated[
            str | None,
            Field(description="Scan name for its run history; omit to list every SNMP scan with its state"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The profiler's endpoint SNMP scans (Work Centers > Profiler > Endpoint Scans). Without a name:
        every scan with enabled, PSN, scope, schedule, job status, last start/end, addresses scanned and
        discovered, and the last result. With a name: the scan's settings (credentials never shown) and its
        runs newest first (result, PSN, scanned, discovered, unreachable, SNMP auth failures, null
        responses, errors), with the next step to see which profiles moved (ise_explain_profile)."""
        app: IseApp = get_client(ctx)
        if not name:
            rows = sorted((scan_row(s) for s in await list_scans(app)), key=lambda r: str(r.get("name")))
            return list_result(
                page_of(rows, limit=limit, offset=offset),
                fmt=response_format,
                columns=["name", "enabled", "source", "targets", "schedule", "job_status", "last_result"],
                extra={
                    "next": "ise_snmp_scan_history(name) for a scan's runs; ise_run_snmp_scan to start one"
                },
            )
        scan = await require_scan(app, name)
        sid = scan_id(scan)
        try:
            raw: Any = await app.openapi.get(f"{HISTORY}/{quote(sid, safe='')}")
        except NotFound:
            raw = scan.get("history") or []
        runs = sorted(
            (history_row(h) for h in history_items(raw) or scan.get("history") or [] if isinstance(h, dict)),
            key=lambda r: str(r.get("time") or ""),
            reverse=True,
        )
        macs = endpoint_macs(raw)
        totals = {
            k: sum(int(r.get(k) or 0) for r in runs)
            for k in ("scanned", "discovered", "not_reachable", "snmp_auth_failed", "snmp_null_response")
        }
        hints: list[str] = []
        if totals["snmp_auth_failed"]:
            hints.append(
                "SNMP auth failures: the endpoints answered but rejected the community / v3 credentials; "
                "fix them with ise_set_snmp_scan(community_env=...)"
            )
        if runs and totals["scanned"] and not totals["discovered"] and not totals["snmp_auth_failed"]:
            hints.append(
                "Addresses were scanned but nothing answered SNMP: check that the endpoints run an SNMP "
                "agent and that UDP/161 from the PSN reaches the segment"
            )
        out: dict[str, Any] = {
            "scan": {**config_view(details_of(scan)), "job_status": scan.get("jobStatus"), "id": sid},
            "runs": runs[offset : offset + limit],
            "total_runs": len(runs),
            "totals": totals,
            "last_result": runs[0].get("result") if runs else None,
            "explain": EXPLAIN_HINT,
        }
        if macs:
            out["endpoints"] = [{"mac": m, "next": f"ise_explain_profile(mac='{m}')"} for m in macs]
        if hints:
            out["hints"] = hints
        if not runs:
            out["note"] = f"No runs yet: start one with ise_run_snmp_scan(names=['{name}'], action='start')"
        return object_result(out, fmt=response_format)

    @reg.write(title="Create or update a profiler SNMP scan")
    async def ise_set_snmp_scan(
        ctx: Context,
        name: Annotated[
            str,
            Field(min_length=1, max_length=255, description="Scan name (created if missing, else updated)"),
        ],
        targets: Annotated[
            list[str] | None,
            Field(
                description="What to scan: subnets '192.0.2.0/24' (/21../32; IPv6 /117../128) or ranges "
                "'192.0.2.10-192.0.2.20', not both; a bare address is a /32. Required to create"
            ),
        ] = None,
        exclude: Annotated[list[str] | None, Field(description="Addresses inside the scope to skip")] = None,
        source: Annotated[
            str | None,
            Field(
                description="PSN FQDN or PSN group that runs the scan; defaults to the only PSN when there "
                "is one"
            ),
        ] = None,
        snmp_version: Annotated[
            Literal["v1", "v2c", "v3"] | None, Field(description="SNMP version (default v2c on create)")
        ] = None,
        community_env: Annotated[
            str | None,
            Field(
                description="v1/v2c: name of the server environment variable holding the read community, "
                "e.g. 'ISE_SNMP_COMMUNITY' (or its _FILE twin); never the community itself"
            ),
        ] = None,
        v3_username: Annotated[str | None, Field(description="v3: SNMPv3 user name")] = None,
        v3_security_level: Annotated[
            Literal["noAuthNoPriv", "authNoPriv", "authPriv"] | None, Field(description="v3: security level")
        ] = None,
        v3_auth_protocol: Annotated[
            Literal["MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"] | None,
            Field(description="v3: authentication protocol"),
        ] = None,
        v3_auth_password_env: Annotated[
            str | None, Field(description="v3: environment variable (ISE_SNMP_...) holding the auth password")
        ] = None,
        v3_privacy_protocol: Annotated[
            Literal["AES", "AES-192", "AES-256", "DES"] | None, Field(description="v3: privacy protocol")
        ] = None,
        v3_privacy_password_env: Annotated[
            str | None,
            Field(description="v3: environment variable (ISE_SNMP_...) holding the privacy password"),
        ] = None,
        schedule: Annotated[
            Literal["none", "daily", "weekly", "monthly"] | None,
            Field(description="When ISE runs it (none: only when started); default none on create"),
        ] = None,
        schedule_time: Annotated[
            str | None,
            Field(description="Time in ISE's 12-hour form, e.g. '02:30 am' (daily/weekly/monthly)"),
        ] = None,
        schedule_day: Annotated[
            str | None, Field(description="Weekly: Sunday..Saturday; monthly: day of the month 1-31")
        ] = None,
        description: Annotated[
            str | None, Field(max_length=1024, description="Free-text note on the scan")
        ] = None,
        enabled: Annotated[
            bool | None,
            Field(description="Enable or disable the scan (a disabled scan never runs, even on schedule)"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a profiler endpoint SNMP scan, or update the one with this name: ISE's PSN sends SNMP
        queries to every address in the scope so printers, cameras and building controllers that say little
        over DHCP/RADIUS get profiled (and so an SGT). The community or SNMPv3 passwords come from server
        environment variables named ISE_SNMP_... (never tool arguments, never shown). Omitted settings keep
        their current values on update; changing only `enabled` uses ISE's status call and needs no
        credential. Unchanged: no_change. Preview-first with a diff; start it with ise_run_snmp_scan and
        read the runs with ise_snmp_scan_history."""
        app: IseApp = get_client(ctx)
        args = {
            "name": name,
            "targets": targets,
            "exclude": exclude,
            "source": source,
            "snmp_version": snmp_version,
            "community_env": community_env,
            "v3_username": v3_username,
            "v3_security_level": v3_security_level,
            "v3_auth_protocol": v3_auth_protocol,
            "v3_auth_password_env": v3_auth_password_env,
            "v3_privacy_protocol": v3_privacy_protocol,
            "v3_privacy_password_env": v3_privacy_password_env,
            "schedule": schedule,
            "schedule_time": schedule_time,
            "schedule_day": schedule_day,
            "description": description,
            "enabled": enabled,
        }
        current = await find_scan(app, name)
        cur = dict(details_of(current)) if current else {}
        blockers: list[str] = []

        # Network scope
        scope: dict[str, Any] = dict(cur.get("networkScope") or {})
        if targets is not None:
            if not targets:
                raise InvalidRequest("targets can't be empty")
            subnets, ranges = parse_targets(targets)
            scope = {"subnets": subnets, "ipRanges": ranges, "excludedIps": scope.get("excludedIps") or []}
        if exclude is not None:
            for ip in exclude:
                try:
                    ipaddress.ip_address(ip.strip())
                except ValueError:
                    raise InvalidRequest(f"exclude takes addresses, not {ip!r}") from None
            scope["excludedIps"] = [ip.strip() for ip in exclude]
        if current is None and targets is None:
            raise InvalidRequest(f"No SNMP scan {name!r} yet: give targets to create it")

        # Where it runs
        psns, groups = await psn_choices(app)
        scan_source = source or cur.get("scanSource")
        if not scan_source:
            if len(psns) == 1 and not groups:
                scan_source = psns[0]
            else:
                blockers.append(
                    "Give source: the PSN or PSN group to run the scan on "
                    f"(PSNs: {', '.join(psns) or 'none listed'}; groups: {', '.join(groups) or 'none'})"
                )
        elif source and (psns or groups) and source not in psns + groups:
            blockers.append(
                f"{source!r} is not a PSN or PSN group ISE offers for scans "
                f"(PSNs: {', '.join(psns) or 'none'}; groups: {', '.join(groups) or 'none'})"
            )

        # Schedule
        if schedule is not None or schedule_time is not None or schedule_day is not None:
            kind: str = schedule or next(
                (k for k, v in SCHEDULES.items() if v == (cur.get("scheduleTime") or {}).get("scheduleType")),
                "none",
            )
            sched, errs = build_schedule(kind, schedule_time, schedule_day)
            if errs:
                raise InvalidRequest("; ".join(errs))
        else:
            sched = cur.get("scheduleTime") or {"scheduleType": "NO_SCHEDULE"}

        # Credentials
        cur_auth = cur.get("snmpAuthData") if isinstance(cur.get("snmpAuthData"), list) else []
        cur_version = next(
            (k for k, v in VERSIONS.items() if cur_auth and v == cur_auth[0].get("snmpVersion")), None
        )
        version = snmp_version or cur_version or "v2c"
        v3_args = (
            v3_username,
            v3_security_level,
            v3_auth_protocol,
            v3_auth_password_env,
            v3_privacy_protocol,
            v3_privacy_password_env,
        )
        cred_given = (
            community_env is not None or any(a is not None for a in v3_args) or snmp_version is not None
        )
        auth: list[dict[str, Any]] | None = None
        auth_shown: list[dict[str, Any]] = auth_view(cur_auth)
        if version in ("v1", "v2c"):
            if any(a is not None for a in v3_args):
                raise InvalidRequest(f"The v3_* settings apply to snmp_version='v3', not {version}")
            if community_env:
                community = secret_from_env(community_env, "community_env")
                if not community:
                    blockers.append(
                        f"{community_env} (or {community_env}_FILE) is not set on this server: add it to the "
                        "server's environment and restart it."
                    )
                else:
                    auth = [{"snmpVersion": VERSIONS[version], "roCommunity": community}]
                auth_shown = [
                    {"snmpVersion": VERSIONS[version], "roCommunity": f"(from {community_env}, never shown)"}
                ]
            elif cred_given:
                blockers.append(f"SNMP {version} needs community_env (the ISE_SNMP_... variable holding it)")
        elif cred_given or current is None:
            level = v3_security_level or "authPriv"
            if not v3_username:
                blockers.append("SNMPv3 needs v3_username")
            entry: dict[str, Any] = {"snmpVersion": "snmpV3", "username": v3_username, "securityLevel": level}
            shown: dict[str, Any] = dict(entry)
            if level in ("authNoPriv", "authPriv"):
                if not (v3_auth_protocol and v3_auth_password_env):
                    blockers.append(f"securityLevel {level} needs v3_auth_protocol and v3_auth_password_env")
                else:
                    pw = secret_from_env(v3_auth_password_env, "v3_auth_password_env")
                    if not pw:
                        blockers.append(f"{v3_auth_password_env} is not set on this server")
                    entry.update(authProtocol=v3_auth_protocol, authPassword=pw)
                    shown.update(
                        authProtocol=v3_auth_protocol,
                        authPassword=f"(from {v3_auth_password_env}, never shown)",
                    )
            if level == "authPriv":
                if not (v3_privacy_protocol and v3_privacy_password_env):
                    blockers.append(
                        "securityLevel authPriv needs v3_privacy_protocol and v3_privacy_password_env"
                    )
                else:
                    pw = secret_from_env(v3_privacy_password_env, "v3_privacy_password_env")
                    if not pw:
                        blockers.append(f"{v3_privacy_password_env} is not set on this server")
                    entry.update(privacyProtocol=v3_privacy_protocol, privacyPassword=pw)
                    shown.update(
                        privacyProtocol=v3_privacy_protocol,
                        privacyPassword=f"(from {v3_privacy_password_env}, never shown)",
                    )
            auth, auth_shown = [entry], [shown]
        if current is None and version != "v3" and community_env is None:
            blockers.append("A new scan needs credentials: community_env (v1/v2c) or the v3_* settings (v3)")

        desired: dict[str, Any] = {
            **({"id": scan_id(current)} if current else {}),
            "name": name,
            "description": (cur.get("description") or "") if description is None else description,
            "isEnabled": (bool(scan_enabled(current)) if current else True) if enabled is None else enabled,
            "scanSource": scan_source,
            "networkScope": scope,
            "scheduleTime": sched,
        }
        size = scope_size(scope)
        side: list[str] = []
        if desired["isEnabled"] and sched.get("scheduleType") != "NO_SCHEDULE":
            side.append(
                f"ISE scans {size if size is not None else 'the'} address(es) {schedule_view(sched)} from "
                f"{scan_source}: SNMP (UDP/161) queries to every address in the scope"
            )
        if sched.get("scheduleType") == "NO_SCHEDULE":
            side.append("Nothing is scanned until it is started: ise_run_snmp_scan(action='start')")

        if current is None:
            after = {**config_view({**desired, "snmpAuthData": []}), "credentials": auth_shown}

            async def create() -> Any:
                body = {**desired, "snmpAuthData": auth}
                res = await _send(app, "POST", SCANS, body, auth)
                res = res if isinstance(res, dict) else {}
                made = await find_scan(app, name)
                return {
                    "created": name,
                    "id": res.get("scanId") or scan_id(made or {}) or None,
                    "message": res.get("message"),
                    "next": f"ise_run_snmp_scan(names=['{name}'], action='start'), then "
                    "ise_snmp_scan_history",
                }

            return await preview_or_apply(
                ctx,
                tool="ise_set_snmp_scan",
                args=args,
                confirm=confirm,
                plan=Plan(
                    f"Create SNMP scan {name} ({', '.join(after['targets'])}) on {scan_source}",
                    details={"scan": after, "addresses": size, "method": "POST", "path": SCANS},
                    blockers=blockers,
                    side_effects=side,
                ),
                apply=create,
            )

        # Update
        before_view = {**config_view(cur), "enabled": scan_enabled(current)}
        after_view = {**config_view({**desired, "snmpAuthData": cur_auth}), "credentials": auth_shown}
        changes = field_changes(before_view, after_view)
        secret_sent = auth is not None
        only_status = bool(changes) and set(changes) == {"enabled"} and not secret_sent
        noop = not blockers and not changes and not secret_sent
        sid = scan_id(current)
        if not noop and not only_status and auth is None and not blockers:
            auth = reusable_auth(cur_auth)
            if auth is None:
                blockers.append(
                    "ISE does not return the stored SNMP credentials, and an update replaces the whole scan: "
                    "give community_env (or the v3_* settings) again, or change only `enabled`."
                )
        plan = Plan(
            f"Update SNMP scan {name}"
            + (f": {'enable' if enabled else 'disable'} it" if only_status else ""),
            details={
                "changes": changes,
                **({"credentials": "replaced (never shown)"} if secret_sent else {}),
                "addresses": size,
                "method": "POST" if only_status else "PUT",
                "path": STATUS if only_status else f"{SCANS}/{sid}",
            },
            fingerprint=fingerprint(cur),
            blockers=blockers,
            side_effects=[] if noop else side,
            noop=noop,
            noop_reason=f"SNMP scan {name!r} already has exactly these settings" if noop else None,
        )

        async def update() -> Any:
            if only_status:
                res = await app.openapi.post(
                    STATUS, {"status": "enable" if desired["isEnabled"] else "disable", "ids": [sid]}
                )
                return {
                    "updated": name,
                    "enabled": desired["isEnabled"],
                    "result": action_results(res, {sid: name}),
                }
            res = await _send(
                app, "PUT", f"{SCANS}/{quote(sid, safe='')}", {**desired, "snmpAuthData": auth}, auth
            )
            return {
                "updated": name,
                "id": sid,
                "message": res.get("message") if isinstance(res, dict) else None,
            }

        return await preview_or_apply(
            ctx, tool="ise_set_snmp_scan", args=args, confirm=confirm, plan=plan, apply=update
        )

    @reg.write(title="Start, stop, enable or disable SNMP scans")
    async def ise_run_snmp_scan(
        ctx: Context,
        names: Annotated[list[str], Field(min_length=1, description="Scan names (ise_snmp_scan_history)")],
        action: Annotated[
            Literal["start", "stop", "enable", "disable"],
            Field(
                description="start (one scan at a time: ISE's rule) or stop a run now; enable/disable a scan "
                "(a disabled scan never runs, even on its schedule)"
            ),
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Run a profiler SNMP scan now (start), stop one that is running, or enable / disable scans. Start
        sends SNMP queries from the scan's PSN to every address in its scope; the endpoints that answer get
        SNMP attributes that can change their profile (ise_explain_profile shows it). ISE starts one scan per
        request and stops several. Enable/disable on scans already in that state: no_change. Delete a scan
        with ise_delete_object(kind='snmp_scan'). Preview-first:
        the scans, their PSN, scope size and job status; the result reports ISE's answer per scan."""
        app: IseApp = get_client(ctx)
        if len(set(names)) != len(names):
            raise InvalidRequest("names lists a scan twice")
        scans = [await require_scan(app, n) for n in names]
        ids = {scan_id(s): scan_name(s) for s in scans}
        blockers: list[str] = []
        if action == "start" and len(scans) > 1:
            blockers.append("ISE starts one SNMP scan at a time: start them one by one")
        if action == "start":
            blockers += [
                f"{scan_name(s)!r} is disabled: enable it first (action='enable')"
                for s in scans
                if scan_enabled(s) is False
            ]
        rows = []
        total = 0
        for s in scans:
            size = scope_size(details_of(s).get("networkScope") or {})
            total += size or 0
            rows.append(
                {
                    "name": scan_name(s),
                    "enabled": scan_enabled(s),
                    "source": details_of(s).get("scanSource"),
                    "addresses": size,
                    "job_status": s.get("jobStatus"),
                }
            )
        want = action == "enable"
        noop = action in ("enable", "disable") and all(scan_enabled(s) is want for s in scans)
        side: list[str] = []
        if action == "start":
            side.append(
                f"{rows[0]['source']} sends SNMP (UDP/161) queries to {rows[0]['addresses']} address(es); "
                "endpoints that answer may be reprofiled"
            )
        elif action == "disable":
            side.append(
                "Disabled scans don't run on their schedule until enabled again; to remove a scan: "
                "ise_delete_object(kind='snmp_scan', target=<name>)"
            )
        path = ACTION if action in ("start", "stop") else STATUS
        body = (
            {"action": action, "ids": list(ids)} if path == ACTION else {"status": action, "ids": list(ids)}
        )
        plan = Plan(
            f"{action.capitalize()} SNMP scan(s) {', '.join(names)}",
            details={"scans": rows, "method": "POST", "path": path},
            fingerprint=fingerprint([[scan_enabled(s), s.get("jobStatus")] for s in scans]),
            blockers=blockers,
            side_effects=[] if noop else side,
            blast_radius=len(scans),
            noop=noop and not blockers,
            noop_reason=(f"Every scan is already {action}d" if noop and not blockers else None),
        )

        async def apply() -> Any:
            res = await app.openapi.post(path, body)
            out: dict[str, Any] = {"action": action, "result": action_results(res, ids)}
            if action == "start":
                out["next"] = (
                    f"ise_snmp_scan_history(name='{names[0]}') once the run ends; then "
                    "ise_explain_profile(mac) on an endpoint in the scope"
                )
            elif action in ("stop", "disable"):
                out["next"] = (
                    "ise_snmp_scan_history shows the state; ise_delete_object(kind='snmp_scan', "
                    "target=<name>) removes a scan (DELETE /api/v1/profiler/snmp/scan with {'ids': [...]})"
                )
            return out

        return await preview_or_apply(
            ctx,
            tool="ise_run_snmp_scan",
            args={"names": names, "action": action},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )


async def delete_snmp_scan(ctx: Context, app: IseApp, target: str, confirm: str | None) -> dict[str, Any]:
    """ise_delete_object kind='snmp_scan': one scan by name (or id), sent as the collection
    DELETE /scan {"ids": [id]} (deleteSNMPScans); ISE 3.5 answers 405 on DELETE /scan/{id} (#161)."""
    scans = await list_scans(app)
    hits = [s for s in scans if scan_name(s) == target] or [s for s in scans if scan_id(s) == target]
    if not hits:
        raise NotFound(f"No SNMP scan {target!r} (see ise_snmp_scan_history with no name)", 404)
    scan = hits[0]
    name, sid = scan_name(scan), scan_id(scan)
    d = details_of(scan)
    blockers: list[str] = []
    if scan_running(scan):
        blockers.append(
            f"{name!r} is running (job status {scan.get('jobStatus') or 'started, not ended'}): stop "
            f"it first with ise_run_snmp_scan(names=['{name}'], action='stop')"
        )
    enabled = scan_enabled(scan)
    side = ["Its run history goes with it; endpoints it profiled keep their attributes and profiles"]
    if enabled and (d.get("scheduleTime") or {}).get("scheduleType") not in (None, "NO_SCHEDULE"):
        side.insert(
            0,
            f"Its {schedule_view(d.get('scheduleTime'))} schedule stops: those addresses are no "
            "longer scanned",
        )
    body = {"ids": [sid]}
    plan = Plan(
        f"Delete SNMP scan {name}",
        details={
            **config_view(d),
            "enabled": enabled,
            "job_status": scan.get("jobStatus"),
            "id": sid,
            "method": "DELETE",
            "path": SCANS,
            "body": body,
        },
        fingerprint=fingerprint([scan_enabled(scan), scan.get("jobStatus"), d]),
        blockers=blockers,
        side_effects=side,
    )

    async def apply() -> Any:
        res = await app.openapi.request("DELETE", SCANS, json=body)
        rows = [
            {**r, "name": name} if r.get("name") in (None, "None") else r
            for r in action_results(res, {sid: name})
        ]
        failed = [r for r in rows if str(r.get("status") or "").lower() not in ("success", "sent")]
        if failed:
            why = failed[0].get("failure_reason") or failed[0]["status"]
            raise UpstreamError(f"ISE did not delete SNMP scan {name!r}: {why}", 502)
        return {"deleted": name, "id": sid, "result": rows}

    return await preview_or_apply(
        ctx,
        tool="ise_delete_object",
        args={"kind": "snmp_scan", "target": target},
        confirm=confirm,
        plan=plan,
        apply=apply,
    )


def action_results(res: Any, names: dict[str, str]) -> list[dict[str, Any]]:
    """SNMPScanResponseWrapper {"result": [{id, status, failureReason}]} with scan names."""
    data = _unwrap(res)
    items = data.get("result") if isinstance(data, dict) else data
    out = []
    for r in items if isinstance(items, list) else []:
        if isinstance(r, dict):
            row = {"name": names.get(str(r.get("id")), r.get("id")), "status": r.get("status")}
            if r.get("failureReason"):
                row["failure_reason"] = r["failureReason"]
            out.append(row)
    return out or [{"name": n, "status": "sent"} for n in names.values()]


async def _send(app: IseApp, method: str, path: str, body: dict[str, Any], auth: Any) -> Any:
    """POST/PUT a scan; ISE's error text never carries a credential back to the caller."""
    try:
        return await app.openapi.request(method, path, json=body)
    except UpstreamError as err:
        text = str(err)
        for a in auth or []:
            for k in SECRET_FIELDS:
                if a.get(k):
                    text = text.replace(str(a[k]), "***")
        raise type(err)(text, err.status_code) from None

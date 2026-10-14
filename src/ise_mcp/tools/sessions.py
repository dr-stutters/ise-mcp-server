"""Live sessions and authentication history (MnT, XML)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import asyncio
from typing import Annotated, Any
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    InvalidRequest,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from stutters_mcp_core.http import page_of

from ise_mcp.client import IseApp
from ise_mcp.knowledge import FAILURE_HINTS, decode_steps
from ise_mcp.tools._common import DEFAULT_LOOKBACK_MINUTES, normalize_mac, parse_ip
from ise_mcp.xmlutil import as_list

SESSION_COLUMNS = [
    "user_name",
    "calling_station_id",
    "framed_ip_address",
    "nas_ip_address",
    "server",
    "audit_session_id",
]


def _clean(d: Any) -> Any:
    if isinstance(d, dict):
        return {k: _clean(v) for k, v in d.items() if v not in (None, "", {}, [])}
    return d


async def failure_info(app: IseApp, failure_reason: str | None) -> dict[str, Any] | None:
    """Decode '22056 Subject not found ...' using the MnT catalog plus curated hints."""
    if not failure_reason:
        return None
    code = failure_reason.strip().split(" ", 1)[0]
    out: dict[str, Any] = {"code": code, "reason": failure_reason}
    catalog = (await app.failure_reasons()).get(code)
    if catalog:
        out["cause"] = catalog.get("cause")
        out["resolution"] = catalog.get("resolution")
    if code in FAILURE_HINTS:
        out["likely"] = FAILURE_HINTS[code]["likely"]
        out["next_step"] = FAILURE_HINTS[code]["check"]
    return _clean(out)  # type: ignore[no-any-return]


def auth_row(
    el: dict[str, Any], *, steps: bool = False, catalog: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Shape one MnT authStatusElements record."""
    row: dict[str, Any] = {
        "time": el.get("acs_timestamp"),
        "result": "PASS" if str(el.get("passed", "")).lower() == "true" else "FAIL",
        "user": el.get("user_name"),
        "mac": el.get("calling_station_id"),
        "nas_ip": el.get("nas_ip_address"),
        "nad": el.get("network_device_name"),
        "nas_port": el.get("nas_port_id"),
        "method": el.get("authentication_method"),
        "protocol": el.get("authentication_protocol"),
        "identity_store": el.get("identity_store"),
        "identity_group": el.get("identity_group"),
        "authz_profiles": el.get("selected_azn_profiles"),
        "sgt": el.get("cts_security_group"),
        "posture": el.get("posture_status"),
        "failure_reason": el.get("failure_reason"),
        "response": el.get("response"),
        "location": el.get("location"),
        "device_type": el.get("device_type"),
        "psn": el.get("acs_server"),
        "audit_session_id": el.get("audit_session_id"),
    }
    if steps:
        row["steps"] = decode_steps(el.get("execution_steps"), catalog)
    return _clean(row)  # type: ignore[no-any-return]


async def auth_history(app: IseApp, mac: str, minutes: int, records: int) -> list[dict[str, Any]]:
    """Raw MnT auth records for a MAC, newest first."""
    data = await app.mnt_get(f"AuthStatus/MACAddress/{quote(mac)}/{minutes * 60}/{records}/All")
    if not isinstance(data, dict):
        return []
    out: list[dict[str, Any]] = []
    for lst in as_list(data.get("authStatusList")):
        if isinstance(lst, dict):
            out += [e for e in as_list(lst.get("authStatusElements")) if isinstance(e, dict)]
    out.sort(key=lambda e: str(e.get("acs_timestamp") or ""), reverse=True)
    return out


async def find_session(
    app: IseApp,
    *,
    mac: str | None = None,
    ip: str | None = None,
    username: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any] | None:
    if mac:
        path = f"Session/MACAddress/{quote(normalize_mac(mac))}"
    elif ip:
        addr = parse_ip(ip)
        if addr is None:
            raise InvalidRequest(f"{ip!r} is not an IP address")
        path = f"Session/EndPointIPAddress/{quote(addr)}"
    elif username:
        path = f"Session/UserName/{quote(username, safe='')}"
    elif session_id:
        path = f"Session/Active/SessionID/{quote(session_id, safe='')}/0"
    else:
        raise InvalidRequest("Give one of mac, ip, username or session_id")
    data = await app.mnt_get(path)
    if not isinstance(data, dict):
        return None
    session: dict[str, Any] = _clean(data)
    attrs = parse_other_attrs(session.pop("other_attr_string", None))
    policy = {
        "policy_set": attrs.get("ISEPolicySetName"),
        "authentication_rule": attrs.get("IdentityPolicyMatchedRule"),
        "authorization_rule": attrs.get("AuthorizationPolicyMatchedRule"),
    }
    if any(policy.values()):
        session["matched_policy"] = _clean(policy)
    if attrs:
        session["attributes"] = attrs
    for noisy in ("execution_steps",):
        session.pop(noisy, None)
    return session


_NOISY_ATTRS = {"StepLatency", "StepData", "EnableFlag", "TotalAuthenLatency", "ClientLatency"}


def parse_other_attrs(text: Any) -> dict[str, Any]:
    """MnT's other_attr_string ('Key=Value:!:Key=Value...') as a dict; repeated keys become lists."""
    out: dict[str, Any] = {}
    if not isinstance(text, str):
        return out
    for part in text.split(":!:"):
        key, sep, value = part.partition("=")
        key = key.strip()
        if not sep or not key or key in _NOISY_ATTRS:
            continue
        if key in out:
            out[key] = [*(out[key] if isinstance(out[key], list) else [out[key]]), value]
        else:
            out[key] = value
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List active sessions")
    async def ise_list_active_sessions(
        ctx: Context,
        user: Annotated[str | None, Field(description="Filter: username contains (case-insensitive)")] = None,
        nas_ip: Annotated[str | None, Field(description="Filter: sessions on this network device IP")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List active RADIUS sessions from MnT (user, MAC, endpoint IP, NAD IP, PSN, audit session id),
        plus total, posture and profiler session counts. An empty list is normal when no endpoint is
        connected. Drill into one with ise_find_session or ise_endpoint_360."""
        app: IseApp = get_client(ctx)

        async def count(path: str) -> dict[str, Any]:
            try:
                data = await app.mnt_get(path)
            except UpstreamError:
                return {}
            return data if isinstance(data, dict) else {}

        active_raw, posture, profiler = await asyncio.gather(
            app.mnt_get("Session/ActiveList"), count("Session/PostureCount"), count("Session/ProfilerCount")
        )
        active: dict[str, Any] = active_raw if isinstance(active_raw, dict) else {}
        rows = [s for s in as_list(active.get("activeSession")) if isinstance(s, dict)]
        if user:
            rows = [r for r in rows if user.lower() in str(r.get("user_name") or "").lower()]
        if nas_ip:
            rows = [r for r in rows if r.get("nas_ip_address") == nas_ip.strip()]
        extra = {
            "active_sessions": active.get("noOfActiveSession", len(rows)),
            "posture_sessions": posture.get("count"),
            "profiler_sessions": profiler.get("count"),
        }
        return list_result(
            page_of([_clean(r) for r in rows], limit=limit, offset=offset),
            fmt=response_format,
            columns=SESSION_COLUMNS,
            extra={k: v for k, v in extra.items() if v is not None},
        )

    @reg.read(title="Find a session")
    async def ise_find_session(
        ctx: Context,
        mac: Annotated[str | None, Field(description="Endpoint MAC address (any notation)")] = None,
        ip: Annotated[str | None, Field(description="Endpoint (framed) IP address")] = None,
        username: Annotated[str | None, Field(description="Authenticated username")] = None,
        session_id: Annotated[
            str | None, Field(description="Audit session id (from the NAD or a session list)")
        ] = None,
    ) -> ToolResult:
        """Look up the live MnT session for an endpoint by MAC, IP, username or audit session id (give
        one). Returns the session's NAD, port, framed IP, PSN, timestamps, endpoint profile, posture and
        accounting counters, or found=false when there is no active session (the endpoint may have
        disconnected: see ise_get_auth_history for past attempts)."""
        app: IseApp = get_client(ctx)
        session = await find_session(app, mac=mac, ip=ip, username=username, session_id=session_id)
        if session is None:
            return object_result(
                {
                    "found": False,
                    "note": "No active session matches. Use ise_get_auth_history "
                    "with the MAC for recent attempts.",
                }
            )
        return object_result({"found": True, "session": session})

    @reg.read(title="Authentication history for a MAC")
    async def ise_get_auth_history(
        ctx: Context,
        mac: Annotated[str, Field(description="Endpoint MAC address (any notation)")],
        minutes: Annotated[
            int,
            Field(ge=1, le=10080, description="How far back to look, in minutes (default 24 h, max 7 days)"),
        ] = DEFAULT_LOOKBACK_MINUTES,
        max_records: Annotated[int, Field(ge=1, le=200, description="Most records to return")] = 20,
        include_steps: Annotated[
            bool, Field(description="Include decoded execution steps per attempt")
        ] = False,
    ) -> ToolResult:
        """Recent authentication attempts for an endpoint MAC from MnT (newest first): pass/fail,
        username, NAD, method/protocol, identity store, authorization profiles, SGT and the failure
        reason decoded with cause and resolution. For a single diagnosis use ise_why_auth_failed."""
        app: IseApp = get_client(ctx)
        mac_n = normalize_mac(mac)
        records = await auth_history(app, mac_n, minutes, max_records)
        catalog = await app.failure_reasons() if include_steps else None
        rows = [auth_row(r, steps=include_steps, catalog=catalog) for r in records]
        for row in rows:
            if row.get("failure_reason"):
                row["failure"] = await failure_info(app, row.pop("failure_reason"))
        out: dict[str, Any] = {"mac": mac_n, "window_minutes": minutes, "attempts": rows}
        if not rows:
            out["note"] = (
                f"MnT has no authentication records for {mac_n} in the last {minutes} minutes. "
                "Check the MAC, widen the window, or confirm the NAD sends RADIUS to this ISE."
            )
        return object_result(out)

    @reg.read(title="Search failure reasons")
    async def ise_list_failure_reasons(
        ctx: Context,
        query: Annotated[
            str | None,
            Field(description="A failure code (e.g. 22056) or words to search for (e.g. 'certificate')"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """Decode ISE authentication failure reasons from the MnT catalog (~800 entries): code, reason,
        cause and resolution, plus a curated 'likely cause / next step' for common codes. Pass a code
        like 22056 or 12321, or keywords like 'shared secret'."""
        app: IseApp = get_client(ctx)
        reasons = list((await app.failure_reasons()).values())
        if query:
            q = query.strip().lower()
            if q.isdigit():
                reasons = [r for r in reasons if r["code"] == q]
            else:
                terms = q.split()
                reasons = [
                    r
                    for r in reasons
                    if all(t in f"{r.get('reason')} {r.get('cause')}".lower() for t in terms)
                ]
        rows = []
        for r in reasons:
            row = dict(r)
            if r["code"] in FAILURE_HINTS:
                row["likely"] = FAILURE_HINTS[r["code"]]["likely"]
                row["next_step"] = FAILURE_HINTS[r["code"]]["check"]
            rows.append(row)
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["code", "reason", "cause", "resolution"],
        )

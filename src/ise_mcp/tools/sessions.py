"""Live sessions and authentication history (MnT, XML)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import asyncio
from typing import Annotated, Any
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import (
    InvalidRequest,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp
from ise_mcp.knowledge import FAILURE_HINTS, decode_steps
from ise_mcp.tools._common import DEFAULT_LOOKBACK_MINUTES, gather_limited, normalize_mac, parse_ip
from ise_mcp.xmlutil import as_list

SESSION_COLUMNS = ["user", "mac", "ip", "nas_ip", "nad", "psn", "audit_session_id"]


COA_MESSAGE_CODES = {"5417", "5205"}
# Dynamic-authorization (CoA) failure reasons that MnT stores alongside logins.
COA_FAILURE_CODES = {"11213", "11215", "11216", "11217", "11218", "11219"}

# RADIUS reply attributes worth showing; the rest (Class, EAP-Key-Name, MS-MPPE keys, State,
# LicenseTypes ...) are session plumbing or key material.
_REPLY_DROP = {
    "Class",
    "EAP-Key-Name",
    "MS-MPPE-Send-Key",
    "MS-MPPE-Recv-Key",
    "LicenseTypes",
    "State",
    "Message-Authenticator",
    "EAP-Message",
    "cisco-command-code",
}
_AVPAIR_DROP = ("audit-session-id=",)


def is_coa_record(rec: dict[str, Any]) -> bool:
    """MnT AuthStatus also holds CoA/dynamic-authorization results (message code 5417/5205, failure
    reasons 112xx, a CoA packet type in the response); they are not login attempts."""
    if str(rec.get("message_code") or "") in COA_MESSAGE_CODES:
        return True
    if "RadiusPacketType=CoA" in str(rec.get("response") or ""):
        return True
    return str(rec.get("failure_reason") or "").split(" ", 1)[0] in COA_FAILURE_CODES


def compact_reply(text: Any) -> str | None:
    """MnT's response '{A=1; cisco-av-pair=x=y; ... }' without key material and session plumbing."""
    if not isinstance(text, str) or not text.strip():
        return None
    body = text.strip().removeprefix("{").removesuffix("}")
    kept: list[str] = []
    dropped_last = False
    for part in body.split(";"):
        chunk = part.strip()
        if not chunk:
            continue
        key, sep, value = chunk.partition("=")
        if not sep or " " in key:
            # A ';' inside a value (e.g. a Reply-Message): glue it back onto the previous attribute.
            if kept and not dropped_last:
                kept[-1] += f"; {chunk}"
            continue
        dropped_last = key in _REPLY_DROP
        if dropped_last:
            continue
        if key == "cisco-av-pair":
            if value.startswith(_AVPAIR_DROP):
                dropped_last = True
                continue
            kept.append(value)
        else:
            kept.append(f"{key}={value}")
    return "; ".join(kept) or None


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
        "kind": "coa" if is_coa_record(el) else None,
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
        "reply": compact_reply(el.get("response")),
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
    for dup in _ATTR_NOISE:
        attrs.pop(dup, None)
    if attrs:
        session["attributes"] = attrs
    for noisy in _SESSION_NOISE:
        session.pop(noisy, None)
    if "response" in session:
        reply = compact_reply(session.pop("response"))
        if reply:
            session["reply"] = reply
    if str(session.get("acct_status_type") or "").lower() == "stop" and str(
        session.get("acct_acs_timestamp") or ""
    ) >= str(session.get("auth_acs_timestamp") or ""):
        # (A Stop older than the latest authentication is a late Stop from a previous NAD/session.)
        # MnT's by-MAC/user/IP lookup returns the last session even after it ended.
        session["active"] = False
        session["note"] = (
            f"This session ENDED (accounting Stop at {session.get('acct_acs_timestamp')}): the endpoint "
            "is not connected now, and there is no live session to send a CoA to."
        )
        return session
    if not session.get("selected_azn_profiles") and not session.get("authentication_method"):
        # MnT returns the session's latest event, which can be accounting or a CoA without the auth result.
        session["note"] = (
            "MnT's latest event for this session is accounting/CoA, so the authorization result and "
            "matched policy are not in it; see ise_get_auth_history for the last authentication."
        )
    return session


# Session fields that repeat another field or are internal ids/counters of no use to an operator.
_SESSION_NOISE = (
    "execution_steps",
    "orig_calling_station_id",
    "cpmsession_id",
    "auth_acsview_timestamp",
    "acct_acsview_timestamp",
    "auth_id",
    "acct_id",
    "acct_delay_time",
    "acct_authentic",
    "response_time",
)
# other_attr_string keys already shown elsewhere (matched_policy, mac, session id) or internal.
_ATTR_NOISE = (
    "ISEPolicySetName",
    "IdentityPolicyMatchedRule",
    "AuthorizationPolicyMatchedRule",
    "IdentitySelectionMatchedRule",
    "CPMSessionID",
    "AcsSessionID",
    "EndPointMACAddress",
    "OriginalUserName",
    "RADIUS Username",
    "CiscoAVPair",
    "NetworkDeviceProfileId",
    "DTLSSupport",
    "IsThirdPartyDeviceFlow",
    "Framed-MTU",
)

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


async def _nad_names(app: IseApp, ips: set[str], cap: int = 20) -> dict[str, str]:
    """{NAS IP: NAD name} for the NAS IPs on a page: exact-IP lookups in parallel, then one pass over
    the (cached) NAD list for subnets; 'no NAD covers it' when nothing does."""
    import ipaddress

    from ise_mcp.tools.network import all_nads, nad_networks

    async def exact(ip: str) -> tuple[str, str | None]:
        try:
            page = await app.ers_pager.fetch_page(
                app.ers, "/ers/config/networkdevice", {"filter": f"ipaddress.EQ.{ip}"}, limit=2
            )
        except UpstreamError:
            return ip, None
        names = [str(i.get("name")) for i in page.items if isinstance(i, dict) and i.get("name")]
        return ip, (names[0] if names else None)

    wanted = sorted(ips)[:cap]
    out = {ip: name for ip, name in await gather_limited(wanted, exact, limit=4) if name}
    missing = [ip for ip in wanted if ip not in out]
    if missing:
        try:
            nads, _ = await all_nads(app)
        except UpstreamError:
            return out
        for ip in missing:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            best: tuple[int, str] | None = None
            for nad in nads:
                for net in nad_networks(nad):
                    if addr.version == net.version and addr in net and (not best or net.prefixlen > best[0]):
                        best = (net.prefixlen, str(nad.get("name")))
            out[ip] = best[1] if best else "no NAD covers it"
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List active sessions")
    async def ise_list_active_sessions(
        ctx: Context,
        user: Annotated[str | None, Field(description="Filter: username contains (case-insensitive)")] = None,
        nad: Annotated[
            str | None,
            Field(description="Filter: sessions through this NAD: name (or part of it), or a NAS IP"),
        ] = None,
        nas_ip: Annotated[str | None, Field(description="Deprecated: use nad")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List active RADIUS sessions from MnT (user, MAC, endpoint IP, NAS IP and NAD name, PSN,
        audit session id), plus total, posture and profiler session counts. An empty list is normal
        when no endpoint is connected. Drill into one with ise_find_session or ise_endpoint_360."""
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
        flt = None
        nad = nad or nas_ip
        if nad:
            from ise_mcp.tools.activity import nad_filter  # activity imports this module

            flt = await nad_filter(app, nad)
            if flt is not None:
                f = flt
                rows = [r for r in rows if f.matches(r.get("nas_ip_address"))]
        page = page_of(rows, limit=limit, offset=offset)
        names = await _nad_names(
            app, {str(r.get("nas_ip_address")) for r in page.items if r.get("nas_ip_address")}
        )
        rows = [
            {
                "user": r.get("user_name"),
                "mac": r.get("calling_station_id"),
                "ip": r.get("framed_ip_address"),
                "nas_ip": r.get("nas_ip_address"),
                "nad": names.get(str(r.get("nas_ip_address"))),
                "psn": r.get("server"),
                "audit_session_id": r.get("audit_session_id"),
            }
            for r in rows
        ]
        extra = {
            "active_sessions": active.get("noOfActiveSession", len(rows)),
            "posture_sessions": posture.get("count"),
            "profiler_sessions": profiler.get("count"),
            "nad_filter": flt.label if flt else None,
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
        accounting counters, or found=false when MnT has no session. active=false means MnT only has
        the last, ended session (accounting Stop): the endpoint is not connected now (see
        ise_get_auth_history for past attempts)."""
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
        return object_result({"found": True, "active": session.get("active", True), "session": session})

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

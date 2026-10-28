"""MnT depth (I75): per-session RADIUS accounting totals, and deleting a stale session record.

- ise_get_accounting reads `AcctStatus/MACAddress/{mac}/{seconds}`: one element per session with packets and
  bytes in/out and the session time, as the NAD last reported them in an accounting Interim-Update or
  Stop. An unknown MAC answers with an empty `acctStatusList`.
- ise_delete_session sends `DELETE Session/Delete/MACAddress/{mac}`: MnT drops the session record, so a
  session the switch ended without ISE seeing the Stop stops showing as online and stops attracting
  CoA/ANC. A live session gets a CoA (ise_coa_disconnect), not a delete.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

from typing import Annotated, Any
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import (
    Confirm,
    Plan,
    ToolRegistrar,
    compact,
    get_client,
    object_result,
    preview_or_apply,
)
from ise_mcp.client import IseApp
from ise_mcp.tools._common import DEFAULT_LOOKBACK_MINUTES, normalize_mac
from ise_mcp.tools._safety import protect_blockers
from ise_mcp.tools.sessions import find_session
from ise_mcp.tools.writes import fingerprint
from ise_mcp.xmlutil import as_list

ZERO_COUNTERS_NOTE = (
    "Every byte and packet counter is 0: the NAD has not sent accounting with counters yet. IOS-XE "
    "sends them in Interim-Updates only with 'aaa accounting update newinfo periodic <minutes>' (and "
    "in the Stop when the session ends)."
)

_COUNTERS = (
    ("packets_in", "paks_in"),
    ("packets_out", "paks_out"),
    ("bytes_in", "bytes_in"),
    ("bytes_out", "bytes_out"),
)


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def duration(seconds: int | None) -> str | None:
    """95229 -> '1d 2h 27m 9s'."""
    if seconds is None:
        return None
    days, rem = divmod(max(seconds, 0), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = [f"{days}d"] if days else []
    if days or hours:
        parts.append(f"{hours}h")
    if days or hours or minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def accounting_rows(data: Any) -> list[dict[str, Any]]:
    """MnT acctStatusOutputList -> one row per session (counters as ints)."""
    if not isinstance(data, dict):
        return []
    out: list[dict[str, Any]] = []
    for lst in as_list(data.get("acctStatusList")):
        if not isinstance(lst, dict):
            continue
        for el in as_list(lst.get("acctStatusElements")):
            if not isinstance(el, dict):
                continue
            seconds = _int(el.get("session_time"))
            row: dict[str, Any] = {
                "mac": el.get("calling_station_id") or lst.get("macAddress"),
                "audit_session_id": el.get("audit_session_id"),
                "psn": el.get("server"),
            }
            for key, src in _COUNTERS:
                row[key] = _int(el.get(src))
            row["session_time_seconds"] = seconds
            row["session_time"] = duration(seconds)
            out.append({k: v for k, v in row.items() if v is not None})
    return out


def accounting_totals(rows: list[dict[str, Any]]) -> dict[str, int]:
    totals = {key: sum(int(r.get(key) or 0) for r in rows) for key, _ in _COUNTERS}
    totals["session_time_seconds"] = sum(int(r.get("session_time_seconds") or 0) for r in rows)
    return totals


# What identifies the session record a delete targets (see dangerous.SESSION_KEYS), plus whether it ended:
# a session that came back to life between preview and confirm must be previewed again.
_DELETE_KEYS = (
    "audit_session_id",
    "acs_server",
    "nas_ip_address",
    "nas_port_id",
    "acct_status_type",
    "acct_acs_timestamp",
)

SESSION_DETAILS = (
    "user_name",
    "network_device_name",
    "nas_ip_address",
    "nas_port_id",
    "framed_ip_address",
    "acs_server",
    "audit_session_id",
    "auth_acs_timestamp",
    "acct_acs_timestamp",
    "acct_status_type",
)


def stale_reason(session: dict[str, Any], *, nad_confirmed_gone: bool) -> tuple[str | None, list[str]]:
    """(why this session record is stale, blockers). Ended (accounting Stop) records are stale; an
    active-looking record only when the caller checked the NAD has no session for the MAC."""
    if session.get("active") is False:
        return (
            f"MnT recorded an accounting Stop at {session.get('acct_acs_timestamp')}: the session ended, "
            "and the record only makes the endpoint look online.",
            [],
        )
    if nad_confirmed_gone:
        return (
            "MnT shows the session as active (no accounting Stop reached ISE), and you checked the NAD "
            f"({session.get('network_device_name') or session.get('nas_ip_address')}) has no session for "
            "this MAC: the switch dropped it without ISE hearing the Stop.",
            [],
        )
    return None, [
        "MnT shows this session as ACTIVE (no accounting Stop). Deleting a live session's record hides a "
        "connected endpoint: end it with ise_coa_disconnect instead. If the switch really has no session "
        "for this MAC ('show access-session mac <mac>'), call again with nad_confirmed_gone=true."
    ]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="RADIUS accounting totals for a MAC")
    async def ise_get_accounting(
        ctx: Context,
        mac: Annotated[str, Field(description="Endpoint MAC address (any notation)")],
        minutes: Annotated[
            int,
            Field(ge=1, le=10080, description="How far back to look, in minutes (default 24 h, max 7 days)"),
        ] = DEFAULT_LOOKBACK_MINUTES,
    ) -> ToolResult:
        """RADIUS accounting totals for an endpoint MAC from MnT ("how much did this host move?"): packets
        and bytes in/out and session time per session, as the NAD last reported them (accounting
        Interim-Update or Stop), plus the sum over the window. 'in' is from the endpoint (Acct-Input),
        'out' is to it. An empty list means MnT has no accounting for the MAC in the window. Counters
        stay at 0 until the NAD sends interim updates ('aaa accounting update newinfo periodic N' on
        IOS-XE). For the session itself (NAD, port, state) use ise_find_session."""
        app: IseApp = get_client(ctx)
        mac_n = normalize_mac(mac)
        data = await app.mnt_get(f"AcctStatus/MACAddress/{quote(mac_n)}/{minutes * 60}")
        rows = accounting_rows(data)
        out: dict[str, Any] = {"mac": mac_n, "window_minutes": minutes, "sessions": rows}
        if rows:
            totals = accounting_totals(rows)
            totals_out: dict[str, Any] = dict(totals)
            totals_out["session_time"] = duration(totals["session_time_seconds"])
            out["totals"] = totals_out
            if not any(totals[k] for k, _ in _COUNTERS):
                out["note"] = ZERO_COUNTERS_NOTE
        else:
            out["note"] = (
                f"MnT has no accounting for {mac_n} in the last {minutes} minutes: check the MAC, widen the "
                "window, or confirm the NAD sends RADIUS accounting ('aaa accounting network/identity "
                "default start-stop group <ise>') to this ISE."
            )
        # shape=False keeps "sessions": [] for an unknown MAC (rows carry no empties or secrets).
        return object_result(out, shape=False)

    @reg.dangerous(title="Delete a stale MnT session")
    async def ise_delete_session(
        ctx: Context,
        mac: Annotated[str, Field(description="Endpoint MAC address whose stale session record to delete")],
        nad_confirmed_gone: Annotated[
            bool,
            Field(
                description="The session still looks active in MnT, but you checked the NAD has no "
                "session for this MAC (the switch dropped it without sending a Stop). Default false: "
                "only ended sessions are deleted."
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete an endpoint's stale session record from ISE MnT, the classic fix when a session the
        switch already dropped still shows the host online or blocks CoA/ANC. Only ended sessions
        (accounting Stop) are deleted; an active-looking one needs nad_confirmed_gone=true after you
        checked the switch. Protect-listed MACs, users and NADs are refused. Nothing is sent to the
        NAD; the next authentication creates a new session. Preview-first: shows the session and why
        it is stale."""
        app: IseApp = get_client(ctx)
        mac_n = normalize_mac(mac)
        session = await find_session(app, mac=mac_n)
        s = session or {}
        blockers: list[str] = []
        reason: str | None = None
        if session is None:
            blockers.append(f"MnT has no session for {mac_n}; there is nothing to delete")
        else:
            reason, blockers = stale_reason(session, nad_confirmed_gone=nad_confirmed_gone)
        blockers += protect_blockers(
            app.settings,
            mac=mac_n,
            user=str(s.get("user_name") or "") or None,
            nad=str(s.get("network_device_name") or "") or None,
            nad_ips=[str(s.get("nas_ip_address") or s.get("device_ip_address") or "")],
        )
        details = compact({k: s.get(k) for k in SESSION_DETAILS})
        if reason:
            details["why_stale"] = reason
        plan = Plan(
            f"Delete MnT session record for {mac_n}",
            details=details,
            blockers=blockers,
            fingerprint=fingerprint({k: s.get(k) for k in _DELETE_KEYS} | {"active": s.get("active")}),
            side_effects=[
                "ise_find_session and Context Visibility stop showing this session until the endpoint "
                "authenticates again",
                "Nothing is sent to the NAD: a session that is really live keeps working there",
            ],
            blast_radius=1,
        )

        async def apply() -> Any:
            reply = await app.mnt_delete(f"Session/Delete/MACAddress/{quote(mac_n)}")
            after = await find_session(app, mac=mac_n)
            out: dict[str, Any] = {"deleted": after is None, "mac": mac_n}
            if reply not in (None, "", {}):
                out["reply"] = reply
            if after is not None:
                out["note"] = (
                    "MnT still returns a session for this MAC after the delete: the endpoint may have "
                    "re-authenticated already (check auth_acs_timestamp), or this ISE build ignored the "
                    "delete."
                )
                out["session_after"] = compact({k: after.get(k) for k in SESSION_DETAILS})
            return out

        return await preview_or_apply(
            ctx,
            tool="ise_delete_session",
            args={"mac": mac_n, "nad_confirmed_gone": nad_confirmed_gone},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

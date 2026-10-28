"""Bulk CoA by scope (I66): reauthenticate or disconnect every live session on a NAD, network device
group, authorization profile, SGT, policy set, user or SSID, after a policy change.

The candidate set comes from MnT's ActiveList. NAD, NDG and user scopes filter it directly; the others
need each session's detail (Session/MACAddress, plus the newest auth record when the session's latest
event is accounting and carries no authorization result), so they are bounded by DETAIL_CAP. Every
target then gets a detail lookup anyway (NAD name, port, owning PSN, ended-session check) and the
per-session rails of the single-session tools apply: protect lists, and no port bounce/shutdown in
bulk (only a session terminate, so the shared-port guard never has to fire)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from ise_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    compact,
    get_client,
    preview_or_apply,
)
from ise_mcp.client import IseApp
from ise_mcp.tools._common import gather_limited
from ise_mcp.tools._safety import protect_blockers
from ise_mcp.tools.dangerous import DISCONNECT_TYPES, coa_result, q, send_reauth
from ise_mcp.tools.sessions import auth_history, find_session, is_coa_record
from ise_mcp.tools.writes import fingerprint
from ise_mcp.xmlutil import as_list

Scope = Literal["nad", "ndg", "authz_profile", "sgt", "policy_set", "user", "ssid"]
# Scopes the ActiveList can't answer: each candidate needs a detail lookup.
DETAIL_SCOPES = ("authz_profile", "sgt", "policy_set", "ssid")
# Most per-session detail lookups one call makes before refusing (narrow by NAD/NDG first).
DETAIL_CAP = 200
MAX_BULK = 200
# How far back the auth-record fallback looks for a session's authorization result.
AUTH_FALLBACK_MINUTES = 1440


async def active_rows(app: IseApp) -> list[dict[str, Any]]:
    data = await app.mnt_get("Session/ActiveList")
    if not isinstance(data, dict):
        return []
    return [s for s in as_list(data.get("activeSession")) if isinstance(s, dict)]


def _split(value: Any) -> list[str]:
    return [p.strip() for p in str(value or "").split(",") if p.strip()]


def ssid_of(session: dict[str, Any]) -> str | None:
    """The SSID from Called-Station-Id ('AA-BB-CC-DD-EE-FF:SSID'), when the session is wireless."""
    attrs = session.get("attributes") or {}
    called = session.get("called_station_id") or attrs.get("Called-Station-ID")
    if isinstance(called, list):
        called = called[0] if called else None
    text = str(called or "")
    if ":" not in text:
        return None
    # The BSSID may itself use ':' separators: the SSID is what follows the 6th octet.
    m = re.match(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}:(.+)$", text)
    return m.group(1) if m else text.rsplit(":", 1)[1] or None


def _port_key(port: str) -> tuple[str, str]:
    p = port.strip().lower().replace(" ", "")
    m = re.match(r"^([a-z-]*)(.*)$", p)
    return (m.group(1), m.group(2)) if m else ("", p)


def port_matches(want: str, port: Any) -> bool:
    """'Gi1/0/1' matches 'GigabitEthernet1/0/1' (same numbers, one name a prefix of the other)."""
    if not port:
        return False
    (wa, wn), (pa, pn) = _port_key(want), _port_key(str(port))
    return wn == pn and (wa == pa or (bool(wa) and pa.startswith(wa)) or (bool(pa) and wa.startswith(pa)))


def sgt_matches(want: str, sgt: Any) -> bool:
    """'Employees', '4' or '0004' against MnT's cts_security_group ('Employees' or 'Employees (4/0004)')."""
    text = str(sgt or "").strip()
    if not text:
        return False
    w = want.strip().casefold()
    if w in (text.casefold(), text.split("(")[0].strip().casefold()):
        return True
    if w.isdigit() or re.fullmatch(r"0x[0-9a-f]+", w):
        tag = int(w, 16) if w.startswith("0x") else int(w)
        nums = re.findall(r"\b(\d+)\b", text.split("(", 1)[1] if "(" in text else text)
        hexes = re.findall(r"\b([0-9A-Fa-f]{4})\b", text)
        return tag in {int(n) for n in nums} or tag in {int(h, 16) for h in hexes}
    return False


def ndg_matches(want: str, group: str) -> bool:
    """A NAD group 'Location#All Locations#Sydney' matches 'Location#All Locations#Sydney', a parent
    path ('Location#All Locations') or the last name ('Sydney'), case-insensitively."""
    g, w = group.casefold(), want.strip().casefold()
    return g == w or g.startswith(w + "#") or g.rsplit("#", 1)[-1] == w


async def session_facts(app: IseApp, row: dict[str, Any], *, need_authz: bool) -> dict[str, Any]:
    """One ActiveList row plus its session detail: NAD name, port, PSN, authorization result, SGT,
    policy set, SSID and whether it has ended. With need_authz, a session whose latest MnT event is
    accounting (no authorization in it) takes the profile/SGT from its newest successful login."""
    mac = str(row.get("calling_station_id") or "")
    facts: dict[str, Any] = {
        "mac": mac or None,
        "user": row.get("user_name"),
        "nas_ip": row.get("nas_ip_address"),
        "port": row.get("nas_port_id"),
        "psn": row.get("server"),
        "ip": row.get("framed_ip_address"),
        "audit_session_id": row.get("audit_session_id"),
    }
    if not mac:
        facts["error"] = "MnT lists the session without a MAC"
        return facts
    try:
        s = await find_session(app, mac=mac) or {}
    except (UpstreamError, InvalidRequest) as e:
        facts["error"] = f"session lookup failed: {str(e)[:120]}"
        return facts
    if not s:
        facts["active"] = False
        return facts
    facts.update(
        compact(
            {
                "user": s.get("user_name") or facts["user"],
                "nas_ip": s.get("nas_ip_address") or s.get("device_ip_address") or facts["nas_ip"],
                "nad": s.get("network_device_name"),
                "port": s.get("nas_port_id") or facts["port"],
                "psn": s.get("acs_server") or facts["psn"],
                "ip": s.get("framed_ip_address") or facts["ip"],
                "audit_session_id": s.get("audit_session_id") or facts["audit_session_id"],
                "authz_profiles": _split(s.get("selected_azn_profiles")) or None,
                "sgt": s.get("cts_security_group"),
                "policy_set": (s.get("matched_policy") or {}).get("policy_set"),
                "ssid": ssid_of(s),
            }
        )
    )
    facts["active"] = s.get("active") is not False
    if need_authz and facts["active"] and not facts.get("authz_profiles"):
        try:
            history = await auth_history(app, mac, AUTH_FALLBACK_MINUTES, 5)
        except UpstreamError:
            history = []
        for rec in history:
            if is_coa_record(rec) or str(rec.get("passed", "")).lower() != "true":
                continue
            facts["authz_profiles"] = _split(rec.get("selected_azn_profiles")) or None
            facts.setdefault("sgt", rec.get("cts_security_group") or None)
            facts.setdefault("nad", rec.get("network_device_name") or None)
            facts["authz_from"] = f"auth record {rec.get('acs_timestamp')}"
            break
    return {k: v for k, v in facts.items() if v is not None}


def fact_matches(scope: str, value: str, facts: dict[str, Any]) -> bool | None:
    """Does a session (its facts) fall in the scope? None when the facts can't tell."""
    v = value.strip().casefold()
    if scope == "authz_profile":
        profiles = facts.get("authz_profiles")
        return None if not profiles else v in {p.casefold() for p in profiles}
    if scope == "sgt":
        return None if not facts.get("sgt") else sgt_matches(value, facts["sgt"])
    if scope == "policy_set":
        ps = facts.get("policy_set")
        return None if not ps else str(ps).casefold() == v
    if scope == "ssid":
        ssid = facts.get("ssid")
        return None if not ssid else str(ssid).casefold() == v
    if scope == "port":
        return None if not facts.get("port") else port_matches(value, facts["port"])
    raise InvalidRequest(f"Unknown scope {scope!r}")


async def ndg_filter(app: IseApp, value: str) -> tuple[list[Any], list[str]]:
    """Networks and names of the NADs in a network device group (or a child of it)."""
    from ise_mcp.tools.network import all_nads, nad_networks

    nads, _ = await all_nads(app)
    hit = [n for n in nads if any(ndg_matches(value, str(g)) for g in n.get("NetworkDeviceGroupList") or [])]
    nets = [net for n in hit for net in nad_networks(n)]
    return nets, [str(n.get("name")) for n in hit]


async def scope_rows(
    app: IseApp, rows: list[dict[str, Any]], scope: str, value: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """ActiveList rows narrowed by a scope the list itself can answer (nad, ndg, user), and what the
    scope resolved to. Detail scopes pass every row through."""
    import ipaddress

    info: dict[str, Any] = {}
    if scope == "user":
        v = value.strip().casefold()
        return [r for r in rows if str(r.get("user_name") or "").casefold() == v], info
    if scope == "nad":
        from ise_mcp.tools.activity import nad_filter  # activity imports sessions, like this module

        flt = await nad_filter(app, value)
        if flt is None:
            raise InvalidRequest("Give the NAD name or NAS IP in `value`")
        info["nad"] = flt.label
        return [r for r in rows if flt.matches(r.get("nas_ip_address"))], info
    if scope == "ndg":
        nets, names = await ndg_filter(app, value)
        info["nads_in_group"] = names
        if not names:
            return [], info

        def in_group(ip: Any) -> bool:
            try:
                addr = ipaddress.ip_address(str(ip or "").strip())
            except ValueError:
                return False
            return any(addr.version == n.version and addr in n for n in nets)

        return [r for r in rows if in_group(r.get("nas_ip_address"))], info
    return rows, info


async def scoped_sessions(app: IseApp, scope: str, value: str, limit: int) -> dict[str, Any]:
    """The live sessions in scope with their facts: targets, sessions the facts couldn't place
    (undetermined), ended/failed lookups, and too_many when more than `limit` match."""
    rows = await active_rows(app)
    rows, info = await scope_rows(app, rows, scope, value)
    out: dict[str, Any] = {"scope_info": info, "active_list_total": len(rows)}
    need_detail = scope in DETAIL_SCOPES
    if not need_detail and len(rows) > limit:
        out["too_many"] = len(rows)
        out["targets"] = []
        return out
    if need_detail and len(rows) > DETAIL_CAP:
        raise InvalidRequest(
            f"{len(rows)} live sessions would each need a detail lookup to check {scope}={value!r} (cap "
            f"{DETAIL_CAP}). Narrow with scope='nad' or 'ndg', or use ise_list_active_sessions."
        )
    facts = await gather_limited(
        rows,
        lambda r: session_facts(app, r, need_authz=scope in ("authz_profile", "sgt")),
        limit=5,
    )
    targets, undetermined, skipped = [], [], []
    for f in facts:
        if f.get("error"):
            skipped.append({**_row(f), "reason": f["error"]})
            continue
        if f.get("active") is False:
            skipped.append({**_row(f), "reason": "session ended (accounting Stop)"})
            continue
        if need_detail:
            hit = fact_matches(scope, value, f)
            if hit is None:
                undetermined.append(_row(f))
                continue
            if not hit:
                continue
        targets.append(f)
    if len(targets) > limit:
        out["too_many"] = len(targets)
    out.update(targets=targets, undetermined=undetermined, skipped=skipped)
    return out


def _row(f: dict[str, Any]) -> dict[str, Any]:
    keys = ("user", "mac", "nad", "nas_ip", "port", "psn", "authz_profiles", "sgt", "policy_set", "ssid")
    return {k: f[k] for k in keys if f.get(k) not in (None, "", [])}


async def send_one(app: IseApp, f: dict[str, Any], action: str, reauth_type: str) -> dict[str, Any]:
    """One CoA, as the single-session tools send it; a failure is a result row, not an exception."""
    row = {"mac": f.get("mac"), "user": f.get("user"), "nad": f.get("nad") or f.get("nas_ip")}
    try:
        if action == "reauth":
            res = await send_reauth(app, {"acs_server": f.get("psn")}, str(f["mac"]), reauth_type)
        else:
            path = (
                f"CoA/Disconnect/{q(f.get('psn', ''))}/{q(f['mac'])}/{DISCONNECT_TYPES['default']}/"
                f"{q(f.get('nas_ip', ''))}/{q(f.get('ip') or '0.0.0.0')}"
            )
            res = coa_result(await app.mnt_get(path, missing_ok=False))
    except UpstreamError as e:
        failed: dict[str, Any] = compact({**row, "coa_acknowledged": False, "error": str(e)[:200]})
        return failed
    done: dict[str, Any] = compact({**row, **res})
    return done


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Bulk CoA by scope")
    async def ise_coa_bulk(
        ctx: Context,
        scope: Annotated[
            Scope,
            Field(
                description="Which sessions: 'nad' (name or NAS IP), 'ndg' (network device group path or "
                "name, children included), 'authz_profile', 'sgt' (name or tag number), 'policy_set', "
                "'user' (exact username) or 'ssid'"
            ),
        ],
        value: Annotated[str, Field(description="The NAD, group, profile, SGT, policy set, user or SSID")],
        action: Annotated[
            Literal["reauth", "disconnect"],
            Field(
                description="'reauth' (new policy applies, session kept) or 'disconnect' (session "
                "terminate; port bounce and shutdown are never sent in bulk)"
            ),
        ] = "reauth",
        reauth_type: Annotated[
            Literal["default", "last", "rerun"], Field(description="CoA reauth type (action='reauth')")
        ] = "default",
        max: Annotated[
            int,
            Field(ge=1, le=MAX_BULK, description="Refuse when more sessions than this match"),
        ] = 25,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Send a CoA to every live session in a scope (all sessions on a NAD or device group, with an
        authorization profile, SGT or policy set, of a user, or on an SSID), so a policy change (dACL,
        profile, SGT, rule) applies now instead of at each endpoint's next reauthentication.
        Preview-first: lists every session (user, MAC, NAD, port, PSN) and the count as blast radius
        (bounded by MCP_MAX_BLAST_RADIUS and `max`); protected MACs, users or NADs refuse the whole run.
        Ended sessions are left out; sessions whose MnT record doesn't say (profile/SGT/policy set/SSID
        scopes) are listed as undetermined and not touched. Confirm returns one result row per session."""
        app: IseApp = get_client(ctx)
        found = await scoped_sessions(app, scope, value, max)
        targets: list[dict[str, Any]] = found["targets"]
        blockers: list[str] = []
        if found.get("too_many"):
            blockers.append(
                f"{found['too_many']} live sessions match {scope}={value!r}, more than max={max}: narrow "
                f"the scope or raise max (up to {MAX_BULK})"
            )
        elif not targets:
            where = found["scope_info"].get("nads_in_group")
            hint = (
                f" (no NAD is in a device group matching {value!r}; see ise_list_ndgs)"
                if scope == "ndg" and where == []
                else ""
            )
            blockers.append(
                f"No live session matches {scope}={value!r}{hint}; there is nothing to send a CoA for"
            )
        for f in targets:
            blockers += protect_blockers(
                app.settings,
                mac=f.get("mac"),
                user=str(f.get("user") or "") or None,
                nad=str(f.get("nad") or "") or None,
                nad_ips=[str(f.get("nas_ip") or "")],
            )
            if not f.get("psn"):
                blockers.append(f"MnT doesn't say which PSN owns {f.get('mac')}'s session")
            if action == "disconnect" and not f.get("nas_ip"):
                blockers.append(f"MnT has no NAS IP for {f.get('mac')}'s session")
        side_effects = [
            f"{len(targets)} endpoint(s) re-authenticate; brief interruption possible on some devices"
            if action == "reauth"
            else f"{len(targets)} session(s) end; each endpoint must re-authenticate",
        ]
        if found.get("undetermined"):
            side_effects.append(
                f"{len(found['undetermined'])} session(s) are left out: MnT doesn't record their {scope} "
                "(their latest event is accounting and no recent login says). Check them with "
                "ise_find_session / ise_get_auth_history and send ise_coa_reauth singly if needed"
            )
        details = compact(
            {
                "scope": f"{scope}={value}",
                "action": action if action == "disconnect" else f"reauth ({reauth_type})",
                "matched": len(targets),
                **found["scope_info"],
                "sessions": [_row(f) for f in targets[:MAX_BULK]],
                "undetermined": found.get("undetermined") or None,
                "skipped": found.get("skipped") or None,
            }
        )
        plan = Plan(
            f"CoA {action} for {len(targets)} session(s) in {scope} {value}",
            details=details,
            blockers=list(dict.fromkeys(blockers)),
            # The targeted sessions: a session that starts, ends or moves PSN/NAD refuses the confirm.
            fingerprint=fingerprint(
                sorted(
                    tuple(str(f.get(k)) for k in ("mac", "audit_session_id", "psn", "nas_ip"))
                    for f in targets
                )
            ),
            side_effects=side_effects,
            blast_radius=len(targets),
        )

        async def apply() -> Any:
            results = await gather_limited(targets, lambda f: send_one(app, f, action, reauth_type), limit=4)
            acked = sum(1 for r in results if r.get("coa_acknowledged"))
            failed = [r for r in results if not r.get("coa_acknowledged")]
            out: dict[str, Any] = {
                "sent": len(results),
                "acknowledged": acked,
                "not_acknowledged": len(failed),
                "results": results,
            }
            if failed:
                out["note"] = (
                    f"{len(failed)} CoA(s) were not acknowledged (error, CoA off on the NAD, wrong CoA "
                    "port/secret, or the session ended): retry those with ise_coa_reauth / "
                    "ise_coa_disconnect after checking ise_find_session"
                )
            return out

        return await preview_or_apply(
            ctx,
            tool="ise_coa_bulk",
            args={
                "scope": scope,
                "value": value,
                "action": action,
                "reauth_type": reauth_type,
                "max": max,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

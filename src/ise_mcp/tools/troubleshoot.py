"""Task tools that combine the three surfaces: why did an auth fail, everything about an endpoint."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import asyncio
from typing import Annotated, Any
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import (
    InvalidRequest,
    NotFound,
    ToolRegistrar,
    UpstreamError,
    get_client,
    object_result,
)
from ise_mcp.client import IseApp
from ise_mcp.knowledge import decode_steps
from ise_mcp.tools._common import (
    DEFAULT_LOOKBACK_MINUTES,
    anc_assignments,
    ers_name_map,
    normalize_mac,
)
from ise_mcp.tools.ad import ad_diagnosis
from ise_mcp.tools.endpoints import endpoint_row, profile_name
from ise_mcp.tools.identity import user_row
from ise_mcp.tools.network import find_nads_for_ip, nad_summary
from ise_mcp.tools.policy import rules_using_profile
from ise_mcp.tools.sessions import auth_history, auth_row, failure_info, find_session

USER_STORE_CODES = {"22056", "22040", "22041", "24206", "22063"}
LOCAL_STORES = {"", "internal users", "internal endpoints", "guest users", "none"}


def involves_ad(code: str, identity_store: Any) -> bool:
    """Whether a failure needs the AD checks: an AD failure code (244xx/247xx, 25048/25058, 91020),
    a 'not found' that may have searched AD, or a login whose identity store isn't a local one."""
    if code.startswith(("244", "247")) or code in ("25048", "25058", "91020", "22056"):
        return True
    return str(identity_store or "").strip().lower() not in LOCAL_STORES


async def _safe(coro: Any) -> Any:
    """Run a sub-lookup; turn errors into {"error": ...} so one broken surface doesn't sink the tool."""
    try:
        return await coro
    except NotFound:
        return None
    except UpstreamError as e:
        return {"error": str(e)[:300]}


async def internal_user_facts(app: IseApp, username: str) -> dict[str, Any]:
    hit = await app.ers_find("internaluser", username)
    if hit is None:
        return {"exists_in_internal_users": False}
    user = await app.ers_get("internaluser", str(hit["id"]))
    groups = await ers_name_map(app, "identitygroup")
    return {"exists_in_internal_users": True, **user_row(user, groups)}


async def anc_for(app: IseApp, mac: str) -> str | None:
    for e in await anc_assignments(app, mac):
        return str(e.get("policyName") or "unknown")
    return None


async def get_endpoint(app: IseApp, mac: str) -> dict[str, Any] | None:
    try:
        data = await app.openapi.get(f"/api/v1/endpoint/{quote(mac)}")
    except NotFound:
        return None
    return data if isinstance(data, dict) else None


async def is_rejected(app: IseApp, mac: str) -> bool:
    data = await app.openapi.get("/api/v1/endpoint/getRejected")
    items = data.get("response", data) if isinstance(data, dict) else data
    return any(mac.upper() in str(i).upper() for i in items or [])


def compact_steps(steps: list[str]) -> list[str]:
    """Execution steps with a description only (bare codes say nothing), adjacent repeats collapsed."""
    out: list[str] = []
    for step in steps:
        if " " not in str(step).strip():
            continue
        if out and out[-1] == step:
            continue
        out.append(step)
    return out


def coa_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Failed CoA records: count, latest, and what they mean (they are not login failures)."""
    latest = rows[0]
    reason = latest.get("failure_reason") or latest.get("reply") or ""
    if latest.get("failure_reason") and not str(latest["failure_reason"]).startswith("11215"):
        meaning = "ISE reports this CoA failure reason; it concerns the CoA, not the login."
    elif "CoANAK" in str(latest.get("reply") or ""):
        meaning = (
            "The switch answered the CoA with a NAK: usually the session no longer exists on the switch "
            "(the endpoint left or re-authenticated), or the switch refuses that CoA type."
        )
    else:
        meaning = (
            "ISE got no answer to the CoA: check 'aaa server radius dynamic-author' (client = this PSN, "
            "same key) on the switch, the NAD's CoA port in ISE (default 1700), and UDP 1700 in between."
        )
    return {"count": len(rows), "latest": latest.get("time"), "reason": reason, "meaning": meaning}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Why did authentication fail?")
    async def ise_why_auth_failed(
        ctx: Context,
        mac: Annotated[
            str | None, Field(description="Endpoint MAC address (any notation); preferred")
        ] = None,
        username: Annotated[
            str | None,
            Field(description="Username; used to find the MAC via a live session, and to check the user"),
        ] = None,
        minutes: Annotated[
            int, Field(ge=1, le=10080, description="How far back to look, in minutes (default 24 h)")
        ] = DEFAULT_LOOKBACK_MINUTES,
    ) -> ToolResult:
        """Diagnose an endpoint's authentication in one call. Pulls its recent MnT auth attempts and
        explains the latest failure: decoded failure reason with cause, resolution and a likely fix, the
        execution steps, the network device it came through (or that none matches the NAS IP), the
        internal user's state when the user store is involved, the authorization profile and the rules
        that use it, and whether the latest attempt has since passed. Give a MAC (best) or a username
        with a live session."""
        app: IseApp = get_client(ctx)
        if not mac and not username:
            raise InvalidRequest("Give a MAC address (preferred) or a username")
        out: dict[str, Any] = {}
        if not mac and username:
            session = await _safe(find_session(app, username=username))
            if isinstance(session, dict) and session.get("calling_station_id"):
                mac = str(session["calling_station_id"])
                which = "last (ended)" if session.get("active") is False else "live"
                out["note"] = f"MAC {mac} taken from {username}'s {which} session"
            else:
                facts = await _safe(internal_user_facts(app, username))
                return object_result(
                    {
                        "username": username,
                        "verdict": "No live session for this user, and MnT can only search history by "
                        "MAC. Give the endpoint MAC (from the switch/WLC, or ise_list_endpoints) for the "
                        "full diagnosis.",
                        "internal_user": facts,
                    }
                )
        assert mac is not None
        mac_n = normalize_mac(mac)
        out["mac"] = mac_n
        records = await auth_history(app, mac_n, minutes, 50)
        if not records:
            endpoint = await _safe(get_endpoint(app, mac_n))
            out["verdict"] = (
                f"ISE has no authentication record for {mac_n} in the last {minutes} minutes: the RADIUS "
                "request never reached ISE (wrong RADIUS server/port on the switch or WLC, ACL/firewall, "
                "or the NAD sends to another PSN), or the MAC is wrong."
            )
            out["endpoint_known_to_ise"] = bool(endpoint and not endpoint.get("error"))
            out["next_steps"] = [
                "Check the NAD exists in ISE for the switch's RADIUS source IP (ise_get_nad <ip>): ISE "
                "silently drops RADIUS from unknown devices (11007), which the switch logs as 'RADIUS "
                "server not responding' / 'AAA Server Down', and MnT keeps no record for the MAC",
                "Check the shared secret matches on both sides (a mismatch is also dropped: 11036)",
                "Check the switch/WLC RADIUS server config points at this ISE (1812/1813) and that the "
                "port actually tries MAB/802.1X (an idle MAB client must send traffic first)",
                "Widen `minutes` if the attempt was earlier",
            ]
            return object_result(out)

        all_rows = [auth_row(r) for r in records]
        # CoA / dynamic-authorization results live in the same MnT history but aren't logins.
        login_idx = [i for i, r in enumerate(all_rows) if r.get("kind") != "coa"]
        coa_rows = [r for r in all_rows if r.get("kind") == "coa"]
        records = [records[i] for i in login_idx]
        rows = [all_rows[i] for i in login_idx]
        fails = [i for i, r in enumerate(rows) if r["result"] == "FAIL"]
        passes = [i for i, r in enumerate(rows) if r["result"] == "PASS"]
        out["attempts_in_window"] = {"logins": len(rows), "failed": len(fails), "passed": len(passes)}
        coa_failed = [r for r in coa_rows if r["result"] == "FAIL"]
        if coa_rows:
            out["attempts_in_window"]["coa_records"] = len(coa_rows)
        if coa_failed:
            out["coa_failures"] = coa_summary(coa_failed)
        if not rows:
            out["verdict"] = (
                f"No login attempt for {mac_n} in the last {minutes} minutes, only "
                f"{len(coa_rows)} CoA (change-of-authorization) record(s): ISE tried to reauthenticate or "
                "disconnect an older session. The endpoint has not authenticated since: check that it "
                "is connected and that the switch port runs MAB/802.1X."
            )
            return object_result(out)
        latest = rows[0]
        if not fails:
            out["verdict"] = (
                f"No login failures: the latest login PASSED at {latest.get('time')} "
                f"(authorization profile {latest.get('authz_profiles')})."
            )
            if coa_failed:
                out["verdict"] += " Only CoA requests failed (see coa_failures); they don't block login."
            out["latest_attempt"] = latest
            session = await _safe(find_session(app, mac=mac_n))
            if isinstance(session, dict) and session.get("matched_policy"):
                out["matched_policy"] = session["matched_policy"]
            elif latest.get("authz_profiles"):
                out["rules_using_profile"] = await _safe(
                    rules_using_profile(app, str(latest["authz_profiles"]).split(",")[0].strip())
                )
            if session is None or (isinstance(session, dict) and session.get("active") is False):
                out["session"] = "no active session now (the endpoint disconnected or the session ended)"
            return object_result(out)

        idx = fails[0]
        failed = rows[idx]
        info = await failure_info(app, failed.get("failure_reason"))
        code = (info or {}).get("code", "")
        if idx == 0:
            out["verdict"] = (
                f"The latest login FAILED at {failed.get('time')}: {failed.get('failure_reason')}."
            )
        else:
            out["verdict"] = (
                f"The latest login PASSED at {latest.get('time')}; the most recent failure was at "
                f"{failed.get('time')}: {failed.get('failure_reason')}."
            )
        failed.pop("failure_reason", None)
        out["failure"] = info
        out["failed_attempt"] = failed
        if idx == 0:
            out["steps"] = compact_steps(
                decode_steps(records[idx].get("execution_steps"), await app.failure_reasons())
            )
        else:
            out["steps"] = "omitted (the latest login passed); ise_get_auth_history include_steps=true"

        checks: dict[str, Any] = {}
        nas_ip = failed.get("nas_ip")
        if nas_ip:
            nads = await _safe(find_nads_for_ip(app, str(nas_ip)))
            if isinstance(nads, list):
                checks["network_device"] = (
                    nad_summary(nads[0]) if nads else f"No NAD covers {nas_ip}: add one with ise_create_nad"
                )
            else:
                checks["network_device"] = nads
        user = failed.get("user")
        if (
            user
            and user != "INVALID"
            and (code in USER_STORE_CODES or failed.get("identity_store") == "Internal Users")
        ):
            checks["internal_user"] = await _safe(internal_user_facts(app, str(user)))
        elif user == "INVALID" and username:
            checks["internal_user"] = await _safe(internal_user_facts(app, username))
        if involves_ad(str(code), failed.get("identity_store")):
            # MnT records an unknown subject as user 'INVALID': look up the username given instead.
            ad_name = username if user in (None, "", "INVALID") else user
            ad = await _safe(ad_diagnosis(app, failed.get("identity_store"), ad_name))
            if isinstance(ad, dict) and not ad_name:
                ad["user"] = "MnT records the user as INVALID; pass username=... to look them up in AD"
            if ad is not None:
                checks["active_directory"] = ad
                if code == "15039" and isinstance(ad, dict):
                    usable = [
                        g
                        for jp in ad.get("join_points") or []
                        if isinstance(jp, dict)
                        for g in (jp.get("user") or {}).get("groups_usable_in_policy") or []
                    ]
                    checks["ad_groups_hint"] = (
                        f"The user authenticated against AD; their groups usable in policy are {usable}. "
                        "No authorization rule above the deny matched them: add a rule on "
                        "'<join point>:ExternalGroups equals <group>' or check the existing ones "
                        "(ise_policy_explain)."
                        if usable
                        else "The user authenticated against AD but none of their groups are added to "
                        "the join point, so no ExternalGroups rule can match (ise_add_ad_groups)."
                    )
        if failed.get("authz_profiles"):
            checks["rules_using_profile"] = await _safe(
                rules_using_profile(app, str(failed["authz_profiles"]).split(",")[0].strip())
            )
        if checks:
            out["checks"] = checks
        if idx != 0:
            out["latest_attempt"] = latest
        return object_result(out)

    @reg.read(title="Endpoint 360")
    async def ise_endpoint_360(
        ctx: Context,
        mac: Annotated[str, Field(description="Endpoint MAC address (any notation)")],
    ) -> ToolResult:
        """Everything ISE knows about one endpoint, in one call: the endpoint record (identity group,
        static assignment, profile, IP, custom/MDM attributes), its live session (NAD, port, user, PSN),
        the last authentication attempts with decoded failures, any ANC policy applied, and whether ISE
        has it on the rejected-endpoints list. Start here
        for 'what is this device and what happened to it?'."""
        app: IseApp = get_client(ctx)
        mac_n = normalize_mac(mac)
        endpoint, session, history, anc, groups, rejected = await asyncio.gather(
            _safe(get_endpoint(app, mac_n)),
            _safe(find_session(app, mac=mac_n)),
            _safe(auth_history(app, mac_n, DEFAULT_LOOKBACK_MINUTES, 5)),
            _safe(anc_for(app, mac_n)),
            _safe(ers_name_map(app, "endpointgroup")),
            _safe(is_rejected(app, mac_n)),
        )
        out: dict[str, Any] = {"mac": mac_n}
        if isinstance(endpoint, dict) and "error" not in endpoint:
            row = endpoint_row(endpoint, groups if isinstance(groups, dict) and "error" not in groups else {})
            pid = row.pop("profile_id", None)
            row["profile"] = (
                await _safe(profile_name(app, pid)) if pid else "not profiled (no profiler match yet)"
            )
            out["endpoint"] = row
        else:
            out["endpoint"] = endpoint or "not in the ISE endpoint database"
        out["session"] = session or "no active session"
        if isinstance(history, list):
            attempts = [auth_row(r) for r in history]
            for a in attempts:
                if a.get("failure_reason"):
                    a["failure"] = await _safe(failure_info(app, a.pop("failure_reason")))
            out["recent_auths"] = attempts or "none in the last 24 hours"
        else:
            out["recent_auths"] = history
        out["anc_policy"] = anc or "none"
        if rejected is True:
            out["rejected"] = (
                "ISE lists this endpoint as rejected (Context Visibility > Rejected Endpoints); release it "
                "with ise_release_rejected_endpoint"
            )
        return object_result(out)

"""Task tools that combine the three surfaces: why did an auth fail, everything about an endpoint."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import asyncio
from typing import Annotated, Any
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
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
from ise_mcp.tools.endpoints import endpoint_row, profile_name
from ise_mcp.tools.identity import user_row
from ise_mcp.tools.network import find_nads_for_ip, nad_summary
from ise_mcp.tools.policy import rules_using_profile
from ise_mcp.tools.sessions import auth_history, auth_row, failure_info, find_session

USER_STORE_CODES = {"22056", "22040", "22041", "24206", "22063"}


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
                out["note"] = f"MAC {mac} taken from {username}'s live session"
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
                "Check the switch/WLC RADIUS server config points at this ISE (1812/1813)",
                "Check the NAD exists in ISE for the RADIUS source IP (ise_get_nad <ip>)",
                "Widen `minutes` if the attempt was earlier",
            ]
            return object_result(out)

        rows = [auth_row(r) for r in records]
        fails = [i for i, r in enumerate(rows) if r["result"] == "FAIL"]
        passes = [i for i, r in enumerate(rows) if r["result"] == "PASS"]
        out["attempts_in_window"] = {"total": len(rows), "failed": len(fails), "passed": len(passes)}
        latest = rows[0]
        if not fails:
            out["verdict"] = (
                f"No failures: the latest attempt PASSED at {latest.get('time')} "
                f"(authorization profile {latest.get('authz_profiles')})."
            )
            out["latest_attempt"] = latest
            session = await _safe(find_session(app, mac=mac_n))
            if isinstance(session, dict) and session.get("matched_policy"):
                out["matched_policy"] = session["matched_policy"]
            elif latest.get("authz_profiles"):
                out["rules_using_profile"] = await _safe(
                    rules_using_profile(app, str(latest["authz_profiles"]).split(",")[0].strip())
                )
            return object_result(out)

        idx = fails[0]
        failed = rows[idx]
        info = await failure_info(app, failed.get("failure_reason"))
        code = (info or {}).get("code", "")
        if idx == 0:
            out["verdict"] = (
                f"The latest attempt FAILED at {failed.get('time')}: {failed.get('failure_reason')}."
            )
        else:
            out["verdict"] = (
                f"The latest attempt PASSED at {latest.get('time')}; the most recent failure was at "
                f"{failed.get('time')}: {failed.get('failure_reason')}."
            )
        failed.pop("failure_reason", None)
        out["failure"] = info
        out["failed_attempt"] = failed
        out["steps"] = decode_steps(records[idx].get("execution_steps"), await app.failure_reasons())

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
        the last authentication attempts with decoded failures, and any ANC policy applied. Start here
        for 'what is this device and what happened to it?'."""
        app: IseApp = get_client(ctx)
        mac_n = normalize_mac(mac)
        endpoint, session, history, anc, groups = await asyncio.gather(
            _safe(get_endpoint(app, mac_n)),
            _safe(find_session(app, mac=mac_n)),
            _safe(auth_history(app, mac_n, DEFAULT_LOOKBACK_MINUTES, 5)),
            _safe(anc_for(app, mac_n)),
            _safe(ers_name_map(app, "endpointgroup")),
        )
        out: dict[str, Any] = {"mac": mac_n}
        if isinstance(endpoint, dict) and "error" not in endpoint:
            row = endpoint_row(endpoint, groups if isinstance(groups, dict) and "error" not in groups else {})
            row["profile"] = await _safe(profile_name(app, row.pop("profile_id", None)))
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
        return object_result(out)

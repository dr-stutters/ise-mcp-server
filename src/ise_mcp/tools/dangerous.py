"""Dangerous-tier tools (MCP_ENABLE_WRITES + MCP_ENABLE_DANGEROUS): CoA, ANC, and deletes of network
devices, policy and certificates. All are preview-first and state the blast radius."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    compact,
    get_client,
    preview_or_apply,
)

from ise_mcp.client import IseApp
from ise_mcp.tools._common import anc_assignments, normalize_mac, openapi_all
from ise_mcp.tools._safety import PORT_ACTIONS, port_coa_guard, protect_blockers
from ise_mcp.tools.network import nad_summary, resolve_nad
from ise_mcp.tools.policy import PolicyKind, list_policy_sets, policy_set_rules, resolve_policy_set
from ise_mcp.tools.sessions import find_session
from ise_mcp.tools.writes import fingerprint

REAUTH_TYPES = {"default": 0, "last": 1, "rerun": 2}
DISCONNECT_TYPES = {"default": 0, "port_bounce": 1, "port_shutdown": 2}
RULE_SECTIONS = {
    "authorization": "authorization",
    "authentication": "authentication",
    "exception": "exception",
}


def coa_result(data: Any) -> dict[str, Any]:
    ok = isinstance(data, dict) and str(data.get("results", "")).lower() == "true"
    out: dict[str, Any] = {"coa_acknowledged": ok}
    if not ok:
        out["note"] = (
            "ISE sent the CoA but the network device did not acknowledge it (CoA not enabled on the "
            "device, wrong CoA port/secret, or the session already ended)."
        )
    return out


# What identifies the session a CoA targets. The framed IP is left out: it often appears a moment after
# the session starts (DHCP), which would refuse a confirm for the same session.
SESSION_KEYS = ("audit_session_id", "acs_server", "nas_ip_address", "nas_port_id")


def session_fingerprint(session: dict[str, Any] | None) -> str:
    return fingerprint({k: (session or {}).get(k) for k in SESSION_KEYS})


def q(value: Any) -> str:
    return quote(str(value), safe="")


async def session_or_blocker(app: IseApp, mac: str) -> tuple[dict[str, Any] | None, list[str]]:
    session = await find_session(app, mac=mac)
    if not session:
        return None, [f"{mac} has no active session; there is nothing to send a CoA for"]
    if session.get("active") is False:
        return session, [
            f"{mac}'s last session has ended (accounting Stop); there is nothing to send a CoA for"
        ]
    if not session.get("acs_server"):
        return session, ["MnT doesn't say which PSN owns this session; can't route the CoA"]
    return session, []


async def anc_rules(app: IseApp, policy: str) -> list[str]:
    """'PolicySet / Rule' for network-access authorization rules/exceptions whose condition mentions
    Session:ANCPolicy with this policy name (library conditions are matched by text only)."""
    out: list[str] = []
    for ps in await list_policy_sets(app, "network-access"):
        rules = await policy_set_rules(app, "network-access", str(ps["id"]))
        for section in ("authorization", "local_exceptions"):
            for r in rules[section]:
                cond = str(r.get("condition") or "")
                if re.search(rf"ANCPolicy (equals|in|contains) {re.escape(policy)}(\b|\)|$)", cond, re.I):
                    out.append(f"{ps.get('name')} / {r.get('name')}")
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="CoA: reauthenticate a session")
    async def ise_coa_reauth(
        ctx: Context,
        mac: Annotated[str, Field(description="Endpoint MAC address with an active session")],
        reauth_type: Annotated[
            Literal["default", "last", "rerun"],
            Field(description="'default', 'last' (reuse last method) or 'rerun' (rerun the full auth)"),
        ] = "default",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Send a RADIUS Change of Authorization (reauthenticate) for an endpoint's live session, so new
        policy (group, profile, ANC) applies now instead of at the next reauth. Briefly interrupts the
        endpoint on some devices. Preview-first: shows the session, NAD and PSN it goes through."""
        app: IseApp = get_client(ctx)
        mac_n = normalize_mac(mac)
        session, blockers = await session_or_blocker(app, mac_n)
        psn = str((session or {}).get("acs_server", ""))
        details = {
            k: (session or {}).get(k)
            for k in (
                "user_name",
                "nas_ip_address",
                "nas_port_id",
                "network_device_name",
                "acs_server",
                "framed_ip_address",
            )
        }
        s0 = session or {}
        blockers += protect_blockers(
            app.settings,
            mac=mac_n,
            user=str(s0.get("user_name") or "") or None,
            nad=str(s0.get("network_device_name") or "") or None,
            nad_ips=[str(s0.get("nas_ip_address") or s0.get("device_ip_address") or "")],
        )
        plan = Plan(
            f"CoA reauth ({reauth_type}) for {mac_n}",
            details=compact(details),
            blockers=blockers,
            fingerprint=session_fingerprint(session),
            side_effects=["The endpoint re-authenticates; brief interruption possible"],
            blast_radius=1,
        )

        async def apply() -> Any:
            data = await app.mnt_get(
                f"CoA/Reauth/{q(psn)}/{q(mac_n)}/{REAUTH_TYPES[reauth_type]}", missing_ok=False
            )
            return coa_result(data)

        return await preview_or_apply(
            ctx,
            tool="ise_coa_reauth",
            args={"mac": mac_n, "reauth_type": reauth_type},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="CoA: disconnect a session")
    async def ise_coa_disconnect(
        ctx: Context,
        mac: Annotated[str, Field(description="Endpoint MAC address with an active session")],
        disconnect_type: Annotated[
            Literal["default", "port_bounce", "port_shutdown"],
            Field(description="'default' (session terminate), 'port_bounce' or 'port_shutdown' (stays down)"),
        ] = "default",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Send a RADIUS CoA disconnect for an endpoint's live session: terminate it, bounce the switch
        port, or shut the port down (stays down until an admin re-enables it). Disrupts the endpoint.
        Preview-first: shows the session, NAD, port and PSN."""
        app: IseApp = get_client(ctx)
        mac_n = normalize_mac(mac)
        session, blockers = await session_or_blocker(app, mac_n)
        s = session or {}
        nas_ip = str(s.get("nas_ip_address") or s.get("device_ip_address") or "")
        endpoint_ip = str(s.get("framed_ip_address") or "0.0.0.0")
        details = {
            k: s.get(k)
            for k in (
                "user_name",
                "nas_ip_address",
                "nas_port_id",
                "network_device_name",
                "acs_server",
                "framed_ip_address",
            )
        }
        side = {
            "default": "The session ends; the endpoint must re-authenticate",
            "port_bounce": "The switch port goes down and up; everything on it reconnects",
            "port_shutdown": "The switch port is shut down and STAYS down until re-enabled on the switch",
        }
        side_effects = [side[disconnect_type]]
        blockers += protect_blockers(
            app.settings,
            mac=mac_n,
            user=str(s.get("user_name") or "") or None,
            nad=str(s.get("network_device_name") or "") or None,
            nad_ips=[nas_ip],
        )
        if not nas_ip and session:
            blockers.append("MnT has no NAS IP for this session")
        # port_bounce / port_shutdown take down every endpoint on the switch port (I18): count them,
        # report the true blast radius, and block a shared port (uplink/trunk) unless opted in.
        blast = 1
        if disconnect_type in ("port_bounce", "port_shutdown"):
            blast, port_blockers, port_side = await port_coa_guard(app, session, f"A {disconnect_type}")
            blockers += port_blockers
            side_effects += port_side
        plan = Plan(
            f"CoA disconnect ({disconnect_type}) for {mac_n}",
            details=compact(details),
            blockers=blockers,
            fingerprint=session_fingerprint(session),
            side_effects=side_effects,
            blast_radius=blast,
        )

        async def apply() -> Any:
            path = (
                f"CoA/Disconnect/{q(s.get('acs_server', ''))}/{q(mac_n)}/"
                f"{DISCONNECT_TYPES[disconnect_type]}/{q(nas_ip)}/{q(endpoint_ip)}"
            )
            return coa_result(await app.mnt_get(path, missing_ok=False))

        return await preview_or_apply(
            ctx,
            tool="ise_coa_disconnect",
            args={"mac": mac_n, "disconnect_type": disconnect_type},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Apply ANC policy to an endpoint")
    async def ise_apply_anc(
        ctx: Context,
        mac: Annotated[str, Field(description="Endpoint MAC address")],
        policy: Annotated[str, Field(description="ANC policy name (see ise_list_anc_policies)")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Put an Adaptive Network Control policy on an endpoint (quarantine, port bounce, shutdown or
        reauthenticate, depending on the policy's actions). ISE issues the CoA itself. Preview-first;
        undo with ise_clear_anc."""
        app: IseApp = get_client(ctx)
        mac_n = normalize_mac(mac)
        hit = await app.ers_find("ancpolicy", policy)
        if hit is None:
            raise NotFound(f"No ANC policy {policy!r}; see ise_list_anc_policies.", 404)
        anc = await app.ers_get("ancpolicy", str(hit["id"]))
        session = await find_session(app, mac=mac_n)
        warnings: list[str] = []
        rules: list[str] = []
        if "QUARANTINE" in (anc.get("actions") or []):
            rules = await anc_rules(app, str(anc.get("name") or hit["name"]))
            if not rules:
                warnings.append(
                    "No network-access authorization rule matches Session:ANCPolicy for this policy, so "
                    "QUARANTINE changes nothing: add one first (ise_create_authz_rule with condition "
                    f"'Session:ANCPolicy equals {anc.get('name') or hit['name']}')"
                )
        sa = session or {}
        blockers = protect_blockers(
            app.settings,
            mac=mac_n,
            user=str(sa.get("user_name") or "") or None,
            nad=str(sa.get("network_device_name") or "") or None,
            nad_ips=[str(sa.get("nas_ip_address") or sa.get("device_ip_address") or "")],
        )
        # An ANC policy whose action bounces/shuts the port takes down the whole port, like a CoA
        # port_bounce: apply the same shared-port rail (I18).
        blast = 1
        extra_side: list[str] = []
        actions = [str(a) for a in anc.get("actions") or []]
        if any(p in a.upper() for a in actions for p in PORT_ACTIONS) and session:
            blast, port_blockers, extra_side = await port_coa_guard(app, session, f"ANC policy {policy}")
            blockers += port_blockers
        plan = Plan(
            f"Apply ANC policy {policy} to {mac_n}",
            details={
                "actions": anc.get("actions"),
                "authz_rules_matching_it": rules or None,
                "live_session": bool(session) and sa.get("active") is not False,
                "nad": sa.get("network_device_name"),
            },
            side_effects=[
                f"Actions: {', '.join(actions)}",
                "ISE sends a CoA to the live session itself, so the new authorization applies at once"
                if session and session.get("active") is not False
                else "No live session: the policy applies when the endpoint next authenticates",
                "Verify after a few seconds with ise_find_session: matched_policy.authorization_rule should "
                "be the ANC rule above (an idle MAB endpoint re-authenticates only when it sends traffic)",
                *extra_side,
                *warnings,
            ],
            blockers=blockers,
            # Only the policy: the session may legitimately churn (reauth) between preview and confirm.
            fingerprint=fingerprint(anc),
            blast_radius=blast,
        )
        body = {
            "OperationAdditionalData": {
                "additionalData": [
                    {"name": "macAddress", "value": mac_n},
                    {"name": "policyName", "value": str(anc.get("name") or hit["name"])},
                ]
            }
        }
        return await preview_or_apply(
            ctx,
            tool="ise_apply_anc",
            args={"mac": mac_n, "policy": policy},
            confirm=confirm,
            plan=plan,
            apply=lambda: app.ers_request("PUT", "/ers/config/ancendpoint/apply", json=body),
        )

    @reg.dangerous(title="Clear ANC policy from an endpoint")
    async def ise_clear_anc(
        ctx: Context,
        mac: Annotated[str, Field(description="Endpoint MAC address")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Remove the ANC policy from an endpoint (release it from quarantine). ISE re-authorizes the
        session. Preview-first; blocked if no ANC policy is applied."""
        app: IseApp = get_client(ctx)
        mac_n = normalize_mac(mac)
        current = await anc_assignments(app, mac_n)
        blockers = [] if current else [f"{mac_n} has no ANC policy applied"]
        blockers += protect_blockers(app.settings, mac=mac_n)
        plan = Plan(
            f"Clear ANC from {mac_n}",
            details={"applied": [c.get("policyName") for c in current]},
            blockers=blockers,
            fingerprint=fingerprint(current),
            side_effects=[
                "ISE ends the live session (CoA); the endpoint re-authenticates with normal policy. An idle "
                "MAB endpoint only re-authenticates when it next sends traffic",
                "Verify with ise_find_session: the authorization rule should no longer be the ANC rule",
            ],
            blast_radius=1,
        )
        body = {"OperationAdditionalData": {"additionalData": [{"name": "macAddress", "value": mac_n}]}}
        return await preview_or_apply(
            ctx,
            tool="ise_clear_anc",
            args={"mac": mac_n},
            confirm=confirm,
            plan=plan,
            apply=lambda: app.ers_request("PUT", "/ers/config/ancendpoint/clear", json=body),
        )

    @reg.dangerous(title="Delete network device")
    async def ise_delete_nad(
        ctx: Context,
        device: Annotated[str, Field(description="NAD name, id or IP")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a network device. ISE then rejects all RADIUS/TACACS+ from its IPs (11007), so every
        user and endpoint behind it loses access at the next authentication. Preview-first."""
        app: IseApp = get_client(ctx)
        current = await resolve_nad(app, device)
        nad_ips = [
            str(i.get("ipaddress"))
            for i in current.get("NetworkDeviceIPList") or []
            if isinstance(i, dict) and i.get("ipaddress")
        ]
        plan = Plan(
            f"Delete network device {current.get('name')}",
            details=nad_summary(current),
            fingerprint=fingerprint(current),
            blockers=protect_blockers(app.settings, nad=str(current.get("name") or ""), nad_ips=nad_ips),
            side_effects=["All RADIUS/TACACS+ from this device's IPs is rejected (11007) from now on"],
        )

        async def apply() -> Any:
            try:
                return await app.ers_request("DELETE", f"/ers/config/networkdevice/{q(current['id'])}")
            finally:
                app.__dict__.pop("_nad_cache", None)

        return await preview_or_apply(
            ctx, tool="ise_delete_nad", args={"device": device}, confirm=confirm, plan=plan, apply=apply
        )

    @reg.dangerous(title="Delete a policy rule")
    async def ise_delete_policy_rule(
        ctx: Context,
        policy_set: Annotated[str, Field(description="Policy set name or id")],
        rule: Annotated[str, Field(description="Rule name or id (see ise_get_policy_set)")],
        section: Annotated[
            Literal["authorization", "authentication", "exception"], Field(description="Which rule table")
        ] = "authorization",
        kind: PolicyKind = "network-access",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete one authentication/authorization rule or local exception from a policy set. Traffic
        that matched it falls through to the next rule (often the default), which can grant or deny
        more than intended. Default rules can't be deleted. Preview-first."""
        app: IseApp = get_client(ctx)
        ps = await resolve_policy_set(app, kind, policy_set)
        rules = await policy_set_rules(app, kind, str(ps["id"]))
        table = rules["local_exceptions" if section == "exception" else section]
        match = [r for r in table if rule in (r.get("id"), r.get("name"))]
        if not match:
            raise NotFound(f"No {section} rule {rule!r} in {ps['name']}; see ise_get_policy_set.", 404)
        if len(match) > 1:
            raise InvalidRequest(f"Several {section} rules are named {rule!r}; give the rule id instead.")
        target = match[0]
        blockers = ["The default rule can't be deleted"] if target.get("condition") == "DEFAULT" else []
        idx = table.index(target)
        nxt = table[idx + 1]["name"] if idx + 1 < len(table) else None
        plan = Plan(
            f"Delete {section} rule {target['name']} from {ps['name']}",
            details=target,
            fingerprint=fingerprint({"policy_set": ps["id"], "rule": target}),
            blockers=blockers,
            side_effects=[f"Requests that matched it fall through to {nxt!r}" if nxt else "none"],
        )
        path = f"/api/v1/policy/{kind}/policy-set/{q(ps['id'])}/{RULE_SECTIONS[section]}/{q(target['id'])}"
        return await preview_or_apply(
            ctx,
            tool="ise_delete_policy_rule",
            args={"policy_set": policy_set, "rule": rule, "section": section, "kind": kind},
            confirm=confirm,
            plan=plan,
            apply=lambda: app.openapi.delete(path),
        )

    @reg.dangerous(title="Delete a policy set")
    async def ise_delete_policy_set(
        ctx: Context,
        policy_set: Annotated[str, Field(description="Policy set name or id")],
        kind: PolicyKind = "network-access",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a whole policy set with all its rules. Requests it matched fall to the next policy set
        (often Default). The Default set can't be deleted. Preview-first with the rule counts."""
        app: IseApp = get_client(ctx)
        ps = await resolve_policy_set(app, kind, policy_set)
        rules = await policy_set_rules(app, kind, str(ps["id"]))
        blockers = ["The Default policy set can't be deleted"] if ps.get("default") else []
        plan = Plan(
            f"Delete {kind} policy set {ps['name']}",
            details={"rules": {k: len(v) for k, v in rules.items()}, "hits": ps.get("hitCounts")},
            fingerprint=fingerprint({"policy_set": ps, "rules": rules}),
            blockers=blockers,
            side_effects=["Matching requests fall through to the next policy set"],
        )
        return await preview_or_apply(
            ctx,
            tool="ise_delete_policy_set",
            args={"policy_set": policy_set, "kind": kind},
            confirm=confirm,
            plan=plan,
            apply=lambda: app.openapi.delete(f"/api/v1/policy/{kind}/policy-set/{q(ps['id'])}"),
        )

    @reg.dangerous(title="Delete a certificate")
    async def ise_delete_certificate(
        ctx: Context,
        cert_id: Annotated[str, Field(description="Certificate id (from ise_list_certificates)")],
        kind: Annotated[
            Literal["system", "trusted"], Field(description="System (node) or trusted certificate")
        ],
        node: Annotated[str | None, Field(description="Node hostname (system certificates only)")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a system (node identity) or trusted certificate. Deleting a trusted CA breaks EAP-TLS
        and anything chaining to it; a system cert in use (EAP, Admin, Portal...) is blocked.
        Preview-first."""
        app: IseApp = get_client(ctx)
        if kind == "system" and not node:
            raise InvalidRequest("System certificates are per node: give `node` (see ise_list_nodes)")
        if kind == "trusted":
            path = f"/api/v1/certs/trusted-certificate/{quote(cert_id, safe='')}"
            certs = await openapi_all(app, "/api/v1/certs/trusted-certificate")
        else:
            path = f"/api/v1/certs/system-certificate/{quote(str(node), safe='')}/{quote(cert_id, safe='')}"
            certs = await openapi_all(app, f"/api/v1/certs/system-certificate/{quote(str(node), safe='')}")
        match = [c for c in certs if isinstance(c, dict) and c.get("id") == cert_id]
        if not match:
            raise NotFound(f"No {kind} certificate {cert_id}; see ise_list_certificates.", 404)
        cert = match[0]
        blockers = []
        if (
            kind == "system"
            and cert.get("usedBy")
            and str(cert.get("usedBy")).strip() not in ("", "Not in use")
        ):
            blockers.append(f"Certificate is in use for: {cert.get('usedBy')}")
        details = {
            k: cert.get(k)
            for k in (
                "friendlyName",
                "issuedTo",
                "issuedBy",
                "expirationDate",
                "usedBy",
                "trustedFor",
                "status",
            )
        }
        plan = Plan(
            f"Delete {kind} certificate {cert.get('friendlyName')}",
            details=compact(details),
            fingerprint=fingerprint(cert),
            blockers=blockers,
            side_effects=["Authentications relying on this certificate fail"] if kind == "trusted" else [],
        )
        return await preview_or_apply(
            ctx,
            tool="ise_delete_certificate",
            args={"cert_id": cert_id, "kind": kind, "node": node},
            confirm=confirm,
            plan=plan,
            apply=lambda: app.openapi.delete(path),
        )

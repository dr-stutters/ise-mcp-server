"""Profiler and posture (I14 read slice, I40 profiler authoring).

Profiler (see docs/profiler.md for what the ISE 3.5 APIs allow):
- reads: classic profiling policies (ERS, name/parent only), custom profiling rules (OpenAPI
  /api/v1/profiler/policy), probe configuration per PSN, why an endpoint has its profile;
- writes: custom profiling rules (create/update/delete); classic profiling policies, their certainty
  factors and the feed service are GUI-only, and the tools say so instead of failing;
- dangerous: ise_reprofile_endpoint (CoA reauth through the PSN that owns the session).

Posture is read-only (what is configured); it does not run or assess endpoints.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import asyncio
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
from ise_mcp.client import IseApp
from ise_mcp.tools._common import (
    ers_list,
    list_result,
    normalize_mac,
    openapi_all,
    render_condition,
)
from ise_mcp.tools.dangerous import reauth_target, send_reauth, session_fingerprint
from ise_mcp.tools.policy_edit import condition_node
from ise_mcp.tools.sessions import find_session
from ise_mcp.tools.writes import fingerprint

RULES_PATH = "/api/v1/profiler/policy"
# The four endpoint labels a custom profiling rule sets (and authorization rules can match as
# EndPoints:<label>): tool argument -> ISE field.
LABELS = {
    "endpoint_type": "MFCInfoEndpointType",
    "manufacturer": "MFCInfoHardwareManufacturer",
    "model": "MFCInfoHardwareModel",
    "os": "MFCInfoOperatingSystem",
}
# Same labels on the endpoint record (/api/v1/endpoint/{mac}).
ENDPOINT_LABELS = {
    "endpoint_type": "mfcInfoEndpointType",
    "manufacturer": "mfcInfoHardwareManufacturer",
    "model": "mfcInfoHardwareModel",
    "os": "mfcInfoOperatingSystem",
}
PROBES = (
    "radius",
    "dhcp",
    "dhcpSpan",
    "http",
    "dns",
    "netflow",
    "nmap",
    "snmpQuery",
    "snmpTrap",
    "activeDirectory",
    "pxgrid",
)
GUI_ONLY_CLASSIC = (
    "Classic profiling policies (conditions, certainty factors, minimum certainty factor, exception and "
    "CoA actions) are GUI-only: ERS profilerprofile is read-only (name, description, parent). Create or "
    "change them in Work Centers > Profiler > Profiling Policies, or classify devices over the API with a "
    "custom profiling rule (ise_set_profiling_rule)."
)
GUI_ONLY_CF = (
    "Not in any ISE REST API: the certainty factor, matched policy version and the raw attributes the "
    "probes collected. See Context Visibility > Endpoints > {mac} > Attributes (TotalCertaintyFactor, "
    "MatchedPolicy, EndPointPolicy, PolicyVersion)."
)
FEED_SERVICE = (
    "Not exposed over REST: see Administration > FeedService > Profiler for the last feed update and the "
    "subscription status."
)
# Endpoint-record fields worth showing as 'what ISE has on it' (ids and empty IoT fields dropped).
_EP_FIELDS = (
    "ipAddress",
    "ipv6Address",
    "vendor",
    "productId",
    "serialNumber",
    "deviceType",
    "softwareRevision",
    "hardwareRevision",
    "protocol",
    "portalUser",
    "identityStore",
    "assetName",
    "assetVendor",
    "assetProductId",
    "assetDeviceType",
    "anomalousBehaviour",
)
_SESSION_FIELDS = (
    "endpoint_policy",
    "network_device_name",
    "nas_port_id",
    "authentication_method",
    "identity_group",
    "framed_ip_address",
    "acs_server",
    "auth_acs_timestamp",
)


def _posture_policy_row(p: dict[str, Any]) -> dict[str, Any]:
    reqs = p.get("requirementList") or []
    return {
        "name": p.get("name"),
        "enabled": p.get("enable"),
        "os": p.get("osNameList"),
        "type": p.get("postureType"),
        "compliance_module": p.get("complianceModule"),
        "requirements": len(reqs),
        "enforcement": sorted({str(r.get("enforcement")) for r in reqs if r.get("enforcement")}) or None,
        "identity_groups": len(p.get("roleList") or []) or None,
        "id": p.get("id"),
    }


def _posture_requirement_row(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": r.get("name"),
        "os": r.get("osNameList"),
        "type": r.get("postureType"),
        "rules": [c.get("name") for c in r.get("ruleList") or []] or None,
        "evaluation": r.get("conditionEvaluationOption"),
        "remediation": (r.get("remediation") or {}).get("name"),
        "compliance_module": r.get("complianceModule"),
        "id": r.get("id"),
    }


# --- profiler helpers ---------------------------------------------------------------------------


def _as_list(value: Any) -> list[str]:
    if value in (None, "", []):
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)]


def rule_row(r: dict[str, Any]) -> dict[str, Any]:
    labels = r.get("profileLabel") or {}
    row = {
        "name": r.get("name"),
        "type": r.get("profilingType"),
        "enabled": r.get("status"),
        "priority": r.get("rulePriority"),
        "condition": render_condition(r.get("condition")) if r.get("condition") else None,
        "labels": {k: _as_list(labels.get(v)) for k, v in LABELS.items() if _as_list(labels.get(v))} or None,
        "direct_map": r.get("directMapRules"),
        "matched_endpoints": r.get("matchedEndpoints"),
        "id": r.get("policyId"),
    }
    return {k: v for k, v in row.items() if v is not None}


async def profiling_rules(
    app: IseApp, *, name: str | None = None, rule_type: str | None = None
) -> list[dict[str, Any]]:
    params = {k: v for k, v in {"name": name, "type": rule_type}.items() if v}
    data = await app.openapi.get(RULES_PATH, params or None)
    data = data.get("response", data) if isinstance(data, dict) else data
    return [r for r in data or [] if isinstance(r, dict)]


async def find_rule(app: IseApp, name: str) -> dict[str, Any] | None:
    """The profiling rule with exactly this name (the name filter may also match case-insensitively)."""
    if "," in name:
        raise InvalidRequest(
            "Profiling rule names can't contain a comma (ISE's name filter is comma-separated)"
        )
    try:
        hits = await profiling_rules(app, name=name)
    except NotFound:
        return None
    exact = [r for r in hits if r.get("name") == name]
    return exact[0] if exact else None


async def profiler_dictionary(app: IseApp) -> dict[str, list[str]]:
    """The attributes custom profiling rules can match on: {dictionary: [attribute, ...]}."""
    cache: dict[str, list[str]] | None = app.__dict__.get("_profiler_dict")
    if cache is None:
        data = await app.openapi.get("/api/v1/profiler/endpoint-custom-dictionary")
        cache = {str(k): [str(a) for a in v] for k, v in (data or {}).items() if isinstance(v, list)}
        app.__dict__["_profiler_dict"] = cache
    return cache


def check_profiler_condition(node: dict[str, Any], dictionary: dict[str, list[str]]) -> list[str]:
    """Canonicalise (in place) one ConditionAttributes node against the profiler dictionary; blockers."""
    d, a = str(node["dictionaryName"]), str(node["attributeName"])
    dict_name = next((k for k in dictionary if k.lower() == d.lower()), None)
    if dict_name is None:
        return [f"Unknown profiler dictionary {d!r}; one of: {', '.join(sorted(dictionary))}"]
    attr = next((x for x in dictionary[dict_name] if x.lower() == a.lower()), None)
    if attr is None:
        return [
            f"{dict_name} has no attribute {a!r}; it has: {', '.join(dictionary[dict_name][:40])}"
            + (" ..." if len(dictionary[dict_name]) > 40 else "")
        ]
    node["dictionaryName"], node["attributeName"] = dict_name, attr
    return []


async def build_profiler_condition(
    app: IseApp, conditions: list[str], match: str
) -> tuple[dict[str, Any], list[str]]:
    nodes = [condition_node(c, {}) for c in conditions]
    dictionary = await profiler_dictionary(app)
    blockers: list[str] = []
    for n in nodes:
        blockers += check_profiler_condition(n, dictionary)
    if len(nodes) == 1:
        return nodes[0], blockers
    block = "ConditionAndBlock" if match == "all" else "ConditionOrBlock"
    return {"conditionType": block, "isNegate": False, "children": nodes}, blockers


def probe_view(cfg: dict[str, Any]) -> dict[str, Any]:
    """A PSN's probe set: a probe that is null is disabled; an object or a list (even empty) is on."""
    enabled: dict[str, Any] = {}
    disabled: list[str] = []
    for probe in PROBES:
        value = cfg.get(probe)
        if value is None:
            disabled.append(probe)
        else:
            enabled[probe] = value or "on"
    return {"enabled": enabled, "disabled": disabled}


async def profile_chain(app: IseApp, profile_id: str, depth: int = 10) -> list[dict[str, Any]]:
    """The profiling policy and its parents, child first ({name, description, id})."""
    chain: list[dict[str, Any]] = []
    seen: set[str] = set()
    pid: str | None = profile_id
    while pid and pid not in seen and len(chain) < depth:
        seen.add(pid)
        try:
            p = await app.ers_get("profilerprofile", pid)
        except NotFound:
            chain.append({"id": pid, "note": "not found in ERS profilerprofile"})
            break
        chain.append({k: p.get(k) for k in ("name", "description", "id") if p.get(k)})
        pid = str(p.get("parentId") or "") or None
    return chain


async def _safe(coro: Any) -> Any:
    try:
        return await coro
    except NotFound:
        return None
    except UpstreamError as e:
        return {"error": str(e)}


def explain(
    mac: str,
    endpoint: dict[str, Any] | None,
    chain: list[dict[str, Any]],
    session: dict[str, Any] | None,
    rules: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Assemble ise_explain_profile's answer from what the REST APIs have."""
    out: dict[str, Any] = {"mac": mac}
    why: list[str] = []
    if not endpoint:
        out["endpoint"] = "not in the ISE endpoint database"
        why.append(
            "ISE has no endpoint record for this MAC: no RADIUS or probe data has reached ISE for it (or "
            "it was deleted). Nothing has been profiled."
        )
    profile = chain[0].get("name") if chain else None
    static = bool(endpoint and endpoint.get("staticProfileAssignment"))
    if endpoint:
        out["profile"] = profile or "Unknown (not profiled)"
        out["static_profile_assignment"] = static
        if chain:
            out["policy_chain"] = [c.get("name") or c.get("id") for c in chain]
        labels = {k: _as_list(endpoint.get(v)) for k, v in ENDPOINT_LABELS.items()}
        labels = {k: v for k, v in labels.items() if v}
        if labels:
            out["labels"] = labels
        seen = {k: endpoint.get(k) for k in _EP_FIELDS if endpoint.get(k) not in (None, "", "[]", [])}
        if endpoint.get("customAttributes"):
            seen["customAttributes"] = endpoint.get("customAttributes")
        if endpoint.get("mdmAttributes"):
            seen["mdmAttributes"] = endpoint.get("mdmAttributes")
        if seen:
            out["endpoint_attributes"] = seen
        if static:
            why.append(
                f"The profile {profile or '(none)'} is assigned statically: the profiler does not change it. "
                "Clear the static assignment (ise_set_endpoint) to let profiling decide."
            )
        elif profile and profile != "Unknown":
            parents = " > ".join(str(c.get("name")) for c in reversed(chain[1:]))
            why.append(
                f"The profiler matched the profiling policy {profile}"
                + (f" (under {parents})" if parents else "")
                + ": of the policies whose minimum certainty factor the endpoint's attributes reached, "
                "it had the highest certainty factor (a child policy needs its parent to match first)."
            )
        else:
            why.append(
                "No profiling policy matched with enough certainty, so ISE calls it Unknown. Either the "
                "probes have not seen attributes that identify it (check ise_profiler_status: RADIUS, DHCP "
                "and device sensor data are the usual sources), or no policy covers this kind of device; a "
                "custom profiling rule (ise_set_profiling_rule) can label it."
            )
    if isinstance(session, dict) and "error" not in session:
        s = {k: session.get(k) for k in _SESSION_FIELDS if session.get(k)}
        reply = str(session.get("reply") or "")
        if "profile-name=" in reply:
            s["profile_sent_to_nad"] = (
                reply.split("profile-name=", 1)[1].split(";", 1)[0].split(",", 1)[0].strip()
            )
        if session.get("active") is False:
            s["active"] = False
        out["last_session"] = s
        at_auth = s.get("endpoint_policy")
        if at_auth and profile and at_auth != profile:
            why.append(
                f"The last authentication ran with the profile {at_auth}; the endpoint is now {profile}. "
                "Policy on EndPoints:EndPointPolicy applies the new profile at the next authentication, or "
                "now with ise_reprofile_endpoint."
            )
    else:
        out["last_session"] = session or "no session in MnT"
    if isinstance(rules, list) and endpoint:
        mine = {k: set(_as_list(endpoint.get(v))) for k, v in ENDPOINT_LABELS.items()}
        hits = []
        for r in rules:
            lab = r.get("profileLabel") or {}
            if any(set(_as_list(lab.get(LABELS[k]))) & mine[k] for k in LABELS):
                hits.append(rule_row(r))
        if hits:
            out["custom_rules_with_its_labels"] = hits
            why.append(
                "Custom profiling rules set labels this endpoint has: "
                + ", ".join(str(h.get("name")) for h in hits)
            )
    elif isinstance(rules, dict):
        out["custom_rules"] = rules
    out["why"] = why
    out["not_available_over_rest"] = GUI_ONLY_CF.format(mac=mac)
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List profiler profiles")
    async def ise_list_profiler_profiles(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="Filter to profiles whose name contains this (case-insensitive)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the classic profiling policies (ISE ships ~700, e.g. 'Apple-Device', 'Cisco-IP-Phone').
        ERS returns name, description and id only: their conditions and certainty factors aren't in any
        REST API, and creating or editing them is GUI-only (Work Centers > Profiler > Profiling Policies).
        Use name to find whether a profile exists and its id (for an EndPoints:EndPointPolicy
        authorization condition). API-writable classification: ise_set_profiling_rule."""
        app: IseApp = get_client(ctx)
        filters = [f"name.CONTAINS.{name}"] if name else None
        page = await ers_list(app, "profilerprofile", filters=filters, limit=limit, offset=offset)
        return list_result(page, fmt=response_format, columns=["name", "description", "id"])

    @reg.read(title="List posture policies")
    async def ise_list_posture_policies(
        ctx: Context,
        enabled_only: Annotated[bool, Field(description="Only policies that are enabled")] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List posture policies (which OS/identity-group a requirement set applies to): name, enabled,
        OS, agent type, requirement count and enforcement (MANDATORY/OPTIONAL/AUDIT), compliance module.
        Read-only summary of what posture is configured; it does not assess any endpoint. Drill into a
        requirement with ise_list_posture_requirements."""
        app: IseApp = get_client(ctx)
        rows = [_posture_policy_row(p) for p in await openapi_all(app, "/api/v1/posture/policy")]
        if enabled_only:
            rows = [r for r in rows if r.get("enabled")]
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["name", "enabled", "os", "type", "requirements", "enforcement"],
        )

    @reg.read(title="List posture requirements")
    async def ise_list_posture_requirements(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List posture requirements (the checks a policy enforces): name, OS, agent type, the rules it
        contains, how they are combined (ALL_SUCCEED / ANY_FAIL), and the remediation. Read-only."""
        app: IseApp = get_client(ctx)
        rows = [_posture_requirement_row(r) for r in await openapi_all(app, "/api/v1/posture/requirement")]
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["name", "os", "type", "rules", "evaluation", "remediation"],
        )

    # --- profiler (I40) ---------------------------------------------------------------------------

    @reg.read(title="List custom profiling rules")
    async def ise_list_profiling_rules(
        ctx: Context,
        rule_type: Annotated[
            Literal["CUSTOM", "DIRECT", "ML"] | None,
            Field(description="Only this rule type (CUSTOM: condition -> labels; DIRECT: copy an attribute)"),
        ] = None,
        name: Annotated[
            str | None, Field(description="Filter: rule name contains (case-insensitive)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the profiler's custom / direct / ML profiling rules (ISE 3.3+ Profiler Policy Management):
        name, type, enabled, priority, condition, the endpoint labels it sets (endpoint type, manufacturer,
        model, OS) and how many endpoints it matched. These are separate from the classic profiling
        policies (ise_list_profiler_profiles); none ship with ISE."""
        app: IseApp = get_client(ctx)
        rows = [rule_row(r) for r in await profiling_rules(app, rule_type=rule_type)]
        if name:
            rows = [r for r in rows if name.lower() in str(r.get("name") or "").lower()]
        rows.sort(key=lambda r: (r.get("priority") is None, r.get("priority") or 0, str(r.get("name"))))
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["name", "type", "enabled", "priority", "condition", "labels", "matched_endpoints"],
        )

    @reg.read(title="Profiler status per PSN")
    async def ise_profiler_status(
        ctx: Context,
        node: Annotated[str | None, Field(description="Only this node (hostname)")] = None,
    ) -> ToolResult:
        """Profiler health and setup: which nodes run the Profiler service, each PSN's probes (enabled with
        their settings, and disabled), live profiler session count, custom profiling rule count, cloud
        profiler / telemetry state, and the feed service (GUI-only, said so). Use it when endpoints stay
        'Unknown': a disabled RADIUS or DHCP probe is the usual cause. Read-only."""
        app: IseApp = get_client(ctx)
        nodes_raw = await app.openapi.get("/api/v1/deployment/node")
        nodes = nodes_raw.get("response", nodes_raw) if isinstance(nodes_raw, dict) else nodes_raw
        nodes = [n for n in nodes or [] if isinstance(n, dict)]
        if node:
            nodes = [n for n in nodes if str(n.get("hostname")).lower() == node.lower()]
            if not nodes:
                raise NotFound(f"No ISE node {node!r} (see ise_list_nodes)", 404)
        profilers = [n for n in nodes if "Profiler" in (n.get("services") or [])]

        async def probes(n: dict[str, Any]) -> dict[str, Any]:
            host = str(n.get("hostname"))
            cfg = await _safe(app.openapi.get(f"/api/v1/profile/{quote(host, safe='')}"))
            row: dict[str, Any] = {"node": host, "roles": n.get("roles")}
            if isinstance(cfg, dict) and "error" not in cfg:
                row.update(probe_view(cfg.get("response", cfg)))
            else:
                row["probes"] = cfg or "no probe configuration returned"
            return row

        rows, count, rules, cloud = await asyncio.gather(
            asyncio.gather(*(probes(n) for n in profilers)),
            _safe(app.mnt_get("Session/ProfilerCount")),
            _safe(profiling_rules(app)),
            _safe(app.openapi.get("/api/v1/profiler/cloud/connection")),
        )
        out: dict[str, Any] = {"profiler_nodes": list(rows)}
        others = [str(n.get("hostname")) for n in nodes if n not in profilers]
        if others:
            out["nodes_without_profiler_service"] = others
        if not profilers:
            out["note"] = "No node runs the Profiler service: endpoints are not profiled."
        if isinstance(count, dict):
            out["profiler_sessions"] = count.get("count")
        if isinstance(rules, list):
            out["custom_profiling_rules"] = {
                "total": len(rules),
                "enabled": sum(1 for r in rules if r.get("status")),
            }
        if isinstance(cloud, dict) and "error" not in cloud:
            out["cloud_profiler"] = {
                "registered": bool(cloud.get("deploymentId") or cloud.get("status")),
                "status": cloud.get("status"),
                "region": cloud.get("region"),
                "telemetry_enabled": cloud.get("telemetryEnabled"),
            }
        out["feed_service"] = FEED_SERVICE
        return object_result(out)

    @reg.read(title="Explain an endpoint's profile")
    async def ise_explain_profile(
        ctx: Context,
        mac: Annotated[str, Field(description="Endpoint MAC address (any notation)")],
    ) -> ToolResult:
        """Why an endpoint has its profile: the profiling policy it matched and its parent chain
        (e.g. Apple-iPhone under Apple-Device), whether the profile is static, the endpoint labels
        (endpoint type, manufacturer, model, OS) and the custom rules that set them, what ISE holds on the
        endpoint and its last session (profile used at authentication, profile sent to the NAD), and a
        plain 'why'. The certainty factor and raw probe attributes are not in any REST API; the answer
        says where to find them. Use ise_endpoint_360 for sessions and auth history."""
        app: IseApp = get_client(ctx)
        mac_n = normalize_mac(mac)
        endpoint, session, rules = await asyncio.gather(
            _safe(app.openapi.get(f"/api/v1/endpoint/{quote(mac_n)}")),
            _safe(find_session(app, mac=mac_n)),
            _safe(profiling_rules(app)),
        )
        if isinstance(endpoint, dict) and "error" in endpoint:
            raise UpstreamError(str(endpoint["error"]))
        ep = endpoint if isinstance(endpoint, dict) else None
        chain = await profile_chain(app, str(ep["profileId"])) if ep and ep.get("profileId") else []
        return object_result(explain(mac_n, ep, chain, session, rules))

    @reg.write(title="Create or update a custom profiling rule")
    async def ise_set_profiling_rule(
        ctx: Context,
        name: Annotated[str, Field(description="Rule name (created if missing, otherwise updated)")],
        conditions: Annotated[
            list[str] | None,
            Field(
                description="'Dictionary:attribute operator value' on profiler attributes, e.g. "
                "'DHCP:dhcpClassIdentifier contains MSFT', 'MAC:oui equals Cisco Systems, Inc', "
                "'CDP:cdpCachePlatform startsWith cisco IP Phone'. Required to create."
            ),
        ] = None,
        match: Annotated[
            Literal["all", "any"], Field(description="Combine conditions with AND or OR")
        ] = "all",
        endpoint_type: Annotated[
            list[str] | None, Field(description="Label: endpoint type(s) to set")
        ] = None,
        manufacturer: Annotated[
            list[str] | None, Field(description="Label: hardware manufacturer(s)")
        ] = None,
        model: Annotated[list[str] | None, Field(description="Label: hardware model(s)")] = None,
        os: Annotated[list[str] | None, Field(description="Label: operating system(s)")] = None,
        priority: Annotated[
            int | None,
            Field(ge=1, description="Rule priority (lower wins); new rules default to after the rest"),
        ] = None,
        enabled: Annotated[bool | None, Field(description="Enable or disable the rule")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create or update a CUSTOM profiling rule (ISE 3.3+): when its conditions match an endpoint's
        profiler attributes, ISE sets the given labels (endpoint type, manufacturer, model, OS), which
        authorization rules can match as EndPoints:MFCInfoEndpointType etc. Conditions are checked against
        the profiler dictionary before anything is sent. Labels given replace that label's values; omitted
        ones are kept on update. This is the API-writable way to classify devices: classic profiling
        policies (with certainty factors) are GUI-only. Preview-first with a diff."""
        app: IseApp = get_client(ctx)
        labels_in = {"endpoint_type": endpoint_type, "manufacturer": manufacturer, "model": model, "os": os}
        args = {
            "name": name,
            "conditions": conditions,
            "match": match,
            **labels_in,
            "priority": priority,
            "enabled": enabled,
        }
        current = await find_rule(app, name)
        blockers: list[str] = []
        condition = None
        if conditions is not None:
            if not conditions or any(not c.strip() for c in conditions):
                raise InvalidRequest("Give at least one non-empty condition")
            condition, blockers = await build_profiler_condition(app, conditions, match)
        if current is None:
            if condition is None:
                raise InvalidRequest(f"No profiling rule {name!r} yet: give conditions to create it")
            if not any(labels_in.values()):
                raise InvalidRequest(
                    "Give at least one label (endpoint_type, manufacturer, model or os) to set"
                )
            body: dict[str, Any] = {
                "name": name,
                "profilingType": "CUSTOM",
                "status": True if enabled is None else enabled,
                "condition": condition,
                "profileLabel": {LABELS[k]: list(v or []) for k, v in labels_in.items()},
            }
            if priority is None:
                # ISE requires a priority on create: default to after every existing rule.
                known = [r.get("rulePriority") for r in await profiling_rules(app)]
                priority = max([p for p in known if isinstance(p, int)], default=0) + 10
            body["rulePriority"] = priority

            async def create() -> Any:
                await app.openapi.request("POST", RULES_PATH, json=[body], expect="text")
                made = await find_rule(app, name)
                return rule_row(made) if made else {"created": name}

            return await preview_or_apply(
                ctx,
                tool="ise_set_profiling_rule",
                args=args,
                confirm=confirm,
                plan=Plan(
                    f"Create custom profiling rule {name}",
                    details={**rule_row(body), "condition": render_condition(condition)},
                    blockers=blockers,
                    side_effects=[
                        "Endpoints matching the condition get these labels at their next profiling"
                    ],
                ),
                apply=create,
            )
        if current.get("profilingType") != "CUSTOM":
            blockers.append(
                f"{name!r} is a {current.get('profilingType')} rule; only CUSTOM rules are edited here"
            )
        desired = {k: v for k, v in current.items() if k != "matchedEndpoints"}
        if condition is not None:
            desired["condition"] = condition
        lab = dict(current.get("profileLabel") or {})
        for k, v in labels_in.items():
            if v is not None:
                lab[LABELS[k]] = list(v)
        desired["profileLabel"] = lab
        if priority is not None:
            desired["rulePriority"] = priority
        if enabled is not None:
            desired["status"] = enabled
        before = {k: v for k, v in current.items() if k != "matchedEndpoints"}
        if desired == before:
            raise InvalidRequest(f"Profiling rule {name!r} already has exactly these settings")
        matched = current.get("matchedEndpoints")

        async def update() -> Any:
            await app.openapi.request("PUT", RULES_PATH, json=[desired], expect="text")
            made = await find_rule(app, name)
            return rule_row(made) if made else {"updated": name}

        return await preview_or_apply(
            ctx,
            tool="ise_set_profiling_rule",
            args=args,
            confirm=confirm,
            plan=Plan(
                f"Update custom profiling rule {name}",
                details={"changes": field_changes(before, desired, replace=True)},
                fingerprint=fingerprint(current),
                blockers=blockers,
                side_effects=[f"{matched} endpoint(s) matched this rule; their labels follow the change"]
                if matched
                else [],
            ),
            apply=update,
        )

    @reg.write(title="Delete a custom profiling rule", destructive=True)
    async def ise_delete_profiling_rule(
        ctx: Context,
        name: Annotated[str, Field(description="Rule name (see ise_list_profiling_rules)")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a CUSTOM profiling rule. Endpoints it labelled lose those labels at their next profiling,
        so authorization rules on EndPoints:MFCInfo* stop matching them. Classic profiling policies can't
        be deleted over the API (GUI-only). Preview-first: shows the rule and how many endpoints it
        matched."""
        app: IseApp = get_client(ctx)
        current = await find_rule(app, name)
        if current is None:
            raise NotFound(f"No profiling rule {name!r} (see ise_list_profiling_rules)", 404)
        blockers = []
        if current.get("profilingType") != "CUSTOM":
            blockers.append(
                f"{name!r} is a {current.get('profilingType')} rule; only CUSTOM rules are deleted here"
            )
        matched = current.get("matchedEndpoints") or 0
        plan = Plan(
            f"Delete custom profiling rule {name}",
            details=rule_row(current),
            fingerprint=fingerprint(current),
            blockers=blockers,
            side_effects=[f"{matched} endpoint(s) it matched lose its labels"] if matched else [],
            blast_radius=int(matched) if str(matched).isdigit() else None,
        )

        async def apply() -> Any:
            await app.openapi.request("DELETE", RULES_PATH, json=[current["policyId"]], expect="text")
            return {"deleted": name, "id": current["policyId"]}

        return await preview_or_apply(
            ctx,
            tool="ise_delete_profiling_rule",
            args={"name": name},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Reprofile an endpoint (CoA)")
    async def ise_reprofile_endpoint(
        ctx: Context,
        mac: Annotated[str, Field(description="Endpoint MAC address with an active session")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make ISE re-evaluate an endpoint's profile now: sends a CoA reauthenticate through the PSN that
        owns its session, so the NAD re-authenticates, fresh RADIUS / device-sensor attributes reach the
        profiler, and the authorization result applies the current profile. ISE has no 'reprofile' call;
        this is what its own profiler CoA does. Briefly interrupts the endpoint on some NADs. An endpoint
        with a static profile keeps it. Preview-first: shows the session, NAD, PSN and current profile.
        Check the result with ise_explain_profile a few seconds later."""
        app: IseApp = get_client(ctx)
        mac_n = normalize_mac(mac)
        (session, blockers, details), endpoint = await asyncio.gather(
            reauth_target(app, mac_n), _safe(app.openapi.get(f"/api/v1/endpoint/{quote(mac_n)}"))
        )
        side = ["The endpoint re-authenticates; brief interruption possible"]
        if isinstance(endpoint, dict) and "error" not in endpoint:
            pid = endpoint.get("profileId")
            chain = await profile_chain(app, str(pid), depth=1) if pid else []
            details["current_profile"] = chain[0].get("name") if chain else "Unknown (not profiled)"
            if endpoint.get("staticProfileAssignment"):
                side.append("The profile is assigned statically: reprofiling won't change it")
        if (session or {}).get("endpoint_policy"):
            details["profile_at_last_auth"] = (session or {}).get("endpoint_policy")
        plan = Plan(
            f"Reprofile {mac_n} (CoA reauth)",
            details=details,
            blockers=blockers,
            fingerprint=session_fingerprint(session),
            side_effects=side,
            blast_radius=1,
        )

        async def apply() -> Any:
            out = await send_reauth(app, session, mac_n, "default")
            out["next_step"] = "Run ise_explain_profile in a few seconds to see the profile and labels now"
            return out

        return await preview_or_apply(
            ctx,
            tool="ise_reprofile_endpoint",
            args={"mac": mac_n},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

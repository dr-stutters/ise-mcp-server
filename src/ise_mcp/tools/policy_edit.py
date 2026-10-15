"""Write-tier policy editing (OpenAPI): policy sets, authentication rules, authorization rules (network
access and device admin) and rule updates. Conditions are written as short text and checked against the
policy dictionaries before anything is sent, so a typo shows up as a blocker in the preview instead of an
opaque ISE 400."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import difflib
import re
import time
from collections.abc import Callable
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
    field_changes,
    get_client,
    preview_or_apply,
)

from ise_mcp.client import IseApp
from ise_mcp.tools._common import render_condition
from ise_mcp.tools.endpoint_bulk import custom_attribute_defs
from ise_mcp.tools.policy import PolicyKind, list_policy_sets, resolve_policy_set
from ise_mcp.tools.writes import fingerprint

Section = Literal["authentication", "authorization", "exception"]
Match = Annotated[
    Literal["all", "any"],
    Field(description="'all' = conditions AND-ed (default), 'any' = OR-ed"),
]
ConditionList = Annotated[
    list[str],
    Field(
        description="Conditions, each either a library condition name (e.g. 'Wired_MAB', 'Wired_802.1X', see "
        "ise_list_conditions) or 'Dictionary:Attribute operator value', e.g. 'DEVICE:Location equals "
        "Location#All Locations#Sydney', 'Session:ANCPolicy equals mcp-quarantine', 'IdentityGroup:Name "
        "equals User Identity Groups:Employee', 'Radius:NAS-IP-Address equals 10.1.1.1'. Prefix 'NOT ' to "
        "negate. Attribute names are checked against ise_list_dictionary_attributes."
    ),
]
RuleState = Literal["enabled", "disabled", "monitor"]
FAIL_ACTIONS = ("REJECT", "DROP", "CONTINUE")

_OPERATORS = (
    "notEquals",
    "equals",
    "contains",
    "notContains",
    "startsWith",
    "notStartsWith",
    "endsWith",
    "notEndsWith",
    "in",
    "notIn",
    "matches",
    "greaterThan",
    "lessThan",
    "ipEquals",
    "ipNotEquals",
    "ipGreaterThan",
    "ipLessThan",
)
_EXPR = re.compile(
    r"^\s*(?P<dict>[^:]+):(?P<attr>.+?)\s+(?P<op>"
    + "|".join(sorted(_OPERATORS, key=len, reverse=True))
    + r")\s+(?P<value>.+?)\s*$",
    re.IGNORECASE,
)
DICT_TTL = 600.0
SECTION_PATH = {
    "authentication": "authentication",
    "authorization": "authorization",
    "exception": "exception",
}


def _resp(data: Any) -> Any:
    return data.get("response", data) if isinstance(data, dict) else data


def q(value: Any) -> str:
    return quote(str(value), safe="")


# --- conditions ---------------------------------------------------------------------------------


def condition_node(text: str, library: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """A library condition name -> ConditionReference; 'Dict:Attr op value' -> ConditionAttributes."""
    neg = False
    raw = text.strip()
    if raw.upper().startswith("NOT "):
        neg, raw = True, raw[4:].strip()
    if raw.lower() in library:
        c = library[raw.lower()]
        return {
            "conditionType": "ConditionReference",
            "isNegate": neg,
            "id": c.get("id"),
            "name": c.get("name"),
        }
    m = _EXPR.match(raw)
    if not m:
        raise InvalidRequest(
            f"Condition {text!r} is neither a library condition (see ise_list_conditions) nor "
            "'Dictionary:Attribute operator value'"
        )
    op = next(o for o in _OPERATORS if o.lower() == m.group("op").lower())
    return {
        "conditionType": "ConditionAttributes",
        "isNegate": neg,
        "dictionaryName": m.group("dict").strip(),
        "attributeName": m.group("attr").strip(),
        "operator": op,
        "attributeValue": m.group("value"),
    }


async def condition_library(app: IseApp, kind: str) -> dict[str, dict[str, Any]]:
    data = _resp(await app.openapi.get(f"/api/v1/policy/{kind}/condition")) or []
    return {str(c.get("name")).lower(): c for c in data if isinstance(c, dict) and c.get("name")}


async def dictionary_attributes(app: IseApp, kind: str, scope: str) -> list[dict[str, Any]]:
    """Dictionary attributes usable in policy-set / authentication / authorization conditions. ~300 KB
    for network access, so cached on the app for 10 minutes."""
    cache: dict[tuple[str, str], tuple[float, list[dict[str, Any]]]] = app.__dict__.setdefault(
        "_dict_cache", {}
    )
    hit = cache.get((kind, scope))
    if hit and time.monotonic() - hit[0] < DICT_TTL:
        return hit[1]
    data = _resp(await app.openapi.get(f"/api/v1/policy/{kind}/dictionaries/{scope}")) or []
    attrs = [a for a in data if isinstance(a, dict)]
    cache[(kind, scope)] = (time.monotonic(), attrs)
    return attrs


def check_attribute(node: dict[str, Any], attrs: list[dict[str, Any]]) -> list[str]:
    """Validate (and canonicalise in place) one ConditionAttributes node against the dictionaries.
    Returns blockers."""
    d, a = str(node["dictionaryName"]), str(node["attributeName"])
    index = {(str(x.get("dictionaryName")).lower(), str(x.get("name")).lower()): x for x in attrs}
    found = index.get((d.lower(), a.lower()))
    if found is None:
        names = [f"{x.get('dictionaryName')}:{x.get('name')}" for x in attrs]
        close = difflib.get_close_matches(f"{d}:{a}", names, n=4, cutoff=0.6)
        hint = f" Did you mean {', '.join(close)}?" if close else " See ise_list_dictionary_attributes."
        return [f"Unknown attribute {d}:{a} for this rule type.{hint}"]
    node["dictionaryName"] = found.get("dictionaryName")
    node["attributeName"] = found.get("name")
    if node["dictionaryName"] == "DEVICE":
        # NDG values are written without the root ("All Locations#Sydney", not
        # "Location#All Locations#Sydney"); ISE rejects the full path with "not a permitted option".
        value = str(node["attributeValue"]).strip()
        root = f"{node['attributeName']}#"
        if value.lower().startswith(root.lower()):
            node["attributeValue"] = value[len(root) :]
    allowed = [v for v in found.get("allowedValues") or [] if isinstance(v, dict)]
    if (
        allowed
        and node["dictionaryName"] != "DEVICE"
        and node["operator"] in ("equals", "notEquals")
        and len(allowed) > 1
    ):
        value = str(node["attributeValue"]).strip()
        for v in allowed:
            if value.lower() in (str(v.get("key")).lower(), str(v.get("value")).lower()):
                node["attributeValue"] = v.get("key")
                return []
        keys = ", ".join(str(v.get("key")) for v in allowed[:25])
        return [f"{node['dictionaryName']}:{node['attributeName']} can't be {value!r}; allowed: {keys}"]
    return []


async def build_condition(
    app: IseApp, kind: str, scope: str, conditions: list[str], match: str
) -> tuple[dict[str, Any] | None, list[str]]:
    """The OpenAPI condition tree for a list of condition strings, plus blockers for anything ISE would
    reject (unknown attribute, value not in the attribute's enum)."""
    if not conditions:
        return None, []
    library = await condition_library(app, kind)
    nodes = [condition_node(c, library) for c in conditions]
    blockers: list[str] = []
    if any(n["conditionType"] == "ConditionAttributes" for n in nodes):
        attrs = await dictionary_attributes(app, kind, scope)
        custom: dict[str, str] | None = None
        for n in nodes:
            if n["conditionType"] != "ConditionAttributes":
                continue
            if str(n["dictionaryName"]).lower() == "endpoints" and kind == "network-access":
                # ISE's policy dictionary doesn't always list endpoint custom attributes (seen on 3.5:
                # one appears and later drops out), so accept any attribute defined in ISE.
                if custom is None:
                    custom = await custom_attribute_defs(app)
                hit = next((c for c in custom if c.lower() == str(n["attributeName"]).lower()), None)
                if hit:
                    n["dictionaryName"], n["attributeName"] = "EndPoints", hit
                    continue
            blockers += check_attribute(n, attrs)
    if len(nodes) == 1:
        return nodes[0], blockers
    block = "ConditionAndBlock" if match == "all" else "ConditionOrBlock"
    return {"conditionType": block, "isNegate": False, "children": nodes}, blockers


def strip_links(obj: Any) -> Any:
    """Drop the read-only 'link' and 'hitCounts' members everywhere (ISE rejects some on PUT)."""
    if isinstance(obj, dict):
        return {k: strip_links(v) for k, v in obj.items() if k not in ("link", "hitCounts")}
    if isinstance(obj, list):
        return [strip_links(v) for v in obj]
    return obj


# --- lookups ------------------------------------------------------------------------------------


async def name_list(app: IseApp, path: str) -> list[str]:
    data = _resp(await app.openapi.get(path)) or []
    return [str(x.get("name")) for x in data if isinstance(x, dict) and x.get("name")]


def missing(wanted: list[str], known: list[str], what: str, tool: str) -> list[str]:
    lower = {k.lower() for k in known}
    out = []
    for w in wanted:
        if w.lower() not in lower:
            close = difflib.get_close_matches(w, known, n=3, cutoff=0.6)
            hint = f" (did you mean {', '.join(close)}?)" if close else ""
            out.append(f"No {what} {w!r}{hint}; see {tool}")
    return out


def canonical(wanted: list[str], known: list[str]) -> list[str]:
    by_lower = {k.lower(): k for k in known}
    return [by_lower.get(w.lower(), w) for w in wanted]


async def section_rules(app: IseApp, kind: str, ps_id: str, section: str) -> list[dict[str, Any]]:
    data = _resp(
        await app.openapi.get(f"/api/v1/policy/{kind}/policy-set/{q(ps_id)}/{SECTION_PATH[section]}")
    )
    rules = [r for r in data or [] if isinstance(r, dict)]
    return sorted(rules, key=lambda r: (r.get("rule") or {}).get("rank", 0))


def rule_names(rules: list[dict[str, Any]]) -> list[str]:
    return [str((r.get("rule") or {}).get("name")) for r in rules]


def find_rule(rules: list[dict[str, Any]], key: str, where: str) -> dict[str, Any]:
    hits = [r for r in rules if key in ((r.get("rule") or {}).get("id"), (r.get("rule") or {}).get("name"))]
    if not hits:
        lowered = [r for r in rules if str((r.get("rule") or {}).get("name", "")).lower() == key.lower()]
        hits = lowered
    if not hits:
        raise NotFound(f"No rule {key!r} in {where}. Rules: {', '.join(rule_names(rules))}", 404)
    if len(hits) > 1:
        raise InvalidRequest(f"Several rules in {where} are named {key!r}; give the rule id")
    return hits[0]


def landing(names: list[str], rank: int) -> dict[str, Any]:
    """Where a new entry at `rank` lands among the existing names (in order, Default last). ISE keeps the
    default last, so a rank past the end lands just before it."""
    pos = min(rank, max(len(names) - 1, 0))
    return {
        "inserted_before": names[pos] if pos < len(names) else None,
        "inserted_after": names[pos - 1] if 0 < pos <= len(names) else None,
    }


def rule_view(entry: dict[str, Any]) -> dict[str, Any]:
    rule = entry.get("rule") or {}
    out = {
        "name": rule.get("name"),
        "rank": rule.get("rank"),
        "state": rule.get("state"),
        "condition": "DEFAULT" if rule.get("default") else render_condition(rule.get("condition")),
    }
    for k in (
        "profile",
        "securityGroup",
        "commands",
        "identitySourceName",
        "ifAuthFail",
        "ifUserNotFound",
        "ifProcessFail",
    ):
        if entry.get(k) not in (None, "", []):
            out[k] = entry[k]
    return out


def register(reg: ToolRegistrar) -> None:  # noqa: C901 - one registration block per tool
    # --- policy sets ---------------------------------------------------------------------------

    @reg.write(title="Create policy set")
    async def ise_create_policy_set(
        ctx: Context,
        name: Annotated[str, Field(description="Policy set name, e.g. 'mcp-wired-access'")],
        conditions: ConditionList,
        kind: PolicyKind = "network-access",
        match: Match = "all",
        allowed_protocols: Annotated[
            str | None,
            Field(
                description="Allowed protocols service or RADIUS/TACACS server sequence (default: 'Default "
                "Network Access' / 'Default Device Admin'; see ise_list_allowed_protocols)"
            ),
        ] = None,
        rank: Annotated[
            int, Field(ge=0, description="Position (0 = evaluated first); Default stays last")
        ] = 0,
        state: Annotated[RuleState, Field(description="enabled, disabled or monitor")] = "enabled",
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a network-access (RADIUS) or device-admin (TACACS+) policy set: the conditions that
        select it (e.g. the switch's device group, Wired_MAB) and its allowed-protocols service. ISE adds a
        Default authentication rule (All_User_ID_Stores) and a Default authorization rule (DenyAccess /
        Deny All Shell Profile); add real rules with ise_create_authn_rule and ise_create_authz_rule.
        Policy sets are evaluated top-down, so the preview shows where it lands. Conditions are checked
        against the policy dictionaries first. Preview-first."""
        app: IseApp = get_client(ctx)
        service = allowed_protocols or (
            "Default Network Access" if kind == "network-access" else "Default Device Admin"
        )
        existing = await list_policy_sets(app, kind)
        ordered = sorted(existing, key=lambda p: int(p.get("rank") or 0))
        names = [str(p.get("name")) for p in ordered]
        condition, blockers = await build_condition(app, kind, "policyset", conditions, match)
        if condition is None:
            raise InvalidRequest("Give at least one condition (a policy set without one never matches)")
        services = await name_list(app, f"/api/v1/policy/{kind}/service-names")
        blockers += missing(
            [service], services, "allowed protocols / server sequence", "ise_list_allowed_protocols"
        )
        if name.lower() in (n.lower() for n in [str(p.get("name")) for p in existing]):
            blockers.append(f"A {kind} policy set named {name!r} already exists")
        body: dict[str, Any] = {
            "name": name,
            "description": description or "",
            "state": state,
            "rank": rank,
            "serviceName": canonical([service], services)[0],
            "condition": condition,
            "isProxy": False,
        }
        details = {
            "kind": kind,
            "name": name,
            "condition": render_condition(condition),
            "allowed_protocols": body["serviceName"],
            "state": state,
            "rank": rank,
            **landing(names, rank),
            "default_rules_added_by_ise": ["authentication: Default", "authorization: Default"],
        }
        return await preview_or_apply(
            ctx,
            tool="ise_create_policy_set",
            args={
                "name": name,
                "conditions": conditions,
                "kind": kind,
                "match": match,
                "allowed_protocols": allowed_protocols,
                "rank": rank,
                "state": state,
                "description": description,
            },
            confirm=confirm,
            plan=Plan(
                f"Create {kind} policy set {name}",
                details=details,
                blockers=blockers,
                fingerprint=fingerprint([str(p.get("name")) for p in existing]),
                side_effects=["Matching requests stop reaching the policy sets below it"],
            ),
            apply=lambda: _created(app.openapi.post(f"/api/v1/policy/{kind}/policy-set", body)),
        )

    @reg.write(title="Update policy set")
    async def ise_update_policy_set(
        ctx: Context,
        policy_set: Annotated[str, Field(description="Policy set name or id (see ise_list_policy_sets)")],
        kind: PolicyKind = "network-access",
        state: Annotated[RuleState | None, Field(description="enabled, disabled or monitor")] = None,
        conditions: Annotated[
            list[str] | None,
            Field(description="Replace the conditions (same syntax as ise_create_policy_set)"),
        ] = None,
        match: Match = "all",
        allowed_protocols: Annotated[str | None, Field(description="New allowed protocols service")] = None,
        rank: Annotated[int | None, Field(ge=0, description="Move to this position (0 = first)")] = None,
        new_name: Annotated[str | None, Field(description="Rename the policy set")] = None,
        description: Annotated[str | None, Field(description="New description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a policy set: enable/disable/monitor it, replace its conditions, switch its allowed
        protocols, move it or rename it. Only the given fields change. Disabling or narrowing a set sends
        its traffic to the next matching set (often Default). The Default set's name, rank and condition
        are fixed. Preview-first with a field diff."""
        app: IseApp = get_client(ctx)
        ps = await resolve_policy_set(app, kind, policy_set)
        current = strip_links(_resp(await app.openapi.get(f"/api/v1/policy/{kind}/policy-set/{q(ps['id'])}")))
        desired = dict(current)
        blockers: list[str] = []
        if state is not None:
            desired["state"] = state
        if conditions is not None:
            if not conditions:
                raise InvalidRequest(
                    "Give at least one condition (an empty condition would match everything)"
                )
            cond, cond_blockers = await build_condition(app, kind, "policyset", conditions, match)
            blockers += cond_blockers
            desired["condition"] = cond
        if allowed_protocols is not None:
            services = await name_list(app, f"/api/v1/policy/{kind}/service-names")
            blockers += missing(
                [allowed_protocols], services, "allowed protocols service", "ise_list_allowed_protocols"
            )
            desired["serviceName"] = canonical([allowed_protocols], services)[0]
        if rank is not None:
            desired["rank"] = rank
        if new_name is not None:
            desired["name"] = new_name
            others = [
                str(p.get("name")).lower()
                for p in await list_policy_sets(app, kind)
                if p.get("id") != ps["id"]
            ]
            if new_name.lower() in others:
                blockers.append(f"A {kind} policy set named {new_name!r} already exists")
        if description is not None:
            desired["description"] = description
        if desired == current:
            raise InvalidRequest("Nothing to change: give at least one field that differs")
        if current.get("default") and any(x is not None for x in (conditions, rank, new_name)):
            blockers.append("The Default policy set's name, rank and condition can't be changed")
        changes = field_changes(current, desired)
        if any(k == "condition" or k.startswith("condition.") for k in changes):
            changes = {k: v for k, v in changes.items() if not k.startswith("condition")}
            changes["condition"] = {
                "from": render_condition(current.get("condition")),
                "to": render_condition(desired.get("condition")),
            }
        side = []
        if state in ("disabled",) or conditions is not None:
            side.append("Requests this set no longer matches fall through to the next policy set")
        plan = Plan(
            f"Update {kind} policy set {ps['name']}",
            details={"changes": changes},
            fingerprint=fingerprint(current),
            blockers=blockers,
            side_effects=side,
        )
        return await preview_or_apply(
            ctx,
            tool="ise_update_policy_set",
            args={
                "policy_set": policy_set,
                "kind": kind,
                "state": state,
                "conditions": conditions,
                "match": match,
                "allowed_protocols": allowed_protocols,
                "rank": rank,
                "new_name": new_name,
                "description": description,
            },
            confirm=confirm,
            plan=plan,
            apply=lambda: _updated(
                app.openapi.put(f"/api/v1/policy/{kind}/policy-set/{q(ps['id'])}", desired), policy_set_view
            ),
        )

    # --- rules ---------------------------------------------------------------------------------

    @reg.write(title="Create authentication rule")
    async def ise_create_authn_rule(
        ctx: Context,
        policy_set: Annotated[str, Field(description="Policy set name or id (see ise_list_policy_sets)")],
        name: Annotated[str, Field(description="Rule name, e.g. 'MAB'")],
        conditions: ConditionList,
        identity_source: Annotated[
            str,
            Field(
                description="Identity store or sequence: 'Internal Endpoints' (MAB), 'Internal Users', "
                "'All_User_ID_Stores', an AD join point or a sequence (see ise_list_identity_sources)"
            ),
        ],
        kind: PolicyKind = "network-access",
        match: Match = "all",
        if_auth_fail: Annotated[
            Literal["REJECT", "DROP", "CONTINUE"], Field(description="When the credentials are wrong")
        ] = "REJECT",
        if_user_not_found: Annotated[
            Literal["REJECT", "DROP", "CONTINUE"],
            Field(
                description="When the user/MAC isn't in the store. CONTINUE is typical for MAB, so unknown "
                "endpoints still reach authorization (e.g. for guest redirect)"
            ),
        ] = "REJECT",
        if_process_fail: Annotated[
            Literal["REJECT", "DROP", "CONTINUE"], Field(description="When the store can't be reached")
        ] = "DROP",
        rank: Annotated[
            int, Field(ge=0, description="Position (0 = first); the Default rule stays last")
        ] = 0,
        enabled: Annotated[bool, Field(description="Create enabled (true) or disabled")] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add an authentication rule to a policy set: conditions -> identity source, with what to do when
        authentication fails, the user isn't found, or the store is unreachable. Typical: 'Wired_MAB' ->
        Internal Endpoints (if_user_not_found=CONTINUE); 'Wired_802.1X' -> All_User_ID_Stores. First
        match wins; the preview shows where it lands. Preview-first."""
        app: IseApp = get_client(ctx)
        ps = await resolve_policy_set(app, kind, policy_set)
        rules = await section_rules(app, kind, str(ps["id"]), "authentication")
        condition, blockers = await build_condition(app, kind, "authentication", conditions, match)
        if condition is None:
            raise InvalidRequest("Give at least one condition")
        stores = await name_list(app, f"/api/v1/policy/{kind}/identity-stores")
        blockers += missing([identity_source], stores, "identity source", "ise_list_identity_sources")
        names = rule_names(rules)
        if name.lower() in (n.lower() for n in names):
            blockers.append(f"Rule {name!r} already exists in {ps['name']}")
        body = {
            "rule": {
                "name": name,
                "rank": rank,
                "state": "enabled" if enabled else "disabled",
                "default": False,
                "condition": condition,
            },
            "identitySourceName": canonical([identity_source], stores)[0],
            "ifAuthFail": if_auth_fail,
            "ifUserNotFound": if_user_not_found,
            "ifProcessFail": if_process_fail,
        }
        details = {
            "policy_set": ps["name"],
            **rule_view(body),
            **landing(names, rank),
        }
        base = f"/api/v1/policy/{kind}/policy-set/{q(ps['id'])}/authentication"
        return await preview_or_apply(
            ctx,
            tool="ise_create_authn_rule",
            args={
                "policy_set": policy_set,
                "name": name,
                "conditions": conditions,
                "identity_source": identity_source,
                "kind": kind,
                "match": match,
                "if_auth_fail": if_auth_fail,
                "if_user_not_found": if_user_not_found,
                "if_process_fail": if_process_fail,
                "rank": rank,
                "enabled": enabled,
            },
            confirm=confirm,
            plan=Plan(
                f"Add authentication rule {name} to {ps['name']}",
                details=details,
                blockers=blockers,
                fingerprint=fingerprint(names),
            ),
            apply=lambda: _created(app.openapi.post(base, body)),
        )

    @reg.write(title="Create authorization rule")
    async def ise_create_authz_rule(
        ctx: Context,
        policy_set: Annotated[str, Field(description="Policy set name or id (see ise_list_policy_sets)")],
        name: Annotated[str, Field(description="Rule name")],
        conditions: ConditionList,
        profiles: Annotated[
            list[str] | None,
            Field(description="Network access: authorization profile names (see ise_list_authz_profiles)"),
        ] = None,
        sgt: Annotated[
            str | None, Field(description="Network access: security group (SGT) to assign")
        ] = None,
        command_sets: Annotated[
            list[str] | None,
            Field(description="Device admin: TACACS+ command sets (see ise_list_command_sets)"),
        ] = None,
        shell_profile: Annotated[
            str | None, Field(description="Device admin: TACACS+ shell profile (see ise_list_shell_profiles)")
        ] = None,
        kind: PolicyKind = "network-access",
        section: Annotated[
            Literal["authorization", "exception"],
            Field(
                description="'authorization' (normal rules) or 'exception' (local exceptions, evaluated "
                "before the set's authorization rules)"
            ),
        ] = "authorization",
        match: Match = "all",
        rank: Annotated[int, Field(ge=0, description="Position (0 = first); existing rules shift down")] = 0,
        enabled: Annotated[bool, Field(description="Create enabled (true) or disabled")] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add an authorization rule (or local exception) to a policy set: conditions -> result. Network
        access: authorization profiles (+ optional SGT), e.g. 'Session:ANCPolicy equals Quarantine' ->
        a quarantine profile. Device admin: command sets + shell profile, e.g. 'IdentityGroup:Name equals
        User Identity Groups:NetAdmins' -> PermitAll + priv 15. First match wins, so the preview shows the
        rules it lands between. Names are checked before anything is sent. Preview-first; change or
        disable later with ise_update_policy_rule."""
        app: IseApp = get_client(ctx)
        ps = await resolve_policy_set(app, kind, policy_set)
        rules = await section_rules(app, kind, str(ps["id"]), section)
        condition, blockers = await build_condition(app, kind, "authorization", conditions, match)
        if condition is None:
            raise InvalidRequest("Give at least one condition")
        rule: dict[str, Any] = {
            "name": name,
            "rank": rank,
            "state": "enabled" if enabled else "disabled",
            "default": False,
            "condition": condition,
        }
        body: dict[str, Any] = {"rule": rule}
        blockers += await _results(app, kind, body, profiles, sgt, command_sets, shell_profile, creating=True)
        names = rule_names(rules)
        if name.lower() in (n.lower() for n in names):
            blockers.append(f"Rule {name!r} already exists in {ps['name']} ({section})")
        details = {
            "policy_set": ps["name"],
            "section": section,
            **rule_view(body),
            **landing(names, rank),
        }
        base = f"/api/v1/policy/{kind}/policy-set/{q(ps['id'])}/{SECTION_PATH[section]}"
        return await preview_or_apply(
            ctx,
            tool="ise_create_authz_rule",
            args={
                "policy_set": policy_set,
                "name": name,
                "conditions": conditions,
                "profiles": profiles,
                "sgt": sgt,
                "command_sets": command_sets,
                "shell_profile": shell_profile,
                "kind": kind,
                "section": section,
                "match": match,
                "rank": rank,
                "enabled": enabled,
            },
            confirm=confirm,
            plan=Plan(
                f"Add {section} rule {name} to {ps['name']}",
                details=details,
                blockers=blockers,
                fingerprint=fingerprint(names),
            ),
            apply=lambda: _created(app.openapi.post(base, body)),
        )

    @reg.write(title="Update a policy rule")
    async def ise_update_policy_rule(
        ctx: Context,
        policy_set: Annotated[str, Field(description="Policy set name or id")],
        rule: Annotated[str, Field(description="Rule name or id (see ise_get_policy_set)")],
        section: Annotated[Section, Field(description="Which rule table the rule is in")] = "authorization",
        kind: PolicyKind = "network-access",
        state: Annotated[RuleState | None, Field(description="enabled, disabled or monitor")] = None,
        rank: Annotated[int | None, Field(ge=0, description="Move to this position (0 = first)")] = None,
        new_name: Annotated[str | None, Field(description="Rename the rule")] = None,
        conditions: Annotated[
            list[str] | None,
            Field(description="Replace the conditions (same syntax as ise_create_authz_rule)"),
        ] = None,
        match: Match = "all",
        profiles: Annotated[list[str] | None, Field(description="Replace the authorization profiles")] = None,
        sgt: Annotated[str | None, Field(description="Set the SGT ('' removes it)")] = None,
        command_sets: Annotated[list[str] | None, Field(description="Replace the command sets")] = None,
        shell_profile: Annotated[str | None, Field(description="Set the shell profile")] = None,
        identity_source: Annotated[
            str | None, Field(description="Authentication: new identity source")
        ] = None,
        if_user_not_found: Annotated[
            Literal["REJECT", "DROP", "CONTINUE"] | None, Field(description="Authentication: new action")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change one rule in a policy set: enable/disable/monitor it, move it, rename it, replace its
        conditions, or change its result (authorization profiles, SGT, command sets, shell profile,
        identity source). Only the given fields change. The Default rule's name, rank and condition are
        fixed, but its result can change. Preview-first with a field diff; takes effect at the next
        authentication (use ise_coa_reauth to apply it to a live session now)."""
        app: IseApp = get_client(ctx)
        ps = await resolve_policy_set(app, kind, policy_set)
        rules = await section_rules(app, kind, str(ps["id"]), section)
        target = find_rule(rules, rule, f"{ps['name']} ({section})")
        rule_id = str((target.get("rule") or {}).get("id"))
        path = f"/api/v1/policy/{kind}/policy-set/{q(ps['id'])}/{SECTION_PATH[section]}/{q(rule_id)}"
        current = strip_links(_resp(await app.openapi.get(path)))
        desired: dict[str, Any] = {**current, "rule": dict(current.get("rule") or {})}
        r = desired["rule"]
        blockers: list[str] = []
        is_default = bool(r.get("default"))
        if state is not None:
            r["state"] = state
        if rank is not None:
            r["rank"] = rank
        if new_name is not None:
            r["name"] = new_name
            others = [n.lower() for n, x in zip(rule_names(rules), rules, strict=True) if x is not target]
            if new_name.lower() in others:
                blockers.append(f"A rule named {new_name!r} already exists in {ps['name']} ({section})")
        if conditions is not None:
            if not conditions:
                raise InvalidRequest(
                    "Give at least one condition (an empty condition would match everything)"
                )
            scope = "authentication" if section == "authentication" else "authorization"
            cond, cond_blockers = await build_condition(app, kind, scope, conditions, match)
            blockers += cond_blockers
            r["condition"] = cond
        if is_default and any(x is not None for x in (rank, new_name, conditions)):
            blockers.append("The Default rule's name, rank and condition can't be changed")
        if section == "authentication":
            if any(x is not None for x in (profiles, sgt, command_sets, shell_profile)):
                raise InvalidRequest(
                    "Authentication rules have no profiles/SGT/command sets: use identity_source"
                )
            if identity_source is not None:
                stores = await name_list(app, f"/api/v1/policy/{kind}/identity-stores")
                blockers += missing([identity_source], stores, "identity source", "ise_list_identity_sources")
                desired["identitySourceName"] = canonical([identity_source], stores)[0]
            if if_user_not_found is not None:
                desired["ifUserNotFound"] = if_user_not_found
        else:
            if identity_source is not None or if_user_not_found is not None:
                raise InvalidRequest("identity_source/if_user_not_found only apply to authentication rules")
            blockers += await _results(app, kind, desired, profiles, sgt, command_sets, shell_profile)
        if desired == current:
            raise InvalidRequest("Nothing to change: give at least one field that differs")
        changes = field_changes(current, desired)
        if any(k.startswith("rule.condition") for k in changes):
            changes = {k: v for k, v in changes.items() if not k.startswith("rule.condition")}
            changes["rule.condition"] = {
                "from": render_condition((current.get("rule") or {}).get("condition")),
                "to": render_condition(r.get("condition")),
            }
        side = []
        if state == "disabled" or conditions is not None:
            side.append("Requests this rule no longer matches fall through to the next rule")
        return await preview_or_apply(
            ctx,
            tool="ise_update_policy_rule",
            args={
                "policy_set": policy_set,
                "rule": rule,
                "section": section,
                "kind": kind,
                "state": state,
                "rank": rank,
                "new_name": new_name,
                "conditions": conditions,
                "match": match,
                "profiles": profiles,
                "sgt": sgt,
                "command_sets": command_sets,
                "shell_profile": shell_profile,
                "identity_source": identity_source,
                "if_user_not_found": if_user_not_found,
            },
            confirm=confirm,
            plan=Plan(
                f"Update {section} rule {(current.get('rule') or {}).get('name')} in {ps['name']}",
                details={"changes": changes},
                fingerprint=fingerprint(current),
                blockers=blockers,
                side_effects=side,
            ),
            apply=lambda: _updated(app.openapi.put(path, desired), rule_view),
        )


async def _created(coro: Any) -> Any:
    """Shorten an OpenAPI create response to the new object's id/name."""
    data = _resp(await coro)
    if isinstance(data, dict):
        rule = data.get("rule")
        inner: dict[str, Any] = rule if isinstance(rule, dict) else data
        return compact({"id": inner.get("id"), "name": inner.get("name"), "rank": inner.get("rank")})
    return data


async def _updated(coro: Any, view: Callable[[dict[str, Any]], dict[str, Any]]) -> Any:
    """The updated object as ISE returned it, in the same compact shape the read tools use."""
    data = _resp(await coro)
    return view(data) if isinstance(data, dict) else data


def policy_set_view(ps: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = compact(
        {
            "name": ps.get("name"),
            "rank": ps.get("rank"),
            "state": ps.get("state"),
            "condition": "DEFAULT" if ps.get("default") else render_condition(ps.get("condition")),
            "allowed_protocols": ps.get("serviceName"),
        }
    )
    return out


async def _results(
    app: IseApp,
    kind: str,
    body: dict[str, Any],
    profiles: list[str] | None,
    sgt: str | None,
    command_sets: list[str] | None,
    shell_profile: str | None,
    *,
    creating: bool = False,
) -> list[str]:
    """Validate and set the result fields of an authorization rule body; returns blockers."""
    blockers: list[str] = []
    if kind == "network-access":
        if command_sets is not None or shell_profile is not None:
            raise InvalidRequest("command_sets/shell_profile are for device-admin rules; use profiles")
        if creating and not profiles:
            raise InvalidRequest("Give at least one authorization profile (e.g. PermitAccess)")
        if profiles is not None:
            known = await name_list(app, "/api/v1/policy/network-access/authorization-profiles")
            blockers += missing(profiles, known, "authorization profile", "ise_list_authz_profiles")
            body["profile"] = canonical(profiles, known)
        if sgt == "":
            body.pop("securityGroup", None)
        elif sgt is not None:
            known = await name_list(app, "/api/v1/policy/network-access/security-groups")
            blockers += missing([sgt], known, "security group", "ise_list_sgts")
            body["securityGroup"] = canonical([sgt], known)[0]
        return blockers
    if profiles is not None or sgt is not None:
        raise InvalidRequest("profiles/sgt are for network-access rules; use command_sets and shell_profile")
    if creating and not (command_sets or shell_profile):
        raise InvalidRequest("Give command_sets and/or shell_profile for a device-admin rule")
    if command_sets is not None:
        known = await name_list(app, "/api/v1/policy/device-admin/command-sets")
        blockers += missing(command_sets, known, "command set", "ise_list_command_sets")
        body["commands"] = canonical(command_sets, known)
    if shell_profile is not None:
        known = await name_list(app, "/api/v1/policy/device-admin/shell-profiles")
        blockers += missing([shell_profile], known, "shell profile", "ise_list_shell_profiles")
        body["profile"] = canonical([shell_profile], known)[0]
    return blockers

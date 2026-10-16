"""Client-side policy evaluator (I13): "which rule would this request hit?"

ISE has no evaluate API, so this walks the policy sets and authorization rules in rank order and
evaluates the conditions it understands against a set of request attributes the caller supplies
(`Dictionary:Attribute` -> value, e.g. `{"Radius:NAS-Port-Type": "Ethernet", "DEVICE:Location":
"All Locations#mcp-test-lab"}`). It is honest about its limits: a condition it can't evaluate
(a library reference it can't resolve, or an attribute the caller didn't supply) is `unknown`, not a
guess, and the result says so. It never calls ISE to make a decision - only to read the policy.

The evaluator is pure (see `evaluate`): True / False / None(=unknown), so it is unit-tested without an
appliance. A live regression test compares its prediction with MnT's actual matched rule.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from typing import Annotated, Any, Literal

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
from ise_mcp.tools._common import render_condition
from ise_mcp.tools.ad import NotJoined, ad_user_facts, all_join_points, strip_domain
from ise_mcp.tools.network import resolve_nad
from ise_mcp.tools.policy import PolicyKind, list_policy_sets, resolve_policy_set

Flow = Literal["wired-mab", "wired-dot1x", "wireless-mab", "wireless-dot1x"]

# What each access flow looks like to the policy engine (3.x dictionaries).
FLOW_ATTRIBUTES: dict[str, dict[str, str]] = {
    "wired-mab": {
        "Normalised Radius:RadiusFlowType": "WiredMAB",
        "Radius:NAS-Port-Type": "Ethernet",
        "Radius:Service-Type": "Call Check",
    },
    "wired-dot1x": {
        "Normalised Radius:RadiusFlowType": "Wired802_1x",
        "Radius:NAS-Port-Type": "Ethernet",
        "Radius:Service-Type": "Framed",
    },
    "wireless-mab": {
        "Normalised Radius:RadiusFlowType": "WirelessMAB",
        "Radius:NAS-Port-Type": "Wireless - IEEE 802.11",
        "Radius:Service-Type": "Call Check",
    },
    "wireless-dot1x": {
        "Normalised Radius:RadiusFlowType": "Wireless802_1x",
        "Radius:NAS-Port-Type": "Wireless - IEEE 802.11",
        "Radius:Service-Type": "Framed",
    },
}
# With a flow, assume a normal successful login: authentication passed and no ANC policy applied.
FLOW_DEFAULTS = {"Network Access:AuthenticationStatus": "AuthenticationPassed", "Session:ANCPolicy": ""}


def normalize_device_attrs(attrs: dict[str, Any]) -> dict[str, Any]:
    """DEVICE:<group type> values without the root, as ISE stores them in conditions: the NAD tools
    show 'Location#All Locations#Sydney', a condition compares 'All Locations#Sydney'."""
    out: dict[str, Any] = {}
    for key, value in attrs.items():
        dictionary, sep, attr = key.partition(":")
        if not sep and key.strip().casefold() in ("location", "device type"):
            dictionary, sep, attr = "DEVICE", ":", key  # a bare NDG attribute name
        if sep and dictionary.strip().casefold() == "device" and isinstance(value, str):
            root = attr.strip() + "#"
            if value.casefold().startswith(root.casefold()):
                value = value[len(root) :]
        out[key] = value
    return out


def nad_attributes(nad: dict[str, Any]) -> dict[str, str]:
    """Policy attributes a request through this NAD carries: its device groups and NAS IP."""
    out: dict[str, str] = {}
    for group in nad.get("NetworkDeviceGroupList") or []:
        root, sep, rest = str(group).partition("#")
        if sep:
            out[f"DEVICE:{root}"] = rest
    if nad.get("name"):
        out["Network Access:NetworkDeviceName"] = str(nad["name"])
    entries = [e for e in nad.get("NetworkDeviceIPList") or [] if isinstance(e, dict) and e.get("ipaddress")]
    # Only a device with exactly one host address has a known NAS-IP-Address.
    if len(entries) == 1 and str(entries[0].get("mask", "32")) in ("32", "128"):
        out["Radius:NAS-IP-Address"] = str(entries[0]["ipaddress"])
    return out


async def _authz_entries(app: IseApp, kind: str, ps_id: str, section: str) -> list[dict[str, Any]]:
    """Raw entries ({rule: {...condition tree...}, profile, securityGroup}) for a policy set's
    'authorization' or 'exception' section, in rank order. Unlike policy_set_rules, this keeps the
    condition tree the evaluator needs. ISE evaluates local exceptions before the standard rules."""
    try:
        data = await app.openapi.get(f"/api/v1/policy/{kind}/policy-set/{ps_id}/{section}")
    except (UpstreamError, NotFound):
        return []
    entries = data.get("response", data) if isinstance(data, dict) else data
    rows = [e for e in entries or [] if isinstance(e, dict)]
    return sorted(
        rows,
        key=lambda e: ((e.get("rule") or {}).get("rank") is None, (e.get("rule") or {}).get("rank") or 0),
    )


async def _global_exceptions(app: IseApp, kind: str) -> list[dict[str, Any]]:
    """Global authorization exceptions (ISE evaluates them before every policy set's rules), ranked."""
    try:
        data = await app.openapi.get(f"/api/v1/policy/{kind}/policy-set/global-exception")
    except (UpstreamError, NotFound):
        return []
    entries = data.get("response", data) if isinstance(data, dict) else data
    rows = [e for e in entries or [] if isinstance(e, dict)]
    return sorted(
        rows,
        key=lambda e: ((e.get("rule") or {}).get("rank") is None, (e.get("rule") or {}).get("rank") or 0),
    )


# Operators this evaluator understands. Everything is compared as a string unless the operator is
# numeric. ISE operator keys are camelCase in the OpenAPI condition model.
Result = bool | None  # True = matches, False = doesn't, None = unknown (can't tell)


def _num(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def eval_operator(op: str, actual: str, expected: str) -> Result:
    """Compare one attribute value. None when the operator isn't one we can evaluate."""
    a, e = actual.strip(), (expected or "").strip()
    al, el = a.casefold(), e.casefold()
    if op in ("equals", "notEquals"):
        res = al == el
        return res if op == "equals" else not res
    if op in ("contains", "notContains"):
        res = el in al
        return res if op == "contains" else not res
    if op == "startsWith":
        return al.startswith(el)
    if op == "endsWith":
        return al.endswith(el)
    if op in ("in", "notIn"):  # expected is a comma/CR separated set
        members = {m.strip().casefold() for m in re.split(r"[,\n]", e) if m.strip()}
        res = al in members
        return res if op == "in" else not res
    if op == "matches":  # ISE uses .* regex
        try:
            return re.fullmatch(e, a) is not None
        except re.error:
            return None
    if op in ("greaterThan", "lessThan", "greaterOrEquals", "lessOrEquals"):
        na, ne = _num(a), _num(e)
        if na is None or ne is None:
            return None
        return {
            "greaterThan": na > ne,
            "lessThan": na < ne,
            "greaterOrEquals": na >= ne,
            "lessOrEquals": na <= ne,
        }[op]
    return None  # unknown operator


def _attr_keys(cond: dict[str, Any]) -> list[str]:
    """Candidate attribute keys for a ConditionAttributes node, most specific first."""
    dn, an = cond.get("dictionaryName"), cond.get("attributeName")
    keys = []
    if dn and an:
        keys.append(f"{dn}:{an}")
    if an:
        keys.append(str(an))
    return keys


def _lookup(attrs: dict[str, Any], keys: list[str]) -> Any:
    lowered = {k.casefold(): v for k, v in attrs.items()}
    for k in keys:
        if k.casefold() in lowered:
            return lowered[k.casefold()]
    return None


def eval_multi(op: str, actual: Any, expected: str) -> Result:
    """One attribute comparison; `actual` may be a list (multi-valued attributes such as
    '<join point>:ExternalGroups': a user is in several groups). ISE matches a positive operator when
    any value matches, and a negated one (notEquals, notContains, notIn) when no value matches."""
    if not isinstance(actual, list):
        return eval_operator(op, str(actual), expected)
    negative = op in ("notEquals", "notContains", "notIn")
    positive = {"notEquals": "equals", "notContains": "contains", "notIn": "in"}.get(op, op)
    results = [eval_operator(positive, str(a), expected) for a in actual]
    if any(r is True for r in results):
        hit: Result = True
    elif any(r is None for r in results):
        return None
    else:
        hit = False
    return (not hit) if negative else hit


def evaluate(
    cond: Any, attrs: dict[str, Any], library: dict[str, Any], seen: set[str] | None = None
) -> Result:
    """Evaluate a condition tree against `attrs`. `library` maps a ConditionReference id/name to its
    resolved definition (so references evaluate recursively); a reference not in it is unknown.
    True/False/None(=unknown). A default/empty condition is True (matches anything)."""
    if not isinstance(cond, dict):
        return True  # null condition = DEFAULT / ANY
    seen = seen or set()
    ctype = str(cond.get("conditionType", ""))
    negate = bool(cond.get("isNegate"))

    def finish(r: Result) -> Result:
        if r is None or not negate:
            return r
        return not r

    if "AndBlock" in ctype or "OrBlock" in ctype:
        results = [evaluate(c, attrs, library, seen) for c in cond.get("children") or []]
        if "AndBlock" in ctype:
            if any(r is False for r in results):
                return finish(False)
            return finish(None if any(r is None for r in results) else True)
        if any(r is True for r in results):
            return finish(True)
        return finish(None if any(r is None for r in results) else False)
    if ctype == "ConditionReference" or (cond.get("name") and "dictionaryName" not in cond):
        ref = str(cond.get("id") or cond.get("name"))
        if ref in seen:  # a self-referential library condition: don't loop
            return finish(None)
        definition = library.get(ref) or library.get(str(cond.get("name")))
        if not isinstance(definition, dict):
            return finish(None)  # unresolved library condition -> unknown
        return finish(evaluate(definition, attrs, library, seen | {ref}))
    if "dictionaryName" in cond or "attributeName" in cond:
        if cond.get("dictionaryValue") is not None:
            return finish(None)  # compares against another attribute, not a literal -> can't tell
        expected = cond.get("attributeValue")
        if expected is None:
            return finish(None)  # no literal to compare against -> unknown, never "None" the string
        actual = _lookup(attrs, _attr_keys(cond))
        if actual is None:
            return finish(None)  # attribute not supplied -> unknown
        return finish(eval_multi(str(cond.get("operator", "equals")), actual, str(expected)))
    return finish(None)


def unknown_reasons(cond: Any, attrs: dict[str, Any], library: dict[str, Any]) -> list[str]:
    """Human-readable reasons a condition evaluated to unknown (missing attributes, unresolved
    references, unknown operators), for the honest-limits report."""
    out: list[str] = []

    def walk(c: Any) -> None:
        if not isinstance(c, dict):
            return
        ctype = str(c.get("conditionType", ""))
        if "AndBlock" in ctype or "OrBlock" in ctype:
            for child in c.get("children") or []:
                walk(child)
        elif ctype == "ConditionReference" or (c.get("name") and "dictionaryName" not in c):
            ref = str(c.get("id") or c.get("name"))
            if ref in library or str(c.get("name")) in library:
                walk(library.get(ref) or library.get(str(c.get("name"))))
            else:
                out.append(f"library condition {c.get('name')!r} not resolved")
        elif "dictionaryName" in c or "attributeName" in c:
            if _lookup(attrs, _attr_keys(c)) is None:
                out.append(f"no value supplied for {c.get('dictionaryName')}:{c.get('attributeName')}")
            elif eval_operator(str(c.get("operator", "equals")), "x", "y") is None and c.get(
                "operator"
            ) not in ("equals", "notEquals"):
                out.append(f"operator {c.get('operator')!r} not evaluated")

    walk(cond)
    return out


async def build_library(app: IseApp, kind: str) -> dict[str, Any]:
    """The reusable condition library keyed by both id and name, for reference resolution."""
    try:
        data = await app.openapi.get(f"/api/v1/policy/{kind}/condition")
    except (UpstreamError, NotFound):
        return {}
    items = data.get("response", data) if isinstance(data, dict) else data
    lib: dict[str, Any] = {}
    for c in items or []:
        if isinstance(c, dict):
            if c.get("id"):
                lib[str(c["id"])] = c
            if c.get("name"):
                lib[str(c["name"])] = c
    return lib


def _reference_ids(cond: Any, out: set[str]) -> None:
    if not isinstance(cond, dict):
        return
    ctype = str(cond.get("conditionType", ""))
    if "AndBlock" in ctype or "OrBlock" in ctype:
        for c in cond.get("children") or []:
            _reference_ids(c, out)
    elif (ctype == "ConditionReference" or (cond.get("name") and "dictionaryName" not in cond)) and cond.get(
        "id"
    ):
        out.add(str(cond["id"]))


async def resolve_references(app: IseApp, kind: str, conditions: list[Any], library: dict[str, Any]) -> None:
    """Fetch any ConditionReference (e.g. the built-in Wired_MAB / Wired_802.1X) not already in the
    bulk library by id, and add it (built-in system conditions aren't in the bulk condition list)."""
    wanted: set[str] = set()
    for cond in conditions:
        _reference_ids(cond, wanted)
    for cid in wanted - set(library):
        try:
            data = await app.openapi.get(f"/api/v1/policy/{kind}/condition/{cid}")
        except (UpstreamError, NotFound):
            continue
        definition = data.get("response", data) if isinstance(data, dict) else data
        if isinstance(definition, dict):
            library[cid] = definition
            if definition.get("name"):
                library[str(definition["name"])] = definition


def _result_word(r: Result) -> str:
    return {True: "match", False: "no-match", None: "unknown"}[r]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Explain which policy rule a request would hit")
    async def ise_policy_explain(
        ctx: Context,
        attributes: Annotated[
            dict[str, str | list[str]] | None,
            Field(
                description="Request attributes as 'Dictionary:Attribute' -> value (a list for "
                "multi-valued ones such as '<join point>:ExternalGroups'), e.g. "
                '{"Radius:NAS-Port-Type": "Ethernet", "DEVICE:Location": "All Locations#mcp-test-lab", '
                '"Network Access:EapAuthentication": "EAP-TLS"}. A bare attribute name also matches. '
                "NDG values may include the root ('Location#All Locations#X'). Optional with nad/flow."
            ),
        ] = None,
        kind: PolicyKind = "network-access",
        policy_set: Annotated[
            str | None,
            Field(description="Evaluate only this set's authorization rules; omit to select the set too"),
        ] = None,
        include_disabled: Annotated[
            bool, Field(description="Include disabled sets/rules (ISE skips them at runtime)")
        ] = False,
        nad: Annotated[
            str | None,
            Field(
                description="Network device the request comes through (name or IP): fills its device "
                "groups (DEVICE:Location, DEVICE:Device Type, ...), name and NAS IP"
            ),
        ] = None,
        flow: Annotated[
            Flow | None,
            Field(
                description="Access flow: fills RadiusFlowType, NAS-Port-Type and Service-Type (what "
                "Wired_MAB / Wired_802.1X / Wireless_* test) and assumes authentication passed and no "
                "ANC policy. Your `attributes` override anything filled in"
            ),
        ] = None,
        ad_user: Annotated[
            str | None,
            Field(
                description="AD username: looks the user up through every AD join point and fills "
                "'<join point>:ExternalGroups' with their groups, so AD-group rules evaluate"
            ),
        ] = None,
    ) -> ToolResult:
        """Predict which policy set and authorization rule a request would match, client-side (ISE has
        no evaluate API). Walks sets then authorization rules in rank order, evaluating the conditions
        it understands against `attributes`; a condition it can't evaluate (an unresolved library
        reference, a missing attribute, posture/profiler/time) is reported as 'unknown', never guessed,
        and the verdict is marked uncertain when an unknown rule outranks the first match. Use it to
        sanity-check a change before you make it; confirm against ise_get_auth_history for a real
        session. Not a substitute for ISE's own evaluation. Quickest form: nad='<switch>' and
        flow='wired-mab' (or wired-dot1x, wireless-*) plus any attributes you know (identity group,
        EAP type, endpoint profile); for AD users add ad_user='<username>'."""
        app: IseApp = get_client(ctx)
        given = dict(attributes or {})
        nad_note = None
        filled: dict[str, Any] = {}
        if flow:
            filled.update(FLOW_ATTRIBUTES[flow])
            filled.update(FLOW_DEFAULTS)
        if nad:
            nad_obj = await resolve_nad(app, nad, fuzzy=True)
            nad_note = nad_obj.get("resolved_from")
            filled.update(nad_attributes(nad_obj))
        ad_note: list[str] = []
        if ad_user:
            try:
                points = await all_join_points(app)
            except UpstreamError as e:
                points = []
                ad_note.append(f"Could not read the AD join points (ERS): {str(e)[:150]}")
            if not points and not ad_note:
                ad_note.append("No AD join point is configured: ad_user was ignored")
            for jp in points:
                try:
                    facts = await ad_user_facts(app, jp, strip_domain(ad_user))
                except (NotJoined, UpstreamError) as e:
                    ad_note.append(f"{jp.get('name')}: {str(e)[:150]}")
                    continue
                if facts.get("found"):
                    # Only groups added to the join point reach policy (ISE's ExternalGroups); the
                    # user's other groups would let contains/startsWith rules match wrongly.
                    filled[f"{jp.get('name')}:ExternalGroups"] = list(
                        facts.get("groups_usable_in_policy") or []
                    )
                else:
                    ad_note.append(f"{jp.get('name')}: {facts.get('detail')}")
        if flow and kind == "device-admin":
            raise InvalidRequest("flow is for network-access (RADIUS) requests; omit it for device-admin")
        full = {g.strip().casefold() for g in given}
        bare = {g.strip().casefold() for g in given if ":" not in g}
        assumed = {
            k: v
            for k, v in filled.items()
            if k.casefold() not in full and k.partition(":")[2].casefold() not in bare
        }
        attributes = normalize_device_attrs({**assumed, **given})
        if not attributes:
            raise InvalidRequest("Give attributes, or nad and/or flow to fill them in")
        library = await build_library(app, kind)
        sets = await list_policy_sets(app, kind)
        sets = sorted(sets, key=lambda p: (p.get("rank") is None, p.get("rank") or 0))
        await resolve_references(app, kind, [p.get("condition") for p in sets], library)

        set_trace: list[dict[str, Any]] = []
        chosen: dict[str, Any] | None = None
        uncertain_before = False
        if policy_set:
            chosen = await resolve_policy_set(app, kind, policy_set)
        else:
            for ps in sets:
                if not include_disabled and str(ps.get("state")) == "disabled":
                    continue
                r = True if ps.get("default") else evaluate(ps.get("condition"), attributes, library)
                row = {
                    "rank": ps.get("rank"),
                    "name": ps.get("name"),
                    "condition": "DEFAULT" if ps.get("default") else render_condition(ps.get("condition")),
                    "result": _result_word(r),
                }
                reasons = (
                    [] if ps.get("default") else unknown_reasons(ps.get("condition"), attributes, library)
                )
                if r is None and reasons:
                    row["unknown_because"] = reasons
                set_trace.append(row)
                if r is True:
                    chosen = ps
                    break
                if r is None:
                    uncertain_before = True  # an unknown set outranks the one we pick next
        if chosen is None:
            if uncertain_before:
                return object_result(
                    {
                        "verdict": "No policy set was confirmed to match.",
                        "note": "UNCERTAIN: one or more sets have a condition this evaluator could not "
                        "evaluate (see 'unknown_because'); one of them might match at runtime. No "
                        "default set is defined.",
                        "set_selection": set_trace,
                    }
                )
            return object_result(
                {
                    "verdict": "No policy set matched and there is no default set.",
                    "set_selection": set_trace,
                }
            )

        # ISE evaluates global exceptions first, then this set's local exceptions, then its rules.
        global_exc = await _global_exceptions(app, kind)
        exceptions = await _authz_entries(app, kind, str(chosen["id"]), "exception")
        rules = await _authz_entries(app, kind, str(chosen["id"]), "authorization")
        await resolve_references(
            app,
            kind,
            [(e.get("rule") or {}).get("condition") for e in global_exc + exceptions + rules],
            library,
        )
        rule_trace: list[dict[str, Any]] = []
        matched: dict[str, Any] | None = None
        uncertain = uncertain_before
        ordered = (
            [("global-exception", e) for e in global_exc]
            + [("exception", e) for e in exceptions]
            + [("authz", e) for e in rules]
        )
        for section, entry in ordered:
            rule = entry.get("rule") or {}
            if not include_disabled and str(rule.get("state")) == "disabled":
                continue
            r = True if rule.get("default") else evaluate(rule.get("condition"), attributes, library)
            row = {
                "section": section,
                "rank": rule.get("rank"),
                "name": rule.get("name"),
                "condition": "DEFAULT" if rule.get("default") else render_condition(rule.get("condition")),
                "result": _result_word(r),
                "profile": entry.get("profile"),
                "security_group": entry.get("securityGroup"),
            }
            reasons = (
                [] if rule.get("default") else unknown_reasons(rule.get("condition"), attributes, library)
            )
            if r is None and reasons:
                row["unknown_because"] = reasons
            rule_trace.append(row)
            if r is True:
                matched = row
                break
            if r is None:
                uncertain = True  # this rule might match at runtime, ahead of our pick

        verdict = (
            f"Would match '{matched['name']}' -> profile {matched.get('profile')}, SGT "
            f"{matched.get('security_group')}"
            if matched
            else "No authorization rule matched (not even Default)"
        )
        note = None
        if matched and uncertain:
            note = (
                "UNCERTAIN: a higher-ranked set or rule has a condition this evaluator could not "
                "evaluate (see 'unknown_because'); at runtime ISE might match it first. Treat the "
                "match as a best guess and confirm with ise_get_auth_history for a real session."
            )
        elif not matched and uncertain:
            note = "Some rules were unknown; the real result may differ. See 'unknown_because'."
        defaults = [k for k in FLOW_DEFAULTS if k in assumed]
        if defaults:
            note = (note + " " if note else "") + (
                "Assumes a normal login: authentication passed and no ANC policy on the endpoint; pass "
                "'Session:ANCPolicy' (see ise_list_anc_endpoints) or 'Network Access:AuthenticationStatus' "
                "to test otherwise."
            )
        return object_result(
            {
                "verdict": verdict,
                "note": note,
                "nad_resolved": nad_note,
                "ad_user": ad_note or None,
                "assumed_attributes": {k: v or "(none)" for k, v in assumed.items()} or None,
                "policy_set": chosen.get("name"),
                "set_selection": set_trace or "evaluated only the given policy_set",
                "authorization": rule_trace,
                "limits": "Conditions using posture, profiler logical profiles, time/date, identity-store "
                "group lookups (except AD groups via ad_user) or attributes you didn't supply evaluate to "
                "'unknown'. Global and local "
                "authorization exceptions are evaluated first (section='global-exception'/'exception'). "
                "This is a client-side prediction, not ISE's own evaluation.",
            }
        )

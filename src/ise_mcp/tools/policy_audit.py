"""Policy hygiene (I65): ise_policy_audit (ranked findings, each naming its fix tool) and
ise_unused_objects (objects ise_where_used finds no reference to).

ISE has no hygiene report over REST. The audit reads the policy (policy sets with their
authentication / authorization rules and local exceptions, and their hit counters), the
allowed-protocols services, authorization profiles and dACLs, network device groups and the devices in
them, and internal users, and reports what a pre-audit or an inherited-ISE review looks at first:

- disabled rules and policy sets; enabled rules with a zero hit counter (ISE's counters carry no
  timestamp: they count since the last reset, so a fresh reset gives the clean baseline);
- shadowed rules: a later rule that can never match because an earlier enabled rule matches everything
  it matches (no condition, the same condition tree, or a subset of its AND-ed conditions). Only those
  cases are provable from the configuration; when the earlier rule depends on time, posture or profiling
  state (which changes during a session) the finding says 'possible';
- permissive defaults: a Default authorization rule that returns PermitAccess (device admin: a default
  that permits all commands), a Default authentication rule that continues when the user is not found;
- weak allowed protocols: EAP-MD5, LEAP, MS-CHAPv1, PAP, weak EAP ciphers, Message-Authenticator not
  required (BlastRADIUS), and weak inner methods in EAP-TTLS;
- authorization profiles naming a dACL that does not exist;
- policy sets whose condition needs a network device group that has no devices (or does not exist);
- enabled internal users with no expiry date.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import NotFound, ToolRegistrar, UpstreamError, get_client, object_result
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list
from ise_mcp.tools.where_used import ERS_RESOURCE, Scan, find_references

AuditCheck = Literal[
    "disabled",
    "zero_hits",
    "shadowed",
    "permissive_default",
    "weak_protocols",
    "dangling_dacl",
    "empty_ndg",
    "user_expiry",
]
ALL_CHECKS: tuple[str, ...] = AuditCheck.__args__  # type: ignore[attr-defined]
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SECTION_LABEL = {
    "authentication": "authentication rule",
    "authorization": "authorization rule",
    "exception": "local exception",
}
USER_CAP = 500
PROFILE_CAP = 5000
UNUSED_CAP = 300

# Allowed-protocols flags: (path in the ERS object, severity, what it means).
WEAK_PROTOCOLS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (
        ("allowEapMd5",),
        "high",
        "EAP-MD5 (no mutual authentication, no key material, offline dictionary attack)",
    ),
    (("allowLeap",), "high", "LEAP (broken since 2003: offline dictionary attack with asleap)"),
    (("allowMsChapV1",), "high", "MS-CHAPv1 (DES-based, crackable)"),
    (("allowPapAscii",), "medium", "PAP/ASCII (password sent under the RADIUS shared secret only)"),
    (("allowWeakCiphersForEap",), "medium", "weak ciphers for EAP (3DES, RC4, ...)"),
    (("eapTtls", "eapTtlsMsChapV1"), "low", "EAP-TTLS inner MS-CHAPv1"),
    (("eapTtls", "eapTtlsEapMd5"), "low", "EAP-TTLS inner EAP-MD5"),
    (("eapTtls", "eapTtlsPapAscii"), "low", "EAP-TTLS inner PAP (inside the tunnel; fine for some clients)"),
)
# Flags that only mean something when the parent protocol is on.
PROTOCOL_PARENT = {"eapTtls": "allowEapTtls"}
BLAST_RADIUS = "Message-Authenticator not required on Access-Requests (BlastRADIUS, CVE-2024-3596)"
MAB_NOTE = " (MAB host lookups can arrive as PAP or EAP-MD5: check the MAB devices before turning it off)"
PROTOCOLS_GUI = "Policy > Policy Elements > Results > Authentication > Allowed Protocols"

# Dictionaries / attributes whose value changes during a session, so a rule on them may match at one
# authentication and not the next: a shadow behind such a rule is only 'possible'.
DYNAMIC_DICTIONARIES = {"datetime", "time and date", "posture", "endpoints"}
DYNAMIC_ATTRIBUTES = {"posturestatus", "logicalprofile", "endpointpolicy", "postureassessmentstatus"}
PROFILED_GROUP = "endpoint identity groups:profiled"

PERMIT_PROFILES = {"permitaccess"}
PERMIT_COMMANDS = {"permitallcommands"}

BUILTIN_DACLS = {
    "PERMIT_ALL_IPV4_TRAFFIC",
    "DENY_ALL_IPV4_TRAFFIC",
    "PERMIT_ALL_IPV6_TRAFFIC",
    "DENY_ALL_IPV6_TRAFFIC",
    "PERMIT_ALL_TRAFFIC",
    "DENY_ALL_TRAFFIC",
}

# Objects ISE ships with (and some it won't delete): reported apart from the rest by ise_unused_objects.
BUILTIN = {
    "authz_profile": {
        "permitaccess",
        "denyaccess",
        "cisco_ip_phones",
        "non_cisco_ip_phones",
        "cisco_webauth",
        "nsp_onboard",
        "block_wireless_access",
        "cisco_temporal_onboard",
        "udn",
    },
    "dacl": {d.lower() for d in BUILTIN_DACLS},
    "sgt": {"unknown", "any", "trustsec_devices"},
    "sgacl": {"permit ip", "deny ip", "deny_ip_log", "permit_ip_log"},
    # GuestType_* (default): the identity group of each default guest type (ISE ships them).
    "identity_group": {
        "all_accounts (default)",
        "group_accounts (default)",
        "own_accounts (default)",
        "guesttype_contractor (default)",
        "guesttype_daily (default)",
        "guesttype_weekly (default)",
        "guesttype_sociallogin (default)",
    },
    "endpoint_group": {"unknown", "profiled", "registereddevices", "blocked list", "guestendpoints"},
    "ndg": {
        "device type#all device types",
        "location#all locations",
        "ipsec#is ipsec device",
        "ipsec#is ipsec device#yes",
        "ipsec#is ipsec device#no",
    },
}


def is_builtin(kind: str, name: str) -> bool:
    """An object ISE ships with; also any 'GuestType_<type> (default)' identity group."""
    low = name.lower()
    if kind == "identity_group" and low.startswith("guesttype_") and low.endswith(" (default)"):
        return True
    return low in BUILTIN.get(kind, set())


UnusedKind = Literal["authz_profile", "dacl", "sgt", "sgacl", "identity_group", "endpoint_group", "ndg"]
DEFAULT_UNUSED_KINDS = ["authz_profile", "dacl", "sgt", "identity_group", "endpoint_group"]
NOT_CHECKED = {
    "sgt": "SXP bindings learned from peers and NAD TrustSec settings are not checked",
    "identity_group": "guest types and sponsor groups are not checked",
    "endpoint_group": "profiling policies that create matching groups are not checked",
    "authz_profile": "ANC policies and guest portals are not checked",
}


# --- condition analysis ---------------------------------------------------------------------------


def _norm(cond: Any) -> Any:
    """A hashable, order-insensitive form of a condition tree (library references by name)."""
    if not isinstance(cond, dict):
        return None
    ctype = str(cond.get("conditionType", ""))
    neg = bool(cond.get("isNegate"))
    if "Block" in ctype:
        op = "and" if "And" in ctype else "or"
        return (op, neg, frozenset(_norm(c) for c in cond.get("children") or []))
    if "dictionaryName" in cond or "attributeName" in cond:
        values = [
            cond.get("attributeValue"),
            cond.get("dictionaryValue"),
            *(cond.get("attributeValues") or []),
        ]
        return (
            "attr",
            neg,
            str(cond.get("dictionaryName", "")).lower(),
            str(cond.get("attributeName", "")).lower(),
            str(cond.get("operator", "equals")).lower(),
            tuple(sorted(str(v).lower() for v in values if v not in (None, ""))),
        )
    return ("ref", neg, str(cond.get("name") or cond.get("id") or "").lower())


def _and_terms(cond: Any) -> frozenset[Any]:
    """The AND-ed terms of a condition (one term for anything but a plain AND block)."""
    n = _norm(cond)
    if isinstance(n, tuple) and n[0] == "and" and not n[1]:
        return frozenset(n[2])
    return frozenset([n])


def _is_dynamic(cond: Any, library: dict[str, Any], seen: set[str] | None = None) -> bool:
    """True when the condition (through library references) tests time, posture or profiling state."""
    if not isinstance(cond, dict):
        return False
    seen = set() if seen is None else seen
    ctype = str(cond.get("conditionType", ""))
    if "time" in ctype.lower():
        return True
    if "Block" in ctype:
        return any(_is_dynamic(c, library, seen) for c in cond.get("children") or [])
    if "dictionaryName" in cond or "attributeName" in cond:
        dn = str(cond.get("dictionaryName", "")).lower()
        an = str(cond.get("attributeName", "")).lower()
        values = " ".join(
            str(v).lower() for v in [cond.get("attributeValue"), *(cond.get("attributeValues") or [])] if v
        )
        return dn in DYNAMIC_DICTIONARIES or an in DYNAMIC_ATTRIBUTES or PROFILED_GROUP in values
    key = str(cond.get("id") or cond.get("name"))
    if key in seen:
        return False
    seen.add(key)
    definition = library.get(str(cond.get("id"))) or library.get(str(cond.get("name")))
    return _is_dynamic(definition, library, seen)


def shadowed_by(
    earlier: list[dict[str, Any]], cond: Any, library: dict[str, Any]
) -> tuple[dict[str, Any], str, str] | None:
    """(earlier entry, certainty, why) for the first earlier enabled rule that matches everything `cond`
    matches, or None. `earlier` holds {name, condition} dicts, in rank order."""
    terms = _and_terms(cond)
    for e in earlier:
        ec = e.get("condition")
        if ec is None:
            why = "it has no condition (matches everything)"
        elif _norm(ec) == _norm(cond):
            why = "it has the same condition"
        elif cond is not None and _and_terms(ec) <= terms:
            why = "its conditions are a subset of this rule's AND-ed conditions"
        else:
            continue
        certainty = "possible" if _is_dynamic(ec, library) else "certain"
        return e, certainty, why
    return None


def _ndg_terms(
    cond: Any,
    library: dict[str, Any],
    ndg_types: set[str],
    required: bool = True,
    seen: set[str] | None = None,
) -> list[tuple[str, str, list[str], bool]]:
    """(type, operator, values, required) for every DEVICE:<NDG type> test in a condition tree.
    `required` is False under an OR block or a negation (the set can match without that group)."""
    if not isinstance(cond, dict):
        return []
    seen = set() if seen is None else seen
    ctype = str(cond.get("conditionType", ""))
    neg = bool(cond.get("isNegate"))
    if "Block" in ctype:
        child_required = required and not neg and "And" in ctype
        return [
            t
            for c in cond.get("children") or []
            for t in _ndg_terms(c, library, ndg_types, child_required, seen)
        ]
    if "dictionaryName" in cond or "attributeName" in cond:
        if str(cond.get("dictionaryName", "")).upper() != "DEVICE":
            return []
        attr = str(cond.get("attributeName", ""))
        op = str(cond.get("operator", "equals"))
        if attr.lower() not in ndg_types or neg or op.lower().startswith("not"):
            return []
        values = [str(v) for v in [cond.get("attributeValue"), *(cond.get("attributeValues") or [])] if v]
        return [(attr, op, values, required)]
    key = str(cond.get("id") or cond.get("name"))
    if key in seen:
        return []
    seen.add(key)
    definition = library.get(str(cond.get("id"))) or library.get(str(cond.get("name")))
    return _ndg_terms(definition, library, ndg_types, required and not neg, seen)


def _group_matches(op: str, want: str, group: str) -> bool:
    """Does a device's group (full NDG name, 'Location#All Locations#Lab') satisfy the test? Child
    groups count for equals too, so an NDG with devices only in its children is not called empty."""
    g, w = group.lower(), want.lower()
    op = op.lower()
    if op in ("contains", "matches"):
        return w in g
    if op == "endswith":
        return g.endswith(w)
    return g == w or g.startswith(w + "#")


# --- the audit ------------------------------------------------------------------------------------


class Audit:
    def __init__(self, app: IseApp, kind: str, checks: set[str]) -> None:
        self.app, self.kind, self.checks = app, kind, checks
        self.scan = Scan(app)
        self.findings: list[dict[str, Any]] = []

    def add(self, check: str, severity: str, where: dict[str, Any], detail: str, fix: dict[str, Any]) -> None:
        self.findings.append({"severity": severity, "check": check, **where, "detail": detail, "fix": fix})

    async def run(self, policy_set: str | None) -> None:
        sets = await self.scan.policy_sets(self.kind)
        if self.scan._sets.get(self.kind) is not None:
            if policy_set:
                key = policy_set.strip().lower()
                chosen = [
                    p for p in sets if key in (str(p.get("id")).lower(), str(p.get("name", "")).lower())
                ]
                if not chosen:
                    names = ", ".join(str(p.get("name")) for p in sets)
                    raise NotFound(f"No {self.kind} policy set {policy_set!r}. Existing: {names}", 404)
            else:
                chosen = sets
            library = await self.scan.library(self.kind) if self.checks & {"shadowed", "empty_ndg"} else {}
            await self._policy_sets(sets, chosen, library)
            for ps in chosen:
                if ps.get("state") != "disabled":  # the set's own finding covers its rules
                    await self._rules(ps, library)
            if "weak_protocols" in self.checks:
                await self._protocols(chosen)
            if "empty_ndg" in self.checks:
                await self._empty_ndgs(chosen, library)
        if "dangling_dacl" in self.checks and self.kind == "network-access" and not policy_set:
            await self._dangling_dacls()
        if "user_expiry" in self.checks and not policy_set:
            await self._user_expiry()

    def _set_where(self, ps: dict[str, Any]) -> dict[str, Any]:
        return {"where": "policy set", "policy_set": ps.get("name"), "rank": ps.get("rank")}

    async def _policy_sets(
        self, sets: list[dict[str, Any]], chosen: list[dict[str, Any]], library: dict[str, Any]
    ) -> None:
        chosen_ids = {str(p.get("id")) for p in chosen}
        earlier: list[dict[str, Any]] = []
        for ps in sorted(sets, key=lambda p: (p.get("rank") is None, p.get("rank") or 0)):
            name, state, is_default = ps.get("name"), ps.get("state"), bool(ps.get("default"))
            fix_args = {"policy_set": name, "kind": self.kind}
            if str(ps.get("id")) in chosen_ids and not is_default:
                if state == "disabled" and "disabled" in self.checks:
                    self.add(
                        "disabled",
                        "low",
                        self._set_where(ps),
                        "Policy set is disabled: none of its rules are evaluated",
                        {
                            "tool": "ise_update_policy_set",
                            "args": {**fix_args, "state": "enabled"},
                            "or": "ise_delete_policy_set (dangerous) if it is no longer needed",
                        },
                    )
                elif state == "enabled" and "zero_hits" in self.checks and ps.get("hitCounts") == 0:
                    self.add(
                        "zero_hits",
                        "low",
                        self._set_where(ps),
                        "Policy set has matched no request since the hit counters were last reset",
                        {
                            "tool": "ise_update_policy_set",
                            "args": {**fix_args, "state": "disabled"},
                            "or": "ise_delete_policy_set (dangerous) once it is confirmed unused",
                        },
                    )
                if state == "enabled" and "shadowed" in self.checks:
                    hit = shadowed_by(earlier, ps.get("condition"), library)
                    if hit:
                        e, certainty, why = hit
                        self.add(
                            "shadowed",
                            "medium" if certainty == "certain" else "low",
                            {**self._set_where(ps), "shadowed_by": e.get("name"), "certainty": certainty},
                            f"Never reached: policy set {e.get('name')!r} (rank {e.get('rank')}) "
                            f"comes first and {why}",
                            {
                                "tool": "ise_update_policy_set",
                                "args": {**fix_args, "rank": e.get("rank")},
                                "or": "change the earlier set's conditions, or disable this one",
                            },
                        )
            if state == "enabled" and not is_default:
                earlier.append(ps)

    async def _rules(self, ps: dict[str, Any], library: dict[str, Any]) -> None:
        ps_name, ps_id = str(ps.get("name")), str(ps.get("id"))
        set_zero = ps.get("hitCounts") == 0
        for section in ("authentication", "authorization", "exception"):
            entries = await self.scan.entries(self.kind, ps_id, section)
            earlier: list[dict[str, Any]] = []
            for entry in entries:
                rule = entry.get("rule") or {}
                name, state, is_default = rule.get("name"), rule.get("state"), bool(rule.get("default"))
                where = {
                    "where": SECTION_LABEL[section],
                    "policy_set": ps_name,
                    "rule": name,
                    "rank": rule.get("rank"),
                }
                fix_args = {"policy_set": ps_name, "rule": name, "section": section, "kind": self.kind}
                if is_default:
                    if "permissive_default" in self.checks:
                        self._permissive_default(section, entry, where, fix_args)
                    continue
                if state == "disabled":
                    if "disabled" in self.checks:
                        self.add(
                            "disabled",
                            "low",
                            where,
                            "Rule is disabled",
                            {
                                "tool": "ise_update_policy_rule",
                                "args": {**fix_args, "state": "enabled"},
                                "or": "ise_delete_policy_rule (dangerous) if it is no longer needed",
                            },
                        )
                    continue
                if state != "enabled":
                    continue  # monitor-only rules don't take effect and shadow nothing
                if "zero_hits" in self.checks and rule.get("hitCounts") == 0 and not set_zero:
                    self.add(
                        "zero_hits",
                        "info" if section == "exception" else "low",
                        where,
                        "Rule has matched no request since the hit counters were last reset",
                        {
                            "tool": "ise_update_policy_rule",
                            "args": {**fix_args, "state": "disabled"},
                            "or": "ise_delete_policy_rule (dangerous) once it is confirmed unused",
                        },
                    )
                if "shadowed" in self.checks:
                    hit = shadowed_by(earlier, rule.get("condition"), library)
                    if hit:
                        e, certainty, why = hit
                        self.add(
                            "shadowed",
                            "medium" if certainty == "certain" else "low",
                            {**where, "shadowed_by": e.get("name"), "certainty": certainty},
                            f"Never reached: rule {e.get('name')!r} (rank {e.get('rank')}) "
                            f"comes first and {why}",
                            {
                                "tool": "ise_update_policy_rule",
                                "args": {**fix_args, "rank": e.get("rank")},
                                "or": "narrow the earlier rule's conditions, or disable this one",
                            },
                        )
                earlier.append({"name": name, "rank": rule.get("rank"), "condition": rule.get("condition")})

    def _permissive_default(
        self, section: str, entry: dict[str, Any], where: dict[str, Any], fix_args: dict[str, Any]
    ) -> None:
        if section == "authorization":
            profiles = [str(p) for p in entry.get("profile") or []] if self.kind == "network-access" else []
            commands = [str(c) for c in entry.get("commands") or []] if self.kind == "device-admin" else []
            if any(p.lower() in PERMIT_PROFILES for p in profiles):
                self.add(
                    "permissive_default",
                    "high",
                    where,
                    f"The Default authorization rule returns {', '.join(profiles)}: anything that "
                    "authenticates and matches no other rule gets full access",
                    {"tool": "ise_update_policy_rule", "args": {**fix_args, "profiles": ["DenyAccess"]}},
                )
            if any(c.lower() in PERMIT_COMMANDS for c in commands):
                self.add(
                    "permissive_default",
                    "high",
                    where,
                    "The Default device-admin authorization rule permits all commands "
                    f"({', '.join(commands)})",
                    {
                        "tool": "ise_update_policy_rule",
                        "args": {**fix_args, "command_sets": ["DenyAllCommands"]},
                    },
                )
        elif section == "authentication" and str(entry.get("ifUserNotFound", "")).upper() == "CONTINUE":
            self.add(
                "permissive_default",
                "medium",
                where,
                "The Default authentication rule continues to authorization when the user is not found",
                {"tool": "ise_update_policy_rule", "args": {**fix_args, "if_user_not_found": "REJECT"}},
            )

    async def _protocols(self, chosen: list[dict[str, Any]]) -> None:
        used: dict[str, list[str]] = {}
        for ps in chosen:
            if ps.get("state") == "disabled":
                continue
            used.setdefault(str(ps.get("serviceName") or "").lower(), []).append(str(ps.get("name")))
        services = await self.scan.ers_details(ERS_RESOURCE["allowed_protocols"], 500)
        for svc in services:
            sets = used.get(str(svc.get("name", "")).lower())
            if not sets:
                continue  # a sequence (proxy) or a service no chosen policy set uses
            where = {"where": "allowed protocols", "service": svc.get("name"), "used_by": sets}
            fix = {
                "tool": "ise_set_allowed_protocols",
                "args": {"name": svc.get("name")},
                "gui": PROTOCOLS_GUI,
            }
            for path, severity, what in WEAK_PROTOCOLS:
                if self.kind == "device-admin" and path[-1] in ("allowPapAscii", "allowEapMd5", "allowLeap"):
                    continue  # TACACS+ PAP is encrypted by the TACACS+ body; EAP is RADIUS-only
                parent = PROTOCOL_PARENT.get(path[0])
                if parent and svc.get(parent) is not True:
                    continue
                value: Any = svc
                for key in path:
                    value = value.get(key) if isinstance(value, dict) else None
                if value is True:
                    note = ""
                    if path[-1] in ("allowPapAscii", "allowEapMd5") and svc.get("processHostLookup"):
                        note = MAB_NOTE
                    self.add(
                        "weak_protocols",
                        severity,
                        {**where, "flag": ".".join(path)},
                        f"Permits {what}{note}",
                        fix,
                    )
            if self.kind == "network-access" and svc.get("requireMessageAuth") is False:
                self.add(
                    "weak_protocols",
                    "medium",
                    {**where, "flag": "requireMessageAuth"},
                    BLAST_RADIUS,
                    fix,
                )

    async def _empty_ndgs(self, chosen: list[dict[str, Any]], library: dict[str, Any]) -> None:
        from ise_mcp.tools.network import all_nads  # noqa: PLC0415 - keeps the import graph shallow

        try:
            ndgs = await ers_list(self.app, "networkdevicegroup", limit=5000, offset=0)
        except (UpstreamError, NotFound) as e:
            self.scan._note("network device groups not readable", e)
            return
        names = {str(g.get("name")).lower(): str(g.get("name")) for g in ndgs.items if isinstance(g, dict)}
        types = {n.split("#", 1)[0] for n in names}
        terms_by_set = [
            (ps, _ndg_terms(ps.get("condition"), library, types))
            for ps in chosen
            if ps.get("state") != "disabled" and not ps.get("default")
        ]
        if not any(t for _, t in terms_by_set):
            return
        try:
            nads, complete = await all_nads(self.app)
        except (UpstreamError, NotFound) as e:
            self.scan._note("network devices not readable", e)
            return
        self.scan.scanned.append("networkdevice")
        if not complete:
            self.scan.incomplete.append("Only the first 1000 network devices were checked for empty groups")
            return  # an "empty" group could hold devices past the cap: no findings rather than wrong ones
        groups = [str(g) for n in nads for g in n.get("NetworkDeviceGroupList") or []]
        for ps, terms in terms_by_set:
            for attr, op, values, required in terms:
                for value in values:
                    full = value if value.lower().startswith(attr.lower() + "#") else f"{attr}#{value}"
                    if any(_group_matches(op, full, g) for g in groups):
                        continue
                    exists = op.lower() not in ("equals", "in") or full.lower() in names
                    detail = (
                        f"The condition DEVICE:{attr} {op} {value!r} matches no network device"
                        + ("" if exists else " (and no such device group exists)")
                        + ("" if required else "; the set can still match through its other conditions")
                    )
                    self.add(
                        "empty_ndg",
                        "medium" if required else "low",
                        {**self._set_where(ps), "device_group": full},
                        detail,
                        {
                            "tool": "ise_update_nad",
                            "args": {"groups": ["<the device's groups>", full]},
                            "or": "ise_update_policy_set (conditions) if the group is wrong",
                        },
                    )

    async def _dangling_dacls(self) -> None:
        profiles = await self.scan.ers_details("authorizationprofile", PROFILE_CAP)
        if not profiles:
            return
        try:
            dacls = await ers_list(self.app, "downloadableacl", limit=5000, offset=0)
        except (UpstreamError, NotFound) as e:
            self.scan._note("downloadable ACLs not readable", e)
            return
        self.scan.scanned.append("downloadableacl")
        known = {str(d.get("name")).lower() for d in dacls.items if isinstance(d, dict)}
        known |= {d.lower() for d in BUILTIN_DACLS}
        for prof in profiles:
            for field in ("daclName", "ipv6DaclName"):
                name = str(prof.get(field) or "")
                if name and name.lower() not in known:
                    self.add(
                        "dangling_dacl",
                        "high",
                        {"where": "authorization profile", "profile": prof.get("name"), "field": field},
                        f"Names dACL {name!r}, which does not exist: sessions given this profile fail "
                        "on the switch (dACL download fails)",
                        {
                            "tool": "ise_update_authz_profile",
                            "args": {"profile": prof.get("name"), "dacl": "<an existing dACL>"},
                            "or": f"ise_set_dacl to create {name!r}",
                        },
                    )

    async def _user_expiry(self) -> None:
        try:
            page = await ers_list(
                self.app, "internaluser", limit=USER_CAP, offset=0, detail=True, detail_cap=None
            )
        except (UpstreamError, NotFound) as e:
            self.scan._note("internal users not readable", e)
            return
        self.scan.scanned.append("internaluser")
        if page.more:
            self.scan.incomplete.append(f"Only the first {USER_CAP} internal users were checked for expiry")
        for user in page.items:
            if (
                isinstance(user, dict)
                and user.get("enabled") is not False
                and not user.get("expiryDateEnabled")
            ):
                self.add(
                    "user_expiry",
                    "info",
                    {"where": "internal user", "user": user.get("name")},
                    "Enabled internal user with no expiry date",
                    {
                        "tool": "ise_update_internal_user",
                        "args": {"user": user.get("name"), "enabled": False},
                        "or": "set an expiry date in the GUI (Administration > Identities > Users) "
                        "if it must stay",
                    },
                )


def _rank_key(f: dict[str, Any]) -> tuple[Any, ...]:
    return (
        SEVERITY_ORDER.get(f["severity"], 9),
        ALL_CHECKS.index(f["check"]),
        str(f.get("policy_set") or ""),
        f.get("rank") if isinstance(f.get("rank"), int) else 0,
    )


async def run_audit(
    app: IseApp, kind: str, policy_set: str | None, checks: list[str] | None, limit: int = 100
) -> dict[str, Any]:
    audit = Audit(app, kind, set(checks or ALL_CHECKS))
    await audit.run(policy_set)
    findings = sorted(audit.findings, key=_rank_key)
    summary: dict[str, int] = {}
    by_check: dict[str, int] = {}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
        by_check[f["check"]] = by_check.get(f["check"], 0) + 1
    out: dict[str, Any] = {
        "kind": kind,
        "policy_set": policy_set,
        "checks": sorted(audit.checks, key=ALL_CHECKS.index),
        "count": len(findings),
        "summary": {k: summary[k] for k in SEVERITY_ORDER if k in summary},
        "by_check": by_check,
        "findings": findings[:limit],
        "notes": [
            "Hit counters carry no timestamp: zero_hits means none since the counters were last reset.",
            "Shadowing is reported only where it is provable from the configuration (no condition, the same "
            "condition, or a subset of AND-ed conditions); 'possible' when the earlier rule depends on time, "
            "posture or profiling state.",
        ],
        "scanned": list(dict.fromkeys(audit.scan.scanned)),
    }
    if len(findings) > limit:
        out["truncated"] = (
            f"Showing the first {limit} of {len(findings)} findings (most severe first): raise limit, "
            "narrow with checks or policy_set"
        )
    if audit.scan.incomplete:
        out["incomplete"] = list(dict.fromkeys(audit.scan.incomplete))
    return out


# --- unused objects -------------------------------------------------------------------------------


async def run_unused(app: IseApp, kinds: list[str], include_builtin: bool) -> dict[str, Any]:
    scan = Scan(app)
    unused: dict[str, list[dict[str, Any]]] = {}
    builtin_unused: dict[str, list[str]] = {}
    counts: dict[str, dict[str, int]] = {}
    for kind in dict.fromkeys(kinds):
        resource = ERS_RESOURCE[kind]
        try:
            page = await ers_list(app, resource, limit=UNUSED_CAP, offset=0)
        except (UpstreamError, NotFound) as e:
            scan._note(f"{resource} not readable", e)
            continue
        if page.more:
            scan.incomplete.append(f"Only the first {UNUSED_CAP} {kind} objects were checked")
        rows: list[dict[str, Any]] = []
        for obj in page.items:
            if not isinstance(obj, dict):
                continue
            result = await find_references(app, kind, obj, scan)
            if result["used"]:
                continue
            name = str(obj.get("name"))
            if is_builtin(kind, name) and not include_builtin:
                builtin_unused.setdefault(kind, []).append(name)
                continue
            rows.append(
                {
                    "name": name,
                    "id": obj.get("id"),
                    "fix": {"tool": "ise_delete_object", "args": {"kind": kind, "target": name}},
                }
            )
        unused[kind] = rows
        counts[kind] = {"checked": len(page.items), "unused": len(rows)}
    out: dict[str, Any] = {
        "kinds": list(dict.fromkeys(kinds)),
        "counts": counts,
        "unused": unused,
        "note": "Unused = ise_where_used finds no reference. ise_delete_object previews the same scan and "
        "blocks the delete when something does use the object.",
    }
    if builtin_unused:
        out["built_in_unused"] = builtin_unused
    not_checked = [f"{k}: {NOT_CHECKED[k]}" for k in out["kinds"] if k in NOT_CHECKED]
    if not_checked:
        out["not_checked"] = not_checked
    out["scanned"] = list(dict.fromkeys(scan.scanned))
    if scan.incomplete:
        out["incomplete"] = list(dict.fromkeys(scan.incomplete))
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Audit ISE policy hygiene")
    async def ise_policy_audit(
        ctx: Context,
        kind: Annotated[
            Literal["network-access", "device-admin"],
            Field(description="'network-access' (RADIUS) or 'device-admin' (TACACS+)"),
        ] = "network-access",
        policy_set: Annotated[
            str | None,
            Field(description="Only this policy set (name or id); skips the dACL and internal-user checks"),
        ] = None,
        checks: Annotated[
            list[AuditCheck] | None,
            Field(
                description="Run only these checks (default all): disabled, zero_hits, shadowed, "
                "permissive_default, weak_protocols, dangling_dacl, empty_ndg, user_expiry"
            ),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500, description="Most findings to return")] = 100,
    ) -> ToolResult:
        """Policy hygiene audit, for a pre-audit, a quarterly clean-up or an inherited ISE: ranked
        findings (high, medium, low, info), each with where it is and the tool that fixes it.
        Checks: disabled rules and policy sets; enabled rules with zero hits (counters have no
        timestamp: zero since the last reset); rules and policy sets shadowed by an earlier one (no
        condition, the same condition, or a subset of its AND-ed conditions; 'possible' when the earlier
        rule tests time, posture or profiling); Default rules that permit (PermitAccess, PermitAllCommands,
        continue on user-not-found); allowed-protocols services used by a policy set that permit EAP-MD5,
        LEAP, MS-CHAPv1, PAP, weak EAP ciphers or don't require Message-Authenticator (BlastRADIUS);
        authorization profiles naming a missing dACL; policy sets whose condition needs a device group
        with no devices; enabled internal users with no expiry. 'incomplete' lists anything ISE wouldn't
        return. Read-only; nothing is changed."""
        app: IseApp = get_client(ctx)
        return object_result(await run_audit(app, kind, policy_set, list(checks) if checks else None, limit))

    @reg.read(title="Find unused ISE objects")
    async def ise_unused_objects(
        ctx: Context,
        kinds: Annotated[
            list[UnusedKind] | None,
            Field(
                description="Object kinds to check (default authz_profile, dacl, sgt, identity_group, "
                "endpoint_group; also sgacl, ndg)"
            ),
        ] = None,
        include_builtin: Annotated[
            bool,
            Field(description="List objects ISE ships with (PermitAccess, Unknown SGT, ...) with the rest"),
        ] = False,
    ) -> ToolResult:
        """Objects nothing references, for a clean-up: authorization profiles, dACLs, SGTs, SGACLs,
        identity and endpoint groups, network device groups for which the ise_where_used scan (policy
        sets and rules, library conditions, profiles, identity sequences, egress matrix, devices, group
        members) finds no use, each with its ise_delete_object call. Built-in objects are listed apart
        unless include_builtin (the GuestType_* (default) groups among them). SGTs bound in static IP-SGT
        mappings or mapping groups count as used. 'not_checked' names what the scan does not cover per
        kind (e.g. SXP bindings learned from peers) and 'incomplete' anything ISE wouldn't return:
        check those before deleting. Up to 300 objects per kind. Read-only."""
        app: IseApp = get_client(ctx)
        return object_result(await run_unused(app, list(kinds or DEFAULT_UNUSED_KINDS), include_builtin))

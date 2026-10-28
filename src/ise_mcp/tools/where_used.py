"""ise_where_used (I64): which policy sets, rules, profiles, sequences, egress matrix cells and network
devices reference an ISE object.

ISE has no "where used" API. This reads the policy (network access and device admin: policy sets,
authentication and authorization rules, local and global exceptions, the library conditions they
reference) and the ERS objects that point at other objects (authorization profiles -> dACLs, identity
sequences -> identity stores and certificate profiles, egress cells -> SGTs and SGACLs, NADs -> device
groups), and reports every reference with where it sits. Conditions are followed through library
conditions (`via` names the library condition a match came through), using the same reference
resolution as ise_policy_explain.

`find_references` is the shared scan: ise_delete_object builds its "still in use" blockers from it.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

from collections.abc import Callable
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import InvalidRequest, NotFound, ToolRegistrar, UpstreamError, get_client, object_result
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list, ers_resolve
from ise_mcp.tools.policy import list_policy_sets
from ise_mcp.tools.policy_explain import build_library, resolve_references

WhereKind = Literal[
    "authz_profile",
    "dacl",
    "sgt",
    "sgacl",
    "identity_group",
    "endpoint_group",
    "ndg",
    "condition",
    "allowed_protocols",
    "identity_sequence",
    "cert_profile",
    "ad_join_point",
    "ad_group",
    "command_set",
    "shell_profile",
]

ERS_RESOURCE = {
    "authz_profile": "authorizationprofile",
    "dacl": "downloadableacl",
    "sgt": "sgt",
    "sgacl": "sgacl",
    "identity_group": "identitygroup",
    "endpoint_group": "endpointgroup",
    "ndg": "networkdevicegroup",
    "allowed_protocols": "allowedprotocols",
    "identity_sequence": "idstoresequence",
    "cert_profile": "certificateprofile",
    "ad_join_point": "activedirectory",
    "command_set": "tacacscommandsets",
    "shell_profile": "tacacsprofile",
}

LIST_TOOL = {
    "authz_profile": "ise_list_authz_profiles",
    "dacl": "ise_list_dacls",
    "sgt": "ise_list_sgts",
    "sgacl": "ise_list_sgacls",
    "identity_group": "ise_list_identity_groups",
    "endpoint_group": "ise_list_endpoint_groups",
    "ndg": "ise_list_ndgs",
    "condition": "ise_list_conditions",
    "allowed_protocols": "ise_list_allowed_protocols",
    "identity_sequence": "ise_list_identity_sources",
    "cert_profile": "ise_list_identity_sources",
    "ad_join_point": "ise_list_identity_sources",
    "command_set": "ise_list_command_sets",
    "shell_profile": "ise_list_shell_profiles",
}

POLICY_KINDS = ("network-access", "device-admin")
MATRIX_CELL_CAP = 2000
PROFILE_CAP = 5000
# The sections of a policy set, as ISE's OpenAPI paths name them, and how a reference is labelled.
SECTIONS = {
    "authentication": "authentication rule",
    "authorization": "authorization rule",
    "exception": "local exception",
}
GROUP_DICTIONARIES = {"identitygroup", "internaluser", "endpoints"}
GROUP_ROOT = {"identity_group": "User Identity Groups", "endpoint_group": "Endpoint Identity Groups"}

Match = Callable[[dict[str, Any]], bool]


def _response(data: Any) -> Any:
    return data.get("response", data) if isinstance(data, dict) else data


def _ranked(entries: Any) -> list[dict[str, Any]]:
    rows = [e for e in entries or [] if isinstance(e, dict)]
    return sorted(
        rows,
        key=lambda e: ((e.get("rule") or {}).get("rank") is None, (e.get("rule") or {}).get("rank") or 0),
    )


def _is_reference(cond: dict[str, Any]) -> bool:
    ctype = str(cond.get("conditionType", ""))
    return ctype == "ConditionReference" or (
        bool(cond.get("name")) and "dictionaryName" not in cond and "Block" not in ctype
    )


def _values(cond: dict[str, Any]) -> list[str]:
    out = [cond.get("attributeValue"), cond.get("dictionaryValue")]
    out += list(cond.get("attributeValues") or [])
    return [str(v) for v in out if v not in (None, "")]


def condition_hits(
    cond: Any, library: dict[str, Any], match: Match, via: str | None = None, seen: set[str] | None = None
) -> list[str | None]:
    """Where `match` holds in a condition tree: None for a direct match, else the name of the library
    condition the match came through. Library references are followed (once each)."""
    if not isinstance(cond, dict):
        return []
    seen = set() if seen is None else seen
    out: list[str | None] = [via] if match(cond) else []
    ctype = str(cond.get("conditionType", ""))
    if "Block" in ctype:
        for child in cond.get("children") or []:
            out += condition_hits(child, library, match, via, seen)
    elif _is_reference(cond):
        key = str(cond.get("id") or cond.get("name"))
        definition = library.get(str(cond.get("id"))) or library.get(str(cond.get("name")))
        if isinstance(definition, dict) and key not in seen:
            seen.add(key)
            out += condition_hits(definition, library, match, via or str(cond.get("name")), seen)
    return list(dict.fromkeys(out))


# --- matchers for attribute conditions ------------------------------------------------------------


def group_matcher(kind: str, name: str) -> Match:
    """IdentityGroup:Name equals 'User Identity Groups:Employee' (or 'Endpoint Identity Groups:
    Profiled:Cisco-IP-Phone' for an endpoint group, matched on its last segment)."""
    root = GROUP_ROOT[kind].lower() + ":"
    want = name.lower()

    def match(cond: dict[str, Any]) -> bool:
        if str(cond.get("dictionaryName", "")).lower() not in GROUP_DICTIONARIES:
            return False
        for v in _values(cond):
            low = v.lower()
            if low.startswith(root):
                rest = low[len(root) :]
                if rest == want or rest.endswith(":" + want):
                    return True
        return False

    return match


def ndg_matcher(name: str) -> Match:
    """DEVICE:Location equals 'All Locations#Lab' for the group 'Location#All Locations#Lab'."""
    group_type, _, path = name.partition("#")

    def match(cond: dict[str, Any]) -> bool:
        if str(cond.get("dictionaryName", "")).upper() != "DEVICE":
            return False
        if str(cond.get("attributeName", "")).lower() != group_type.lower():
            return False
        return any(v.lower() in (path.lower(), name.lower()) for v in _values(cond))

    return match


def ad_group_matcher(target: str) -> Match:
    """'<join point>:ExternalGroups equals domain/OU/group'; the target is 'JOINPOINT:group' or a bare
    group (any join point), matched on the full path or its last part."""
    join_point, sep, group = target.rpartition(":")
    if not sep:
        join_point, group = "", target
    want = group.strip().lower()

    def match(cond: dict[str, Any]) -> bool:
        if str(cond.get("attributeName", "")).lower() != "externalgroups":
            return False
        if join_point and str(cond.get("dictionaryName", "")).lower() != join_point.strip().lower():
            return False
        return any(v.lower() == want or v.lower().endswith("/" + want) for v in _values(cond))

    return match


def join_point_matcher(name: str) -> Match:
    return lambda cond: str(cond.get("dictionaryName", "")).lower() == name.lower()


def reference_matcher(obj: dict[str, Any]) -> Match:
    oid, name = str(obj.get("id") or ""), str(obj.get("name") or "").lower()

    def match(cond: dict[str, Any]) -> bool:
        if not _is_reference(cond):
            return False
        return (bool(oid) and str(cond.get("id")) == oid) or str(cond.get("name", "")).lower() == name

    return match


# --- the scan -------------------------------------------------------------------------------------


class Scan:
    """Reads (once each) what the reference checks need, recording anything ISE wouldn't return."""

    def __init__(self, app: IseApp) -> None:
        self.app = app
        self.incomplete: list[str] = []
        self.scanned: list[str] = []
        self._sets: dict[str, list[dict[str, Any]] | None] = {}
        self._entries: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        self._libraries: dict[str, dict[str, Any]] = {}

    def _note(self, what: str, err: Exception) -> None:
        self.incomplete.append(f"{what}: {str(err)[:160]}")

    async def policy_sets(self, kind: str) -> list[dict[str, Any]]:
        if kind not in self._sets:
            try:
                self._sets[kind] = await list_policy_sets(self.app, kind)
                self.scanned.append(f"{kind} policy sets")
            except (UpstreamError, NotFound) as e:
                self._sets[kind] = None
                self._note(f"{kind} policy sets not readable", e)
        return self._sets[kind] or []

    async def entries(self, kind: str, ps_id: str, section: str) -> list[dict[str, Any]]:
        key = (kind, ps_id, section)
        if key not in self._entries:
            path = f"/api/v1/policy/{kind}/policy-set/{ps_id}"
            path = path if section == "global-exception" else f"{path}/{section}"
            try:
                self._entries[key] = _ranked(_response(await self.app.openapi.get(path)))
            except NotFound:
                self._entries[key] = []
            except UpstreamError as e:
                self._entries[key] = []
                self._note(f"{kind} {section} rules of {ps_id} not readable", e)
        return self._entries[key]

    async def rules(self, kind: str, sections: tuple[str, ...]) -> list[tuple[str, str, dict[str, Any]]]:
        """(policy set name, section, raw entry) for the given sections of every set, plus the global
        exceptions when 'exception' is asked for."""
        out: list[tuple[str, str, dict[str, Any]]] = []
        sets = await self.policy_sets(kind)
        if "exception" in sections and self._sets.get(kind) is not None:
            for e in await self.entries(kind, "global-exception", "global-exception"):
                out.append(("(global exceptions)", "global-exception", e))
        for ps in sets:
            for section in sections:
                for e in await self.entries(kind, str(ps.get("id")), section):
                    out.append((str(ps.get("name")), section, e))
        return out

    async def library(self, kind: str) -> dict[str, Any]:
        """The condition library, plus every referenced condition the bulk list leaves out."""
        if kind not in self._libraries:
            lib = await build_library(self.app, kind)
            conditions = [ps.get("condition") for ps in await self.policy_sets(kind)]
            for _, _, e in await self.rules(kind, ("authentication", "authorization", "exception")):
                conditions.append((e.get("rule") or {}).get("condition"))
            conditions += [c for c in list(lib.values()) if isinstance(c, dict)]
            await resolve_references(self.app, kind, conditions, lib)
            self._libraries[kind] = lib
        return self._libraries[kind]

    async def ers_details(self, resource: str, cap: int) -> list[dict[str, Any]]:
        try:
            page = await ers_list(self.app, resource, limit=cap, offset=0, detail=True, detail_cap=None)
        except (UpstreamError, NotFound) as e:
            self._note(f"{resource} not readable", e)
            return []
        self.scanned.append(resource)
        return [i for i in page.items if isinstance(i, dict)]


def _rule_ref(
    kind: str, ps: str, section: str, entry: dict[str, Any], field: str, via: str | None
) -> dict[str, Any]:
    rule = entry.get("rule") or {}
    where = "global exception" if section == "global-exception" else SECTIONS[section]
    if kind == "device-admin":
        where = f"device-admin {where}"
    ref: dict[str, Any] = {
        "where": where,
        "policy_kind": kind,
        "policy_set": ps,
        "rule": rule.get("name"),
        "field": field,
        "label": f"{ps} / {rule.get('name')}",
    }
    if rule.get("state") and rule.get("state") != "enabled":
        ref["state"] = rule.get("state")
    if via:
        ref["via"] = via
    return ref


def _value_in(value: Any, name: str) -> bool:
    values = value if isinstance(value, list) else [value]
    return any(isinstance(v, str) and v.lower() == name.lower() for v in values)


async def _rule_field_refs(
    scan: Scan, kinds: tuple[str, ...], sections: tuple[str, ...], field: str, name: str
) -> list[dict[str, Any]]:
    out = []
    for kind in kinds:
        for ps, section, e in await scan.rules(kind, sections):
            if _value_in(e.get(field), name):
                out.append(_rule_ref(kind, ps, section, e, field, None))
    return out


async def _condition_refs(scan: Scan, match: Match) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for kind in POLICY_KINDS:
        sets = await scan.policy_sets(kind)
        if scan._sets.get(kind) is None:
            continue
        library = await scan.library(kind)
        for ps in sets:
            for via in condition_hits(ps.get("condition"), library, match):
                ref = {
                    "where": "policy set" if kind == "network-access" else "device-admin policy set",
                    "policy_kind": kind,
                    "policy_set": ps.get("name"),
                    "field": "condition",
                    "label": str(ps.get("name")),
                }
                out.append({**ref, "via": via} if via else ref)
        for ps_name, section, e in await scan.rules(kind, ("authentication", "authorization", "exception")):
            for via in condition_hits((e.get("rule") or {}).get("condition"), library, match):
                out.append(_rule_ref(kind, ps_name, section, e, "condition", via))
        seen_ids: set[str] = set()
        for cond in library.values():
            if not isinstance(cond, dict) or str(cond.get("id")) in seen_ids:
                continue
            seen_ids.add(str(cond.get("id")))
            # Children only: a library condition doesn't reference itself.
            hits = [h for c in cond.get("children") or [] for h in condition_hits(c, library, match)]
            if not cond.get("children") and match(cond) and not _is_reference(cond):
                hits = [None]
            if hits:
                out.append(
                    {
                        "where": "library condition",
                        "policy_kind": kind,
                        "condition": cond.get("name"),
                        "label": str(cond.get("name")),
                    }
                )
    return out


async def _members(app: IseApp, kind: str, obj: dict[str, Any]) -> dict[str, Any]:
    name, oid = str(obj.get("name")), str(obj.get("id"))

    async def ers_count(resource: str, filt: str) -> int:
        page = await app.ers_pager.fetch_page(app.ers, f"/ers/config/{resource}", {"filter": filt}, limit=1)
        return page.total or len(page.items)

    if kind == "identity_group" and (n := await ers_count("internaluser", f"identityGroup.EQ.{name}")):
        return {"internal_users": n}
    if kind == "endpoint_group":
        eps = await app.openapi.get("/api/v1/endpoint", {"filter": f"groupId.EQ.{oid}", "page": 1, "size": 1})
        if eps:
            return {"endpoints": "at least 1 (see ise_list_endpoints group=...)"}
    return {}


async def resolve_target(app: IseApp, kind: str, name: str) -> dict[str, Any]:
    """The object as ISE has it ({name, id, ...}); an AD group is taken as given."""
    if kind == "ad_group":
        if not name.strip():
            raise InvalidRequest("Give an AD group ('JOINPOINT:domain/OU/group' or the group name)")
        return {"name": name.strip()}
    if kind == "condition":
        key = name.strip().lower()
        for pk in POLICY_KINDS:
            for cid, cond in (await build_library(app, pk)).items():
                if isinstance(cond, dict) and key in (cid.lower(), str(cond.get("name", "")).lower()):
                    return {"name": cond.get("name"), "id": cond.get("id"), "policy_kind": pk}
        raise NotFound(f"No library condition named {name!r}. Use ise_list_conditions.", 404)
    return await ers_resolve(
        app, ERS_RESOURCE[kind], name, what=kind.replace("_", " "), list_tool=LIST_TOOL[kind]
    )


async def find_references(  # noqa: C901
    app: IseApp, kind: str, obj: dict[str, Any], scan: Scan | None = None
) -> dict[str, Any]:
    """Every reference to `obj` (an ERS object or {name, id}) of `kind`; see the module docstring.
    Pass a `scan` to reuse its reads across many objects (ise_unused_objects)."""
    scan = scan or Scan(app)
    name, oid = str(obj.get("name")), str(obj.get("id") or "")
    refs: list[dict[str, Any]] = []
    if kind == "authz_profile":
        refs += await _rule_field_refs(
            scan, ("network-access",), ("authorization", "exception"), "profile", name
        )
    elif kind in ("command_set", "shell_profile"):
        field = "commands" if kind == "command_set" else "profile"
        refs += await _rule_field_refs(scan, ("device-admin",), ("authorization", "exception"), field, name)
    elif kind == "sgt":
        refs += await _rule_field_refs(
            scan, ("network-access",), ("authorization", "exception"), "securityGroup", name
        )
        for field, filt in (("source", "sgtSrcName"), ("destination", "sgtDstName")):
            try:
                page = await app.ers_pager.fetch_page(
                    app.ers,
                    "/ers/config/egressmatrixcell",
                    {"filter": f"{filt}.EQ.{name}"},
                    limit=MATRIX_CELL_CAP,
                )
            except (UpstreamError, NotFound) as e:
                scan._note("egress matrix not readable", e)
                continue
            for cell in page.items:
                refs.append(
                    {"where": "egress cell", "field": field, "cell": cell.get("name"), "id": cell.get("id")}
                )
        scan.scanned.append("egress matrix")
    elif kind == "sgacl":
        for cell in await scan.ers_details("egressmatrixcell", MATRIX_CELL_CAP):
            if oid in [str(a) for a in cell.get("sgacls") or []]:
                refs.append(
                    {
                        "where": "egress cell",
                        "field": "sgacls",
                        "cell": cell.get("name"),
                        "id": cell.get("id"),
                    }
                )
    elif kind == "dacl":
        for prof in await scan.ers_details("authorizationprofile", PROFILE_CAP):
            for field in ("daclName", "ipv6DaclName"):
                if str(prof.get(field) or "").lower() == name.lower():
                    refs.append(
                        {"where": "authorization profile", "profile": prof.get("name"), "field": field}
                    )
    elif kind in ("identity_group", "endpoint_group"):
        refs += await _condition_refs(scan, group_matcher(kind, name))
    elif kind == "ndg":
        refs += await _condition_refs(scan, ndg_matcher(name))
        from ise_mcp.tools.network import all_nads  # noqa: PLC0415 - keeps the import graph shallow

        try:
            nads, complete = await all_nads(app)
            scan.scanned.append("networkdevice")
            if not complete:
                scan.incomplete.append("Only the first 1000 network devices were checked")
        except (UpstreamError, NotFound) as e:
            nads = []
            scan._note("network devices not readable", e)
        for nad in nads:
            groups = [str(g).lower() for g in nad.get("NetworkDeviceGroupList") or []]
            if name.lower() in groups or any(g.startswith(name.lower() + "#") for g in groups):
                refs.append({"where": "network device", "nad": nad.get("name"), "id": nad.get("id")})
    elif kind == "condition":
        refs += await _condition_refs(scan, reference_matcher(obj))
    elif kind == "ad_group":
        refs += await _condition_refs(scan, ad_group_matcher(name))
    elif kind == "allowed_protocols":
        for pk in POLICY_KINDS:
            for ps in await scan.policy_sets(pk):
                if str(ps.get("serviceName") or "").lower() == name.lower():
                    refs.append(
                        {
                            "where": "policy set" if pk == "network-access" else "device-admin policy set",
                            "policy_kind": pk,
                            "policy_set": ps.get("name"),
                            "field": "serviceName",
                            "label": str(ps.get("name")),
                        }
                    )
    if kind in ("identity_sequence", "cert_profile", "ad_join_point"):
        refs += await _rule_field_refs(scan, POLICY_KINDS, ("authentication",), "identitySourceName", name)
    if kind in ("cert_profile", "ad_join_point"):
        for seq in await scan.ers_details("idstoresequence", 500):
            stores = [
                str(i.get("idstore", "")).lower() for i in seq.get("idSeqItem") or [] if isinstance(i, dict)
            ]
            if kind == "ad_join_point" and name.lower() in stores:
                refs.append({"where": "identity sequence", "sequence": seq.get("name"), "field": "idSeqItem"})
            if (
                kind == "cert_profile"
                and str(seq.get("certificateAuthenticationProfile") or "").lower() == name.lower()
            ):
                refs.append(
                    {
                        "where": "identity sequence",
                        "sequence": seq.get("name"),
                        "field": "certificateAuthenticationProfile",
                    }
                )
    if kind == "ad_join_point":
        refs += await _condition_refs(scan, join_point_matcher(name))
    members = await _members(app, kind, obj)
    by_where: dict[str, int] = {}
    for r in refs:
        by_where[r["where"]] = by_where.get(r["where"], 0) + 1
    out: dict[str, Any] = {
        "kind": kind,
        "object": {k: obj[k] for k in ("name", "id") if obj.get(k)},
        "used": bool(refs or members),
        "count": len(refs),
        "by_where": by_where,
        "references": refs,
    }
    if members:
        out["members"] = members
    out["scanned"] = list(dict.fromkeys(scan.scanned))
    if scan.incomplete:
        out["incomplete"] = list(dict.fromkeys(scan.incomplete))
    return out


def delete_blockers(result: dict[str, Any]) -> tuple[list[str], list[str]]:
    """(blockers, warnings) for ise_delete_object from a find_references result."""
    blockers: list[str] = []
    members = result.get("members") or {}
    if n := members.get("internal_users"):
        blockers.append(f"{n} internal user(s) are in this group")
    if members.get("endpoints"):
        blockers.append("Endpoints are still in this group (see ise_list_endpoints group=...)")
    grouped: dict[str, list[str]] = {}
    cells = 0
    for r in result.get("references") or []:
        if r["where"] == "egress cell":
            cells += 1
            continue
        label = r.get("label") or r.get("profile") or r.get("sequence") or r.get("nad") or r.get("condition")
        if r.get("via"):
            label = f"{label} (via {r['via']})"
        grouped.setdefault(r["where"], []).append(str(label))
    if cells:
        what = "SGACL" if result.get("kind") == "sgacl" else "SGT"
        blockers.append(f"{cells} egress matrix cell(s) use this {what}")
    for where, labels in grouped.items():
        labels = list(dict.fromkeys(labels))
        shown = ", ".join(labels[:10]) + (f" and {len(labels) - 10} more" if len(labels) > 10 else "")
        blockers.append(f"Used by {where}(s): {shown}")
    warnings = [f"Not checked ({i})" for i in result.get("incomplete") or []]
    return blockers, warnings


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Where is an ISE object used")
    async def ise_where_used(
        ctx: Context,
        kind: Annotated[
            WhereKind,
            Field(
                description="Object kind: authz_profile, dacl, sgt, sgacl, identity_group, endpoint_group, "
                "ndg (e.g. 'Location#All Locations#Lab'), condition (library condition), allowed_protocols, "
                "identity_sequence, cert_profile, ad_join_point, ad_group ('JOINPOINT:domain/OU/group' or "
                "the group), command_set, shell_profile"
            ),
        ],
        name: Annotated[str, Field(description="The object's name or id")],
    ) -> ToolResult:
        """Everything that references one ISE object, before changing or deleting it: policy sets
        (condition, allowed protocols) and their authentication / authorization rules and local and
        global exceptions, network access and device admin, each with the policy set, rule and field
        (conditions are followed through library conditions: 'via'); library conditions; authorization
        profiles (dACLs); identity sequences (identity stores, certificate profile); TrustSec egress
        matrix cells (SGTs, SGACLs); network devices (device groups); and group members (internal users,
        endpoints). 'incomplete' lists anything ISE wouldn't return, so an empty result there is not
        proof of no use."""
        app: IseApp = get_client(ctx)
        obj = await resolve_target(app, kind, name)
        return object_result(await find_references(app, kind, obj))

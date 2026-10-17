"""Configuration export and diff (I42): ISE policy and objects as stable, name-based YAML.

The export format is documented in docs/config-export.md; ise_import_config (I43) and the
policy change-review prompt (I46) build on it, so changes to the shape need a `format` bump."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import contextlib
import datetime as dt
import difflib
import hashlib
import importlib.metadata
from collections.abc import Awaitable, Callable
from functools import partial
from pathlib import Path
from typing import Annotated, Any

import yaml
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
from ise_mcp._core.formatting import compact, max_chars
from ise_mcp.client import IseApp
from ise_mcp.config import Settings
from ise_mcp.tools._common import ers_list, gather_limited, openapi_all
from ise_mcp.tools.policy import list_policy_sets

FORMAT = 1
HEADER = "ise_export"
KINDS = ("network-access", "device-admin")
RULE_SECTIONS = (
    ("authentication", "authentication"),
    ("authorization", "authorization"),
    ("exception", "local_exceptions"),
)  # (API path, export key), in evaluation order
SECTIONS = (
    "policy_sets",
    "authz_profiles",
    "dacls",
    "nads",
    "ndgs",
    "identity_groups",
    "endpoint_groups",
    "custom_attributes",
    "sgts",
    "sgacls",
    "egress_matrix",
    "command_sets",
    "shell_profiles",
)
ALIASES = {
    "all": SECTIONS,
    "policy": ("policy_sets", "authz_profiles", "dacls"),
    "network": ("nads", "ndgs"),
    "groups": ("identity_groups", "endpoint_groups"),
    "trustsec": ("sgts", "sgacls", "egress_matrix"),
    "device_admin": ("command_sets", "shell_profiles"),
}
# Fields that change without a configuration change (ids, links, counters, timestamps): never exported.
VOLATILE = frozenset(
    {
        "id",
        "link",
        "links",
        "_links",
        "hitCounts",
        "generationId",
        "matrixId",
        "dateCreated",
        "dateModified",
        "createTime",
        "updateTime",
        "lastUpdate",
    }
)
# Keys written first / last in every mapping (the rest sorted), so the YAML reads naturally.
FIRST_KEYS = ("name", "source", "destination", "rank", "state", "default", "description", "condition")
LAST_KEYS = ("authentication", "authorization", "local_exceptions")
DEFAULT_MAX_OBJECTS = 5000

Scope = Annotated[
    list[str] | None,
    Field(
        description="Sections to export (default: all): policy_sets, authz_profiles, dacls, nads, ndgs, "
        "identity_groups, endpoint_groups, custom_attributes, sgts, sgacls, egress_matrix, command_sets, "
        "shell_profiles; or the groups policy, network, groups, trustsec, device_admin"
    ),
]


# --- normalisation ------------------------------------------------------------------------------


def resolve_scope(scope: list[str] | None) -> list[str]:
    """Section names in canonical order; aliases expanded; unknown names refused."""
    if not scope:
        return list(SECTIONS)
    wanted: set[str] = set()
    for s in scope:
        key = s.strip().lower().replace("-", "_")
        if key in ALIASES:
            wanted.update(ALIASES[key])
        elif key in SECTIONS:
            wanted.add(key)
        else:
            raise InvalidRequest(
                f"Unknown export section {s!r}. Sections: {', '.join(SECTIONS)}; groups: "
                f"{', '.join(a for a in ALIASES if a != 'all')}"
            )
    return [s for s in SECTIONS if s in wanted]


def condition_text(cond: Any) -> Any:
    """An OpenAPI condition tree as the strings the policy write tools accept: a library condition name
    or 'Dictionary:Attribute operator value' ('NOT ' prefix when negated); blocks become {and: [...]} /
    {or: [...]}, a negated block {not: {...}}. None stays None (a default rule)."""
    if not isinstance(cond, dict):
        return cond
    ctype = str(cond.get("conditionType") or "")
    negate = bool(cond.get("isNegate"))
    if ctype.endswith("AndBlock") or ctype.endswith("OrBlock"):
        block = {
            "and" if ctype.endswith("AndBlock") else "or": [
                condition_text(c) for c in cond.get("children") or []
            ]
        }
        return {"not": block} if negate else block
    prefix = "NOT " if negate else ""
    if "attributeName" in cond or "dictionaryName" in cond:
        value = cond.get("attributeValue")
        if value is None:
            value = cond.get("dictionaryValue")
        return (
            f"{prefix}{cond.get('dictionaryName')}:{cond.get('attributeName')} "
            f"{cond.get('operator') or 'equals'} {value}"
        )
    if cond.get("name"):
        return f"{prefix}{cond.get('name')}"
    return {k: v for k, v in cond.items() if k not in VOLATILE}  # unknown shape: keep it, minus ids


def clean(obj: Any) -> Any:
    """Volatile keys and empty values dropped, secrets masked (core mask_secrets rules)."""
    return compact(obj, drop=VOLATILE)


def ordered(value: Any) -> Any:
    """Mappings with FIRST_KEYS first, LAST_KEYS last and everything else sorted; recursively."""
    if isinstance(value, list):
        return [ordered(v) for v in value]
    if not isinstance(value, dict):
        return value
    keys = list(value)
    head = [k for k in FIRST_KEYS if k in value]
    tail = [k for k in LAST_KEYS if k in value]
    middle = sorted((k for k in keys if k not in head and k not in tail), key=str)
    return {k: ordered(value[k]) for k in head + middle + tail}


def _name_key(obj: dict[str, Any]) -> tuple[str, str]:
    name = str(obj.get("name") or obj.get("attributeName") or "")
    return (name.casefold(), name)


def by_name(objs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(objs, key=_name_key)


def _lines(text: Any) -> list[str]:
    return [ln.rstrip() for ln in str(text or "").splitlines() if ln.strip()]


def norm_rule(entry: dict[str, Any]) -> dict[str, Any]:
    """{"rule": {...}, "profile": [...], ...} (OpenAPI) -> one flat mapping with ISE's field names."""
    rule = dict(entry.get("rule") or {})
    out: dict[str, Any] = {
        "name": rule.pop("name", None),
        "rank": rule.pop("rank", None),
        "state": rule.pop("state", None),
        "default": True if rule.pop("default", False) else None,
    }
    cond = rule.pop("condition", None)
    out["condition"] = None if out["default"] else condition_text(cond)
    out.update(rule)
    out.update({k: v for k, v in entry.items() if k != "rule"})
    return clean(out)  # type: ignore[no-any-return]


def norm_policy_set(ps: dict[str, Any]) -> dict[str, Any]:
    out = dict(ps)
    out["condition"] = None if ps.get("default") else condition_text(ps.get("condition"))
    out["default"] = True if ps.get("default") else None
    return clean(out)  # type: ignore[no-any-return]


def norm_nad(nad: dict[str, Any]) -> dict[str, Any]:
    out = dict(nad)
    ips = [i for i in nad.get("NetworkDeviceIPList") or [] if isinstance(i, dict)]
    out["NetworkDeviceIPList"] = sorted(ips, key=lambda i: (str(i.get("ipaddress")), str(i.get("mask"))))
    out["NetworkDeviceGroupList"] = sorted(str(g) for g in nad.get("NetworkDeviceGroupList") or [])
    return clean(out)  # type: ignore[no-any-return]


def norm_dacl(d: dict[str, Any]) -> dict[str, Any]:
    return clean({**d, "dacl": _lines(d.get("dacl"))})  # type: ignore[no-any-return]


def norm_sgacl(a: dict[str, Any]) -> dict[str, Any]:
    return clean({**a, "aclcontent": _lines(a.get("aclcontent"))})  # type: ignore[no-any-return]


def norm_endpoint_groups(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """parentId -> parent (the parent group's name)."""
    names = {str(g.get("id")): str(g.get("name")) for g in groups if g.get("id")}
    out = []
    for g in groups:
        row = dict(g)
        parent = row.pop("parentId", None)
        if parent:
            row["parent"] = names.get(str(parent), str(parent))
        out.append(clean(row))
    return by_name(out)


def norm_matrix(
    cells: list[dict[str, Any]], sgts: dict[str, str], acls: dict[str, str]
) -> list[dict[str, Any]]:
    """Egress cells keyed by source/destination SGT name, SGACL ids resolved to names (order kept: ISE
    applies a cell's SGACLs in order). The default cell is ANY -> ANY."""
    out = []
    for c in cells:
        row = {k: v for k, v in c.items() if k not in ("sourceSgtId", "destinationSgtId", "sgacls", "name")}
        if c.get("name") == "ANY-ANY":
            src = dst = "ANY"
        else:
            src = sgts.get(str(c.get("sourceSgtId")), str(c.get("sourceSgtId") or "ANY"))
            dst = sgts.get(str(c.get("destinationSgtId")), str(c.get("destinationSgtId") or "ANY"))
        row["source"], row["destination"] = src, dst
        row["sgacls"] = [acls.get(str(a), str(a)) for a in c.get("sgacls") or []]
        out.append(clean(row))
    return sorted(
        out, key=lambda r: (r["source"] != "ANY", r["source"].casefold(), r["destination"].casefold())
    )


def to_yaml(data: dict[str, Any]) -> str:
    return yaml.safe_dump(
        ordered_doc(data), sort_keys=False, default_flow_style=False, allow_unicode=True, width=10_000
    )


def ordered_doc(data: dict[str, Any]) -> dict[str, Any]:
    """Header first, then the sections in canonical order (each normalised by `ordered`)."""
    out: dict[str, Any] = {}
    if HEADER in data:
        out[HEADER] = data[HEADER]
    for s in SECTIONS:
        if s in data:
            out[s] = ordered(data[s])
    return out


def body_digest(data: dict[str, Any]) -> str:
    body = {k: v for k, v in data.items() if k != HEADER}
    return "sha256:" + hashlib.sha256(to_yaml(body).encode()).hexdigest()


def load_export(text: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise InvalidRequest(f"Not valid YAML: {str(e)[:200]}") from e
    if not isinstance(data, dict) or not isinstance(data.get(HEADER), dict):
        raise InvalidRequest(f"Not an ISE config export (no '{HEADER}' header; see ise_export_config)")
    fmt = data[HEADER].get("format")
    if fmt != FORMAT:
        raise InvalidRequest(f"Export format {fmt!r} is not supported by this server (format {FORMAT})")
    return data


# --- fetching -----------------------------------------------------------------------------------


class Export:
    """One export run: section data plus notes about anything partial or skipped."""

    def __init__(self, app: IseApp, max_objects: int) -> None:
        self.app = app
        self.max_objects = max_objects
        self.incomplete: dict[str, str] = {}
        self.skipped: dict[str, str] = {}
        # The objects as ISE returned them (with ids and real secrets), for ise_import_config.
        self.raw: dict[str, list[dict[str, Any]]] = {}  # section -> ERS objects
        self.raw_sets: dict[str, list[dict[str, Any]]] = {}  # kind -> policy sets
        self.raw_rules: dict[str, list[dict[str, Any]]] = {}  # OpenAPI rule-table path -> rules
        self.sgt_names: dict[str, str] = {}  # id -> name, read for the egress matrix
        self.acl_names: dict[str, str] = {}

    async def ers_all(self, section: str, resource: str) -> list[dict[str, Any]]:
        """Every object of an ERS collection with full details (paged, bounded concurrency)."""
        page = await ers_list(
            self.app, resource, limit=self.max_objects, offset=0, detail=True, detail_cap=None
        )
        if not page.complete:
            self.incomplete[section] = f"first {len(page.items)} of {page.total or 'more'} (max_objects)"
        items = [i for i in page.items if isinstance(i, dict)]
        self.raw[section] = items
        return items

    async def policy_sets(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for kind in KINDS:
            try:
                sets = await list_policy_sets(self.app, kind)
            except (UpstreamError, NotFound) as e:
                # Device admin is off (no DeviceAdmin service) or the API is not licensed.
                self.skipped[f"policy_sets.{kind}"] = str(e)[:200]
                continue
            self.raw_sets[kind] = sets
            rules = await gather_limited(sets, partial(self._rules, kind), limit=4)
            rows = []
            for ps, sections in zip(sets, rules, strict=True):
                rows.append({**norm_policy_set(ps), **sections})
            rows.sort(key=lambda r: (r.get("rank") is None, r.get("rank") or 0, _name_key(r)))
            entry: dict[str, Any] = {"sets": rows}
            glob = await self._section(f"/api/v1/policy/{kind}/policy-set/global-exception")
            if glob:
                entry["global_exceptions"] = glob
            out[kind] = entry
        return out

    async def _rules(self, kind: str, ps: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        base = f"/api/v1/policy/{kind}/policy-set/{ps['id']}"
        out: dict[str, list[dict[str, Any]]] = {}
        for path, key in RULE_SECTIONS:
            rules = await self._section(f"{base}/{path}")
            if rules:
                out[key] = rules
        return out

    async def _section(self, path: str) -> list[dict[str, Any]]:
        try:
            data = await self.app.openapi.get(path)
        except NotFound:
            return []
        data = data.get("response", data) if isinstance(data, dict) else data
        raw = [r for r in data or [] if isinstance(r, dict)]
        self.raw_rules[path] = raw
        rules = [norm_rule(r) for r in raw]
        return sorted(rules, key=lambda r: (r.get("rank") is None, r.get("rank") or 0, _name_key(r)))

    async def section(self, name: str) -> Any:
        fetch: dict[str, Callable[[], Awaitable[Any]]] = {
            "policy_sets": self.policy_sets,
            "authz_profiles": lambda: self._simple(name, "authorizationprofile", clean),
            "dacls": lambda: self._simple(name, "downloadableacl", norm_dacl),
            "nads": lambda: self._simple(name, "networkdevice", norm_nad),
            "ndgs": lambda: self._simple(name, "networkdevicegroup", clean),
            "identity_groups": lambda: self._simple(name, "identitygroup", clean),
            "endpoint_groups": self._endpoint_groups,
            "custom_attributes": self._custom_attributes,
            "sgts": lambda: self._simple(name, "sgt", clean),
            "sgacls": lambda: self._simple(name, "sgacl", norm_sgacl),
            "egress_matrix": self._matrix,
            "command_sets": lambda: self._simple(name, "tacacscommandsets", clean),
            "shell_profiles": lambda: self._simple(name, "tacacsprofile", clean),
        }
        return await fetch[name]()

    async def _simple(
        self, section: str, resource: str, norm: Callable[[dict[str, Any]], Any]
    ) -> list[dict[str, Any]]:
        return by_name([norm(o) for o in await self.ers_all(section, resource)])

    async def _endpoint_groups(self) -> list[dict[str, Any]]:
        return norm_endpoint_groups(await self.ers_all("endpoint_groups", "endpointgroup"))

    async def _custom_attributes(self) -> list[dict[str, Any]]:
        data = await self.app.openapi.get("/api/v1/endpoint-custom-attribute")
        data = data.get("response", data) if isinstance(data, dict) else data
        self.raw["custom_attributes"] = [a for a in data or [] if isinstance(a, dict)]
        return by_name([clean(a) for a in self.raw["custom_attributes"]])

    async def _matrix(self) -> list[dict[str, Any]]:
        cells = await self.ers_all("egress_matrix", "egressmatrixcell")
        if not cells:
            return []
        sgt_page = await ers_list(self.app, "sgt", limit=10_000, offset=0)
        acl_page = await ers_list(self.app, "sgacl", limit=10_000, offset=0)
        sgts = {str(s["id"]): str(s.get("name")) for s in sgt_page.items if "id" in s}
        acls = {str(a["id"]): str(a.get("name")) for a in acl_page.items if "id" in a}
        self.sgt_names, self.acl_names = sgts, acls
        return norm_matrix(cells, sgts, acls)


async def _header_facts(app: IseApp) -> dict[str, Any]:
    out: dict[str, Any] = {"ise_version": None, "hostname": None}
    with contextlib.suppress(UpstreamError):
        out["ise_version"] = await app.version()
    try:
        nodes = await openapi_all(app, "/api/v1/deployment/node", cap=200)
        summary = app.deployment_summary([n for n in nodes if isinstance(n, dict)])
        out["hostname"] = summary.get("config_node_pan")
    except UpstreamError:
        pass
    return out


def server_version() -> str:
    try:
        return importlib.metadata.version("ise-mcp-server")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


async def export_config(
    app: IseApp,
    sections: list[str],
    *,
    max_objects: int = DEFAULT_MAX_OBJECTS,
    now: dt.datetime | None = None,
    run: Export | None = None,
) -> dict[str, Any]:
    """The export as a dict (header + sections). Sections are fetched one after another so a large
    deployment sees one section's per-item GETs at a time (each bounded by ISE_DETAIL_CONCURRENCY).
    Pass `run` to keep the raw objects it read (ise_import_config plans against them)."""
    run = run or Export(app, max_objects)
    data: dict[str, Any] = {}
    for s in sections:
        try:
            data[s] = await run.section(s)
        except (UpstreamError, NotFound) as e:
            if s not in ("command_sets", "shell_profiles"):
                raise
            run.skipped[s] = str(e)[:200]  # TACACS objects need the DeviceAdmin service
    header: dict[str, Any] = {
        "format": FORMAT,
        **await _header_facts(app),
        "exported_at": (now or dt.datetime.now(dt.UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "server_version": server_version(),
        "sections": sections,
        "counts": {s: count_objects(s, data[s]) for s in sections if s in data},
        "digest": body_digest(data),
    }
    if run.incomplete:
        header["incomplete"] = run.incomplete
    if run.skipped:
        header["skipped"] = run.skipped
    return {HEADER: header, **data}


def count_objects(section: str, value: Any) -> int:
    if section == "policy_sets":
        return sum(len(v.get("sets") or []) for v in value.values())
    return len(value)


# --- diff ---------------------------------------------------------------------------------------


def _flat(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Nested mappings as dotted paths; lists and scalars are leaves."""
    if not isinstance(obj, dict) or not obj:
        return {prefix: obj} if prefix else {}
    out: dict[str, Any] = {}
    for k, v in obj.items():
        path = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict) and v and k != "condition":
            out.update(_flat(v, path))
        else:
            out[path] = v
    return out


def field_changes(old: dict[str, Any], new: dict[str, Any], ignore: tuple[str, ...] = ()) -> dict[str, Any]:
    """{field: change} for every field that differs. Lists of scalars report added/removed items (or
    'reordered'); anything else from/to."""
    a, b = _flat(old), _flat(new)
    out: dict[str, Any] = {}
    for key in sorted(set(a) | set(b)):
        if key in ignore or a.get(key) == b.get(key):
            continue
        va, vb = a.get(key), b.get(key)
        if (
            isinstance(va, list)
            and isinstance(vb, list)
            and all(not isinstance(x, dict | list) for x in va + vb)
        ):
            added = [x for x in vb if x not in va]
            removed = [x for x in va if x not in vb]
            out[key] = {"added": added, "removed": removed} if added or removed else {"reordered": vb}
            out[key] = {k: v for k, v in out[key].items() if v}
        else:
            out[key] = {"from": va, "to": vb}
    return out


def _moved(old_order: list[str], new_order: list[str]) -> set[str]:
    """Names whose relative order changed: everything outside the longest run of common names kept in
    order. A rule that only shifts because another was added or removed above it is not moved."""
    common = set(old_order) & set(new_order)
    a = [n for n in old_order if n in common]
    b = [n for n in new_order if n in common]
    kept: set[str] = set()
    for block in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_matching_blocks():
        kept.update(a[block.a : block.a + block.size])
    return common - kept


class _Section:
    def __init__(self) -> None:
        self.added: list[str] = []
        self.removed: list[str] = []
        self.changed: dict[str, Any] = {}
        self.moved: dict[str, Any] = {}

    def result(self) -> dict[str, Any] | None:
        out = {
            "added": self.added,
            "removed": self.removed,
            "moved": self.moved,
            "changed": self.changed,
        }
        out = {k: v for k, v in out.items() if v}
        return out or None


def _keyed(section: str, objs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if section == "egress_matrix":
        return {f"{o.get('source')} -> {o.get('destination')}": o for o in objs}
    if section == "custom_attributes":
        return {str(o.get("attributeName")): o for o in objs}
    return {str(o.get("name")): o for o in objs}


def _diff_objects(
    section: str, old: list[dict[str, Any]], new: list[dict[str, Any]]
) -> dict[str, Any] | None:
    a, b = _keyed(section, old or []), _keyed(section, new or [])
    out = _Section()
    out.added = sorted(set(b) - set(a), key=str.casefold)
    out.removed = sorted(set(a) - set(b), key=str.casefold)
    for key in sorted(set(a) & set(b), key=str.casefold):
        changes = field_changes(a[key], b[key])
        if changes:
            out.changed[key] = changes
    return out.result()


def _ranked(
    out: _Section, prefix: str, old: list[dict[str, Any]], new: list[dict[str, Any]], skip: tuple[str, ...]
) -> None:
    """Diff one ranked table (policy sets of a kind, or one rule table): add/remove/move/change."""
    a = {str(r.get("name")): r for r in old}
    b = {str(r.get("name")): r for r in new}
    out.added += [f"{prefix}{n}" for n in b if n not in a]
    out.removed += [f"{prefix}{n}" for n in a if n not in b]
    for n in _moved([str(r.get("name")) for r in old], [str(r.get("name")) for r in new]):
        out.moved[f"{prefix}{n}"] = {"from": a[n].get("rank"), "to": b[n].get("rank")}
    for n in a:
        if n in b:
            changes = field_changes(a[n], b[n], ignore=("rank", *skip))
            if changes:
                out.changed[f"{prefix}{n}"] = changes


def _diff_policy(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    sets, rules = _Section(), _Section()
    tables = ("global_exceptions",)
    for kind in KINDS:
        ok, nk = (old or {}).get(kind) or {}, (new or {}).get(kind) or {}
        osets = {str(s.get("name")): s for s in ok.get("sets") or []}
        nsets = {str(s.get("name")): s for s in nk.get("sets") or []}
        rule_keys = tuple(k for _, k in RULE_SECTIONS)
        _ranked(sets, f"{kind}/", ok.get("sets") or [], nk.get("sets") or [], skip=rule_keys)
        for name in osets.keys() & nsets.keys():
            for key in rule_keys:
                _ranked(
                    rules, f"{kind}/{name}/{key}/", osets[name].get(key) or [], nsets[name].get(key) or [], ()
                )
        for key in tables:
            _ranked(rules, f"{kind}/{key}/", ok.get(key) or [], nk.get(key) or [], ())
    out: dict[str, Any] = {}
    for label, sec in (("policy_sets", sets), ("policy_rules", rules)):
        sec.added.sort(key=str.casefold)
        sec.removed.sort(key=str.casefold)
        sec.moved = dict(sorted(sec.moved.items()))
        sec.changed = dict(sorted(sec.changed.items()))
        res = sec.result()
        if res:
            out[label] = res
    return out


def diff_exports(
    old: dict[str, Any], new: dict[str, Any], sections: list[str] | None = None, *, max_changes: int = 200
) -> dict[str, Any]:
    """Section-by-section differences between two exports (dicts from load_export / export_config)."""
    oh, nh = old.get(HEADER) or {}, new.get(HEADER) or {}
    in_both = [s for s in SECTIONS if s in (oh.get("sections") or []) and s in (nh.get("sections") or [])]
    wanted = [s for s in in_both if sections is None or s in sections]
    result: dict[str, Any] = {}
    for s in wanted:
        if s == "policy_sets":
            result.update(_diff_policy(old.get(s) or {}, new.get(s) or {}))
        else:
            res = _diff_objects(s, old.get(s) or [], new.get(s) or [])
            if res:
                result[s] = res
    summary = {
        k: sum(len(sec.get(k) or {}) for sec in result.values())
        for k in ("added", "removed", "moved", "changed")
    }
    out: dict[str, Any] = {
        "before": {k: oh.get(k) for k in ("hostname", "exported_at", "digest")},
        "after": {k: nh.get(k) for k in ("hostname", "exported_at", "digest")},
        "unchanged": not result,
        "summary": summary,
        "sections_compared": wanted,
    }
    only = sorted(set(oh.get("sections") or []) ^ set(nh.get("sections") or []))
    if only:
        out["not_compared"] = f"Not in both exports: {', '.join(only)}"
    notes = [
        f"{side} export is partial: {h['incomplete']}"
        for side, h in (("before", oh), ("after", nh))
        if h.get("incomplete")
    ]
    notes += [
        f"{side} export skipped: {h['skipped']}"
        for side, h in (("before", oh), ("after", nh))
        if h.get("skipped")
    ]
    if notes:
        out["notes"] = notes
    total = sum(summary.values())
    if total > max_changes:
        result = _truncate(result, max_changes)
        out["truncated"] = (
            f"{total} differences; showing about {max_changes} (raise max_changes or narrow scope)"
        )
    out["sections"] = result
    return out


def _truncate(result: dict[str, Any], budget: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, sec in result.items():
        kept: dict[str, Any] = {}
        for kind, items in sec.items():
            if budget <= 0:
                break
            if isinstance(items, list):
                kept[kind] = items[:budget]
            else:
                kept[kind] = dict(list(items.items())[:budget])
            budget -= len(kept[kind])
        if kept:
            out[name] = kept
    return out


# --- files --------------------------------------------------------------------------------------


def resolve_path(settings: Settings, path: str) -> Path:
    """Where an export file may live: inside ISE_EXPORT_DIR when set (relative paths resolve there),
    otherwise any absolute path; always a .yaml / .yml file."""
    raw = Path(path.strip()).expanduser()
    if raw.suffix.lower() not in (".yaml", ".yml"):
        raise InvalidRequest("Export files must end in .yaml or .yml")
    base = settings.export_dir
    if base is not None:
        root = base.resolve()
        target = (root / raw).resolve()
        if not target.is_relative_to(root):
            raise InvalidRequest(f"{path!r} is outside ISE_EXPORT_DIR")
        return target
    if not raw.is_absolute():
        raise InvalidRequest("Give an absolute path (or set ISE_EXPORT_DIR to use relative paths)")
    return raw.resolve()


def write_export(settings: Settings, path: str, text: str) -> Path:
    target = resolve_path(settings, path)
    if not target.parent.is_dir():
        raise InvalidRequest(f"Directory {str(target.parent)!r} does not exist")
    if target.exists():
        # Only an earlier export may be overwritten, never an unrelated file.
        try:
            load_export(target.read_text(encoding="utf-8"))
        except (InvalidRequest, OSError, UnicodeDecodeError) as e:
            raise InvalidRequest(
                f"{str(target)!r} exists and is not an ISE config export; not overwriting"
            ) from e
    target.write_text(text, encoding="utf-8")
    return target


def read_source(settings: Settings, source: str) -> dict[str, Any]:
    """An export given as YAML text or as a file path."""
    text = source.strip()
    if "\n" in text or text.startswith(f"{HEADER}:"):
        return load_export(text)
    target = resolve_path(settings, text)
    try:
        return load_export(target.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise NotFound(f"No export file at {str(target)!r}", 404) from e


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Export ISE configuration as YAML")
    async def ise_export_config(
        ctx: Context,
        scope: Scope = None,
        path: Annotated[
            str | None,
            Field(
                description="Write the YAML to this .yaml file on the server instead of returning it "
                "(relative to ISE_EXPORT_DIR when set; only an earlier export is ever overwritten)"
            ),
        ] = None,
        max_objects: Annotated[
            int, Field(ge=1, le=100_000, description="Per-section object cap (large deployments)")
        ] = DEFAULT_MAX_OBJECTS,
    ) -> ToolResult:
        """Export ISE configuration as reviewable YAML: policy sets with their authentication,
        authorization and local exception rules (network access and device admin), authorization
        profiles, dACLs, NADs and NDGs (shared secrets and SNMP communities masked), identity and
        endpoint groups, endpoint custom attributes, SGTs, SGACLs, the TrustSec egress matrix, TACACS+
        command sets and shell profiles. References are names, not ids; rules keep their rank and
        everything else is sorted by name; ids, links, hit counts and timestamps are left out, so two
        exports of an unchanged ISE differ only in the header's exported_at. Keep one as a baseline and
        compare later with ise_diff_config. Large deployments: one GET per object (NADs!), so narrow
        `scope` or use `path` for a full export."""
        app: IseApp = get_client(ctx)
        sections = resolve_scope(scope)
        data = await export_config(app, sections, max_objects=max_objects)
        text = to_yaml(data)
        header = data[HEADER]
        if path:
            target = write_export(app.settings, path, text)
            summary = {k: header[k] for k in ("sections", "counts", "digest") if k in header}
            extra = {k: header[k] for k in ("incomplete", "skipped") if k in header}
            return object_result({"path": str(target), "bytes": len(text.encode()), **summary, **extra})
        if len(text) > max_chars():
            raise InvalidRequest(
                f"The export is {len(text)} characters, over the response limit ({max_chars()}): give `path` "
                "to write it to a file, or a narrower `scope`"
            )
        return ToolResult(content=text)

    @reg.read(title="Diff ISE configuration exports")
    async def ise_diff_config(
        ctx: Context,
        before: Annotated[
            str, Field(description="The earlier export: a path to a .yaml export file, or the YAML text")
        ],
        after: Annotated[
            str,
            Field(
                description="The later export (path or YAML text), or 'live' to export ISE now and compare"
            ),
        ] = "live",
        scope: Scope = None,
        max_changes: Annotated[int, Field(ge=1, le=5000, description="Cap on differences listed")] = 200,
    ) -> dict[str, Any]:
        """Compare two ise_export_config exports, or one export against live ISE ('live'), section by
        section: objects added, removed and changed with field-level changes (from/to; list fields as
        added/removed items). Rules match by policy set + rule name; a rule whose position changed is
        listed under `moved` (from/to rank), not as a change, and rules that only shift because one was
        added above are not moved. Only sections in both exports are compared. Masked secrets compare
        equal, so a changed shared secret is not visible. 'What changed since the baseline?'"""
        app: IseApp = get_client(ctx)
        old = read_source(app.settings, before)
        sections = resolve_scope(scope) if scope else None
        if after.strip().lower() == "live":
            wanted = [s for s in old[HEADER].get("sections") or [] if sections is None or s in sections]
            new = await export_config(app, resolve_scope(wanted) if wanted else [])
        else:
            new = read_source(app.settings, after)
        return diff_exports(old, new, sections, max_changes=max_changes)

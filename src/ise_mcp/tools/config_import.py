"""Configuration import (I43): apply an ise_export_config export to an ISE, preview-first.

The import plans one step per object (create, update, or with prune delete), matched by name, in
dependency order: groups and TrustSec objects first, then dACLs, profiles, TACACS objects and NADs, then
policy sets and their rules. Objects that are already the same are skipped. References are resolved from
names to ids when each step runs, so a step can use an object an earlier step created. The export masks
secrets; NAD secrets are passed separately. Applying stops at the first failure and says what was done."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import fnmatch
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Annotated, Any
from urllib.parse import quote

from fastmcp import Context
from pydantic import Field

from ise_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from ise_mcp._core.formatting import MASK
from ise_mcp.client import IseApp
from ise_mcp.tools._common import clear_name_maps, ers_name_map
from ise_mcp.tools.config_export import (
    HEADER,
    KINDS,
    RULE_SECTIONS,
    SECTIONS,
    Export,
    Scope,
    _flat,
    _keyed,
    _moved,
    export_config,
    field_changes,
    norm_matrix,
    read_source,
    resolve_scope,
)
from ise_mcp.tools.policy import list_policy_sets
from ise_mcp.tools.policy_edit import (
    check_attribute,
    condition_library,
    condition_node,
    dictionary_attributes,
    strip_links,
)
from ise_mcp.tools.writes import deep_merge, fingerprint

# Dependency order: a section only refers to sections before it.
APPLY_ORDER = (
    "ndgs",
    "identity_groups",
    "endpoint_groups",
    "custom_attributes",
    "sgts",
    "sgacls",
    "egress_matrix",
    "dacls",
    "authz_profiles",
    "command_sets",
    "shell_profiles",
    "nads",
    "policy_sets",
)
ERS = {  # section -> (ERS resource, JSON wrapper)
    "ndgs": ("networkdevicegroup", "NetworkDeviceGroup"),
    "identity_groups": ("identitygroup", "IdentityGroup"),
    "endpoint_groups": ("endpointgroup", "EndPointGroup"),
    "sgts": ("sgt", "Sgt"),
    "sgacls": ("sgacl", "Sgacl"),
    "egress_matrix": ("egressmatrixcell", "EgressMatrixCell"),
    "dacls": ("downloadableacl", "DownloadableAcl"),
    "authz_profiles": ("authorizationprofile", "AuthorizationProfile"),
    "command_sets": ("tacacscommandsets", "TacacsCommandSets"),
    "shell_profiles": ("tacacsprofile", "TacacsProfile"),
    "nads": ("networkdevice", "NetworkDevice"),
}
# Short names for NAD secrets in `secrets`; any dotted field path works too.
SECRET_ALIASES = {
    "radius": "authenticationSettings.radiusSharedSecret",
    "radius_second": "authenticationSettings.secondRadiusSharedSecret",
    "key_encryption_key": "authenticationSettings.keyEncryptionKey",
    "message_authenticator_key": "authenticationSettings.messageAuthenticatorCodeKey",
    "tacacs": "tacacsSettings.sharedSecret",
    "snmp_ro": "snmpsettings.roCommunity",
}
RULE_SCOPE = {"authentication": "authentication", "authorization": "authorization"}
STEP_LIST_CAP = 300

Secrets = Annotated[
    dict[str, dict[str, str]] | None,
    Field(
        description="NAD secrets by NAD name (the export masks them): "
        "{'sw1': {'radius': '...', 'tacacs': '...', 'snmp_ro': '...'}}; other keys: radius_second, "
        "key_encryption_key, message_authenticator_key, or a "
        "dotted field path. Existing NADs keep their secrets unless given here; a new NAD needs every secret "
        "its export shows as set"
    ),
]


@dataclass
class Step:
    op: str  # create | update | delete
    section: str
    name: str
    run: Callable[[], Awaitable[Any]]
    changes: dict[str, Any] | None = None

    def label(self) -> str:
        return f"{self.op} {self.section} {self.name}"

    def view(self) -> dict[str, Any]:
        out: dict[str, Any] = {"op": self.op, "section": self.section, "name": self.name}
        if self.changes:
            out["changes"] = self.changes
        return out


@dataclass
class ImportPlan:
    steps: list[Step] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)  # section -> objects already the same
    left_alone: dict[str, list[str]] = field(default_factory=dict)  # not in the export, prune off
    notes: list[str] = field(default_factory=list)
    live_digest: str = ""

    def skip(self, section: str) -> None:
        self.skipped[section] = self.skipped.get(section, 0) + 1


# --- helpers ------------------------------------------------------------------------------------


def matches(name: str, only: list[str] | None) -> bool:
    return not only or any(fnmatch.fnmatchcase(name.lower(), g.lower()) for g in only)


def _get(obj: dict[str, Any], path: str) -> Any:
    cur: Any = obj
    for part in path.split("."):
        cur = cur.get(part) if isinstance(cur, dict) else None
    return cur


def _set(obj: dict[str, Any], path: str, value: Any) -> None:
    *parents, last = path.split(".")
    cur = obj
    for part in parents:
        cur = cur.setdefault(part, {})
    cur[last] = value


def _masked_paths(obj: Any, prefix: str = "") -> list[str]:
    if isinstance(obj, dict):
        return [p for k, v in obj.items() for p in _masked_paths(v, f"{prefix}{k}.")]
    return [prefix.rstrip(".")] if obj == MASK else []


def ers_body(section: str, obj: dict[str, Any]) -> dict[str, Any]:
    """An export object back in ERS shape (references still names; see _resolve_refs)."""
    body = {k: v for k, v in obj.items()}
    if section == "dacls" and isinstance(body.get("dacl"), list):
        body["dacl"] = "\n".join(body["dacl"])
    if section == "sgacls" and isinstance(body.get("aclcontent"), list):
        body["aclcontent"] = "\n".join(body["aclcontent"])
    if section == "egress_matrix":
        body.pop("source", None)
        body.pop("destination", None)
    return body


async def _resolve_refs(app: IseApp, section: str, obj: dict[str, Any], body: dict[str, Any]) -> None:
    """Names -> ids, looked up when the step runs (an earlier step may have just created the target)."""
    if section == "endpoint_groups" and obj.get("parent"):
        groups = {v: k for k, v in (await ers_name_map(app, "endpointgroup")).items()}
        body.pop("parent", None)
        if obj["parent"] not in groups:
            raise NotFound(f"Parent endpoint group {obj['parent']!r} does not exist", 404)
        body["parentId"] = groups[obj["parent"]]
    if section == "egress_matrix":
        sgts = {v: k for k, v in (await ers_name_map(app, "sgt")).items()}
        acls = {v: k for k, v in (await ers_name_map(app, "sgacl")).items()}
        for side, key in (("source", "sourceSgtId"), ("destination", "destinationSgtId")):
            if obj[side] == "ANY":
                continue
            if obj[side] not in sgts:
                raise NotFound(f"SGT {obj[side]!r} does not exist", 404)
            body[key] = sgts[obj[side]]
        missing = [a for a in obj.get("sgacls") or [] if a not in acls]
        if missing:
            raise NotFound(f"SGACL(s) {', '.join(missing)} do not exist", 404)
        body["sgacls"] = [acls[a] for a in obj.get("sgacls") or []]


# --- planning: ERS sections ---------------------------------------------------------------------


def given_changes(
    live: dict[str, Any], wanted: dict[str, Any], ignore: tuple[str, ...] = ()
) -> dict[str, Any]:
    """Field changes for the fields the export gives. A field it leaves out keeps the target's value
    (ISE fills in defaults a hand-written export doesn't spell out)."""
    given = set(_flat(wanted))
    return {k: v for k, v in field_changes(live, wanted, ignore=ignore).items() if k in given}


def _fill_secrets(
    plan: ImportPlan,
    name: str,
    body: dict[str, Any],
    raw: dict[str, Any] | None,
    given: dict[str, str],
) -> None:
    """Replace masked values with supplied secrets, or (updates) the current ones."""
    for key, value in given.items():
        _set(body, SECRET_ALIASES.get(key, key), value)
    for path in _masked_paths(body):
        current = _get(raw, path) if raw is not None else None
        if current not in (None, "", MASK):
            _set(body, path, current)
        else:
            alias = next((a for a, p in SECRET_ALIASES.items() if p == path), path)
            plan.blockers.append(f"NAD {name!r}: give its {alias} secret in `secrets` (the export masks it)")


def _ers_section(
    app: IseApp,
    plan: ImportPlan,
    section: str,
    wanted: list[dict[str, Any]],
    live: list[dict[str, Any]],
    raw: list[dict[str, Any]],
    *,
    only: list[str] | None,
    prune: bool,
    secrets: dict[str, dict[str, str]],
) -> None:
    resource, wrapper = ERS[section]
    want = {k: v for k, v in _keyed(section, wanted).items() if _in_filter(section, v, only)}
    have = _keyed(section, live)
    raw_by_key = _keyed(section, raw)
    if section == "ndgs":  # parents first
        order = sorted(want, key=lambda k: (k.count("#"), k.casefold()))
    elif section == "endpoint_groups":
        order = sorted(want, key=lambda k: (bool(want[k].get("parent")), k.casefold()))
    else:
        order = sorted(want, key=str.casefold)
    for key in order:
        obj = want[key]
        given = secrets.get(key, {}) if section == "nads" else {}
        current = raw_by_key.get(key)
        if key not in have:
            body = ers_body(section, obj)
            if section == "nads":
                _fill_secrets(plan, key, body, None, given)
            if section == "egress_matrix" and key == "ANY -> ANY":
                plan.blockers.append(
                    "The ANY -> ANY egress cell is missing on the target; ISE should always have it"
                )
                continue
            plan.steps.append(
                Step("create", section, key, _ers_create(app, section, resource, wrapper, obj, body))
            )
            continue
        changes = given_changes(have[key], obj)
        new_secrets = [
            k for k, v in given.items() if current is None or _get(current, SECRET_ALIASES.get(k, k)) != v
        ]
        for k in new_secrets:
            changes[SECRET_ALIASES.get(k, k)] = {"from": MASK, "to": MASK}
        if not changes:
            plan.skip(section)
            continue
        if current is None:
            plan.blockers.append(f"{section} {key!r}: the live object could not be read")
            continue
        body = ers_body(section, obj)
        if section == "nads":
            _fill_secrets(plan, key, body, current, given)
        # Fields the export doesn't give keep their current value (ids, ISE's defaults).
        base = {k: v for k, v in current.items() if k not in ("link", "source", "destination")}
        body = deep_merge(base, body)
        plan.steps.append(
            Step("update", section, key, _ers_update(app, section, resource, wrapper, obj, body), changes)
        )
    extra = sorted(
        (k for k in have if k not in want and _in_filter(section, have[k], only)), key=str.casefold
    )
    if not extra:
        return
    if not prune:
        plan.left_alone[section] = extra
        return
    for key in extra:
        current = raw_by_key.get(key)
        if section == "egress_matrix" and key == "ANY -> ANY":
            continue  # the default cell can't be deleted
        if current is None or not current.get("id"):
            plan.blockers.append(f"{section} {key!r}: the live object could not be read")
            continue
        plan.steps.append(Step("delete", section, key, _ers_delete(app, resource, str(current["id"]))))


def _in_filter(section: str, obj: dict[str, Any], only: list[str] | None) -> bool:
    if section == "egress_matrix":
        return matches(str(obj.get("source")), only) or matches(str(obj.get("destination")), only)
    if section == "ndgs":  # a device group path matches by its full path or its own (last) name
        name = str(obj.get("name") or "")
        return matches(name, only) or matches(name.rsplit("#", 1)[-1], only)
    return matches(str(obj.get("name") or obj.get("attributeName") or ""), only)


def _ers_create(
    app: IseApp, section: str, resource: str, wrapper: str, obj: dict[str, Any], body: dict[str, Any]
) -> Callable[[], Awaitable[Any]]:
    async def run() -> Any:
        await _resolve_refs(app, section, obj, body)
        out = await app.ers_create(resource, {wrapper: body})
        clear_name_maps(app)
        return out.get("id")

    return run


def _ers_update(
    app: IseApp, section: str, resource: str, wrapper: str, obj: dict[str, Any], body: dict[str, Any]
) -> Callable[[], Awaitable[Any]]:
    async def run() -> Any:
        await _resolve_refs(app, section, obj, body)
        await app.ers_request(
            "PUT", f"/ers/config/{resource}/{quote(str(body['id']), safe='')}", json={wrapper: body}
        )
        clear_name_maps(app)
        return body["id"]

    return run


def _ers_delete(app: IseApp, resource: str, obj_id: str) -> Callable[[], Awaitable[Any]]:
    async def run() -> Any:
        await app.ers_request("DELETE", f"/ers/config/{resource}/{quote(obj_id, safe='')}", expect="text")
        clear_name_maps(app)
        return obj_id

    return run


# --- planning: custom attributes ----------------------------------------------------------------


def _custom_attributes(
    app: IseApp,
    plan: ImportPlan,
    wanted: list[dict[str, Any]],
    live: list[dict[str, Any]],
    *,
    only: list[str] | None,
    prune: bool,
) -> None:
    want = {str(a.get("attributeName")): a for a in wanted if matches(str(a.get("attributeName")), only)}
    have = {str(a.get("attributeName")): a for a in live}
    for name in sorted(want, key=str.casefold):
        body = {"attributeName": name, "attributeType": want[name].get("attributeType")}
        if name not in have:
            plan.steps.append(Step("create", "custom_attributes", name, _custom_post(app, body)))
        elif have[name].get("attributeType") != body["attributeType"]:
            plan.blockers.append(
                f"Custom attribute {name!r} is {have[name].get('attributeType')} on the target and "
                f"{body['attributeType']} in the export; ISE can't change a type (delete it first)"
            )
        else:
            plan.skip("custom_attributes")
    extra = sorted((n for n in have if n not in want and matches(n, only)), key=str.casefold)
    if extra and not prune:
        plan.left_alone["custom_attributes"] = extra
    for name in extra if prune else []:
        plan.steps.append(Step("delete", "custom_attributes", name, _custom_delete(app, name)))


def _custom_post(app: IseApp, body: dict[str, Any]) -> Callable[[], Awaitable[Any]]:
    async def run() -> Any:
        await app.openapi.request("POST", "/api/v1/endpoint-custom-attribute", json=body, expect="text")
        app.__dict__.pop("_dict_cache", None)
        return body["attributeName"]

    return run


def _custom_delete(app: IseApp, name: str) -> Callable[[], Awaitable[Any]]:
    async def run() -> Any:
        await app.openapi.request(
            "DELETE", f"/api/v1/endpoint-custom-attribute/{quote(name, safe='')}", expect="text"
        )
        app.__dict__.pop("_dict_cache", None)
        return name

    return run


# --- planning: policy sets and rules ------------------------------------------------------------


def condition_api(tree: Any, library: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """An export condition (string / {and|or|not: ...}) as an OpenAPI condition tree."""
    if tree is None:
        return None
    if isinstance(tree, str):
        return condition_node(tree, library)
    if isinstance(tree, dict) and len(tree) == 1:
        ((op, value),) = tree.items()
        if op == "not":
            node = condition_api(value, library)
            if node is None:
                raise InvalidRequest("'not' needs a condition")
            node["isNegate"] = True
            return node
        if op in ("and", "or") and isinstance(value, list):
            return {
                "conditionType": "ConditionAndBlock" if op == "and" else "ConditionOrBlock",
                "isNegate": False,
                "children": [condition_api(c, library) for c in value],
            }
    raise InvalidRequest(f"Unrecognised condition {tree!r} (expected a string or {{and|or|not: ...}})")


def _leaves(node: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not node:
        return []
    if node.get("children"):
        return [leaf for c in node["children"] for leaf in _leaves(c)]
    return [node]


class PolicyContext:
    """What policy planning needs from the target: condition libraries, dictionaries, known names."""

    def __init__(self, app: IseApp) -> None:
        self.app = app
        self.libraries: dict[str, dict[str, dict[str, Any]]] = {}
        self.attrs: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self.names: dict[str, set[str]] = {}

    async def library(self, kind: str) -> dict[str, dict[str, Any]]:
        if kind not in self.libraries:
            self.libraries[kind] = await condition_library(self.app, kind)
        return self.libraries[kind]

    async def condition(self, kind: str, scope: str, tree: Any, where: str, blockers: list[str]) -> Any:
        try:
            node = condition_api(tree, await self.library(kind))
        except InvalidRequest as e:
            blockers.append(f"{where}: {e}")
            return None
        for leaf in _leaves(node):
            if leaf.get("conditionType") != "ConditionAttributes":
                continue
            if str(leaf.get("dictionaryName")).lower() == "endpoints":
                continue  # endpoint custom attributes: not always in the policy dictionary
            if (kind, scope) not in self.attrs:
                self.attrs[(kind, scope)] = await dictionary_attributes(self.app, kind, scope)
            blockers += [f"{where}: {b}" for b in check_attribute(leaf, self.attrs[(kind, scope)])]
        return node

    async def known(self, what: str, path: str) -> set[str]:
        if what not in self.names:
            data = await self.app.openapi.get(path)
            data = data.get("response", data) if isinstance(data, dict) else data
            self.names[what] = {str(x.get("name")) for x in data or [] if isinstance(x, dict)}
        return self.names[what]


REF_PATHS = {
    "profile": "/api/v1/policy/network-access/authorization-profiles",
    "sgt": "/api/v1/policy/network-access/security-groups",
    "commands": "/api/v1/policy/device-admin/command-sets",
    "shell": "/api/v1/policy/device-admin/shell-profiles",
}


async def _check_refs(
    pc: PolicyContext, kind: str, table: str, rule: dict[str, Any], where: str, created: dict[str, set[str]]
) -> list[str]:
    """Rule results that name objects neither on the target nor created by this import."""
    if table == "authentication":
        return []
    checks: list[tuple[str, list[str]]] = []
    if kind == "network-access":
        checks.append(("profile", list(rule.get("profile") or [])))
        if rule.get("securityGroup"):
            checks.append(("sgt", [str(rule["securityGroup"])]))
    else:
        checks.append(("commands", list(rule.get("commands") or [])))
        if rule.get("profile"):
            checks.append(("shell", [str(rule["profile"])]))
    out = []
    labels = {
        "profile": "authorization profile",
        "sgt": "SGT",
        "commands": "command set",
        "shell": "shell profile",
    }
    for what, names in checks:
        known = await pc.known(what, REF_PATHS[what]) | created.get(what, set())
        out += [
            f"{where}: no {labels[what]} {n!r} on the target or in the import"
            for n in names
            if n not in known
        ]
    return out


def _rule_body(rule: dict[str, Any], condition: Any) -> dict[str, Any]:
    head = {"name": rule.get("name"), "rank": rule.get("rank"), "state": rule.get("state", "enabled")}
    head["default"] = bool(rule.get("default"))
    head["condition"] = condition
    body: dict[str, Any] = {"rule": head}
    body.update({k: v for k, v in rule.items() if k not in ("name", "rank", "state", "default", "condition")})
    return body


def _set_body(ps: dict[str, Any], condition: Any) -> dict[str, Any]:
    tables = {key for _, key in RULE_SECTIONS}
    body = {k: v for k, v in ps.items() if k not in tables and k != "condition"}
    body["default"] = bool(ps.get("default"))
    body["condition"] = condition
    body.setdefault("state", "enabled")
    body.setdefault("isProxy", False)
    return body


async def _policy(
    app: IseApp,
    plan: ImportPlan,
    wanted: dict[str, Any],
    live: dict[str, Any],
    run: Export,
    *,
    only: list[str] | None,
    prune: bool,
    created: dict[str, set[str]],
) -> None:
    pc = PolicyContext(app)
    for kind in KINDS:
        want_kind = (wanted or {}).get(kind)
        if want_kind is None:
            continue
        if kind not in (live or {}):
            plan.blockers.append(
                f"{kind} policy can't be read on the target ({run.skipped.get(f'policy_sets.{kind}')})"
            )
            continue
        have_kind = live[kind]
        raw_sets = {str(p.get("name")): p for p in run.raw_sets.get(kind) or []}
        have_sets = {str(s.get("name")): s for s in have_kind.get("sets") or []}
        want_sets = [s for s in want_kind.get("sets") or [] if _set_in_filter(s, only)]
        moved_sets = _moved(
            [
                str(s.get("name"))
                for s in have_kind.get("sets") or []
                if str(s.get("name")) in {str(w.get("name")) for w in want_sets}
            ],
            [str(s.get("name")) for s in want_sets],
        )
        rule_keys = tuple(k for _, k in RULE_SECTIONS)
        for ps in want_sets:
            name = str(ps.get("name"))
            where = f"{kind}/{name}"

            async def body_of(
                ps: dict[str, Any] = ps, where: str = where, kind: str = kind
            ) -> dict[str, Any]:
                if ps.get("default"):
                    return _set_body(ps, None)
                cond = await pc.condition(kind, "policyset", ps.get("condition"), where, plan.blockers)
                return _set_body(ps, cond)

            if name not in have_sets:
                if ps.get("default"):
                    plan.blockers.append(f"{where}: the target has no default policy set to update")
                    continue
                plan.steps.append(
                    Step("create", "policy_sets", where, _set_create(app, kind, await body_of()))
                )
                current_rules: dict[str, list[dict[str, Any]]] = {}
                raw_rules: dict[str, list[dict[str, Any]]] = {}
                fresh = True
            else:
                strip = {k: v for k, v in have_sets[name].items() if k not in rule_keys}
                want_strip = {k: v for k, v in ps.items() if k not in rule_keys}
                changes = given_changes(strip, want_strip, ignore=("rank",))
                if name in moved_sets:
                    changes["rank"] = {"from": have_sets[name].get("rank"), "to": ps.get("rank")}
                if changes:
                    plan.steps.append(
                        Step(
                            "update",
                            "policy_sets",
                            where,
                            _set_update(app, kind, raw_sets[name], await body_of()),
                            changes,
                        )
                    )
                else:
                    plan.skip("policy_sets")
                current_rules = {k: have_sets[name].get(k) or [] for k in rule_keys}
                base = f"/api/v1/policy/{kind}/policy-set/{raw_sets[name]['id']}"
                raw_rules = {key: run.raw_rules.get(f"{base}/{path}") or [] for path, key in RULE_SECTIONS}
                fresh = False
            for path, key in RULE_SECTIONS:
                await _rules(
                    app,
                    plan,
                    pc,
                    kind,
                    f"{where}/{key}",
                    RULE_SCOPE.get(key, "authorization"),
                    key,
                    ps.get(key) or [],
                    current_rules.get(key) or [],
                    raw_rules.get(key) or [],
                    base=_SetPath(kind, name, path),
                    only=None if _set_matches(ps, only) else only,
                    prune=prune,
                    created=created,
                    fresh_set=fresh,
                )
        for name, cur in have_sets.items():
            if any(str(w.get("name")) == name for w in want_sets) or not _set_in_filter(cur, only):
                continue
            if cur.get("default") or not matches(name, only):
                continue
            if prune:
                plan.steps.append(
                    Step(
                        "delete",
                        "policy_sets",
                        f"{kind}/{name}",
                        _set_delete(app, kind, str(raw_sets[name]["id"])),
                    )
                )
            else:
                plan.left_alone.setdefault("policy_sets", []).append(f"{kind}/{name}")
        globals_want = want_kind.get("global_exceptions") or []
        globals_have = have_kind.get("global_exceptions") or []
        if globals_want or (prune and globals_have):
            gpath = f"/api/v1/policy/{kind}/policy-set/global-exception"
            await _rules(
                app,
                plan,
                pc,
                kind,
                f"{kind}/global_exceptions",
                "authorization",
                "global_exceptions",
                globals_want,
                globals_have,
                run.raw_rules.get(gpath) or [],
                base=_SetPath(kind, None, "global-exception"),
                only=only,
                prune=prune,
                created=created,
                fresh_set=False,
            )


def _set_matches(ps: dict[str, Any], only: list[str] | None) -> bool:
    return matches(str(ps.get("name")), only)


def _set_in_filter(ps: dict[str, Any], only: list[str] | None) -> bool:
    """A policy set is in the import when its name matches, or any of its rules' names do."""
    if _set_matches(ps, only):
        return True
    return any(matches(str(r.get("name")), only) for _, k in RULE_SECTIONS for r in ps.get(k) or [])


@dataclass
class _SetPath:
    """Where a rule table lives; the policy set id is looked up when a step runs (it may be new)."""

    kind: str
    set_name: str | None  # None: global exceptions
    table: str  # API path segment

    async def url(self, app: IseApp) -> str:
        if self.set_name is None:
            return f"/api/v1/policy/{self.kind}/policy-set/{self.table}"
        sets = await list_policy_sets(app, self.kind)
        ps = next((p for p in sets if p.get("name") == self.set_name), None)
        if ps is None:
            raise NotFound(f"Policy set {self.set_name!r} does not exist", 404)
        return f"/api/v1/policy/{self.kind}/policy-set/{ps['id']}/{self.table}"


async def _rules(
    app: IseApp,
    plan: ImportPlan,
    pc: PolicyContext,
    kind: str,
    where: str,
    scope: str,
    table: str,
    wanted: list[dict[str, Any]],
    live: list[dict[str, Any]],
    raw: list[dict[str, Any]],
    *,
    base: _SetPath,
    only: list[str] | None,
    prune: bool,
    created: dict[str, set[str]],
    fresh_set: bool,
) -> None:
    """One rule table. Rules are planned in export rank order so ISE places each at its rank."""
    want = [r for r in wanted if r.get("default") or matches(str(r.get("name")), only)]
    have = {str(r.get("name")): r for r in live}
    raw_by_name = {str((r.get("rule") or {}).get("name")): r for r in raw}
    moved = _moved(
        [n for n in have if n in {str(w.get("name")) for w in want}], [str(w.get("name")) for w in want]
    )
    for rule in sorted(want, key=lambda r: (r.get("rank") is None, r.get("rank") or 0)):
        name = str(rule.get("name"))
        label = f"{where}/{name}"
        default = bool(rule.get("default"))
        changes: dict[str, Any] | None = None
        if default and not fresh_set and name not in have:
            plan.blockers.append(f"{label}: the target table has no Default rule")
            continue
        if name in have and not fresh_set:
            changes = field_changes(have[name], rule, ignore=("rank",))
            if name in moved and not default:
                changes["rank"] = {"from": have[name].get("rank"), "to": rule.get("rank")}
            if not changes:
                plan.skip("policy_rules")
                continue
        # Only rules that change are checked and built (conditions need the library and dictionaries).
        cond = (
            None if default else await pc.condition(kind, scope, rule.get("condition"), label, plan.blockers)
        )
        plan.blockers += await _check_refs(pc, kind, table, rule, label, created)
        body = _rule_body(rule, cond)
        if default and fresh_set:
            # ISE creates the Default rule with every policy set; only its result can change.
            step = Step("update", "policy_rules", label, _default_rule_update(app, base, body))
        elif changes is None:
            step = Step("create", "policy_rules", label, _rule_create(app, base, body))
        else:
            run = _rule_update(app, base, raw_by_name[name], body, keep_rank=default)
            step = Step("update", "policy_rules", label, run, changes)
        plan.steps.append(step)
    for name, cur in have.items():
        if cur.get("default") or any(str(w.get("name")) == name for w in want) or not matches(name, only):
            continue
        if prune:
            rid = str((raw_by_name.get(name, {}).get("rule") or {}).get("id"))
            plan.steps.append(Step("delete", "policy_rules", f"{where}/{name}", _rule_delete(app, base, rid)))
        else:
            plan.left_alone.setdefault("policy_rules", []).append(f"{where}/{name}")


def _set_create(app: IseApp, kind: str, body: dict[str, Any]) -> Callable[[], Awaitable[Any]]:
    async def run() -> Any:
        data = await app.openapi.post(f"/api/v1/policy/{kind}/policy-set", body)
        data = data.get("response", data) if isinstance(data, dict) else data
        return data.get("id") if isinstance(data, dict) else None

    return run


def _set_update(
    app: IseApp, kind: str, raw: dict[str, Any], body: dict[str, Any]
) -> Callable[[], Awaitable[Any]]:
    async def run() -> Any:
        desired = deep_merge(strip_links(raw), body)
        desired["condition"] = body["condition"]  # a condition is replaced, never merged
        desired["id"] = raw["id"]
        await app.openapi.put(f"/api/v1/policy/{kind}/policy-set/{quote(str(raw['id']), safe='')}", desired)
        return raw["id"]

    return run


def _set_delete(app: IseApp, kind: str, ps_id: str) -> Callable[[], Awaitable[Any]]:
    async def run() -> Any:
        await app.openapi.request("DELETE", f"/api/v1/policy/{kind}/policy-set/{quote(ps_id, safe='')}")
        return ps_id

    return run


def _rule_create(app: IseApp, base: _SetPath, body: dict[str, Any]) -> Callable[[], Awaitable[Any]]:
    async def run() -> Any:
        data = await app.openapi.post(await base.url(app), body)
        data = data.get("response", data) if isinstance(data, dict) else data
        return ((data or {}).get("rule") or {}).get("id") if isinstance(data, dict) else None

    return run


def _rule_update(
    app: IseApp, base: _SetPath, raw: dict[str, Any], body: dict[str, Any], *, keep_rank: bool = False
) -> Callable[[], Awaitable[Any]]:
    async def run() -> Any:
        rule = raw.get("rule") or {}
        head = {**body["rule"], "id": rule.get("id")}
        if keep_rank:
            head["rank"] = rule.get("rank")
        desired = {**body, "rule": head}
        await app.openapi.put(f"{await base.url(app)}/{quote(str(rule.get('id')), safe='')}", desired)
        return rule.get("id")

    return run


def _default_rule_update(app: IseApp, base: _SetPath, body: dict[str, Any]) -> Callable[[], Awaitable[Any]]:
    """The Default rule of a policy set created earlier in this run: find it, then set its result."""

    async def run() -> Any:
        url = await base.url(app)
        data = await app.openapi.get(url)
        data = data.get("response", data) if isinstance(data, dict) else data
        current = next((r for r in data or [] if (r.get("rule") or {}).get("default")), None)
        if current is None:
            raise NotFound(f"No Default rule at {url}", 404)
        rule = current["rule"]
        desired = {**body, "rule": {**body["rule"], "id": rule["id"], "rank": rule.get("rank")}}
        await app.openapi.put(f"{url}/{quote(str(rule['id']), safe='')}", desired)
        return rule["id"]

    return run


def _rule_delete(app: IseApp, base: _SetPath, rule_id: str) -> Callable[[], Awaitable[Any]]:
    async def run() -> Any:
        await app.openapi.request("DELETE", f"{await base.url(app)}/{quote(rule_id, safe='')}")
        return rule_id

    return run


# --- the whole plan -----------------------------------------------------------------------------


async def plan_import(
    app: IseApp,
    source: dict[str, Any],
    sections: list[str] | None = None,
    *,
    only: list[str] | None = None,
    prune: bool = False,
    secrets: dict[str, dict[str, str]] | None = None,
) -> ImportPlan:
    exported = [s for s in source[HEADER].get("sections") or [] if s in SECTIONS]
    wanted = [s for s in exported if sections is None or s in sections]
    run = Export(app, max_objects=100_000)
    live = await export_config(app, resolve_scope(wanted) if wanted else [], run=run)
    plan = ImportPlan(live_digest=str(live[HEADER].get("digest")))
    secrets = secrets or {}
    if source[HEADER].get("incomplete"):
        plan.notes.append(
            f"The export is partial ({source[HEADER]['incomplete']}); prune is limited to what it has"
        )
        if prune:
            plan.blockers.append(
                "prune is refused for a partial export: it would delete what the export missed"
            )
    nads = {str(n.get("name")) for n in source.get("nads") or []}
    unknown = sorted(k for k in secrets if k not in nads or "nads" not in wanted)
    if unknown:
        plan.blockers.append(f"secrets given for NADs not in this import: {', '.join(unknown)}")
    created = _created_names(source, live, only)
    for section in APPLY_ORDER:
        if section not in wanted:
            continue
        if section in live[HEADER].get("skipped", {}):
            plan.blockers.append(
                f"{section} can't be read on the target ({live[HEADER]['skipped'][section]})"
            )
            continue
        if section == "policy_sets":
            await _policy(
                app,
                plan,
                source.get(section) or {},
                live.get(section) or {},
                run,
                only=only,
                prune=prune,
                created=created,
            )
        elif section == "custom_attributes":
            _custom_attributes(
                app, plan, source.get(section) or [], live.get(section) or [], only=only, prune=prune
            )
        else:
            raw = run.raw.get(section) or []
            live_objs = live.get(section) or []
            if section == "egress_matrix":
                raw = _label_cells(raw, run)
            _ers_section(
                app,
                plan,
                section,
                source.get(section) or [],
                live_objs,
                raw,
                only=only,
                prune=prune,
                secrets=secrets,
            )
    if "allowed_protocols" in wanted:
        plan.notes.append(
            "allowed_protocols is exported for review and diff only: create or change a service with "
            "ise_set_allowed_protocols"
        )
    plan.steps = _deletes_last(plan.steps)
    return plan


def _deletes_last(steps: list[Step]) -> list[Step]:
    """Creates and updates in dependency order, then deletes in reverse (rules before their policy set,
    a NAD before its device group, a profile before its dACL)."""
    rank = {s: i for i, s in enumerate(APPLY_ORDER)}
    rank["policy_rules"] = len(APPLY_ORDER)  # deleted before policy sets
    keep = [s for s in steps if s.op != "delete"]
    deletes = [s for s in steps if s.op == "delete"]
    return keep + sorted(deletes, key=lambda s: -rank[s.section])


def _created_names(
    source: dict[str, Any], live: dict[str, Any], only: list[str] | None
) -> dict[str, set[str]]:
    """Names this import creates, by rule-result reference kind (they count as known)."""
    out: dict[str, set[str]] = {}
    for what, section in (
        ("profile", "authz_profiles"),
        ("sgt", "sgts"),
        ("commands", "command_sets"),
        ("shell", "shell_profiles"),
    ):
        out[what] = {
            str(o.get("name")) for o in source.get(section) or [] if matches(str(o.get("name")), only)
        }
    return out


def _label_cells(raw: list[dict[str, Any]], run: Export) -> list[dict[str, Any]]:
    """Raw egress cells carrying the source/destination SGT names the export keys them by."""
    out = []
    for r in raw:
        cell = norm_matrix([r], run.sgt_names, run.acl_names)[0]
        out.append({**r, "source": cell["source"], "destination": cell["destination"]})
    return out


def plan_view(plan: ImportPlan, source: dict[str, Any], cap: int = STEP_LIST_CAP) -> dict[str, Any]:
    counts = {op: sum(1 for s in plan.steps if s.op == op) for op in ("create", "update", "delete")}
    counts["unchanged"] = sum(plan.skipped.values())
    header = source[HEADER]
    out: dict[str, Any] = {
        "source": {k: header.get(k) for k in ("hostname", "exported_at", "digest")},
        "summary": counts,
        "steps": [{"#": i + 1, **s.view()} for i, s in enumerate(plan.steps[:cap])],
    }
    if len(plan.steps) > cap:
        out["steps_not_shown"] = len(plan.steps) - cap
    if plan.skipped:
        out["unchanged"] = dict(sorted(plan.skipped.items()))
    if plan.left_alone:
        out["not_in_export"] = {
            "note": "On the target but not in the export: left alone (prune=true deletes them)",
            **{k: v[:50] for k, v in sorted(plan.left_alone.items())},
        }
    if plan.notes:
        out["notes"] = plan.notes
    return out


async def apply_plan(plan: ImportPlan) -> dict[str, Any]:
    """Run the steps in order; stop at the first failure and report what happened."""
    done: list[str] = []
    for i, step in enumerate(plan.steps):
        try:
            await step.run()
        except (UpstreamError, NotFound, InvalidRequest) as e:
            rest = len(plan.steps) - i - 1
            raise UpstreamError(
                f"Import stopped at step {i + 1} of {len(plan.steps)} ({step.label()}): {str(e)[:300]}. "
                f"Applied before it ({len(done)}): {', '.join(done) or 'nothing'}. "
                f"Not attempted: {rest} step(s). "
                "Fix the cause and run ise_import_config again: it plans from the target's new state."
            ) from e
        done.append(step.label())
    return {"applied": len(done), "steps": done[:STEP_LIST_CAP]}


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Import ISE configuration from an export")
    async def ise_import_config(
        ctx: Context,
        source: Annotated[
            str, Field(description="An ise_export_config export: a path to its .yaml file, or the YAML text")
        ],
        scope: Scope = None,
        only: Annotated[
            list[str] | None,
            Field(
                description="Only objects whose name matches one of these globs, e.g. ['mcp-test-*'] (case-"
                "insensitive; rules match by rule or policy set name, egress cells by either SGT). "
                "Also limits prune"
            ),
        ] = None,
        secrets: Secrets = None,
        prune: Annotated[
            bool,
            Field(
                description="Also delete objects of the imported sections (within `only`) that the "
                "export lacks"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Apply an ise_export_config export to this ISE (another ISE's, or a saved baseline): plans
        one step per object, matched by name, in dependency order (device and identity groups, custom
        attributes, SGTs, SGACLs and egress cells, dACLs, authorization profiles, TACACS+ command sets
        and shell profiles, NADs, then policy sets and their rules in rank order). Objects already the
        same are skipped; objects on the target that the export lacks are left alone unless prune=true.
        NAD secrets are masked in exports, so pass them in `secrets`. The preview is the whole plan
        with field-level changes; confirm applies it step by step and stops at the first failure,
        saying what was applied. Afterwards ise_diff_config(before=<the export>) should be empty."""
        app: IseApp = get_client(ctx)
        doc = read_source(app.settings, source)
        sections = resolve_scope(scope) if scope else None
        plan = await plan_import(app, doc, sections, only=only, prune=prune, secrets=secrets)
        view = plan_view(plan, doc)
        counts = view["summary"]
        summary = (
            f"Import {counts['create']} create, {counts['update']} update, {counts['delete']} delete "
            f"({counts['unchanged']} unchanged)"
        )
        blockers = list(plan.blockers)
        if not plan.steps and not blockers:
            blockers.append("Nothing to do: the target already matches the export")
        side = ["Policy changes take effect at the next authentication (no CoA is sent)"]
        if counts["delete"]:
            side.append(f"{counts['delete']} object(s) are deleted (prune)")
        return await preview_or_apply(
            ctx,
            tool="ise_import_config",
            args={"source": source, "scope": scope, "only": only, "secrets": secrets, "prune": prune},
            confirm=confirm,
            plan=Plan(
                summary,
                details=view,
                blockers=blockers,
                fingerprint=fingerprint([s.view() for s in plan.steps]),  # what the confirm depends on
                side_effects=side,
                blast_radius=len(plan.steps),
            ),
            apply=lambda: apply_plan(plan),
        )

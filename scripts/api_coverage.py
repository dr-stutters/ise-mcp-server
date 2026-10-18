"""ISE API coverage: which operations of the live ISE API are behind a curated tool.

    set -a; . /path/to/lab-secrets.env; set +a
    ISE_URL=https://ise ISE_USERNAME=$LAB_ISE_USERNAME ISE_PASSWORD=$LAB_ISE_PASSWORD \
        uv run python scripts/api_coverage.py --save-spec /tmp/ise-spec.json > /tmp/coverage.md
    uv run python scripts/api_coverage.py --spec /tmp/ise-spec.json --uncovered --by-tool

Spec side: the same loaders the server uses for ise_search_spec (src/ise_mcp/specs.py): every springfox
OpenAPI group from /api/swagger-resources + /api/v3/api-docs?group=..., the ERS data model
(/ers/data-model.json, synthesised into list/create/get/update/delete per resource) and the hand-written
MnT doc. `--save-spec` keeps a compact (group, method, path, summary) snapshot so the table can be
regenerated offline with `--spec`.

Tool side: static analysis of src/ise_mcp/tools/*.py. Every function decorated with @reg.read/write/
dangerous is a tool; its body (and the helpers it calls, transitively, within the tools package) is
scanned for the client calls that reach ISE: app.openapi.get/post/put/delete/request, app.ers_request,
app.sponsor_request, app.ers_get/ers_find/ers_create, app.ers_pager.fetch_page, app.mnt_get and the
_common helpers (ers_list, ers_resolve, ers_name_map, openapi_all, ...). f-string placeholders are
resolved where the value is a literal, a module constant or a dict of constants (e.g. DELETE_KINDS);
anything else becomes a wildcard that matches one path segment. OVERRIDES below patches the few places
the heuristics cannot see through.

The counts are per operation (method + path). A tool that only reads an object's name still counts the
GET it uses; "covered" means "some curated tool calls it", not "fully modelled".
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT / "src" / "ise_mcp" / "tools"
METHODS = ("get", "post", "put", "patch", "delete")

# Endpoints the static scan cannot attribute (paths assembled outside the tools package, or passed in
# from data). tool -> [(method, path)].
OVERRIDES: dict[str, list[tuple[str, str]]] = {
    # ise_status probes all three surfaces (client.py _probe).
    "ise_status": [
        ("GET", "/api/v1/deployment/node"),
        ("GET", "/ers/config/op/systemconfig/iseversion"),
        ("GET", "/admin/API/mnt/Version"),
    ],
}
# Matches the wildcard heuristics produce that the tool never makes: tool -> [(method, path)].
EXCLUDE: dict[str, list[tuple[str, str]]] = {
    # _SetPath.url builds /policy/{kind}/policy-set/{table}: the table is a rule section, never these.
    "ise_import_config": [
        ("POST", "/api/v1/policy/network-access/policy-set/reset-hitcount"),
        ("POST", "/api/v1/policy/device-admin/policy-set/reset-hitcount"),
        ("GET", "/api/v1/policy/network-access/policy-set/{policyId}/mfa"),
        ("POST", "/api/v1/policy/network-access/policy-set/{policyId}/mfa"),
        ("GET", "/api/v1/policy/device-admin/policy-set/{policyId}/mfa"),
        ("POST", "/api/v1/policy/device-admin/policy-set/{policyId}/mfa"),
    ],
}
# Registered by the core, not under tools/: the escape hatch and the spec browser reach everything by
# design, so they are not coverage. ise_status is (OVERRIDES).
CORE_TOOLS = ("ise_status", "ise_search_spec", "ise_get_definition", "ise_api_call")
GENERIC_TOOLS = {"ise_api_call", "ise_search_spec", "ise_get_definition", "ise_review_change"}

# Client primitives: callee name -> how to turn the call into (method, path-expression).
# "arg" = index of the path argument; "method" = fixed method or index of the method argument;
# "ers_res" = index of the ERS resource argument, with the shape of the path.
PRIMITIVES: dict[str, dict[str, Any]] = {
    "get": {"recv": "openapi", "method": "GET", "arg": 0},
    "post": {"recv": "openapi", "method": "POST", "arg": 0},
    "put": {"recv": "openapi", "method": "PUT", "arg": 0},
    "delete": {"recv": "openapi", "method": "DELETE", "arg": 0},
    "request": {"recv": "openapi", "method": 0, "arg": 1},
    "ers_request": {"method": 0, "arg": 1},
    "sponsor_request": {"method": 0, "arg": 1},
    "mnt_get": {"method": "GET", "arg": 0, "prefix": "/admin/API/mnt/"},
    "failure_reasons": {"method": "GET", "fixed": "/admin/API/mnt/FailureReasons"},
    "fetch_page": {"method": "GET", "arg": 1},
    "openapi_all": {"method": "GET", "arg": 1},
    "name_list": {"method": "GET", "arg": 1},
    "ers_get": {"ers_res": 0, "shape": [("GET", "/ers/config/{res}/{id}")]},
    "ers_find": {"ers_res": 0, "shape": [("GET", "/ers/config/{res}")]},
    "ers_create": {"ers_res": 0, "shape": [("POST", "/ers/config/{res}")]},
    "ers_list": {"ers_res": 1, "shape": [("GET", "/ers/config/{res}"), ("GET", "/ers/config/{res}/{id}")]},
    "ers_resolve": {"ers_res": 1, "shape": [("GET", "/ers/config/{res}"), ("GET", "/ers/config/{res}/{id}")]},
    "ers_name_map": {"ers_res": 1, "shape": [("GET", "/ers/config/{res}")]},
    "ers_put": {"ers_res": 1, "shape": [("PUT", "/ers/config/{res}/{id}")]},
    "ers_post": {"ers_res": 1, "shape": [("POST", "/ers/config/{res}")]},
}
# Names of f-string placeholders that are ids/keys: they match only {param} segments of a spec path,
# never a literal segment (so /endpoint/{mac} does not swallow /endpoint/getRejected).
ID_LIKE = re.compile(
    r"(^|_)(id|ids|mac|mac_n|host|node|name|key|cid|gid|rid|psn|addr|ip|value|task_id)$|_id$"
)


# --- path templates ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Seg:
    """One path segment of a tool-side template: a literal, or a placeholder."""

    literal: str | None = None
    values: frozenset[str] | None = None  # enumerated literal values (dict constants), else None
    param_only: bool = False  # placeholder may only match a {param} segment of the spec

    def matches(self, spec_seg: str) -> bool:
        is_param = spec_seg.startswith("{") and spec_seg.endswith("}")
        if self.literal is not None:
            return self.literal == spec_seg or (is_param and False)
        if self.values is not None:
            return spec_seg in self.values or is_param
        return is_param or not self.param_only


@dataclass(frozen=True)
class Template:
    method: str
    segs: tuple[Seg, ...]
    source: str  # where it came from, for diagnostics

    def matches(self, method: str, spec_path: str) -> bool:
        if method != self.method:
            return False
        parts = spec_path.strip("/").split("/")
        if len(parts) != len(self.segs):
            return False
        return all(s.matches(p) for s, p in zip(self.segs, parts, strict=True))

    def text(self) -> str:
        out = []
        for s in self.segs:
            if s.literal is not None:
                out.append(s.literal)
            elif s.values is not None:
                out.append(
                    next(iter(s.values)) if len(s.values) == 1 else "{" + "|".join(sorted(s.values)) + "}"
                )
            else:
                out.append("{*}")
        return "/" + "/".join(out)


# --- static analysis ----------------------------------------------------------------------------------


@dataclass
class Module:
    name: str
    tree: ast.Module
    constants: dict[str, ast.AST] = field(default_factory=dict)  # module-level constant expressions
    functions: dict[str, list[ast.AST]] = field(default_factory=dict)  # module-scope defs (+ register())
    methods: dict[str, list[ast.AST]] = field(default_factory=dict)  # class methods, by name
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)  # local name -> (module, name)


@dataclass
class Tool:
    name: str
    module: str
    tier: str
    templates: list[Template] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)


Values = frozenset[str] | None  # None = unknown / wildcard
FuncDef = ast.FunctionDef | ast.AsyncFunctionDef


def _const_values(node: ast.AST | None) -> Values:
    """Literal string values a constant expression can take (str, dict of str, tuple/list/set of str)."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return frozenset([node.value])
    if isinstance(node, ast.Dict):
        vals: set[str] = set()
        for v in node.values:
            got = _const_values(v)
            if got is None:
                return None
            vals |= got
        return frozenset(vals)
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        vals = set()
        for e in node.elts:
            got = _const_values(e)
            if got is None:
                return None
            vals |= got
        return frozenset(vals)
    return None


def _is_const(node: ast.AST) -> bool:
    return _const_values(node) is not None


def load_modules() -> dict[str, Module]:
    mods: dict[str, Module] = {}
    for path in sorted(TOOLS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        mod = Module(path.stem, tree)
        for node in tree.body:
            if isinstance(node, ast.Assign) and _is_const(node.value):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        mod.constants[t.id] = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
                if _is_const(node.value):
                    mod.constants[node.target.id] = node.value
            elif (
                isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("ise_mcp.tools.")
            ):
                src_mod = node.module.rsplit(".", 1)[-1]
                for alias in node.names:
                    mod.imports[alias.asname or alias.name] = (src_mod, alias.name)
            elif isinstance(node, FuncDef):
                mod.functions.setdefault(node.name, []).append(node)
                if node.name == "register":  # helpers shared by the tools live inside register()
                    for inner in node.body:
                        if isinstance(inner, FuncDef) and not inner.decorator_list:
                            mod.functions.setdefault(inner.name, []).append(inner)
            elif isinstance(node, ast.ClassDef):
                for inner in node.body:
                    if isinstance(inner, FuncDef):
                        mod.methods.setdefault(inner.name, []).append(inner)
        mods[path.stem] = mod
    return mods


class Analyzer:
    def __init__(self, mods: dict[str, Module]) -> None:
        self.mods = mods
        self.tools: list[Tool] = []

    # -- discovery
    def find_tools(self) -> list[Tool]:
        for m in self.mods.values():
            for node in ast.walk(m.tree):
                if not isinstance(node, FuncDef):
                    continue
                for dec in node.decorator_list:
                    call = dec if isinstance(dec, ast.Call) else None
                    target = call.func if call else dec
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "reg"
                        and target.attr in ("read", "write", "dangerous")
                    ):
                        name = node.name
                        if call:
                            for kw in call.keywords:
                                if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                                    name = str(kw.value.value)
                        tool = Tool(name, m.name, target.attr)
                        self.scan(tool, m, node, env={}, visited=set())
                        for method, path in OVERRIDES.get(name, []):
                            tool.templates.append(self._template(method, path, "override"))
                        resolved_sites = {t.source.rsplit(" ", 1)[-1] for t in tool.templates}
                        tool.unresolved = sorted(
                            {u for u in tool.unresolved if u.split(" ", 1)[0] not in resolved_sites}
                        )
                        self.tools.append(tool)
        found = {t.name for t in self.tools}
        for name, ops in OVERRIDES.items():
            if name not in found:  # registered by the core (ise_status): only what OVERRIDES says
                tool = Tool(name, "core", "read")
                tool.templates = [self._template(m, p, "override") for m, p in ops]
                self.tools.append(tool)
        self.tools.sort(key=lambda t: t.name)
        return self.tools

    # -- callee resolution (scoped: nested defs are already in the walk; then module, imports, methods)
    def resolve_callee(self, mod: Module, fn: ast.AST, func: ast.AST) -> list[tuple[Module, ast.AST]]:
        nested = {n.name: n for n in ast.walk(fn) if isinstance(n, FuncDef) and n is not fn}
        if isinstance(func, ast.Name):
            if func.id in nested:  # a closure: walked inline already, but re-scan it with the call's bindings
                return [(mod, nested[func.id])] if nested[func.id].args.args else []
            if func.id in mod.functions:
                return [(mod, d) for d in mod.functions[func.id]]
            if func.id in mod.imports:
                src_mod, orig = mod.imports[func.id]
                target = self.mods.get(src_mod)
                if target and orig in target.functions:
                    return [(target, d) for d in target.functions[orig]]
            return []
        if isinstance(func, ast.Attribute):
            name = func.attr
            if name in mod.methods:
                return [(mod, d) for d in mod.methods[name]]
            for src_mod, _ in set(mod.imports.values()):
                target = self.mods.get(src_mod)
                if target and name in target.methods:
                    return [(target, d) for d in target.methods[name]]
        return []

    # -- scanning
    def scan(
        self,
        tool: Tool,
        mod: Module,
        fn: ast.AST,
        env: dict[str, Values],
        visited: set[int],
        outer: _Ctx | None = None,
    ) -> None:
        key = (id(fn), tuple(sorted((k, v) for k, v in env.items() if v is not None)))
        if hash(key) in visited:
            return
        visited.add(hash(key))
        ctx = _Ctx(self, mod, fn, env, outer)
        nested = {id(n) for n in ast.walk(fn) if isinstance(n, FuncDef) and n is not fn}
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            callee = _callee_name(node.func)
            if callee is None:
                continue
            prim = PRIMITIVES.get(callee)
            if prim and self._primitive_applies(node, prim):
                self._record_primitive(tool, node, prim, ctx, callee)
                continue
            for target_mod, target in self.resolve_callee(mod, fn, node.func):
                sub_env = self._bind(target, node, ctx)
                # a closure sees the enclosing function's names (base = f"..."; one(section) uses base)
                self.scan(tool, target_mod, target, sub_env, visited, ctx if id(target) in nested else None)

    @staticmethod
    def _primitive_applies(call: ast.Call, prim: dict[str, Any]) -> bool:
        recv = prim.get("recv")
        if recv is None:
            return True
        # app.openapi.get(...) / self.app.openapi.get(...): the receiver must be the openapi client
        f = call.func
        return isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute) and f.value.attr == recv

    def _record_primitive(
        self, tool: Tool, call: ast.Call, prim: dict[str, Any], ctx: _Ctx, callee: str
    ) -> None:
        where = f"{ctx.mod.name}:{call.lineno}"
        if "ers_res" in prim:
            res = self._arg(call, prim["ers_res"], "resource")
            vals = ctx.resolve(res) if res is not None else None
            if not vals:
                tool.unresolved.append(f"{where} {callee}(resource={ast.unparse(res)[:40] if res else '?'})")
                return
            for method, shape in prim["shape"]:
                segs: list[Seg] = []
                for part in shape.strip("/").split("/"):
                    if part == "{res}":
                        segs.append(Seg(values=vals))
                    elif part == "{id}":
                        segs.append(Seg(param_only=True))
                    else:
                        segs.append(Seg(literal=part))
                tool.templates.append(Template(method, tuple(segs), f"{callee}() {where}"))
            return
        if "fixed" in prim:
            tool.templates.append(self._template(prim["method"], prim["fixed"], f"{callee}() {where}"))
            return
        m = prim["method"]
        if isinstance(m, int):
            marg = self._arg(call, m, "method")
            mvals = ctx.resolve(marg) if marg is not None else None
            methods = sorted(mvals) if mvals else ["?"]
        else:
            methods = [m]
        parg = self._arg(call, prim["arg"], "path")
        if parg is None:
            tool.unresolved.append(f"{where} {callee}() without a path")
            return
        templates = ctx.path_templates(parg)
        if not templates:
            tool.unresolved.append(f"{where} {callee}({ast.unparse(parg)[:60]})")
            return
        prefix = prim.get("prefix", "")
        for found in templates:
            full = tuple(Seg(literal=p) for p in prefix.strip("/").split("/")) + found if prefix else found
            if _ers_resource_unknown(full):
                tool.unresolved.append(f"{where} {callee}({ast.unparse(parg)[:60]}): ERS resource unknown")
                continue
            for method in methods:
                tool.templates.append(Template(method.upper(), full, f"{callee}() {where}"))

    @staticmethod
    def _arg(call: ast.Call, idx: int, kw: str) -> ast.AST | None:
        if len(call.args) > idx:
            return call.args[idx]
        for k in call.keywords:
            if k.arg == kw:
                return k.value
        return None

    def _bind(self, target: ast.AST, call: ast.Call, ctx: _Ctx) -> dict[str, Values]:
        """Map the callee's parameters to the caller's argument values (where they resolve)."""
        assert isinstance(target, FuncDef)
        params = [a.arg for a in target.args.posonlyargs + target.args.args]
        if params and params[0] == "self":
            params = params[1:]
        env: dict[str, Values] = {}
        for i, a in enumerate(call.args):
            if i < len(params):
                env[params[i]] = ctx.resolve(a)
        for k in call.keywords:
            if k.arg:
                env[k.arg] = ctx.resolve(k.value)
        for kwonly in target.args.kwonlyargs:
            env.setdefault(kwonly.arg, None)
        return env

    @staticmethod
    def _template(method: str, path: str, source: str) -> Template:
        segs = tuple(
            Seg(param_only=True) if p.startswith("{") else Seg(literal=p) for p in path.strip("/").split("/")
        )
        return Template(method, segs, source)


class _Ctx:
    """Name resolution inside one function: bound parameters, local assignments, module constants."""

    def __init__(
        self, analyzer: Analyzer, mod: Module, fn: ast.AST, env: dict[str, Values], outer: _Ctx | None = None
    ) -> None:
        self.analyzer, self.mod, self.fn, self.env = analyzer, mod, fn, env
        self.local = self._local_assignments(fn)
        if outer is not None:  # closure: the enclosing function's bindings and locals, unless shadowed
            for name, bound in outer.env.items():
                self.env.setdefault(name, bound)
            for name, assigned in outer.local.items():
                if name not in self.local and name not in self.env:
                    self.local[name] = assigned
        self._busy: set[str] = set()

    @staticmethod
    def _local_assignments(fn: ast.AST) -> dict[str, list[ast.AST]]:
        """name -> expressions assigned to it anywhere in the function (plain, tuple-unpacked, loop and
        comprehension targets)."""
        out: dict[str, list[ast.AST]] = defaultdict(list)

        def unpack(target: ast.AST, value: ast.AST) -> None:
            if isinstance(target, ast.Name):
                out[target.id].append(value)
            elif isinstance(target, ast.Tuple | ast.List):
                if isinstance(value, ast.Tuple | ast.List) and len(value.elts) == len(target.elts):
                    for t, v in zip(target.elts, value.elts, strict=True):
                        unpack(t, v)
                elif isinstance(value, ast.IfExp):
                    unpack(target, value.body)
                    unpack(target, value.orelse)
                elif isinstance(value, ast.expr):  # x, y = TABLE[key]: positional slices of a dict of tuples
                    for i, t in enumerate(target.elts):
                        out_node = ast.Subscript(value=value, slice=ast.Constant(i), ctx=ast.Load())
                        out_node._positional = True  # type: ignore[attr-defined]
                        unpack(t, out_node)

        for node in ast.walk(fn):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    unpack(t, node.value)
            elif isinstance(node, ast.AnnAssign) and node.value:
                unpack(node.target, node.value)
            elif isinstance(node, ast.For | ast.AsyncFor):
                iter_ = node.iter
                if isinstance(iter_, ast.Tuple | ast.List) and isinstance(node.target, ast.Tuple | ast.List):
                    for elt in iter_.elts:
                        unpack(node.target, elt)
                else:
                    unpack(node.target, ast.Subscript(value=iter_, slice=ast.Constant(0), ctx=ast.Load()))
            elif isinstance(node, ast.comprehension):
                unpack(node.target, ast.Subscript(value=node.iter, slice=ast.Constant(0), ctx=ast.Load()))
        return out

    def _const_node(self, name: str) -> ast.AST | None:
        if name in self.local and len(self.local[name]) == 1 and _is_const(self.local[name][0]):
            return self.local[name][0]
        return self.mod.constants.get(name)

    def resolve(self, node: ast.AST | None) -> Values:
        if node is None:
            return None
        if isinstance(node, ast.Await):
            return self.resolve(node.value)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return frozenset([node.value])
        if isinstance(node, ast.Dict | ast.Tuple | ast.List | ast.Set):
            return _const_values(node)
        if isinstance(node, ast.Name):
            if node.id in self.env:
                return self.env[node.id]
            if node.id in self.local and node.id not in self._busy:
                self._busy.add(node.id)
                try:
                    vals: set[str] = set()
                    for v in self.local[node.id]:
                        got = self.resolve(v)
                        if got is None:
                            return None
                        vals |= got
                    return frozenset(vals)
                finally:
                    self._busy.discard(node.id)
            if node.id in self.mod.constants:
                return _const_values(self.mod.constants[node.id])
            return None
        if isinstance(node, ast.Subscript):
            if getattr(node, "_positional", False) and isinstance(node.slice, ast.Constant):
                return self._positional(node.value, int(str(node.slice.value)))
            return self.resolve(node.value)  # dict/tuple of constants -> all its values
        if isinstance(node, ast.IfExp):
            a, b = self.resolve(node.body), self.resolve(node.orelse)
            return (a | b) if a is not None and b is not None else None
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in ("values", "keys", "items", "get"):
                return self.resolve(f.value)
            if isinstance(f, ast.Name) and f.id in ("str", "quote"):
                return self.resolve(node.args[0]) if node.args else None
        return None

    def _positional(self, container: ast.AST, index: int) -> Values:
        """Element `index` of every tuple in a constant dict/tuple of tuples (x, y = TABLE[k])."""
        if isinstance(container, ast.Subscript):
            container = container.value
        if isinstance(container, ast.Name):
            found = self._const_node(container.id)
            if found is None:
                return None
            container = found
        rows = container.values if isinstance(container, ast.Dict) else getattr(container, "elts", None)
        if not rows:
            return None
        vals: set[str] = set()
        for row in rows:
            if not isinstance(row, ast.Tuple | ast.List) or len(row.elts) <= index:
                return None
            got = _const_values(row.elts[index])
            if got is None:
                return None
            vals |= got
        return frozenset(vals)

    def path_templates(self, node: ast.AST) -> list[tuple[Seg, ...]]:
        """All path templates an expression can denote."""
        if isinstance(node, ast.Await):
            return self.path_templates(node.value)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [_segs_from_literal(node.value)]
        if isinstance(node, ast.JoinedStr):
            return self._segs_from_fstring(node)
        if isinstance(node, ast.Name):
            if node.id in self.env:
                vals = self.env[node.id]
                return [_segs_from_literal(v) for v in sorted(vals)] if vals else []
            if node.id in self.local and node.id not in self._busy:
                self._busy.add(node.id)
                try:
                    out: list[tuple[Seg, ...]] = []
                    for v in self.local[node.id]:
                        out += self.path_templates(v)
                    return out
                finally:
                    self._busy.discard(node.id)
            vals = self.resolve(node)
            return [_segs_from_literal(v) for v in sorted(vals)] if vals else []
        if isinstance(node, ast.Subscript):
            vals = self.resolve(node)
            return [_segs_from_literal(v) for v in sorted(vals)] if vals else []
        if isinstance(node, ast.IfExp):
            return self.path_templates(node.body) + self.path_templates(node.orelse)
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "format":  # "...{}/{}".format(a, b)
                return self.path_templates(f.value)
            # a helper that returns the path: op_path(jp, "join"), client_path(name), base.url(app)
            out = []
            for target_mod, target in self.analyzer.resolve_callee(self.mod, self.fn, f):
                env = self.analyzer._bind(target, node, self)
                sub = _Ctx(self.analyzer, target_mod, target, env)
                for ret in ast.walk(target):
                    if isinstance(ret, ast.Return) and ret.value is not None:
                        out += sub.path_templates(ret.value)
            return out
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.path_templates(node.left), self.path_templates(node.right)
            return [a + b for a in left for b in right] if left and right else []
        return []

    def _segs_from_fstring(self, node: ast.JoinedStr) -> list[tuple[Seg, ...]]:
        """Templates for an f-string. A placeholder whose value is itself a path (a Name assigned an
        f-string, a path helper call) is spliced in; other placeholders become one wildcard segment."""
        # Pieces: text, a Seg placeholder, or a list of templates (spliced alternatives).
        pieces: list[str | Seg | list[tuple[Seg, ...]]] = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                pieces.append(str(part.value))
            elif isinstance(part, ast.FormattedValue):
                expr = part.value
                vals = self.resolve(expr)
                if vals:
                    pieces.append(Seg(values=vals))
                    continue
                spliced = (
                    self.path_templates(expr) if isinstance(expr, ast.Name | ast.Call | ast.Await) else []
                )
                pieces.append(spliced if spliced else self._placeholder(expr))
        # Expand spliced alternatives into a cartesian product of flat piece lists.
        variants: list[list[str | Seg]] = [[]]
        for piece in pieces:
            if isinstance(piece, list):
                variants = [
                    v + ["/" + "/".join(_seg_text(s) for s in alt)] for v in variants for alt in piece
                ]
                # _seg_text keeps placeholders as marker strings; they are turned back into Segs below
            else:
                variants = [v + [piece] for v in variants]
        return [self._join_pieces(v) for v in variants]

    @staticmethod
    def _join_pieces(pieces: list[str | Seg]) -> tuple[Seg, ...]:
        segs: list[Seg] = []
        current: list[str | Seg] = []

        def flush() -> None:
            if not current:
                return
            holders = [c for c in current if isinstance(c, Seg)]
            text = "".join(c for c in current if isinstance(c, str))
            if not holders:
                if text:
                    segs.append(_seg_from_text(text))
            elif len(holders) == 1 and not text:
                segs.append(holders[0])
            else:
                segs.append(Seg(param_only=any(h.param_only for h in holders)))
            current.clear()

        for piece in pieces:
            if isinstance(piece, Seg):
                current.append(piece)
                continue
            for i, chunk in enumerate(piece.split("/")):
                if i > 0:
                    flush()
                if chunk:
                    current.append(chunk)
        flush()
        return tuple(segs)

    @staticmethod
    def _placeholder(expr: ast.AST) -> Seg:
        if isinstance(expr, ast.Name):
            return Seg(param_only=bool(ID_LIKE.search(expr.id)))
        if isinstance(expr, ast.Attribute):
            return Seg(param_only=bool(ID_LIKE.search(expr.attr)))  # self.kind vs self.set_id
        return Seg(param_only=True)  # quote(x), q(x), str(x), ps['id']


_MARK_ANY, _MARK_PARAM = "\x00any\x00", "\x00param\x00"


def _seg_text(seg: Seg) -> str:
    if seg.literal is not None:
        return seg.literal
    if seg.values is not None:
        return "\x00" + "|".join(sorted(seg.values)) + "\x00"
    return _MARK_PARAM if seg.param_only else _MARK_ANY


def _seg_from_text(text: str) -> Seg:
    if text == _MARK_ANY:
        return Seg()
    if text == _MARK_PARAM:
        return Seg(param_only=True)
    if text.startswith("\x00") and text.endswith("\x00"):
        return Seg(values=frozenset(text.strip("\x00").split("|")))
    if text == "{}" or (text.startswith("{") and text.endswith("}")):
        return Seg(param_only=True)
    return Seg(literal=text)


def _segs_from_literal(path: str) -> tuple[Seg, ...]:
    return tuple(_seg_from_text(p) for p in path.strip("/").split("/") if p)


def _ers_resource_unknown(segs: tuple[Seg, ...]) -> bool:
    """/ers/config/{resource}/... with an unresolved resource would match every ERS resource."""
    return (
        len(segs) >= 3
        and segs[0].literal == "ers"
        and segs[1].literal == "config"
        and segs[2].literal is None
        and segs[2].values is None
    )


def _callee_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


# --- spec --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Op:
    surface: str  # openapi | ers | mnt
    group: str
    method: str
    path: str
    summary: str


def ops_from_doc(surface: str, doc: dict[str, Any], group: str | None = None) -> list[Op]:
    out: list[Op] = []
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for m, op in item.items():
            if m not in METHODS or not isinstance(op, dict):
                continue
            g = group
            if g is None:
                tags = op.get("tags") or []
                g = str(tags[0]) if tags else "?"
                if surface == "ers" and g.startswith("ERS "):
                    g = g[4:]
            out.append(Op(surface, g, m.upper(), path, str(op.get("summary") or op.get("operationId") or "")))
    return out


async def fetch_spec() -> list[Op]:
    from ise_mcp.client import IseApp
    from ise_mcp.config import Settings
    from ise_mcp.specs import load_ers, load_mnt, load_openapi

    url = os.environ.get("ISE_URL")
    user = os.environ.get("ISE_USERNAME")
    password = os.environ.get("ISE_PASSWORD")
    if not (url and user and password):
        sys.exit("Set ISE_URL, ISE_USERNAME and ISE_PASSWORD (or pass --spec <snapshot>)")
    settings = Settings(
        _env_file=None,
        url=url,
        username=user,
        password=password,
        verify_ssl=os.environ.get("ISE_VERIFY_SSL", "false").lower() in ("1", "true", "yes"),
        mcp_cache_dir="",
    )
    app = IseApp(settings)
    ops: list[Op] = []
    try:
        for doc in await load_openapi(app):
            # specs.py appends the group name as the last tag of every operation
            group = None
            for item in (doc.get("paths") or {}).values():
                for m, op in item.items():
                    if m in METHODS and op.get("tags"):
                        group = str(op["tags"][-1])
                        break
                if group:
                    break
            ops += ops_from_doc("openapi", doc, group or str(doc.get("info", {}).get("title", "?")))
        ops += ops_from_doc("ers", await load_ers(app))
        ops += ops_from_doc("mnt", await load_mnt(app), "MnT")
        version = await app.version()
        print(f"<!-- ISE {version}: {len(ops)} operations -->", file=sys.stderr)
    finally:
        await app.aclose()
    return ops


def save_spec(ops: list[Op], path: Path) -> None:
    path.write_text(json.dumps([op.__dict__ for op in ops], indent=0) + "\n")


def load_spec(path: Path) -> list[Op]:
    return [Op(**o) for o in json.loads(path.read_text())]


# --- matching and report -----------------------------------------------------------------------------


@dataclass
class Coverage:
    ops: list[Op]
    tools: list[Tool]
    by_op: dict[Op, set[str]] = field(default_factory=dict)
    by_tool: dict[str, set[Op]] = field(default_factory=dict)
    extra: dict[str, set[str]] = field(default_factory=dict)  # tool -> "METHOD path" not in any spec

    def compute(self) -> None:
        self.by_op = {op: set() for op in self.ops}
        for tool in self.tools:
            if tool.name in GENERIC_TOOLS:
                continue
            hits: set[Op] = set()
            excluded = set(EXCLUDE.get(tool.name, ()))
            for t in tool.templates:
                matched = [
                    op
                    for op in self.ops
                    if t.matches(op.method, op.path) and (op.method, op.path) not in excluded
                ]
                if not matched:
                    self.extra.setdefault(tool.name, set()).add(f"{t.method} {t.text()}")
                for op in matched:
                    hits.add(op)
                    self.by_op[op].add(tool.name)
            self.by_tool[tool.name] = hits


def _pct(n: int, total: int) -> str:
    return f"{100 * n // total} %" if total else "-"


def short(names: set[str], cap: int | None = None) -> str:
    out = sorted(n.removeprefix("ise_") for n in names)
    if cap and len(out) > cap:
        return ", ".join(out[:cap]) + f" (+{len(out) - cap} more)"
    return ", ".join(out)


def report(cov: Coverage, *, uncovered: bool, by_tool: bool, tools_cap: int | None) -> str:
    lines: list[str] = []
    groups: dict[tuple[str, str], list[Op]] = defaultdict(list)
    for op in cov.ops:
        groups[(op.surface, op.group)].append(op)

    def covered(ops: list[Op]) -> list[Op]:
        return [o for o in ops if cov.by_op[o]]

    def tools_for(ops: list[Op]) -> set[str]:
        return set().union(*(cov.by_op[o] for o in ops)) if ops else set()

    curated = [t for t in cov.tools if t.name not in GENERIC_TOOLS]
    lines.append(
        f"<!-- generated by scripts/api_coverage.py: {len(curated) - 1} tools under src/ise_mcp/tools "
        f"+ {len(CORE_TOOLS)} core ({', '.join(CORE_TOOLS)}), {len(cov.ops)} operations -->"
    )
    # Surface summary
    lines += ["", "| Surface | Operations | Behind a curated tool | Tools |", "|---|---|---|---|"]
    for surface, label in (("openapi", "OpenAPI `/api/v1`"), ("ers", "ERS `/ers/config`"), ("mnt", "MnT")):
        ops = [o for o in cov.ops if o.surface == surface]
        cv = covered(ops)
        ngroups = len({o.group for o in ops})
        unit = "groups" if surface == "openapi" else "resources" if surface == "ers" else "calls"
        size = f"{len(ops)} in {ngroups} {unit}" if surface != "mnt" else f"{len(ops)} {unit}"
        lines.append(f"| {label} | {size} | {len(cv)} ({_pct(len(cv), len(ops))}) | {len(tools_for(ops))} |")

    # OpenAPI per group
    lines += ["", "### OpenAPI groups", "", "| Group | Operations | Covered | Tools |", "|---|---|---|---|"]
    oa = sorted((k for k in groups if k[0] == "openapi"), key=lambda k: (-len(covered(groups[k])), k[1]))
    for key in oa:
        ops = groups[key]
        cv = covered(ops)
        pct = _pct(len(cv), len(ops))
        lines.append(f"| {key[1]} | {len(ops)} | {len(cv)} ({pct}) | {short(tools_for(ops), tools_cap)} |")

    # ERS per resource (only touched ones in the table; the rest as a list)
    ers_keys = sorted(k for k in groups if k[0] == "ers")
    touched = [k for k in ers_keys if covered(groups[k])]
    lines += [
        "",
        f"### ERS resources ({len(touched)} of {len(ers_keys)} used)",
        "",
        "| Resource | Operations | Covered | Tools |",
        "|---|---|---|---|",
    ]
    for key in sorted(touched, key=lambda k: (-len(covered(groups[k])), k[1])):
        ops = groups[key]
        cv = covered(ops)
        used = ", ".join(sorted({o.method for o in cv}, key=["GET", "POST", "PUT", "DELETE"].index))
        lines.append(f"| {key[1]} | {len(ops)} | {len(cv)} ({used}) | {short(tools_for(ops), tools_cap)} |")
    untouched = [k[1] for k in ers_keys if k not in touched]
    lines += ["", f"ERS resources with no curated tool ({len(untouched)}): " + ", ".join(untouched)]

    # ERS operations beyond the data model (apply/clear, deploy, join, suspend ...)
    extra_ers = sorted({e for es in cov.extra.values() for e in es if "/ers/" in e})
    if extra_ers:
        lines += ["", "### ERS operations used that the data model does not list", ""]
        for e in extra_ers:
            who = sorted(t for t, es in cov.extra.items() if e in es)
            lines.append(f"- `{e}` ({short(set(who))})")

    # MnT
    mnt_ops = [o for o in cov.ops if o.surface == "mnt"]
    lines += ["", "### MnT", "", "| Call | Covered by |", "|---|---|"]
    for op in mnt_ops:
        lines.append(f"| `{op.path.removeprefix('/admin/API/mnt/')}` | {short(cov.by_op[op]) or '-'} |")

    other_extra = sorted({e for es in cov.extra.values() for e in es if "/ers/" not in e})
    if other_extra:
        lines += ["", "### Tool paths matching no spec operation (check the heuristics)", ""]
        for e in other_extra:
            who = sorted(t for t, es in cov.extra.items() if e in es)
            lines.append(f"- `{e}` ({short(set(who))})")

    unresolved = [u for t in cov.tools for u in t.unresolved]
    if unresolved:
        lines += ["", f"### Unresolved call sites ({len(unresolved)})", ""] + [
            f"- {u}" for u in sorted(set(unresolved))
        ]

    if uncovered:
        lines += ["", "## Uncovered operations", ""]
        for key in sorted(groups, key=lambda k: (k[0] != "openapi", k[1])):
            ops = [o for o in groups[key] if not cov.by_op[o]]
            if not ops or key[0] == "ers":
                continue
            lines += [f"### {key[1]} ({len(ops)} of {len(groups[key])} uncovered)", ""]
            for op in sorted(ops, key=lambda o: (o.path, o.method)):
                lines.append(f"- `{op.method} {op.path}` {op.summary[:90]}")
            lines.append("")

    if by_tool:
        lines += ["", "## Endpoints per tool", ""]
        for tool in cov.tools:
            if tool.name in GENERIC_TOOLS:
                continue
            ops = sorted(cov.by_tool.get(tool.name, ()), key=lambda o: (o.surface, o.path, o.method))
            extras = sorted(cov.extra.get(tool.name, ()))
            lines.append(f"- **{tool.name}** ({tool.tier}, {tool.module}): {len(ops)} operations")
            for op in ops:
                lines.append(f"  - `{op.method} {op.path}` [{op.group}]")
            for e in extras:
                lines.append(f"  - `{e}` (not in spec)")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--spec", type=Path, help="read the operation snapshot instead of the live ISE")
    ap.add_argument("--save-spec", type=Path, help="write the operation snapshot fetched from ISE")
    ap.add_argument("--uncovered", action="store_true", help="list every uncovered OpenAPI/MnT operation")
    ap.add_argument("--by-tool", action="store_true", help="list the operations each tool uses")
    ap.add_argument("--tools-cap", type=int, default=None, help="shorten long tool lists in the tables")
    args = ap.parse_args()

    if args.spec:
        ops = load_spec(args.spec)
    else:
        sys.path.insert(0, str(ROOT / "src"))
        ops = asyncio.run(fetch_spec())
        if args.save_spec:
            save_spec(ops, args.save_spec)

    analyzer = Analyzer(load_modules())
    tools = analyzer.find_tools()
    cov = Coverage(ops, tools)
    cov.compute()
    sys.stdout.write(report(cov, uncovered=args.uncovered, by_tool=args.by_tool, tools_cap=args.tools_cap))


if __name__ == "__main__":
    main()

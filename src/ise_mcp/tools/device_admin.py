"""Device administration (TACACS+): command sets and shell profiles (ERS), TACACS+ external servers and
server sequences (ERS), the node services that turn the Device Admin service on, and two client-side
checks: a command-set matcher (`command_verdict`, "would this command be allowed?") and
`ise_admin_policy_explain` (admin user + NAD + command -> device-admin policy set, rule, shell profile
and command verdict). Device-admin policy sets and rules use the policy tools with kind='device-admin'.

Command-set matching follows the ISE admin guide ("Command Sets" / "Process Rules"):
- the command name is a wildcard pattern, case-insensitive, matched against the whole word ('?' one
  character, '*' any run of characters);
- the arguments field is split on whitespace into regexes compared with the request's arguments by
  position; each must match its whole argument (anchored, case-insensitive: 'start' does not match
  'startup-config', 'start.*' does), a regex can't span two arguments ('running-config.*1/0/1' never
  matches 'running-config interface Gi1/0/1'), and extra request arguments are ignored;
- in each set a matching DENY_ALWAYS line wins; otherwise the first matching line decides (PERMIT or
  DENY); with no match the set permits only when 'permit any command that is not listed' is set;
- across the rule's sets: any DENY_ALWAYS -> deny, else any permit -> permit, else deny.
Not modelled: IOS keyword abbreviations (the device expands 'sh run' to 'show running-config' before it
asks ISE, so give full keywords), and privilege levels (the device only asks ISE about commands at the
levels it has 'aaa authorization commands <level>' for). These rules were checked against ISE 3.5 and
an IOS-XE 17.18 switch (tests/live/test_live_device_admin.py).
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
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
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list, ers_name_map, list_result, parse_ip
from ise_mcp.tools.network import nad_ips, resolve_nad
from ise_mcp.tools.policy import list_policy_sets, resolve_policy_set
from ise_mcp.tools.policy_explain import (
    authz_order,
    build_library,
    nad_attributes,
    normalize_device_attrs,
    resolve_references,
    walk_rules,
    walk_sets,
)
from ise_mcp.tools.writes import (
    SDWAN_TACACS_ATTRIBUTE,
    deep_merge,
    ers_post,
    ers_put,
    fingerprint,
    masked_changes,
    valid_sdwan_group,
)

_COMMAND = re.compile(r"^\s*(?P<grant>PERMIT|DENY_ALWAYS|DENY)\s+(?P<cmd>\S+)(?:\s+(?P<args>.*?))?\s*$", re.I)


_PROFILE_NAME = re.compile(r"^[A-Za-z0-9_ ]+$")
_SERVER_NAME = re.compile(r"^[A-Za-z0-9_]+$")  # ISE's rule for TACACS+ server and sequence names


def command_row(c: dict[str, Any]) -> dict[str, Any]:
    cmds = ((c.get("commands") or {}).get("commandList")) or []
    return {
        "name": c.get("name"),
        "permit_unmatched": c.get("permitUnmatched"),
        "commands": [
            " ".join(
                x for x in (str(e.get("grant")), str(e.get("command")), str(e.get("arguments") or "")) if x
            )
            for e in cmds
            if isinstance(e, dict)
        ],
        "description": c.get("description") or None,
        "id": c.get("id"),
    }


def shell_row(p: dict[str, Any]) -> dict[str, Any]:
    attrs = ((p.get("sessionAttributes") or {}).get("sessionAttributeList")) or []
    return {
        "name": p.get("name"),
        "attributes": {
            str(a.get("name")): f"{a.get('value')}" + (" (optional)" if a.get("type") == "OPTIONAL" else "")
            for a in attrs
            if isinstance(a, dict)
        },
        "description": p.get("description") or None,
        "id": p.get("id"),
    }


def parse_commands(lines: list[str]) -> list[dict[str, str]]:
    out = []
    for line in lines:
        m = _COMMAND.match(line)
        if not m:
            raise InvalidRequest(
                f"Command {line!r} must be 'PERMIT|DENY|DENY_ALWAYS <command> [<arguments regex>]', "
                "e.g. 'PERMIT show .*' or 'DENY_ALWAYS reload'"
            )
        out.append(
            {"grant": m.group("grant").upper(), "command": m.group("cmd"), "arguments": m.group("args") or ""}
        )
    return out


async def ers_by_name(app: IseApp, resource: str, name: str) -> dict[str, Any] | None:
    hit = await app.ers_find(resource, name)
    return await app.ers_get(resource, str(hit["id"])) if hit else None


# --- command-set matching (pure; see the module docstring for the semantics) --------------------

DENY_ALL_SHELL = "deny all shell profile"  # ISE's built-in result that fails exec authorization


def split_command(line: str) -> tuple[str, list[str]]:
    """'show running-config' -> ('show', ['running-config']); a trailing '<cr>' (what IOS sends as the
    last argument) is dropped."""
    words = line.split()
    if not words:
        raise InvalidRequest("Give a command line, e.g. 'show running-config'")
    if words[-1].lower() == "<cr>":
        words = words[:-1]
    return words[0], words[1:]


def wildcard_match(pattern: str, word: str) -> bool:
    """ISE command-name match: case-insensitive, whole word, '?' = one character, '*' = any run."""
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(rx, word, re.I) is not None


def line_matches(entry: dict[str, Any], cmd: str, args: list[str]) -> bool | None:
    """Does one command-set line match? None when its argument regex is invalid."""
    if not wildcard_match(str(entry.get("command") or ""), cmd):
        return False
    for i, pattern in enumerate(str(entry.get("arguments") or "").split()):
        actual = args[i] if i < len(args) else ""
        try:
            if re.fullmatch(pattern, actual, re.I) is None:
                return False
        except re.error:
            return None
    return True


def _line_text(e: dict[str, Any]) -> str:
    return " ".join(
        x for x in (str(e.get("grant")), str(e.get("command")), str(e.get("arguments") or "")) if x
    )


def match_command_set(cs: dict[str, Any], command: str) -> dict[str, Any]:
    """One command set's result for a command line: permit, deny, deny_always, or unmatched (with
    permit_unmatched deciding), plus the line that decided (1-based, as listed in ISE)."""
    cmd, args = split_command(command)
    lines = [e for e in ((cs.get("commands") or {}).get("commandList") or []) if isinstance(e, dict)]
    out: dict[str, Any] = {"command_set": cs.get("name")}
    bad = [i for i, e in enumerate(lines, 1) if line_matches(e, cmd, args) is None]
    if bad:
        out["invalid_regex_lines"] = bad  # ISE refuses to save these, so they're skipped here too
    hits = [(i, e) for i, e in enumerate(lines, 1) if line_matches(e, cmd, args)]
    always = [(i, e) for i, e in hits if str(e.get("grant")).upper() == "DENY_ALWAYS"]
    pick = always[0] if always else (hits[0] if hits else None)
    if pick:
        i, e = pick
        grant = str(e.get("grant")).upper()
        out.update(
            {
                "result": {"PERMIT": "permit", "DENY": "deny", "DENY_ALWAYS": "deny_always"}.get(
                    grant, "deny"
                ),
                "matched_line": i,
                "line": _line_text(e),
            }
        )
        if always and hits[0][0] != i:
            out["note"] = f"DENY_ALWAYS on line {i} wins over the earlier line {hits[0][0]}"
        return out
    permit = bool(cs.get("permitUnmatched"))
    out.update(
        {
            "result": "permit" if permit else "unmatched",
            "matched_line": None,
            "line": "permit any command that is not listed" if permit else None,
        }
    )
    return out


def command_verdict(sets: list[dict[str, Any]], command: str) -> dict[str, Any]:
    """The overall verdict for a command across a rule's command sets: DENY_ALWAYS anywhere -> deny,
    else any set permitting -> permit, else deny (no command set at all also denies)."""
    per_set = [match_command_set(cs, command) for cs in sets]
    results = [r["result"] for r in per_set]
    if not sets:
        verdict, why = "deny", "the rule returns no command set, so command authorization fails"
    elif "deny_always" in results:
        r = per_set[results.index("deny_always")]
        verdict, why = "deny", f"DENY_ALWAYS in {r['command_set']} line {r['matched_line']}: {r['line']}"
    elif "permit" in results:
        r = per_set[results.index("permit")]
        where = f"line {r['matched_line']}: {r['line']}" if r["matched_line"] else str(r["line"])
        verdict, why = "permit", f"{r['command_set']} {where}"
    elif "deny" in results:
        r = per_set[results.index("deny")]
        verdict, why = "deny", f"{r['command_set']} line {r['matched_line']}: {r['line']}"
    else:
        verdict, why = "deny", "no line in any command set matches and none permits unmatched commands"
    return {"command": command, "verdict": verdict, "because": why, "command_sets": per_set}


# --- TACACS+ external servers and sequences -----------------------------------------------------

CONNECT_MODES = {"OFF": "off", "ON_LEGACY": "legacy", "ON_DRAFT_COMPLIANT": "draft-compliant"}


def tacacs_server_row(s: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": s.get("name"),
        "host": s.get("hostIP"),
        "port": s.get("connectionPort"),
        "timeout": s.get("timeout"),
        "single_connect": s.get("singleConnect"),
        "shared_secret_set": bool(s.get("sharedSecret")),
        "description": s.get("description") or None,
        "id": s.get("id"),
    }


def server_names(seq: dict[str, Any]) -> list[str]:
    return [x.strip() for x in str(seq.get("serverList") or "").split(",") if x.strip()]


def tacacs_sequence_row(q: dict[str, Any], known: set[str] | None = None) -> dict[str, Any]:
    names = server_names(q)
    row: dict[str, Any] = {
        "name": q.get("name"),
        "servers": names,
        "local_accounting": q.get("localAccounting"),
        "remote_accounting": q.get("remoteAccounting"),
        "prefix_strip": q.get("prefixDelimiter") if q.get("prefixStrip") else None,
        "suffix_strip": q.get("suffixDelimiter") if q.get("suffixStrip") else None,
        "description": q.get("description") or None,
        "id": q.get("id"),
    }
    if known is not None and (missing := [n for n in names if n.lower() not in known]):
        row["missing_servers"] = missing
    return row


async def _all_detail(app: IseApp, resource: str) -> list[dict[str, Any]]:
    page = await ers_list(app, resource, limit=500, offset=0, detail=True)
    return [x for x in page.items if isinstance(x, dict)]


# --- device-admin explain -----------------------------------------------------------------------


async def _user_group_paths(app: IseApp, group_ids: list[str]) -> list[str]:
    """Identity group ids -> the values IdentityGroup:Name conditions compare, e.g.
    'User Identity Groups:NetOps'."""
    names = await ers_name_map(app, "identitygroup")
    out = []
    for gid in group_ids:
        name = names.get(gid)
        if not name:
            continue
        try:
            parent = str((await app.ers_get("identitygroup", gid)).get("parent") or "")
        except (UpstreamError, NotFound):
            parent = ""
        root = (
            parent.split("IdentityGroups:", 1)[1] if "IdentityGroups:" in parent else "User Identity Groups"
        )
        out.append(f"{root}:{name}")
    return out


async def internal_user_attributes(app: IseApp, user: str) -> dict[str, Any] | None:
    """Policy attributes for an internal user (identity groups), or None when there is no such user."""
    hit = await app.ers_find("internaluser", user)
    if not hit:
        return None
    full = await app.ers_get("internaluser", str(hit["id"]))
    gids = [g.strip() for g in str(full.get("identityGroups") or "").split(",") if g.strip()]
    return {
        "IdentityGroup:Name": await _user_group_paths(app, gids),
        "InternalUser:Name": str(full.get("name")),
        "InternalUser:Enabled": "true" if full.get("enabled", True) else "false",
    }


def tacacs_request_attributes(user: str | None, nad: dict[str, Any] | None) -> dict[str, Any]:
    """What a TACACS+ request from `nad` for `user` carries for policy-set / rule conditions."""
    out: dict[str, Any] = {
        # The condition may store the protocol's label or its value (Protocol is an INT enum).
        "Network Access:Protocol": ["TACACS+", "1"],
    }
    if user:
        out["TACACS:User"] = user
        out["Network Access:UserName"] = user
    if nad:
        attrs = nad_attributes(nad)
        if ip := attrs.pop("Radius:NAS-IP-Address", None):
            out["Network Access:Device IP Address"] = ip
        out.update(attrs)
    return out


async def policy_set_entries(app: IseApp, kind: str, ps_id: str) -> list[tuple[str, dict[str, Any]]]:
    """A set's authentication rules as raw (section, entry) pairs in rank order (with conditions)."""
    try:
        data = await app.openapi.get(f"/api/v1/policy/{kind}/policy-set/{ps_id}/authentication")
    except (UpstreamError, NotFound):
        return []
    entries = data.get("response", data) if isinstance(data, dict) else data
    rows = [e for e in entries or [] if isinstance(e, dict)]
    rows.sort(
        key=lambda e: ((e.get("rule") or {}).get("rank") is None, (e.get("rule") or {}).get("rank") or 0)
    )
    return [("authn", e) for e in rows]


async def resolve_command_sets(app: IseApp, names: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    found, missing = [], []
    for n in names:
        cs = await ers_by_name(app, "tacacscommandsets", n)
        (found.append(cs) if cs else missing.append(n))
    return found, missing


async def tacacs_audit(
    app: IseApp, nads: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Per-NAD TACACS+ facts for ise_audit_nads ({name: {...}} for NADs with a TACACS+ secret, with
    'findings'), plus deployment-wide findings. Secrets are compared as hashes, never returned."""
    import hashlib  # noqa: PLC0415 - only the audit needs it

    tac = [n for n in nads if (n.get("tacacsSettings") or {}).get("sharedSecret")]
    if not tac:
        return {}, []
    general: list[str] = []
    try:
        nodes = (await app.openapi.get("/api/v1/deployment/node")).get("response") or []
        if nodes and not any("DeviceAdmin" in (n.get("services") or []) for n in nodes):
            general.append(
                f"{len(tac)} device(s) have a TACACS+ secret but no node runs the DeviceAdmin service "
                "(ise_update_node_services enable=['DeviceAdmin'])"
            )
    except (UpstreamError, NotFound):
        pass
    try:
        sets = await list_policy_sets(app, "device-admin")
        library = await build_library(app, "device-admin")
        await resolve_references(app, "device-admin", [p.get("condition") for p in sets], library)
    except (UpstreamError, NotFound) as e:
        sets, library = [], {}
        general.append(f"Could not read the device-admin policy sets: {str(e)[:150]}")
    users: dict[str, list[str]] = {}
    for n in tac:
        digest = hashlib.sha256(str(n["tacacsSettings"]["sharedSecret"]).encode()).hexdigest()
        users.setdefault(digest, []).append(str(n.get("name")))
    out: dict[str, dict[str, Any]] = {}
    for n in tac:
        name = str(n.get("name"))
        settings = n.get("tacacsSettings") or {}
        secret = str(settings.get("sharedSecret"))
        findings: list[str] = []
        if len(secret) < 12:
            findings.append(f"TACACS+ shared secret is short ({len(secret)} chars; use 16+)")
        shared = users[hashlib.sha256(secret.encode()).hexdigest()]
        if len(shared) > 1:
            others = [s for s in shared if s != name]
            findings.append(
                f"TACACS+ secret reused on {len(others)} other device(s): {', '.join(others[:5])}"
            )
        row: dict[str, Any] = {
            "shared_secret_set": True,
            "single_connect": CONNECT_MODES.get(str(settings.get("connectModeOptions")), "off"),
        }
        if sets:
            attrs = normalize_device_attrs(tacacs_request_attributes(None, n))
            chosen, trace, uncertain = walk_sets(sets, attrs, library, include_disabled=False)
            maybe = [t["name"] for t in trace if t["result"] == "unknown"]
            row["device_admin_policy_set"] = chosen.get("name") if chosen else None
            if maybe:
                row["may_match_first"] = maybe  # conditions on the user, time, ... decide at login
            if chosen is None and not maybe:
                findings.append("no device-admin policy set matches it: every TACACS+ request is rejected")
            elif chosen is not None and chosen.get("default") and not maybe:
                findings.append(
                    f"only the default device-admin policy set ({chosen.get('name')}) matches it: no "
                    "policy set was written for this device"
                )
        row["findings"] = findings
        out[name] = row
    return out, general


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List TACACS+ command sets")
    async def ise_list_command_sets(
        ctx: Context,
        name: Annotated[str | None, Field(description="Filter: name contains")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """List TACACS+ command sets (device administration): each command as 'GRANT command args'
        (PERMIT, DENY, DENY_ALWAYS; args are regexes) and whether unmatched commands are permitted.
        Device-admin authorization rules return command sets (see ise_get_policy_set kind=device-admin)."""
        app: IseApp = get_client(ctx)
        filters = [f"name.CONTAINS.{name}"] if name else None
        page = await ers_list(
            app,
            "tacacscommandsets",
            filters=filters,
            limit=limit,
            offset=offset,
            detail=True,
            shape=command_row,
        )
        return list_result(page, fmt=response_format)

    @reg.read(title="List TACACS+ shell profiles")
    async def ise_list_shell_profiles(
        ctx: Context,
        name: Annotated[str | None, Field(description="Filter: name contains")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """List TACACS+ shell profiles (device administration): the attributes sent at login, e.g.
        priv-lvl (IOS privilege level), idletime, or WLC role1. Device-admin authorization rules return a
        shell profile."""
        app: IseApp = get_client(ctx)
        filters = [f"name.CONTAINS.{name}"] if name else None
        page = await ers_list(
            app, "tacacsprofile", filters=filters, limit=limit, offset=offset, detail=True, shape=shell_row
        )
        return list_result(page, fmt=response_format)

    @reg.read(title="List TACACS+ external servers and sequences")
    async def ise_get_tacacs_servers(ctx: Context) -> ToolResult:
        """List TACACS+ external servers (other TACACS+ servers ISE proxies device-admin requests to: host,
        port, timeout, single-connect, whether a shared secret is set, never its value) and TACACS+
        server sequences (the ordered server lists a device-admin policy set can proxy to, with
        accounting and username prefix/suffix stripping). A sequence naming a server that doesn't
        exist is flagged in 'missing_servers'."""
        app: IseApp = get_client(ctx)
        servers = await _all_detail(app, "tacacsexternalservers")
        sequences = await _all_detail(app, "tacacsserversequence")
        known = {str(x.get("name")).lower() for x in servers}
        return object_result(
            {
                "servers": [tacacs_server_row(x) for x in servers],
                "sequences": [tacacs_sequence_row(q, known) for q in sequences],
            }
        )

    @reg.read(title="Test a command against TACACS+ command sets")
    async def ise_test_command_set(
        ctx: Context,
        command: Annotated[
            list[str],
            Field(
                description="Command lines with full keywords as the device sends them, e.g. "
                "['show running-config', 'configure terminal', 'reload'] (IOS expands 'sh run' before "
                "asking ISE; this tool does not)"
            ),
        ],
        command_sets: Annotated[
            list[str] | None,
            Field(description="Command set names to test together, as one rule returns them"),
        ] = None,
        policy_set: Annotated[
            str | None,
            Field(description="Device-admin policy set whose rule's command sets to test (with `rule`)"),
        ] = None,
        rule: Annotated[str | None, Field(description="Authorization rule name in `policy_set`")] = None,
        draft: Annotated[
            list[str] | None,
            Field(
                description="A command set that is not in ISE yet, in ise_set_command_set's format, e.g. "
                "['PERMIT show .*', 'DENY_ALWAYS reload']; tested together with any named sets"
            ),
        ] = None,
        draft_permit_unmatched: Annotated[
            bool, Field(description="The draft set's 'permit any command that is not listed'")
        ] = False,
    ) -> ToolResult:
        """Test command lines against TACACS+ command sets without a device: would each be permitted, and
        which line decides? Evaluates them the way ISE does: per set, DENY_ALWAYS wins, otherwise the first
        matching line (command-name wildcards; argument regexes by position, each anchored to its whole
        argument and case-insensitive), otherwise 'permit unmatched'; across sets, DENY_ALWAYS anywhere
        denies, else any permit permits, else deny. Give the sets by name, as a device-admin rule
        (policy_set + rule), or as a draft before you create it. Reports the verdict and the deciding line
        per command. Client-side: confirm with a real login after a change."""
        app: IseApp = get_client(ctx)
        names = list(command_sets or [])
        source = None
        if (policy_set is None) != (rule is None):
            raise InvalidRequest("Give policy_set and rule together")
        if policy_set and rule:
            ps = await resolve_policy_set(app, "device-admin", policy_set)
            entries = await authz_order(app, "device-admin", str(ps["id"]))
            hit = next(
                (e for _, e in entries if str((e.get("rule") or {}).get("name")).lower() == rule.lower()),
                None,
            )
            if hit is None:
                raise NotFound(f"No authorization rule {rule!r} in device-admin set {ps.get('name')!r}", 404)
            names += [str(c) for c in hit.get("commands") or []]
            source = {
                "policy_set": ps.get("name"),
                "rule": hit["rule"].get("name"),
                "shell_profile": hit.get("profile"),
            }
        if not names and draft is None:
            raise InvalidRequest("Give command_sets, policy_set + rule, or a draft")
        sets, missing = await resolve_command_sets(app, names)
        if missing:
            raise NotFound(f"No command set named {', '.join(missing)}; see ise_list_command_sets", 404)
        if draft is not None:
            sets.append(
                {
                    "name": "(draft)",
                    "permitUnmatched": draft_permit_unmatched,
                    "commands": {"commandList": parse_commands(draft)},
                }
            )
        return object_result(
            {
                "from_rule": source,
                "command_sets": [c.get("name") for c in sets],
                "results": [command_verdict(sets, c) for c in command],
                "limits": "Full keywords only (no IOS abbreviation expansion); the device only asks ISE "
                "about commands at the privilege levels it has 'aaa authorization commands <level>' for.",
            }
        )

    @reg.read(title="Explain a device-admin (TACACS+) login and command")
    async def ise_admin_policy_explain(
        ctx: Context,
        user: Annotated[str, Field(description="Admin username as typed at the device login")],
        nad: Annotated[str, Field(description="Network device the admin logs in to (name or IP)")],
        command: Annotated[
            list[str] | None,
            Field(
                description="Command lines to check, full keywords, e.g. ['show running-config', 'reload']"
            ),
        ] = None,
        attributes: Annotated[
            dict[str, str | list[str]] | None,
            Field(
                description="Extra or overriding attributes as 'Dictionary:Attribute' -> value, e.g. "
                '{"IdentityGroup:Name": ["User Identity Groups:NetOps"]} for a user not in the internal '
                "store, or AD groups as '<join point>:ExternalGroups'"
            ),
        ] = None,
        include_disabled: Annotated[
            bool, Field(description="Include disabled sets/rules (ISE skips them at runtime)")
        ] = False,
    ) -> ToolResult:
        """Predict what a TACACS+ device-admin login gets, client-side (ISE has no evaluate API and no
        TACACS+ live-log REST API): which device-admin policy set the NAD and user select, the
        authentication rule (identity source), the authorization rule (with its hit count), the shell
        profile (priv-lvl etc.; Deny All Shell Profile means the login fails) and, for each `command`,
        the command-set verdict and the line that decided it. Internal users' identity groups are
        looked up; for AD users pass '<join point>:ExternalGroups' in attributes. Conditions it can't
        evaluate are 'unknown' and make the result UNCERTAIN, never guessed. Use it before a change
        that could lock admins out."""
        app: IseApp = get_client(ctx)
        kind = "device-admin"
        nad_obj = await resolve_nad(app, nad, fuzzy=True)
        filled = tacacs_request_attributes(user, nad_obj)
        notes: list[str] = []
        internal = await internal_user_attributes(app, user)
        if internal:
            if internal["InternalUser:Enabled"] == "false":
                notes.append(f"Internal user {user} is disabled: authentication fails")
            filled.update(internal)
        else:
            notes.append(
                f"{user} is not an internal user: identity-group conditions are unknown unless you pass "
                "them in attributes"
            )
        given = dict(attributes or {})
        full = {g.strip().casefold() for g in given}
        assumed = {k: v for k, v in filled.items() if k.casefold() not in full}
        attrs = normalize_device_attrs({**assumed, **given})

        library = await build_library(app, kind)
        sets = await list_policy_sets(app, kind)
        await resolve_references(app, kind, [p.get("condition") for p in sets], library)
        chosen, set_trace, uncertain = walk_sets(sets, attrs, library, include_disabled)
        base: dict[str, Any] = {
            "nad": {"name": nad_obj.get("name"), "ips": nad_ips(nad_obj)},
            "assumed_attributes": assumed,
            "set_selection": set_trace,
        }
        if not (nad_obj.get("tacacsSettings") or {}).get("sharedSecret"):
            notes.append(f"{nad_obj.get('name')} has no TACACS+ shared secret: ISE drops its requests")
        if chosen is None:
            return object_result(
                {
                    "verdict": "No device-admin policy set matches: the login is rejected",
                    **base,
                    "notes": notes,
                }
            )
        rules = await policy_set_entries(app, kind, str(chosen["id"]))
        ordered = await authz_order(app, kind, str(chosen["id"]))
        await resolve_references(
            app, kind, [(e.get("rule") or {}).get("condition") for _, e in rules + ordered], library
        )
        authn, authn_trace, authn_unknown = walk_rules(
            rules, attrs, library, include_disabled, {"identity_source": "identitySourceName"}
        )
        matched, rule_trace, rule_unknown = walk_rules(
            ordered,
            attrs,
            library,
            include_disabled,
            {"shell_profile": "profile", "command_sets": "commands"},
        )
        uncertain = uncertain or rule_unknown
        out: dict[str, Any] = {
            "policy_set": chosen.get("name"),
            **base,
            "authentication": authn_trace,
            "identity_source": authn.get("identity_source") if authn else None,
            "authorization": rule_trace,
        }
        if authn_unknown:
            notes.append("An authentication rule ahead of the chosen one could not be evaluated")
        if matched is None:
            out["verdict"] = "No authorization rule matches (not even Default): the login is rejected"
            out["notes"] = notes
            return object_result(out)
        shell = str(matched.get("shell_profile") or "")
        login_ok = bool(shell) and shell.lower() != DENY_ALL_SHELL
        profile = await ers_by_name(app, "tacacsprofile", shell) if login_ok else None
        out["shell_profile"] = shell_row(profile) if profile else shell or None
        out["verdict"] = (
            f"Rule '{matched['name']}' -> shell profile {shell}, command sets "
            f"{', '.join(matched.get('command_sets') or []) or '(none)'}"
            if login_ok
            else f"Rule '{matched['name']}' returns {shell or 'no shell profile'}: the login (exec "
            "authorization) is denied"
        )
        if command:
            sets_found, missing = await resolve_command_sets(
                app, [str(c) for c in matched.get("command_sets") or []]
            )
            if missing:
                notes.append(f"Command set(s) {', '.join(missing)} not found: treated as absent")
            out["commands"] = [command_verdict(sets_found, c) for c in command]
            if not login_ok:
                notes.append("The login itself is denied, so no command runs whatever the verdicts say")
        if uncertain:
            notes.append(
                "UNCERTAIN: a higher-ranked set or rule has a condition this evaluator could not evaluate "
                "(see 'unknown_because'); at runtime ISE might match it first."
            )
        out["notes"] = notes or None
        out["limits"] = (
            "Client-side prediction. Assumes authentication succeeds; conditions on time, AD groups you "
            "did not pass, or attributes not supplied are 'unknown'. Commands: full keywords only, and "
            "the device asks ISE only at the privilege levels it authorizes with ISE."
        )
        return object_result(out)

    @reg.write(title="Create or replace a TACACS+ command set")
    async def ise_set_command_set(
        ctx: Context,
        name: Annotated[str, Field(description="Command set name, e.g. 'mcp-show-only'")],
        commands: Annotated[
            list[str],
            Field(
                description="Ordered commands, each 'PERMIT|DENY|DENY_ALWAYS <command> [<arguments regex>]', "
                "e.g. ['PERMIT show .*', 'PERMIT ping', 'DENY_ALWAYS reload']. [] = no commands"
            ),
        ],
        permit_unmatched: Annotated[
            bool | None,
            Field(
                description="Permit commands that match no line (true = blacklist style). Default: false for "
                "a new set, unchanged for an existing one"
            ),
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a TACACS+ command set, or replace an existing one's command list. Command
        authorization on the device (aaa authorization commands) then permits/denies each command per
        the first matching line; DENY_ALWAYS wins even over other permitting command sets. Preview-first
        with a diff for an existing set."""
        app: IseApp = get_client(ctx)
        parsed = parse_commands(commands)
        existing = await ers_by_name(app, "tacacscommandsets", name)
        patch: dict[str, Any] = {"commands": {"commandList": parsed}}
        if permit_unmatched is not None or existing is None:
            patch["permitUnmatched"] = bool(permit_unmatched)
        if description is not None:
            patch["description"] = description
        args = {
            "name": name,
            "commands": commands,
            "permit_unmatched": permit_unmatched,
            "description": description,
        }
        if existing:
            desired = {**existing, **patch}
            if desired == existing:
                raise InvalidRequest(f"Command set {name!r} already has exactly these settings")
            plan = Plan(
                f"Replace command set {name}",
                details={"changes": field_changes(command_row(existing), command_row(desired), replace=True)},
                fingerprint=fingerprint(existing),
                side_effects=[
                    "Admins whose rule returns this set get the new command list at their next command"
                ],
            )
            return await preview_or_apply(
                ctx,
                tool="ise_set_command_set",
                args=args,
                confirm=confirm,
                plan=plan,
                apply=lambda: ers_put(app, "tacacscommandsets", "TacacsCommandSets", desired),
            )
        body = {"name": name, "description": description or "", **patch}
        return await preview_or_apply(
            ctx,
            tool="ise_set_command_set",
            args=args,
            confirm=confirm,
            plan=Plan(f"Create command set {name}", details=command_row(body)),
            apply=lambda: ers_post(app, "tacacscommandsets", "TacacsCommandSets", body),
        )

    @reg.write(title="Create or update a TACACS+ shell profile")
    async def ise_set_shell_profile(
        ctx: Context,
        name: Annotated[
            str,
            Field(description="Shell profile name: letters, digits, '_' and spaces, e.g. 'NetOps_priv15'"),
        ],
        privilege: Annotated[
            int | None, Field(ge=0, le=15, description="IOS privilege level at login (priv-lvl)")
        ] = None,
        idle_timeout: Annotated[
            int | None, Field(ge=0, description="Idle timeout in minutes (idletime)")
        ] = None,
        attributes: Annotated[
            dict[str, str] | None,
            Field(
                description="Other mandatory attributes, e.g. {'role1': 'ALL'} for a WLC, {'autocmd': ...}"
            ),
        ] = None,
        sdwan_group: Annotated[
            str | None,
            Field(
                description="Catalyst SD-WAN user group for an SD-WAN Manager/edge admin login over TACACS+, "
                "e.g. 'netadmin' or 'operator': sets the custom attribute viptela-group-name"
            ),
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a TACACS+ shell profile, or update an existing one: the attributes ISE returns when an
        admin logs in, e.g. privilege 15 for full IOS access or 1 for read-only, an idle timeout, WLC
        roles, or the Catalyst SD-WAN user group (sdwan_group -> viptela-group-name; TACACS+ needs no
        dictionary for it). Given attributes are set; others on an existing profile are kept.
        Preview-first."""
        app: IseApp = get_client(ctx)
        wanted: dict[str, str] = dict(attributes or {})
        clash = [
            k
            for k, given in (
                ("priv-lvl", privilege),
                ("idletime", idle_timeout),
                (SDWAN_TACACS_ATTRIBUTE, sdwan_group),
            )
            if given is not None and k.lower() in {w.lower() for w in wanted}
        ]
        if clash:
            raise InvalidRequest(
                f"Give {', '.join(clash)} either as its own argument or in attributes, not both"
            )
        if privilege is not None:
            wanted["priv-lvl"] = str(privilege)
        if idle_timeout is not None:
            wanted["idletime"] = str(idle_timeout)
        if sdwan_group is not None:
            wanted[SDWAN_TACACS_ATTRIBUTE] = valid_sdwan_group(sdwan_group)
        if not wanted and description is None:
            raise InvalidRequest("Give privilege, idle_timeout, sdwan_group, attributes or description")
        if not _PROFILE_NAME.match(name):
            raise InvalidRequest(
                f"Shell profile names may only contain letters, digits, '_' and spaces (ISE rule): {name!r}"
            )
        existing = await ers_by_name(app, "tacacsprofile", name)
        current_attrs = ((existing or {}).get("sessionAttributes") or {}).get("sessionAttributeList") or []
        merged = {str(a.get("name")): a for a in current_attrs if isinstance(a, dict)}
        for k, v in wanted.items():
            old = merged.get(k)
            if not (isinstance(old, dict) and str(old.get("value")) == v):
                merged[k] = {"type": "MANDATORY", "name": k, "value": v}
        args = {
            "name": name,
            "privilege": privilege,
            "idle_timeout": idle_timeout,
            "attributes": attributes,
            "sdwan_group": sdwan_group,
            "description": description,
        }
        patch: dict[str, Any] = {"sessionAttributes": {"sessionAttributeList": list(merged.values())}}
        if description is not None:
            patch["description"] = description
        if existing:
            desired = deep_merge(existing, patch)
            if desired == existing:
                raise InvalidRequest(f"Shell profile {name!r} already has exactly these settings")
            return await preview_or_apply(
                ctx,
                tool="ise_set_shell_profile",
                args=args,
                confirm=confirm,
                plan=Plan(
                    f"Update shell profile {name}",
                    details={"changes": field_changes(shell_row(existing), shell_row(desired), replace=True)},
                    fingerprint=fingerprint(existing),
                ),
                apply=lambda: ers_put(app, "tacacsprofile", "TacacsProfile", desired),
            )
        body = {"name": name, "description": description or "", **patch}
        return await preview_or_apply(
            ctx,
            tool="ise_set_shell_profile",
            args=args,
            confirm=confirm,
            plan=Plan(f"Create shell profile {name}", details=shell_row(body)),
            apply=lambda: ers_post(app, "tacacsprofile", "TacacsProfile", body),
        )

    @reg.write(title="Create or update a TACACS+ external server")
    async def ise_set_tacacs_server(
        ctx: Context,
        name: Annotated[
            str, Field(description="External server name: letters, digits and '_', e.g. 'legacy_acs1'")
        ],
        host: Annotated[str | None, Field(description="Server IPv4 address (required to create)")] = None,
        shared_secret: Annotated[
            str | None, Field(description="TACACS+ shared secret (required to create; never echoed)")
        ] = None,
        port: Annotated[int | None, Field(ge=1, le=65535, description="TCP port (default 49)")] = None,
        timeout_seconds: Annotated[
            int | None, Field(ge=1, le=120, description="Server timeout in seconds (default 20)")
        ] = None,
        single_connect: Annotated[
            bool | None, Field(description="Use one TCP connection for all requests (default true)")
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a TACACS+ external server (a TACACS+ server ISE proxies device-admin requests to, used
        through a TACACS+ server sequence), or update an existing one: given fields change, others are
        kept. Preview-first; the secret is never shown, only whether it changes."""
        app: IseApp = get_client(ctx)
        if not _SERVER_NAME.match(name):
            raise InvalidRequest(
                f"TACACS+ external server names may only contain letters, digits and '_' (ISE rule): {name!r}"
            )
        if host is not None and not parse_ip(host):
            raise InvalidRequest(f"host must be an IPv4 address: {host!r}")
        patch = {
            k: v
            for k, v in {
                "hostIP": host,
                "sharedSecret": shared_secret,
                "connectionPort": port,
                "timeout": timeout_seconds,
                "singleConnect": single_connect,
                "description": description,
            }.items()
            if v is not None
        }
        args = {
            "name": name,
            "host": host,
            "shared_secret": shared_secret,
            "port": port,
            "timeout_seconds": timeout_seconds,
            "single_connect": single_connect,
            "description": description,
        }
        existing = await ers_by_name(app, "tacacsexternalservers", name)
        if existing:
            desired = {**existing, **patch}
            if desired == existing:
                raise InvalidRequest(f"TACACS+ server {name!r} already has exactly these settings")
            return await preview_or_apply(
                ctx,
                tool="ise_set_tacacs_server",
                args=args,
                confirm=confirm,
                plan=Plan(
                    f"Update TACACS+ external server {name}",
                    details={"changes": masked_changes(existing, desired)},
                    fingerprint=fingerprint(existing),
                    side_effects=["Sequences that list this server use the new settings at the next request"],
                ),
                apply=lambda: ers_put(app, "tacacsexternalservers", "TacacsExternalServer", desired),
            )
        blockers = [
            f"{f} is required to create a server"
            for f, v in (("host", host), ("shared_secret", shared_secret))
            if v is None
        ]
        body = {
            "name": name,
            "description": description or "",
            "connectionPort": 49,
            "timeout": 20,
            "singleConnect": True,
            **patch,
        }
        shown = tacacs_server_row(body)
        return await preview_or_apply(
            ctx,
            tool="ise_set_tacacs_server",
            args=args,
            confirm=confirm,
            plan=Plan(f"Create TACACS+ external server {name}", details=shown, blockers=blockers),
            apply=lambda: ers_post(app, "tacacsexternalservers", "TacacsExternalServer", body),
        )

    @reg.write(title="Create or update a TACACS+ server sequence")
    async def ise_set_tacacs_server_sequence(
        ctx: Context,
        name: Annotated[str, Field(description="Sequence name: letters, digits and '_'")],
        servers: Annotated[
            list[str] | None,
            Field(
                description="TACACS+ external server names in the order ISE tries them (required to create)"
            ),
        ] = None,
        local_accounting: Annotated[bool | None, Field(description="Keep accounting on ISE too")] = None,
        remote_accounting: Annotated[
            bool | None, Field(description="Forward accounting to the servers (default true)")
        ] = None,
        prefix_strip: Annotated[
            str | None,
            Field(description="Strip a username prefix up to this delimiter, e.g. '\\'; '' turns it off"),
        ] = None,
        suffix_strip: Annotated[
            str | None, Field(description="Strip a username suffix from this delimiter, e.g. '@'; '' = off")
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a TACACS+ server sequence (an ordered list of TACACS+ external servers a device-admin
        policy set can proxy to), or update one: given fields change, others are kept. The servers must
        exist (ise_get_tacacs_servers). Preview-first with a diff."""
        app: IseApp = get_client(ctx)
        if not _SERVER_NAME.match(name):
            raise InvalidRequest(
                f"TACACS+ server sequence names may only contain letters, digits and '_' (ISE rule): {name!r}"
            )
        known = {
            str(x.get("name")).lower(): str(x.get("name"))
            for x in await _all_detail(app, "tacacsexternalservers")
        }
        missing = [s_ for s_ in servers or [] if s_.lower() not in known]
        if missing:
            raise NotFound(
                f"No TACACS+ external server named {', '.join(missing)}; see ise_get_tacacs_servers", 404
            )
        if servers is not None and not servers:
            raise InvalidRequest("A sequence needs at least one server")
        patch: dict[str, Any] = {}
        if servers:
            patch["serverList"] = ",".join(known[s_.lower()] for s_ in servers)
        for key, on in (("localAccounting", local_accounting), ("remoteAccounting", remote_accounting)):
            if on is not None:
                patch[key] = on
        for flag, delim, value in (
            ("prefixStrip", "prefixDelimiter", prefix_strip),
            ("suffixStrip", "suffixDelimiter", suffix_strip),
        ):
            if value is not None:
                patch[flag] = bool(value)
                if value:
                    patch[delim] = value
        if description is not None:
            patch["description"] = description
        args = {
            "name": name,
            "servers": servers,
            "local_accounting": local_accounting,
            "remote_accounting": remote_accounting,
            "prefix_strip": prefix_strip,
            "suffix_strip": suffix_strip,
            "description": description,
        }
        existing = await ers_by_name(app, "tacacsserversequence", name)
        if existing:
            desired = {**existing, **patch}
            if desired == existing:
                raise InvalidRequest(f"Sequence {name!r} already has exactly these settings")
            return await preview_or_apply(
                ctx,
                tool="ise_set_tacacs_server_sequence",
                args=args,
                confirm=confirm,
                plan=Plan(
                    f"Update TACACS+ server sequence {name}",
                    details={
                        "changes": field_changes(tacacs_sequence_row(existing), tacacs_sequence_row(desired))
                    },
                    fingerprint=fingerprint(existing),
                    side_effects=["Policy sets proxying to this sequence use it at the next request"],
                ),
                apply=lambda: ers_put(app, "tacacsserversequence", "TacacsServerSequence", desired),
            )
        if not servers:
            raise InvalidRequest("Give servers to create a sequence")
        body = {
            "name": name,
            "description": "",
            "localAccounting": False,
            "remoteAccounting": True,
            "prefixStrip": False,
            "suffixStrip": False,
            **patch,
        }
        return await preview_or_apply(
            ctx,
            tool="ise_set_tacacs_server_sequence",
            args=args,
            confirm=confirm,
            plan=Plan(f"Create TACACS+ server sequence {name}", details=tacacs_sequence_row(body)),
            apply=lambda: ers_post(app, "tacacsserversequence", "TacacsServerSequence", body),
        )

    @reg.dangerous(title="Enable or disable node services")
    async def ise_update_node_services(
        ctx: Context,
        enable: Annotated[
            list[
                Literal[
                    "DeviceAdmin",
                    "Session",
                    "Profiler",
                    "pxGrid",
                    "SXP",
                    "PassiveIdentity",
                    "TC-NAC",
                    "pxGridCloud",
                ]
            ]
            | None,
            Field(description="Services to turn on, e.g. ['DeviceAdmin'] for TACACS+"),
        ] = None,
        disable: Annotated[
            list[
                Literal[
                    "DeviceAdmin",
                    "Session",
                    "Profiler",
                    "pxGrid",
                    "SXP",
                    "PassiveIdentity",
                    "TC-NAC",
                    "pxGridCloud",
                ]
            ]
            | None,
            Field(description="Services to turn off"),
        ] = None,
        node: Annotated[
            str | None, Field(description="Node hostname (see ise_list_nodes); optional with a single node")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Turn services on or off on an ISE node: DeviceAdmin (TACACS+ on port 49, needed before any
        device-admin policy works), Session (RADIUS: the node is a PSN), Profiler, pxGrid, SXP,
        PassiveIdentity. Disabling Session stops RADIUS on that node, so it is blocked on the only PSN.
        ISE restarts the affected services, which can take several minutes. Preview-first."""
        app: IseApp = get_client(ctx)
        if not enable and not disable:
            raise InvalidRequest("Give enable and/or disable")
        if set(enable or []) & set(disable or []):
            raise InvalidRequest("A service can't be both enabled and disabled")
        nodes = (await app.openapi.get("/api/v1/deployment/node")).get("response") or []
        node_arg = node  # the confirm call must repeat the caller's arguments, not the resolved host
        if node is None:
            if len(nodes) != 1:
                raise InvalidRequest(
                    f"{len(nodes)} nodes in the deployment: give `node` (one of "
                    f"{', '.join(str(n.get('hostname')) for n in nodes)})"
                )
            node = str(nodes[0].get("hostname"))
        match = [n for n in nodes if str(n.get("hostname")).lower() == node.lower()]
        if not match:
            raise NotFound(f"No node {node!r}; see ise_list_nodes", 404)
        current = match[0]
        services = list(current.get("services") or [])
        new = [s for s in services if s not in (disable or [])] + [
            s for s in enable or [] if s not in services
        ]
        blockers: list[str] = []
        if new == services:
            blockers.append(f"Nothing changes: {node} already runs {', '.join(services) or 'no services'}")
        if "Session" in (disable or []):
            others = [n for n in nodes if n is not current and "Session" in (n.get("services") or [])]
            if not others:
                blockers.append(
                    f"{node} is the only node running Session (RADIUS); disabling it stops all RADIUS"
                )
        side = [f"ISE restarts the changed services on {node}; allow a few minutes"]
        if "DeviceAdmin" in (enable or []):
            side.append("TACACS+ (TCP 49) starts answering on this node; device-admin policy applies")
        if "DeviceAdmin" in (disable or []):
            side.append("TACACS+ logins to devices that use this node fail over to local/backup servers")
        plan = Plan(
            f"Update services on {node}",
            details={"from": services, "to": new, "roles": current.get("roles")},
            blockers=blockers,
            fingerprint=fingerprint({"roles": current.get("roles"), "services": services}),
            side_effects=side,
            blast_radius=1,  # one node; operators put this behind MCP_CHANGE_WINDOW (I18)
        )
        body = {"roles": current.get("roles") or [], "services": new}
        return await preview_or_apply(
            ctx,
            tool="ise_update_node_services",
            args={"enable": enable, "disable": disable, "node": node_arg},
            confirm=confirm,
            plan=plan,
            apply=lambda: app.openapi.put(f"/api/v1/deployment/node/{quote(node, safe='')}", body),
        )

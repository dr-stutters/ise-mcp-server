"""Device administration (TACACS+): command sets and shell profiles (ERS), and the node services that turn
the Device Admin service on. Device-admin policy sets and rules use the policy tools with
kind='device-admin'."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    field_changes,
    get_client,
    preview_or_apply,
)

from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list, list_result
from ise_mcp.tools.writes import deep_merge, ers_post, ers_put, fingerprint

_COMMAND = re.compile(r"^\s*(?P<grant>PERMIT|DENY_ALWAYS|DENY)\s+(?P<cmd>\S+)(?:\s+(?P<args>.*?))?\s*$", re.I)


_PROFILE_NAME = re.compile(r"^[A-Za-z0-9_ ]+$")


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
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a TACACS+ shell profile, or update an existing one: the attributes ISE returns when an
        admin logs in, e.g. privilege 15 for full IOS access or 1 for read-only, an idle timeout, or WLC
        roles. Given attributes are set; others on an existing profile are kept. Preview-first."""
        app: IseApp = get_client(ctx)
        wanted: dict[str, str] = dict(attributes or {})
        clash = [
            k
            for k, given in (("priv-lvl", privilege), ("idletime", idle_timeout))
            if given is not None and k in wanted
        ]
        if clash:
            raise InvalidRequest(
                f"Give {', '.join(clash)} either as its own argument or in attributes, not both"
            )
        if privilege is not None:
            wanted["priv-lvl"] = str(privilege)
        if idle_timeout is not None:
            wanted["idletime"] = str(idle_timeout)
        if not wanted and description is None:
            raise InvalidRequest("Give privilege, idle_timeout, attributes or description")
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

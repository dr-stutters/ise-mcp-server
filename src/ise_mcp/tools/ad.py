"""Active Directory join points (ERS identitystores.activedirectory): create a join point, join/leave
nodes, search the domain's groups, add groups for policy use, and test a user's group membership.

ERS quirks (ISE 3.5): the per-join-point operations are PUTs on /ers/config/activedirectory/{id}/<op>
with an `OperationAdditionalData` body (name/value pairs), even the read-only ones (getGroupsByDomain,
getUserGroups, getTrustedDomains, isUserMemberOf). There is no join-status endpoint: getTrustedDomains
answers 500 "AD Instance: X is not joined" when no node is joined, which is how status is derived.
Domain credentials for join/leave are passed per call and never stored, echoed or logged.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from typing import Annotated, Any
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
    get_client,
    object_result,
    preview_or_apply,
)
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_resolve, list_result
from ise_mcp.tools.writes import fingerprint

JOIN_POINT_NAME = re.compile(r"[A-Za-z0-9_.-]{1,31}")
DOMAIN_NAME = re.compile(r"(?=.{3,253}$)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")
GROUP_COLUMNS = ["name", "sid", "type", "added"]


def op_body(**pairs: str | None) -> dict[str, Any]:
    """The OperationAdditionalData body ERS uses for the join-point operations."""
    return {
        "OperationAdditionalData": {
            "additionalData": [{"name": k, "value": v} for k, v in pairs.items() if v is not None]
        }
    }


def op_path(jp: dict[str, Any], op: str) -> str:
    return f"/ers/config/activedirectory/{quote(str(jp['id']), safe='')}/{op}"


async def resolve_join_point(app: IseApp, join_point: str) -> dict[str, Any]:
    return await ers_resolve(
        app, "activedirectory", join_point, what="AD join point", list_tool="ise_list_identity_sources"
    )


def groups_of(data: Any) -> list[dict[str, Any]]:
    body = data.get("ERSActiveDirectoryGroups", data) if isinstance(data, dict) else {}
    return [g for g in (body.get("groups") or []) if isinstance(g, dict)]


def short_name(group: str) -> str:
    return group.rsplit("/", 1)[-1].lower()


async def join_status(app: IseApp, jp: dict[str, Any]) -> dict[str, Any]:
    """{'joined': bool, 'domains': [...], 'detail': str} from getTrustedDomains."""
    try:
        data = await app.ers_request("PUT", op_path(jp, "getTrustedDomains"), json={})
    except (UpstreamError, NotFound) as e:
        msg = str(e)
        if "not joined" in msg.lower():
            return {"joined": False, "detail": "No ISE node is joined to the domain (ise_join_ad)"}
        return {"joined": None, "detail": f"Could not read the join status: {msg[:200]}"}
    body = data.get("ERSActiveDirectoryDomains", data) if isinstance(data, dict) else {}
    domains = [
        {
            "domain": d.get("dnsName"),
            "forest": d.get("forest"),
            **({"unusable": d["unusableReason"]} if d.get("unusableReason") else {}),
        }
        for d in body.get("domains") or []
        if isinstance(d, dict)
    ]
    return {"joined": True, "domains": domains}


async def search_groups(
    app: IseApp, jp: dict[str, Any], pattern: str, domain: str | None = None
) -> list[dict[str, Any]]:
    data = await app.ers_request(
        "PUT",
        op_path(jp, "getGroupsByDomain"),
        json=op_body(domain=domain or str(jp.get("domain")), filter=pattern),
    )
    return groups_of(data)


def jp_summary(jp: dict[str, Any]) -> dict[str, Any]:
    adv = jp.get("advancedSettings") or {}
    return {
        "name": jp.get("name"),
        "domain": jp.get("domain"),
        "description": jp.get("description"),
        "id": jp.get("id"),
        "groups": [g.get("name") for g in groups_of(jp.get("adgroups") or {})],
        "attributes": [
            a.get("name")
            for a in (jp.get("adAttributes") or {}).get("attributes") or []
            if isinstance(a, dict)
        ],
        "scope": jp.get("adScopesNames"),
        "machine_auth": adv.get("enableMachineAuth"),
        "identity_not_in_ad": adv.get("identityNotInAdBehaviour"),
    }


class NotJoined(Exception):
    pass


async def ad_user_facts(app: IseApp, jp: dict[str, Any], username: str) -> dict[str, Any]:
    """A user's AD groups through a join point, marking the ones added for policy. Raises NotJoined."""
    added = {str(g.get("sid")): g.get("name") for g in groups_of(jp.get("adgroups") or {})}
    try:
        data = await app.ers_request("PUT", op_path(jp, "getUserGroups"), json=op_body(username=username))
    except (UpstreamError, NotFound) as e:
        low = str(e).lower()
        # The join point itself resolved, so a 404 here is ERS's "No such user" (core's NotFound
        # message drops ERS's text; on ISE 3.5 this op answers 404 only for an unknown user).
        if isinstance(e, NotFound) or "no such user" in low:
            return {
                "join_point": jp.get("name"),
                "username": username,
                "found": False,
                "detail": f"No user {username!r} in {jp.get('domain')} (or its trusted domains)",
            }
        if "not joined" in low:
            raise NotJoined(
                f"Join point {jp.get('name')} is not joined to {jp.get('domain')}: ise_join_ad first"
            ) from e
        raise
    groups = groups_of(data)
    in_policy = [str(added[str(g.get("sid"))]) for g in groups if str(g.get("sid")) in added]
    return {
        "join_point": jp.get("name"),
        "username": username,
        "found": True,
        "groups": [g.get("name") for g in groups],
        "groups_usable_in_policy": in_policy,
        "hint": (
            None
            if in_policy
            else "None of this user's groups are added to the join point, so no "
            f"{jp.get('name')}:ExternalGroups condition can match them (ise_add_ad_groups)"
        ),
    }


async def all_join_points(app: IseApp) -> list[dict[str, Any]]:
    page = await app.ers_pager.fetch_page(app.ers, "/ers/config/activedirectory", limit=100)
    return [await app.ers_get("activedirectory", str(p["id"])) for p in page.items if p.get("id")]


def strip_domain(username: str) -> str:
    """'CORP\\alice' -> 'alice'; UPNs are kept (AD resolves them)."""
    return username.split("\\", 1)[-1]


async def ad_diagnosis(app: IseApp, identity_store: str | None, username: str | None) -> dict[str, Any]:
    """For ise_why_auth_failed: the join status and the user's groups for the join point(s) involved
    (the one named as the identity store, else every join point)."""
    points = await all_join_points(app)
    if not points:
        return {"join_points": "none configured: AD is not set up on this ISE"}
    named = [p for p in points if str(p.get("name")).lower() == str(identity_store or "").lower()]
    out: list[dict[str, Any]] = []
    for jp in named or points:
        row: dict[str, Any] = {"join_point": jp.get("name"), "domain": jp.get("domain")}
        row["join"] = await join_status(app, jp)
        row["groups_added"] = len(groups_of(jp.get("adgroups") or {}))
        if username and row["join"].get("joined"):
            try:
                facts = await ad_user_facts(app, jp, strip_domain(username))
                row["user"] = {k: v for k, v in facts.items() if k not in ("join_point",) and v is not None}
            except (UpstreamError, NotJoined) as e:
                row["user"] = {"error": str(e)[:200]}
        out.append(row)
    return {"join_points": out}


async def credentials_check(username: str, password: str) -> None:
    if not username.strip() or not password:
        raise InvalidRequest("Give the domain account's username and password")
    if any(c in username for c in "\r\n"):
        raise InvalidRequest("username must be one line")


def register(reg: ToolRegistrar) -> None:  # noqa: C901 - one registration block per tool
    # --- read ---------------------------------------------------------------------------------

    @reg.read(title="Get an AD join point (config + join status)")
    async def ise_get_ad_join_point(
        ctx: Context,
        join_point: Annotated[str, Field(description="Join point name or id (ise_list_identity_sources)")],
    ) -> ToolResult:
        """One Active Directory join point: domain, the AD groups and attributes added for policy, key
        advanced settings, and whether ISE is joined (with the domains it can see). Use it when AD
        logins fail with 24408/24415/24428 (not joined / unreachable) or an ExternalGroups condition
        never matches (group not added)."""
        app: IseApp = get_client(ctx)
        jp = await resolve_join_point(app, join_point)
        out = jp_summary(jp)
        out["join"] = await join_status(app, jp)
        out["policy_condition"] = (
            f"{jp.get('name')}:ExternalGroups EQUALS <one of groups>"
            if out["groups"]
            else "No groups added yet: ise_list_ad_groups, then ise_add_ad_groups"
        )
        return object_result(out)

    @reg.read(title="Search an AD domain's groups")
    async def ise_list_ad_groups(
        ctx: Context,
        join_point: Annotated[str, Field(description="Join point name or id")],
        filter: Annotated[  # noqa: A002 - matches the ISE GUI's field name
            str, Field(description="Group name pattern with * wildcards, e.g. 'mcp*' or '*admins'")
        ] = "*",
        domain: Annotated[
            str | None, Field(description="Domain to search; default the join point's domain")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Search the joined domain for groups (name as ISE writes it, e.g.
        'corp.example.com/Groups/employees', SID, scope) and say which are already added to the
        join point. Only added groups can be used in policy (ise_add_ad_groups). Needs a joined node."""
        app: IseApp = get_client(ctx)
        jp = await resolve_join_point(app, join_point)
        if not filter.strip():
            raise InvalidRequest("filter can't be empty; use '*' for every group")
        added = {str(g.get("sid")) for g in groups_of(jp.get("adgroups") or {})}
        try:
            found = await search_groups(app, jp, filter, domain)
        except (UpstreamError, NotFound) as e:
            if "not joined" in str(e).lower():
                raise InvalidRequest(
                    f"Join point {jp.get('name')} is not joined to {jp.get('domain')}: ise_join_ad first"
                ) from e
            raise
        rows = [
            {
                "name": g.get("name"),
                "sid": g.get("sid"),
                "type": g.get("type"),
                "added": g.get("sid") in added,
            }
            for g in found
        ]
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=GROUP_COLUMNS
        )

    @reg.read(title="Test an AD user (lookup + groups)")
    async def ise_test_ad_user(
        ctx: Context,
        join_point: Annotated[str, Field(description="Join point name or id")],
        username: Annotated[str, Field(description="sAMAccountName or UPN, e.g. 'alice' or 'alice@x.com'")],
    ) -> dict[str, Any]:
        """Look a user up in AD through the join point (no password, no login) and return their
        groups, marking the ones added to the join point, i.e. the values an
        '<join point>:ExternalGroups' condition can match for them. 'No such user' maps to ISE
        failure 22056/24415 territory; 'not joined' means ise_join_ad first."""
        app: IseApp = get_client(ctx)
        jp = await resolve_join_point(app, join_point)
        if not username.strip():
            raise InvalidRequest("Give a username")
        try:
            return await ad_user_facts(app, jp, username)
        except NotJoined as e:
            raise InvalidRequest(str(e)) from e

    # --- write --------------------------------------------------------------------------------

    @reg.write(title="Create an AD join point")
    async def ise_create_ad_join_point(
        ctx: Context,
        name: Annotated[
            str,
            Field(description="Join point name; it is the policy dictionary: 'CORP' -> CORP:ExternalGroups"),
        ],
        domain: Annotated[str, Field(description="AD DNS domain, e.g. 'corp.example.com'")],
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an Active Directory join point (the definition only; no node joins yet). Next:
        ise_join_ad (needs a domain account that may add computers), then ise_list_ad_groups and
        ise_add_ad_groups. ISE must resolve the domain's SRV records through its name server.
        Preview-first; blocked if the name or domain already has a join point."""
        app: IseApp = get_client(ctx)
        if not JOIN_POINT_NAME.fullmatch(name):
            raise InvalidRequest("Join point names are 1-31 letters, digits, '_', '-' or '.'")
        if not DOMAIN_NAME.fullmatch(domain.strip()):
            raise InvalidRequest(f"{domain!r} is not a DNS domain name")
        page = await app.ers_pager.fetch_page(app.ers, "/ers/config/activedirectory", limit=100)
        existing = [await app.ers_get("activedirectory", str(p["id"])) for p in page.items if p.get("id")]
        blockers = [
            f"Join point {p.get('name')!r} already exists for {p.get('domain')}"
            for p in existing
            if str(p.get("name")).lower() == name.lower() or str(p.get("domain")).lower() == domain.lower()
        ]
        body = {
            "name": name,
            "domain": domain.strip().lower(),
            "description": description or "",
            "adScopesNames": "Default_Scope",
            "enableDomainAllowedList": True,
        }
        return await preview_or_apply(
            ctx,
            tool="ise_create_ad_join_point",
            args={"name": name, "domain": domain, "description": description},
            confirm=confirm,
            plan=Plan(
                f"Create AD join point {name} for {domain}",
                details=body,
                blockers=blockers,
                fingerprint=fingerprint([p.get("id") for p in existing]),
            ),
            apply=lambda: app.ers_create("activedirectory", {"ERSActiveDirectory": body}),
        )

    @reg.write(title="Add AD groups to a join point")
    async def ise_add_ad_groups(
        ctx: Context,
        join_point: Annotated[str, Field(description="Join point name or id")],
        groups: Annotated[
            list[str],
            Field(
                description="Groups to add: full names ('corp.com/Users/VPN Users'), short names "
                "('VPN Users') or SIDs, as ise_list_ad_groups shows them"
            ),
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make AD groups usable in policy: after this, '<join point>:ExternalGroups EQUALS <group
        name>' conditions accept them (ise_create_authz_rule). Groups already added are kept. Names are
        resolved against the domain first, so a typo is a blocker, not a silent no-match. Needs a joined
        node. Preview-first."""
        app: IseApp = get_client(ctx)
        if not groups:
            raise InvalidRequest("Give at least one group")
        jp = await resolve_join_point(app, join_point)
        current = groups_of(jp.get("adgroups") or {})
        have = {str(g.get("sid")) for g in current}
        try:
            domain_groups = await search_groups(app, jp, "*")
        except (UpstreamError, NotFound) as e:
            if "not joined" in str(e).lower():
                raise InvalidRequest(
                    f"Join point {jp.get('name')} is not joined to {jp.get('domain')}: ise_join_ad first"
                ) from e
            raise
        blockers: list[str] = []
        new: list[dict[str, Any]] = []
        for want in groups:
            key = want.strip().lower()
            hits = [
                g for g in domain_groups if key in (str(g.get("name")).lower(), str(g.get("sid")).lower())
            ] or [g for g in domain_groups if short_name(str(g.get("name"))) == key]
            if not hits:
                blockers.append(f"No group {want!r} in {jp.get('domain')} (see ise_list_ad_groups)")
            elif len(hits) > 1:
                names = ", ".join(str(h.get("name")) for h in hits)
                blockers.append(f"{want!r} matches several groups ({names}): give the full name")
            elif str(hits[0].get("sid")) in have or any(n["sid"] == hits[0].get("sid") for n in new):
                continue
            else:
                h = hits[0]
                new.append({"name": h.get("name"), "sid": h.get("sid"), "type": h.get("type") or "GLOBAL"})
        if not new and not blockers:
            blockers.append("Every group given is already added to the join point")
        merged = [{k: g.get(k) for k in ("name", "sid", "type") if g.get(k)} for g in current] + new
        body = {
            "ERSActiveDirectory": {
                "id": jp["id"],
                "name": jp.get("name"),
                "domain": jp.get("domain"),
                "adgroups": {"groups": merged},
            }
        }

        async def apply() -> Any:
            out = await app.ers_request("PUT", op_path(jp, "addGroups"), json=body)
            app.__dict__.pop("_dict_cache", None)  # the ExternalGroups dictionary values change
            return out or {"added": [g["name"] for g in new]}

        return await preview_or_apply(
            ctx,
            tool="ise_add_ad_groups",
            args={"join_point": join_point, "groups": groups},
            confirm=confirm,
            plan=Plan(
                f"Add {len(new)} AD group(s) to {jp.get('name')}",
                details={"add": [g["name"] for g in new], "keep": [g.get("name") for g in current]},
                blockers=blockers,
                fingerprint=fingerprint(sorted(have)),
            ),
            apply=apply,
        )

    # --- dangerous ----------------------------------------------------------------------------

    async def _join_or_leave(
        ctx: Context,
        *,
        tool: str,
        op: str,
        join_point: str,
        username: str,
        password: str,
        node: str | None,
        org_unit: str | None,
        confirm: str | None,
    ) -> dict[str, Any]:
        app: IseApp = get_client(ctx)
        await credentials_check(username, password)
        jp = await resolve_join_point(app, join_point)
        status = await join_status(app, jp)
        nodes = (await app.openapi.get("/api/v1/deployment/node")).get("response") or []
        known = [str(n.get("hostname")) for n in nodes]
        if node is not None and node.lower() != "all":
            match = [
                n
                for n in nodes
                if node.strip().lower() in (str(n.get("hostname")).lower(), str(n.get("fqdn")).lower())
            ]
            if not match:
                raise NotFound(f"No node {node!r}; see ise_list_nodes", 404)
            # ERS wants the node's FQDN here; the bare hostname fails with "Falied to send http get request".
            target = str(match[0].get("fqdn") or match[0].get("hostname"))
            path = op_path(jp, op)
            body = op_body(username=username, password=password, node=target, orgunit=org_unit)
        else:
            path, target = op_path(jp, f"{op}AllNodes"), "every node"
            body = op_body(username=username, password=password, orgunit=org_unit)
        side: list[str] = []
        blockers: list[str] = []
        if op == "join":
            side.append(f"Creates/updates the computer account(s) for {target} in {jp.get('domain')}")
            if status.get("joined") and target == "every node":
                side.append("Already joined: nodes already in the domain are re-joined")
        else:
            side.append(
                f"AD logins through {jp.get('name')} fail on {target} (24408 not joined) until re-joined"
            )
            side.append("The computer account is removed from AD when the credentials allow it")
            if status.get("joined") is False:
                blockers.append(f"{jp.get('name')} is not joined on any node")
        shown = {
            "join_point": jp.get("name"),
            "domain": jp.get("domain"),
            "nodes": target if target != "every node" else known,
            "username": username,
            "password": "set (never shown)",
            "org_unit": org_unit,
            "currently_joined": status.get("joined"),
        }
        args = {
            "join_point": join_point,
            "username": username,
            "password": password,
            "node": node,
            "org_unit": org_unit,
        }
        verb = "Join" if op == "join" else "Leave"

        async def apply() -> Any:
            try:
                return await app.ers_request("PUT", path, json=body, timeout=180)
            except UpstreamError as e:
                # Never let ISE's error text carry the domain password back to the caller.
                raise UpstreamError(str(e).replace(password, "***"), e.status_code) from None

        return await preview_or_apply(
            ctx,
            tool=tool,
            args=args,
            confirm=confirm,
            plan=Plan(
                f"{verb} {jp.get('domain')} on {target} (join point {jp.get('name')})",
                details={k: v for k, v in shown.items() if v is not None},
                blockers=blockers,
                side_effects=side,
                fingerprint=fingerprint([jp.get("id"), status.get("joined")]),
            ),
            apply=apply,
        )

    @reg.dangerous(title="Join ISE nodes to Active Directory")
    async def ise_join_ad(
        ctx: Context,
        join_point: Annotated[str, Field(description="Join point name or id (ise_create_ad_join_point)")],
        username: Annotated[
            str, Field(description="Domain account allowed to add computers, e.g. 'Administrator'")
        ],
        password: Annotated[str, Field(description="Its password (used once; never stored or shown)")],
        node: Annotated[
            str | None, Field(description="One node hostname; default every node in the deployment")
        ] = None,
        org_unit: Annotated[
            str | None, Field(description="OU for the computer account, e.g. 'OU=ISE,DC=corp,DC=com'")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Join one or all ISE nodes to the join point's AD domain (creates the computer account). ISE
        needs DNS SRV lookups for the domain, Kerberos 88, LDAP 389/3268, SMB 445 and NTP in sync with
        the DC. The credentials are sent once to ISE and never stored. Takes up to a few minutes. Check
        with ise_get_ad_join_point. Preview-first."""
        return await _join_or_leave(
            ctx,
            tool="ise_join_ad",
            op="join",
            join_point=join_point,
            username=username,
            password=password,
            node=node,
            org_unit=org_unit,
            confirm=confirm,
        )

    @reg.dangerous(title="Leave Active Directory")
    async def ise_leave_ad(
        ctx: Context,
        join_point: Annotated[str, Field(description="Join point name or id")],
        username: Annotated[str, Field(description="Domain account allowed to remove the computer account")],
        password: Annotated[str, Field(description="Its password (used once; never stored or shown)")],
        node: Annotated[
            str | None, Field(description="One node hostname; default every node in the deployment")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Take one or all ISE nodes out of the AD domain: AD-backed logins through this join point stop
        working there at once. The join point definition and its groups stay (delete with
        ise_delete_object kind='ad_join_point' after leaving). Preview-first."""
        return await _join_or_leave(
            ctx,
            tool="ise_leave_ad",
            op="leave",
            join_point=join_point,
            username=username,
            password=password,
            node=node,
            org_unit=None,
            confirm=confirm,
        )

"""Admin access audit (roadmap I74, reads only): ISE's own administrators, their admin groups (with the
external AD groups mapped to them), the RBAC policies that give each group its menu and data access, and a
summary for a quarterly access review (Super Admins, disabled, never-disabled, external).

Everything comes from the OpenAPI RBAC group (`/api/v1/rbac/...`, ISE 3.5 spec "Rbac Catalog"):
- `admin-user` lists id/name/status/groups; `admin-user/{name}` adds the external, read-only,
  change-password-on-next-login and inactive-account-never-disabled flags (one GET per admin).
- `admin-group` lists name/description/externalGroupCount; `admin-group/{name}` adds isExternal, the
  external identity source and groups, and the members. On ISE 3.5 the list leaves out some groups an
  RBAC policy or admin still names (seen live: 'ERS Trustsec'), so those are added from the policies.
- `policy` maps admin groups to a menu-access and a data-access permission set; `menu-access/{name}` and
  `data-access/{name}` are trees of Show/Hide and Full/Read Only/No Access.
No RBAC writes: admin-user POST answers 500 on 3.5 and admin accounts are a lockout risk (ROADMAP).
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.
from typing import Annotated, Any
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import (
    AuthError,
    InvalidRequest,
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from ise_mcp._core.formatting import NOT_SECRET_KEYS
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp
from ise_mcp.tools._common import gather_limited

RBAC = "/api/v1/rbac"
SUPER_ADMIN = "Super Admin"
# More Super Admins than this is flagged in ise_deployment_health: Cisco's admin-access guidance is to
# give each person their own account in the narrowest admin group, keeping Super Admin for a few.
SUPER_ADMIN_REVIEW = 3
DENIED = (
    "ISE refused the RBAC read ({status}): the API account needs an admin group that can read Admin "
    "Access (Super Admin, System Admin, RBAC Admin or Read Only Admin); ERS-only groups are refused."
)
NO_RBAC_API = (
    "This ISE doesn't serve the OpenAPI RBAC API ({path} answered 404). It is in the ISE 3.5 spec; check "
    "ise_search_spec('rbac') and that the OpenAPI service is on (Administration > System > Settings > API "
    "Settings)."
)
NO_MENU = "none (no GUI menus: API-only or data-only policy)"
NO_DATA = "none (no data access set)"
USER_COLUMNS = ["name", "enabled", "groups", "super_admin", "external", "never_disabled", "description"]
GROUP_COLUMNS = ["name", "members", "external", "external_groups", "policies", "description"]
POLICY_COLUMNS = ["name", "enabled", "admin_groups", "menu_access", "data_access"]
# Keys that match the core secret pattern ("password") but hold admin names or flags: compact() would
# mask them (ise_deployment_health showed the admin names as ********, #124).
NOT_SECRET_KEYS.update({"change_password_pending", "change_password_next_login"})


def _denied(e: AuthError) -> AuthError:
    return AuthError(DENIED.format(status=e.status_code or 403), e.status_code)


async def rbac_get(app: IseApp, path: str) -> Any:
    """GET under /api/v1/rbac with the two answers an audit hits: 403 (account can't read RBAC) and 404 on
    a collection (no RBAC API). A 404 on one object is re-raised for the caller to word."""
    try:
        return await app.openapi.get(f"{RBAC}{path}")
    except AuthError as e:
        raise _denied(e) from e
    except NotFound as e:
        if "/" not in path.strip("/"):
            raise NotFound(NO_RBAC_API.format(path=f"{RBAC}{path}"), 404) from e
        raise


def _q(name: str) -> str:
    return quote(name, safe="")


def _list(data: Any, key: str) -> list[dict[str, Any]]:
    items = data.get(key) if isinstance(data, dict) else data
    return [i for i in items or [] if isinstance(i, dict)]


# --- admin users ------------------------------------------------------------------------------------


def user_row(summary: dict[str, Any], detail: dict[str, Any] | None) -> dict[str, Any]:
    d = detail or {}
    groups = d.get("rbacGroups") or summary.get("rbacGroupNames") or []
    enabled = d.get("status") if d.get("status") is not None else summary.get("statusEnabled")
    names = " ".join(str(x) for x in (summary.get("firstName"), summary.get("lastName")) if x)
    row: dict[str, Any] = {
        "name": summary.get("name") or d.get("name"),
        "enabled": enabled,
        "groups": [str(g) for g in groups],
        "super_admin": SUPER_ADMIN in groups,
        "external": d.get("external"),
        "read_only": d.get("readOnly"),
        "never_disabled": d.get("inactiveAccountNeverDisabled"),
        "change_password_next_login": d.get("changePasswordOnNextLogin"),
        "full_name": names or None,
        "email": summary.get("emailAddr") or d.get("email") or None,
        "description": summary.get("description") or d.get("description") or None,
        "id": summary.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None and v != ""}


async def admin_users(app: IseApp, *, detail: bool = True) -> list[dict[str, Any]]:
    """Every ISE admin as a row; with `detail` one GET per admin adds the account flags (an admin whose
    detail GET fails keeps the list fields and gets `detail_error`)."""
    users = _list(await rbac_get(app, "/admin-user"), "adminUserList")
    if not detail:
        return [user_row(u, None) for u in users]

    async def one(u: dict[str, Any]) -> dict[str, Any]:
        try:
            data = await rbac_get(app, f"/admin-user/{_q(str(u.get('name')))}")
        except (NotFound, AuthError) as e:
            return {**user_row(u, None), "detail_error": str(e)[:150]}
        d = data.get("adminUserDetails") if isinstance(data, dict) else None
        return user_row(u, d if isinstance(d, dict) else None)

    return await gather_limited(users, one, app.settings.detail_concurrency)


def admin_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts and names for an access review."""

    def names(pred: Any) -> list[str]:
        return sorted(str(r["name"]) for r in rows if pred(r))

    supers = names(lambda r: r.get("super_admin"))
    out: dict[str, Any] = {
        "admins": len(rows),
        "super_admins": len(supers),
        "super_admin_names": supers,
        "enabled_super_admins": len(names(lambda r: r.get("super_admin") and r.get("enabled") is not False)),
        "disabled": names(lambda r: r.get("enabled") is False),
        "never_disabled": names(lambda r: r.get("never_disabled") is True),
        "external": names(lambda r: r.get("external") is True),
        "change_password_pending": names(lambda r: r.get("change_password_next_login") is True),
    }
    if any("detail_error" in r for r in rows):
        out["note"] = "Some admins' details could not be read; their flags are missing."
    return out


# --- groups and policies ----------------------------------------------------------------------------


def policy_row(p: dict[str, Any]) -> dict[str, Any]:
    perm = p.get("Permission") or p.get("permission") or {}
    row = {
        "name": p.get("policyName") or p.get("name"),
        "enabled": p.get("enabled"),
        "admin_groups": [str(g) for g in p.get("adminGroups") or []],
        "menu_access": perm.get("menuAccessName") if isinstance(perm, dict) else None,
        "data_access": perm.get("dataAccessName") if isinstance(perm, dict) else None,
    }
    return {k: v for k, v in row.items() if v is not None}


async def rbac_policies(app: IseApp) -> list[dict[str, Any]]:
    return [policy_row(p) for p in _list(await rbac_get(app, "/policy"), "RbacPolicyList")]


def group_row(
    summary: dict[str, Any], detail: dict[str, Any] | None, policies: list[dict[str, Any]]
) -> dict[str, Any]:
    d = detail or {}
    name = str(summary.get("name") or d.get("name"))
    members = [
        {k: v for k, v in (("name", m.get("name")), ("enabled", m.get("isEnabled"))) if v is not None}
        for m in d.get("rbacUsers") or []
        if isinstance(m, dict)
    ]
    ext = d.get("externalGroups") or []
    row: dict[str, Any] = {
        "name": name,
        "description": summary.get("description") or d.get("description") or None,
        "members": [m["name"] for m in members if m.get("name")],
        "disabled_members": [m["name"] for m in members if m.get("enabled") is False],
        "external": d.get("isExternal"),
        "external_identity_source": d.get("externalIdenSourceName"),
        "external_groups": [str(g) for g in ext] if isinstance(ext, list) else [str(ext)],
        "external_group_count": summary.get("externalGroupCount"),
        "policies": [p["name"] for p in policies if name in p.get("admin_groups", [])],
    }
    if summary.get("_unlisted"):
        row["note"] = "Not returned by the admin-group list; named by an RBAC policy or admin."
    return {k: v for k, v in row.items() if v is not None and v != "" and v != []}


async def admin_groups(
    app: IseApp, *, detail: bool = True
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(group rows, policy rows). Groups an RBAC policy names but the admin-group list omits are added."""
    groups = _list(await rbac_get(app, "/admin-group"), "adminGroupList")
    policies = await rbac_policies(app)
    known = {str(g.get("name")) for g in groups}
    for p in policies:
        for g in p.get("admin_groups", []):
            if g not in known:
                known.add(g)
                groups.append({"name": g, "_unlisted": True})
    if not detail:
        return [group_row(g, None, policies) for g in groups], policies

    async def one(g: dict[str, Any]) -> dict[str, Any]:
        try:
            d = await rbac_get(app, f"/admin-group/{_q(str(g.get('name')))}")
        except NotFound:
            return group_row(g, None, policies)
        return group_row(g, d if isinstance(d, dict) else None, policies)

    rows = await gather_limited(groups, one, app.settings.detail_concurrency)
    return sorted(rows, key=lambda r: str(r["name"]).lower()), policies


# --- permission sets ---------------------------------------------------------------------------------


def _leaves(nodes: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        kids = n.get("childPermissions") or []
        out += _leaves(kids) if kids else [n]
    return out


def menu_summary(data: dict[str, Any]) -> dict[str, Any]:
    """Top-level menus shown/hidden and how many menu pages are shown."""
    top = [n for n in data.get("menuAccessPrivileges") or [] if isinstance(n, dict)]
    leaves = _leaves(top)
    return {
        "name": data.get("name"),
        "tabs_shown": [str(n.get("name")) for n in top if str(n.get("permission")).lower() == "show"],
        "tabs_hidden": [str(n.get("name")) for n in top if str(n.get("permission")).lower() != "show"],
        "pages_shown": sum(1 for n in leaves if str(n.get("permission")).lower() == "show"),
        "pages_total": len(leaves),
    }


def data_summary(data: dict[str, Any]) -> dict[str, Any]:
    """Each data-access category's own permission, plus a count of its items by permission."""
    out: dict[str, Any] = {"name": data.get("name"), "categories": []}
    for n in data.get("dataAccessPrivileges") or []:
        if not isinstance(n, dict):
            continue
        counts: dict[str, int] = {}
        for leaf in _leaves(n.get("childPermissions") or []):
            key = str(leaf.get("permission"))
            counts[key] = counts.get(key, 0) + 1
        cat: dict[str, Any] = {"name": n.get("name"), "permission": n.get("permission")}
        if counts:
            cat["items"] = counts
        out["categories"].append(cat)
    return out


async def permission_sets(app: IseApp, policies: list[dict[str, Any]]) -> dict[tuple[str, str], Any]:
    """{(kind, name): summary} for each distinct menu/data access set the policies name."""
    wanted = sorted(
        {("menu", p["menu_access"]) for p in policies if p.get("menu_access")}
        | {("data", p["data_access"]) for p in policies if p.get("data_access")}
    )

    async def one(key: tuple[str, str]) -> Any:
        kind, name = key
        try:
            data = await rbac_get(app, f"/{kind}-access/{_q(name)}")
        except NotFound:
            return {"name": name, "error": "not found"}
        if not isinstance(data, dict):
            return {"name": name}
        return menu_summary(data) if kind == "menu" else data_summary(data)

    return dict(zip(wanted, await gather_limited(wanted, one), strict=True))


# --- health section -----------------------------------------------------------------------------------


async def health_section(app: IseApp, f: Any) -> dict[str, Any]:
    """The `admins` section of ise_deployment_health. {} with an info finding when RBAC can't be read."""
    try:
        rows = await admin_users(app)
    except UpstreamError as e:
        f.add("info", "admins", f"Admin accounts were not reviewed: {str(e)[:200]}")
        return {}
    s = admin_summary(rows)
    f.add(
        "info",
        "admins",
        f"{s['admins']} admin account(s), {s['super_admins']} Super Admin "
        f"({', '.join(s['super_admin_names'])}); "
        f"disabled: {len(s['disabled'])}, never-disabled: {len(s['never_disabled'])}, external: "
        f"{len(s['external'])}. Full review: ise_list_admin_users, ise_get_admin_access.",
    )
    if s["enabled_super_admins"] > SUPER_ADMIN_REVIEW:
        f.add(
            "low",
            "admins",
            f"{s['enabled_super_admins']} enabled Super Admin accounts (more than {SUPER_ADMIN_REVIEW}).",
            "Move people who don't need full control to a narrower admin group (Policy, Network Device, "
            "Identity, Helpdesk or Read Only Admin).",
        )
    risky = sorted(
        str(r["name"])
        for r in rows
        if r.get("super_admin") and r.get("never_disabled") and r.get("enabled") is not False
    )
    if risky:
        f.add(
            "low",
            "admins",
            f"Super Admin account(s) exempt from inactivity disabling: {', '.join(risky)}.",
            "Clear 'Inactive account never disabled' unless it is the break-glass account (Administration > "
            "System > Admin Access > Administrators).",
        )
    return s


# --- tools -----------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List ISE admin users")
    async def ise_list_admin_users(
        ctx: Context,
        group: Annotated[
            str | None, Field(description="Only members of this admin group, e.g. 'Super Admin'")
        ] = None,
        external: Annotated[
            bool | None, Field(description="true: only external admins; false: only internal ones")
        ] = None,
        inactive_only: Annotated[
            bool, Field(description="Only disabled admin accounts (status disabled in ISE)")
        ] = False,
        name: Annotated[str | None, Field(description="Filter: admin name contains")] = None,
        detail: Annotated[
            bool,
            Field(
                description="One GET per admin for the external, read-only, never-disabled and "
                "change-password flags (needed for `external`)"
            ),
        ] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """ISE's own administrators (Administration > System > Admin Access > Administrators), for an access
        review: name, enabled, admin groups, Super Admin or not, external, read-only, 'inactive account never
        disabled' and 'change password on next login', plus a summary (Super Admin count and names, disabled,
        never-disabled, external). Passwords are never returned. What a group may do:
        ise_get_admin_access; groups and their AD mappings: ise_list_admin_groups."""
        app: IseApp = get_client(ctx)
        if external is not None and not detail:
            raise InvalidRequest("`external` needs detail=true (the flag is only in each admin's detail)")
        rows = await admin_users(app, detail=detail)
        summary = admin_summary(rows)
        if group:
            g = group.strip().lower()
            rows = [r for r in rows if g in (str(x).lower() for x in r.get("groups", []))]
        if external is not None:
            rows = [r for r in rows if bool(r.get("external")) is external]
        if inactive_only:
            rows = [r for r in rows if r.get("enabled") is False]
        if name:
            rows = [r for r in rows if name.lower() in str(r.get("name", "")).lower()]
        rows.sort(key=lambda r: str(r.get("name", "")).lower())
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=USER_COLUMNS,
            extra={"summary": summary},
        )

    @reg.read(title="List ISE admin groups")
    async def ise_list_admin_groups(
        ctx: Context,
        name: Annotated[str | None, Field(description="Filter: group name contains")] = None,
        external_only: Annotated[
            bool, Field(description="Only groups mapped to external (AD/LDAP/SAML) groups")
        ] = False,
        with_members: Annotated[bool, Field(description="Only groups that have at least one admin")] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """ISE admin groups (built-in such as Super Admin, Policy Admin, Read Only Admin, ERS Admin, and
        custom ones): description, member admins (and which are disabled), whether the group is external and
        the external identity source and AD groups mapped to it ('which AD groups grant admin?'), and the
        RBAC policies that give it access. One GET per group. Permissions in detail: ise_get_admin_access."""
        app: IseApp = get_client(ctx)
        rows, _ = await admin_groups(app)
        if name:
            rows = [r for r in rows if name.lower() in str(r["name"]).lower()]
        if external_only:
            rows = [r for r in rows if r.get("external") or r.get("external_groups")]
        if with_members:
            rows = [r for r in rows if r.get("members")]
        mapped = [r["name"] for r in rows if r.get("external_groups")]
        extra: dict[str, Any] = {
            "external_mappings": {r["name"]: r["external_groups"] for r in rows if r.get("external_groups")}
        }
        if not mapped:
            extra["note"] = "No admin group is mapped to an external (AD/LDAP) group."
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=GROUP_COLUMNS, extra=extra
        )

    @reg.read(title="List ISE RBAC policies")
    async def ise_list_rbac_policies(
        ctx: Context,
        group: Annotated[
            str | None, Field(description="Only policies that apply to this admin group")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """ISE admin RBAC policies (Administration > System > Admin Access > Authorization > Policy): name,
        enabled, the admin groups they apply to, and the menu-access and data-access permission sets they
        grant. An admin gets the union of the enabled policies of their groups. Expanded per group or admin:
        ise_get_admin_access."""
        app: IseApp = get_client(ctx)
        rows = await rbac_policies(app)
        if group:
            g = group.strip().lower()
            rows = [r for r in rows if g in (x.lower() for x in r.get("admin_groups", []))]
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=POLICY_COLUMNS
        )

    @reg.read(title="Explain an ISE admin's access")
    async def ise_get_admin_access(
        ctx: Context,
        group: Annotated[str | None, Field(description="An admin group name, e.g. 'Policy Admin'")] = None,
        user: Annotated[
            str | None, Field(description="An admin user name (resolves to their groups)")
        ] = None,
    ) -> ToolResult:
        """What an ISE admin group, or an admin user through their groups, may do: group -> enabled RBAC
        policies -> menu access (top-level tabs shown and hidden, menu pages shown) and data access (each
        category's permission: Admin Groups, User/Endpoint Identity Groups, Network Device Groups), plus the
        external AD groups mapped to the group and its members. For a user also their account flags. Give
        `group` or `user`. Super Admin's own access cannot be narrowed (ISE built-in)."""
        app: IseApp = get_client(ctx)
        if bool(group) == bool(user):
            raise InvalidRequest("Give exactly one of `group` or `user`")
        out: dict[str, Any] = {}
        if user:
            try:
                data = await rbac_get(app, f"/admin-user/{_q(user.strip())}")
            except NotFound as e:
                raise NotFound(f"No admin user named {user!r}; see ise_list_admin_users.", 404) from e
            d = data.get("adminUserDetails") if isinstance(data, dict) else None
            if not isinstance(d, dict):
                raise NotFound(f"No admin user named {user!r}; see ise_list_admin_users.", 404)
            row = user_row({"name": d.get("name") or user.strip()}, d)
            out["user"] = row
            names = list(row.get("groups", []))
        else:
            names = [str(group).strip()]
        rows, policies = await admin_groups(app)
        by_name = {str(r["name"]).lower(): r for r in rows}
        if group and names[0].lower() not in by_name:
            close = [r["name"] for r in rows if names[0].lower() in str(r["name"]).lower()][:5]
            hint = f" Names containing it: {', '.join(close)}." if close else " See ise_list_admin_groups."
            raise NotFound(f"No admin group named {names[0]!r}.{hint}", 404)
        mine = [
            p for p in policies if {g.lower() for g in p.get("admin_groups", [])} & {n.lower() for n in names}
        ]
        enabled = [p for p in mine if p.get("enabled") is not False]
        sets = await permission_sets(app, enabled)
        out["groups"] = []
        for n in names:
            g = by_name.get(n.lower(), {"name": n, "note": "unknown admin group"})
            gp = [p for p in enabled if n.lower() in (x.lower() for x in p.get("admin_groups", []))]
            out["groups"].append(
                {
                    **g,
                    "policies": [
                        {
                            "name": p["name"],
                            "menu_access": sets.get(("menu", p.get("menu_access", "")))
                            or p.get("menu_access")
                            or NO_MENU,
                            "data_access": sets.get(("data", p.get("data_access", "")))
                            or p.get("data_access")
                            or NO_DATA,
                        }
                        for p in gp
                    ],
                }
            )
        disabled = [p["name"] for p in mine if p.get("enabled") is False]
        if disabled:
            out["disabled_policies"] = disabled
        if SUPER_ADMIN.lower() in (n.lower() for n in names):
            out["note"] = (
                "Super Admin: full access to every menu and all data (ISE built-in, cannot be narrowed)."
            )
        if not enabled:
            out["note"] = (
                out.get("note", "") + " No enabled RBAC policy applies: no menu or data access."
            ).strip()
        return object_result(out)

"""Internal users, user identity groups and identity sources (ERS + OpenAPI)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import (
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    object_result,
)
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list, ers_name_map, ers_resolve, gather_limited, list_result

USER_COLUMNS = ["name", "enabled", "groups", "email", "description", "id"]


def user_row(user: dict[str, Any], groups: dict[str, str]) -> dict[str, Any]:
    ids = [g for g in str(user.get("identityGroups") or "").split(",") if g]
    row = {
        "name": user.get("name"),
        "id": user.get("id"),
        "enabled": user.get("enabled"),
        "groups": [groups.get(g, g) for g in ids],
        "email": user.get("email"),
        "first_name": user.get("firstName"),
        "last_name": user.get("lastName"),
        "description": user.get("description"),
        "auth_store": user.get("passwordIDStore"),  # key avoids the core secret mask
        "expiry_date": user.get("expiryDate") if user.get("expiryDateEnabled") else None,
        "created": user.get("dateCreated"),
        "modified": user.get("dateModified"),
        "custom_attributes": user.get("customAttributes"),
    }
    return {k: v for k, v in row.items() if v not in (None, "", {}, [])}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List internal users")
    async def ise_list_internal_users(
        ctx: Context,
        name: Annotated[str | None, Field(description="Filter: username contains")] = None,
        group: Annotated[
            str | None, Field(description="Filter: member of this identity group (name)")
        ] = None,
        detail: Annotated[
            bool, Field(description="Fetch each user for enabled state, groups and email (pages up to 100)")
        ] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List users in the ISE internal user store: username, enabled/disabled, identity groups and
        email. Passwords are never returned. For one user use ise_get_internal_user."""
        app: IseApp = get_client(ctx)
        filters = [f"name.CONTAINS.{name}"] if name else []
        groups = await ers_name_map(app, "identitygroup")
        if group:
            # ERS filters users by group name server-side (exact, case-sensitive), so resolve the
            # canonical name first; no full scan is needed.
            canonical = {v.lower(): v for v in groups.values()}.get(group.strip().lower())
            if canonical is None:
                raise NotFound(f"No identity group named {group!r}; see ise_list_identity_groups.", 404)
            filters.append(f"identityGroup.EQ.{canonical}")
        page = await ers_list(
            app,
            "internaluser",
            filters=filters or None,
            limit=limit,
            offset=offset,
            detail=detail,
            shape=lambda u: user_row(u, groups),
        )
        return list_result(page, fmt=response_format, columns=USER_COLUMNS if detail else None)

    @reg.read(title="Get an internal user")
    async def ise_get_internal_user(
        ctx: Context,
        user: Annotated[str, Field(description="Username or id (from ise_list_internal_users)")],
    ) -> ToolResult:
        """One internal user: enabled state, identity group names, names/email, password store,
        expiry, created/modified dates and custom attributes. Passwords are never returned. Use it to
        check why a user fails (disabled? expired? wrong group?)."""
        app: IseApp = get_client(ctx)
        obj = await ers_resolve(
            app, "internaluser", user, what="internal user", list_tool="ise_list_internal_users"
        )
        groups = await ers_name_map(app, "identitygroup")
        return object_result(user_row(obj, groups))

    @reg.read(title="List user identity groups")
    async def ise_list_identity_groups(
        ctx: Context,
        name: Annotated[str | None, Field(description="Filter: name contains")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List user identity groups (e.g. Employee, GuestType_Daily, custom groups) with description
        and id. Internal users belong to these; authorization rules match on them."""
        app: IseApp = get_client(ctx)
        filters = [f"name.CONTAINS.{name}"] if name else None
        page = await ers_list(app, "identitygroup", filters=filters, limit=limit, offset=offset)
        return list_result(page, fmt=response_format, columns=["name", "description", "id"])

    @reg.read(title="List identity sources")
    async def ise_list_identity_sources(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """List where ISE looks users up: identity source sequences (with their ordered stores),
        Active Directory join points (domain, status) and LDAP servers. Use it when an auth fails with
        'subject not found' to see which stores a sequence searches."""
        app: IseApp = get_client(ctx)
        rows: list[dict[str, Any]] = []
        seqs = await ers_list(app, "idstoresequence", limit=200, offset=0, detail=True, detail_cap=None)
        for s in seqs.items:
            stores = sorted(s.get("idSeqItem") or [], key=lambda i: i.get("order", 0))
            rows.append(
                {
                    "type": "sequence",
                    "name": s.get("name"),
                    "stores": [i.get("idstore") for i in stores],
                    "certificate_profile": s.get("certificateAuthenticationProfile"),
                    "description": s.get("description"),
                }
            )

        async def ad(item: dict[str, Any]) -> dict[str, Any]:
            obj = await app.ers_get("activedirectory", str(item["id"]))
            return {
                "type": "active_directory",
                "name": obj.get("name"),
                "domain": obj.get("domain"),
                "description": obj.get("description"),
            }

        for resource, fn in (("activedirectory", ad),):
            try:
                page = await ers_list(app, resource, limit=200, offset=0)
                rows += await gather_limited(page.items, fn)
            except UpstreamError as e:
                rows.append({"type": resource, "error": str(e)[:200]})
        try:
            ldap = await ers_list(app, "ldap", limit=200, offset=0)
            rows += [
                {"type": "ldap", "name": i.get("name"), "description": i.get("description")}
                for i in ldap.items
            ]
        except UpstreamError:
            pass
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

"""Endpoints (OpenAPI) and endpoint identity groups (ERS)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import NotFound, ResponseFormat, ToolRegistrar, get_client
from ise_mcp._core.http import PageNumber
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list, ers_name_map, is_uuid, list_result

ENDPOINT_PAGER = PageNumber(items=None, total=None, max_size=100)
ENDPOINT_COLUMNS = ["mac", "group", "static_group", "profile", "ip", "description", "id"]


async def profile_name(app: IseApp, profile_id: str | None) -> str | None:
    if not profile_id:
        return None
    cache: dict[str, str] = app.__dict__.setdefault("_profile_names", {})
    if profile_id not in cache:
        try:
            cache[profile_id] = str((await app.ers_get("profilerprofile", profile_id)).get("name"))
        except NotFound:
            cache[profile_id] = profile_id
    return cache[profile_id]


def endpoint_row(ep: dict[str, Any], groups: dict[str, str]) -> dict[str, Any]:
    row = {
        "mac": ep.get("mac") or ep.get("name"),
        "group": groups.get(str(ep.get("groupId")), ep.get("groupId")),
        "static_group": ep.get("staticGroupAssignment"),
        "profile_id": ep.get("profileId"),
        "static_profile": ep.get("staticProfileAssignment"),
        "ip": ep.get("ipAddress"),
        "description": ep.get("description"),
        "identity_store": ep.get("identityStore"),
        "portal_user": ep.get("portalUser"),
        "device_type": ep.get("deviceType") or ep.get("mfcInfoEndpointType"),
        "vendor": ep.get("vendor") or ep.get("mfcInfoHardwareManufacturer"),
        "os": ep.get("mfcInfoOperatingSystem"),
        "mdm": ep.get("mdmAttributes"),
        "custom": ep.get("customAttributes"),
        "id": ep.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, "", "[]")}


async def resolve_group_id(app: IseApp, resource: str, name_or_id: str, what: str, list_tool: str) -> str:
    if is_uuid(name_or_id):
        return name_or_id
    hit = await app.ers_find(resource, name_or_id)
    if hit is None:
        raise NotFound(f"No {what} named {name_or_id!r}; see {list_tool}.", 404)
    return str(hit["id"])


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List endpoints")
    async def ise_list_endpoints(
        ctx: Context,
        mac: Annotated[
            str | None, Field(description="Filter: MAC contains (e.g. '00:50:56' for a vendor OUI)")
        ] = None,
        group: Annotated[str | None, Field(description="Filter: endpoint identity group name or id")] = None,
        ip: Annotated[str | None, Field(description="Filter: endpoint IP address")] = None,
        static_only: Annotated[
            bool, Field(description="Only endpoints with a static group assignment")
        ] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List endpoints ISE knows about (seen via RADIUS/profiling or added by hand): MAC, endpoint
        identity group, whether the group is static, profile, IP and description. Use ise_endpoint_360
        for everything about one endpoint (sessions, auth history, ANC)."""
        app: IseApp = get_client(ctx)
        filters = []
        if mac:
            filters.append(f"mac.CONTAINS.{mac.upper()}")
        if group:
            gid = await resolve_group_id(
                app, "endpointgroup", group, "endpoint group", "ise_list_endpoint_groups"
            )
            filters.append(f"groupId.EQ.{gid}")
        if ip:
            filters.append(f"ipAddress.EQ.{ip}")
        if static_only:
            filters.append("staticGroupAssignment.EQ.true")
        params = {"filter": filters} if filters else None
        page = await ENDPOINT_PAGER.fetch_page(
            app.openapi, "/api/v1/endpoint", params, limit=limit, offset=offset
        )
        groups = await ers_name_map(app, "endpointgroup")
        rows = []
        for ep in page.items:
            if isinstance(ep, dict):
                row = endpoint_row(ep, groups)
                row["profile"] = await profile_name(app, row.pop("profile_id", None))
                rows.append(row)
        page.items = rows
        return list_result(page, fmt=response_format, columns=ENDPOINT_COLUMNS)

    @reg.read(title="List endpoint identity groups")
    async def ise_list_endpoint_groups(
        ctx: Context,
        name: Annotated[str | None, Field(description="Filter: name contains")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List endpoint identity groups (e.g. Blocked List, Profiled, RegisteredDevices, custom groups):
        name, description and id. Group names are used by authorization conditions and by the endpoint
        create/update tools."""
        app: IseApp = get_client(ctx)
        filters = [f"name.CONTAINS.{name}"] if name else None
        page = await ers_list(app, "endpointgroup", filters=filters, limit=limit, offset=offset)
        return list_result(page, fmt=response_format, columns=["name", "description", "id"])

"""TrustSec (SGTs, SGACLs, egress matrix, IP-SGT mappings) and ANC (ERS + OpenAPI)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import ResponseFormat, ToolRegistrar, get_client
from stutters_mcp_core.http import page_of

from ise_mcp.client import IseApp
from ise_mcp.tools._common import (
    anc_assignments,
    ers_list,
    ers_name_map,
    list_result,
    normalize_mac,
    openapi_all,
)


def sgt_row(s: dict[str, Any]) -> dict[str, Any]:
    value = s.get("value")
    return {
        "name": s.get("name"),
        "value": value,
        "hex": f"{int(value):04X}" if isinstance(value, int) else None,
        "description": s.get("description"),
        "propagate_to_apic": s.get("propogateToApic") or None,
        "id": s.get("id"),
    }


def sgacl_row(a: dict[str, Any]) -> dict[str, Any]:
    lines = [ln for ln in str(a.get("aclcontent") or "").splitlines() if ln.strip()]
    return {
        "name": a.get("name"),
        "ip_version": a.get("ipVersion"),
        "aces": lines,
        "read_only": a.get("readOnly") or None,
        "description": a.get("description"),
        "id": a.get("id"),
    }


async def sgt_names(app: IseApp) -> dict[str, str]:
    """{sgt id: 'Name (value)'}."""
    page = await ers_list(app, "sgt", limit=5000, offset=0, detail=True, detail_cap=None)
    return {str(s["id"]): f"{s.get('name')} ({s.get('value')})" for s in page.items if "id" in s}


MATRIX_CELL_CAP = 2000


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List security group tags")
    async def ise_list_sgts(
        ctx: Context,
        name: Annotated[str | None, Field(description="Filter: name contains")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List TrustSec security group tags (SGTs): name, numeric value (and hex), description and id.
        SGT names/values appear in authorization rules, the egress matrix and IP-SGT mappings."""
        app: IseApp = get_client(ctx)
        filters = [f"name.CONTAINS.{name}"] if name else None
        page = await ers_list(
            app, "sgt", filters=filters, limit=limit, offset=offset, detail=True, shape=sgt_row
        )
        return list_result(page, fmt=response_format, columns=["name", "value", "hex", "description", "id"])

    @reg.read(title="List SGACLs")
    async def ise_list_sgacls(
        ctx: Context,
        name: Annotated[str | None, Field(description="Filter: name contains")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """List security group ACLs (SGACLs) with their ACE lines and IP version. SGACLs are applied
        in egress matrix cells (see ise_get_egress_matrix)."""
        app: IseApp = get_client(ctx)
        filters = [f"name.CONTAINS.{name}"] if name else None
        page = await ers_list(
            app, "sgacl", filters=filters, limit=limit, offset=offset, detail=True, shape=sgacl_row
        )
        return list_result(page, fmt=response_format)

    @reg.read(title="TrustSec egress matrix")
    async def ise_get_egress_matrix(
        ctx: Context,
        source: Annotated[
            str | None, Field(description="Only cells whose source SGT name contains this")
        ] = None,
        destination: Annotated[
            str | None, Field(description="Only cells whose destination SGT name contains this")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The TrustSec egress policy matrix as cells: source SGT -> destination SGT, the SGACLs
        applied, the final catch-all rule (permit/deny), and cell status. Answers 'can Employees talk to
        Development_Servers?'. Cells not listed fall back to the ANY-ANY default."""
        app: IseApp = get_client(ctx)
        # Narrow server-side by SGT name first so a large matrix isn't fetched cell by cell.
        filters = []
        if source:
            filters.append(f"sgtSrcName.CONTAINS.{source}")
        if destination:
            filters.append(f"sgtDstName.CONTAINS.{destination}")
        cells = await ers_list(
            app,
            "egressmatrixcell",
            filters=filters or None,
            limit=MATRIX_CELL_CAP,
            offset=0,
            detail=True,
            detail_cap=None,
        )
        sgts = await sgt_names(app)
        acls = await ers_name_map(app, "sgacl")
        rows = []
        for c in cells.items:
            src = sgts.get(
                str(c.get("sourceSgtId")), "ANY" if not c.get("sourceSgtId") else c.get("sourceSgtId")
            )
            dst = sgts.get(
                str(c.get("destinationSgtId")),
                "ANY" if not c.get("destinationSgtId") else c.get("destinationSgtId"),
            )
            if c.get("name") == "ANY-ANY":
                src = dst = "ANY"
            row = {
                "source": src,
                "destination": dst,
                "sgacls": [acls.get(str(a), a) for a in c.get("sgacls") or []],
                "default_rule": c.get("defaultRule"),
                "status": c.get("matrixCellStatus"),
                "name": c.get("name"),
                "id": c.get("id"),
            }
            rows.append(row)
        if source:
            rows = [r for r in rows if source.lower() in str(r["source"]).lower()]
        if destination:
            rows = [r for r in rows if destination.lower() in str(r["destination"]).lower()]
        rows.sort(key=lambda r: (r["source"] != "ANY", str(r["source"]), str(r["destination"])))
        extra = None
        if not cells.complete:
            extra = {
                "partial": f"Only the first {MATRIX_CELL_CAP} cells were read; filter by source or "
                "destination for the rest."
            }
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["source", "destination", "sgacls", "default_rule", "status"],
            extra=extra,
        )

    @reg.read(title="List IP-SGT mappings")
    async def ise_list_ip_sgt_mappings(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List static IP-to-SGT mappings (host or subnet -> SGT), with the devices/groups they are
        deployed to. Dynamic mappings learned from sessions are not included (see sessions)."""
        app: IseApp = get_client(ctx)
        items = await openapi_all(app, "/api/v1/trustsec/ip-sgt-mapping")
        return list_result(page_of(items, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="List ANC policies")
    async def ise_list_anc_policies(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List Adaptive Network Control (ANC) policies and their actions (QUARANTINE, PORTBOUNCE,
        SHUTDOWN, REAUTHENTICATE). Policy names are used by ise_apply_anc."""
        app: IseApp = get_client(ctx)
        page = await ers_list(
            app,
            "ancpolicy",
            limit=limit,
            offset=offset,
            detail=True,
            shape=lambda p: {"name": p.get("name"), "actions": p.get("actions"), "id": p.get("id")},
        )
        return list_result(page, fmt=response_format)

    @reg.read(title="List endpoints under ANC")
    async def ise_list_anc_endpoints(
        ctx: Context,
        mac: Annotated[str | None, Field(description="Only this endpoint MAC")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List endpoints that currently have an ANC policy applied (e.g. quarantined), with the policy
        name. Clear one with ise_clear_anc."""
        app: IseApp = get_client(ctx)
        rows = [
            {"mac": e.get("macAddress"), "policy": e.get("policyName"), "id": e.get("id")}
            for e in await anc_assignments(app, normalize_mac(mac) if mac else None)
        ]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

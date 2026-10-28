"""TrustSec virtual networks and SGT-VN-VLAN mappings (read only).

In SD-Access, Catalyst Center owns these objects: it creates the virtual networks in ISE (OpenAPI
`trustsec/virtualnetwork`) and the SGT -> VN (-> VLAN) mappings (ERS `sgtvnvlan`) that tie each
security group to the fabric's virtual networks. This server reads them; it does not write them, so
ISE and the fabric don't drift apart.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import json
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import ResponseFormat, ToolRegistrar, UpstreamError, get_client
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list, ers_name_map, list_result, openapi_all

VN_PATH = "/api/v1/trustsec/virtualnetwork"


def parse_attributes(raw: Any) -> Any:
    """`additionalAttributes` is a JSON string; return it parsed (or as given when it isn't JSON)."""
    if not isinstance(raw, str) or not raw.strip():
        return raw or None
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def vn_row(vn: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": vn.get("name"),
        "last_update": vn.get("lastUpdate"),
        "additional_attributes": parse_attributes(vn.get("additionalAttributes")),
        "id": vn.get("id"),
    }


def vlan_text(vlan: dict[str, Any]) -> str:
    name = str(vlan.get("name") or vlan.get("id") or "?")
    return f"{name} (default)" if vlan.get("defaultVlan") else name


def mapping_row(m: dict[str, Any], sgt_names: dict[str, str]) -> dict[str, Any]:
    """One ERS SgtVNVlanContainer -> {sgt, virtual_networks, vlans, ...} with the SGT id resolved."""
    sgt_id = str(m.get("sgtId") or "")
    vns: list[str] = []
    vlans: dict[str, list[str]] = {}
    default_vn = None
    for vn in m.get("virtualnetworklist") or []:
        if not isinstance(vn, dict):
            continue
        name = str(vn.get("name") or vn.get("id") or "?")
        vns.append(name)
        if vn.get("defaultVirtualNetwork"):
            default_vn = name
        names = [vlan_text(v) for v in vn.get("vlans") or [] if isinstance(v, dict)]
        if names:
            vlans[name] = names
    return {
        "sgt": sgt_names.get(sgt_id, sgt_id or None),
        "virtual_networks": vns,
        "default_virtual_network": default_vn,
        "vlans": vlans,
        "name": m.get("name"),
        "description": m.get("description") or None,
        "sgt_id": sgt_id or None,
        "id": m.get("id"),
    }


async def sgt_vn_mappings(app: IseApp) -> tuple[list[dict[str, Any]], str | None]:
    """Every SGT-VN-VLAN mapping, shaped, plus the detail note when per-item reads were skipped."""
    sgt_names = await ers_name_map(app, "sgt")
    page = await ers_list(app, "sgtvnvlan", limit=10_000, offset=0, detail=True)
    note = getattr(page, "note", None)
    if note:
        return [{"name": i.get("name"), "id": i.get("id")} for i in page.items], note
    return [mapping_row(m, sgt_names) for m in page.items], None


def _matches(value: Any, key: str | None) -> bool:
    return not key or key.strip().lower() in str(value or "").lower()


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List TrustSec virtual networks")
    async def ise_list_virtual_networks(
        ctx: Context,
        name: Annotated[str | None, Field(description="Only VNs whose name contains this")] = None,
        include_sgts: Annotated[
            bool,
            Field(
                description="Also list the SGTs mapped to each VN (from the SGT-VN-VLAN mappings, ERS) "
                "and the SGTs mapped to no VN"
            ),
        ] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the TrustSec virtual networks ISE knows (Work Centers > TrustSec > Components >
        Virtual Networks): name, last update, additional attributes and id, and with include_sgts the
        security groups mapped to each VN. In SD-Access, Catalyst Center creates these when a VN is
        added to the fabric (DEFAULT_VN and INFRA_VN are its own); 'does ISE know this VN, and which
        SGTs belong to it?' is the day-2 check after a VN add or a group-based policy migration.
        Compare with the fabric's VNs from catc_get_sda_fabric. Read only: Catalyst Center owns these
        objects, so change them there."""
        app: IseApp = get_client(ctx)
        vns = [vn_row(v) for v in await openapi_all(app, VN_PATH) if isinstance(v, dict)]
        vns = [v for v in vns if _matches(v["name"], name)]
        vns.sort(key=lambda v: str(v["name"] or "").lower())
        extra: dict[str, Any] = {}
        columns = ["name", "last_update", "id"]
        if include_sgts:
            try:
                mappings, note = await sgt_vn_mappings(app)
            except UpstreamError as e:
                mappings, note = [], f"SGT-VN-VLAN mappings unavailable (ERS): {e}"
            if note:
                extra["sgt_note"] = note
            else:
                by_vn: dict[str, list[str]] = {}
                for m in mappings:
                    for vn in m["virtual_networks"]:
                        by_vn.setdefault(vn, []).append(str(m["sgt"]))
                for v in vns:
                    v["sgts"] = sorted(by_vn.get(str(v["name"]), []), key=str.lower)
                columns = ["name", "sgts", "last_update", "id"]
                known = {str(v["name"]) for v in vns}
                if not name:
                    mapped = {str(m["sgt"]) for m in mappings if m["virtual_networks"]}
                    sgts = sorted((await ers_name_map(app, "sgt")).values(), key=str.lower)
                    extra["sgts_without_vn"] = [s for s in sgts if s not in mapped]
                    unknown = sorted({vn for vn in by_vn if vn not in known})
                    if unknown:
                        extra["mapped_vns_not_listed"] = unknown
        if not vns and not name:
            extra["note"] = (
                "ISE has no virtual networks: none were created here and no Catalyst Center integration "
                "has pushed any (SD-Access adds them when a VN is added to a fabric)"
            )
        return list_result(
            page_of(vns, limit=limit, offset=offset), fmt=response_format, columns=columns, extra=extra
        )

    @reg.read(title="List SGT-VN-VLAN mappings")
    async def ise_list_sgt_vn_vlan(
        ctx: Context,
        sgt: Annotated[str | None, Field(description="Only SGTs whose name contains this")] = None,
        virtual_network: Annotated[
            str | None, Field(description="Only mappings that include a VN whose name contains this")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the SGT-VN-VLAN mappings (ERS sgtvnvlan): for each security group, the virtual
        networks it belongs to (and which one is its default) and the VLANs per VN, with the SGT id
        resolved to its name. In SD-Access, Catalyst Center writes these when a scalable group is
        assigned to a VN; an SGT with no VN can't be used in that fabric's host onboarding. See
        ise_list_virtual_networks for the VNs themselves. Read only: change them in Catalyst Center."""
        app: IseApp = get_client(ctx)
        rows, note = await sgt_vn_mappings(app)
        if note:
            return list_result(
                page_of(rows, limit=limit, offset=offset), fmt=response_format, extra={"detail_note": note}
            )
        rows = [
            r
            for r in rows
            if _matches(r["sgt"], sgt)
            and (not virtual_network or any(_matches(v, virtual_network) for v in r["virtual_networks"]))
        ]
        rows.sort(key=lambda r: str(r["sgt"] or "").lower())
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["sgt", "virtual_networks", "default_virtual_network", "vlans", "name"],
        )

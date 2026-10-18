"""TrustSec (SGTs, SGACLs, egress matrix, IP-SGT mappings) and ANC (ERS + OpenAPI)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

from datetime import UTC, datetime
from typing import Annotated, Any
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import NotFound, ResponseFormat, ToolRegistrar, get_client
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp
from ise_mcp.tools._common import (
    anc_assignments,
    ers_list,
    ers_name_map,
    list_result,
    normalize_mac,
    openapi_all,
)
from ise_mcp.tools.network import resolve_nad


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


async def _default_cell(
    app: IseApp, sgts: dict[str, str], acls: dict[str, str], source: str, destination: str
) -> dict[str, Any] | str:
    """What applies to a source/destination pair with no explicit cell: the ANY-ANY default."""
    known = {n.lower() for n in sgts.values()}
    missing = [n for n in (source, destination) if not any(n.lower() in k for k in known)]
    if missing:
        return f"No SGT name contains {', '.join(repr(m) for m in missing)} (see ise_list_sgts)"
    # ERS can't filter cells by name; the default cell's source SGT name is 'ANY'.
    page = await ers_list(
        app,
        "egressmatrixcell",
        filters=["sgtSrcName.EQ.ANY"],
        limit=20,
        offset=0,
        detail=True,
        detail_cap=None,
    )
    cell = next((c for c in page.items if isinstance(c, dict) and c.get("name") == "ANY-ANY"), None)
    if cell is None:
        return "No explicit cell, and the ANY-ANY default cell could not be read"
    return {
        "source": source,
        "destination": destination,
        "explicit_cell": False,
        "applies": "ANY-ANY default",
        "sgacls": [acls.get(str(a), a) for a in cell.get("sgacls") or []],
        "default_rule": cell.get("defaultRule"),
        "status": cell.get("matrixCellStatus"),
    }


# --- TrustSec device report (GET /api/v1/trustsec/policy/device-report) -------------------------

DEVICE_REPORT = "/api/v1/trustsec/policy/device-report"

# `state`: the last step in the ISE <-> device TrustSec exchange.
REPORT_STEPS = {
    "ENVDATA_DOWNLOAD": "environment data downloaded",
    "SGACL_DOWNLOAD": "SGACLs downloaded",
    "TRUSTSEC_POLICY_DOWNLOAD": "policy downloaded",
    "STEERING_POLICY_DOWNLOAD": "steering policy downloaded",
    "STEERING_CONTRACT_DOWNLOAD": "steering contract downloaded",
    "DEVICE_REPORT": "device report received",
    "COA_SENT": "CoA sent",
    "COA_ERROR": "CoA error",
}
# `status` values that mean the last step succeeded.
REPORT_OK = {"UPDATE_SUCCESS", "REPORT_VALIDATION_SUCCESS", "ENV_REQUEST_SUCCESS", "COA_ACK", "COA_APPROVED"}
REPORT_HINTS = {
    "COA_NACK": "the switch refused the TrustSec CoA: check 'aaa server radius dynamic-author' and its key",
    "COA_TIMED_OUT": "the TrustSec CoA got no answer: check the NAD's CoA port and that UDP 1700 reaches "
    "the switch",
    "COA_ERROR": "ISE could not send the TrustSec CoA: check the NAD's CoA settings",
    "ENV_REQUEST_FAILED": "environment data request failed: the NAD's TrustSec device id/password must match "
    "'cts credentials' on the switch, and the PAC must be valid ('show cts pacs')",
    "UPDATE_ERROR": "policy download failed: 'cts refresh policy' on the switch and check "
    "'show cts role-based permissions'",
    "UPDATE_TIMED_OUT": "policy download timed out: 'cts refresh policy' on the switch",
    "TIMED_OUT": "the exchange timed out: 'cts refresh environment-data' then 'cts refresh policy' on "
    "the switch",
    "REPORT_VALIDATION_ERROR": "the switch's report does not match ISE's policy: 'cts refresh policy', then "
    "compare 'show cts role-based permissions' with ise_get_egress_matrix",
    "REPORT_VALIDATION_WARNING": "the switch's report differs from ISE's policy in part: compare "
    "'show cts role-based permissions' with ise_get_egress_matrix",
}
STALE_HINT = (
    "ISE changed TrustSec policy after the device last downloaded it: ise_push_trustsec_matrix, or "
    "'cts refresh policy' on the switch"
)


def report_time(value: Any) -> datetime | None:
    """ISE timestamps in the report (ISO 8601, or epoch seconds/milliseconds) -> aware datetime."""
    if value in (None, ""):
        return None
    if isinstance(value, int | float):
        secs = float(value) / (1000 if value > 1e11 else 1)
        return datetime.fromtimestamp(secs, tz=UTC)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%a %b %d %H:%M:%S %Z %Y")
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def device_report_row(r: dict[str, Any]) -> dict[str, Any]:
    """One CTSDeviceReport -> device, last step, status, whether the device holds ISE's current policy."""
    state = r.get("state")
    status = r.get("status")
    policy_at = report_time(r.get("policyUpdatedTime"))
    status_at = report_time(r.get("statusUpdatedTime"))
    ok = status in REPORT_OK
    current: bool | None
    if not ok:
        current = False
    elif policy_at and status_at:
        current = status_at >= policy_at
    else:
        current = None
    hint = REPORT_HINTS.get(str(status))
    if hint is None and current is False:
        hint = STALE_HINT
    return {
        "device": r.get("name"),
        "ip": r.get("ipAddress"),
        "last_step": REPORT_STEPS.get(str(state), state),
        "status": status,
        "current": current,
        "policy_updated": r.get("policyUpdatedTime"),
        "status_updated": r.get("statusUpdatedTime"),
        "policy_version": r.get("policyVersionId"),
        "hint": hint,
        "push_id": r.get("pushId"),
        "pull_id": r.get("pullId"),
    }


def report_items(data: Any) -> list[dict[str, Any]]:
    """The report body ({"response": [...] | {...} | null}) -> list of device reports."""
    body = data.get("response", data) if isinstance(data, dict) else data
    if isinstance(body, dict):
        return [body]
    return [i for i in body if isinstance(i, dict)] if isinstance(body, list) else []


REPORT_COLUMNS = [
    "device",
    "ip",
    "last_step",
    "status",
    "current",
    "policy_updated",
    "status_updated",
    "hint",
]
NO_REPORT_NOTE = (
    "No TrustSec device has reported to ISE. This report covers the HTTPS (REST) policy download: the "
    "device appears once ISE's TrustSec HTTPS server is enabled (GET /api/v1/trustsec/general-settings, "
    "httpsServerConfig.enableHttps), the NAD has TrustSec settings (ise_update_nad trustsec_id / "
    "trustsec_password, plus the REST API credentials) and the switch downloads with 'cts policy-server'. "
    "Switches that download over RADIUS/PAC only never appear here; check them with 'show cts "
    "role-based permissions'. See docs/trustsec.md."
)


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
        Development_Servers?'. Cells not listed fall back to the ANY-ANY default; given both a source
        and a destination with no cell, the result's 'effective' field shows that default."""
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
        extra: dict[str, Any] | None = None
        if not cells.complete:
            extra = {
                "partial": f"Only the first {MATRIX_CELL_CAP} cells were read; filter by source or "
                "destination for the rest."
            }
        if source and destination and not rows:
            extra = {**(extra or {}), "effective": await _default_cell(app, sgts, acls, source, destination)}
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["source", "destination", "sgacls", "default_rule", "status"],
            extra=extra,
        )

    @reg.read(title="TrustSec policy status per device")
    async def ise_trustsec_device_report(
        ctx: Context,
        nad: Annotated[
            str | None,
            Field(
                description="Network device name (may be partial), id or IP; default: all TrustSec devices"
            ),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Which network devices have downloaded ISE's current TrustSec policy: per device the last step of
        the ISE <-> switch exchange (environment data, SGACLs, policy, CoA), its status, when ISE last
        changed policy, when the device last reported, whether it is current, and what to check when it
        is not (PAC, CTS credentials, CoA, 'cts refresh policy'). This is ISE's side of the check after
        ise_set_egress_policy / ise_push_trustsec_matrix; the switch side is 'show cts role-based
        permissions'. ISE keeps this report for devices that download policy over HTTPS ('cts
        policy-server' on IOS-XE, ISE's TrustSec HTTPS server enabled); a device missing from it either
        never downloaded policy or downloads over RADIUS/PAC only (then the switch CLI is the check)."""
        app: IseApp = get_client(ctx)
        extra: dict[str, Any] | None = None
        if nad:
            device = await resolve_nad(app, nad, fuzzy=True)
            name = str(device.get("name"))
            try:
                data = await app.openapi.get(f"{DEVICE_REPORT}/network-device/{quote(name, safe='')}")
            except NotFound:
                raise NotFound(
                    f"ISE has no TrustSec report for network device {name!r}: it has never downloaded "
                    "TrustSec policy over HTTPS (the flow this report covers). Check the NAD's TrustSec "
                    "settings (ise_get_nad), ISE's TrustSec HTTPS server (GET /api/v1/trustsec/"
                    "general-settings) and the switch ('show cts policy-server statistics' for HTTPS, "
                    "'show cts pacs' / 'show cts role-based permissions' for RADIUS downloads); see "
                    "docs/trustsec.md.",
                    404,
                ) from None
            items = report_items(data)
            if len(items) > 1:
                items = [i for i in items if i.get("name") == name]
            if device.get("resolved_from"):
                extra = {"resolved_from": device["resolved_from"]}
        else:
            items = report_items(await app.openapi.get(DEVICE_REPORT))
            if not items:
                extra = {"note": NO_REPORT_NOTE}
        rows = sorted((device_report_row(i) for i in items), key=lambda r: str(r["device"]))
        page = page_of(rows, limit=limit, offset=offset)
        return list_result(page, fmt=response_format, columns=REPORT_COLUMNS, extra=extra)

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

"""Deployment, licensing, patches, backups and certificates (OpenAPI)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import asyncio
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import (
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp
from ise_mcp.tools._common import openapi_all


def _response(data: Any) -> Any:
    return data.get("response", data) if isinstance(data, dict) else data


def _parse_date(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    for fmt in (
        "%a %b %d %H:%M:%S %Z %Y",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _cert_row(c: dict[str, Any], node: str | None) -> dict[str, Any]:
    expires = _parse_date(c.get("expirationDate"))
    row: dict[str, Any] = {
        "name": c.get("friendlyName"),
        "id": c.get("id"),
        "node": node,
        "used_by": c.get("usedBy"),
        "issued_to": c.get("issuedTo"),
        "issued_by": c.get("issuedBy"),
        "expires": c.get("expirationDate"),
        "days_left": (expires - datetime.now(UTC)).days if expires else None,
        "status": c.get("status"),
        "trusted_for": c.get("trustedFor"),
        # What a renewal copies (I52 #190). ISE's REST API has no SANs for a certificate.
        "key_size": c.get("keySize"),
        "signature_algorithm": c.get("signatureAlgorithm"),
        "valid_from": c.get("validFrom"),
        "self_signed": c.get("selfSigned"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List ISE deployment nodes")
    async def ise_list_nodes(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the ISE nodes in the deployment: hostname, FQDN, IP, roles (PAN/MnT/PSN/Standalone),
        enabled services (Session = PSN, Profiler, pxGrid, ...) and sync status. Use the hostname with
        ise_list_certificates (system certs are per node)."""
        app: IseApp = get_client(ctx)
        nodes = _response(await app.openapi.get("/api/v1/deployment/node")) or []
        return list_result(page_of(list(nodes), limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="ISE license status")
    async def ise_get_license_status(ctx: Context) -> ToolResult:
        """Licensing summary: smart-licensing registration state, connection type, evaluation period,
        and per-tier (Essentials/Advantage/Premier/Device Admin/...) status, compliance and consumption.
        Use it to explain features that are unavailable or out of compliance."""
        app: IseApp = get_client(ctx)
        paths = {
            "tiers": "/api/v1/license/system/tier-state",
            "smart_state": "/api/v1/license/system/smart-state",
            "registration": "/api/v1/license/system/register",
            "connection_type": "/api/v1/license/system/connection-type",
            "evaluation": "/api/v1/license/system/eval-license",
        }

        async def one(path: str) -> Any:
            try:
                return _response(await app.openapi.get(path))
            except UpstreamError as e:
                return {"error": str(e)[:200]}

        values = await asyncio.gather(*(one(p) for p in paths.values()))
        return object_result(dict(zip(paths, values, strict=True)))

    @reg.read(title="List installed patches")
    async def ise_list_patches(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List installed ISE patches and hot patches with install dates, plus the base ISE version.
        Use it to check whether a fix/patch level is present before troubleshooting a known bug."""
        app: IseApp = get_client(ctx)
        patch, hot = await asyncio.gather(
            app.openapi.get("/api/v1/patch"), app.openapi.get("/api/v1/hotpatch")
        )
        patch = _response(patch) or {}
        rows: list[dict[str, Any]] = [
            {"type": "patch", "name": f"Patch {p.get('patchNumber')}", "installed": p.get("installDate")}
            for p in (patch.get("patchVersion") or [])
            if isinstance(p, dict)
        ]
        for h in _response(hot) or []:
            if isinstance(h, dict):
                rows.append(
                    {"type": "hotpatch", "name": h.get("hotpatchName"), "installed": h.get("installDate")}
                )
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            extra={"ise_version": patch.get("iseVersion")},
        )

    @reg.read(title="Last configuration backup")
    async def ise_get_backup_status(ctx: Context) -> ToolResult:
        """Status of the last configuration backup (name, repository, start/end time, status, progress).
        Answers 'when did ISE last back up and did it work?'. Take one with ise_create_backup."""
        app: IseApp = get_client(ctx)
        data = _response(await app.openapi.get("/api/v1/backup-restore/config/last-backup-status"))
        if not isinstance(data, dict) or not any(v not in (None, "") for v in data.values()):
            return object_result(
                {"status": "none", "note": "No configuration backup has run on this deployment."}
            )
        return object_result(data)

    @reg.read(title="List certificates")
    async def ise_list_certificates(
        ctx: Context,
        kind: Annotated[
            Literal["system", "trusted"],
            Field(
                description="'system' = per-node identity certs (EAP, Admin, Portal); 'trusted' = trust store"
            ),
        ] = "system",
        node: Annotated[
            str | None,
            Field(description="Node hostname for system certs (default: every node, see ise_list_nodes)"),
        ] = None,
        expiring_within_days: Annotated[
            int | None, Field(ge=0, description="Only certificates that expire within this many days")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List system (per-node identity) or trusted certificates with what they are used for, issuer,
        expiry and days left (JSON rows also carry key size, signature algorithm, valid-from and
        self-signed). Use expiring_within_days=60 to find certificates about to expire (a
        common cause of EAP-TLS/PEAP failures). Ids feed the certificate delete tool."""
        app: IseApp = get_client(ctx)
        rows: list[dict[str, Any]] = []
        if kind == "trusted":
            page = await openapi_all(app, "/api/v1/certs/trusted-certificate")
            rows = [_cert_row(c, None) for c in page if isinstance(c, dict)]
        else:
            nodes = (
                [node]
                if node
                else [
                    str(n.get("hostname"))
                    for n in _response(await app.openapi.get("/api/v1/deployment/node")) or []
                ]
            )
            for host in nodes:
                certs = await openapi_all(app, f"/api/v1/certs/system-certificate/{quote(host, safe='')}")
                rows += [_cert_row(c, host) for c in certs if isinstance(c, dict)]
        if expiring_within_days is not None:
            rows = [
                r for r in rows if r.get("days_left") is not None and r["days_left"] <= expiring_within_days
            ]
        rows.sort(key=lambda r: (r.get("days_left") is None, r.get("days_left") or 0))
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["name", "node", "used_by", "issued_by", "expires", "days_left", "id"]
            if kind == "system"
            else ["name", "issued_to", "issued_by", "expires", "days_left", "status", "id"],
        )

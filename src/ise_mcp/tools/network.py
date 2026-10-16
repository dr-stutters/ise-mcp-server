"""Network access devices (NADs), network device groups (NDGs) and a NAD audit (ERS)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import hashlib
import ipaddress
import time
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import (
    InvalidRequest,
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    object_result,
)
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list, ers_resolve, list_result, parse_ip

NAD_CACHE_SECONDS = 60
DEFAULT_NDGS = {"Location#All Locations", "Device Type#All Device Types"}
WEAK_COMMUNITIES = {"public", "private", "cisco", "community"}
NAD_COLUMNS = ["name", "ips", "groups", "radius", "tacacs", "snmp", "trustsec", "profile", "id"]


def nad_ips(nad: dict[str, Any]) -> list[str]:
    return [
        f"{i.get('ipaddress')}/{i.get('mask')}"
        for i in nad.get("NetworkDeviceIPList") or []
        if isinstance(i, dict) and i.get("ipaddress")
    ]


def nad_networks(nad: dict[str, Any]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets = []
    for cidr in nad_ips(nad):
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return nets


def nad_summary(nad: dict[str, Any]) -> dict[str, Any]:
    """One row per NAD: never includes secret values, only whether they are set."""
    auth = nad.get("authenticationSettings") or {}
    tacacs = nad.get("tacacsSettings") or {}
    snmp = nad.get("snmpsettings") or {}
    trustsec = nad.get("trustsecsettings") or {}
    return {
        "name": nad.get("name"),
        "id": nad.get("id"),
        "description": nad.get("description"),
        "ips": nad_ips(nad),
        "groups": nad.get("NetworkDeviceGroupList") or [],
        "radius": "secret set" if auth.get("radiusSharedSecret") else "no secret",
        "tacacs": "secret set" if tacacs.get("sharedSecret") else "no",
        "snmp": snmp.get("version") or "no",
        "trustsec": "yes" if trustsec else "no",
        "profile": nad.get("profileName"),
        "coa_port": nad.get("coaPort"),
    }


async def all_nads(app: IseApp, cap: int = 1000) -> tuple[list[dict[str, Any]], bool]:
    """Full details for every NAD (up to cap); returns (nads, complete). Cached for a minute so a burst of
    subnet lookups (e.g. several ise_why_auth_failed calls) doesn't refetch every device."""
    cached = app.__dict__.get("_nad_cache")
    if cached and time.monotonic() - cached[0] < NAD_CACHE_SECONDS:
        return cached[1], cached[2]
    page = await ers_list(app, "networkdevice", limit=cap, offset=0, detail=True, detail_cap=None)
    nads = [n for n in page.items if isinstance(n, dict)]
    app.__dict__["_nad_cache"] = (time.monotonic(), nads, page.complete)
    return nads, page.complete


async def find_nads_for_ip(app: IseApp, ip: str) -> list[dict[str, Any]]:
    """NADs whose IP list contains `ip` (exact entries first, then subnets, most specific first)."""
    exact = await ers_list(
        app, "networkdevice", filters=[f"ipaddress.EQ.{ip}"], limit=10, offset=0, detail=True
    )
    if exact.items:
        return list(exact.items)
    addr = ipaddress.ip_address(ip)
    nads, _ = await all_nads(app)
    hits = []
    for nad in nads:
        nets = [n for n in nad_networks(nad) if addr.version == n.version and addr in n]
        if nets:
            hits.append((max(n.prefixlen for n in nets), nad))
    hits.sort(key=lambda h: -h[0])
    return [h[1] for h in hits]


async def resolve_nad(app: IseApp, key: str, *, fuzzy: bool = False) -> dict[str, Any]:
    key = key.strip()
    if ip := parse_ip(key):
        nads = await find_nads_for_ip(app, ip)
        if not nads:
            raise NotFound(
                f"No network device covers {ip}. RADIUS from it fails with 11007; add it with "
                "ise_create_nad.",
                404,
            )
        return nads[0]
    return await ers_resolve(
        app, "networkdevice", key, what="network device", list_tool="ise_list_nads", fuzzy=fuzzy
    )


def unmask_flags(nad: dict[str, Any]) -> dict[str, Any]:
    """Expose enableMultiSecret (a "true"/"false" string) as a real boolean."""
    auth = nad.get("authenticationSettings")
    if isinstance(auth, dict) and "enableMultiSecret" in auth:
        auth["multiSecretEnabled"] = str(auth.pop("enableMultiSecret")).lower() == "true"
    return nad


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List network devices (NADs)")
    async def ise_list_nads(
        ctx: Context,
        name: Annotated[str | None, Field(description="Filter: name contains")] = None,
        ip: Annotated[
            str | None,
            Field(description="Filter: exact IP entry on the device (use ise_get_nad for subnet lookups)"),
        ] = None,
        group: Annotated[
            str | None,
            Field(description="Filter: device group (location or device type) contains, e.g. 'Sydney'"),
        ] = None,
        detail: Annotated[
            bool, Field(description="Fetch each device for IPs, groups and secrets set (pages up to 100)")
        ] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List network access devices (switches, WLCs, VPN headends) that ISE accepts RADIUS/TACACS+
        from: name, IPs/subnets, device groups (NDGs), whether RADIUS/TACACS secrets and SNMP/TrustSec
        are configured (never the secret values). Use ise_get_nad for one device in full."""
        app: IseApp = get_client(ctx)
        filters = []
        if name:
            filters.append(f"name.CONTAINS.{name}")
        if ip:
            filters.append(f"ipaddress.EQ.{ip}")
        if group:
            filters.append(f"location.CONTAINS.{group}")
        page = await ers_list(
            app,
            "networkdevice",
            filters=filters,
            limit=limit,
            offset=offset,
            detail=detail,
            shape=nad_summary,
        )
        if group and not page.items:
            # The location filter misses device-type groups; retry on type.
            filters[-1] = f"type.CONTAINS.{group}"
            page = await ers_list(
                app,
                "networkdevice",
                filters=filters,
                limit=limit,
                offset=offset,
                detail=detail,
                shape=nad_summary,
            )
        return list_result(page, fmt=response_format, columns=NAD_COLUMNS if detail else None)

    @reg.read(title="Get a network device")
    async def ise_get_nad(
        ctx: Context,
        device: Annotated[
            str,
            Field(
                description="NAD name, id, or an IP address (finds the device whose IP list/subnet covers it)"
            ),
        ],
    ) -> ToolResult:
        """Full configuration of one network device: IPs/subnets, device groups, device profile, RADIUS
        settings (KeyWrap, DTLS, CoA port), TACACS+, SNMP and TrustSec settings. Shared secrets and SNMP
        communities are always masked. Give an IP to answer 'which NAD does this switch match?'."""
        app: IseApp = get_client(ctx)
        return object_result(unmask_flags(await resolve_nad(app, device, fuzzy=True)))

    @reg.read(title="List network device groups")
    async def ise_list_ndgs(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="Filter: group path contains, e.g. 'Location' or 'Sydney'")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List network device groups (NDGs) as full paths like 'Location#All Locations#Sydney' or
        'Device Type#All Device Types#Switch'. These paths are what NADs and policy conditions use."""
        app: IseApp = get_client(ctx)
        filters = [f"name.CONTAINS.{name}"] if name else None
        page = await ers_list(app, "networkdevicegroup", filters=filters, limit=limit, offset=offset)
        return list_result(page, fmt=response_format, columns=["name", "description", "id"])

    @reg.read(title="Audit network devices")
    async def ise_audit_nads(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """Audit every network device for common misconfigurations: no RADIUS or TACACS+ secret, short
        shared secrets, the same secret reused on many devices, only the default device groups (so
        policy can't tell them apart), overlapping IP ranges, well-known SNMP communities, and KeyWrap
        without keys. Returns one row per device with findings (secret values are never shown)."""
        app: IseApp = get_client(ctx)
        nads, complete = await all_nads(app)
        secret_users: dict[str, list[str]] = {}
        for nad in nads:
            secret = (nad.get("authenticationSettings") or {}).get("radiusSharedSecret")
            if secret:
                digest = hashlib.sha256(str(secret).encode()).hexdigest()
                secret_users.setdefault(digest, []).append(str(nad.get("name")))
        nets = [(str(n.get("name")), net) for n in nads for net in nad_networks(n)]
        rows = []
        for nad in nads:
            name = str(nad.get("name"))
            auth = nad.get("authenticationSettings") or {}
            findings: list[str] = []
            secret = auth.get("radiusSharedSecret")
            tacacs = (nad.get("tacacsSettings") or {}).get("sharedSecret")
            if not secret and not tacacs:
                findings.append("no RADIUS or TACACS+ shared secret: ISE can't authenticate anything from it")
            if secret and len(str(secret)) < 12:
                findings.append(f"RADIUS shared secret is short ({len(str(secret))} chars; use 16+)")
            if secret:
                shared = secret_users[hashlib.sha256(str(secret).encode()).hexdigest()]
                if len(shared) > 1:
                    others = [s for s in shared if s != name]
                    findings.append(
                        f"RADIUS secret reused on {len(others)} other device(s): {', '.join(others[:5])}"
                    )
            groups = set(nad.get("NetworkDeviceGroupList") or [])
            if groups and groups <= DEFAULT_NDGS | {"IPSEC#Is IPSEC Device", "IPSEC#Is IPSEC Device#No"}:
                findings.append("only default device groups (no location/type): policy can't distinguish it")
            for other, onet in nets:
                if other == name:
                    continue
                for net in nad_networks(nad):
                    if net.version == onet.version and net.overlaps(onet):
                        findings.append(f"IP range {net} overlaps {other} ({onet})")
            snmp = nad.get("snmpsettings") or {}
            for key in ("roCommunity", "rwCommunity"):
                if str(snmp.get(key) or "").lower() in WEAK_COMMUNITIES:
                    findings.append(f"SNMP {key} is a well-known default community")
            if auth.get("enableKeyWrap") and not auth.get("keyEncryptionKey"):
                findings.append("KeyWrap enabled without a key-encryption key")
            rows.append({"name": name, "ips": nad_ips(nad), "findings": findings or ["ok"]})
        rows.sort(key=lambda r: r["findings"] == ["ok"])
        extra: dict[str, Any] = {
            "devices": len(nads),
            "with_findings": sum(1 for r in rows if r["findings"] != ["ok"]),
        }
        if not complete:
            extra["note"] = "More than 1000 devices: only the first 1000 were audited."
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            extra=extra,
            columns=["name", "ips", "findings"],
        )


async def nad_name_or_none(app: IseApp, key: str) -> dict[str, Any] | None:
    try:
        return await resolve_nad(app, key)
    except NotFound:
        return None
    except InvalidRequest:
        return None

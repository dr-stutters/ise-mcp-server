"""Network access devices (NADs), network device groups (NDGs) and a NAD audit (ERS)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import hashlib
import ipaddress
import time
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from ise_mcp._core import (
    InvalidRequest,
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
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


EXPECTED_MAX = 2000


class ExpectedNad(BaseModel):
    """One device an inventory says should be a NAD; a catc_list_devices row works as it is
    (hostname, managementIpAddress)."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    name: str = Field(
        validation_alias=AliasChoices("name", "hostname"), description="Device name in the inventory"
    )
    ip: str = Field(
        validation_alias=AliasChoices("ip", "managementIpAddress", "management_ip"),
        description="The IP its RADIUS/TACACS+ comes from (usually the management IP)",
    )
    ndg: str | list[str] | None = Field(
        default=None,
        description="Device group(s) it should be in: a full path ('Location#All Locations#SYD') or the "
        "last part ('SYD')",
    )
    aaa_server: str | None = Field(
        default=None,
        description="The RADIUS server IP or name its running config points at, when known: checked "
        "against the ISE nodes",
    )


def short_name(name: str) -> str:
    return name.strip().lower().split(".")[0]


def in_group(groups: list[str], want: str) -> bool:
    """A NAD group path matches a full path or its last part(s), case-insensitively."""
    w = want.strip().lower()
    return any(g.lower() == w or g.lower().endswith("#" + w) for g in groups)


def covering(nads: list[dict[str, Any]], ip: str) -> list[tuple[int, dict[str, Any]]]:
    """(prefix length, NAD) for every NAD whose IP list covers `ip`, most specific first."""
    addr = ipaddress.ip_address(ip)
    hits = []
    for nad in nads:
        nets = [n for n in nad_networks(nad) if n.version == addr.version and addr in n]
        if nets:
            hits.append((max(n.prefixlen for n in nets), nad))
    hits.sort(key=lambda h: -h[0])
    return hits


def coverage_audit(
    nads: list[dict[str, Any]],
    expected: list[ExpectedNad],
    *,
    check_stale: bool,
    stale_within: str | None,
    ise_addresses: set[str] | None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Reconcile an inventory with the NADs. Devices are matched by IP (a NAD whose IP list or
    subnet covers the device's IP, most specific first), never by name: Catalyst Center reuses an
    existing NAD with another name. Returns the coverage section and {stale NAD name: finding}."""
    by_name: dict[str, list[dict[str, Any]]] = {}
    for nad in nads:
        by_name.setdefault(short_name(str(nad.get("name") or "")), []).append(nad)
    rows: list[dict[str, Any]] = []
    used: set[str] = set()
    counts = {"missing_nad": 0, "wrong_ndg": 0, "ip_mismatch": 0, "aaa_elsewhere": 0}
    renamed = 0
    for dev in expected:
        ip = str(ipaddress.ip_address(dev.ip.strip()))
        row: dict[str, Any] = {"device": dev.name, "ip": ip}
        findings: list[str] = []
        fix: list[str] = []
        hits = covering(nads, ip)
        twins = [n for n in by_name.get(short_name(dev.name), []) if n not in [h[1] for h in hits]]
        if hits:
            prefix, nad = hits[0]
            name = str(nad.get("name"))
            used.update(str(h[1].get("name")) for h in hits)
            row["nad"] = name
            row["match"] = "ip" if prefix in (32, 128) else f"subnet ({', '.join(nad_ips(nad))})"
            if short_name(name) != short_name(dev.name):
                row["nad_name_differs"] = True
                renamed += 1
            groups = [str(g) for g in nad.get("NetworkDeviceGroupList") or []]
            wanted = [dev.ndg] if isinstance(dev.ndg, str) else list(dev.ndg or [])
            missing_groups = [w for w in wanted if w.strip() and not in_group(groups, w)]
            if missing_groups:
                counts["wrong_ndg"] += 1
                findings.append(
                    f"wrong_ndg: NAD {name} is not in {', '.join(missing_groups)} (its groups: "
                    f"{', '.join(groups) or 'none'})"
                )
                fix.append(f"ise_update_nad(device={name!r}, groups=[...]) with the expected group paths")
        else:
            counts["missing_nad"] += 1
            findings.append(
                f"missing_nad: no NAD covers {ip}: ISE drops its RADIUS/TACACS+ silently (11007), so "
                "nobody behind it can authenticate"
            )
            fix.append(f"ise_create_nad(name={dev.name!r}, ips=['{ip}/32'], ...) or a bulk plan for many")
        for twin in twins:
            counts["ip_mismatch"] += 1
            used.add(str(twin.get("name")))
            findings.append(
                f"ip_mismatch: NAD {twin.get('name')} has the device's name but {', '.join(nad_ips(twin))}, "
                f"not {ip} (re-addressed device or a stale entry)"
            )
            fix.append(f"ise_update_nad(device={twin.get('name')!r}, ips=['{ip}/32']) if it is this device")
        if (
            dev.aaa_server
            and ise_addresses is not None
            and dev.aaa_server.strip().lower() not in ise_addresses
        ):
            counts["aaa_elsewhere"] += 1
            findings.append(
                f"aaa_elsewhere: its RADIUS server {dev.aaa_server} is not an ISE node "
                f"({', '.join(sorted(ise_addresses)) or 'none found'})"
            )
            fix.append("point the device's 'radius server' at an ISE PSN (template or catc site AAA)")
        row["findings"] = findings or ["ok"]
        if fix:
            row["fix"] = fix
        rows.append(row)
    stale: dict[str, str] = {}
    if check_stale:
        for nad in nads:
            name = str(nad.get("name"))
            groups = [str(g) for g in nad.get("NetworkDeviceGroupList") or []]
            if name in used or (stale_within and not in_group(groups, stale_within)):
                continue
            stale[name] = (
                f"stale_nad: not in the expected inventory ({', '.join(nad_ips(nad))}): a decommissioned "
                "device, or one the inventory doesn't manage"
            )
    rows.sort(key=lambda r: r["findings"] == ["ok"])
    ok = sum(1 for r in rows if r["findings"] == ["ok"])
    problems = {k: v for k, v in counts.items() if v}
    if stale:
        problems["stale_nad"] = len(stale)
    verdict = f"{len(expected) - counts['missing_nad']} of {len(expected)} expected device(s) are NADs in ISE"
    if renamed:
        verdict += f" (matched by IP; {renamed} under another NAD name)"
    checked = (
        "missing, stale, wrong-group or IP-mismatch" if check_stale else "missing, wrong-group or IP-mismatch"
    )
    verdict += (
        ": " + ", ".join(f"{v} {k}" for k, v in problems.items()) + "."
        if problems
        else f"; no {checked} findings."
    )
    if not check_stale:
        verdict += " Stale NADs not checked (check_stale=false)."

    section: dict[str, Any] = {
        "verdict": verdict,
        "expected": len(expected),
        "ok": ok,
        **problems,
        "devices": rows,
    }
    if stale:
        section["stale_nads"] = [
            {
                "nad": n,
                "finding": f,
                "fix": f"ise_get_auth_list(nad={n!r}) for recent traffic, then "
                "ise_delete_nad (dangerous) or add the device to the inventory",
            }
            for n, f in stale.items()
        ]
    if check_stale:
        section["stale_scope"] = f"NADs in {stale_within}" if stale_within else "every NAD"
    return section, stale


async def ise_node_addresses(app: IseApp) -> set[str] | None:
    """IPs, FQDNs and hostnames of the ISE nodes (lower case), or None when they can't be read."""
    try:
        nodes = (await app.openapi.get("/api/v1/deployment/node")).get("response") or []
    except (UpstreamError, NotFound):
        return None
    out: set[str] = set()
    for n in nodes:
        for key in ("ipAddress", "fqdn", "hostname"):
            if n.get(key):
                out.add(str(n[key]).lower())
        for ip in n.get("ipAddresses") or []:
            out.add(str(ip).lower())
    return out


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
        expected: Annotated[
            list[ExpectedNad] | None,
            Field(
                description="Inventory to reconcile with the NADs, e.g. the rows of "
                "catc_list_devices(site=...): {name, ip, ndg?, aaa_server?} (hostname / "
                "managementIpAddress also accepted). Adds missing_nad, stale_nad, wrong_ndg, ip_mismatch "
                "and aaa_elsewhere findings in `coverage`",
                max_length=EXPECTED_MAX,
            ),
        ] = None,
        check_stale: Annotated[
            bool,
            Field(
                description="With `expected`: report NADs that match no expected device (stale_nad). "
                "Turn off, or scope with stale_within, when `expected` is only part of the inventory"
            ),
        ] = True,
        stale_within: Annotated[
            str | None,
            Field(
                description="With `expected`: only NADs in this device group can be stale (a path or "
                "its last part, e.g. the site's location group)"
            ),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """Audit every network device for common misconfigurations: no RADIUS or TACACS+ secret, short
        shared secrets, the same secret reused on many devices, only the default device groups (so
        policy can't tell them apart), overlapping IP ranges, well-known SNMP communities, and KeyWrap
        without keys. Devices with a TACACS+ secret get a 'tacacs' column: secret set, single-connect
        mode, and the device-admin policy set their logins would select (a finding when only the default
        set, or none, matches; 'may_match_first' lists sets whose conditions depend on the user), plus a
        warning when no node runs the DeviceAdmin service. Returns one row per device with findings
        (secret values are never shown). With `expected` (an inventory such as catc_list_devices
        rows) it also reconciles coverage, matching devices to NADs by IP (Catalyst Center reuses an
        existing NAD under its own name): missing_nad (no NAD covers the device's IP: silent drops,
        11007), stale_nad (a NAD no expected device matches), wrong_ndg, ip_mismatch (a NAD with the
        device's name but another IP) and aaa_elsewhere (the device's RADIUS server is not an ISE
        node), each with the fix to preview."""
        from ise_mcp.tools.device_admin import tacacs_audit  # noqa: PLC0415 - device_admin imports this module

        app: IseApp = get_client(ctx)
        bad = [d.ip for d in expected or [] if parse_ip(d.ip) is None]
        if bad:
            raise InvalidRequest(f"Not IP addresses in `expected`: {', '.join(bad[:10])}")
        nads, complete = await all_nads(app)
        tac_rows, tac_general = await tacacs_audit(app, nads)
        coverage: dict[str, Any] | None = None
        stale: dict[str, str] = {}
        if expected is not None:
            needs_nodes = any(d.aaa_server for d in expected)
            coverage, stale = coverage_audit(
                nads,
                expected,
                check_stale=check_stale,
                stale_within=stale_within,
                ise_addresses=await ise_node_addresses(app) if needs_nodes else None,
            )
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
            row: dict[str, Any] = {"name": name, "ips": nad_ips(nad)}
            if name in tac_rows:
                tac = dict(tac_rows[name])
                findings += tac.pop("findings")
                row["tacacs"] = tac
            if name in stale:
                findings.append(stale[name])
            row["findings"] = findings or ["ok"]
            rows.append(row)
        rows.sort(key=lambda r: r["findings"] == ["ok"])
        extra: dict[str, Any] = {
            "devices": len(nads),
            "with_findings": sum(1 for r in rows if r["findings"] != ["ok"]),
        }
        if tac_rows:
            extra["tacacs"] = {
                "devices": len(tac_rows),
                "single_connect": sum(1 for t in tac_rows.values() if t["single_connect"] != "off"),
                "no_device_admin_policy_set": [
                    n
                    for n, t in tac_rows.items()
                    if any("device-admin policy set" in f for f in t["findings"])
                ],
                "findings": tac_general or None,
            }
        if coverage is not None:
            extra["coverage"] = coverage
        if not complete:
            extra["note"] = "More than 1000 devices: only the first 1000 were audited."
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            extra=extra,
            columns=["name", "ips", "tacacs", "findings"],
        )


async def nad_name_or_none(app: IseApp, key: str) -> dict[str, Any] | None:
    try:
        return await resolve_nad(app, key)
    except NotFound:
        return None
    except InvalidRequest:
        return None

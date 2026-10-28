"""TrustSec writes: static IP-SGT mappings, SXP connections and bindings, and the TrustSec CoA push
(ERS sgmapping / sxpconnections / sxplocalbindings, OpenAPI trustsec/coa/push).

ISE 3.x keeps one object per static mapping: ERS `sgmapping` (deploy target + SXP domains) and ERS
`sxplocalbindings` (the same id, seen as the SXP binding) are two views of it. SXP writes are slow on
ISE 3.5 (30-60 s), so they get a longer HTTP timeout.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import ipaddress
from typing import Annotated, Any, Literal

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
    compact,
    field_changes,
    get_client,
    preview_or_apply,
)
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list, ers_name_map, ers_resolve, is_uuid, list_result, parse_ip
from ise_mcp.tools.network import nad_ips, resolve_nad
from ise_mcp.tools.writes import fingerprint, put_body

SLOW_WRITE_TIMEOUT = 120.0
SXP_MODES = Literal["SPEAKER", "LISTENER", "BOTH"]
SXP_VERSIONS = Literal["VERSION_1", "VERSION_2", "VERSION_3", "VERSION_4"]
COA_TYPES = Literal["ALL", "ENV", "POLICY", "SGACL", "SGT"]


# --- TrustSec CoA push scope (#169) -----------------------------------------------------------------

MATRICES = "/api/v1/trustsec/matrix"
NAD_SCAN_CAP = 5000
SHOWN_DEVICES = 20
ONE_DEVICE_NOTE = (
    "ISE's push API has no per-device scope. To refresh one device (a staged TrustSec change), run "
    "'cts refresh policy' on it (and 'show cts role-based permissions' to check)."
)


async def resolve_matrix(app: IseApp, key: str) -> dict[str, Any]:
    """A TrustSec policy matrix by id or name (GET /api/v1/trustsec/matrix)."""
    got = await app.openapi.get(MATRICES)
    rows = [m for m in (got.get("response") if isinstance(got, dict) else got) or [] if isinstance(m, dict)]
    k = key.strip()
    hits = [m for m in rows if k in (m.get("matrixUuId"), m.get("name"))] or [
        m for m in rows if str(m.get("name") or "").lower() == k.lower()
    ]
    if not hits:
        names = ", ".join(str(m.get("name")) for m in rows) or "none"
        raise NotFound(f"No TrustSec matrix {key!r} (matrices: {names})", 404)
    return hits[0]


def matrix_summary(m: dict[str, Any]) -> dict[str, Any]:
    return compact(  # type: ignore[no-any-return]
        {
            "name": m.get("name"),
            "id": m.get("matrixUuId"),
            "type": m.get("type"),
            "policy_type": m.get("matrixPolicyType"),
            "nads": m.get("noOfNads"),
            "nad_list": m.get("nadList"),
            "ndg_list": m.get("ndgList"),
        }
    )


def in_matrix(nads: list[dict[str, Any]], m: dict[str, Any]) -> list[dict[str, Any]]:
    """The TrustSec NADs a matrix holds: those named (or by id) in its nadList or inside one of its
    ndgList groups. A matrix with neither list (the PRODUCTION/default one) keeps them all."""
    names = {str(x).lower() for x in m.get("nadList") or []}
    groups = [str(g).lower() for g in m.get("ndgList") or []]
    if not names and not groups:
        return nads

    def member(n: dict[str, Any]) -> bool:
        if str(n.get("name") or "").lower() in names or str(n.get("id") or "").lower() in names:
            return True
        ndgs = [str(g).lower() for g in n.get("NetworkDeviceGroupList") or []]
        return any(d == g or d.startswith(g + "#") for g in groups for d in ndgs)

    return [n for n in nads if member(n)]


async def trustsec_nads(app: IseApp) -> tuple[list[dict[str, Any]] | None, bool, str | None]:
    """The NADs with TrustSec settings (ERS networkdevice trustsecsettings), whether the scan was
    complete, and why not when ERS could not be read."""
    try:
        page = await ers_list(
            app, "networkdevice", limit=NAD_SCAN_CAP, offset=0, detail=True, detail_cap=None
        )
    except UpstreamError as e:
        return None, False, f"ERS networkdevice: {e}"
    nads = [n for n in page.items if isinstance(n, dict) and n.get("trustsecsettings")]
    nads.sort(key=lambda n: str(n.get("name") or "").lower())
    return nads, page.complete, None


def push_on(n: dict[str, Any]) -> bool:
    """False only when the NAD's TrustSec settings say 'send configuration changes to device' is off."""
    updates = (n.get("trustsecsettings") or {}).get("sgaNotificationAndUpdates") or {}
    return updates.get("sendConfigurationToDevice") is not False


def nad_row(n: dict[str, Any]) -> dict[str, Any]:
    row = {"name": n.get("name"), "ips": nad_ips(n), "groups": n.get("NetworkDeviceGroupList")}
    return {k: v for k, v in row.items() if v}


def mapping_name(ip: str) -> str:
    """'10.1.2.3' or '10.1.2.0/24' -> ISE's mapping name/hostIp ('10.1.2.3/32', '10.1.2.0/24')."""
    try:
        net = ipaddress.ip_network(ip.strip(), strict=False)
    except ValueError as e:
        raise InvalidRequest(f"{ip!r} is not an IP address or CIDR (hostnames are not supported)") from e
    return f"{net.network_address}/{net.prefixlen}"


async def resolve_sgt(app: IseApp, key: str) -> dict[str, Any]:
    """An SGT by id, exact name or numeric tag value."""
    key = key.strip()
    if key.isdigit():
        page = await ers_list(app, "sgt", limit=5000, offset=0, detail=True, detail_cap=None)
        hits = [s for s in page.items if str(s.get("value")) == key]
        if not hits:
            raise NotFound(f"No SGT with value {key}; see ise_list_sgts.", 404)
        hit: dict[str, Any] = hits[0]
        return hit
    return await ers_resolve(app, "sgt", key, what="SGT", list_tool="ise_list_sgts")


async def list_sxp_domains(app: IseApp) -> list[str]:
    page = await ers_list(app, "sxpvpns", limit=1000, offset=0, detail=True, detail_cap=None)
    return [str(v.get("sxpVpnName")) for v in page.items if v.get("sxpVpnName")]


async def check_domains(app: IseApp, wanted: list[str]) -> list[str]:
    known = await list_sxp_domains(app)
    return [f"No SXP domain {d!r} (known: {', '.join(known) or 'none'})" for d in wanted if d not in known]


async def find_mapping(app: IseApp, name: str) -> dict[str, Any] | None:
    hit = await app.ers_find("sgmapping", name)
    return await app.ers_get("sgmapping", str(hit["id"])) if hit else None


async def resolve_mapping(app: IseApp, target: str) -> dict[str, Any]:
    if is_uuid(target):
        return await app.ers_get("sgmapping", target.strip())
    found = await find_mapping(app, mapping_name(target))
    if found is None:
        raise NotFound(f"No IP-SGT mapping for {target}; see ise_list_ip_sgt_mappings.", 404)
    return found


async def deploy_target(app: IseApp, deploy_to: str | None) -> tuple[str, str | None, str]:
    """(deployType, deployTo id, label) for 'all' / a NAD name or IP / an NDG full name."""
    if deploy_to is None or deploy_to.strip().lower() in ("", "all"):
        return "ALL", None, "all TrustSec devices"
    key = deploy_to.strip()
    if "#" in key:
        ndg = await ers_resolve(
            app, "networkdevicegroup", key, what="network device group", list_tool="ise_list_ndgs"
        )
        return "NDG", str(ndg["id"]), f"device group {ndg.get('name')}"
    nad = await resolve_nad(app, key)
    return "ND", str(nad["id"]), f"network device {nad.get('name')}"


def sxp_row(c: dict[str, Any]) -> dict[str, Any]:
    return {
        "peer_ip": c.get("ipAddress"),
        "peer_name": c.get("sxpPeer"),
        "peer_role": c.get("sxpMode"),
        "version": c.get("sxpVersion"),
        "domain": c.get("sxpVpn"),
        "ise_node": c.get("sxpNode"),
        "enabled": c.get("enabled"),
        "description": c.get("description"),
        "id": c.get("id"),
    }


def binding_row(b: dict[str, Any]) -> dict[str, Any]:
    return {
        "ip": b.get("ipAddressOrHost"),
        "sgt": b.get("sgt"),
        "domains": [d for d in str(b.get("sxpVpn") or "").split(",") if d],
        "virtual_networks": [v for v in str(b.get("vns") or "").split(",") if v],
        "id": b.get("id"),
    }


async def find_sxp_connection(app: IseApp, peer_ip: str, domain: str | None = None) -> list[dict[str, Any]]:
    page = await ers_list(app, "sxpconnections", limit=5000, offset=0, detail=True, detail_cap=None)
    return [
        c
        for c in page.items
        if c.get("ipAddress") == peer_ip and (domain is None or c.get("sxpVpn") == domain)
    ]


async def resolve_sxp_connection(app: IseApp, target: str) -> dict[str, Any]:
    if is_uuid(target):
        return await app.ers_get("sxpconnections", target.strip())
    ip = parse_ip(target)
    if ip is None:
        raise InvalidRequest("Give the SXP peer's IP address or the connection id")
    hits = await find_sxp_connection(app, ip)
    if not hits:
        raise NotFound(f"No SXP connection to {ip}; see ise_list_sxp_connections.", 404)
    if len(hits) > 1:
        raise InvalidRequest(
            f"{len(hits)} SXP connections to {ip} (one per domain/node): give the connection id"
        )
    return hits[0]


async def sxp_nodes(app: IseApp) -> tuple[dict[str, str], list[str]]:
    """({node hostname: IP}, nodes running the SXP service)."""
    nodes = (await app.openapi.get("/api/v1/deployment/node")).get("response") or []
    names = {str(n.get("hostname")): str(n.get("ipAddress")) for n in nodes}
    return names, [str(n.get("hostname")) for n in nodes if "SXP" in (n.get("services") or [])]


def register(reg: ToolRegistrar) -> None:  # noqa: C901 - one registration block per tool
    # --- reads -------------------------------------------------------------------------------

    @reg.read(title="List SXP connections")
    async def ise_list_sxp_connections(
        ctx: Context,
        peer_ip: Annotated[str | None, Field(description="Only connections to this peer IP")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List SXP (SGT Exchange Protocol) connections between ISE nodes and network devices: peer IP
        and name, the PEER's role (peer_role LISTENER = the device learns IP-SGT bindings from ISE;
        SPEAKER = ISE learns from the device), SXP version, domain, ISE node and whether it is enabled.
        ISE has no API for the live connection state: check it on the device ('show cts sxp
        connections brief')."""
        app: IseApp = get_client(ctx)
        page = await ers_list(
            app, "sxpconnections", limit=5000, offset=0, detail=True, detail_cap=None, shape=sxp_row
        )
        rows = [r for r in page.items if not peer_ip or r["peer_ip"] == peer_ip.strip()]
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["peer_ip", "peer_name", "peer_role", "version", "domain", "ise_node", "enabled"],
        )

    @reg.read(title="List SXP bindings")
    async def ise_list_sxp_bindings(
        ctx: Context,
        domain: Annotated[str | None, Field(description="Only bindings sent to this SXP domain")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the IP-SGT bindings ISE advertises over SXP (static mappings sent to an SXP domain):
        IP or subnet, SGT and the SXP domains / virtual networks. Every SXP speaker connection in a
        domain advertises that domain's bindings. Session-learned bindings are not included."""
        app: IseApp = get_client(ctx)
        page = await ers_list(
            app, "sxplocalbindings", limit=5000, offset=0, detail=True, detail_cap=None, shape=binding_row
        )
        rows = [r for r in page.items if not domain or domain in r["domains"]]
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["ip", "sgt", "domains", "virtual_networks", "id"],
            extra={"sxp_domains": await list_sxp_domains(app)},
        )

    # --- writes ------------------------------------------------------------------------------

    @reg.write(title="Create or update a static IP-SGT mapping")
    async def ise_set_ip_sgt(
        ctx: Context,
        ip: Annotated[str, Field(description="Host IP or subnet in CIDR form, e.g. 10.1.2.3 or 10.1.2.0/24")],
        sgt: Annotated[str, Field(description="SGT name, numeric value or id (see ise_list_sgts)")],
        sxp_domains: Annotated[
            list[str] | None,
            Field(
                description="SXP domains to advertise the binding in, e.g. ['default'] (see "
                "ise_list_sxp_bindings); [] stops advertising; omit to keep the current setting"
            ),
        ] = None,
        deploy_to: Annotated[
            str | None,
            Field(
                description="Where 'deploy' pushes it: 'all' (default), a network device name/IP, or a "
                "device group full name ('Location#All Locations#HQ')"
            ),
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Map a host or subnet to a security group tag, the way servers and other non-802.1X hosts get
        into TrustSec policy. Devices learn it over SXP when the mapping is sent to an SXP domain with a
        speaker connection (ise_set_sxp_connection), or by an SSH deploy (ise_deploy_ip_sgt). Creates the
        mapping or updates the one for the same IP/subnet. Preview-first."""
        app: IseApp = get_client(ctx)
        name = mapping_name(ip)
        tag = await resolve_sgt(app, sgt)
        domains = sxp_domains
        blockers = await check_domains(app, domains or [])
        args = {
            "ip": ip,
            "sgt": sgt,
            "sxp_domains": sxp_domains,
            "deploy_to": deploy_to,
            "description": description,
        }
        current = await find_mapping(app, name)
        desired: dict[str, Any] = dict(current) if current else {"name": name, "hostIp": name}
        desired["sgt"] = str(tag["id"])
        if deploy_to is None and current:
            # Omitted on an update: keep the current deploy target.
            dlabel = (
                "all TrustSec devices"
                if current.get("deployType") == "ALL"
                else f"{current.get('deployType')} {current.get('deployTo')}"
            )
        else:
            dtype, dto, dlabel = await deploy_target(app, deploy_to)
            desired["deployType"] = dtype
            if dto:
                desired["deployTo"] = dto
            else:
                desired.pop("deployTo", None)
        if domains is not None:
            desired["sgtDomain"] = list(domains)
        if description is not None:
            desired["description"] = description
        shown = {
            "mapping": name,
            "sgt": f"{tag.get('name')} ({tag.get('value')})",
            "deploy_to": dlabel,
            "sxp_domains": desired.get("sgtDomain") or [],
        }
        side = []
        if desired.get("sgtDomain"):
            side.append(
                f"SXP speakers in {', '.join(desired['sgtDomain'])} advertise it to their listeners at once"
            )
        side.append("Devices without SXP only get it after ise_deploy_ip_sgt")
        if current:
            changes = field_changes(current, desired, replace=True)
            if "sgt" in changes:
                names = await ers_name_map(app, "sgt")
                changes["sgt"] = {k: names.get(str(v), v) for k, v in changes["sgt"].items()}
            if not changes:
                blockers.append(f"Nothing changes: {name} already maps to {shown['sgt']}")
            plan = Plan(
                f"Update IP-SGT mapping {name}",
                details={**shown, "changes": changes},
                fingerprint=fingerprint(current),
                blockers=blockers,
                side_effects=side,
            )

            async def update() -> Any:
                body = {"SGMapping": put_body(desired)}
                return await app.ers_request(
                    "PUT", f"/ers/config/sgmapping/{current['id']}", json=body, timeout=SLOW_WRITE_TIMEOUT
                )

            return await preview_or_apply(
                ctx, tool="ise_set_ip_sgt", args=args, confirm=confirm, plan=plan, apply=update
            )
        plan = Plan(
            f"Create IP-SGT mapping {name}",
            details=shown,
            fingerprint=fingerprint({"absent": name}),
            blockers=blockers,
            side_effects=side,
        )

        async def create() -> Any:
            if await find_mapping(app, name) is not None:
                raise InvalidRequest(f"A mapping for {name} appeared since the preview; preview again")
            return await app.ers_create("sgmapping", {"SGMapping": desired}, timeout=SLOW_WRITE_TIMEOUT)

        return await preview_or_apply(
            ctx,
            tool="ise_set_ip_sgt",
            args=args,
            confirm=confirm,
            plan=plan,
            apply=create,
        )

    @reg.write(title="Create or update an SXP connection")
    async def ise_set_sxp_connection(
        ctx: Context,
        peer_ip: Annotated[str, Field(description="The network device's SXP source IP")],
        peer_role: Annotated[
            SXP_MODES,
            Field(
                description="The DEVICE's role (ISE's 'Peer Role'): LISTENER (the device learns bindings "
                "from ISE, the usual case), SPEAKER (ISE learns bindings from the device) or BOTH"
            ),
        ] = "LISTENER",
        peer_name: Annotated[str | None, Field(description="Peer label in ISE; default: the peer IP")] = None,
        domain: Annotated[str, Field(description="SXP domain (see ise_list_sxp_bindings)")] = "default",
        node: Annotated[
            str | None, Field(description="ISE node running SXP; optional when only one node runs it")
        ] = None,
        version: Annotated[SXP_VERSIONS, Field(description="Highest SXP version to use")] = "VERSION_4",
        enabled: Annotated[bool, Field(description="Enable the connection")] = True,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an SXP connection between an ISE node and a network device, or change the existing one
        for the same peer and domain. ISE uses the global SXP password setting (none by default); the
        device must be configured to match, e.g. 'cts sxp connection peer <ISE IP> source <peer_ip>
        password none mode local listener' for peer_role LISTENER (a role mismatch shows as 'Conn_mode
        mismatch' in 'debug cts sxp error'). The node needs the SXP service
        (ise_update_node_services). Preview-first."""
        app: IseApp = get_client(ctx)
        ip = parse_ip(peer_ip)
        if ip is None:
            raise InvalidRequest(f"{peer_ip!r} is not an IP address")
        names, with_sxp = await sxp_nodes(app)
        blockers = await check_domains(app, [domain])
        if node is None:
            if len(with_sxp) == 1:
                hostname = with_sxp[0]
            elif not with_sxp:
                hostname = next(iter(names)) if len(names) == 1 else ""
                blockers.append(
                    "No ISE node runs the SXP service: enable it with ise_update_node_services enable=['SXP']"
                )
            else:
                raise InvalidRequest(f"Several nodes run SXP ({', '.join(with_sxp)}): give `node`")
        else:
            match = [n for n in names if n.lower() == node.strip().lower()]
            if not match:
                raise NotFound(f"No ISE node {node!r}; see ise_list_nodes", 404)
            hostname = match[0]
            if hostname not in with_sxp:
                blockers.append(
                    f"Node {hostname} doesn't run the SXP service: enable it with ise_update_node_services"
                )
        args = {
            "peer_ip": peer_ip,
            "peer_role": peer_role,
            "peer_name": peer_name,
            "domain": domain,
            "node": node,
            "version": version,
            "enabled": enabled,
            "description": description,
        }
        existing = await find_sxp_connection(app, ip, domain)
        current = existing[0] if existing else None
        desired: dict[str, Any] = dict(current) if current else {}
        desired.update(
            {
                "ipAddress": ip,
                "sxpPeer": peer_name or (current or {}).get("sxpPeer") or ip,
                "sxpVpn": domain,
                "sxpNode": hostname,
                "sxpMode": peer_role,
                "sxpVersion": version,
                "enabled": enabled,
            }
        )
        if not current:
            desired["name"] = desired["sxpPeer"]
        if description is not None:
            desired["description"] = description
        device_mode = peer_role.lower()
        details = {
            **sxp_row(desired),
            "device_side": f"cts sxp connection peer {names.get(hostname, '<ISE node IP>')} source {ip} "
            f"password none mode local {device_mode}",
            "password_note": "'password none' matches ISE's default global SXP password (none); if a "
            "global SXP password is set in ISE, use 'password default' with the same password",
        }
        if current:
            changes = field_changes(current, desired, replace=True)
            if not changes:
                blockers.append(f"Nothing changes: the SXP connection to {ip} is already set like this")
            plan = Plan(
                f"Update SXP connection to {ip} ({domain})",
                details={**details, "changes": changes},
                fingerprint=fingerprint(current),
                blockers=blockers,
                side_effects=["The SXP session to the peer restarts"],
            )

            async def update() -> Any:
                body = {"ERSSxpConnection": put_body(desired)}
                return await app.ers_request(
                    "PUT",
                    f"/ers/config/sxpconnections/{current['id']}",
                    json=body,
                    timeout=SLOW_WRITE_TIMEOUT,
                )

            return await preview_or_apply(
                ctx, tool="ise_set_sxp_connection", args=args, confirm=confirm, plan=plan, apply=update
            )
        plan = Plan(f"Create SXP connection to {ip} ({domain})", details=details, blockers=blockers)

        async def create_conn() -> Any:
            if await find_sxp_connection(app, ip, domain):
                raise InvalidRequest(f"An SXP connection to {ip} appeared since the preview; preview again")
            return await app.ers_create(
                "sxpconnections", {"ERSSxpConnection": desired}, timeout=SLOW_WRITE_TIMEOUT
            )

        return await preview_or_apply(
            ctx,
            tool="ise_set_sxp_connection",
            args=args,
            confirm=confirm,
            plan=plan,
            apply=create_conn,
        )

    @reg.write(title="Delete an IP-SGT mapping or SXP connection", destructive=True)
    async def ise_delete_trustsec_object(
        ctx: Context,
        kind: Annotated[
            Literal["ip_sgt", "sxp_connection"], Field(description="IP-SGT mapping or SXP connection")
        ],
        target: Annotated[
            str, Field(description="ip_sgt: the IP/CIDR or id; sxp_connection: the peer IP or id")
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a static IP-SGT mapping (SXP listeners withdraw it; devices it was deployed to keep it
        until the next deploy) or an SXP connection (the session to the device goes down).
        Preview-first."""
        app: IseApp = get_client(ctx)
        if kind == "ip_sgt":
            current = await resolve_mapping(app, target)
            resource, label = "sgmapping", f"IP-SGT mapping {current.get('name')}"
            side = ["SXP listeners withdraw the binding"] if current.get("sgtDomain") else []
        else:
            current = await resolve_sxp_connection(app, target)
            resource, label = "sxpconnections", f"SXP connection to {current.get('ipAddress')}"
            side = ["The SXP session to the device goes down"]
        plan = Plan(
            f"Delete {label}", details=compact(current), fingerprint=fingerprint(current), side_effects=side
        )
        return await preview_or_apply(
            ctx,
            tool="ise_delete_trustsec_object",
            args={"kind": kind, "target": target},
            confirm=confirm,
            plan=plan,
            apply=lambda: app.ers_request(
                "DELETE", f"/ers/config/{resource}/{current['id']}", timeout=SLOW_WRITE_TIMEOUT
            ),
        )

    # --- dangerous ----------------------------------------------------------------------------

    @reg.dangerous(title="Push TrustSec policy to devices (CoA)")
    async def ise_push_trustsec_matrix(
        ctx: Context,
        coa_type: Annotated[
            COA_TYPES,
            Field(
                description="What devices refresh: POLICY (egress matrix/SGACLs, default), SGACL, SGT, "
                "ENV (environment data) or ALL"
            ),
        ] = "POLICY",
        matrix: Annotated[
            str | None,
            Field(
                description="Matrix name or id (GET /api/v1/trustsec/matrix) when ISE has several "
                "(multiple matrices / DEFCON); omit for ISE's default"
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Send a TrustSec CoA to every TrustSec network device so it downloads the current egress
        matrix / SGACLs / SGTs now instead of at its refresh timer: the 'Push' button in the ISE GUI.
        Only devices with TrustSec (CTS) settings and 'send configuration changes to device' on take part;
        the preview lists them (count, then the first few by name, IP and device group) as the blast
        radius, and names TrustSec devices the push skips. The API has no per-device push
        (COAPushRequest takes only coaType and matrixId): to refresh ONE device, as a staged TrustSec
        change starts, run 'cts refresh policy' on that device instead. Verify on a device with 'show cts
        role-based permissions'. Preview-first."""
        app: IseApp = get_client(ctx)
        body: dict[str, Any] = {"coaType": coa_type}
        details: dict[str, Any] = {"coaType": coa_type}
        matrix_row: dict[str, Any] | None = None
        if matrix:
            matrix_row = await resolve_matrix(app, matrix)
            body["matrixId"] = matrix_row["matrixUuId"]
            details["matrix"] = matrix_summary(matrix_row)
        devices, complete, why = await trustsec_nads(app)
        if devices is not None and matrix_row is not None:
            devices = in_matrix(devices, matrix_row)
        if devices is not None:
            # ISE sends the CoA only to NADs with 'send configuration changes to device' on.
            skipped = [n for n in devices if not push_on(n)]
            devices = [n for n in devices if push_on(n)]
            if skipped:
                details["trustsec_without_push"] = {
                    "count": len(skipped),
                    "names": [str(n.get("name")) for n in skipped[:SHOWN_DEVICES]],
                    "note": "TrustSec NADs with 'send configuration changes to device' off: ISE's push "
                    "skips them (ise_update_nad trustsec_push=true); they refresh on their own timer",
                }
        blast: dict[str, Any]
        if devices is None or not complete:
            reason = why or f"ISE listed more than {NAD_SCAN_CAP} network devices"
            blast = {"blast_unknown": f"the TrustSec devices could not all be listed: {reason}"}
            if devices:
                details["trustsec_devices_seen"] = len(devices)
        else:
            blast = {"blast_radius": len(devices)}
            details["trustsec_devices"] = len(devices)
        if devices:
            details["devices"] = [nad_row(n) for n in devices[:SHOWN_DEVICES]]
            if len(devices) > SHOWN_DEVICES:
                details["devices_not_shown"] = len(devices) - SHOWN_DEVICES
        details["one_device_instead"] = ONE_DEVICE_NOTE
        target = f"matrix {matrix_row.get('name')}" if matrix_row else "all TrustSec devices"
        count = f" ({len(devices)} devices)" if devices is not None and complete else ""
        plan = Plan(
            f"TrustSec CoA push ({coa_type}) to {target}{count}",
            details=details,
            side_effects=[
                "Every listed TrustSec device re-downloads policy; changed SGACLs take effect on all of "
                "them at once (ISE has no per-device push)"
            ],
            **blast,
        )
        return await preview_or_apply(
            ctx,
            tool="ise_push_trustsec_matrix",
            args={"coa_type": coa_type, "matrix": matrix},
            confirm=confirm,
            plan=plan,
            apply=lambda: app.openapi.put("/api/v1/trustsec/coa/push", json=body),
        )

    @reg.dangerous(title="Deploy IP-SGT mappings to devices (SSH)")
    async def ise_deploy_ip_sgt(
        ctx: Context,
        ip: Annotated[
            str | None, Field(description="Deploy only this mapping (IP/CIDR or id); omit for all")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Push static IP-SGT mappings to their target devices: ISE logs in over SSH with the device
        configuration deployment credentials in each NAD's TrustSec settings and adds 'cts role-based
        sgt-map' lines. Devices that learn mappings over SXP don't need this. Preview-first; the result
        includes ISE's deploy status."""
        app: IseApp = get_client(ctx)
        if ip:
            current = await resolve_mapping(app, ip)
            path = f"/ers/config/sgmapping/{current['id']}/deploy"
            summary = f"Deploy IP-SGT mapping {current.get('name')}"
            details: dict[str, Any] = compact(current)
            state: Any = current
        else:
            path = "/ers/config/sgmapping/deploy/all"
            summary = "Deploy all IP-SGT mappings"
            page = await ers_list(app, "sgmapping", limit=5000, offset=0, detail=True, detail_cap=None)
            state = sorted(page.items, key=lambda m: str(m.get("id")))
            details = {
                "mappings": (await app.ers_pager.fetch_page(app.ers, "/ers/config/sgmapping", limit=1)).total
            }

        async def apply() -> Any:
            out = await app.ers_request("PUT", path, timeout=SLOW_WRITE_TIMEOUT)
            status = await app.ers_request("GET", "/ers/config/sgmapping/deploy/status")
            return {
                "deploy": out,
                "status_at_call_time": status,
                "note": "The deploy runs on: re-check GET /ers/config/sgmapping/deploy/status with "
                "ise_api_call until CompleteCount equals DeviceCount",
            }

        plan = Plan(
            summary,
            details=details,
            fingerprint=fingerprint(state),
            side_effects=["ISE opens SSH sessions to the target devices and changes their running config"],
        )
        return await preview_or_apply(
            ctx, tool="ise_deploy_ip_sgt", args={"ip": ip}, confirm=confirm, plan=plan, apply=apply
        )

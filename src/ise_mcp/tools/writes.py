"""Write-tier tools (MCP_ENABLE_WRITES): preview-first create/update for NADs, endpoints, users,
groups, authorization profiles, dACLs, SGTs, the egress matrix, ANC policies and authorization rules.

Every tool returns a preview + confirm token first; nothing changes until the identical call is
repeated with `confirm`. Secrets passed in (RADIUS/TACACS secrets, SNMP communities, passwords) are
never echoed: previews show only whether they are set.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import hashlib
import ipaddress
import json
import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from ise_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    compact,
    field_changes,
    get_client,
    preview_or_apply,
)
from ise_mcp._core.formatting import MASK, is_secret_key, mask_secrets
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_name_map, ers_resolve, is_uuid, normalize_mac
from ise_mcp.tools.endpoint_bulk import check_custom_values, custom_attribute_defs
from ise_mcp.tools.network import resolve_nad
from ise_mcp.tools.policy import rules_using_profile

# --- helpers ------------------------------------------------------------------------------------


def fingerprint(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def masked_changes(
    current: dict[str, Any], desired: dict[str, Any], *, replace: bool = False
) -> dict[str, Any]:
    """field_changes() with secret fields reduced to 'changed' (and removals still flagged)."""
    out: dict[str, Any] = {}
    for key, change in field_changes(current, desired, replace=replace).items():
        if is_secret_key(key.rsplit(".", 1)[-1]):
            out[key] = {"from": MASK if change["from"] else None, "to": MASK if change["to"] else None}
            if change.get("removed"):
                out[key]["removed"] = True
        else:
            # A removed (or replaced) nested object may hold secrets: mask inside it too.
            out[key] = {k: mask_secrets(v) if k in ("from", "to") else v for k, v in change.items()}
    return out


def put_body(obj: dict[str, Any]) -> dict[str, Any]:
    """An ERS object as returned by GET, minus read-only bits, ready for PUT."""
    return {k: v for k, v in obj.items() if k != "link"}


def deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def parse_ip_entries(ips: list[str]) -> list[dict[str, Any]]:
    entries = []
    for raw in ips:
        try:
            net = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError as e:
            raise InvalidRequest(f"{raw!r} is not an IP address or CIDR") from e
        entries.append({"ipaddress": str(net.network_address), "mask": net.prefixlen})
    return entries


async def ers_put(app: IseApp, resource: str, wrapper: str, obj: dict[str, Any]) -> Any:
    app.__dict__.pop("_nad_cache", None)
    return await app.ers_request("PUT", f"/ers/config/{resource}/{obj['id']}", json={wrapper: put_body(obj)})


async def ers_post(app: IseApp, resource: str, wrapper: str, body: dict[str, Any]) -> dict[str, Any]:
    app.__dict__.pop("_nad_cache", None)
    return await app.ers_create(resource, {wrapper: body})


async def group_ids(app: IseApp, resource: str, names: list[str], what: str, list_tool: str) -> list[str]:
    known = await ers_name_map(app, resource)
    by_name = {v.lower(): k for k, v in known.items()}
    ids = []
    for n in names:
        if is_uuid(n) and n in known:
            ids.append(n)
        elif n.lower() in by_name:
            ids.append(by_name[n.lower()])
        else:
            raise NotFound(f"No {what} named {n!r}; see {list_tool}.", 404)
    return ids


async def exists(app: IseApp, resource: str, name: str) -> bool:
    return await app.ers_find(resource, name) is not None


async def references(app: IseApp, kind: str, obj: dict[str, Any]) -> list[str]:
    """Blockers for deleting an object that other objects still point at."""
    name, oid = str(obj.get("name")), str(obj.get("id"))

    async def ers_count(resource: str, filt: str) -> int:
        page = await app.ers_pager.fetch_page(app.ers, f"/ers/config/{resource}", {"filter": filt}, limit=1)
        return page.total or len(page.items)

    if kind == "identity_group" and (n := await ers_count("internaluser", f"identityGroup.EQ.{name}")):
        return [f"{n} internal user(s) are in this group"]
    if kind == "endpoint_group":
        eps = await app.openapi.get("/api/v1/endpoint", {"filter": f"groupId.EQ.{oid}", "page": 1, "size": 1})
        if eps:
            return ["Endpoints are still in this group (see ise_list_endpoints group=...)"]
    if kind == "ndg":
        field = "location" if name.startswith("Location#") else "type"
        if name.startswith(("Location#", "Device Type#")) and (
            n := await ers_count("networkdevice", f"{field}.EQ.{name}")
        ):
            return [f"{n} network device(s) are in this group"]
    if kind == "tacacs_server":
        page = await app.ers_pager.fetch_page(app.ers, "/ers/config/tacacsserversequence", limit=500)
        for item in page.items:
            seq = await app.ers_get("tacacsserversequence", str(item["id"]))
            listed = [x.strip().lower() for x in str(seq.get("serverList") or "").split(",")]
            if name.lower() in listed:
                return [f"Listed in TACACS+ server sequence {seq.get('name')}"]
    if kind == "sgt":
        out = []
        for filt in (f"sgtSrcName.EQ.{name}", f"sgtDstName.EQ.{name}"):
            if n := await ers_count("egressmatrixcell", filt):
                out.append(f"{n} egress matrix cell(s) use this SGT")
        return out
    return []


DELETE_KINDS = {
    "endpoint": "endpoint",
    "internal_user": "internaluser",
    "identity_group": "identitygroup",
    "endpoint_group": "endpointgroup",
    "authz_profile": "authorizationprofile",
    "dacl": "downloadableacl",
    "sgt": "sgt",
    "sgacl": "sgacl",
    "ndg": "networkdevicegroup",
    "anc_policy": "ancpolicy",
    "command_set": "tacacscommandsets",
    "shell_profile": "tacacsprofile",
    "ad_join_point": "activedirectory",
    "tacacs_server": "tacacsexternalservers",
    "tacacs_sequence": "tacacsserversequence",
    "sponsor_group": "sponsorgroup",
    "guest_type": "guesttype",
}

ACCESS = {"accept": "ACCESS_ACCEPT", "reject": "ACCESS_REJECT"}


def register(reg: ToolRegistrar) -> None:  # noqa: C901 - one registration block per tool
    # --- NADs ----------------------------------------------------------------------------------

    @reg.write(title="Create network device")
    async def ise_create_nad(
        ctx: Context,
        name: Annotated[str, Field(description="Device name, e.g. 'syd-access-sw01'")],
        ips: Annotated[list[str], Field(description="IP addresses or CIDR ranges RADIUS/TACACS+ comes from")],
        radius_secret: Annotated[
            str | None, Field(description="RADIUS shared secret (never echoed back)")
        ] = None,
        tacacs_secret: Annotated[
            str | None, Field(description="TACACS+ shared secret (never echoed back)")
        ] = None,
        groups: Annotated[
            list[str] | None,
            Field(
                description="Device group paths, e.g. ['Location#All Locations#Sydney', "
                "'Device Type#All Device Types#Switch'] (see ise_list_ndgs)"
            ),
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        profile: Annotated[str, Field(description="Network device profile (vendor), e.g. Cisco")] = "Cisco",
        coa_port: Annotated[int, Field(ge=1, le=65535, description="RADIUS CoA port on the device")] = 1700,
        snmp_ro_community: Annotated[
            str | None, Field(description="SNMP v2c read community for profiling (never echoed back)")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a network access device (switch, WLC, VPN) so ISE accepts its RADIUS and/or TACACS+
        requests. Preview-first; secrets are never shown. Blocked if the name exists. Default device
        groups are used when `groups` is omitted (consider adding location/type groups)."""
        app: IseApp = get_client(ctx)
        if not radius_secret and not tacacs_secret:
            raise InvalidRequest("Give radius_secret and/or tacacs_secret; a NAD without either is useless")
        body: dict[str, Any] = {
            "name": name,
            "description": description or "",
            "profileName": profile,
            "coaPort": coa_port,
            "NetworkDeviceIPList": parse_ip_entries(ips),
            "NetworkDeviceGroupList": groups or ["Location#All Locations", "Device Type#All Device Types"],
        }
        if radius_secret:
            body["authenticationSettings"] = {
                "networkProtocol": "RADIUS",
                "radiusSharedSecret": radius_secret,
                "enableKeyWrap": False,
                "keyInputFormat": "ASCII",
            }
        if tacacs_secret:
            body["tacacsSettings"] = {"sharedSecret": tacacs_secret, "connectModeOptions": "OFF"}
        if snmp_ro_community:
            body["snmpsettings"] = {
                "version": "TWO_C",
                "roCommunity": snmp_ro_community,
                "pollingInterval": 3600,
                "linkTrapQuery": True,
                "macTrapQuery": True,
                "originatingPolicyServicesNode": "Auto",
            }
        blockers = (
            [f"A network device named {name!r} already exists"]
            if await exists(app, "networkdevice", name)
            else []
        )
        plan = Plan(f"Create network device {name}", details=compact(body), blockers=blockers)
        return await preview_or_apply(
            ctx,
            tool="ise_create_nad",
            args={
                "name": name,
                "ips": ips,
                "radius_secret": radius_secret,
                "tacacs_secret": tacacs_secret,
                "groups": groups,
                "description": description,
                "profile": profile,
                "coa_port": coa_port,
                "snmp_ro_community": snmp_ro_community,
            },
            confirm=confirm,
            plan=plan,
            apply=lambda: ers_post(app, "networkdevice", "NetworkDevice", body),
        )

    @reg.write(title="Update network device")
    async def ise_update_nad(
        ctx: Context,
        device: Annotated[str, Field(description="NAD name, id or IP (see ise_list_nads)")],
        ips: Annotated[list[str] | None, Field(description="Replace the IP/CIDR list")] = None,
        radius_secret: Annotated[str | None, Field(description="New RADIUS shared secret")] = None,
        tacacs_secret: Annotated[str | None, Field(description="New TACACS+ shared secret")] = None,
        groups: Annotated[list[str] | None, Field(description="Replace the device group paths")] = None,
        description: Annotated[str | None, Field(description="New description")] = None,
        coa_port: Annotated[int | None, Field(ge=1, le=65535, description="New CoA port")] = None,
        new_name: Annotated[str | None, Field(description="Rename the device")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a network device: IPs, shared secrets, device groups, description, CoA port or name.
        Only the given fields change. Preview-first, showing a field-by-field diff (secrets shown only
        as changed). Changing a secret breaks RADIUS until the device is updated to match."""
        app: IseApp = get_client(ctx)
        current = await resolve_nad(app, device)
        patch: dict[str, Any] = {}
        if ips is not None:
            patch["NetworkDeviceIPList"] = parse_ip_entries(ips)
        if radius_secret is not None:
            patch["authenticationSettings"] = {"radiusSharedSecret": radius_secret}
            patch["authenticationSettings"].setdefault("networkProtocol", "RADIUS")
        if tacacs_secret is not None:
            patch["tacacsSettings"] = {
                "sharedSecret": tacacs_secret,
                "connectModeOptions": (current.get("tacacsSettings") or {}).get("connectModeOptions", "OFF"),
            }
        if groups is not None:
            patch["NetworkDeviceGroupList"] = groups
        if description is not None:
            patch["description"] = description
        if coa_port is not None:
            patch["coaPort"] = coa_port
        blockers: list[str] = []
        if new_name is not None:
            patch["name"] = new_name
            if new_name != current.get("name") and await exists(app, "networkdevice", new_name):
                blockers.append(f"A network device named {new_name!r} already exists")
        if not patch:
            raise InvalidRequest("Nothing to change: give at least one field")
        desired = deep_merge(current, patch)
        side = ["RADIUS from this device fails until its secret matches"] if radius_secret is not None else []
        plan = Plan(
            f"Update network device {current.get('name')}",
            details={"changes": masked_changes(current, desired, replace=True)},  # ERS PUT replaces
            fingerprint=fingerprint(current),
            side_effects=side,
            blockers=blockers,
        )
        return await preview_or_apply(
            ctx,
            tool="ise_update_nad",
            args={
                "device": device,
                "ips": ips,
                "radius_secret": radius_secret,
                "tacacs_secret": tacacs_secret,
                "groups": groups,
                "description": description,
                "coa_port": coa_port,
                "new_name": new_name,
            },
            confirm=confirm,
            plan=plan,
            apply=lambda: ers_put(app, "networkdevice", "NetworkDevice", desired),
        )

    @reg.write(title="Create network device group")
    async def ise_create_ndg(
        ctx: Context,
        path: Annotated[
            str,
            Field(description="Full group path, e.g. 'Location#All Locations#Sydney' (parent must exist)"),
        ],
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a network device group (location, device type or a custom hierarchy) under an
        existing parent, so devices can be grouped and policy can match on it. Preview-first."""
        app: IseApp = get_client(ctx)
        parts = path.split("#")
        if len(parts) < 3:
            raise InvalidRequest("Give a full path like 'Location#All Locations#Sydney'")
        parent = "#".join(parts[:-1])
        blockers = []
        if await exists(app, "networkdevicegroup", path):
            blockers.append(f"Group {path!r} already exists")
        if not await exists(app, "networkdevicegroup", parent):
            blockers.append(f"Parent group {parent!r} doesn't exist; create it first")
        body = {"name": path, "description": description or "", "othername": parts[0]}
        return await preview_or_apply(
            ctx,
            tool="ise_create_ndg",
            args={"path": path, "description": description},
            confirm=confirm,
            plan=Plan(f"Create device group {path}", details=body, blockers=blockers),
            apply=lambda: ers_post(app, "networkdevicegroup", "NetworkDeviceGroup", body),
        )

    # --- endpoints -----------------------------------------------------------------------------

    @reg.write(title="Create or update an endpoint")
    async def ise_set_endpoint(
        ctx: Context,
        mac: Annotated[str, Field(description="Endpoint MAC address (any notation)")],
        group: Annotated[
            str | None, Field(description="Endpoint identity group name or id (see ise_list_endpoint_groups)")
        ] = None,
        static_group: Annotated[
            bool, Field(description="Pin the group (profiling won't move the endpoint to another group)")
        ] = True,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        custom_attributes: Annotated[
            dict[str, str] | None,
            Field(description="Custom attribute values to set, by name (see ise_list_custom_attributes)"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add an endpoint by MAC or change an existing one's identity group, description and custom
        attribute values, e.g. to allow-list a printer for MAB or tag a device for a policy that matches
        'EndPoints:<attribute>'. Preview-first with a diff for existing endpoints; unknown or mistyped
        custom attributes are refused. For many endpoints use ise_bulk_endpoints. Takes effect at the
        endpoint's next authentication (use the CoA tools to force it)."""
        app: IseApp = get_client(ctx)
        mac_n = normalize_mac(mac)
        gid = None
        if group:
            gid = (
                await group_ids(app, "endpointgroup", [group], "endpoint group", "ise_list_endpoint_groups")
            )[0]
        page = await app.ers_pager.fetch_page(
            app.ers, "/ers/config/endpoint", {"filter": f"mac.EQ.{mac_n}"}, limit=2
        )
        existing = await app.ers_get("endpoint", str(page.items[0]["id"])) if page.items else None
        patch: dict[str, Any] = {}
        if gid:
            patch["groupId"] = gid
            patch["staticGroupAssignment"] = static_group
        if description is not None:
            patch["description"] = description
        blockers: list[str] = []
        if custom_attributes:
            blockers = check_custom_values(custom_attributes, await custom_attribute_defs(app))
            patch["customAttributes"] = {"customAttributes": dict(custom_attributes)}
        if existing and not patch:
            raise InvalidRequest("Nothing to change: give group, description or custom_attributes")
        if existing:
            desired = deep_merge(existing, patch)
            plan = Plan(
                f"Update endpoint {mac_n}",
                details={"changes": field_changes(existing, desired, replace=True)},
                fingerprint=fingerprint(existing),
                blockers=blockers,
            )

            async def apply() -> Any:
                return await ers_put(app, "endpoint", "ERSEndPoint", desired)
        else:
            body = {
                "name": mac_n,
                "mac": mac_n,
                "staticProfileAssignment": False,
                "staticGroupAssignment": False,
                **patch,
            }
            plan = Plan(f"Create endpoint {mac_n}", details=body, blockers=blockers)

            async def apply() -> Any:
                return await ers_post(app, "endpoint", "ERSEndPoint", body)

        return await preview_or_apply(
            ctx,
            tool="ise_set_endpoint",
            args={
                "mac": mac_n,
                "group": group,
                "static_group": static_group,
                "description": description,
                "custom_attributes": custom_attributes,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    # --- identity ------------------------------------------------------------------------------

    @reg.write(title="Create internal user")
    async def ise_create_internal_user(
        ctx: Context,
        name: Annotated[str, Field(description="Username")],
        password: Annotated[
            str, Field(description="Initial password (ISE password policy applies; never echoed)")
        ],
        groups: Annotated[
            list[str] | None, Field(description="Identity group names (see ise_list_identity_groups)")
        ] = None,
        email: Annotated[str | None, Field(description="Email address")] = None,
        first_name: Annotated[str | None, Field(description="First name")] = None,
        last_name: Annotated[str | None, Field(description="Last name")] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        enabled: Annotated[bool, Field(description="Whether the account can authenticate")] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a user in the ISE internal identity store (for 802.1X/PAP/TACACS+ logins), in the given
        identity groups. Preview-first; the password is never shown. Blocked if the username exists."""
        app: IseApp = get_client(ctx)
        gids = await group_ids(
            app, "identitygroup", groups or [], "identity group", "ise_list_identity_groups"
        )
        body = {
            "name": name,
            "password": password,
            "enabled": enabled,
            "changePassword": False,
            "identityGroups": ",".join(gids),
            "passwordIDStore": "Internal Users",
            "email": email or "",
            "firstName": first_name or "",
            "lastName": last_name or "",
            "description": description or "",
        }
        blockers = [f"User {name!r} already exists"] if await exists(app, "internaluser", name) else []
        preview = {
            **{k: v for k, v in body.items() if k not in ("password", "passwordIDStore")},
            "groups": groups or [],
        }
        return await preview_or_apply(
            ctx,
            tool="ise_create_internal_user",
            args={
                "name": name,
                "password": password,
                "groups": groups,
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "description": description,
                "enabled": enabled,
            },
            confirm=confirm,
            plan=Plan(f"Create internal user {name}", details=compact(preview), blockers=blockers),
            apply=lambda: ers_post(app, "internaluser", "InternalUser", body),
        )

    @reg.write(title="Update internal user")
    async def ise_update_internal_user(
        ctx: Context,
        user: Annotated[str, Field(description="Username or id")],
        enabled: Annotated[bool | None, Field(description="Enable or disable the account")] = None,
        password: Annotated[str | None, Field(description="Set a new password (never echoed)")] = None,
        groups: Annotated[
            list[str] | None, Field(description="Replace identity group membership (names)")
        ] = None,
        email: Annotated[str | None, Field(description="New email")] = None,
        description: Annotated[str | None, Field(description="New description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Enable/disable an internal user, reset their password, or change groups/email/description.
        Only the given fields change. Preview-first with a diff (password shown only as changed)."""
        app: IseApp = get_client(ctx)
        current = await ers_resolve(
            app, "internaluser", user, what="internal user", list_tool="ise_list_internal_users"
        )
        patch: dict[str, Any] = {}
        if enabled is not None:
            patch["enabled"] = enabled
        if password is not None:
            patch["password"] = password
        if groups is not None:
            gids = await group_ids(app, "identitygroup", groups, "identity group", "ise_list_identity_groups")
            patch["identityGroups"] = ",".join(gids)
        if email is not None:
            patch["email"] = email
        if description is not None:
            patch["description"] = description
        if not patch:
            raise InvalidRequest("Nothing to change: give at least one field")
        desired = deep_merge(current, patch)
        shown = current
        if "password" not in patch:
            # GET returns a placeholder ("*******"); sending it back would reset the password to it.
            # ISE keeps the stored password when the PUT omits these, so they are not removals.
            kept = ("password", "enablePassword", "passwordIDStore")
            for key in kept:
                desired.pop(key, None)
            shown = {k: v for k, v in current.items() if k not in kept}
        plan = Plan(
            f"Update internal user {current.get('name')}",
            details={"changes": masked_changes(shown, desired, replace=True)},  # ERS PUT replaces
            fingerprint=fingerprint(current),
        )
        return await preview_or_apply(
            ctx,
            tool="ise_update_internal_user",
            args={
                "user": user,
                "enabled": enabled,
                "password": password,
                "groups": groups,
                "email": email,
                "description": description,
            },
            confirm=confirm,
            plan=plan,
            apply=lambda: ers_put(app, "internaluser", "InternalUser", desired),
        )

    @reg.write(title="Create identity or endpoint group")
    async def ise_create_group(
        ctx: Context,
        kind: Annotated[
            Literal["identity", "endpoint"], Field(description="'identity' (users) or 'endpoint'")
        ],
        name: Annotated[str, Field(description="Group name")],
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a user identity group or an endpoint identity group, for policy to match on and for
        users/endpoints to be placed in. Preview-first; blocked if the name exists."""
        app: IseApp = get_client(ctx)
        resource, wrapper = (
            ("identitygroup", "IdentityGroup") if kind == "identity" else ("endpointgroup", "EndPointGroup")
        )
        body = {"name": name, "description": description or ""}
        blockers = [f"{kind} group {name!r} already exists"] if await exists(app, resource, name) else []
        return await preview_or_apply(
            ctx,
            tool="ise_create_group",
            args={"kind": kind, "name": name, "description": description},
            confirm=confirm,
            plan=Plan(f"Create {kind} group {name}", details=body, blockers=blockers),
            apply=lambda: ers_post(app, resource, wrapper, body),
        )

    # --- authorization results -----------------------------------------------------------------

    async def _profile_body(
        app: IseApp,
        *,
        access: str | None,
        vlan: str | None,
        dacl: str | None,
        reauth_seconds: int | None,
        voice_domain: bool | None,
        description: str | None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if access is not None:
            body["accessType"] = ACCESS[access]
        if vlan is not None:
            body["vlan"] = {"nameID": vlan, "tagID": 1}
        if dacl is not None:
            if dacl and not await exists(app, "downloadableacl", dacl):
                raise NotFound(f"No dACL named {dacl!r}; see ise_list_dacls.", 404)
            body["daclName"] = dacl
        if reauth_seconds is not None:
            body["reauth"] = {"timer": reauth_seconds, "connectivity": "RADIUS_REQUEST"}
        if voice_domain is not None:
            body["voiceDomainPermission"] = voice_domain
        if description is not None:
            body["description"] = description
        return body

    @reg.write(title="Create authorization profile")
    async def ise_create_authz_profile(
        ctx: Context,
        name: Annotated[str, Field(description="Profile name")],
        access: Annotated[
            Literal["accept", "reject"], Field(description="Access-Accept or Access-Reject")
        ] = "accept",
        vlan: Annotated[str | None, Field(description="VLAN name or number to assign")] = None,
        dacl: Annotated[str | None, Field(description="Downloadable ACL name (see ise_list_dacls)")] = None,
        reauth_seconds: Annotated[
            int | None, Field(ge=1, le=65535, description="Session reauth timer")
        ] = None,
        voice_domain: Annotated[
            bool | None, Field(description="Grant voice domain permission (IP phones)")
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an authorization profile (what an authorization rule grants): access type, VLAN, dACL,
        reauth timer, voice domain. Preview-first; blocked if the name exists. Use it in a rule with
        ise_create_authz_rule."""
        app: IseApp = get_client(ctx)
        body = {
            "name": name,
            "authzProfileType": "SWITCH",
            "profileName": "Cisco",
            "trackMovement": False,
            "serviceTemplate": False,
            "easywiredSessionCandidate": False,
            **await _profile_body(
                app,
                access=access,
                vlan=vlan,
                dacl=dacl,
                reauth_seconds=reauth_seconds,
                voice_domain=voice_domain,
                description=description,
            ),
        }
        blockers = (
            [f"Profile {name!r} already exists"] if await exists(app, "authorizationprofile", name) else []
        )
        return await preview_or_apply(
            ctx,
            tool="ise_create_authz_profile",
            args={
                "name": name,
                "access": access,
                "vlan": vlan,
                "dacl": dacl,
                "reauth_seconds": reauth_seconds,
                "voice_domain": voice_domain,
                "description": description,
            },
            confirm=confirm,
            plan=Plan(f"Create authorization profile {name}", details=body, blockers=blockers),
            apply=lambda: ers_post(app, "authorizationprofile", "AuthorizationProfile", body),
        )

    @reg.write(title="Update authorization profile")
    async def ise_update_authz_profile(
        ctx: Context,
        profile: Annotated[str, Field(description="Profile name or id")],
        access: Annotated[Literal["accept", "reject"] | None, Field(description="Access type")] = None,
        vlan: Annotated[str | None, Field(description="VLAN name/number ('' to remove)")] = None,
        dacl: Annotated[str | None, Field(description="dACL name ('' to remove)")] = None,
        reauth_seconds: Annotated[int | None, Field(ge=1, le=65535, description="Reauth timer")] = None,
        voice_domain: Annotated[bool | None, Field(description="Voice domain permission")] = None,
        description: Annotated[str | None, Field(description="New description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change an authorization profile's access type, VLAN, dACL, reauth timer, voice domain or
        description. The preview lists the rules that use the profile (they're all affected at the next
        authentication)."""
        app: IseApp = get_client(ctx)
        current = await ers_resolve(
            app,
            "authorizationprofile",
            profile,
            what="authorization profile",
            list_tool="ise_list_authz_profiles",
        )
        patch = await _profile_body(
            app,
            access=access,
            vlan=vlan or None,
            dacl=dacl or None,
            reauth_seconds=reauth_seconds,
            voice_domain=voice_domain,
            description=description,
        )
        desired = deep_merge(current, patch)
        if vlan == "":
            desired.pop("vlan", None)
        if dacl == "":
            desired.pop("daclName", None)
        if desired == current:
            raise InvalidRequest("Nothing to change: give at least one different field")
        users = await rules_using_profile(app, str(current.get("name")))
        plan = Plan(
            f"Update authorization profile {current.get('name')}",
            details={"changes": field_changes(current, desired, replace=True), "used_by_rules": users},
            fingerprint=fingerprint(current),
            side_effects=[f"Affects {len(users)} rule(s) at the next authentication"] if users else [],
        )
        return await preview_or_apply(
            ctx,
            tool="ise_update_authz_profile",
            args={
                "profile": profile,
                "access": access,
                "vlan": vlan,
                "dacl": dacl,
                "reauth_seconds": reauth_seconds,
                "voice_domain": voice_domain,
                "description": description,
            },
            confirm=confirm,
            plan=plan,
            apply=lambda: ers_put(app, "authorizationprofile", "AuthorizationProfile", desired),
        )

    @reg.write(title="Create or update a downloadable ACL")
    async def ise_set_dacl(
        ctx: Context,
        name: Annotated[str, Field(description="dACL name (created if missing, otherwise updated)")],
        aces: Annotated[
            list[str],
            Field(description="ACEs in order, e.g. ['permit udp any any eq 53', 'deny ip any any']"),
        ],
        ip_version: Annotated[
            Literal["IPV4", "IPV6", "IP_AGNOSTIC"], Field(description="Address family")
        ] = "IPV4",
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a downloadable ACL, or replace an existing one's ACEs. ISE validates the ACL syntax on
        apply. Changes reach sessions at their next authentication. Preview-first with a diff."""
        app: IseApp = get_client(ctx)
        if not aces or any(not a.strip() for a in aces):
            raise InvalidRequest("Give at least one non-empty ACE")
        hit = await app.ers_find("downloadableacl", name)
        body = {"name": name, "dacl": "\n".join(a.strip() for a in aces), "daclType": ip_version}
        if description is not None:
            body["description"] = description
        args = {"name": name, "aces": aces, "ip_version": ip_version, "description": description}
        if hit:
            current = await app.ers_get("downloadableacl", str(hit["id"]))
            desired = deep_merge(current, body)
            if desired == current:
                raise InvalidRequest(f"dACL {name!r} already has exactly these ACEs and settings")
            plan = Plan(
                f"Update dACL {name}",
                details={"changes": field_changes(current, desired, replace=True)},
                fingerprint=fingerprint(current),
            )
            return await preview_or_apply(
                ctx,
                tool="ise_set_dacl",
                args=args,
                confirm=confirm,
                plan=plan,
                apply=lambda: ers_put(app, "downloadableacl", "DownloadableAcl", desired),
            )
        return await preview_or_apply(
            ctx,
            tool="ise_set_dacl",
            args=args,
            confirm=confirm,
            plan=Plan(f"Create dACL {name}", details=body),
            apply=lambda: ers_post(app, "downloadableacl", "DownloadableAcl", body),
        )

    # --- TrustSec ------------------------------------------------------------------------------

    @reg.write(title="Create or update an SGT")
    async def ise_set_sgt(
        ctx: Context,
        name: Annotated[str, Field(description="SGT name (letters, digits, underscore); created if missing")],
        value: Annotated[
            int | None, Field(ge=2, le=65519, description="Tag value; default: next free value for a new SGT")
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a security group tag, or change an existing one's value/description. Changing the value
        of a tag in use re-tags traffic network-wide; the preview says so. Preview-first."""
        app: IseApp = get_client(ctx)
        if not re.fullmatch(r"[A-Za-z0-9_]+", name):
            raise InvalidRequest("SGT names may only contain letters, digits and underscores")
        hit = await app.ers_find("sgt", name)
        args = {"name": name, "value": value, "description": description}
        if hit:
            current = await app.ers_get("sgt", str(hit["id"]))
            patch: dict[str, Any] = {}
            if value is not None:
                patch["value"] = value
            if description is not None:
                patch["description"] = description
            if not patch:
                raise InvalidRequest("SGT exists; give a new value or description to update it")
            desired = deep_merge(current, patch)
            side = (
                ["Re-tags all traffic using this SGT; devices must refresh their policy"]
                if "value" in patch
                else []
            )
            plan = Plan(
                f"Update SGT {name}",
                details={"changes": field_changes(current, desired, replace=True)},
                fingerprint=fingerprint(current),
                side_effects=side,
            )
            return await preview_or_apply(
                ctx,
                tool="ise_set_sgt",
                args=args,
                confirm=confirm,
                plan=plan,
                apply=lambda: ers_put(app, "sgt", "Sgt", desired),
            )
        if value is None:
            page = await app.ers_pager.fetch_page(app.ers, "/ers/config/sgt", limit=10_000)
            used = set()
            for s in page.items:
                used.add((await app.ers_get("sgt", str(s["id"]))).get("value"))
            value = next(v for v in range(2, 65520) if v not in used)
        body = {"name": name, "value": value, "description": description or "", "propogateToApic": False}
        return await preview_or_apply(
            ctx,
            tool="ise_set_sgt",
            args=args,
            confirm=confirm,
            plan=Plan(f"Create SGT {name} ({value})", details=body),
            apply=lambda: ers_post(app, "sgt", "Sgt", body),
        )

    @reg.write(title="Set an egress matrix cell")
    async def ise_set_egress_policy(
        ctx: Context,
        source_sgt: Annotated[str, Field(description="Source SGT name")],
        destination_sgt: Annotated[str, Field(description="Destination SGT name")],
        sgacls: Annotated[
            list[str], Field(description="SGACL names to apply in order (see ise_list_sgacls)")
        ],
        default_rule: Annotated[
            Literal["NONE", "PERMIT_IP", "DENY_IP"], Field(description="Catch-all after the SGACLs")
        ] = "NONE",
        enabled: Annotated[bool, Field(description="Cell status ENABLED or DISABLED")] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set the TrustSec policy for traffic from one SGT to another (one egress matrix cell): which
        SGACLs apply and the final catch-all. Creates the cell or replaces it. Devices enforce it after
        they refresh policy (or a TrustSec CoA push). Preview-first with a diff."""
        app: IseApp = get_client(ctx)
        src = await app.ers_find("sgt", source_sgt)
        dst = await app.ers_find("sgt", destination_sgt)
        if not src or not dst:
            raise NotFound(
                f"Unknown SGT {source_sgt if not src else destination_sgt!r}; see ise_list_sgts.", 404
            )
        acl_ids = await group_ids(app, "sgacl", sgacls, "SGACL", "ise_list_sgacls")
        body: dict[str, Any] = {
            "sourceSgtId": src["id"],
            "destinationSgtId": dst["id"],
            "matrixCellStatus": "ENABLED" if enabled else "DISABLED",
            "defaultRule": default_rule,
            "sgacls": acl_ids,
        }
        page = await app.ers_pager.fetch_page(
            app.ers,
            "/ers/config/egressmatrixcell",
            {"filter": [f"sgtSrcName.EQ.{source_sgt}", f"sgtDstName.EQ.{destination_sgt}"]},
            limit=5,
        )
        current = None
        for c in page.items:
            full = await app.ers_get("egressmatrixcell", str(c["id"]))
            if full.get("sourceSgtId") == src["id"] and full.get("destinationSgtId") == dst["id"]:
                current = full
        args = {
            "source_sgt": source_sgt,
            "destination_sgt": destination_sgt,
            "sgacls": sgacls,
            "default_rule": default_rule,
            "enabled": enabled,
        }
        summary = (
            f"{source_sgt} -> {destination_sgt}: {', '.join(sgacls) or '(no SGACL)'} then {default_rule}"
        )
        if current:
            desired = deep_merge(current, body)
            plan = Plan(
                f"Update egress cell {summary}",
                details={"changes": field_changes(current, desired, replace=True)},
                fingerprint=fingerprint(current),
            )
            return await preview_or_apply(
                ctx,
                tool="ise_set_egress_policy",
                args=args,
                confirm=confirm,
                plan=plan,
                apply=lambda: ers_put(app, "egressmatrixcell", "EgressMatrixCell", desired),
            )
        return await preview_or_apply(
            ctx,
            tool="ise_set_egress_policy",
            args=args,
            confirm=confirm,
            plan=Plan(f"Create egress cell {summary}", details=body),
            apply=lambda: ers_post(app, "egressmatrixcell", "EgressMatrixCell", body),
        )

    @reg.write(title="Create ANC policy")
    async def ise_create_anc_policy(
        ctx: Context,
        name: Annotated[str, Field(description="ANC policy name, e.g. 'Quarantine'")],
        actions: Annotated[
            list[Literal["QUARANTINE", "PORTBOUNCE", "SHUTDOWN", "REAUTHENTICATE"]],
            Field(description="What applying the policy does (QUARANTINE needs a matching authz rule)"),
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an Adaptive Network Control policy that ise_apply_anc can put on endpoints. QUARANTINE
        only has an effect if an authorization rule matches Session:ANCPolicy. Preview-first."""
        app: IseApp = get_client(ctx)
        body = {"name": name, "actions": actions}
        blockers = [f"ANC policy {name!r} already exists"] if await exists(app, "ancpolicy", name) else []
        return await preview_or_apply(
            ctx,
            tool="ise_create_anc_policy",
            args={"name": name, "actions": actions},
            confirm=confirm,
            plan=Plan(f"Create ANC policy {name}", details=body, blockers=blockers),
            apply=lambda: ers_post(app, "ancpolicy", "ErsAncPolicy", body),
        )

    @reg.write(title="Delete an ISE object", destructive=True)
    async def ise_delete_object(
        ctx: Context,
        kind: Annotated[
            Literal[
                "endpoint",
                "internal_user",
                "identity_group",
                "endpoint_group",
                "authz_profile",
                "dacl",
                "sgt",
                "sgacl",
                "ndg",
                "anc_policy",
                "command_set",
                "shell_profile",
                "ad_join_point",
                "tacacs_server",
                "tacacs_sequence",
                "sponsor_group",
                "guest_type",
            ],
            Field(description="What to delete"),
        ],
        target: Annotated[str, Field(description="Name or id (a MAC for endpoints)")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete one endpoint, internal user, identity/endpoint group, authorization profile, dACL, SGT,
        SGACL, device group, ANC policy, TACACS+ command set / shell profile / external server / server
        sequence, AD join point (after ise_leave_ad), sponsor group or guest type (guest accounts:
        ise_delete_guest_user). Preview-first: shows
        the object and what still references it (e.g. rules using a profile, which blocks the delete).
        Network devices and policy are deleted with the dangerous-tier tools."""
        app: IseApp = get_client(ctx)
        resource = DELETE_KINDS[kind]
        if kind == "endpoint":
            mac_n = normalize_mac(target)
            page = await app.ers_pager.fetch_page(
                app.ers, "/ers/config/endpoint", {"filter": f"mac.EQ.{mac_n}"}, limit=2
            )
            if not page.items:
                raise NotFound(f"No endpoint {mac_n}", 404)
            current = await app.ers_get("endpoint", str(page.items[0]["id"]))
        else:
            current = await ers_resolve(
                app, resource, target, what=kind.replace("_", " "), list_tool="the list tools"
            )
        name = str(current.get("name"))
        blockers: list[str] = []
        side: list[str] = []
        if kind == "authz_profile":
            users = await rules_using_profile(app, name)
            if users:
                blockers.append(f"Used by authorization rule(s): {', '.join(users)}")
        if kind in ("command_set", "shell_profile"):
            field = "commands" if kind == "command_set" else "profile"
            users = await rules_using_profile(app, name, "device-admin", field)
            if users:
                blockers.append(f"Used by device-admin rule(s): {', '.join(users)}")
        if kind == "dacl":
            page = await app.ers_pager.fetch_page(app.ers, "/ers/config/authorizationprofile", limit=5000)
            for prof in page.items:
                full = await app.ers_get("authorizationprofile", str(prof["id"]))
                if name in (full.get("daclName"), full.get("ipv6DaclName")):
                    blockers.append(f"Used by authorization profile {full.get('name')}")
        if kind == "ad_join_point":
            from ise_mcp.tools.ad import join_status  # noqa: PLC0415 - ad imports this module

            if (await join_status(app, current)).get("joined"):
                blockers.append(f"{name} is still joined to {current.get('domain')}: ise_leave_ad first")
            side.append(f"Policy conditions on {name}:ExternalGroups stop working")
        if kind in ("sponsor_group", "guest_type") and (
            current.get("isDefaultGroup") or current.get("isDefaultType")
        ):
            blockers.append(f"{name} is one of ISE's default {kind.replace('_', ' ')}s and can't be deleted")
        if kind == "sponsor_group":
            side.append("Its members can no longer sponsor guests (existing guest accounts stay)")
        if kind == "guest_type":
            side.append("Sponsors can no longer create this type; ISE refuses while guest accounts use it")
        blockers += await references(app, kind, current)
        if kind in ("identity_group", "endpoint_group", "sgt"):
            side.append(
                "Policy rules that match on it stop matching (rules are not checked; see ise_get_policy_set)"
            )
        plan = Plan(
            f"Delete {kind.replace('_', ' ')} {name}",
            details=compact(current),
            fingerprint=fingerprint(current),
            blockers=blockers,
            side_effects=side,
        )

        async def apply() -> Any:
            return await app.ers_request("DELETE", f"/ers/config/{resource}/{current['id']}")

        return await preview_or_apply(
            ctx,
            tool="ise_delete_object",
            args={"kind": kind, "target": target},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

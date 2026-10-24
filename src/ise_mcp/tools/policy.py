"""Policy sets and rules (OpenAPI), authorization profiles, dACLs and allowed protocols (ERS)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import asyncio
from typing import Annotated, Any, Literal

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
from ise_mcp.tools._common import (
    ers_list,
    ers_resolve,
    gather_limited,
    list_result,
    render_condition,
    summarize_rule,
)

PolicyKind = Annotated[
    Literal["network-access", "device-admin"],
    Field(description="'network-access' (RADIUS) or 'device-admin' (TACACS+)"),
]


def _resp(data: Any) -> Any:
    return data.get("response", data) if isinstance(data, dict) else data


def policy_set_row(ps: dict[str, Any]) -> dict[str, Any]:
    return {
        "rank": ps.get("rank"),
        "name": ps.get("name"),
        "state": ps.get("state"),
        "condition": "DEFAULT" if ps.get("default") else render_condition(ps.get("condition")),
        "allowed_protocols": ps.get("serviceName"),
        "hits": ps.get("hitCounts"),
        "proxy": ps.get("isProxy") or None,
        "description": ps.get("description"),
        "id": ps.get("id"),
    }


async def list_policy_sets(app: IseApp, kind: str) -> list[dict[str, Any]]:
    data = _resp(await app.openapi.get(f"/api/v1/policy/{kind}/policy-set"))
    return [p for p in data or [] if isinstance(p, dict)]


async def resolve_policy_set(app: IseApp, kind: str, key: str) -> dict[str, Any]:
    sets = await list_policy_sets(app, kind)
    for ps in sets:
        if ps.get("id") == key or str(ps.get("name", "")).lower() == key.strip().lower():
            return ps
    names = ", ".join(str(p.get("name")) for p in sets)
    raise NotFound(f"No {kind} policy set {key!r}. Existing: {names}", 404)


async def policy_set_rules(app: IseApp, kind: str, ps_id: str) -> dict[str, list[dict[str, Any]]]:
    base = f"/api/v1/policy/{kind}/policy-set/{ps_id}"
    sections = ("authentication", "authorization", "exception")

    async def one(section: str) -> list[dict[str, Any]]:
        try:
            data = _resp(await app.openapi.get(f"{base}/{section}"))
        except NotFound:
            return []
        except UpstreamError as e:
            return [{"error": str(e)[:200]}]
        rules = [summarize_rule(r) for r in data or [] if isinstance(r, dict)]
        return sorted(rules, key=lambda r: (r.get("rank") is None, r.get("rank") or 0))

    results = await asyncio.gather(*(one(s) for s in sections))
    return dict(zip(("authentication", "authorization", "local_exceptions"), results, strict=True))


def av_pair_text(adv: Any) -> str:
    """An ERS advanced attribute as 'Dictionary:attribute=value' (the av_pairs form of the write tools)."""
    if not isinstance(adv, dict):
        return str(adv)
    lhs = adv.get("leftHandSideDictionaryAttribue") or {}
    rhs = adv.get("rightHandSideAttribueValue") or {}
    value = rhs.get("value")
    if value is None and rhs.get("attributeName"):  # the value is another dictionary attribute
        value = f"{rhs.get('dictionaryName')}:{rhs.get('attributeName')}"
    return f"{lhs.get('dictionaryName')}:{lhs.get('attributeName')}={value}"


def authz_profile_row(p: dict[str, Any]) -> dict[str, Any]:
    redirect = p.get("webRedirection") or {}
    adv = p.get("advancedAttributes") or []
    row = {
        "name": p.get("name"),
        "access": p.get("accessType"),
        "vlan": (p.get("vlan") or {}).get("nameID"),
        "dacl": p.get("daclName") or p.get("ipv6DaclName"),
        "acl": p.get("acl") or p.get("airespaceACL"),
        "redirect": f"{redirect.get('WebRedirectionType')} ({redirect.get('portalName')})"
        if redirect
        else None,
        "reauth": (p.get("reauth") or {}).get("timer"),
        "voice_domain": p.get("voiceDomainPermission") or None,
        "advanced_attributes": len(adv) or None,
        "profile": p.get("profileName"),
        "description": p.get("description"),
        "id": p.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def dacl_row(d: dict[str, Any]) -> dict[str, Any]:
    lines = [ln for ln in str(d.get("dacl") or "").splitlines() if ln.strip()]
    return {
        "name": d.get("name"),
        "type": d.get("daclType"),
        "aces": len(lines),
        "first_ace": lines[0] if lines else None,
        "description": d.get("description"),
        "id": d.get("id"),
    }


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List policy sets")
    async def ise_list_policy_sets(
        ctx: Context,
        kind: PolicyKind = "network-access",
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List policy sets in evaluation order: rank, name, state, the condition that selects the set,
        its allowed-protocols service, hit count and id. Open one with ise_get_policy_set to see its
        authentication and authorization rules."""
        app: IseApp = get_client(ctx)
        rows = [policy_set_row(p) for p in await list_policy_sets(app, kind)]
        rows.sort(key=lambda r: int(r["rank"]) if r.get("rank") is not None else 1_000_000)
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["rank", "name", "state", "condition", "allowed_protocols", "hits", "id"],
        )

    @reg.read(title="Get a policy set with its rules")
    async def ise_get_policy_set(
        ctx: Context,
        policy_set: Annotated[str, Field(description="Policy set name or id (from ise_list_policy_sets)")],
        kind: PolicyKind = "network-access",
    ) -> ToolResult:
        """One policy set with all of its rules in order: authentication rules (condition -> identity
        source, if-fail/if-not-found actions), authorization rules (condition -> profiles and SGT) and
        local exceptions, each with hit counts and ids. Conditions are rendered as readable text. Use
        it to explain which rule an authentication would hit and what it gets."""
        app: IseApp = get_client(ctx)
        ps = await resolve_policy_set(app, kind, policy_set)
        rules = await policy_set_rules(app, kind, str(ps["id"]))
        return object_result({"policy_set": policy_set_row(ps), **rules})

    @reg.read(title="List authorization profiles")
    async def ise_list_authz_profiles(
        ctx: Context,
        name: Annotated[str | None, Field(description="Filter: name contains")] = None,
        detail: Annotated[
            bool, Field(description="Fetch each profile for access type, VLAN, dACL, redirect")
        ] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List authorization profiles (the result of an authorization rule): access type, VLAN, dACL,
        Airespace/filter ACL, web redirection, reauth timer and voice domain. Use
        ise_get_authz_profile for the full profile including advanced attributes."""
        app: IseApp = get_client(ctx)
        filters = [f"name.CONTAINS.{name}"] if name else None
        page = await ers_list(
            app,
            "authorizationprofile",
            filters=filters,
            limit=limit,
            offset=offset,
            detail=detail,
            shape=authz_profile_row,
        )
        cols = ["name", "access", "vlan", "dacl", "acl", "redirect", "reauth", "id"] if detail else None
        return list_result(page, fmt=response_format, columns=cols)

    @reg.read(title="Get an authorization profile")
    async def ise_get_authz_profile(
        ctx: Context,
        profile: Annotated[str, Field(description="Authorization profile name or id")],
    ) -> ToolResult:
        """Full authorization profile: access type, VLAN, dACL names, ACLs, web redirection, reauth,
        advanced RADIUS attributes (also as av_pairs such as 'Viptela:Viptela-Group-Name=netadmin'),
        device profile. Also lists which authorization rules (in which
        network-access policy sets) use it."""
        app: IseApp = get_client(ctx)
        obj = await ers_resolve(
            app,
            "authorizationprofile",
            profile,
            what="authorization profile",
            list_tool="ise_list_authz_profiles",
        )
        if obj.get("advancedAttributes"):
            obj["av_pairs"] = [av_pair_text(a) for a in obj["advancedAttributes"]]
        obj["used_by_rules"] = await rules_using_profile(app, str(obj.get("name")))
        return object_result(obj)

    @reg.read(title="List downloadable ACLs")
    async def ise_list_dacls(
        ctx: Context,
        name: Annotated[str | None, Field(description="Filter: name contains")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List downloadable ACLs (dACLs) with IP version, number of ACEs and the first ACE. Use
        ise_get_dacl for the full ACL text."""
        app: IseApp = get_client(ctx)
        filters = [f"name.CONTAINS.{name}"] if name else None
        page = await ers_list(
            app, "downloadableacl", filters=filters, limit=limit, offset=offset, detail=True, shape=dacl_row
        )
        return list_result(page, fmt=response_format)

    @reg.read(title="Get a downloadable ACL")
    async def ise_get_dacl(
        ctx: Context,
        dacl: Annotated[str, Field(description="dACL name or id (from ise_list_dacls)")],
    ) -> ToolResult:
        """One downloadable ACL with its full ACE text (one ACE per line), IP version and description."""
        app: IseApp = get_client(ctx)
        obj = await ers_resolve(
            app, "downloadableacl", dacl, what="downloadable ACL", list_tool="ise_list_dacls"
        )
        obj["aces"] = [ln for ln in str(obj.pop("dacl", "") or "").splitlines() if ln.strip()]
        return object_result(obj)

    @reg.read(title="List allowed protocols services")
    async def ise_list_allowed_protocols(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """List allowed-protocols services (selected by each policy set) and which authentication
        protocols each permits: PAP, CHAP, MS-CHAPv2, EAP-MD5, EAP-TLS, PEAP, EAP-FAST, TEAP, LEAP.
        Use it when auths fail with 'protocol not allowed' (e.g. 12001, 15024)."""
        app: IseApp = get_client(ctx)

        def shape(p: dict[str, Any]) -> dict[str, Any]:
            allowed = sorted(
                k.removeprefix("allow") for k, v in p.items() if k.startswith("allow") and v is True
            )
            return {
                "name": p.get("name"),
                "allowed": allowed,
                "description": p.get("description"),
                "id": p.get("id"),
            }

        page = await ers_list(app, "allowedprotocols", limit=limit, offset=offset, detail=True, shape=shape)
        return list_result(page, fmt=response_format)

    @reg.read(title="List library conditions")
    async def ise_list_conditions(
        ctx: Context,
        kind: PolicyKind = "network-access",
        name: Annotated[str | None, Field(description="Filter: name contains (case-insensitive)")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List reusable library conditions (e.g. Wired_802.1X, Wireless_MAB, EAP-TLS) rendered as
        readable text with descriptions. Policy rules refer to these by name."""
        app: IseApp = get_client(ctx)
        data = _resp(await app.openapi.get(f"/api/v1/policy/{kind}/condition")) or []
        rows = [
            {
                "name": c.get("name"),
                "condition": render_condition(c),
                "description": c.get("description"),
                "id": c.get("id"),
            }
            for c in data
            if isinstance(c, dict)
        ]
        if name:
            rows = [r for r in rows if name.lower() in str(r["name"]).lower()]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="List policy dictionary attributes")
    async def ise_list_dictionary_attributes(
        ctx: Context,
        kind: PolicyKind = "network-access",
        scope: Annotated[
            Literal["authorization", "authentication", "policyset"],
            Field(description="Which conditions the attributes are for (they differ slightly)"),
        ] = "authorization",
        dictionary: Annotated[
            str | None,
            Field(
                description="Only this dictionary, e.g. Radius, Session, DEVICE, IdentityGroup, EndPoints, "
                "Network Access, Cisco, Normalised Radius, TACACS (case-insensitive)"
            ),
        ] = None,
        name: Annotated[str | None, Field(description="Filter: attribute name contains")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """List the dictionary attributes policy conditions can use, with data type and allowed values
        (e.g. Radius:NAS-Port-Type -> Ethernet, Virtual...; Session:ANCPolicy; DEVICE:Location;
        Network Access:EapAuthentication -> EAP-TLS...). Write conditions as 'Dictionary:Attribute
        operator value' using these names and the allowed value names."""
        from ise_mcp.tools.policy_edit import dictionary_attributes  # avoid an import cycle

        app: IseApp = get_client(ctx)
        attrs = await dictionary_attributes(app, kind, scope)
        if dictionary:
            attrs = [a for a in attrs if str(a.get("dictionaryName")).lower() == dictionary.lower()]
        if name:
            attrs = [a for a in attrs if name.lower() in str(a.get("name")).lower()]
        rows = []
        for a in attrs:
            allowed = [str(v.get("key")) for v in a.get("allowedValues") or [] if isinstance(v, dict)]
            row = {
                "attribute": f"{a.get('dictionaryName')}:{a.get('name')}",
                "type": a.get("dataType"),
                "allowed": (", ".join(allowed[:30]) + (" ..." if len(allowed) > 30 else "")) or None,
            }
            rows.append({k: v for k, v in row.items() if v})
        if not rows and dictionary:
            dicts = sorted(
                {str(a.get("dictionaryName")) for a in await dictionary_attributes(app, kind, scope)}
            )
            return object_result(
                {"results": [], "note": f"No attributes; dictionaries are: {', '.join(dicts)}"}
            )
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)


async def rules_using_profile(
    app: IseApp, profile: str, kind: str = "network-access", field: str = "profile"
) -> list[str]:
    """'PolicySet / Rule' for every authorization rule (or exception) whose `field` (profiles, or for
    device admin the shell profile / command sets) includes `profile`."""
    out: list[str] = []
    try:
        sets = await list_policy_sets(app, kind)
    except UpstreamError:
        return out
    all_rules = await gather_limited(sets, lambda ps: policy_set_rules(app, kind, str(ps["id"])), limit=4)
    for ps, rules in zip(sets, all_rules, strict=True):
        for section in ("authorization", "local_exceptions"):
            for r in rules[section]:
                value = r.get(field) or []
                if profile == value or (isinstance(value, list) and profile in value):
                    out.append(f"{ps.get('name')} / {r.get('name')}")
    return out

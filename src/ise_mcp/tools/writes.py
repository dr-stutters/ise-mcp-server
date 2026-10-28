"""Write-tier tools (MCP_ENABLE_WRITES): preview-first create/update for NADs, endpoints, users,
groups, authorization profiles, dACLs, SGTs, the egress matrix, ANC policies and authorization rules.

Every tool returns a preview + confirm token first; nothing changes until the identical call is
repeated with `confirm`. Secrets passed in (RADIUS/TACACS secrets, SNMP communities, passwords) are
never echoed: previews show only whether they are set.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import contextlib
import difflib
import hashlib
import ipaddress
import json
import re
from datetime import date
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastmcp import Context
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from ise_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    compact,
    field_changes,
    get_client,
    preview_or_apply,
)
from ise_mcp._core.formatting import MASK, NOT_SECRET_KEYS, is_secret_key, mask_secrets
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_name_map, ers_resolve, gather_limited, is_uuid, normalize_mac
from ise_mcp.tools.endpoint_bulk import check_custom_values, custom_attribute_defs
from ise_mcp.tools.network import resolve_nad
from ise_mcp.tools.policy import av_pair_text, rules_using_profile
from ise_mcp.tools.trustsec import GENERAL_SETTINGS

# --- helpers ------------------------------------------------------------------------------------


CellStatus = Literal["ENABLED", "DISABLED", "MONITOR"]
PUSH_REMINDER = (
    "Devices apply matrix changes at their next policy refresh; ise_push_trustsec_matrix sends the "
    "TrustSec CoA so they download it now"
)


def resolve_cell_status(status: str | None, enabled: bool | None) -> str | None:
    """An egress cell's matrixCellStatus from `status`, or the deprecated `enabled` flag; None when
    neither is given (a new cell is ENABLED, an existing one keeps its status)."""
    legacy = None if enabled is None else ("ENABLED" if enabled else "DISABLED")
    if status and legacy and status != legacy:
        raise InvalidRequest(f"status={status} contradicts enabled={enabled}; pass status only")
    return status or legacy


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


def unchanged(changes: dict[str, Any], *secrets: object) -> bool:
    """C71: the request leaves the object as it is, so the Plan is a no-op (`status: no_change`, no
    token). True when the field diff is empty and no secret argument was given: a secret is never
    compared (it is masked in every diff), so a given one always counts as a change."""
    return not changes and all(s is None for s in secrets)


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


# --- authorization profile advanced attributes (av_pairs) -------------------------------------

# Catalyst SD-WAN (Viptela) maps an admin's user group from this vendor attribute (vendor 41916,
# attribute 1). ISE 3.5 ships no Viptela dictionary (checked on the lab ISE, 2026-10-24) and its REST
# API cannot create RADIUS vendor dictionaries (the OpenAPI Dictionary schema has no vendor id), so a
# missing dictionary is a blocker that names the one-time GUI step.
SDWAN_DICTIONARY = "Viptela"
SDWAN_ATTRIBUTE = "Viptela-Group-Name"
SDWAN_DICTIONARY_STEP = (
    "ISE has no 'Viptela' RADIUS dictionary: ISE does not ship one and its REST API cannot create RADIUS "
    "vendor dictionaries. Add it once in the GUI: Policy > Policy Elements > Dictionaries > System > "
    "RADIUS > RADIUS Vendors > Add, Name 'Viptela', Vendor ID 41916; then under its Dictionary "
    "Attributes add 'Viptela-Group-Name', Attribute ID 1, Data Type STRING, Direction OUT (or BOTH). "
    "Then repeat this call."
)
# TACACS+ has no vendor dictionaries: the Manager reads this custom shell-profile attribute.
SDWAN_TACACS_ATTRIBUTE = "viptela-group-name"
DICTIONARIES_PATH = "/api/v1/policy/network-access/dictionaries"


def _resp(data: Any) -> Any:
    return data.get("response", data) if isinstance(data, dict) else data


def valid_sdwan_group(value: str) -> str:
    group = value.strip()
    if not group or not re.fullmatch(r"[A-Za-z0-9_.-]+", group):
        raise InvalidRequest(
            f"sdwan_group {value!r}: a Catalyst SD-WAN user group name, e.g. 'netadmin', 'operator' or a "
            "custom group (letters, digits, '_', '-', '.')"
        )
    return group


async def check_av_pairs(app: IseApp, advanced: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Check (and canonicalise in place) ERS advanced attributes against ISE's network-access
    dictionaries: the dictionary and attribute exist, the attribute can be sent in a reply (not
    IN-only) and the value is one of its allowed values. Returns (blockers, warnings); when the
    OpenAPI surface does not answer, nothing is blocked and ISE validates on apply."""
    if not advanced:
        return [], []
    try:
        dicts = _resp(await app.openapi.get(DICTIONARIES_PATH)) or []
    except UpstreamError as e:
        return [], [f"av_pairs not checked against ISE's dictionaries ({e}); ISE validates them on apply"]
    names = {str(d.get("name")).lower(): str(d.get("name")) for d in dicts if isinstance(d, dict)}
    attrs_by_dict: dict[str, list[dict[str, Any]]] = {}
    blockers: list[str] = []
    for adv in advanced:
        lhs = adv["leftHandSideDictionaryAttribue"]
        value = str(adv["rightHandSideAttribueValue"]["value"])
        given_d, given_a = str(lhs["dictionaryName"]), str(lhs["attributeName"])
        d = names.get(given_d.lower())
        if d is None:
            if given_d.lower() == SDWAN_DICTIONARY.lower():
                blockers.append(SDWAN_DICTIONARY_STEP)
            else:
                close = difflib.get_close_matches(given_d, list(names.values()), n=3, cutoff=0.6)
                hint = f" Did you mean {', '.join(close)}?" if close else ""
                blockers.append(f"ISE has no dictionary {given_d!r}.{hint}")
            continue
        lhs["dictionaryName"] = d
        if d not in attrs_by_dict:
            data = _resp(await app.openapi.get(f"{DICTIONARIES_PATH}/{quote(d, safe='')}/attribute"))
            attrs_by_dict[d] = [a for a in data or [] if isinstance(a, dict)]
        attrs = {str(a.get("name")).lower(): a for a in attrs_by_dict[d]}
        found = attrs.get(given_a.lower())
        if found is None:
            known = [str(a.get("name")) for a in attrs_by_dict[d]]
            close = difflib.get_close_matches(given_a, known, n=3, cutoff=0.6)
            if d == SDWAN_DICTIONARY and given_a.lower() == SDWAN_ATTRIBUTE.lower():
                hint = " Add it under the Viptela vendor's Dictionary Attributes: ID 1, STRING, OUT."
            else:
                hint = f" Did you mean {', '.join(close)}?" if close else ""
            blockers.append(f"Dictionary {d} has no attribute {given_a!r}.{hint}")
            continue
        lhs["attributeName"] = found.get("name")
        name = f"{d}:{found.get('name')}"
        if found.get("directionType") in ("IN", "NONE"):
            blockers.append(
                f"{name} is a {found.get('directionType')} attribute: a profile can only return OUT or "
                "BOTH attributes"
            )
        allowed = [v for v in found.get("allowedValues") or [] if isinstance(v, dict)]
        if allowed:
            keys = {str(v.get("key")).lower(): str(v.get("key")) for v in allowed}
            numbers = {str(v.get("value")) for v in allowed}
            if value.lower() in keys:
                adv["rightHandSideAttribueValue"]["value"] = keys[value.lower()]
            elif value not in numbers:
                blockers.append(f"{name} must be one of: {', '.join(keys.values())} (got {value!r})")
    return blockers, []


# ERS trustsecsettings for a NAD that had none: daily refreshes, and policy changes sent by CoA (without
# `sendConfigurationToDevice` ISE's TrustSec push skips the device and its device report stays empty).
TRUSTSEC_NAD_DEFAULTS: dict[str, Any] = {
    "sgaNotificationAndUpdates": {
        "downlaodEnvironmentDataEveryXSeconds": 86400,
        "downlaodPeerAuthorizationPolicyEveryXSeconds": 86400,
        "reAuthenticationEveryXSeconds": 86400,
        "downloadSGACLListsEveryXSeconds": 86400,
        "otherSGADevicesToTrustThisDevice": False,
        "sendConfigurationToDevice": True,
        "sendConfigurationToDeviceUsing": "ENABLE_USING_COA",
    },
    "deviceConfigurationDeployment": {"includeWhenDeployingSGTUpdates": False},
}


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


def nad_has_radius(nad: dict[str, Any]) -> bool:
    return bool((nad.get("authenticationSettings") or {}).get("radiusSharedSecret"))


def nad_has_tacacs(nad: dict[str, Any]) -> bool:
    return bool((nad.get("tacacsSettings") or {}).get("sharedSecret"))


def nad_protocol_removals(
    current: dict[str, Any],
    desired: dict[str, Any],
    *,
    remove_radius: bool,
    remove_tacacs: bool,
    radius_secret: str | None,
    tacacs_secret: str | None,
    blockers: list[str],
    side_effects: list[str],
) -> list[str]:
    """Apply remove_radius / remove_tacacs to `desired` (in place) and return the protocols removed.

    The PUT body is built from ISE's own GET, so the protocol that stays keeps its stored key without it
    passing through the tool arguments. Dropping the settings object is how ERS stores "protocol off"
    (a TACACS-only NAD has no authenticationSettings)."""
    removed: list[str] = []
    name = current.get("name")
    for flag, label, key, secret_arg, has in (
        ("remove_radius", "RADIUS", "authenticationSettings", "radius_secret", nad_has_radius),
        ("remove_tacacs", "TACACS+", "tacacsSettings", "tacacs_secret", nad_has_tacacs),
    ):
        wanted = remove_radius if label == "RADIUS" else remove_tacacs
        secret = radius_secret if label == "RADIUS" else tacacs_secret
        if not wanted:
            continue
        if secret is not None:
            blockers.append(f"{flag} and {secret_arg} contradict each other: give one")
        elif not has(current):
            blockers.append(f"{name} has no {label} shared secret set: nothing to remove")
        else:
            desired.pop(key, None)
            removed.append(label)
    if removed and not nad_has_radius(desired) and not nad_has_tacacs(desired):
        blockers.append(
            f"This would leave {name} with neither RADIUS nor TACACS+; to take the device out of ISE use "
            "ise_delete_nad (dangerous)"
        )
    ips = ", ".join(nad_ip_text(current)) or "its IPs"
    if "RADIUS" in removed:
        side_effects.append(
            f"RADIUS from {ips} is dropped from now on (11007 in the live log): network access through "
            "this device stops authenticating"
        )
    if "TACACS+" in removed:
        side_effects.append(
            f"TACACS+ from {ips} is no longer accepted: device admin logins through ISE fail (keep a "
            "local login on the device)"
        )
    return removed


def nad_ip_text(nad: dict[str, Any]) -> list[str]:
    return [
        f"{e.get('ipaddress')}/{e.get('mask', 32)}"
        for e in nad.get("NetworkDeviceIPList") or []
        if isinstance(e, dict)
    ]


async def check_protocols_removed(app: IseApp, nad_id: str, removed: list[str]) -> None:
    """Read the NAD back: ERS PUT can keep a nested object it was not sent, so prove the removal took."""
    after = await app.ers_get("networkdevice", nad_id)
    still = [p for p in removed if (nad_has_radius(after) if p == "RADIUS" else nad_has_tacacs(after))]
    if still:
        raise UpstreamError(
            f"ISE accepted the update but still has {' and '.join(still)} on the device: ERS kept the "
            "settings it was not sent. Untick the protocol in the GUI (Network Devices > the device)"
        )


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


async def find_egress_cell(
    app: IseApp, source_sgt: str, destination_sgt: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """(source SGT, destination SGT, the full egress cell or None) for an SGT name pair. ERS can't filter
    cells by name ('Employees-Servers' is ambiguous when SGT names hold '-'), so the cells are filtered by
    the two SGT names and matched on the SGT ids. NotFound for an unknown SGT."""
    src = await app.ers_find("sgt", source_sgt)
    dst = await app.ers_find("sgt", destination_sgt)
    if not src or not dst:
        raise NotFound(f"Unknown SGT {source_sgt if not src else destination_sgt!r}; see ise_list_sgts.", 404)
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
    return src, dst, current


async def any_any_default_cell(app: IseApp) -> dict[str, Any]:
    """The ANY-ANY default egress cell (full object). ERS can't filter cells by name, but its source SGT
    name ANY filters (ISE 3.5 returns just this cell); an unfiltered scan is the fallback."""
    path = "/ers/config/egressmatrixcell"
    pages: tuple[tuple[dict[str, Any] | None, int], ...] = (
        ({"filter": "sgtSrcName.EQ.ANY"}, 20),
        (None, 10_000),
    )
    for params, limit in pages:
        page = await app.ers_pager.fetch_page(app.ers, path, params, limit=limit)
        hit = next((c for c in page.items if isinstance(c, dict) and c.get("name") == "ANY-ANY"), None)
        if hit is not None:
            return await app.ers_get("egressmatrixcell", str(hit["id"]))
    raise NotFound("The ANY-ANY default egress cell could not be read (ERS egressmatrixcell)", 404)


async def resolve_egress_cell(app: IseApp, target: str) -> tuple[dict[str, Any], str, str]:
    """(full cell, source SGT name, destination SGT name) for ise_delete_object kind='egress_cell': the
    target is 'SOURCE->DESTINATION' (SGT names), the cell id, or 'ANY-ANY'."""
    key = target.strip()
    if re.sub(r"\s+", "", key).upper() in ("ANY-ANY", "ANY->ANY"):
        # #143: ERS lists no SGT named ANY (the cell's source/destination is an internal pseudo-SGT), so an
        # SGT-name lookup fails before delete_egress_cell's blocker runs: find the default cell by name.
        return await any_any_default_cell(app), "ANY", "ANY"
    if is_uuid(key):
        cell = await app.ers_get("egressmatrixcell", key)
        sgts = await ers_name_map(app, "sgt")
        src_name = sgts.get(str(cell.get("sourceSgtId")), str(cell.get("sourceSgtId")))
        dst_name = sgts.get(str(cell.get("destinationSgtId")), str(cell.get("destinationSgtId")))
        return cell, src_name, dst_name
    if "->" not in key:
        raise InvalidRequest(
            f"Give the egress cell as 'SOURCE->DESTINATION' (SGT names) or its id, not {target!r}; "
            "ise_get_egress_matrix lists the cells"
        )
    src_name, dst_name = (p.strip() for p in key.split("->", 1))
    if not src_name or not dst_name:
        raise InvalidRequest(f"Give both SGT names: 'SOURCE->DESTINATION', not {target!r}")
    src, dst, found = await find_egress_cell(app, src_name, dst_name)
    if found is None:
        raise NotFound(
            f"No egress cell {src_name} -> {dst_name}: the pair uses the ANY-ANY default. "
            "ise_get_egress_matrix lists the cells",
            404,
        )
    return found, str(src.get("name") or src_name), str(dst.get("name") or dst_name)


async def delete_egress_cell(ctx: Context, app: IseApp, target: str, confirm: str | None) -> dict[str, Any]:
    """ise_delete_object kind='egress_cell': one explicit matrix cell, never the ANY-ANY default."""
    cell, src_name, dst_name = await resolve_egress_cell(app, target)
    acls = await ers_name_map(app, "sgacl")
    sgacl_names = [acls.get(str(a), str(a)) for a in cell.get("sgacls") or []]
    rule = cell.get("defaultRule") or "NONE"
    status = cell.get("matrixCellStatus") or "ENABLED"
    blockers: list[str] = []
    if cell.get("name") == "ANY-ANY" or (src_name.upper() == "ANY" and dst_name.upper() == "ANY"):
        blockers.append(
            "ANY-ANY is the matrix default and can't be deleted: change its catch-all, SGACLs or status "
            "with ise_set_default_egress_rule"
        )
    details = {
        "cell": cell.get("name"),
        "id": cell.get("id"),
        "source_sgt": src_name,
        "destination_sgt": dst_name,
        "sgacls": sgacl_names,
        "default_rule": rule,
        "status": status,
    }
    side = [
        f"Traffic from {src_name} to {dst_name} falls to the ANY-ANY default cell (ise_get_egress_matrix "
        f"shows what it does)",
        PUSH_REMINDER,
    ]
    if status == "DISABLED":
        side.insert(0, "The cell is DISABLED: devices already apply the ANY-ANY default to this pair")
    plan = Plan(
        f"Delete egress cell {src_name} -> {dst_name}: {', '.join(sgacl_names) or '(no SGACL)'} then {rule} "
        f"({status})",
        details=details,
        fingerprint=fingerprint(cell),
        blockers=blockers,
        side_effects=side,
    )

    async def apply() -> Any:
        return await app.ers_request("DELETE", f"/ers/config/egressmatrixcell/{cell['id']}")

    return await preview_or_apply(
        ctx,
        tool="ise_delete_object",
        args={"kind": "egress_cell", "target": target},
        confirm=confirm,
        plan=plan,
        apply=apply,
    )


# --- egress cells: the built-in catch-all SGACLs (#131) --------------------------------------------

# ISE spells a cell's defaultRule as a built-in SGACL in its `sgacls` list too: the ANY-ANY cell reads
# defaultRule PERMIT_IP with sgacls [<id of 'Permit IP'>]. Sending that list back is refused when
# multiple SGACLs per cell are off (the default): "Only one Catch All Rule SGACL can exsits [None,Permit
# IP,Deny IP! , can not change cell to multiple sgacls ...". An empty list leaves ISE's own entry alone.
CATCH_ALL_SGACLS = {"permit ip": "PERMIT_IP", "deny ip": "DENY_IP", "none": "NONE"}
MULTIPLE_SGACLS_REASON = (
    "ISE allows one SGACL per cell, counting a PERMIT_IP/DENY_IP catch-all as one: multiple SGACLs are "
    "off in the TrustSec settings (ISE: 'can not change cell to multiple sgacls as it set to disable in "
    "trust sec global settings'). Use one SGACL with catch-all NONE, only the catch-all, or turn the "
    "setting on with ise_set_trustsec_settings(multiple_sgacls=True)"
)


def catch_all_rule(name: Any) -> str | None:
    """The defaultRule a built-in catch-all SGACL name stands for ('Permit IP' -> PERMIT_IP), else None."""
    return CATCH_ALL_SGACLS.get(str(name).strip().lower())


def cell_sgacl_ids(cell: dict[str, Any], acl_names: dict[str, str]) -> list[str]:
    """A cell's SGACL ids as read, minus the built-in entry that only repeats its defaultRule (and the
    'None' placeholder): what the cell applies before its catch-all."""
    rule = str(cell.get("defaultRule") or "NONE").upper()
    out = []
    for a in cell.get("sgacls") or []:
        implied = catch_all_rule(acl_names.get(str(a), ""))
        if implied == "NONE" or (implied is not None and implied == rule):
            continue
        out.append(str(a))
    return out


def split_catch_all(sgacls: list[str], rule: str) -> tuple[list[str], list[str]]:
    """(SGACL names to send, blockers) for the caller's `sgacls` against the cell's catch-all `rule`. A
    built-in catch-all that names `rule` is the rule, not an SGACL, and is dropped. One naming another
    catch-all contradicts `rule` and blocks; with rule NONE, 'Permit IP'/'Deny IP' stay as the cell's
    one SGACL (ISE's form when multiple SGACLs are off)."""
    keep: list[str] = []
    blockers: list[str] = []
    for n in sgacls:
        implied = catch_all_rule(n)
        if implied is None or (rule == "NONE" and implied != "NONE"):
            keep.append(n)
        elif implied == "NONE" or implied == rule:
            continue  # the catch-all itself ('None' adds nothing)
        else:
            blockers.append(
                f"sgacls names the catch-all {n!r} ({implied}) but the rule is {rule}: give the catch-all "
                f"once, as the rule (rule={implied}), and leave it out of sgacls"
            )
    return keep, blockers


async def multiple_sgacls_blocker(app: IseApp, sgacl_count: int, rule: str) -> str | None:
    """ISE's refusal, in the preview, for a cell with more than one SGACL (a PERMIT_IP/DENY_IP catch-all
    counts as one) while multiple SGACLs per cell are off in the TrustSec settings."""
    if sgacl_count + (0 if rule == "NONE" else 1) <= 1:
        return None
    try:
        settings = await app.openapi.get(GENERAL_SETTINGS)
    except UpstreamError:
        return None  # unreadable: ISE decides on the PUT
    if isinstance(settings, dict) and settings.get("allowMultipleSGACLs") is False:
        what = f"{sgacl_count} SGACL(s)" + ("" if rule == "NONE" else f" plus the {rule} catch-all")
        return f"{what}: {MULTIPLE_SGACLS_REASON}"
    return None


async def exists(app: IseApp, resource: str, name: str) -> bool:
    return await app.ers_find(resource, name) is not None


async def references(app: IseApp, kind: str, obj: dict[str, Any]) -> list[str]:
    """Blockers for deleting a kind ise_where_used doesn't cover (it covers the policy-facing ones)."""
    name = str(obj.get("name"))
    if kind == "tacacs_server":
        page = await app.ers_pager.fetch_page(app.ers, "/ers/config/tacacsserversequence", limit=500)
        for item in page.items:
            seq = await app.ers_get("tacacsserversequence", str(item["id"]))
            listed = [x.strip().lower() for x in str(seq.get("serverList") or "").split(",")]
            if name.lower() in listed:
                return [f"Listed in TACACS+ server sequence {seq.get('name')}"]
    return []


# Kinds whose "still in use" check is ise_where_used's scan (tools/where_used.py).
WHERE_USED_KINDS = {
    "identity_group",
    "endpoint_group",
    "authz_profile",
    "dacl",
    "sgt",
    "sgacl",
    "ndg",
    "command_set",
    "shell_profile",
    "ad_join_point",
    "allowed_protocols",
}


# ISE ships these and refuses to delete them.
DEFAULT_SERVICES = {"default network access", "default device admin"}

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
    "allowed_protocols": "allowedprotocols",
    "egress_cell": "egressmatrixcell",
}

ACCESS = {"accept": "ACCESS_ACCEPT", "reject": "ACCESS_REJECT"}

# --- authorization profile web redirection and common tasks (I85) -----------------------------

RedirectType = Literal["CentralizedWebAuth", "HotSpot", "NativeSupplicanProvisioning", "ClientProvisioning"]
MacsecPolicy = Literal["MUST_SECURE", "SHOULD_SECURE", "MUST_NOT_SECURE"]
# ERS portal collections, by the kind of portal they hold.
PORTAL_RESOURCES = {
    "sponsored-guest": "sponsoredguestportal",
    "self-registration": "selfregportal",
    "hotspot": "hotspotportal",
    "BYOD": "byodportal",
    "sponsor": "sponsorportal",
    "My Devices": "mydeviceportal",
}
# Which portal kinds each redirect type takes (ISE refuses a portal of another kind). ERS has no
# client provisioning portal collection, so that type's portal is checked by ISE on apply.
REDIRECT_PORTALS: dict[str, tuple[str, ...]] = {
    "CentralizedWebAuth": ("sponsored-guest", "self-registration"),
    "HotSpot": ("hotspot",),
    "NativeSupplicanProvisioning": ("BYOD",),
    "ClientProvisioning": (),
}


class Redirect(BaseModel):
    """Web redirection (ERS webRedirection) on an authorization profile."""

    type: RedirectType = Field(
        description="CentralizedWebAuth (guest CWA: sponsored-guest or self-registration portal), HotSpot "
        "(hotspot portal), NativeSupplicanProvisioning (BYOD portal) or ClientProvisioning (posture)"
    )
    acl: str = Field(
        min_length=1,
        description="Redirect ACL name as configured on the switch/WLC (permit = redirect), e.g. "
        "'ACL-REDIRECT'; ISE sends only the name",
    )
    portal: str = Field(min_length=1, description="Portal name, e.g. 'Sponsored Guest Portal (default)'")
    static_host: str | None = Field(
        default=None,
        description="Static IP, host name or FQDN for the redirect URL instead of the PSN's own name",
    )


InterfaceTemplateArg = Annotated[
    str | None,
    Field(description="Interface template (IBNS 2.0 'template <name>' on the switch) to apply to the port"),
]
AutoSmartPortArg = Annotated[
    str | None,
    Field(description="Auto Smart Port event name the switch maps to a macro, e.g. 'CISCO_PHONE_EVENT'"),
]
MacsecArg = Annotated[
    MacsecPolicy | None, Field(description="MACsec policy (linksec-policy) for the session")
]
NeatArg = Annotated[
    bool | None, Field(description="NEAT: authorise a supplicant switch (device-traffic-class=switch)")
]
WebAuthArg = Annotated[bool | None, Field(description="Local web authentication on the switch")]
AirespaceAclArg = Annotated[
    str | None, Field(description="Airespace ACL name on the WLC (Airespace-ACL-Name)")
]
Ipv6DaclArg = Annotated[str | None, Field(description="IPv6 downloadable ACL name (see ise_list_dacls)")]
TrackMovementArg = Annotated[
    bool | None,
    Field(description="Track the endpoint's location via the MSE location service (a move re-authorizes)"),
]


async def _portal_names(app: IseApp) -> dict[str, list[str]]:
    """Portal names by kind, from the ERS portal collections that answer."""
    out: dict[str, list[str]] = {}
    for kind, resource in PORTAL_RESOURCES.items():
        try:
            page = await app.ers_pager.fetch_page(app.ers, f"/ers/config/{resource}", limit=1000)
        except NotFound:
            continue
        out[kind] = [str(i.get("name")) for i in page.items if isinstance(i, dict) and i.get("name")]
    return out


async def redirect_body(app: IseApp, r: Redirect) -> tuple[dict[str, Any], list[str], list[str]]:
    """(webRedirection, blockers, side effects). The portal is matched to ISE's spelling and checked
    against the redirect type: ISE rejects a portal of the wrong kind."""
    portals = await _portal_names(app)
    wanted = REDIRECT_PORTALS[r.type]
    key = r.portal.strip().lower()
    found = {k: n for k, names in portals.items() for n in names if n.lower() == key}
    blockers: list[str] = []
    warnings = [
        f"The redirect ACL {r.acl!r} must exist on the switch/WLC: ISE sends only its name "
        "(cisco-av-pair url-redirect-acl)"
    ]
    name = r.portal.strip()
    hit = [k for k in wanted if k in found]
    if hit:
        name = found[hit[0]]
    elif found:
        kind, actual = next(iter(found.items()))
        need = " or ".join(wanted) or "client provisioning"
        blockers.append(
            f"Portal {actual!r} is a {kind} portal: {r.type} redirection needs a {need} portal "
            "(ISE rejects the mismatch)"
        )
    elif wanted:
        have = [n for k in wanted for n in portals.get(k, [])]
        blockers.append(
            f"No {' or '.join(wanted)} portal named {r.portal!r}"
            + (f" (have: {', '.join(repr(n) for n in have)})" if have else "")
            + "; see ise_list_guest_portals"
        )
    else:
        warnings.append(
            f"Client provisioning portal {r.portal!r} is checked by ISE on apply (ERS cannot list those)"
        )
    # ERS key spelling as ISE 3.5 returns and accepts it: 'acl' (not 'ACL', which ISE refuses with 400).
    body: dict[str, Any] = {"WebRedirectionType": r.type, "acl": r.acl.strip(), "portalName": name}
    if r.static_host:
        body["staticIPHostNameFQDN"] = r.static_host.strip()
    if r.type == "CentralizedWebAuth":
        body["displayCertificatesRenewalMessages"] = True  # mandatory for CWA (GUI default)
    return body, blockers, warnings


def same_redirect_keys(new: dict[str, Any], old: Any) -> dict[str, Any]:
    """`new` (from redirect_body) lined up with the profile's current webRedirection for the update diff:
    a redirect of the same type keeps the current displayCertificatesRenewalMessages (not a tool argument),
    so re-sending what ISE already has is no change."""
    if not isinstance(old, dict) or old.get("WebRedirectionType") != new.get("WebRedirectionType"):
        return new
    out = dict(new)
    if "displayCertificatesRenewalMessages" in old:
        out["displayCertificatesRenewalMessages"] = old["displayCertificatesRenewalMessages"]
    return out


def common_task_warnings(body: dict[str, Any], before: dict[str, Any] | None = None) -> list[str]:
    """What the NAD must have, and combinations ISE treats specially (side effects, not blockers).
    With `before` (an update), only for what changes."""
    changed = {k for k, v in body.items() if before is None or before.get(k) != v}
    out = []
    if body.get("webRedirection") and body.get("webAuth") and changed & {"webRedirection", "webAuth"}:
        out.append(
            "Both web redirection (central) and web_auth (local web auth) are set: the GUI offers one "
            "or the other; ISE may reject the pair"
        )
    if body.get("neat") and "neat" in changed:
        out.append("NEAT: the switch must run 'cisp enable' and the authenticator port 'dot1x supplicant'")
    if body.get("interfaceTemplate") and "interfaceTemplate" in changed:
        out.append(
            f"Interface template {body['interfaceTemplate']!r} must exist on the switch (IBNS 2.0 "
            "'template' config); ISE sends only its name"
        )
    return out


# --- internal users (I73) ----------------------------------------------------------------------

INTERNAL_STORE = "Internal Users"
# ERS fields holding a user's secrets. GET returns a placeholder for `password` (and nothing for
# `enablePassword`): sending the placeholder back would set it, so they go out only when given.
USER_SECRETS = ("password", "enablePassword")
USER_BULK_MAX = 500
USER_BULK_SAMPLE = 5
# Flags and counters whose names match the core secret pattern ("password"): show their values.
NOT_SECRET_KEYS.update({"changePassword", "passwordNeverExpires", "daysForPasswordExpiration"})
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
NO_EXPIRY = ("", "none", "never")


class InternalUserSpec(BaseModel):
    """One internal user (a bulk item, or the arguments of the single-user tools). None = not given."""

    name: str = Field(description="Username")
    password: str | None = Field(
        default=None,
        description="Password (create: required for the 'Internal Users' password store; never echoed)",
    )
    enable_password: str | None = Field(
        default=None, description="TACACS+ enable password (device admin 'enable'; never echoed)"
    )
    groups: list[str] | None = Field(
        default=None, description="Identity group names (update: replaces the membership)"
    )
    email: str | None = Field(default=None, description="Email address")
    first_name: str | None = Field(default=None, description="First name")
    last_name: str | None = Field(default=None, description="Last name")
    description: str | None = Field(default=None, description="Free-text description")
    enabled: bool | None = Field(default=None, description="Whether the account can authenticate")
    expiry_date: str | None = Field(
        default=None,
        description="Account expiry date 'YYYY-MM-DD' (the account stops authenticating after it); "
        "'' or 'never' removes the expiry",
    )
    change_password_on_login: bool | None = Field(
        default=None, description="Force a password change at the next login"
    )
    password_never_expires: bool | None = Field(
        default=None, description="Exempt the password from ISE's password lifetime policy"
    )
    password_store: str | None = Field(
        default=None,
        description="Where the password is checked: 'Internal Users' (default) or an AD join point / "
        "LDAP server name (ise_list_identity_sources); an AD-backed user needs no password here",
    )
    custom_attributes: dict[str, str] | None = Field(
        default=None,
        description="User custom attribute values by name (defined in ISE under Identity Management > "
        "Settings > User Custom Attributes); update merges into the existing values",
    )
    account_name_alias: str | None = Field(
        default=None, description="Account name alias (ISE mails password-expiry notices to it)"
    )


def expiry_fields(value: str) -> dict[str, Any]:
    text = value.strip()
    if text.lower() in NO_EXPIRY:
        return {"expiryDateEnabled": False, "expiryDate": ""}
    try:
        if not DATE_RE.fullmatch(text):
            raise ValueError
        date.fromisoformat(text)
    except ValueError:
        raise InvalidRequest(
            f"expiry_date {value!r}: give a date as YYYY-MM-DD, or '' / 'never' for no expiry"
        ) from None
    return {"expiryDateEnabled": True, "expiryDate": text}


def expired(fields: dict[str, Any]) -> bool:
    return (
        bool(fields.get("expiryDateEnabled")) and date.fromisoformat(str(fields["expiryDate"])) < date.today()
    )


async def resolve_password_store(app: IseApp, store: str) -> str:
    """'Internal Users' or the exact name of an AD join point / LDAP server."""
    key = store.strip().lower()
    if key in (INTERNAL_STORE.lower(), "internal"):
        return INTERNAL_STORE
    names: list[str] = []
    for resource in ("activedirectory", "ldap"):
        with contextlib.suppress(UpstreamError):  # no LDAP servers / ERS resource on this release
            names += list((await ers_name_map(app, resource)).values())
    for n in names:
        if n.lower() == key:
            return n
    raise NotFound(
        f"No password store {store!r}: give 'Internal Users' or an AD join point / LDAP server name "
        "(see ise_list_identity_sources)",
        404,
    )


async def user_patch(app: IseApp, spec: InternalUserSpec) -> dict[str, Any]:
    """The ERS InternalUser fields for the values `spec` gives. Raises on a bad date, group or store."""
    patch: dict[str, Any] = {}
    if spec.password is not None:
        patch["password"] = spec.password
    if spec.enable_password is not None:
        patch["enablePassword"] = spec.enable_password
    if spec.enabled is not None:
        patch["enabled"] = spec.enabled
    if spec.groups is not None:
        gids = await group_ids(
            app, "identitygroup", spec.groups, "identity group", "ise_list_identity_groups"
        )
        patch["identityGroups"] = ",".join(gids)
    for attr, key in (
        ("email", "email"),
        ("first_name", "firstName"),
        ("last_name", "lastName"),
        ("description", "description"),
        ("account_name_alias", "accountNameAlias"),
    ):
        if (value := getattr(spec, attr)) is not None:
            patch[key] = value
    if spec.change_password_on_login is not None:
        patch["changePassword"] = spec.change_password_on_login
    if spec.password_never_expires is not None:
        patch["passwordNeverExpires"] = spec.password_never_expires
    if spec.expiry_date is not None:
        patch.update(expiry_fields(spec.expiry_date))
    if spec.password_store is not None:
        patch["passwordIDStore"] = await resolve_password_store(app, spec.password_store)
    if spec.custom_attributes is not None:
        patch["customAttributes"] = dict(spec.custom_attributes)
    return patch


def store_problems(user: dict[str, Any]) -> list[str]:
    store = user.get("passwordIDStore") or INTERNAL_STORE
    if store != INTERNAL_STORE and user.get("changePassword"):
        return [
            f"{user.get('name')}: change_password_on_login applies to the 'Internal Users' password "
            f"store only; {store} owns this user's password"
        ]
    return []


def user_create_body(spec: InternalUserSpec, patch: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """POST body and blockers for a new internal user."""
    body: dict[str, Any] = {
        "name": spec.name,
        "enabled": True,
        "changePassword": False,
        "identityGroups": "",
        "passwordIDStore": INTERNAL_STORE,
        "email": "",
        "firstName": "",
        "lastName": "",
        "description": "",
        **patch,
    }
    blockers = store_problems(body)
    if body["passwordIDStore"] == INTERNAL_STORE and not body.get("password"):
        blockers.append(f"{spec.name}: a password is required for the 'Internal Users' password store")
    if expired(body):
        blockers.append(
            f"{spec.name}: expiry_date {body['expiryDate']} is in the past (account born expired)"
        )
    return body, blockers


def user_preview(body: dict[str, Any], groups: list[str] | None) -> dict[str, Any]:
    """A user body without its secrets: which ones are set is listed instead."""
    shown: dict[str, Any] = {k: v for k, v in body.items() if k not in (*USER_SECRETS, "identityGroups")}
    if groups is not None:
        shown["groups"] = groups
    given = [
        label for key, label in (("password", "password"), ("enablePassword", "enable")) if body.get(key)
    ]
    if given:
        shown["credentials_set"] = given
    out: dict[str, Any] = compact(shown)
    return out


def user_update_body(
    current: dict[str, Any], patch: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], list[str], list[str]]:
    """(PUT body, masked changes, blockers, side effects) for an update of `current` by `patch`."""
    desired = deep_merge(current, patch)
    for key in USER_SECRETS:
        if key not in patch:
            desired.pop(key, None)  # placeholder (or absent): ISE keeps the stored value
    if "password" not in patch and "passwordIDStore" not in patch:
        desired.pop("passwordIDStore", None)  # ISE keeps it; sending it alone has asked for a password
    shown = {k: v for k, v in current.items() if k in desired}
    name = current.get("name")
    blockers = store_problems(desired)
    old_store = current.get("passwordIDStore") or INTERNAL_STORE
    if patch.get("passwordIDStore") == INTERNAL_STORE != old_store and "password" not in patch:
        blockers.append(f"{name}: moving the password store to 'Internal Users' needs a password")
    side: list[str] = []
    if expired(patch):
        side.append(f"{name} is expired from now on ({patch['expiryDate']} is past): its logins fail")
    if patch.get("enabled") is False:
        side.append(f"{name} can no longer authenticate (802.1X/PAP/TACACS+)")
    return desired, masked_changes(shown, desired, replace=True), blockers, side


def without_secrets(text: str, *secrets: str | None) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, MASK)
    return text


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
        trustsec_id: Annotated[
            str | None,
            Field(
                description="TrustSec device id: enables TrustSec on the device (with trustsec_password). "
                "Must equal 'cts credentials id' on the switch"
            ),
        ] = None,
        trustsec_password: Annotated[
            str | None,
            Field(description="TrustSec device password ('cts credentials ... password' on the switch)"),
        ] = None,
        trustsec_push: Annotated[
            bool | None,
            Field(
                description="Send TrustSec policy changes to the device by CoA (ise_push_trustsec_matrix "
                "relies on it); on by default when TrustSec is first enabled"
            ),
        ] = None,
        trustsec_rest_user: Annotated[
            str | None,
            Field(
                description="HTTP REST API username for the TrustSec HTTPS policy download: what the switch "
                "sends in 'cts policy-server username' (needs TrustSec on the device and ISE's TrustSec "
                "HTTPS server, ise_set_trustsec_settings)"
            ),
        ] = None,
        trustsec_rest_password: Annotated[
            str | None, Field(description="HTTP REST API password ('cts policy-server ... password')")
        ] = None,
        trustsec_push_id: Annotated[
            bool | None,
            Field(
                description="Push ID support: ISE tags its TrustSec CoAs with a push id and the device "
                "reports each policy download back (what fills ise_trustsec_device_report); needs a "
                "device with PUSH ID (HTTPS) support (IOS XE 26.2.1+, REST API v3)"
            ),
        ] = None,
        remove_radius: Annotated[
            bool,
            Field(
                description="Switch RADIUS off on the device (e.g. back to TACACS+ only); the stored "
                "TACACS+ key is kept without passing it. Not with radius_secret"
            ),
        ] = False,
        remove_tacacs: Annotated[
            bool,
            Field(
                description="Switch TACACS+ off on the device (RADIUS only); the stored RADIUS secret is "
                "kept. Not with tacacs_secret"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a network device: IPs, shared secrets, device groups, description, CoA port, name,
        switch RADIUS or TACACS+ off (remove_radius / remove_tacacs, keeping the other protocol's stored
        key), or
        TrustSec settings: device id/password (what the switch presents in 'cts credentials' to get a PAC
        and download environment data and policy; defaults for the refresh timers and CoA-based updates
        are set the first time), the HTTP REST API username/password for the HTTPS policy download
        ('cts policy-server' on IOS-XE) and push id support (the device reports its downloads, which is
        what ise_trustsec_device_report shows). Only the given fields change. Preview-first, showing a
        field-by-field diff (secrets shown only as changed). Changing a secret breaks RADIUS until the
        device is updated to match."""
        app: IseApp = get_client(ctx)
        current = await resolve_nad(app, device)
        patch: dict[str, Any] = {}
        blockers: list[str] = []
        trustsec_args = (
            trustsec_id,
            trustsec_password,
            trustsec_push,
            trustsec_rest_user,
            trustsec_rest_password,
            trustsec_push_id,
        )
        if any(a is not None for a in trustsec_args):
            existing = current.get("trustsecsettings") or {}
            auth_settings = dict(existing.get("deviceAuthenticationSettings") or {})
            if trustsec_id is not None:
                auth_settings["sgaDeviceId"] = trustsec_id
            if trustsec_password is not None:
                auth_settings["sgaDevicePassword"] = trustsec_password
            if not auth_settings.get("sgaDeviceId") or not auth_settings.get("sgaDevicePassword"):
                blockers.append("TrustSec needs both trustsec_id and trustsec_password the first time")
            if trustsec_rest_user is not None:
                auth_settings["restApiUsername"] = trustsec_rest_user
            if trustsec_rest_password is not None:
                auth_settings["restApiPassword"] = trustsec_rest_password
            if (trustsec_rest_user is not None or trustsec_rest_password is not None) and not (
                auth_settings.get("restApiUsername") and auth_settings.get("restApiPassword")
            ):
                blockers.append(
                    "The REST API credentials need both trustsec_rest_user and trustsec_rest_password the "
                    "first time"
                )
            trustsec = deep_merge(
                TRUSTSEC_NAD_DEFAULTS if not existing else {},
                {**existing, "deviceAuthenticationSettings": auth_settings},
            )
            if trustsec_push is not None:
                trustsec = deep_merge(
                    trustsec,
                    {
                        "sgaNotificationAndUpdates": {
                            "sendConfigurationToDevice": trustsec_push,
                            "sendConfigurationToDeviceUsing": "ENABLE_USING_COA",
                        }
                    },
                )
            if trustsec_push_id is not None:
                trustsec["pushIdSupport"] = "true" if trustsec_push_id else "false"  # ERS keeps it a string
            patch["trustsecsettings"] = trustsec
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
        if new_name is not None:
            patch["name"] = new_name
            if new_name != current.get("name") and await exists(app, "networkdevice", new_name):
                blockers.append(f"A network device named {new_name!r} already exists")
        if not patch and not remove_radius and not remove_tacacs:
            raise InvalidRequest("Nothing to change: give at least one field")
        desired = deep_merge(current, patch)
        side = ["RADIUS from this device fails until its secret matches"] if radius_secret is not None else []
        removed = nad_protocol_removals(
            current,
            desired,
            remove_radius=remove_radius,
            remove_tacacs=remove_tacacs,
            radius_secret=radius_secret,
            tacacs_secret=tacacs_secret,
            blockers=blockers,
            side_effects=side,
        )
        changes = masked_changes(current, desired, replace=True)  # ERS PUT replaces
        details: dict[str, Any] = {"changes": changes}
        noop = unchanged(changes, radius_secret, tacacs_secret, trustsec_password, trustsec_rest_password)
        if removed:
            details["removed"] = [f"{p} removed (secret was set)" for p in removed]

        async def apply() -> Any:
            result = await ers_put(app, "networkdevice", "NetworkDevice", desired)
            if removed:
                await check_protocols_removed(app, str(desired["id"]), removed)
            return result

        plan = Plan(
            f"Update network device {current.get('name')}",
            details=details,
            fingerprint=fingerprint(current),
            side_effects=[] if noop else side,
            blockers=blockers,
            noop=noop,
            noop_reason=f"Network device {current.get('name')} already as requested" if noop else None,
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
                "trustsec_id": trustsec_id,
                "trustsec_password": trustsec_password,
                "trustsec_push": trustsec_push,
                "trustsec_rest_user": trustsec_rest_user,
                "trustsec_rest_password": trustsec_rest_password,
                "trustsec_push_id": trustsec_push_id,
                "remove_radius": remove_radius,
                "remove_tacacs": remove_tacacs,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
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
            str | None,
            Field(
                description="Initial password (ISE password policy applies; never echoed). Required for "
                "the 'Internal Users' password store"
            ),
        ] = None,
        groups: Annotated[
            list[str] | None, Field(description="Identity group names (see ise_list_identity_groups)")
        ] = None,
        email: Annotated[str | None, Field(description="Email address")] = None,
        first_name: Annotated[str | None, Field(description="First name")] = None,
        last_name: Annotated[str | None, Field(description="Last name")] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        enabled: Annotated[bool, Field(description="Whether the account can authenticate")] = True,
        expiry_date: Annotated[
            str | None,
            Field(description="Account expiry date 'YYYY-MM-DD' (contractor/lab accounts); none by default"),
        ] = None,
        change_password_on_login: Annotated[
            bool, Field(description="Force a password change at the first login")
        ] = False,
        password_never_expires: Annotated[
            bool | None, Field(description="Exempt the password from ISE's password lifetime policy")
        ] = None,
        password_store: Annotated[
            str | None,
            Field(
                description="Where the password is checked: 'Internal Users' (default) or an AD join "
                "point / LDAP server name (the user is then AD-backed and needs no password here)"
            ),
        ] = None,
        enable_password: Annotated[
            str | None,
            Field(description="TACACS+ enable password for device admin accounts (never echoed)"),
        ] = None,
        custom_attributes: Annotated[
            dict[str, str] | None, Field(description="User custom attribute values by name")
        ] = None,
        account_name_alias: Annotated[
            str | None, Field(description="Account name alias (ISE mails password-expiry notices to it)")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a user in the ISE internal identity store (for 802.1X/PAP/TACACS+ logins), in the given
        identity groups, with optional lifecycle settings: an account expiry date, change password at
        first login, password never expires, an AD/LDAP-backed password, and a TACACS+ enable password.
        Preview-first; passwords are never shown (the preview lists which are set). Blocked if the
        username exists. For many users use ise_bulk_internal_users."""
        app: IseApp = get_client(ctx)
        spec = InternalUserSpec(
            name=name,
            password=password,
            enable_password=enable_password,
            groups=groups,
            email=email,
            first_name=first_name,
            last_name=last_name,
            description=description,
            enabled=enabled,
            expiry_date=expiry_date,
            change_password_on_login=change_password_on_login,
            password_never_expires=password_never_expires,
            password_store=password_store,
            custom_attributes=custom_attributes,
            account_name_alias=account_name_alias,
        )
        body, blockers = user_create_body(spec, await user_patch(app, spec))
        if await exists(app, "internaluser", name):
            blockers.insert(0, f"User {name!r} already exists")
        return await preview_or_apply(
            ctx,
            tool="ise_create_internal_user",
            args=spec.model_dump(),
            confirm=confirm,
            plan=Plan(
                f"Create internal user {name}",
                details=user_preview(body, groups or []),
                blockers=blockers,
            ),
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
        first_name: Annotated[str | None, Field(description="New first name")] = None,
        last_name: Annotated[str | None, Field(description="New last name")] = None,
        expiry_date: Annotated[
            str | None,
            Field(description="Account expiry date 'YYYY-MM-DD'; '' or 'never' removes the expiry"),
        ] = None,
        change_password_on_login: Annotated[
            bool | None, Field(description="Force a password change at the next login")
        ] = None,
        password_never_expires: Annotated[
            bool | None, Field(description="Exempt the password from ISE's password lifetime policy")
        ] = None,
        password_store: Annotated[
            str | None,
            Field(description="'Internal Users' or an AD join point / LDAP server name"),
        ] = None,
        enable_password: Annotated[
            str | None, Field(description="Set the TACACS+ enable password (never echoed)")
        ] = None,
        custom_attributes: Annotated[
            dict[str, str] | None,
            Field(description="User custom attribute values to set (merged into the existing ones)"),
        ] = None,
        account_name_alias: Annotated[str | None, Field(description="New account name alias")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Enable/disable an internal user, reset their password or enable password, set or remove the
        account expiry date, force a password change at next login, or change groups, names, email,
        description, password store and custom attributes. Only the given fields change; stored
        passwords are kept unless a new one is given. Preview-first with a diff (passwords shown only
        as changed)."""
        app: IseApp = get_client(ctx)
        current = await ers_resolve(
            app, "internaluser", user, what="internal user", list_tool="ise_list_internal_users"
        )
        spec = InternalUserSpec(
            name=str(current.get("name")),
            password=password,
            enable_password=enable_password,
            groups=groups,
            email=email,
            first_name=first_name,
            last_name=last_name,
            description=description,
            enabled=enabled,
            expiry_date=expiry_date,
            change_password_on_login=change_password_on_login,
            password_never_expires=password_never_expires,
            password_store=password_store,
            custom_attributes=custom_attributes,
            account_name_alias=account_name_alias,
        )
        patch = await user_patch(app, spec)
        if not patch:
            raise InvalidRequest("Nothing to change: give at least one field")
        desired, changes, blockers, side = user_update_body(current, patch)
        plan = Plan(
            f"Update internal user {current.get('name')}",
            details={"changes": changes},  # ERS PUT replaces
            blockers=blockers,
            side_effects=side,
            fingerprint=fingerprint(current),
        )
        return await preview_or_apply(
            ctx,
            tool="ise_update_internal_user",
            args={"user": user, **spec.model_dump(exclude={"name"})},
            confirm=confirm,
            plan=plan,
            apply=lambda: ers_put(app, "internaluser", "InternalUser", desired),
        )

    @reg.write(title="Bulk create, update or delete internal users", destructive=True)
    async def ise_bulk_internal_users(  # noqa: C901 - one preview for three actions
        ctx: Context,
        action: Annotated[
            Literal["create", "update", "delete"],
            Field(description="create new users, update existing ones (only the given fields), or delete"),
        ],
        users: Annotated[
            list[InternalUserSpec],
            Field(
                description="Users, same fields as ise_create_internal_user (delete: only the name)",
                min_length=1,
            ),
        ],
        max_items: Annotated[
            int,
            Field(ge=1, le=USER_BULK_MAX, description="Refuse requests larger than this (safety cap)"),
        ] = 200,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create, update or delete many internal users with one preview, such as a batch of contractor
        accounts with an expiry date or a cleanup. ERS has no bulk endpoint for users, so the confirm
        runs one ERS call per user in order and reports a result per user; a failure does not stop
        the rest. Preview-first: counts, a sample, problems (unknown group, bad date, missing
        password) and conflicts (create: the user exists; update/delete: unknown user), which are
        left out of the run. Passwords are never shown. At most 500 users per call."""
        app: IseApp = get_client(ctx)
        seen: dict[str, InternalUserSpec] = {}
        blockers: list[str] = []
        for u in users:
            key = u.name.strip().lower()
            if not key:
                blockers.append("A user without a name")
                continue
            if key in seen:
                if seen[key] != u:
                    blockers.append(f"{u.name} is listed more than once with different settings")
                continue
            seen[key] = u
        if len(seen) > max_items:
            blockers.append(
                f"{len(seen)} users exceed max_items={max_items}; split the request or raise max_items"
            )

        names = [u.name for u in seen.values()]
        found = await gather_limited(names, lambda n: app.ers_find("internaluser", n))
        hits = dict(zip(names, found, strict=True))
        conflicts = [n for n in names if (hits[n] is not None) == (action == "create")]
        todo = [seen[n.strip().lower()] for n in names if n not in conflicts]

        problems: list[str] = []
        work: list[dict[str, Any]] = []  # per user: name, method, path, body
        rows: list[dict[str, Any]] = []
        unchanged: list[str] = []
        currents: list[dict[str, Any]] = []
        if action == "delete":
            for u in todo:
                hit = hits[u.name] or {}
                work.append({"name": u.name, "method": "DELETE", "id": str(hit.get("id"))})
                rows.append({"name": u.name})
        else:
            fulls: list[dict[str, Any]] = []
            if action == "update":
                fulls = await gather_limited(
                    todo, lambda u: app.ers_get("internaluser", str((hits[u.name] or {}).get("id")))
                )
            for i, u in enumerate(todo):
                try:
                    patch = await user_patch(app, u)
                except (InvalidRequest, NotFound) as e:
                    problems.append(f"{u.name}: {e}")
                    continue
                if action == "create":
                    body, item_blockers = user_create_body(u, patch)
                    problems += item_blockers
                    work.append({"name": u.name, "method": "POST", "body": body, "spec": u})
                    rows.append(user_preview(body, u.groups))
                    continue
                current = fulls[i]
                currents.append(current)
                desired, changes, item_blockers, side = user_update_body(current, patch)
                problems += item_blockers
                if not changes:
                    unchanged.append(u.name)
                    continue
                work.append(
                    {"name": u.name, "method": "PUT", "body": desired, "spec": u, "id": str(current["id"])}
                )
                rows.append({"name": u.name, "changes": changes, **({"side_effects": side} if side else {})})
        if problems:
            blockers += problems[:10]
            if len(problems) > 10:
                blockers.append(f"... and {len(problems) - 10} more problems")
        if not work and not blockers:
            blockers.append(
                "Nothing to do: every user "
                + {"create": "already exists", "update": "is unknown or unchanged", "delete": "is unknown"}[
                    action
                ]
            )

        details: dict[str, Any] = {
            "action": action,
            "users_in_run": len(work),
            "sample": rows[:USER_BULK_SAMPLE],
        }
        if len(rows) > USER_BULK_SAMPLE:
            details["more_users"] = [r["name"] for r in rows[USER_BULK_SAMPLE:]][:50]
        if conflicts:
            details["left_out_conflicts"] = {
                "reason": "already exists" if action == "create" else "not found in ISE",
                "count": len(conflicts),
                "names": conflicts[:20],
            }
        if unchanged:
            details["left_out_unchanged"] = unchanged[:20]
        side_effects = {
            "create": ["Each user can authenticate as soon as it is created (unless disabled)"],
            "update": ["Changes apply at each user's next authentication"],
            "delete": ["Deleted users can no longer authenticate; their sessions stay until reauth"],
        }[action]
        plan = Plan(
            f"Bulk {action} of {len(work)} internal user(s)",
            details=details,
            blockers=blockers,
            side_effects=side_effects,
            fingerprint=fingerprint([[w["name"] for w in work], conflicts, currents]),
            blast_radius=len(work),  # users changed; bound with MCP_MAX_BLAST_RADIUS
        )

        async def apply() -> Any:
            results: list[dict[str, Any]] = []
            for w in work:
                spec: InternalUserSpec | None = w.get("spec")
                try:
                    if w["method"] == "POST":
                        out = await ers_post(app, "internaluser", "InternalUser", w["body"])
                        results.append({"name": w["name"], "status": "created", "id": out.get("id")})
                    elif w["method"] == "PUT":
                        await ers_put(app, "internaluser", "InternalUser", w["body"])
                        results.append({"name": w["name"], "status": "updated"})
                    else:
                        await app.ers_request("DELETE", f"/ers/config/internaluser/{quote(w['id'], safe='')}")
                        results.append({"name": w["name"], "status": "deleted"})
                except ToolError as e:
                    secrets = (spec.password, spec.enable_password) if spec else ()
                    results.append(
                        {"name": w["name"], "status": "failed", "error": without_secrets(str(e), *secrets)}
                    )
            failed = [r for r in results if r["status"] == "failed"]
            return {
                "action": action,
                "total": len(results),
                "succeeded": len(results) - len(failed),
                "failed": len(failed),
                "results": results,
            }

        return await preview_or_apply(
            ctx,
            tool="ise_bulk_internal_users",
            args={"action": action, "users": [u.model_dump() for u in users], "max_items": max_items},
            confirm=confirm,
            plan=plan,
            apply=apply,
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

    def _av_pair(spec: str) -> dict[str, Any]:
        """'Cisco:cisco-av-pair=Role=OBSERVER-ROLE' -> an ERS advanced attribute (ERS spells the keys
        'leftHandSideDictionaryAttribue' / 'rightHandSideAttribueValue')."""
        lhs, sep, value = spec.partition("=")
        dictionary, colon, attribute = lhs.strip().partition(":")
        if not sep or not colon or not dictionary.strip() or not attribute.strip() or not value.strip():
            raise InvalidRequest(
                f"av_pairs entry {spec!r}: use 'Dictionary:attribute=value', e.g. "
                "'Cisco:cisco-av-pair=Role=OBSERVER-ROLE'."
            )
        return {
            "leftHandSideDictionaryAttribue": {
                "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
                "dictionaryName": dictionary.strip(),
                "attributeName": attribute.strip(),
            },
            "rightHandSideAttribueValue": {
                "AdvancedAttributeValueType": "AttributeValue",
                "value": value.strip(),
            },
        }

    def _is_sdwan_group(adv: dict[str, Any]) -> bool:
        lhs = adv.get("leftHandSideDictionaryAttribue") or {}
        return (
            str(lhs.get("dictionaryName")).lower() == SDWAN_DICTIONARY.lower()
            and str(lhs.get("attributeName")).lower() == SDWAN_ATTRIBUTE.lower()
        )

    async def _profile_body(
        app: IseApp,
        *,
        access: str | None,
        vlan: str | None,
        dacl: str | None,
        reauth_seconds: int | None,
        voice_domain: bool | None,
        description: str | None,
        ipv6_dacl: str | None = None,
        airespace_acl: str | None = None,
        interface_template: str | None = None,
        auto_smart_port: str | None = None,
        macsec_policy: str | None = None,
        neat: bool | None = None,
        web_auth: bool | None = None,
        track_movement: bool | None = None,
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
        if ipv6_dacl:
            if not await exists(app, "downloadableacl", ipv6_dacl):
                raise NotFound(f"No dACL named {ipv6_dacl!r} (ipv6_dacl); see ise_list_dacls.", 404)
            body["ipv6DaclName"] = ipv6_dacl
        for key, value in (
            ("airespaceACL", airespace_acl),
            ("interfaceTemplate", interface_template),
            ("autoSmartPort", auto_smart_port),
            ("macSecPolicy", macsec_policy),
        ):
            if value:
                body[key] = value.strip()
        for key, flag in (("neat", neat), ("webAuth", web_auth), ("trackMovement", track_movement)):
            if flag is not None:
                body[key] = flag
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
        av_pairs: Annotated[
            list[str] | None,
            Field(
                description="Advanced attributes as 'Dictionary:attribute=value', e.g. "
                "'Cisco:cisco-av-pair=Role=OBSERVER-ROLE' (Catalyst Center admin role) or "
                "'Radius:Session-Timeout=3600'; the value is everything after the first '='. Checked "
                "against ISE's dictionaries"
            ),
        ] = None,
        sdwan_group: Annotated[
            str | None,
            Field(
                description="Catalyst SD-WAN user group for an SD-WAN Manager/edge admin login, e.g. "
                "'netadmin' or 'operator': adds 'Viptela:Viptela-Group-Name=<group>' (the Viptela "
                "dictionary must exist in ISE; the preview names the GUI step if not)"
            ),
        ] = None,
        redirect: Annotated[
            Redirect | None,
            Field(
                description="Web redirection: {type, acl, portal, static_host}; e.g. guest CWA = {type: "
                "'CentralizedWebAuth', acl: 'ACL-REDIRECT', portal: 'Sponsored Guest Portal (default)'}"
            ),
        ] = None,
        interface_template: InterfaceTemplateArg = None,
        auto_smart_port: AutoSmartPortArg = None,
        macsec_policy: MacsecArg = None,
        neat: NeatArg = None,
        web_auth: WebAuthArg = None,
        airespace_acl: AirespaceAclArg = None,
        ipv6_dacl: Ipv6DaclArg = None,
        track_movement: TrackMovementArg = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an authorization profile (what an authorization rule grants): access type, VLAN, dACL,
        reauth timer, voice domain, advanced attributes, web redirection (guest CWA, hotspot, BYOD/NSP or
        client provisioning) and the switch/WLC common tasks (interface template, Auto Smart Port,
        MACsec policy, NEAT, local web auth, Airespace ACL, IPv6 dACL, track movement).

        Advanced attributes: av_pairs, e.g. cisco-av-pair=Role=<role> for a Catalyst Center admin
        login; sdwan_group for Viptela-Group-Name, the SD-WAN Manager admin group. Redirect: the redirect
        ACL (configured on the NAD) and a portal of the matching kind. Preview-first; blocked if the name
        exists, an attribute is not in ISE's dictionaries or the portal does not fit the redirect type.
        Use it in a rule with ise_create_authz_rule."""
        app: IseApp = get_client(ctx)
        advanced = [_av_pair(a) for a in av_pairs or []]
        if sdwan_group is not None:
            advanced = [a for a in advanced if not _is_sdwan_group(a)]
            advanced.append(
                _av_pair(f"{SDWAN_DICTIONARY}:{SDWAN_ATTRIBUTE}={valid_sdwan_group(sdwan_group)}")
            )
        av_blockers, av_warnings = await check_av_pairs(app, advanced)
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
                ipv6_dacl=ipv6_dacl,
                airespace_acl=airespace_acl,
                interface_template=interface_template,
                auto_smart_port=auto_smart_port,
                macsec_policy=macsec_policy,
                neat=neat,
                web_auth=web_auth,
                track_movement=track_movement,
            ),
        }
        if advanced:
            body["advancedAttributes"] = advanced
        redirect_blockers: list[str] = []
        side_effects = list(av_warnings)
        if redirect is not None:
            body["webRedirection"], redirect_blockers, redirect_warnings = await redirect_body(app, redirect)
            side_effects += redirect_warnings
        side_effects += common_task_warnings(body)
        blockers = (
            ([f"Profile {name!r} already exists"] if await exists(app, "authorizationprofile", name) else [])
            + av_blockers
            + redirect_blockers
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
                "av_pairs": av_pairs,
                "sdwan_group": sdwan_group,
                "redirect": redirect.model_dump() if redirect else None,
                "interface_template": interface_template,
                "auto_smart_port": auto_smart_port,
                "macsec_policy": macsec_policy,
                "neat": neat,
                "web_auth": web_auth,
                "airespace_acl": airespace_acl,
                "ipv6_dacl": ipv6_dacl,
                "track_movement": track_movement,
            },
            confirm=confirm,
            plan=Plan(
                f"Create authorization profile {name}",
                details=body,
                blockers=blockers,
                side_effects=side_effects,
            ),
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
        av_pairs: Annotated[
            list[str] | None,
            Field(
                description="Replace the advanced attributes with these 'Dictionary:attribute=value' "
                "entries ([] removes them all); checked against ISE's dictionaries"
            ),
        ] = None,
        sdwan_group: Annotated[
            str | None,
            Field(
                description="Set the Catalyst SD-WAN user group (Viptela:Viptela-Group-Name), keeping the "
                "other advanced attributes ('' removes it)"
            ),
        ] = None,
        redirect: Annotated[
            Redirect | Literal[""] | None,
            Field(
                description="Replace the web redirection with {type, acl, portal, static_host} ('' removes "
                "it); the portal must fit the type"
            ),
        ] = None,
        interface_template: Annotated[
            str | None, Field(description="Interface template name ('' to remove)")
        ] = None,
        auto_smart_port: Annotated[
            str | None, Field(description="Auto Smart Port event name ('' to remove)")
        ] = None,
        macsec_policy: Annotated[
            MacsecPolicy | Literal[""] | None, Field(description="MACsec policy ('' to remove)")
        ] = None,
        neat: NeatArg = None,
        web_auth: WebAuthArg = None,
        airespace_acl: Annotated[str | None, Field(description="Airespace ACL name ('' to remove)")] = None,
        ipv6_dacl: Annotated[str | None, Field(description="IPv6 dACL name ('' to remove)")] = None,
        track_movement: TrackMovementArg = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change an authorization profile's access type, VLAN, dACL, reauth timer, voice domain,
        description, advanced attributes (av_pairs; sdwan_group for the SD-WAN Manager admin group), web
        redirection (redirect) or common tasks (interface template, Auto Smart Port, MACsec, NEAT, local
        web auth, Airespace ACL, IPv6 dACL, track movement). The preview lists the rules that use the
        profile (they're all affected at the next authentication)."""
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
            ipv6_dacl=ipv6_dacl or None,
            airespace_acl=airespace_acl,
            interface_template=interface_template,
            auto_smart_port=auto_smart_port,
            macsec_policy=macsec_policy,
            neat=neat,
            web_auth=web_auth,
            track_movement=track_movement,
        )
        desired = deep_merge(current, patch)
        for value, key in (
            (vlan, "vlan"),
            (dacl, "daclName"),
            (ipv6_dacl, "ipv6DaclName"),
            (airespace_acl, "airespaceACL"),
            (interface_template, "interfaceTemplate"),
            (auto_smart_port, "autoSmartPort"),
            (macsec_policy, "macSecPolicy"),
            (redirect, "webRedirection"),
        ):
            if value == "":
                desired.pop(key, None)
        redirect_blockers: list[str] = []
        redirect_warnings: list[str] = []
        if isinstance(redirect, Redirect):
            # Replaced whole: a stale portal or static host from another type would be refused.
            new_redirect, redirect_blockers, redirect_warnings = await redirect_body(app, redirect)
            desired["webRedirection"] = same_redirect_keys(new_redirect, current.get("webRedirection"))
        av_blockers: list[str] = []
        av_warnings: list[str] = []
        if av_pairs is not None or sdwan_group is not None:
            advanced = (
                [_av_pair(a) for a in av_pairs]
                if av_pairs is not None
                else [dict(a) for a in current.get("advancedAttributes") or [] if isinstance(a, dict)]
            )
            if sdwan_group is not None:
                advanced = [a for a in advanced if not _is_sdwan_group(a)]
                if sdwan_group != "":
                    advanced.append(
                        _av_pair(f"{SDWAN_DICTIONARY}:{SDWAN_ATTRIBUTE}={valid_sdwan_group(sdwan_group)}")
                    )
            # Only new entries are checked: attributes already on the profile are ISE's own.
            existing = {av_pair_text(a) for a in current.get("advancedAttributes") or []}
            av_blockers, av_warnings = await check_av_pairs(
                app, [a for a in advanced if av_pair_text(a) not in existing]
            )
            if advanced:
                desired["advancedAttributes"] = advanced
            else:
                desired.pop("advancedAttributes", None)
        noop = desired == current
        users = [] if noop else await rules_using_profile(app, str(current.get("name")))
        plan = Plan(
            f"Update authorization profile {current.get('name')}",
            details={"changes": field_changes(current, desired, replace=True), "used_by_rules": users},
            fingerprint=fingerprint(current),
            blockers=av_blockers + redirect_blockers,
            side_effects=[]
            if noop
            else ([f"Affects {len(users)} rule(s) at the next authentication"] if users else [])
            + av_warnings
            + redirect_warnings
            + common_task_warnings(desired, current),
            noop=noop,
            noop_reason=f"Authorization profile {current.get('name')} already as requested" if noop else None,
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
                "av_pairs": av_pairs,
                "sdwan_group": sdwan_group,
                "redirect": redirect.model_dump() if isinstance(redirect, Redirect) else redirect,
                "interface_template": interface_template,
                "auto_smart_port": auto_smart_port,
                "macsec_policy": macsec_policy,
                "neat": neat,
                "web_auth": web_auth,
                "airespace_acl": airespace_acl,
                "ipv6_dacl": ipv6_dacl,
                "track_movement": track_movement,
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
            noop = desired == current
            plan = Plan(
                f"Update dACL {name}",
                details={"changes": field_changes(current, desired, replace=True)},
                fingerprint=fingerprint(current),
                noop=noop,
                noop_reason=f"dACL {name} already has exactly these ACEs and settings" if noop else None,
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
            changes = field_changes(current, desired, replace=True)
            noop = unchanged(changes)
            side = (
                ["Re-tags all traffic using this SGT; devices must refresh their policy"]
                if "value" in changes
                else []
            )
            plan = Plan(
                f"Update SGT {name}",
                details={"changes": changes},
                fingerprint=fingerprint(current),
                side_effects=side,
                noop=noop,
                noop_reason=f"SGT {name} already as requested (value {current.get('value')})"
                if noop
                else None,
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
        status: Annotated[
            CellStatus | None,
            Field(
                description="Cell status: ENABLED (enforced), MONITOR (devices count SGACL hits but let the "
                "traffic through: the step before enforcing) or DISABLED. Default: ENABLED for a new "
                "cell, unchanged for an existing one"
            ),
        ] = None,
        enabled: Annotated[
            bool | None,
            Field(description="Deprecated: use status. true = ENABLED, false = DISABLED"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set the TrustSec policy for traffic from one SGT to another (one egress matrix cell): which
        SGACLs apply, the final catch-all, and the cell status (ENABLED, MONITOR or DISABLED). Creates the
        cell or replaces it. A TrustSec rollout sets cells to MONITOR first, reads the monitored hits
        ('show cts role-based counters'), then ENABLED; the ANY-ANY default is ise_set_default_egress_rule.
        Devices enforce it after they refresh policy (or ise_push_trustsec_matrix). Preview-first with a
        diff."""
        app: IseApp = get_client(ctx)
        cell_status = resolve_cell_status(status, enabled)
        if source_sgt.strip().upper() == "ANY" and destination_sgt.strip().upper() == "ANY":
            raise InvalidRequest(
                "ANY -> ANY is the matrix default; change it with ise_set_default_egress_rule "
                "(dangerous tier)"
            )
        src, dst, current = await find_egress_cell(app, source_sgt, destination_sgt)
        # A built-in catch-all named in sgacls is the rule itself, not an SGACL (#131).
        real_names, blockers = split_catch_all(sgacls, default_rule)
        acl_ids = await group_ids(app, "sgacl", real_names, "SGACL", "ise_list_sgacls")
        multi = await multiple_sgacls_blocker(app, len(acl_ids), default_rule)
        if multi:
            blockers.append(multi)
        body: dict[str, Any] = {
            "sourceSgtId": src["id"],
            "destinationSgtId": dst["id"],
            "matrixCellStatus": cell_status or "ENABLED",
            "defaultRule": default_rule,
            "sgacls": acl_ids,
        }
        if current and cell_status is None:
            body["matrixCellStatus"] = current.get("matrixCellStatus") or "ENABLED"
        args = {
            "source_sgt": source_sgt,
            "destination_sgt": destination_sgt,
            "sgacls": sgacls,
            "default_rule": default_rule,
            "status": status,
            "enabled": enabled,
        }
        summary = (
            f"{source_sgt} -> {destination_sgt}: {', '.join(real_names) or '(no SGACL)'} then {default_rule}"
            f" ({body['matrixCellStatus']})"
        )
        if current:
            desired = deep_merge(current, body)
            # ISE's own catch-all entry is not an SGACL: leave it out of the diff (an empty list sent
            # leaves it in place, so the read-back still lists it).
            acl_names = await ers_name_map(app, "sgacl")
            shown = {**current, "sgacls": cell_sgacl_ids(current, acl_names)}
            side = []
            was, now = current.get("matrixCellStatus"), body["matrixCellStatus"]
            if was != now:
                side.append(f"Cell status {was} -> {now}")
                if now == "MONITOR":
                    side.append(
                        "Devices stop enforcing this cell: SGACL hits are counted ('show cts role-based "
                        "counters') and the traffic passes until the cell is ENABLED"
                    )
            side.append(PUSH_REMINDER)
            plan = Plan(
                f"Update egress cell {summary}",
                details={"changes": field_changes(shown, desired, replace=True)},
                fingerprint=fingerprint(current),
                blockers=blockers,
                side_effects=side,
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
            plan=Plan(
                f"Create egress cell {summary}", details=body, blockers=blockers, side_effects=[PUSH_REMINDER]
            ),
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
                "allowed_protocols",
                "egress_cell",
            ],
            Field(description="What to delete"),
        ],
        target: Annotated[
            str,
            Field(
                description="Name or id (a MAC for endpoints; for egress_cell 'SOURCE->DESTINATION' SGT "
                "names, e.g. 'Employees->Servers', or the cell id)"
            ),
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete one endpoint, internal user, identity/endpoint group, authorization profile, dACL, SGT,
        SGACL, device group, ANC policy, TACACS+ command set / shell profile / external server / server
        sequence, AD join point (after ise_leave_ad), sponsor group, guest type (guest accounts:
        ise_delete_guest_user), allowed-protocols service (blocked while a policy set selects it) or
        TrustSec egress matrix cell (its SGT pair then falls to the ANY-ANY default; the ANY-ANY cell itself
        is changed with ise_set_default_egress_rule, never deleted). Preview-first: shows
        the object and what still references it (the ise_where_used scan: rules, profiles, sequences,
        matrix cells, IP-SGT mappings, devices, members), which blocks the delete.
        Network devices and policy are deleted with the dangerous-tier tools."""
        app: IseApp = get_client(ctx)
        resource = DELETE_KINDS[kind]
        if kind == "egress_cell":
            return await delete_egress_cell(ctx, app, target, confirm)
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
        if kind == "ad_join_point":
            from ise_mcp.tools.ad import join_status  # noqa: PLC0415 - ad imports this module

            if (await join_status(app, current)).get("joined"):
                blockers.append(f"{name} is still joined to {current.get('domain')}: ise_leave_ad first")
        if kind in ("sponsor_group", "guest_type") and (
            current.get("isDefaultGroup") or current.get("isDefaultType")
        ):
            blockers.append(f"{name} is one of ISE's default {kind.replace('_', ' ')}s and can't be deleted")
        if kind == "sponsor_group":
            side.append("Its members can no longer sponsor guests (existing guest accounts stay)")
        if kind == "guest_type":
            side.append("Sponsors can no longer create this type; ISE refuses while guest accounts use it")
        if kind == "allowed_protocols" and name.lower() in DEFAULT_SERVICES:
            blockers.append(f"{name} is one of ISE's default allowed-protocols services and can't be deleted")
        if kind in WHERE_USED_KINDS:
            from ise_mcp.tools.where_used import delete_blockers, find_references  # noqa: PLC0415 - cycle

            used, unchecked = delete_blockers(await find_references(app, kind, current))
            blockers += used
            side += unchecked
        blockers += await references(app, kind, current)
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

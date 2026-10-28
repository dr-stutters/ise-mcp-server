"""Reusable policy conditions (I57): ise_set_condition / ise_delete_condition for library, time-and-date and
network conditions, network access (RADIUS) and device admin (TACACS+).

ISE keeps three kinds of reusable condition, each with its own OpenAPI resource:

- library conditions (`/api/v1/policy/{kind}/condition`, read and updated by name): one attribute check
  or an AND/OR block of them, e.g. Wired_802.1X. Written in the same 'Dictionary:Attribute operator
  value' syntax as the rule tools, checked against the policy dictionaries before anything is sent.
- time-and-date conditions (`.../time-condition`): week days, hours and dates, plus exceptions.
- network conditions (`.../network-condition`): NADs, NAD IPs or subnets and device groups (device /
  device-port), or end-station IPs, MACs and CLI/DNIS (end station).

ISE 3.5 keeps one condition library for both policy kinds: an object created under network-access comes
back, with the same id, from the device-admin list too (the device-admin list leaves out library conditions
on RADIUS-only dictionaries). The export writes such an object once, with kind `shared`; writes go to the
kind's own path first and, on a 400, to the other kind's (a delete or update only works on some ISE builds
through the path that created the object). ISE also keeps a time condition's description on an update
(the PUT is accepted and the old description stays), so the update preview leaves it out and says so.

Rules refer to any of them by name. `condition_spec` / `condition_view` are shared with ise_export_config
and ise_import_config (the `conditions` section), so an export entry is exactly ise_set_condition's
arguments."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import ipaddress
import re
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastmcp import Context
from pydantic import BaseModel, ConfigDict, Field

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
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_name_map, normalize_mac, render_condition
from ise_mcp.tools.policy import PolicyKind
from ise_mcp.tools.policy_edit import build_condition, strip_links
from ise_mcp.tools.writes import fingerprint

ConditionType = Literal["library", "time", "network"]
NetworkMatch = Literal["device", "device-port", "endstation"]
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
LIBRARY_TYPES = {
    "ConditionAttributes": "LibraryConditionAttributes",
    "ConditionAndBlock": "LibraryConditionAndBlock",
    "ConditionOrBlock": "LibraryConditionOrBlock",
}
NETWORK_TYPES = {
    "device": "DeviceCondition",
    "device-port": "DevicePortCondition",
    "endstation": "EndstationCondition",
}
NETWORK_MATCH = {v: k for k, v in NETWORK_TYPES.items()}
# Network-condition list fields (ISE name) per tool field, and which match types allow each.
NETWORK_FIELDS = {
    "nads": ("deviceList", ("device", "device-port")),
    "ips": ("ipAddrList", ("device", "device-port", "endstation")),
    "ndgs": ("deviceGroupList", ("device", "device-port")),
    "macs": ("macAddrList", ("endstation",)),
    "cli_dnis": ("cliDnisList", ("endstation",)),
}
RESOURCE = {"library": "condition", "time": "time-condition", "network": "network-condition"}
SCOPES = ("authorization", "policyset", "authentication")
_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_DATE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$")
SHARED = "shared"  # export kind of a condition both policy kinds return with the same id
OTHER_KIND = {"network-access": "device-admin", "device-admin": "network-access"}
TIME_DESCRIPTION_NOTE = (
    "ISE keeps a time condition's description on an update (it accepts the PUT and the old description "
    "stays): change it in the GUI, or delete and re-create the condition"
)


class DateRange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: Annotated[str, Field(description="First date, YYYY-MM-DD")]
    end: Annotated[str, Field(description="Last date, YYYY-MM-DD (the same as start for one day)")]


class TimeWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    days: Annotated[
        list[str] | None, Field(description="Week days, e.g. ['Monday', 'Friday'] (default: every day)")
    ] = None
    start: Annotated[str | None, Field(description="Start time HH:MM, 24 h (default: all day)")] = None
    end: Annotated[str | None, Field(description="End time HH:MM, 24 h")] = None
    dates: Annotated[DateRange | None, Field(description="Only between these dates")] = None


class TimeSpec(TimeWindow):
    exclude: Annotated[
        TimeWindow | None,
        Field(description="When it does NOT match (days, hours, dates), e.g. a public holiday"),
    ] = None


class NetworkSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    match: Annotated[
        NetworkMatch,
        Field(
            description="device = the NAD (by name, IP/subnet or device group); device-port = NAD and "
            "port ('name,port' / 'ip,port' entries); endstation = the client (IPs, MACs, CLI/DNIS)"
        ),
    ] = "device"
    nads: Annotated[list[str], Field(description="NAD names (device-port: 'name,port')")] = []
    ips: Annotated[
        list[str], Field(description="IP addresses or subnets, e.g. 192.0.2.0/24 (device-port: 'ip,port')")
    ] = []
    ndgs: Annotated[
        list[str],
        Field(description="Device groups, e.g. 'Location#All Locations#Lab' (device-port: append ',port')"),
    ] = []
    macs: Annotated[
        list[str], Field(description="Endstation: 'client MAC' or 'client MAC,destination MAC'")
    ] = []
    cli_dnis: Annotated[list[str], Field(description="Endstation: 'CLI,DNIS' (Caller ID, Called ID)")] = []


ConditionTree = Annotated[
    list[Any] | None,
    Field(
        description="type=library: the checks, each 'Dictionary:Attribute operator value' (e.g. "
        "'Radius:NAS-Port-Type equals Ethernet', 'Network Access:Device IP Address ipEquals 192.0.2.1'), "
        "another library condition's name, 'NOT ...', or a nested {and|or: [...]} / {not: ...} block. "
        "Attributes are checked against ise_list_dictionary_attributes"
    ),
]


def _resp(data: Any) -> Any:
    return data.get("response", data) if isinstance(data, dict) else data


def q(value: Any) -> str:
    return quote(str(value), safe="")


# --- reading ------------------------------------------------------------------------------------


async def _items(app: IseApp, path: str) -> list[dict[str, Any]]:
    try:
        data = _resp(await app.openapi.get(path))
    except NotFound:
        return []
    return [c for c in data or [] if isinstance(c, dict)]


async def read_conditions(app: IseApp, kind: str) -> dict[str, list[dict[str, Any]]]:
    """{library, time, network}: every reusable condition of `kind`. Time and network conditions that the
    library list also returns are kept only under their own type."""
    base = f"/api/v1/policy/{kind}"
    time_c = await _items(app, f"{base}/time-condition")
    network = await _items(app, f"{base}/network-condition")
    own = {str(c.get("id")) for c in time_c + network if c.get("id")}
    library = [
        c
        for c in await _items(app, f"{base}/condition")
        if str(c.get("id")) not in own and c.get("conditionType") != "TimeAndDateCondition"
    ]
    return {"library": library, "time": time_c, "network": network}


def find(existing: dict[str, list[dict[str, Any]]], name: str) -> tuple[str, dict[str, Any]] | None:
    for ctype, items in existing.items():
        for c in items:
            if str(c.get("name", "")).lower() == name.lower():
                return ctype, c
    return None


# --- views (what the preview diffs and the export writes) ---------------------------------------


def library_spec(cond: dict[str, Any]) -> dict[str, Any]:
    """A library condition as ise_set_condition arguments: {conditions, match}."""
    from ise_mcp.tools.config_export import condition_text  # noqa: PLC0415 - config_export imports this

    ctype = str(cond.get("conditionType") or "")
    if ("AndBlock" in ctype or "OrBlock" in ctype) and not cond.get("isNegate"):
        return {
            "conditions": [condition_text(c) for c in cond.get("children") or []],
            "match": "all" if "AndBlock" in ctype else "any",
        }
    return {"conditions": [condition_text({**cond, "conditionType": ctype.replace("Library", "")})]}


def _window(c: dict[str, Any], suffix: str) -> dict[str, Any]:
    hours = c.get(f"hoursRange{suffix}") or {}
    dates = c.get(f"datesRange{suffix}") or {}
    days = sorted(c.get(f"weekDays{suffix}") or [], key=lambda d: WEEKDAYS.index(d) if d in WEEKDAYS else 9)
    out: dict[str, Any] = {}
    if days and (suffix or days != list(WEEKDAYS)):
        out["days"] = days
    if hours.get("startTime") or hours.get("endTime"):
        out["start"], out["end"] = hours.get("startTime"), hours.get("endTime")
    if dates.get("startDate") or dates.get("endDate"):
        out["dates"] = {"start": dates.get("startDate"), "end": dates.get("endDate")}
    return out


def time_spec(c: dict[str, Any]) -> dict[str, Any]:
    out = _window(c, "")
    exclude = _window(c, "Exception")
    if exclude:
        out["exclude"] = exclude
    return out


def ndg_from_api(value: str) -> str:
    """'Location,All Locations#Lab' (ISE: root, comma, group under it) -> 'Location#All Locations#Lab'."""
    root, sep, rest = value.partition(",")
    if not sep:
        return value
    port = ""
    if "," in rest:
        rest, _, port = rest.rpartition(",")
        port = f",{port}"
    return (rest if rest.lower().startswith(root.lower() + "#") else f"{root}#{rest}") + port


def ndg_to_api(value: str) -> str:
    """'Location#All Locations#Lab' -> 'Location,All Locations#Lab'; ',port' kept; a value already in
    ISE's 'root,group' form is sent as given."""
    path, sep, port = value.partition(",")
    if sep and "#" not in path:
        return value
    root, hash_, rest = path.partition("#")
    if not hash_:
        return value
    return f"{root},{rest}" + (f",{port}" if sep else "")


def network_spec(c: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"match": NETWORK_MATCH.get(str(c.get("conditionType")), "device")}
    for key, (api, _) in NETWORK_FIELDS.items():
        values = [str(v) for v in c.get(api) or []]
        if key == "ndgs":
            values = [ndg_from_api(v) for v in values]
        if values:
            out[key] = sorted(values, key=str.casefold)
    return out


def condition_view(ctype: str, c: dict[str, Any]) -> dict[str, Any]:
    """One condition as its type plus ise_set_condition's arguments (the export entry, minus kind)."""
    out: dict[str, Any] = {"name": c.get("name"), "type": ctype, "description": c.get("description") or None}
    if ctype == "library":
        out.update(library_spec(c))
    elif ctype == "time":
        out["time"] = time_spec(c)
    else:
        out["network"] = network_spec(c)
    return compact(out)  # type: ignore[no-any-return]


# --- building -----------------------------------------------------------------------------------


def _leaf_strings(tree: Any, out: list[str]) -> None:
    if isinstance(tree, str):
        out.append(tree)
    elif isinstance(tree, dict) and len(tree) == 1:
        ((op, value),) = tree.items()
        if op == "not":
            _leaf_strings(value, out)
        elif op in ("and", "or") and isinstance(value, list) and value:
            for v in value:
                _leaf_strings(v, out)
        else:
            raise InvalidRequest(f"Unrecognised condition {tree!r}: use {{and|or: [...]}} or {{not: ...}}")
    else:
        raise InvalidRequest(f"Unrecognised condition {tree!r} (a string or {{and|or|not: ...}})")


def _assemble(tree: Any, leaves: list[dict[str, Any]]) -> dict[str, Any]:
    if isinstance(tree, str):
        return leaves.pop(0)
    ((op, value),) = tree.items()
    if op == "not":
        node = _assemble(value, leaves)
        node["isNegate"] = not node.get("isNegate")
        return node
    return {
        "conditionType": "ConditionAndBlock" if op == "and" else "ConditionOrBlock",
        "isNegate": False,
        "children": [_assemble(v, leaves) for v in value],
    }


async def library_body(
    app: IseApp, kind: str, conditions: list[Any], match: str
) -> tuple[dict[str, Any], list[str]]:
    """The library condition body (without name/description) for a condition list, plus blockers. Each
    leaf is parsed and checked by the rule tools' parser; the dictionary scope that knows every attribute
    wins (library conditions are usable in policy sets, authentication and authorization rules)."""
    tree: Any = conditions[0] if len(conditions) == 1 else {"and" if match == "all" else "or": conditions}
    strings: list[str] = []
    _leaf_strings(tree, strings)
    best: tuple[dict[str, Any], list[str]] | None = None
    for scope in SCOPES:
        built, blockers = await build_condition(app, kind, scope, strings, "all")
        assert built is not None  # noqa: S101 - strings is never empty here
        if best is None or len(blockers) < len(best[1]):
            leaves = list(built["children"]) if len(strings) > 1 else [built]
            best = (_assemble(tree, leaves), blockers)
        if not blockers:
            break
    assert best is not None  # noqa: S101
    root, blockers = best
    ctype = str(root.get("conditionType"))
    if ctype == "ConditionReference":
        blockers = [
            *blockers,
            f"A library condition can't be just another library condition ({root.get('name')}); add a "
            "check or use that condition directly",
        ]
        return root, blockers
    return {**root, "conditionType": LIBRARY_TYPES[ctype]}, blockers


def _window_body(w: TimeWindow, suffix: str, blockers: list[str], label: str) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if w.days is not None:
        days = []
        for d in w.days:
            word = d.strip().lower()
            hit = next((x for x in WEEKDAYS if len(word) >= 3 and x.lower().startswith(word)), None)
            if hit is None:
                blockers.append(f"{label}: {d!r} is not a week day ({', '.join(WEEKDAYS)})")
            elif hit not in days:
                days.append(hit)
        if not w.days:
            blockers.append(f"{label}: days is empty (leave it out for every day)")
        body[f"weekDays{suffix}"] = sorted(days, key=WEEKDAYS.index)
    if (w.start is None) != (w.end is None):
        blockers.append(f"{label}: give both start and end (HH:MM), or neither for all day")
    elif w.start is not None and w.end is not None:
        for t in (w.start, w.end):
            if not _TIME.match(t):
                blockers.append(f"{label}: time {t!r} is not HH:MM (24 h)")
        body[f"hoursRange{suffix}"] = {"startTime": w.start, "endTime": w.end}
    if w.dates is not None:
        for d in (w.dates.start, w.dates.end):
            if not _DATE.match(d):
                blockers.append(f"{label}: date {d!r} is not YYYY-MM-DD")
        if w.dates.start > w.dates.end:
            blockers.append(f"{label}: dates end before they start")
        body[f"datesRange{suffix}"] = {"startDate": w.dates.start, "endDate": w.dates.end}
    return body


def time_body(spec: TimeSpec) -> tuple[dict[str, Any], list[str]]:
    blockers: list[str] = []
    body: dict[str, Any] = {"conditionType": "TimeAndDateCondition", "isNegate": False}
    body.update(_window_body(spec, "", blockers, "time"))
    body.setdefault("weekDays", list(WEEKDAYS))
    if spec.exclude is not None:
        exclude = _window_body(spec.exclude, "Exception", blockers, "time.exclude")
        if not exclude:
            blockers.append("time.exclude is empty: give days, start/end or dates")
        body.update(exclude)
    return body, blockers


def _check_ip(value: str) -> bool:
    try:
        ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return False
    return True


async def network_body(
    app: IseApp, spec: NetworkSpec, known_nads: set[str] | None = None, known_ndgs: set[str] | None = None
) -> tuple[dict[str, Any], list[str]]:
    """The network condition body plus blockers: entries that don't fit the match type, unknown NADs and
    device groups (`known_*`: names an import creates first), malformed IPs and MACs."""
    blockers: list[str] = []
    body: dict[str, Any] = {"conditionType": NETWORK_TYPES[spec.match]}
    port = spec.match == "device-port"
    for key, (api, allowed) in NETWORK_FIELDS.items():
        values = [v.strip() for v in getattr(spec, key) if v.strip()]
        if not values:
            continue
        if spec.match not in allowed:
            blockers.append(f"network.{key} doesn't apply to match={spec.match}")
            continue
        if port and any("," not in v for v in values):
            blockers.append(f"network.{key}: device-port entries are '<{key[:-1]}>,<port>'")
        body[api] = [ndg_to_api(v) for v in values] if key == "ndgs" else values
    if len(body) == 1:
        blockers.append(
            f"Give at least one of: {', '.join(k for k, (_, a) in NETWORK_FIELDS.items() if spec.match in a)}"
        )
    for ip in spec.ips:
        addr = ip.split(",")[0] if port else ip
        if not _check_ip(addr):
            blockers.append(f"network.ips: {ip!r} is not an IP address or subnet")
    for mac in spec.macs:
        for part in mac.split(","):
            try:
                normalize_mac(part)
            except (InvalidRequest, ValueError):
                blockers.append(f"network.macs: {mac!r} is not 'MAC' or 'MAC,destination MAC'")
                break
    if spec.nads:
        names = {n.lower() for n in (await ers_name_map(app, "networkdevice")).values()}
        names |= {n.lower() for n in known_nads or set()}
        for nad in spec.nads:
            name = nad.split(",")[0] if port else nad
            if name.strip().lower() not in names:
                blockers.append(f"No NAD named {name.strip()!r} (see ise_list_nads)")
    if spec.ndgs:
        groups = {n.lower() for n in (await ers_name_map(app, "networkdevicegroup")).values()}
        groups |= {n.lower() for n in known_ndgs or set()}
        for g in spec.ndgs:
            path = g.split(",")[0] if port else g
            if path.strip().lower() not in groups:
                blockers.append(f"No device group {path.strip()!r} (see ise_list_ndgs; 'Root#Parent#Group')")
    return body, blockers


async def desired_body(
    app: IseApp,
    kind: str,
    ctype: str,
    *,
    conditions: list[Any] | None,
    match: str,
    time: TimeSpec | None,
    network: NetworkSpec | None,
    known_nads: set[str] | None = None,
    known_ndgs: set[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """The body (without name/description/id) for one condition type, and blockers."""
    given = {"conditions": conditions is not None, "time": time is not None, "network": network is not None}
    want = {"library": "conditions", "time": "time", "network": "network"}[ctype]
    extra = [k for k, v in given.items() if v and k != want]
    if extra:
        raise InvalidRequest(f"type={ctype} takes `{want}`, not {', '.join(extra)}")
    if ctype == "library":
        if not conditions:
            raise InvalidRequest("type=library needs `conditions` (at least one check)")
        return await library_body(app, kind, conditions, match)
    if ctype == "time":
        if time is None:
            raise InvalidRequest("type=time needs `time` ({days, start, end, dates, exclude})")
        return time_body(time)
    if network is None:
        raise InvalidRequest("type=network needs `network` ({match, nads, ips, ndgs, macs, cli_dnis})")
    return await network_body(app, network, known_nads, known_ndgs)


def full_view(ctype: str, body: dict[str, Any]) -> dict[str, Any]:
    """What the preview compares: the rendered library condition, or the time / network spec."""
    out: dict[str, Any] = {"description": body.get("description") or None}
    if ctype == "library":
        out["condition"] = render_condition(body)
    elif ctype == "time":
        out["time"] = time_spec(body)
    else:
        out["network"] = network_spec(body)
    return compact(out)  # type: ignore[no-any-return]


def api_kind(kind: str) -> str:
    """The policy kind whose path a write uses first: a shared condition is written through network access."""
    return "network-access" if kind == SHARED else kind


def write_path(kind: str, ctype: str, current: dict[str, Any] | None) -> str:
    base = f"/api/v1/policy/{api_kind(kind)}/{RESOURCE[ctype]}"
    if current is None:
        return base
    if ctype == "library":
        return f"{base}/condition-by-name/{q(current.get('name'))}"
    return f"{base}/{q(current.get('id'))}"


async def _either_kind(kind: str, call: Any) -> Any:
    """`call(kind)`, then `call(other kind)` when ISE answers 400 on the first path. ISE 3.5 shares the
    condition library across both kinds, but on some builds only the path that created an object can
    update or delete it ("Failed to process request"); the first error is raised when both fail."""
    first = api_kind(kind)
    try:
        return await call(first)
    except UpstreamError as e:
        if e.status_code != 400 or isinstance(e, NotFound):
            raise
        try:
            return await call(OTHER_KIND[first])
        except UpstreamError:
            raise e from None


async def write_condition(
    app: IseApp, kind: str, ctype: str, body: dict[str, Any], current: dict[str, Any] | None
) -> Any:
    if current is None:
        data = _resp(await app.openapi.post(write_path(kind, ctype, None), body))
    else:

        async def put(k: str) -> Any:
            return _resp(
                await app.openapi.put(write_path(k, ctype, current), {**body, "id": current.get("id")})
            )

        data = await _either_kind(kind, put)
    app.__dict__.pop("_dict_cache", None)
    if isinstance(data, dict):
        return compact(
            {"id": data.get("id") or (current or {}).get("id"), "name": data.get("name") or body["name"]}
        )
    return data


async def delete_condition(app: IseApp, kind: str, ctype: str, current: dict[str, Any]) -> Any:
    async def delete(k: str) -> Any:
        return await app.openapi.request(
            "DELETE", f"/api/v1/policy/{k}/{RESOURCE[ctype]}/{q(current.get('id'))}"
        )

    await _either_kind(kind, delete)
    return {"deleted": current.get("name"), "id": current.get("id")}


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create or update a policy condition")
    async def ise_set_condition(
        ctx: Context,
        name: Annotated[str, Field(description="Condition name, e.g. 'mcp-business-hours'")],
        type: Annotated[  # noqa: A002 - the issue's and ISE's word for it
            ConditionType,
            Field(
                description="library (attribute checks), time (time and date) or network "
                "(NADs / end stations)"
            ),
        ],
        kind: PolicyKind = "network-access",
        conditions: ConditionTree = None,
        match: Annotated[
            Literal["all", "any"],
            Field(description="type=library with several checks: AND (all) or OR (any)"),
        ] = "all",
        time: Annotated[
            TimeSpec | None,
            Field(
                description="type=time: {days, start, end, dates: {start, end}, exclude: {days, start, end, "
                "dates}}, e.g. {days: [Monday..Friday], start: '08:00', end: '18:00'}"
            ),
        ] = None,
        network: Annotated[
            NetworkSpec | None,
            Field(
                description="type=network: {match: device|device-port|endstation, nads, ips, ndgs, macs, "
                "cli_dnis}"
            ),
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a reusable policy condition, or replace one of the same name: a library condition
        (attribute checks in the rule tools' 'Dictionary:Attribute operator value' syntax, AND/OR, nested
        blocks), a time-and-date condition (week days, hours, dates and exceptions, such as business hours for
        guest or contractor access) or a network condition (NADs by name, IP/subnet or device group, a NAD
        port, or end-station IPs/MACs/CLI-DNIS: scoping device admin to some devices). Rules then use it by
        name (ise_create_authz_rule conditions=['mcp-business-hours']). An update replaces the whole
        definition and takes effect for every rule using it at the next authentication (the preview lists
        them). Re-sending what ISE has is no change. Preview-first."""
        app: IseApp = get_client(ctx)
        name = name.strip()
        if not name:
            raise InvalidRequest("Give the condition a name")
        existing = await read_conditions(app, kind)
        hit = find(existing, name)
        body, blockers = await desired_body(
            app, kind, type, conditions=conditions, match=match, time=time, network=network
        )
        body = {**body, "name": name, "description": description or ""}
        current: dict[str, Any] | None = None
        if hit is not None:
            have_type, listed = hit
            if have_type != type:
                blockers.append(
                    f"{listed.get('name')!r} is a {have_type} condition; delete it first or pick another name"
                )
            else:
                current = strip_links(listed)
                if type == "library":
                    with_name = f"/api/v1/policy/{kind}/condition/condition-by-name/{q(listed.get('name'))}"
                    current = strip_links(_resp(await app.openapi.get(with_name)))
                body["name"] = str(current.get("name"))
                if description is None:
                    body["description"] = current.get("description") or ""
        args = {
            "name": name,
            "type": type,
            "kind": kind,
            "conditions": conditions,
            "match": match,
            "time": time.model_dump(exclude_none=True) if time else None,
            "network": network.model_dump(exclude_defaults=True) if network else None,
            "description": description,
        }
        want = full_view(type, body)
        side: list[str] = []
        if current is None:
            plan = Plan(
                f"Create {kind} {type} condition {name}",
                details={"kind": kind, "type": type, "name": name, **want},
                blockers=blockers,
                fingerprint=fingerprint(existing),
            )
        else:
            have = full_view(type, current)
            if type == "time" and have.get("description") != want.get("description"):
                # ISE keeps a time condition's description on a PUT: don't promise a change it ignores.
                side.append(TIME_DESCRIPTION_NOTE)
                want = compact({**want, "description": have.get("description")})
                body["description"] = current.get("description") or ""
            changes = field_changes(have, want, replace=True)
            same = f"{current.get('name')} already has this definition"
            if TIME_DESCRIPTION_NOTE in side:
                same += f" ({TIME_DESCRIPTION_NOTE})"
            refs = await _references(app, current)
            if refs:
                side.append(f"Used by {refs}: the change applies to them at the next authentication")
            plan = Plan(
                f"Update {kind} {type} condition {current.get('name')}",
                details={"kind": kind, "type": type, "name": current.get("name"), "changes": changes},
                blockers=blockers,
                fingerprint=fingerprint(current),
                side_effects=side,
                noop=not changes,
                noop_reason=None if changes else same,
            )
        return await preview_or_apply(
            ctx,
            tool="ise_set_condition",
            args=args,
            confirm=confirm,
            plan=plan,
            apply=lambda: write_condition(app, kind, type, body, current),
        )

    @reg.write(title="Delete a policy condition", destructive=True)
    async def ise_delete_condition(
        ctx: Context,
        name: Annotated[str, Field(description="Condition name or id (library, time or network)")],
        kind: PolicyKind = "network-access",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a library, time-and-date or network condition. Refused while a policy set, rule,
        exception or another library condition references it (the ise_where_used policy walk, network
        access and device admin): change those rules first (ise_update_policy_rule). Preview-first."""
        from ise_mcp.tools.where_used import delete_blockers, find_references  # noqa: PLC0415 - cycle

        app: IseApp = get_client(ctx)
        existing = await read_conditions(app, kind)
        hit = find(existing, name.strip())
        if hit is None:
            hit = next(
                ((t, c) for t, items in existing.items() for c in items if str(c.get("id")) == name.strip()),
                None,
            )
        if hit is None:
            raise NotFound(f"No {kind} condition named {name!r} (see ise_list_conditions)", 404)
        ctype, current = hit
        result = await find_references(
            app, "condition", {"name": current.get("name"), "id": current.get("id")}
        )
        blockers, unchecked = delete_blockers(result)
        return await preview_or_apply(
            ctx,
            tool="ise_delete_condition",
            args={"name": name, "kind": kind},
            confirm=confirm,
            plan=Plan(
                f"Delete {kind} {ctype} condition {current.get('name')}",
                details={"kind": kind, "type": ctype, **condition_view(ctype, current)},
                blockers=blockers,
                fingerprint=fingerprint(strip_links(current)),
                side_effects=unchecked,
            ),
            apply=lambda: delete_condition(app, kind, ctype, current),
        )


async def _references(app: IseApp, current: dict[str, Any]) -> str:
    """'3 rule(s): Set / Rule, ...' for an update preview; '' when unused or the scan fails."""
    from ise_mcp.tools.where_used import find_references  # noqa: PLC0415 - cycle

    try:
        result = await find_references(
            app, "condition", {"name": current.get("name"), "id": current.get("id")}
        )
    except (UpstreamError, NotFound):
        return ""
    labels = list(dict.fromkeys(str(r.get("label")) for r in result.get("references") or []))
    if not labels:
        return ""
    shown = ", ".join(labels[:5]) + (f" and {len(labels) - 5} more" if len(labels) > 5 else "")
    return f"{len(labels)} reference(s): {shown}"

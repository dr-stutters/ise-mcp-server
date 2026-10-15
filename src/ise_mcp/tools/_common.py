"""Helpers shared by the tool modules: id/MAC/IP parsing, ERS lookups, condition rendering."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any

from fastmcp.tools import ToolResult
from stutters_mcp_core import InvalidRequest, NotFound, ResponseFormat, ValidationFailed
from stutters_mcp_core import list_result as core_list_result
from stutters_mcp_core.http import Page, page_of

from ise_mcp.client import IseApp

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX = re.compile(r"[^0-9A-Fa-f]")

# How long ago to look for auth records by default (MnT AuthStatus takes seconds).
DEFAULT_LOOKBACK_MINUTES = 24 * 60
# How long name->id maps (identity/endpoint groups, SGACLs, SGTs) are reused within a burst of calls.
NAME_MAP_TTL_SECONDS = 60.0


@dataclass
class ErsPage(Page):
    """A Page that can carry a note for the caller (e.g. that per-item details were skipped)."""

    note: str | None = None


def list_result(
    page: Page,
    *,
    fmt: ResponseFormat = "json",
    columns: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> ToolResult:
    """core list_result, plus the page's note (ErsPage) in the metadata."""
    note = getattr(page, "note", None)
    if note:
        extra = {**(extra or {}), "detail_note": note}
        columns = None  # rows are id/name only, so the detail columns would be empty
    return core_list_result(page, fmt=fmt, columns=columns, extra=extra)


def is_uuid(s: str) -> bool:
    return bool(UUID_RE.match(s.strip()))


def normalize_mac(value: str) -> str:
    """Any common MAC notation (aa-bb-cc..., aabb.ccdd.eeff, aabbccddeeff) -> AA:BB:CC:DD:EE:FF."""
    digits = _HEX.sub("", value)
    if len(digits) != 12 or len(re.sub(r"[0-9A-Fa-f.:\-\s]", "", value)) > 0:
        raise InvalidRequest(f"{value!r} is not a MAC address (expected e.g. AA:BB:CC:DD:EE:FF)")
    digits = digits.upper()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def looks_like_mac(value: str) -> bool:
    try:
        normalize_mac(value)
    except InvalidRequest:
        return False
    return True


def parse_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


async def gather_limited[T](
    items: Iterable[Any], fn: Callable[[Any], Awaitable[T]], limit: int = 5
) -> list[T]:
    sem = asyncio.Semaphore(limit)

    async def one(x: Any) -> T:
        async with sem:
            return await fn(x)

    return list(await asyncio.gather(*(one(x) for x in items)))


async def ers_list(
    app: IseApp,
    resource: str,
    *,
    filters: list[str] | None = None,
    filter_or: bool = False,
    limit: int,
    offset: int,
    detail: bool = False,
    shape: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    detail_cap: int | None = -1,
) -> Page:
    """A page of an ERS collection. ERS lists only return id/name/description; with `detail` each item
    is fetched (bounded concurrency) and optionally passed through `shape`. Above `detail_cap` items
    (default: the ISE_DETAIL_THRESHOLD setting; None = no cap, for internal full scans) the per-item
    GETs are skipped and the page carries a note, so a 10k-device list doesn't fire 10k requests."""
    params: dict[str, Any] = {}
    if filters:
        params["filter"] = filters
        if filter_or and len(filters) > 1:
            params["filterType"] = "or"
    path = f"/ers/config/{resource}"
    try:
        page = await app.ers_pager.fetch_page(app.ers, path, params, limit=limit, offset=offset)
    except ValidationFailed as e:
        # Some resources (e.g. authorizationprofile) don't support filters: filter names client-side.
        names = [f.split(".", 2)[2].lower() for f in filters or [] if f.startswith("name.CONTAINS.")]
        if "filter" not in str(e).lower() or not names or len(names) != len(filters or []):
            raise
        everything = await app.ers_pager.fetch_page(app.ers, path, limit=10_000)
        matches = [
            i
            for i in everything.items
            if isinstance(i, dict) and all(n in str(i.get("name", "")).lower() for n in names)
        ]
        page = page_of(matches, limit=limit, offset=offset)
    items = [_strip_link(i) for i in page.items if isinstance(i, dict)]
    cap = app.settings.detail_threshold if detail_cap == -1 else detail_cap
    note = None
    if detail and items and cap is not None and len(items) > cap:
        note = (
            f"{len(items)} items exceed the per-item detail threshold ({cap}, ISE_DETAIL_THRESHOLD): "
            "showing names and ids only. Narrow with filters or a smaller limit for full details."
        )
        detail = False
    if detail and items:
        full = await gather_limited(
            items, lambda i: app.ers_get(resource, str(i["id"])), app.settings.detail_concurrency
        )
        items = [shape(f) if shape else f for f in full]
    return ErsPage(items, page.offset, page.total, more=page.more, note=note)


def _strip_link(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if k != "link"}


async def ers_resolve(
    app: IseApp, resource: str, name_or_id: str, *, what: str, list_tool: str
) -> dict[str, Any]:
    """Full ERS object by UUID or exact name. Raises NotFound with a pointer to the list tool."""
    key = name_or_id.strip()
    if not key:
        raise InvalidRequest(f"Give a {what} name or id")
    if is_uuid(key):
        return await app.ers_get(resource, key)
    hit = await app.ers_find(resource, key)
    if hit is None:
        raise NotFound(f"No {what} named {key!r}. Use {list_tool} to find the exact name.", 404)
    return await app.ers_get(resource, str(hit["id"]))


async def ers_name_map(app: IseApp, resource: str, cap: int = 2000) -> dict[str, str]:
    """{id: name} for a whole (small) ERS collection, e.g. identity groups or SGTs. Reused for
    NAME_MAP_TTL_SECONDS so a burst of calls doesn't refetch it; writes clear it (clear_name_maps)."""
    cache: dict[str, tuple[float, dict[str, str]]] = app.__dict__.setdefault("_name_maps", {})
    hit = cache.get(resource)
    if hit and time.monotonic() - hit[0] < NAME_MAP_TTL_SECONDS:
        return dict(hit[1])
    page = await app.ers_pager.fetch_page(app.ers, f"/ers/config/{resource}", limit=cap)
    out = {str(i["id"]): str(i.get("name")) for i in page.items if isinstance(i, dict) and "id" in i}
    cache[resource] = (time.monotonic(), out)
    return dict(out)


def clear_name_maps(app: IseApp) -> None:
    app.__dict__.pop("_name_maps", None)


# --- policy conditions --------------------------------------------------------------------------


def render_condition(cond: Any) -> str:
    """One-line text for an ISE policy condition tree (OpenAPI shape)."""
    if not isinstance(cond, dict):
        return "ANY" if cond is None else str(cond)
    ctype = str(cond.get("conditionType", ""))
    neg = "NOT " if cond.get("isNegate") else ""
    if ctype in (
        "ConditionAndBlock",
        "LibraryConditionAndBlock",
        "ConditionOrBlock",
        "LibraryConditionOrBlock",
    ):
        joiner = " AND " if "And" in ctype else " OR "
        parts = [render_condition(c) for c in cond.get("children") or []]
        return f"{neg}({joiner.join(parts)})"
    if ctype in ("ConditionReference",):
        return f"{neg}{cond.get('name')}"
    if "dictionaryName" in cond or "attributeName" in cond:
        value = cond.get("attributeValue")
        if value is None and cond.get("dictionaryValue"):
            value = cond.get("dictionaryValue")
        attr = f"{cond.get('dictionaryName')}:{cond.get('attributeName')}"
        return f"{neg}{attr} {cond.get('operator', 'equals')} {value}"
    if cond.get("name"):
        return f"{neg}{cond.get('name')}"
    return neg + ctype


def summarize_rule(entry: dict[str, Any]) -> dict[str, Any]:
    """Flatten an OpenAPI policy rule ({"rule": {...}, "profile": [...], ...}) for display."""
    rule = entry.get("rule") or {}
    out: dict[str, Any] = {
        "rank": rule.get("rank"),
        "name": rule.get("name"),
        "id": rule.get("id"),
        "state": rule.get("state"),
        "condition": "DEFAULT" if rule.get("default") else render_condition(rule.get("condition")),
        "hits": rule.get("hitCounts"),
    }
    for key in (
        "profile",
        "securityGroup",
        "commands",
        "identitySourceName",
        "ifAuthFail",
        "ifUserNotFound",
        "ifProcessFail",
    ):
        if entry.get(key) not in (None, [], ""):
            out[key] = entry[key]
    return out


async def openapi_all(app: IseApp, path: str, cap: int = 2000) -> list[Any]:
    """OpenAPI collections that page with page/size (size <= 100) and return {"response": [...]}."""
    out: list[Any] = []
    page = 1
    while len(out) < cap:
        data = await app.openapi.get(path, {"page": page, "size": 100})
        data = data.get("response", data) if isinstance(data, dict) else data
        batch = data if isinstance(data, list) else []
        out += batch
        if len(batch) < 100:
            break
        page += 1
    return out


async def anc_assignments(app: IseApp, mac: str | None = None) -> list[dict[str, Any]]:
    """Endpoints with an ANC policy applied ({id, macAddress, policyName}); ERS can't filter these by
    MAC, so the (normally short) list is fetched in full and filtered here."""
    page = await app.ers_pager.fetch_page(app.ers, "/ers/config/ancendpoint", limit=5000)
    full = await gather_limited(page.items, lambda i: app.ers_get("ancendpoint", str(i["id"])))
    if mac:
        full = [e for e in full if str(e.get("macAddress", "")).upper() == mac.upper()]
    return full

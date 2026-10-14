"""Helpers shared by the tool modules: id/MAC/IP parsing, ERS lookups, condition rendering."""

from __future__ import annotations

import asyncio
import ipaddress
import re
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from stutters_mcp_core import InvalidRequest, NotFound, ValidationFailed
from stutters_mcp_core.http import Page, page_of

from ise_mcp.client import IseApp

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX = re.compile(r"[^0-9A-Fa-f]")

# How long ago to look for auth records by default (MnT AuthStatus takes seconds).
DEFAULT_LOOKBACK_MINUTES = 24 * 60


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
) -> Page:
    """A page of an ERS collection. ERS lists only return id/name/description; with `detail` each item
    is fetched (bounded concurrency) and optionally passed through `shape`."""
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
    if detail and items:
        full = await gather_limited(items, lambda i: app.ers_get(resource, str(i["id"])))
        items = [shape(f) if shape else f for f in full]
    page.items = items
    return page


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
    """{id: name} for a whole (small) ERS collection, e.g. identity groups or SGTs."""
    page = await app.ers_pager.fetch_page(app.ers, f"/ers/config/{resource}", limit=cap)
    return {str(i["id"]): str(i.get("name")) for i in page.items if isinstance(i, dict) and "id" in i}


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

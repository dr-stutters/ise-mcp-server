"""The ISE "app": one ApiClient per REST surface (OpenAPI, ERS, MnT), sharing a rate limiter.

OpenAPI  https://<ise>/api/v1/...            JSON, Basic auth
ERS      https://<ise>:<ers_port>/ers/config/... JSON (Accept/Content-Type required), Basic auth,
         page/size paging (size <= 100), optional CSRF token for writes
MnT      https://<ise>/admin/API/mnt/...      XML, Basic auth, read-only + CoA
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as dist_version
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
from stutters_mcp_core import AuthError, InvalidRequest, NotFound, UpstreamError, ValidationFailed
from stutters_mcp_core.http import ApiClient, BasicAuth, PageNumber, RateLimiter, default_error_detail

from ise_mcp.config import Settings
from ise_mcp.xmlutil import mnt_error_detail, parse_xml

log = logging.getLogger(__name__)

ERS_JSON = {"Accept": "application/json", "Content-Type": "application/json"}
SURFACES = ("openapi", "ers", "mnt")
SAFE_MNT_PATH = re.compile(r"^[A-Za-z0-9_\-/.:@%+]+$")
SAFE_RESOURCE = re.compile(r"^[a-z]+$")


def server_version() -> str:
    """This package's installed version ("unknown" when running from an uninstalled tree)."""
    try:
        return dist_version("ise-mcp-server")
    except PackageNotFoundError:
        return "unknown"


def ers_error_detail(body: Any) -> str | None:
    """ERS errors look like {"ERSResponse": {"messages": [{"title": "..."}]}}."""
    if isinstance(body, dict) and isinstance(body.get("ERSResponse"), dict):
        msgs = body["ERSResponse"].get("messages") or []
        titles = [str(m.get("title")) for m in msgs if isinstance(m, dict) and m.get("title")]
        if titles:
            return " | ".join(titles)[:500]
    return default_error_detail(body)


def openapi_error_detail(body: Any) -> str | None:
    """OpenAPI errors: {"message": ...} or {"response": {"message": ...}} or a list of messages."""
    return default_error_detail(body)


def with_port(url: str, port: int) -> str:
    """`url` with its port replaced (443 on https leaves the URL as is)."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    default = 443 if parts.scheme == "https" else 80
    netloc = host if port == default else f"{host}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def unwrap(data: Any) -> Any:
    """ERS wraps single objects in their type name ({"NetworkDevice": {...}}); drop that layer."""
    if isinstance(data, dict) and len(data) == 1:
        (value,) = data.values()
        if isinstance(value, dict):
            return value
    return data


class IseApp:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        user, password = settings.require_credentials("ISE_")
        self.username = user
        limiter = RateLimiter(settings.rate_limit, settings.max_concurrency or 5)
        common: dict[str, Any] = {
            "product": "ISE",
            "env_prefix": "ISE_",
            "auth": BasicAuth(user, password),
            "verify": settings.verify,
            "timeout": settings.timeout,
            "retries": settings.retries,
            "limiter": limiter,
            "transport": transport,
        }
        self.openapi = ApiClient(settings.url, error_detail=openapi_error_detail, **common)
        self.ers_url = with_port(settings.url, settings.ers_port)
        self.ers = ApiClient(self.ers_url, headers=ERS_JSON, error_detail=ers_error_detail, **common)
        self.mnt = ApiClient(
            settings.url, headers={"Accept": "application/xml"}, error_detail=mnt_error_detail, **common
        )
        self.ers_pager = PageNumber(items="SearchResult.resources", total="SearchResult.total", max_size=100)
        self._csrf: str | None = None
        self._failure_reasons: dict[str, dict[str, Any]] | None = None
        self._version: str | None = None

    async def aclose(self) -> None:
        await asyncio.gather(self.openapi.aclose(), self.ers.aclose(), self.mnt.aclose())

    # --- ERS ---------------------------------------------------------------------------------

    async def ers_request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        expect: Any = "json",
        timeout: float | None = None,  # noqa: ASYNC109 - per-request HTTP timeout
    ) -> Any:
        """An ERS call that transparently handles CSRF protection: when ISE answers a write with 403
        and mentions CSRF, fetch a token (X-CSRF-Token: fetch) and retry once. `timeout` overrides the
        HTTP timeout for slow writes (e.g. SXP objects take 30-60 s on ISE 3.5)."""
        headers = {"X-CSRF-Token": self._csrf} if self._csrf and method.upper() != "GET" else None
        try:
            out = await self.ers.request(
                method, path, params=params, json=json, headers=headers, expect=expect, timeout=timeout
            )
        except AuthError as e:
            if method.upper() == "GET" or "csrf" not in str(e).lower():
                raise
            await self._fetch_csrf()
            out = await self.ers.request(
                method,
                path,
                params=params,
                json=json,
                headers={"X-CSRF-Token": self._csrf or ""},
                expect=expect,
                timeout=timeout,
            )
        if method.upper() != "GET":
            # Any ERS write can rename or remove objects that the cached name->id maps hold.
            self.__dict__.pop("_name_maps", None)
        return out

    async def _fetch_csrf(self) -> None:
        resp = await self.ers.request(
            "GET",
            "/ers/config/networkdevice/versioninfo",
            headers={"X-CSRF-Token": "fetch"},
            expect="response",
        )
        token = resp.headers.get("X-CSRF-Token")
        if not token:
            raise AuthError(
                "ISE refused the ERS write with a CSRF error and did not issue a CSRF token. Check the "
                "ERS settings (Administration > Settings > API Settings)."
            )
        self._csrf = token

    @staticmethod
    def _res(resource: str) -> str:
        if not SAFE_RESOURCE.match(resource):
            raise InvalidRequest(f"Invalid ERS resource {resource!r}")
        return resource

    async def ers_get(self, resource: str, obj_id: str) -> dict[str, Any]:
        self._res(resource)
        data = await self.ers_request("GET", f"/ers/config/{resource}/{quote(obj_id, safe='')}")
        out: dict[str, Any] = unwrap(data)
        return out

    async def ers_find(self, resource: str, name: str) -> dict[str, Any] | None:
        """Exact-name lookup ({"id", "name", ...}); None if not found. Uses the ERS name filter, or for
        resources that don't support it (e.g. authorizationprofile) a scan of the collection."""
        path = f"/ers/config/{self._res(resource)}"
        try:
            page = await self.ers_pager.fetch_page(self.ers, path, {"filter": f"name.EQ.{name}"}, limit=5)
            items = page.items
        except ValidationFailed as e:
            if "filter" not in str(e).lower():
                raise
            items = (await self.ers_pager.fetch_page(self.ers, path, limit=5000)).items
        for r in items:
            if isinstance(r, dict) and r.get("name") == name:
                return r
        lowered = [r for r in items if isinstance(r, dict) and str(r.get("name", "")).lower() == name.lower()]
        return lowered[0] if len(lowered) == 1 else None

    async def ers_create(
        self,
        resource: str,
        body: dict[str, Any],
        *,
        timeout: float | None = None,  # noqa: ASYNC109 - per-request HTTP timeout
    ) -> dict[str, Any]:
        """POST and return {"id": ..., "location": ...} from the Location header."""
        resp: httpx.Response = await self.ers_request(
            "POST", f"/ers/config/{self._res(resource)}", json=body, expect="response", timeout=timeout
        )
        loc = resp.headers.get("Location", "")
        out: dict[str, Any] = {"id": loc.rstrip("/").rsplit("/", 1)[-1] if loc else None}
        if resp.content:
            with contextlib.suppress(ValueError):
                out["response"] = resp.json()
        return out

    # --- MnT ---------------------------------------------------------------------------------

    async def mnt_get(self, path: str, *, missing_ok: bool = True) -> Any:
        """GET an MnT resource and parse the XML. MnT reports "no session for X" as HTTP 500 with
        cpm-code 34110; that becomes None when `missing_ok`."""
        resp = await self._mnt_raw(path)
        text = resp.text
        if resp.status_code >= 400:
            if missing_ok and resp.status_code == 500 and "34110" in text:
                return None
            if resp.status_code == 404:
                raise NotFound(f"MnT has no resource at {path}", 404)
            raise self.mnt.error_from_response(resp)
        if not text.strip():
            return None
        try:
            _, data = parse_xml(text)
        except ValueError as e:
            raise UpstreamError(f"ISE MnT returned unparseable XML for {path}: {e}") from e
        return data

    async def _mnt_raw(self, path: str) -> httpx.Response:
        """Authenticated GET that returns the response even for 4xx/5xx (MnT error bodies are XML)."""
        if not SAFE_MNT_PATH.match(path) or ".." in path:
            raise InvalidRequest(f"Invalid MnT path {path!r}")
        return await self.mnt.request(  # type: ignore[no-any-return]
            "GET",
            "/admin/API/mnt/" + path.lstrip("/"),
            expect="response",
            ok_status=range(400, 600),
        )

    async def failure_reasons(self) -> dict[str, dict[str, Any]]:
        """All MnT failure reasons keyed by numeric code (cached for the server's lifetime)."""
        if self._failure_reasons is None:
            data = await self.mnt_get("FailureReasons", missing_ok=False)
            reasons: dict[str, dict[str, Any]] = {}
            items = data.get("failureReason") if isinstance(data, dict) else None
            for r in items if isinstance(items, list) else [items] if items else []:
                if not isinstance(r, dict):
                    continue
                code_text = str(r.get("code") or "")
                code = str(r.get("id") or code_text.split(" ", 1)[0])
                reasons[code] = {
                    "code": code,
                    "reason": code_text.split(" ", 1)[1] if " " in code_text else code_text,
                    "cause": r.get("cause"),
                    "resolution": r.get("resolution"),
                }
            self._failure_reasons = reasons
        return self._failure_reasons

    # --- status ------------------------------------------------------------------------------

    async def _probe(self, name: str) -> dict[str, Any]:
        timeout = self.settings.probe_timeout
        try:
            if name == "openapi":
                data = await self.openapi.request(
                    "GET", "/api/v1/deployment/node", timeout=timeout, retry=False
                )
                nodes = data.get("response", []) if isinstance(data, dict) else []
                return {
                    "ok": True,
                    "nodes": [
                        {
                            "hostname": n.get("hostname"),
                            "roles": n.get("roles"),
                            "services": n.get("services"),
                            "status": n.get("nodeStatus"),
                        }
                        for n in nodes
                        if isinstance(n, dict)
                    ],
                }
            if name == "ers":
                data = await self.ers.request(
                    "GET", "/ers/config/op/systemconfig/iseversion", timeout=timeout, retry=False
                )
                values = {
                    str(v.get("name")): v.get("value")
                    for v in (data.get("OperationResult", {}).get("resultValue") or [])
                    if isinstance(v, dict)
                }
                return {
                    "ok": True,
                    "url": self.ers_url,
                    "version": values.get("version"),
                    "patches": values.get("patch information"),
                }
            resp = await self.mnt.request(
                "GET", "/admin/API/mnt/Version", timeout=timeout, retry=False, expect="text"
            )
            _, info = parse_xml(resp)
            return {
                "ok": True,
                "version": info.get("version") if isinstance(info, dict) else None,
                "node_type": info.get("type_of_node") if isinstance(info, dict) else None,
            }
        except (UpstreamError, ValueError, AttributeError, TypeError) as e:
            out: dict[str, Any] = {"ok": False, "error": str(e)[:300]}
            if name == "ers":
                out["url"] = self.ers_url
                out["hint"] = (
                    "ERS tools (NADs, internal users, groups, SGTs, authz profiles, dACLs, ANC) won't work. "
                    "Enable ERS (Administration > System > Settings > API Settings) and check ISE_ERS_PORT "
                    "(443 on ISE 3.1+, 9060 on older releases or when 443 is not enabled for ERS)."
                )
            return out

    async def status(self) -> dict[str, Any]:
        results = await asyncio.gather(*(self._probe(s) for s in SURFACES))
        surfaces = dict(zip(SURFACES, results, strict=True))
        if not any(r["ok"] for r in results):
            first = next(iter(r["error"] for r in results))
            raise UpstreamError(f"No ISE API surface answered. {first}")
        version = surfaces["ers"].get("version") or surfaces["mnt"].get("version")
        if version:
            self._version = str(version)
        out: dict[str, Any] = {
            "version": version,
            "api_user": self.username,
            "server_version": server_version(),
        }
        if surfaces["ers"].get("patches"):
            out["patches"] = surfaces["ers"]["patches"]
        if surfaces["openapi"].get("nodes"):
            out["nodes"] = surfaces["openapi"].pop("nodes")
        out["surfaces"] = surfaces
        down = [s for s, r in surfaces.items() if not r["ok"]]
        if down:
            out["warning"] = f"Surface(s) not answering: {', '.join(down)}; tools using them will fail."
        return out

    async def version(self) -> str:
        if self._version is None:
            try:
                data = await self.mnt_get("Version", missing_ok=False)
                if not isinstance(data, dict) or not data.get("version"):
                    return "unknown"
                self._version = str(data["version"])
            except UpstreamError:
                return "unknown"
        return self._version

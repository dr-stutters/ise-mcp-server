"""pxGrid Direct connectors (I91, #100): a REST CMDB (NetBox, ServiceNow, any JSON source) as an ISE
endpoint attribute source for authorization.

ISE 3.5 pulls the CMDB's records on its own schedule (full and incremental syncs), keys them by a unique
identifier, ties them to endpoints by a correlation identifier (the MAC address attribute), and publishes
the mapped attributes in a dictionary named after the connector, which authorization rules then match
('<connector>:<attribute> EQUALS <value>'). The server only configures the connector: ISE does the pulling,
nothing is subscribed (ADR-003). OpenAPI `/api/v1/pxgrid-direct`:

- `GET/POST /connector-config`, `GET/PUT/DELETE /connector-config/{connectorName}` (ConnectorConfigInfo
  `{"connector": {...}}`: connectorName, connectorType urlfetcher, url, flexibleUrl, attributes with
  attributeMapping, fullsyncSchedule / deltasyncSchedule, coaType, skipCertificateValidations);
- `POST /test-connector` (TestConnectorRequest): fetches the URL with the given credentials and answers the
  data or the error, changes nothing;
- `GET /syncNowStatus/{connectorName}` (syncStatus INPROGRESS / QUEUED / SYNC COMPLETED / ERRORED, and
  SCH_INPROGRESS for a scheduled sync) and `GET /push/{connectorName}/{uniqueId}` (one record as ISE holds
  it).

What ISE 3.5 accepts (live, #170) differs from its spec: a create or update carries `flexibleUrl` only (ISE
answers 400 when `url` is there too, though its GET returns both), an attribute mapping is
`{jsonAttribute, dictionaryAttribute, includeInDictionary}` (not the spec's name/dictionaryName; ISE stores
the JSON side as `$.<attribute>`), and `startDate` is rounded up to the next 5-minute mark. A sync keyed on
a numeric unique id (a JSON number, such as NetBox `id`) stays SCH_INPROGRESS: key on a string attribute.

The CMDB credential (a NetBox API token, a basic-auth password) never travels as a tool argument: it comes
from a server environment variable named `ISE_PXGRID_DIRECT_...` (or its `_FILE` twin), is sent to ISE
only, and is never shown. Previews and diffs say whether a credential is set or changes.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import quote, urlsplit

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
    ValidationFailed,
    field_changes,
    get_client,
    object_result,
    preview_or_apply,
)
from ise_mcp._core.secrets import register_secret
from ise_mcp.client import IseApp
from ise_mcp.tools.writes import deep_merge, fingerprint, unchanged

BASE = "/api/v1/pxgrid-direct"
CONFIG = f"{BASE}/connector-config"
TEST = f"{BASE}/test-connector"
SYNC_STATUS = f"{BASE}/syncNowStatus"
PUSH = f"{BASE}/push"

SECRET_ENV = re.compile(r"ISE_PXGRID_DIRECT_[A-Z0-9_]+")
_NAME = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
COA = {"none": "nocoa", "reauth": "reauth", "port_bounce": "portbounce"}
UNITS = ("hours", "days", "weeks")
SYNC_DONE = {"SYNC COMPLETED", "COMPLETED", "SUCCESS"}
SYNC_RUNNING = {"INPROGRESS", "IN_PROGRESS", "QUEUED", "SCH_INPROGRESS", "SCH_QUEUED"}
NUMERIC_ID_HINT = (
    "ISE 3.5 leaves a sync keyed on a numeric unique id (a JSON number, such as NetBox 'id') at "
    "SCH_INPROGRESS: key the connector on a string attribute (NetBox 'name' or 'serial', or a custom field)"
)
START_FMT = "%Y-%m-%dT%H:%M:%S"
UNIT_STEP = {"hours": timedelta(hours=1), "days": timedelta(days=1), "weeks": timedelta(weeks=1)}
# A rolled-forward start lands at least this far ahead, so the confirm still sends a future time.
START_MARGIN = timedelta(minutes=5)
PAST_START = "the date is in the past"
PAST_START_HINT = (
    "ISE 3.5 refuses a schedule whose start is in the past: pass start='YYYY-MM-DDTHH:MM:SS' (a future time "
    "in ISE's time zone), or preview again (an update without start moves a past saved start forward)"
)
TEST_DATA_CHARS = 4000  # the test answers the CMDB's whole page: keep a sample


# --- helpers ------------------------------------------------------------------------------------


def secret_from_env(var: str, arg: str = "secret_env") -> str:
    """The credential in `var` (or the file `<var>_FILE` names) from the server's environment."""
    if not SECRET_ENV.fullmatch(var):
        raise InvalidRequest(
            f"{arg} must name a variable starting ISE_PXGRID_DIRECT_ (upper case, digits, '_'), not {var!r}: "
            "the tool never reads the server's other secrets."
        )
    value = os.environ.get(var)
    if not value and (file := os.environ.get(f"{var}_FILE")):
        try:
            value = Path(file).expanduser().read_text().removesuffix("\n")
        except OSError:
            raise InvalidRequest(f"{var}_FILE names a file this server can't read") from None
    if not value:
        raise InvalidRequest(
            f"{var} (or {var}_FILE) is not set on this server: add it to the server's environment and "
            "restart it"
        )
    register_secret(value)
    return value


def _unwrap(data: Any) -> Any:
    return data.get("response", data) if isinstance(data, dict) and "response" in data else data


def connector_of(info: Any) -> dict[str, Any]:
    """The connector dict from a ConnectorConfigInfo ({"connector": {...}}) or a bare connector."""
    info = _unwrap(info)
    if isinstance(info, list):
        info = info[0] if info else {}
    if isinstance(info, dict) and isinstance(info.get("connector"), dict):
        return dict(info["connector"])
    return dict(info) if isinstance(info, dict) else {}


async def list_connectors(app: IseApp) -> list[dict[str, Any]]:
    data = _unwrap(await app.openapi.get(CONFIG))
    items = data if isinstance(data, list) else [data] if isinstance(data, dict) and data else []
    return [c for c in (connector_of(x) for x in items) if c]


async def find_connector(app: IseApp, name: str) -> dict[str, Any] | None:
    for c in await list_connectors(app):
        if str(c.get("connectorName") or "") == name:
            return c
    for c in await list_connectors(app):
        if str(c.get("connectorName") or "").lower() == name.lower():
            return c
    return None


async def require_connector(app: IseApp, name: str) -> dict[str, Any]:
    c = await find_connector(app, name)
    if c is None:
        raise NotFound(f"No pxGrid Direct connector {name!r} (ise_pxgrid_direct_status lists them)", 404)
    return c


def _fetch(c: dict[str, Any], which: str) -> dict[str, Any]:
    f = (c.get("flexibleUrl") or {}).get(which)
    return f if isinstance(f, dict) else {}


def _json_path(value: Any) -> str | None:
    """A mapping's record attribute as the user names it: ISE stores 'role' as '$.role'."""
    if value is None:
        return None
    text = str(value)
    return text[2:] if text.startswith("$.") else text


def _mapping(attrs: dict[str, Any]) -> dict[str, Any]:
    """Dictionary attribute -> record attribute, from ISE's live shape (jsonAttribute / dictionaryAttribute)
    or the spec's (name / dictionaryName)."""
    out: dict[str, Any] = {}
    for m in attrs.get("attributeMapping") or []:
        if not isinstance(m, dict):
            continue
        key = m.get("dictionaryAttribute") or m.get("dictionaryName")
        if key:
            out[str(key)] = _json_path(m.get("jsonAttribute") or m.get("name"))
    return out


def _secret_set(c: dict[str, Any]) -> bool:
    url = c.get("url") or {}
    bulk = _fetch(c, "bulk")
    return bool(
        url.get("password")
        or (bulk.get("apiKeyProperties") or {}).get("key")
        or (bulk.get("basicAuthProperties") or {}).get("password")
    )


def _masked(value: str) -> bool:
    """A credential ISE masked in a GET ('******', or 'Token ******')."""
    tail = value.split(" ", 1)[-1]
    return bool(tail) and set(tail) == {"*"}


def _schedule(s: Any) -> str | None:
    if not isinstance(s, dict) or not s.get("interval"):
        return None
    out = f"every {s.get('interval')} {s.get('intervalUnit') or 'hours'}"
    return f"{out} from {s['startDate']}" if s.get("startDate") else out


def connector_view(c: dict[str, Any]) -> dict[str, Any]:
    """A connector in plain words, with no credential (only whether one is set)."""
    url = c.get("url") or {}
    bulk, inc = _fetch(c, "bulk"), _fetch(c, "incremental")
    attrs = c.get("attributes") or {}
    key = bulk.get("apiKeyProperties") or {}
    auth = bulk.get("authenticationType") or url.get("authenticationType")
    return {
        "name": c.get("connectorName"),
        "type": c.get("connectorType"),
        "enabled": c.get("enabled"),
        "bulk_url": bulk.get("url") or url.get("bulkUrl"),
        "incremental_url": inc.get("url") or url.get("incrementalUrl") or None,
        "auth": auth,
        "username": (bulk.get("basicAuthProperties") or {}).get("userName") or url.get("userName") or None,
        "token_header": key.get("headerName") if auth == "apikey" else None,
        "credential_set": _secret_set(c),
        "top_level_object": attrs.get("topLevelObject"),
        "unique_id": attrs.get("uniqueIdentifier"),
        "correlation_id": attrs.get("correlationIdentifier"),
        "version_id": attrs.get("versionIdentifier") or None,
        "attributes": _mapping(attrs),
        "full_sync": _schedule(c.get("fullsyncSchedule")),
        "incremental_sync": _schedule(c.get("deltasyncSchedule")),
        "coa": {v: k for k, v in COA.items()}.get(str(c.get("coaType")), c.get("coaType")),
        "skip_cert_validation": c.get("skipCertificateValidations"),
        "description": c.get("description") or None,
    }


def _fetch_url(
    url: str, auth: str, username: str | None, secret: str | None, header: str, scheme: str
) -> dict[str, Any]:
    f: dict[str, Any] = {"url": url, "method": "GET", "authenticationType": auth}
    if auth == "basic":
        f["basicAuthProperties"] = {"userName": username or ""}
        if secret is not None:
            f["basicAuthProperties"]["password"] = secret
    else:
        f["apiKeyProperties"] = {"keyType": "header", "headerName": header}
        if secret is not None:
            f["apiKeyProperties"]["key"] = f"{scheme} {secret}" if scheme else secret
    return f


def _check_url(value: str, arg: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise InvalidRequest(
            f"{arg} must be an http(s) URL, e.g. 'https://netbox.example.com/api/dcim/devices/'"
        )
    return value


def _sched(interval: int | None, unit: str | None, start: str | None) -> dict[str, Any] | None:
    """A Schedule patch: only what was given (an update keeps the saved interval / start otherwise)."""
    out: dict[str, Any] = {}
    if interval is not None:
        out["interval"] = interval
    if unit is not None or interval is not None:
        out["intervalUnit"] = unit or "hours"
    if start is not None and (interval is not None or unit is not None):
        out["startDate"] = start
    return out or None


def _round5(at: datetime) -> datetime:
    """Up to the next 5-minute mark, as ISE rounds a schedule's startDate."""
    at = at.replace(microsecond=0)
    if at.second or at.minute % 5:
        at = at.replace(second=0) + timedelta(minutes=5 - at.minute % 5)
    return at


def _start(value: str | None) -> str:
    """A schedule's startDate on ISE's 5-minute grid (default: now, rounded up)."""
    if value is None:
        return _round5(datetime.now(UTC)).strftime(START_FMT)
    try:
        at = datetime.strptime(value, START_FMT)
    except ValueError:
        raise InvalidRequest(
            f"start is 'YYYY-MM-DDTHH:MM:SS' (ISE's time zone), e.g. '2026-11-01T02:00:00': {value!r}"
        ) from None
    return _round5(at).strftime(START_FMT)


def _now() -> datetime:
    """Now as a naive UTC time, the clock `_start(None)` uses (tests freeze it)."""
    return datetime.now(UTC).replace(tzinfo=None)


def _rolled_start(sched: Any, now: datetime) -> tuple[str, str] | None:
    """(saved, next) when a schedule's saved startDate is in the past: the next sync time the schedule
    implies (startDate + n x interval, on the 5-minute mark) at least START_MARGIN ahead of `now`. None when
    the start is still ahead, or the schedule has no interval / unreadable start."""
    if not isinstance(sched, dict) or not sched.get("startDate") or not sched.get("interval"):
        return None
    saved = str(sched["startDate"])
    try:
        at = datetime.strptime(saved[:19], START_FMT)
        step = UNIT_STEP[str(sched.get("intervalUnit") or "hours").lower()] * int(sched["interval"])
    except (ValueError, KeyError, TypeError):
        return None
    floor = now + START_MARGIN
    if at > floor or step <= timedelta(0):
        return None
    n = -(-(floor - at) // step)  # ceil: the first slot past the margin
    nxt = at + step * n
    if nxt <= floor:
        nxt += step
    return saved, _round5(nxt).strftime(START_FMT)


def _past_start_hint(e: UpstreamError) -> UpstreamError | None:
    """ISE's 400 'Incorrect start date format or the date is in the past', with what to do about it."""
    if e.status_code == 400 and PAST_START in str(e).lower():
        return ValidationFailed(f"{e} {PAST_START_HINT}", 400)
    return None


def _redacted(value: Any, secrets: list[str]) -> Any:
    """Test-connector output with any credential we sent cut out (ISE may echo the request)."""
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    for s in secrets:
        if s:
            text = text.replace(s, "******")
    return text if isinstance(value, str) else json.loads(text)


def _is_page(d: dict[str, Any]) -> bool:
    """A CMDB page (records in a list under some key) rather than one record."""
    return any(isinstance(v, list) and v and all(isinstance(x, dict) for x in v) for v in d.values())


def _sample(data: Any, top: str | None, unique_id: str | None = None) -> dict[str, Any]:
    """Records count and a short sample of the test's `data`: a JSON string of the CMDB's page, or (ISE
    3.5) of one record."""
    parsed: Any = data
    if isinstance(data, str):
        try:
            parsed = json.loads(data)
        except ValueError:
            return {"data": data[:TEST_DATA_CHARS], "data_truncated": len(data) > TEST_DATA_CHARS}
    records = parsed
    out: dict[str, Any] = {}
    if top and isinstance(parsed, dict):
        records = parsed.get(top)
        if records is None and not _is_page(parsed):
            # ISE 3.5 answers the first record itself, already taken out of the top-level object.
            records = [parsed]
            out["data_note"] = "ISE's test answered one record (taken from the top-level object)"
    if isinstance(records, list):
        out["records"] = len(records)
        out["first_record"] = records[0] if records else None
        if isinstance(parsed, dict) and "count" in parsed:
            out["source_count"] = parsed.get("count")
        key = _json_path(unique_id)
        first = records[0] if records else None
        if key and isinstance(first, dict):
            value = first.get(key)
            if isinstance(value, int | float) and not isinstance(value, bool):
                out["warning"] = f"unique_id {key!r} is a number ({value}) in the record: {NUMERIC_ID_HINT}"
            elif key not in first:
                out["warning"] = f"The first record has no unique_id attribute {key!r}: check the setting"
    else:
        text = json.dumps(parsed, default=str)
        out["data"] = text[:TEST_DATA_CHARS]
        out["data_truncated"] = len(text) > TEST_DATA_CHARS
        if top:
            out["warning"] = f"No list under top_level_object {top!r} in the answer: check the setting"
    return out


def _sync_status(data: Any) -> dict[str, Any]:
    d = _unwrap(data)
    c = d.get("connector") if isinstance(d, dict) and isinstance(d.get("connector"), dict) else d
    status = (c or {}).get("syncStatus") if isinstance(c, dict) else None
    upper = str(status or "").upper()
    out: dict[str, Any] = {"sync_status": status, "sync_completed": upper in SYNC_DONE}
    if upper in SYNC_RUNNING:
        out["sync_running"] = True
        if upper.startswith("SCH_"):
            out["sync_hint"] = (
                "A scheduled sync is running; ISE refuses Sync Now until it ends. If it stays here for more "
                f"than 15 minutes: {NUMERIC_ID_HINT}"
            )
    return out


# --- tools --------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:  # noqa: C901 - one registration block per tool
    @reg.read(title="pxGrid Direct connectors and their sync status")
    async def ise_pxgrid_direct_status(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="Connector name; omit to list every connector with its sync status")
        ] = None,
        unique_id: Annotated[
            str | None,
            Field(
                description="One record's unique id (the connector's unique_id attribute): show it as "
                "ISE holds it"
            ),
        ] = None,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """pxGrid Direct connectors (a REST CMDB such as NetBox as an endpoint attribute source): their URL,
        identifiers, attribute mapping and schedules, the last sync's status (INPROGRESS, QUEUED, SYNC
        COMPLETED, ERRORED), and with unique_id one record as ISE holds it. Credentials are never shown."""
        app: IseApp = get_client(ctx)
        if unique_id is not None and name is None:
            raise InvalidRequest("unique_id needs the connector name")
        if name is None:
            rows = []
            for c in await list_connectors(app):
                row = connector_view(c)
                try:
                    row.update(
                        _sync_status(
                            await app.openapi.get(f"{SYNC_STATUS}/{quote(str(row['name']), safe='')}")
                        )
                    )
                except (NotFound, UpstreamError) as e:
                    row["sync_status_error"] = str(e)
                rows.append(row)
            return object_result(
                {"connectors": rows, "count": len(rows)},
                fmt=response_format,
                note=None
                if rows
                else "No pxGrid Direct connectors: ise_set_pxgrid_direct_connector creates one",
            )
        c = await require_connector(app, name)
        cname = str(c.get("connectorName"))
        out: dict[str, Any] = {**connector_view(c)}
        try:
            out.update(_sync_status(await app.openapi.get(f"{SYNC_STATUS}/{quote(cname, safe='')}")))
        except (NotFound, UpstreamError) as e:
            out["sync_status_error"] = str(e)
        if unique_id is not None:
            try:
                rec = await app.openapi.get(f"{PUSH}/{quote(cname, safe='')}/{quote(unique_id, safe='')}")
            except NotFound:
                out["record"] = None
                out["record_note"] = (
                    f"ISE holds no record {unique_id!r} for {cname} (not synced yet, or another id)"
                )
            else:
                data = rec.get("data", rec) if isinstance(rec, dict) else rec
                out["record"] = data[0] if isinstance(data, list) and len(data) == 1 else data
        if out.get("correlation_id"):
            out["next"] = (
                f"Endpoints whose {out['correlation_id']} matches get the attributes: ise_endpoint_360(mac); "
                f"authorization rules match '{cname}:<attribute> EQUALS <value>'"
            )
        return object_result(out, fmt=response_format)

    @reg.read(title="Test a pxGrid Direct connector")
    async def ise_test_pxgrid_direct(
        ctx: Context,
        name: Annotated[str, Field(description="Saved connector name (ise_set_pxgrid_direct_connector)")],
        secret_env: Annotated[
            str | None,
            Field(
                description="ISE_PXGRID_DIRECT_* variable with the CMDB credential (ISE doesn't hand saved "
                "credentials back, so the test needs it again); omit for a source without one"
            ),
        ] = None,
        token_scheme: Annotated[
            str | None,
            Field(
                description="Word before the token (as set on the connector; default the saved one, else "
                "'Token' for an Authorization header; '' = none)"
            ),
        ] = None,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """Have ISE fetch the saved connector's bulk URL now (POST test-connector) and report whether it
        answered, the error if not, and how many records sit under the top-level object, with the first
        one. Changes nothing on ISE or the CMDB. The credential goes to the connector's own saved URL."""
        app: IseApp = get_client(ctx)
        c = await require_connector(app, name)
        view = connector_view(c)
        secret = secret_from_env(secret_env) if secret_env else None
        bulk = dict(_fetch(c, "bulk"))
        auth = str(view["auth"] or "basic")
        auth_values: dict[str, Any] = {}
        if auth == "basic":
            auth_values = {"userName": view["username"] or "", "password": secret or ""}
            if bulk:
                bulk["basicAuthProperties"] = {
                    **(bulk.get("basicAuthProperties") or {}),
                    "password": secret or "",
                }
        elif auth == "apikey":
            props = dict(bulk.get("apiKeyProperties") or {})
            key = props.get("key")
            if secret is not None:
                # The saved scheme ('Token', 'Bearer') when ISE shows it, else NetBox's 'Token' for an
                # Authorization header; token_scheme overrides.
                saved = str(key or "")
                scheme = (
                    token_scheme.strip()
                    if token_scheme is not None
                    else saved.split(" ", 1)[0]
                    if " " in saved
                    else "Token"
                    if str(props.get("headerName") or "").lower() == "authorization"
                    else ""
                )
                key = f"{scheme} {secret}" if scheme else secret
            props["key"] = key or ""
            auth_values = {
                k: v for k, v in props.items() if k in ("keyType", "headerName", "key", "paramName")
            }
            if bulk:
                bulk["apiKeyProperties"] = props
        attrs = c.get("attributes") or {}
        body: dict[str, Any] = {
            "connectorName": view["name"],
            "url": view["bulk_url"],
            "authType": auth,
            "authValues": auth_values,
            "responseParsing": attrs.get("topLevelObject"),
            "uniqueID": attrs.get("uniqueIdentifier"),
            "skipCertificateValidations": bool(c.get("skipCertificateValidations")),
        }
        if view["incremental_url"]:
            body["incrementalUrl"] = view["incremental_url"]
        if bulk:
            body["flexibleUrl"] = {"bulk": bulk}
        res = _unwrap(await app.openapi.post(TEST, body))
        res = res if isinstance(res, dict) else {"data": res}
        secrets = [s for s in (secret, str(auth_values.get("key") or "")) if s]
        status = str(res.get("status") or "")
        out: dict[str, Any] = {
            "name": view["name"],
            "url": view["bulk_url"],
            "status": status or None,
            "passed": status.lower() in ("success", "ok", "passed", "200") and not res.get("error"),
            "error": _redacted(res.get("error"), secrets) if res.get("error") else None,
        }
        if res.get("data") is not None:
            out.update(
                _redacted(
                    _sample(res.get("data"), attrs.get("topLevelObject"), attrs.get("uniqueIdentifier")),
                    secrets,
                )
            )
        if not out["passed"] and not secret_env and view["credential_set"]:
            out["hint"] = "ISE didn't return the saved credential: pass secret_env to test with it"
        return object_result(out, fmt=response_format)

    @reg.write(title="Create or update a pxGrid Direct connector")
    async def ise_set_pxgrid_direct_connector(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                description="Connector name (also the dictionary authorization rules use), e.g. "
                "'mcp-netbox-dcim'"
            ),
        ],
        bulk_url: Annotated[
            str | None,
            Field(
                description="URL ISE fetches for a full sync (required to create), e.g. "
                "'https://netbox.example.com/api/dcim/devices/?limit=1000'"
            ),
        ] = None,
        incremental_url: Annotated[
            str | None, Field(description="URL for incremental syncs (records changed since the last one)")
        ] = None,
        auth: Annotated[
            Literal["apikey", "basic"] | None,
            Field(
                description="apikey (a token in a header: NetBox) or basic (username + password); "
                "default apikey"
            ),
        ] = None,
        secret_env: Annotated[
            str | None,
            Field(
                description="Server environment variable with the API token or password, e.g. "
                "'ISE_PXGRID_DIRECT_NETBOX_TOKEN' (also <var>_FILE; never shown)"
            ),
        ] = None,
        username: Annotated[str | None, Field(description="Basic-auth username")] = None,
        token_header: Annotated[
            str | None, Field(description="Header carrying the token (default 'Authorization')")
        ] = None,
        token_scheme: Annotated[
            str | None,
            Field(
                description="Word before the token in the header (default 'Token', NetBox's; 'Bearer'; "
                "'' = none)"
            ),
        ] = None,
        top_level_object: Annotated[
            str | None,
            Field(
                description="JSON key holding the record list ('results' for NetBox, 'result' for ServiceNow)"
            ),
        ] = None,
        unique_id: Annotated[
            str | None,
            Field(
                description="Record attribute that is unique per record, holding a string (NetBox 'name' "
                "or 'serial'; not NetBox 'id': ISE 3.5 doesn't finish a sync keyed on a number; required to "
                "create)"
            ),
        ] = None,
        correlation_id: Annotated[
            str | None,
            Field(
                description="Record attribute with the endpoint MAC address that ties records to "
                "endpoints (required to create)"
            ),
        ] = None,
        version_id: Annotated[
            str | None,
            Field(description="Record attribute that changes with each edit (NetBox 'last_updated')"),
        ] = None,
        attributes: Annotated[
            dict[str, str] | None,
            Field(
                description="Dictionary attribute name -> record attribute, e.g. "
                "{'role': 'role', 'site': 'site'}; "
                "replaces the whole mapping"
            ),
        ] = None,
        full_sync_interval: Annotated[
            int | None, Field(ge=1, le=1000, description="Full sync every N units (default 24 hours)")
        ] = None,
        full_sync_unit: Annotated[
            Literal["hours", "days", "weeks"] | None, Field(description="Unit (default hours)")
        ] = None,
        incremental_sync_interval: Annotated[
            int | None,
            Field(ge=1, le=1000, description="Incremental sync every N units (needs incremental_url)"),
        ] = None,
        incremental_sync_unit: Annotated[
            Literal["hours", "days", "weeks"] | None, Field(description="Unit (default hours)")
        ] = None,
        start: Annotated[
            str | None,
            Field(
                description="First sync 'YYYY-MM-DDTHH:MM:SS', rounded up to the next 5 minutes as ISE "
                "does (default now: ISE runs the first full sync within 5 minutes)"
            ),
        ] = None,
        coa: Annotated[
            Literal["none", "reauth", "port_bounce"] | None,
            Field(description="CoA ISE sends when a record's attributes change (default none)"),
        ] = None,
        skip_cert_validation: Annotated[
            bool | None, Field(description="Don't validate the CMDB's certificate (default false; lab only)")
        ] = None,
        enabled: Annotated[bool | None, Field(description="Connector enabled (default true)")] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a pxGrid Direct connector (ISE pulls a REST CMDB such as NetBox on a schedule and adds the
        mapped record attributes to the matching endpoints, for authorization rules on
        '<connector>:<attribute>'), or update the one with this name: given fields change, others are kept.
        Key the connector on a string attribute: ISE 3.5 doesn't finish a sync keyed on a numeric id.
        The token or password comes from a server environment variable (secret_env) and is never shown.
        Preview-first with a diff; no_change when nothing would change. Then ise_test_pxgrid_direct and
        ise_pxgrid_direct_status."""
        app: IseApp = get_client(ctx)
        if not _NAME.match(name):
            raise InvalidRequest(f"Connector names are 1-64 letters, digits, '_' and '-': {name!r}")
        for arg, v in (("bulk_url", bulk_url), ("incremental_url", incremental_url)):
            if v:
                _check_url(v, arg)
        if attributes is not None and not attributes:
            raise InvalidRequest(
                "attributes needs at least one mapping (dictionary attribute -> record attribute)"
            )
        start_at = _start(start) if start is not None else None
        secret = secret_from_env(secret_env) if secret_env else None
        args = {
            k: v
            for k, v in {
                "name": name,
                "bulk_url": bulk_url,
                "incremental_url": incremental_url,
                "auth": auth,
                "secret_env": secret_env,
                "username": username,
                "token_header": token_header,
                "token_scheme": token_scheme,
                "top_level_object": top_level_object,
                "unique_id": unique_id,
                "correlation_id": correlation_id,
                "version_id": version_id,
                "attributes": attributes,
                "full_sync_interval": full_sync_interval,
                "full_sync_unit": full_sync_unit,
                "incremental_sync_interval": incremental_sync_interval,
                "incremental_sync_unit": incremental_sync_unit,
                "start": start,
                "coa": coa,
                "skip_cert_validation": skip_cert_validation,
                "enabled": enabled,
                "description": description,
            }.items()
        }
        existing = await find_connector(app, name)
        old = connector_view(existing) if existing else {}
        a = auth or old.get("auth") or ("basic" if username else "apikey")
        header = token_header or old.get("token_header") or "Authorization"
        scheme = "Token" if token_scheme is None else token_scheme.strip()
        if a == "apikey" and token_scheme is None and existing:
            saved = str((_fetch(existing, "bulk").get("apiKeyProperties") or {}).get("key") or "")
            if " " in saved:
                scheme = saved.split(" ", 1)[0]
        if a == "basic" and token_header:
            raise InvalidRequest("token_header goes with auth='apikey'")
        blockers: list[str] = []
        side: list[str] = []
        if start is not None and start_at != start:
            side.append(f"ISE starts syncs on 5-minute marks: start {start} becomes {start_at}")

        # Patch: only what the call names (plus what a change of auth or URL needs to stay consistent).
        patch: dict[str, Any] = {}
        attrs_patch: dict[str, Any] = {
            k: v
            for k, v in {
                "topLevelObject": top_level_object,
                "uniqueIdentifier": unique_id,
                "correlationIdentifier": correlation_id,
                "versionIdentifier": version_id,
            }.items()
            if v is not None
        }
        if attributes is not None:
            attrs_patch["attributeMapping"] = [
                {"jsonAttribute": src, "dictionaryAttribute": dict_name, "includeInDictionary": True}
                for dict_name, src in attributes.items()
            ]
        if attrs_patch:
            patch["attributes"] = attrs_patch
        flag: object
        for key, flag in (
            ("description", description),
            ("enabled", enabled),
            ("skipCertificateValidations", skip_cert_validation),
            ("coaType", COA[coa] if coa else None),
        ):
            if flag is not None:
                patch[key] = flag
        full = _sched(full_sync_interval, full_sync_unit, start_at)
        delta = _sched(incremental_sync_interval, incremental_sync_unit, start_at)
        if start_at and existing:
            # A new start alone moves the saved schedules' start.
            for key, sched in (("fullsyncSchedule", full), ("deltasyncSchedule", delta)):
                if sched is None and isinstance(existing.get(key), dict) and existing[key].get("interval"):
                    patch[key] = {"startDate": start_at}
        if full:
            patch["fullsyncSchedule"] = full
        if delta:
            patch["deltasyncSchedule"] = delta

        fetch_changed = any(
            v is not None
            for v in (bulk_url, incremental_url, auth, secret, username, token_header, token_scheme)
        )
        if fetch_changed:
            b_url = bulk_url or old.get("bulk_url")
            i_url = incremental_url if incremental_url is not None else old.get("incremental_url")
            user = username if username is not None else old.get("username")
            keep = None
            key_scheme = scheme
            if secret is None and existing and a == old.get("auth"):
                # No new credential: send the saved one back as ISE returned it.
                b = _fetch(existing, "bulk")
                keep = (
                    (b.get("apiKeyProperties") or {}).get("key")
                    if a == "apikey"
                    else (b.get("basicAuthProperties") or {}).get("password")
                    or (existing.get("url") or {}).get("password")
                )
                if a == "apikey" and isinstance(keep, str):
                    if _masked(keep):
                        # ISE masks the saved key: send its mask back untouched (no scheme prefix, or ISE
                        # would store 'Token ******' as the new key). A new scheme needs the token itself.
                        key_scheme = ""
                        if token_scheme is not None:
                            blockers.append(
                                "ISE doesn't return the saved token, so token_scheme can't be changed "
                                "without it: give secret_env too"
                            )
                    elif " " in keep:
                        keep = keep.split(" ", 1)[1]
            cred = secret if secret is not None else keep
            # flexibleUrl only: ISE 3.5 answers 400 to a body carrying `url` as well.
            flex: dict[str, Any] = {"bulk": _fetch_url(str(b_url), a, user, cred, header, key_scheme)}
            if i_url:
                flex["incremental"] = _fetch_url(str(i_url), a, user, cred, header, key_scheme)
            patch["flexibleUrl"] = flex
            if existing and a != old.get("auth") and secret is None:
                blockers.append(f"Changing auth to {a} needs the new credential: give secret_env")

        if existing:
            base = dict(existing)
            desired = deep_merge(base, {k: v for k, v in patch.items() if k != "flexibleUrl"})
            if "flexibleUrl" in patch:
                desired["flexibleUrl"] = patch["flexibleUrl"]  # whole: no stale credential of the other auth
            if _fetch(desired, "bulk"):
                # ISE's GET returns the legacy `url` block too; a PUT carrying both is refused (400).
                desired.pop("url", None)
            if "attributes" in patch and "attributeMapping" in patch["attributes"]:
                desired["attributes"]["attributeMapping"] = patch["attributes"]["attributeMapping"]
            changes = field_changes(connector_view(base), connector_view(desired))
            if secret is not None:
                changes["credential"] = {
                    "from": "******" if old.get("credential_set") else None,
                    "to": "******",
                }
            noop = unchanged({k: v for k, v in changes.items() if k != "credential"}, secret)
            if not noop and start_at is None:
                # ISE 3.5 validates startDate on every PUT and refuses a past one (#189): the PUT carries
                # the saved start from the GET, so move a past one to the next sync time it implies.
                rolled = False
                for key, label in (
                    ("fullsyncSchedule", "full sync"),
                    ("deltasyncSchedule", "incremental sync"),
                ):
                    if (r := _rolled_start(desired.get(key), _now())) is None:
                        continue
                    same = (base.get(key) or {}).get("interval") == desired[key].get("interval") and (
                        base.get(key) or {}
                    ).get("intervalUnit") == desired[key].get("intervalUnit")
                    desired[key] = {**desired[key], "startDate": r[1]}
                    rolled = True
                    side.append(
                        f"ISE refuses a past start: the saved {label} start {r[0]} moves to {r[1]}, "
                        + ("same interval" if same else "on the new interval")
                        + " (pass start to choose another)"
                    )
                if rolled:
                    changes = {
                        **field_changes(connector_view(base), connector_view(desired)),
                        **({"credential": changes["credential"]} if "credential" in changes else {}),
                    }
            if desired.get("skipCertificateValidations") and not base.get("skipCertificateValidations"):
                side.append(
                    "ISE stops validating the CMDB's certificate: anyone on the path can feed it records"
                )
            if not noop:
                side.append(
                    "The next sync uses the new settings; endpoints keep their current attributes until then"
                )
            cname = str(existing.get("connectorName"))
            plan = Plan(
                f"Update pxGrid Direct connector {cname}",
                details={"changes": changes, "method": "PUT", "path": f"{CONFIG}/{cname}"},
                blockers=blockers,
                fingerprint=fingerprint(connector_view(existing)),
                side_effects=side if not noop else [],
                noop=noop,
                noop_reason=f"pxGrid Direct connector {cname} already as requested" if noop else None,
            )

            async def update() -> Any:
                try:
                    await app.openapi.put(f"{CONFIG}/{quote(cname, safe='')}", {"connector": desired})
                except UpstreamError as e:
                    if (hinted := _past_start_hint(e)) is None:
                        raise
                    raise hinted from e
                return {"updated": cname, "connector": connector_view(desired)}

            return await preview_or_apply(
                ctx,
                tool="ise_set_pxgrid_direct_connector",
                args=args,
                confirm=confirm,
                plan=plan,
                apply=update,
            )

        # Create.
        blockers += [
            f"{arg} is required to create a connector"
            for arg, v in (
                ("bulk_url", bulk_url),
                ("unique_id", unique_id),
                ("correlation_id", correlation_id),
                ("attributes", attributes),
            )
            if v is None
        ]
        if secret is None:
            side.append("No credential (secret_env): ISE fetches the URL unauthenticated")
        if incremental_sync_interval is not None and not incremental_url:
            blockers.append("incremental_sync_interval needs incremental_url")
        start_at = start_at or _start(None)
        full = {"interval": 24, "intervalUnit": "hours", **(full or {}), "startDate": start_at}
        if delta:
            patch["deltasyncSchedule"] = {"intervalUnit": "hours", **delta, "startDate": start_at}
        body: dict[str, Any] = {
            "connectorName": name,
            "connectorType": "urlfetcher",
            "protocol": "http",
            "description": description or "",
            "enabled": True if enabled is None else enabled,
            "skipCertificateValidations": bool(skip_cert_validation),
            "coaType": COA[coa or "none"],
            "fullsyncSchedule": full,
            **{
                k: v
                for k, v in patch.items()
                if k
                not in ("description", "enabled", "skipCertificateValidations", "coaType", "fullsyncSchedule")
            },
        }
        body.setdefault("attributes", {})
        if bulk_url and urlsplit(bulk_url).scheme == "http":
            side.append(
                "Plain http: the CMDB credential and records cross the network unencrypted (use https)"
            )
        https = bool(bulk_url) and urlsplit(str(bulk_url)).scheme == "https"
        if body["skipCertificateValidations"]:
            side.append("ISE won't validate the CMDB's certificate: anyone on the path can feed it records")
        elif https:
            side.append(
                "ISE must trust the CMDB's certificate chain (System Certificates > Trusted Certificates)"
            )
        side.append(
            f"ISE runs the first full sync at {body['fullsyncSchedule'].get('startDate')}; endpoints "
            "whose MAC "
            f"matches {correlation_id!r} get the attributes; rules match '{name}:<attribute>'"
        )
        plan = Plan(
            f"Create pxGrid Direct connector {name}",
            details={**connector_view(body), "method": "POST", "path": CONFIG},
            blockers=blockers,
            side_effects=side,
        )

        async def create() -> Any:
            try:
                await app.openapi.post(CONFIG, {"connector": body})
            except UpstreamError as e:
                if (hinted := _past_start_hint(e)) is None:
                    raise
                raise hinted from e
            return {"created": name, "connector": connector_view(body)}

        return await preview_or_apply(
            ctx, tool="ise_set_pxgrid_direct_connector", args=args, confirm=confirm, plan=plan, apply=create
        )


async def delete_pxgrid_direct_connector(
    ctx: Context, app: IseApp, target: str, confirm: str | None
) -> dict[str, Any]:
    """ise_delete_object kind='pxgrid_direct_connector': DELETE /connector-config/{connectorName}."""
    c = await require_connector(app, target)
    cname = str(c.get("connectorName"))
    view = connector_view(c)
    path = f"{CONFIG}/{cname}"
    plan = Plan(
        f"Delete pxGrid Direct connector {cname}",
        details={**view, "method": "DELETE", "path": path},
        fingerprint=fingerprint(view),
        side_effects=[
            f"ISE stops syncing {view.get('bulk_url')}; the attributes it gave endpoints go with its "
            "dictionary",
            f"Authorization rules on '{cname}:<attribute>' stop matching: check ise_list_policy_sets first",
        ],
    )

    async def apply() -> Any:
        try:
            await app.openapi.delete(f"{CONFIG}/{quote(cname, safe='')}")
        except UpstreamError as e:
            if e.status_code != 500:
                raise
            # Seen live (#170): a 500 while a scheduled sync hangs; a fresh preview + confirm then deleted it.
            raise UpstreamError(
                f"{e} ISE answers 500 while a sync is still running or just ended: check "
                f"ise_pxgrid_direct_status(name='{cname}'), then preview the delete again and confirm it",
                500,
            ) from e
        return {"deleted": cname}

    return await preview_or_apply(
        ctx,
        tool="ise_delete_object",
        args={"kind": "pxgrid_direct_connector", "target": target},
        confirm=confirm,
        plan=plan,
        apply=apply,
    )

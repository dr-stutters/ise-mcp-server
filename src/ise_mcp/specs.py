"""Spec sources for <prefix>_search_spec / get_definition / api_call.

- openapi: ISE serves one springfox OpenAPI 3 doc per group. `/api/swagger-resources` lists them.
- ers:     ERS has no OpenAPI doc. Its online SDK loads a data model (`/ers/data-model.json`: fields,
           types, required, enums per resource); this module turns it into a synthetic OpenAPI doc
           with the standard ERS CRUD paths.
- mnt:     MnT has no machine-readable spec; a small hand-written doc covers its REST calls.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ise_mcp._core.spec import SpecSource
from ise_mcp.client import IseApp

log = logging.getLogger(__name__)

_ALLOWED_RE = re.compile(r"allowed values:\s*(.+)", re.IGNORECASE)


async def load_openapi(app: IseApp) -> list[dict[str, Any]]:
    groups = await app.openapi.get("/api/swagger-resources")
    docs: list[dict[str, Any]] = []
    for g in groups or []:
        if not isinstance(g, dict) or not g.get("name"):
            continue
        name = str(g["name"])
        try:
            doc = await app.openapi.get("/api/v3/api-docs", {"group": name})
        except Exception as e:  # one broken group shouldn't hide the rest
            log.warning("Skipping OpenAPI group %s: %s", name, e)
            continue
        if isinstance(doc, dict):
            for op in _operations(doc):
                op.setdefault("tags", [])
                op["tags"] = [*op["tags"], name]
            docs.append(doc)
    return docs


def _operations(doc: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for item in (doc.get("paths") or {}).values():
        if isinstance(item, dict):
            out += [
                op
                for m, op in item.items()
                if m in ("get", "post", "put", "patch", "delete") and isinstance(op, dict)
            ]
    return out


# --- ERS ----------------------------------------------------------------------------------------

_TYPES = {
    "string": "string",
    "boolean": "boolean",
    "integer": "integer",
    "int": "integer",
    "long": "integer",
    "float": "number",
    "double": "number",
    "date": "string",
    "list": "array",
}


def _field_schema(f: dict[str, Any], schemas: dict[str, Any], prefix: str) -> dict[str, Any]:
    ftype = str(f.get("type") or "")
    desc = str(f.get("description") or "")
    children = [c for c in f.get("childNodes") or [] if isinstance(c, dict) and c.get("field")]
    out: dict[str, Any]
    if children:
        name = f"{prefix}.{f['field']}"
        schemas[name] = _object_schema(children, schemas, name)
        out = {"$ref": f"#/components/schemas/{name}"}
        if "list" in ftype.lower() or f["field"].endswith("List"):
            out = {"type": "array", "items": out}
        return out
    out = {"type": _TYPES.get(ftype.lower(), "string")}
    if ftype.lower() == "enum" and (m := _ALLOWED_RE.search(desc)):
        out = {"type": "string", "enum": [v.strip() for v in m.group(1).split(",") if v.strip()]}
    if "list" in ftype.lower() and out.get("type") != "array":
        out = {"type": "array", "items": {"type": "string"}}
    if desc:
        out["description"] = desc[:200]
    if f.get("defaultValue") not in (None, ""):
        out["default"] = f["defaultValue"]
    return out


def _object_schema(fields: list[dict[str, Any]], schemas: dict[str, Any], prefix: str) -> dict[str, Any]:
    props: dict[str, Any] = {}
    required: list[str] = []
    for f in fields:
        if not isinstance(f, dict) or not f.get("field"):
            continue
        props[str(f["field"])] = _field_schema(f, schemas, prefix)
        if str(f.get("required", "")).lower() == "yes":
            required.append(str(f["field"]))
    out: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        out["required"] = required
    return out


# ERS request/response bodies are wrapped in a type name that the data model doesn't include. These were
# read from GET responses on ISE 3.5 (plus the documented names for resources the lab had no objects of).
ERS_WRAPPERS = {
    "activedirectory": "ERSActiveDirectory",
    "adminuser": "AdminUser",
    "allowedprotocols": "AllowedProtocols",
    "ancendpoint": "ErsAncEndpoint",
    "ancpolicy": "ErsAncPolicy",
    "authorizationprofile": "AuthorizationProfile",
    "byodportal": "BYODPortal",
    "certificateprofile": "CertificateProfile",
    "certificatetemplate": "ERSCertificateTemplate",
    "downloadableacl": "DownloadableAcl",
    "egressmatrixcell": "EgressMatrixCell",
    "endpoint": "ERSEndPoint",
    "endpointgroup": "EndPointGroup",
    "externalradiusserver": "ExternalRadiusServer",
    "guestsmtpnotificationsettings": "ERSGuestSmtpNotificationSettings",
    "guesttype": "GuestType",
    "guestuser": "GuestUser",
    "hotspotportal": "HotspotPortal",
    "identitygroup": "IdentityGroup",
    "idstoresequence": "IdStoreSequence",
    "internaluser": "InternalUser",
    "mydeviceportal": "MyDevicePortal",
    "networkdevice": "NetworkDevice",
    "networkdevicegroup": "NetworkDeviceGroup",
    "node": "Node",
    "portal": "ERSPortal",
    "portalglobalsetting": "PortalCustomizationGlobalSetting",
    "portaltheme": "PortalTheme",
    "profilerprofile": "ProfilerProfile",
    "radiusserversequence": "RadiusServerSequence",
    "selfregportal": "SelfRegPortal",
    "sgacl": "Sgacl",
    "sgmapping": "SGMapping",
    "sgmappinggroup": "SGMappingGroup",
    "sgt": "Sgt",
    "sgtvnvlan": "SgtVNVlanContainer",
    "sponsoredguestportal": "SponsoredGuestPortal",
    "sponsorgroup": "SponsorGroup",
    "sponsorportal": "SponsorPortal",
    "sxpconnections": "ERSSxpConnection",
    "sxplocalbindings": "ERSSxpLocalBindings",
    "sxpvpns": "ERSSxpVpn",
    "tacacscommandsets": "TacacsCommandSets",
    "tacacsexternalservers": "TacacsExternalServer",
    "tacacsprofile": "TacacsProfile",
    "tacacsserversequence": "TacacsServerSequence",
}


def ers_doc_from_data_model(model: dict[str, Any], version: str = "ERS") -> dict[str, Any]:
    """Synthetic OpenAPI 3 doc: for each resource, list/create and get/update/delete by id."""
    paths: dict[str, Any] = {}
    schemas: dict[str, Any] = {}
    note = (
        "Synthesised from the ERS SDK data model; not every resource supports every method. Bodies are "
        'wrapped in the resource type, e.g. {"NetworkDevice": {...}} (see a GET response\'s top-level key).'
    )
    for key, fields in sorted(model.items()):
        if not isinstance(fields, list):
            continue
        res = key.rsplit(".", 1)[-1]
        title = key
        schema_name = f"ers.{res}"
        common = [
            {"field": "name", "type": "String", "required": "Yes", "description": "Resource name"},
            {"field": "id", "type": "String", "required": "No", "description": "Resource UUID (update only)"},
            {"field": "description", "type": "String", "required": "No", "description": ""},
        ]
        all_fields = common + fields
        schemas[schema_name] = _object_schema(all_fields, schemas, schema_name)
        schemas[schema_name]["description"] = f"ERS {title}. {note}"
        inner = {"$ref": f"#/components/schemas/{schema_name}"}
        wrapper = ERS_WRAPPERS.get(res)
        if wrapper:
            schemas[schema_name]["description"] += f' Request/response body: {{"{wrapper}": {{...}}}}.'
            body_schema: dict[str, Any] = {
                "type": "object",
                "required": [wrapper],
                "properties": {wrapper: inner},
            }
        else:
            body_schema = inner
        ref = {"content": {"application/json": {"schema": body_schema}}}
        base = f"/ers/config/{res}"
        tag = [f"ERS {title}"]
        paging = [
            {
                "name": "page",
                "in": "query",
                "schema": {"type": "integer"},
                "description": "Page number (1-based)",
            },
            {"name": "size", "in": "query", "schema": {"type": "integer", "maximum": 100}},
            {
                "name": "filter",
                "in": "query",
                "schema": {"type": "string"},
                "description": "field.OP.value, e.g. name.CONTAINS.core (EQ, NEQ, STARTSW, CONTAINS...)",
            },
        ]
        id_param = [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]
        paths[base] = {
            "get": {
                "operationId": f"ers_list_{res}",
                "summary": f"List {title} (ERS; id/name only)",
                "tags": tag,
                "parameters": paging,
                "responses": {"200": {"description": "SearchResult"}},
            },
            "post": {
                "operationId": f"ers_create_{res}",
                "summary": f"Create {title} (ERS)",
                "tags": tag,
                "requestBody": ref,
                "responses": {"201": {"description": "Location header has the id"}},
            },
        }
        paths[base + "/{id}"] = {
            "get": {
                "operationId": f"ers_get_{res}",
                "summary": f"Get {title} by id (ERS)",
                "tags": tag,
                "parameters": id_param,
                "responses": {"200": ref},
            },
            "put": {
                "operationId": f"ers_update_{res}",
                "summary": f"Update {title} by id (ERS)",
                "tags": tag,
                "parameters": id_param,
                "requestBody": ref,
                "responses": {"200": {"description": "ok"}},
            },
            "delete": {
                "operationId": f"ers_delete_{res}",
                "summary": f"Delete {title} by id (ERS)",
                "tags": tag,
                "parameters": id_param,
                "responses": {"204": {"description": "deleted"}},
            },
        }
    return {
        "openapi": "3.0.0",
        "info": {"title": "ISE ERS", "version": version},
        "paths": paths,
        "components": {"schemas": schemas},
    }


async def load_ers(app: IseApp) -> dict[str, Any]:
    model = await app.ers.get("/ers/data-model.json")
    if not isinstance(model, dict):
        raise ValueError("ERS data model is not JSON")
    return ers_doc_from_data_model(model, await app.version())


# --- MnT ----------------------------------------------------------------------------------------


def _mnt_op(op_id: str, summary: str, params: list[str] | None = None) -> dict[str, Any]:
    return {
        "get": {
            "operationId": op_id,
            "summary": summary + " (MnT; XML response)",
            "tags": ["MnT"],
            "parameters": [
                {"name": p, "in": "path", "required": True, "schema": {"type": "string"}}
                for p in params or []
            ],
            "responses": {"200": {"description": "XML"}},
        }
    }


MNT_DOC: dict[str, Any] = {
    "openapi": "3.0.0",
    "info": {"title": "ISE MnT", "version": "mnt"},
    "paths": {
        "/admin/API/mnt/Version": _mnt_op("mntVersion", "ISE version and node type"),
        "/admin/API/mnt/Session/ActiveCount": _mnt_op("mntActiveCount", "Number of active sessions"),
        "/admin/API/mnt/Session/ActiveList": _mnt_op("mntActiveList", "List active sessions"),
        "/admin/API/mnt/Session/PostureCount": _mnt_op("mntPostureCount", "Number of posture sessions"),
        "/admin/API/mnt/Session/ProfilerCount": _mnt_op("mntProfilerCount", "Number of profiler sessions"),
        "/admin/API/mnt/Session/AuthList/{start}/{end}": _mnt_op(
            "mntAuthList", "Sessions authenticated in a window (null/null = all active)", ["start", "end"]
        ),
        "/admin/API/mnt/Session/MACAddress/{mac}": _mnt_op(
            "mntSessionByMac", "Session by endpoint MAC", ["mac"]
        ),
        "/admin/API/mnt/Session/UserName/{user}": _mnt_op(
            "mntSessionByUser", "Session by username", ["user"]
        ),
        "/admin/API/mnt/Session/EndPointIPAddress/{ip}": _mnt_op(
            "mntSessionByIp", "Session by endpoint IP", ["ip"]
        ),
        "/admin/API/mnt/Session/Active/SessionID/{session}/0": _mnt_op(
            "mntSessionById", "Session by audit session id", ["session"]
        ),
        "/admin/API/mnt/AuthStatus/MACAddress/{mac}/{seconds}/{records}/All": _mnt_op(
            "mntAuthStatus",
            "Authentication attempts for a MAC in the last N seconds",
            ["mac", "seconds", "records"],
        ),
        "/admin/API/mnt/FailureReasons": _mnt_op(
            "mntFailureReasons", "Catalog of authentication failure reasons"
        ),
        "/admin/API/mnt/CoA/Reauth/{server}/{mac}/{type}": _mnt_op(
            "mntCoaReauth",
            "CoA reauthenticate (type 0 default, 1 last, 2 rerun); disruptive",
            ["server", "mac", "type"],
        ),
        "/admin/API/mnt/CoA/Disconnect/{server}/{mac}/{type}/{nas_ip}/{endpoint_ip}": _mnt_op(
            "mntCoaDisconnect",
            "CoA disconnect (type 0 default, 1 port bounce, 2 port shutdown); disruptive",
            ["server", "mac", "type", "nas_ip", "endpoint_ip"],
        ),
    },
}


async def load_mnt(app: IseApp) -> dict[str, Any]:
    return MNT_DOC


def spec_sources(app: IseApp) -> list[SpecSource]:
    return [
        SpecSource(
            "openapi",
            load_openapi,
            client=lambda a: a.openapi,
            version=lambda a: a.version(),
            description="ISE OpenAPI (/api/v1), all groups",
        ),
        SpecSource(
            "ers",
            load_ers,
            client=lambda a: a.ers,
            version=lambda a: a.version(),
            description="ISE ERS (/ers/config), from the SDK data model",
        ),
        SpecSource("mnt", load_mnt, client=lambda a: a.mnt, description="ISE MnT (/admin/API/mnt), XML"),
    ]

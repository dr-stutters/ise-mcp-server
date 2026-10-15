"""Endpoint bulk operations, custom attributes and rejected endpoints (OpenAPI)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import contextlib
import hashlib
import json
import re
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import BaseModel, Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
    poll_until,
    preview_or_apply,
)
from stutters_mcp_core.http import page_of

from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_name_map, gather_limited, is_uuid, normalize_mac

ATTR_TYPES = ("String", "Int", "Long", "Float", "Boolean", "Date", "IP")
EXISTENCE_CHECK_MAX = 500
SAMPLE = 5
TASK_DONE = ("COMPLETED_WITH_SUCCESS", "COMPLETED_WITH_FAILURE", "FAILED", "COMPLETED")


class EndpointSpec(BaseModel):
    """One endpoint in a bulk request."""

    mac: str = Field(description="Endpoint MAC address (any notation)")
    group: str | None = Field(default=None, description="Endpoint identity group name or id")
    static_group: bool = Field(default=True, description="Pin the group when one is given")
    description: str | None = Field(default=None, description="Free-text description")
    custom_attributes: dict[str, str] | None = Field(
        default=None, description="Custom attribute values by name (see ise_list_custom_attributes)"
    )


async def custom_attribute_defs(app: IseApp) -> dict[str, str]:
    """{name: type} of the endpoint custom attributes defined in ISE."""
    data = await app.openapi.get("/api/v1/endpoint-custom-attribute")
    data = data.get("response", data) if isinstance(data, dict) else data
    return {
        str(a["attributeName"]): str(a.get("attributeType"))
        for a in data or []
        if isinstance(a, dict) and a.get("attributeName")
    }


def check_custom_values(values: dict[str, Any], defs: dict[str, str]) -> list[str]:
    """Problems with custom attribute values: unknown names (ISE silently drops them) and bad types."""
    problems = []
    for name, value in values.items():
        kind = defs.get(name)
        if kind is None:
            close = [d for d in defs if d.lower() == name.lower()]
            hint = f" (did you mean {close[0]}?)" if close else ""
            problems.append(
                f"Custom attribute {name!r} is not defined{hint}; create it with ise_set_custom_attribute"
            )
            continue
        text = str(value)
        try:
            if kind in ("Int", "Long"):
                int(text)
            elif kind == "Float":
                float(text)
            elif kind == "Boolean" and text.lower() not in ("true", "false"):
                raise ValueError
        except ValueError:
            problems.append(f"Custom attribute {name} is {kind}; {text!r} is not a valid value")
    return problems


async def endpoint_exists(app: IseApp, mac: str) -> bool:
    try:
        data = await app.openapi.get(f"/api/v1/endpoint/{quote(mac)}")
    except NotFound:
        return False
    return isinstance(data, dict) and bool(data.get("mac") or data.get("id"))


async def get_task(app: IseApp, task_id: str) -> dict[str, Any]:
    data = await app.openapi.get(f"/api/v1/task/{quote(task_id, safe='')}")
    return data if isinstance(data, dict) else {}


def task_summary(task: dict[str, Any]) -> dict[str, Any]:
    failures = [
        {"item": d.get("detail") or d.get("id"), "reason": d.get("rootCause")}
        for d in task.get("detailStatus") or []
        if isinstance(d, dict) and str(d.get("resourceExecutionStatus")).upper() != "SUCCESS"
    ]
    out = {
        "task_id": task.get("id"),
        "status": task.get("executionStatus"),
        "total": task.get("resourcesCount"),
        "succeeded": task.get("successCount"),
        "failed": task.get("failCount"),
    }
    if failures:
        out["failures"] = failures[:20]
        if len(failures) > 20:
            out["more_failures"] = len(failures) - 20
    return out


def rejected_macs(items: Any) -> set[str]:
    """MACs on ISE's rejected list; entries are MAC strings or objects with a mac/id field."""
    out: set[str] = set()
    for item in items if isinstance(items, list) else []:
        if isinstance(item, str):
            values: list[Any] = [item]
        elif isinstance(item, dict):
            values = [item.get(k) for k in ("mac", "macAddress", "id", "name")]
        else:
            values = []
        for v in values:
            if isinstance(v, str):
                with contextlib.suppress(InvalidRequest):
                    out.add(normalize_mac(v))
    return out


def register(reg: ToolRegistrar) -> None:  # noqa: C901 - one registration block per tool
    @reg.read(title="List endpoint custom attributes")
    async def ise_list_custom_attributes(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the endpoint custom attribute definitions (name and type: String, Int, Long, Float,
        Boolean, Date, IP). Values are set per endpoint with ise_set_endpoint or ise_bulk_endpoints,
        and policy matches them as 'EndPoints:<name>' (e.g. 'EndPoints:assetTier equals gold')."""
        app: IseApp = get_client(ctx)
        defs = await custom_attribute_defs(app)
        rows = [{"name": n, "type": t} for n, t in sorted(defs.items())]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.write(title="Create or delete an endpoint custom attribute", destructive=True)
    async def ise_set_custom_attribute(
        ctx: Context,
        name: Annotated[str, Field(description="Attribute name (letters, digits, '_'; e.g. assetTier)")],
        attribute_type: Annotated[
            Literal["String", "Int", "Long", "Float", "Boolean", "Date", "IP"],
            Field(description="Value type (ignored when deleting)"),
        ] = "String",
        delete: Annotated[bool, Field(description="Delete the definition instead of creating it")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an endpoint custom attribute definition (so endpoints can carry a value that policy
        matches as 'EndPoints:<name>'), or delete one. Preview-first. Creating is blocked when the
        name exists; deleting removes the attribute's value from every endpoint and breaks rules that
        use it."""
        app: IseApp = get_client(ctx)
        if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", name):
            raise InvalidRequest("Custom attribute names may only contain letters, digits and '_'")
        defs = await custom_attribute_defs(app)
        blockers: list[str] = []
        if delete:
            if name not in defs:
                raise NotFound(f"No custom attribute {name!r}; see ise_list_custom_attributes.", 404)
            plan = Plan(
                f"Delete custom attribute {name}",
                details={"name": name, "type": defs[name]},
                side_effects=[
                    "Every endpoint loses its value for this attribute",
                    f"Policy conditions on 'EndPoints:{name}' stop matching (check ise_get_policy_set)",
                ],
                fingerprint=f"{name}:{defs[name]}",
            )

            async def apply() -> Any:
                return await app.openapi.request(
                    "DELETE", f"/api/v1/endpoint-custom-attribute/{quote(name, safe='')}", expect="text"
                )
        else:
            if name in defs:
                blockers.append(f"Custom attribute {name!r} already exists ({defs[name]})")
            body = {"attributeName": name, "attributeType": attribute_type}
            plan = Plan(f"Create custom attribute {name} ({attribute_type})", details=body, blockers=blockers)

            async def apply() -> Any:
                return await app.openapi.request(
                    "POST", "/api/v1/endpoint-custom-attribute", json=body, expect="text"
                )

        async def apply_and_reset() -> Any:
            result = await apply()
            app.__dict__.pop("_dict_cache", None)  # the EndPoints dictionary changed
            return {"result": result}

        return await preview_or_apply(
            ctx,
            tool="ise_set_custom_attribute",
            args={"name": name, "attribute_type": attribute_type, "delete": delete},
            confirm=confirm,
            plan=plan,
            apply=apply_and_reset,
        )

    @reg.write(title="Bulk create, update or delete endpoints", destructive=True)
    async def ise_bulk_endpoints(
        ctx: Context,
        action: Annotated[
            Literal["create", "update", "delete"],
            Field(
                description="create new endpoints, update existing ones (only the given fields), or delete"
            ),
        ],
        endpoints: Annotated[
            list[EndpointSpec],
            Field(description="Endpoints (for delete only the mac is used)", min_length=1),
        ],
        max_items: Annotated[
            int,
            Field(ge=1, le=EXISTENCE_CHECK_MAX, description="Refuse requests larger than this (safety cap)"),
        ] = EXISTENCE_CHECK_MAX,
        wait: Annotated[bool, Field(description="Wait for ISE's bulk task to finish")] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create, update or delete many endpoints in one ISE bulk task (e.g. onboarding IoT/MAB devices
        from a CMDB list into an identity group with custom attributes). At most 500 endpoints per
        call. Preview-first: shows counts, a sample and conflicts (create: MAC already exists;
        update/delete: MAC unknown), which are left out of the request. Group names and custom
        attributes are checked first (ISE silently drops unknown attributes). Applied as an
        asynchronous task; with wait=true the result lists per-item failures, otherwise check it with
        ise_get_task. Changes apply at each endpoint's next authentication."""
        app: IseApp = get_client(ctx)
        seen: dict[str, EndpointSpec] = {}
        duplicates = []
        blockers: list[str] = []
        for e in endpoints:
            mac = normalize_mac(e.mac)
            if mac in seen:
                duplicates.append(mac)
                if seen[mac].model_dump(exclude={"mac"}) != e.model_dump(exclude={"mac"}):
                    blockers.append(f"{mac} is listed more than once with different settings")
                    continue
            seen[mac] = e
        if len(seen) > max_items:
            blockers.append(
                f"{len(seen)} endpoints exceed max_items={max_items}; split the request or raise max_items"
            )
        group_names = {e.group for e in seen.values() if e.group and action != "delete"}
        gid_by_name: dict[str, str] = {}
        if group_names:
            known = await ers_name_map(app, "endpointgroup")
            by_name = {v.lower(): k for k, v in known.items()}
            for g in group_names:
                gid = g if is_uuid(g) and g in known else by_name.get(g.lower())
                if gid is None:
                    blockers.append(f"No endpoint group named {g!r} (see ise_list_endpoint_groups)")
                else:
                    gid_by_name[g] = gid
        if action != "delete" and any(e.custom_attributes for e in seen.values()):
            defs = await custom_attribute_defs(app)
            problems: list[str] = []
            for e in seen.values():
                for p in check_custom_values(e.custom_attributes or {}, defs):
                    if p not in problems:
                        problems.append(p)
            blockers += problems[:10]

        conflicts: list[str] = []
        if not blockers:
            macs = list(seen)
            present = await gather_limited(macs, lambda m: endpoint_exists(app, m))
            exists = dict(zip(macs, present, strict=True))
            conflicts = [m for m in macs if exists[m] == (action == "create")]
        todo = [m for m in seen if m not in conflicts]
        if not todo and not blockers:
            blockers.append(
                "Nothing to do: every endpoint "
                + ("already exists" if action == "create" else "is unknown to ISE")
            )

        def body_for(mac: str) -> dict[str, Any]:
            e = seen[mac]
            item: dict[str, Any] = {"mac": mac}
            if action == "create":
                item["name"] = mac
            if e.group:
                item["groupId"] = gid_by_name.get(e.group, e.group)
                item["staticGroupAssignment"] = e.static_group
            if e.description is not None:
                item["description"] = e.description
            if e.custom_attributes:
                item["customAttributes"] = dict(e.custom_attributes)
            return item

        payload: Any = {"endpoints": todo} if action == "delete" else [body_for(m) for m in todo]
        details: dict[str, Any] = {
            "action": action,
            "endpoints_in_request": len(todo),
            "sample": (todo if action == "delete" else payload)[:SAMPLE],
        }
        if conflicts:
            details["left_out_conflicts"] = {
                "reason": "already exists" if action == "create" else "not found in ISE",
                "count": len(conflicts),
                "macs": conflicts[:20],
            }
        if duplicates:
            details["duplicates_merged"] = sorted(set(duplicates))[:20]
        side = ["Each endpoint's group/attributes apply at its next authentication (CoA to force it)"]
        if action == "delete":
            side = ["Deleted endpoints lose their static group and attributes; MAB may stop matching"]
        fp = hashlib.sha256(json.dumps([todo, conflicts]).encode()).hexdigest()
        plan = Plan(
            f"Bulk {action} of {len(todo)} endpoint(s)",
            details=details,
            blockers=blockers,
            side_effects=side,
            fingerprint=fp,
        )
        method = {"create": "POST", "update": "PUT", "delete": "DELETE"}[action]

        async def apply() -> Any:
            resp = await app.openapi.request(method, "/api/v1/endpoint/bulk", json=payload)
            task_id = str(resp.get("id")) if isinstance(resp, dict) and resp.get("id") else None
            if not task_id:
                return {"response": resp}
            if not wait:
                return {"task_id": task_id, "note": "Running; check it with ise_get_task."}
            task = await poll_until(
                lambda: get_task(app, task_id),
                done=lambda t: str(t.get("executionStatus", "")).upper() in TASK_DONE,
                describe=lambda t: f"{t.get('successCount')}/{t.get('resourcesCount')} done",
                timeout=600,
                ctx=ctx,
                what=f"bulk {action} task {task_id}",
            )
            return task_summary(task)

        return await preview_or_apply(
            ctx,
            tool="ise_bulk_endpoints",
            args={
                "action": action,
                "endpoints": [e.model_dump() for e in endpoints],
                "max_items": max_items,
                "wait": wait,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.read(title="Get an ISE task's status")
    async def ise_get_task(
        ctx: Context,
        task_id: Annotated[
            str, Field(description="Task id returned by a bulk tool (e.g. ise_bulk_endpoints)")
        ],
    ) -> ToolResult:
        """Status of an asynchronous ISE task (e.g. an endpoint bulk job): execution status, counts of
        succeeded/failed items and the reason for each failure."""
        app: IseApp = get_client(ctx)
        task = await get_task(app, task_id)
        if not task:
            raise NotFound(f"No task {task_id}", 404)
        return object_result(task_summary(task))

    @reg.write(title="Release rejected endpoints")
    async def ise_release_rejected_endpoint(
        ctx: Context,
        macs: Annotated[
            list[str], Field(description="MAC addresses to release (see ise_endpoint_360)", min_length=1)
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Release endpoints from ISE's rejected list (Context Visibility > Rejected Endpoints), e.g. after
        a BYOD/registration failure, so they can authenticate again. Preview-first; MACs that are not on
        the rejected list are reported and left out."""
        app: IseApp = get_client(ctx)
        wanted = list(dict.fromkeys(normalize_mac(m) for m in macs))
        try:
            data = await app.openapi.get("/api/v1/endpoint/getRejected")
        except UpstreamError as e:
            raise UpstreamError(f"Could not read the rejected endpoints: {e}") from e
        items = data.get("response", data) if isinstance(data, dict) else data
        rejected = rejected_macs(items)
        todo = [m for m in wanted if m in rejected]
        missing = [m for m in wanted if m not in todo]
        details: dict[str, Any] = {"release": todo}
        if missing:
            details["not_rejected"] = missing
        plan = Plan(
            f"Release {len(todo)} rejected endpoint(s)",
            details=details,
            blockers=[] if todo else ["None of these MACs is on the rejected list"],
            side_effects=["The endpoints can authenticate again at their next attempt"],
            fingerprint=hashlib.sha256(json.dumps(todo).encode()).hexdigest(),
        )

        async def apply() -> Any:
            return await app.openapi.request(
                "PUT", "/api/v1/endpoint/releaseRejectedEndpoints", json={"identifiers": todo}
            )

        return await preview_or_apply(
            ctx,
            tool="ise_release_rejected_endpoint",
            args={"macs": wanted},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

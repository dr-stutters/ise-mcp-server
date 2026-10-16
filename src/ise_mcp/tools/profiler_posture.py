"""Read-only profiler and posture views (I14, scoped first slice).

Guest/sponsor lifecycle is deliberately left out of this slice: it needs a sponsor account with REST
access and a guest portal set up on ISE (an external prerequisite), and is tracked on the roadmap.
Posture here is read-only (what is configured); it does not run or assess endpoints. Writes for these
areas stay on ise_api_call, as the gap analysis decided.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import ResponseFormat, ToolRegistrar, get_client
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list, list_result, openapi_all


def _posture_policy_row(p: dict[str, Any]) -> dict[str, Any]:
    reqs = p.get("requirementList") or []
    return {
        "name": p.get("name"),
        "enabled": p.get("enable"),
        "os": p.get("osNameList"),
        "type": p.get("postureType"),
        "compliance_module": p.get("complianceModule"),
        "requirements": len(reqs),
        "enforcement": sorted({str(r.get("enforcement")) for r in reqs if r.get("enforcement")}) or None,
        "identity_groups": len(p.get("roleList") or []) or None,
        "id": p.get("id"),
    }


def _posture_requirement_row(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": r.get("name"),
        "os": r.get("osNameList"),
        "type": r.get("postureType"),
        "rules": [c.get("name") for c in r.get("ruleList") or []] or None,
        "evaluation": r.get("conditionEvaluationOption"),
        "remediation": (r.get("remediation") or {}).get("name"),
        "compliance_module": r.get("complianceModule"),
        "id": r.get("id"),
    }


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List profiler profiles")
    async def ise_list_profiler_profiles(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="Filter to profiles whose name contains this (case-insensitive)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List endpoint profiler profiles (ISE ships ~900, e.g. 'Apple-Device', 'Cisco-IP-Phone').
        ERS returns name, description and id only; the profiling rules themselves aren't in ERS. Use
        name to find whether a profile exists and its id (for an EndPoints:EndPointPolicy
        authorization condition). Read-only; create/edit profiler policy via ise_api_call."""
        app: IseApp = get_client(ctx)
        filters = [f"name.CONTAINS.{name}"] if name else None
        page = await ers_list(app, "profilerprofile", filters=filters, limit=limit, offset=offset)
        return list_result(page, fmt=response_format, columns=["name", "description", "id"])

    @reg.read(title="List posture policies")
    async def ise_list_posture_policies(
        ctx: Context,
        enabled_only: Annotated[bool, Field(description="Only policies that are enabled")] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List posture policies (which OS/identity-group a requirement set applies to): name, enabled,
        OS, agent type, requirement count and enforcement (MANDATORY/OPTIONAL/AUDIT), compliance module.
        Read-only summary of what posture is configured; it does not assess any endpoint. Drill into a
        requirement with ise_list_posture_requirements."""
        app: IseApp = get_client(ctx)
        rows = [_posture_policy_row(p) for p in await openapi_all(app, "/api/v1/posture/policy")]
        if enabled_only:
            rows = [r for r in rows if r.get("enabled")]
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["name", "enabled", "os", "type", "requirements", "enforcement"],
        )

    @reg.read(title="List posture requirements")
    async def ise_list_posture_requirements(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List posture requirements (the checks a policy enforces): name, OS, agent type, the rules it
        contains, how they are combined (ALL_SUCCEED / ANY_FAIL), and the remediation. Read-only."""
        app: IseApp = get_client(ctx)
        rows = [_posture_requirement_row(r) for r in await openapi_all(app, "/api/v1/posture/requirement")]
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["name", "os", "type", "rules", "evaluation", "remediation"],
        )

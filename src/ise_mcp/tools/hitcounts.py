"""Reset policy hit counters (I56): the clean baseline before a policy review or clean-up.

ISE's counters carry no timestamp, so "this rule matched nothing" (ise_policy_audit's zero_hits finding)
only means something from a known reset. The OpenAPI has one POST .../reset-hitcount per counter table,
for each kind (network-access, device-admin):

- policy-set/reset-hitcount                         the policy sets themselves (every set of the kind)
- policy-set/global-exception/reset-hitcount        global exception rules
- policy-set/{id}/authentication/reset-hitcount     one set's authentication rules
- policy-set/{id}/authorization/reset-hitcount      one set's authorization rules
- policy-set/{id}/exception/reset-hitcount          one set's local exceptions
- policy-set/{id}/mfa/reset-hitcount                one set's MFA rules (ISE 3.5)

None takes a body. Only counters change, never policy or traffic, but the counts are evidence that
cannot be brought back: the preview reads and lists every count that will be lost."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from ise_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    compact,
    get_client,
    preview_or_apply,
)
from ise_mcp.client import IseApp
from ise_mcp.tools.policy import PolicyKind, list_policy_sets, resolve_policy_set
from ise_mcp.tools.writes import fingerprint

Section = Literal["authentication", "authorization", "exception", "mfa", "global_exception"]
SET_SECTIONS: tuple[str, ...] = ("authentication", "authorization", "exception", "mfa")
ALL_SECTIONS: tuple[str, ...] = (*SET_SECTIONS, "global_exception")


def _resp(data: Any) -> Any:
    return data.get("response", data) if isinstance(data, dict) else data


def table_paths(kind: str, section: str, ps_id: str | None = None) -> tuple[str, str]:
    """(GET path for the current counts, POST path that resets them) of one counter table.
    section 'policy_sets' is the policy-set table itself."""
    base = f"/api/v1/policy/{kind}/policy-set"
    if section == "policy_sets":
        return base, f"{base}/reset-hitcount"
    if section == "global_exception":
        return f"{base}/global-exception", f"{base}/global-exception/reset-hitcount"
    if section not in SET_SECTIONS:
        raise InvalidRequest(f"Unknown section {section!r}; use one of {', '.join(ALL_SECTIONS)}")
    if not ps_id:
        raise InvalidRequest(f"Section {section!r} needs a policy set")
    return f"{base}/{ps_id}/{section}", f"{base}/{ps_id}/{section}/reset-hitcount"


def counter_rows(data: Any) -> list[dict[str, Any]]:
    """Name, id and hit count per row of a policy-set or rule list (rules nest under 'rule')."""
    rows = []
    for entry in _resp(data) or []:
        if not isinstance(entry, dict):
            continue
        nested = entry.get("rule")
        r: dict[str, Any] = nested if isinstance(nested, dict) else entry
        rows.append({"name": r.get("name"), "id": r.get("id"), "hits": r.get("hitCounts")})
    return rows


async def read_table(app: IseApp, get_path: str) -> dict[str, Any]:
    """The current counts of one table; 'missing' when this ISE has no such table (MFA before 3.5)."""
    try:
        rows = counter_rows(await app.openapi.get(get_path))
    except NotFound:
        return {"missing": True, "rows": []}
    except UpstreamError as e:
        return {"error": str(e)[:200], "rows": []}
    return {"rows": rows}


def _hits(rows: list[dict[str, Any]]) -> int:
    return sum(int(r["hits"]) for r in rows if isinstance(r.get("hits"), int))


def _message(data: Any) -> Any:
    body = _resp(data)
    if isinstance(body, dict):
        return body.get("message") or body
    return body or "reset"


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Reset policy hit counters")
    async def ise_reset_hitcounts(
        ctx: Context,
        scope: Annotated[
            Literal["policy_sets", "policy_set"],
            Field(
                description="'policy_sets': the hit counters of the policy sets themselves (every set of "
                "the kind; ISE has no per-set reset for this table). 'policy_set': the rule counters inside "
                "one policy set (`policy_set`, `sections`)"
            ),
        ],
        kind: PolicyKind = "network-access",
        policy_set: Annotated[
            str | None,
            Field(description="Policy set name or id (scope='policy_set'; from ise_list_policy_sets)"),
        ] = None,
        sections: Annotated[
            list[Section] | None,
            Field(
                description="Which rule counters: 'authentication', 'authorization', 'exception' (local "
                "exceptions), 'mfa' (ISE 3.5) of the policy set, and/or 'global_exception' (the kind's "
                "global exceptions, any scope). Default: scope='policy_set' all four set sections; "
                "scope='policy_sets' none (only the policy-set counters)"
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Reset (zero) ISE policy hit counters: the clean baseline before a policy review or clean-up
        (zero the counters, wait a business cycle, then ise_policy_audit's zero-hit findings mean
        something). scope='policy_sets' zeroes the policy-set counters of every set of the kind;
        scope='policy_set' zeroes one set's authentication, authorization, local exception and/or MFA
        rule counters; 'global_exception' in `sections` adds the global exceptions. Only counters
        change (no policy, no sessions), but they cannot be restored: the preview lists every current
        count that will be lost, so keep it (ise_export_config also records hitCounts). MFA sections
        this ISE does not have are skipped. Preview-first; blast radius = counter tables reset."""
        app: IseApp = get_client(ctx)
        want = list(dict.fromkeys(sections or ([] if scope == "policy_sets" else SET_SECTIONS)))
        blockers: list[str] = []
        ps: dict[str, Any] | None = None
        if scope == "policy_set":
            if not policy_set:
                raise InvalidRequest(
                    "scope='policy_set' needs `policy_set` (name or id; see ise_list_policy_sets)"
                )
            ps = await resolve_policy_set(app, kind, policy_set)
            if not want:
                raise InvalidRequest(f"Give at least one section: {', '.join(ALL_SECTIONS)}")
        else:
            if policy_set:
                raise InvalidRequest(
                    "scope='policy_sets' resets every policy set's own counter (ISE has no per-set reset for "
                    "it); for the rules inside one set use scope='policy_set'"
                )
            per_set = [s for s in want if s in SET_SECTIONS]
            if per_set:
                raise InvalidRequest(
                    f"Sections {', '.join(per_set)} belong to one policy set: use scope='policy_set' with "
                    "`policy_set`"
                )

        tables: list[tuple[str, str]] = []  # (label, section)
        if scope == "policy_sets":
            tables.append(("policy_sets", "policy_sets"))
        tables += [(s, s) for s in want]

        ps_id = str(ps["id"]) if ps else None
        reads: list[dict[str, Any]] = []
        for label, section in tables:
            get_path, post_path = table_paths(kind, section, ps_id if section in SET_SECTIONS else None)
            if section == "policy_sets":
                current = {"rows": counter_rows(await list_policy_sets(app, kind))}
            else:
                current = await read_table(app, get_path)
            reads.append({"label": label, "post": post_path, **current})

        skipped = [r for r in reads if r.get("missing")]
        todo = [r for r in reads if not r.get("missing")]
        for r in reads:
            if r.get("error"):
                blockers.append(f"Could not read the current {r['label']} counts: {r['error']}")
        if not todo and not blockers:
            blockers.append("This ISE has none of the requested counter tables; nothing to reset")

        lost = sum(_hits(r["rows"]) for r in todo)
        counts = {
            r["label"]: compact(
                {
                    "total_hits": _hits(r["rows"]),
                    "rules" if r["label"] != "policy_sets" else "policy_sets": [
                        compact({"name": x.get("name"), "hits": x.get("hits")}) for x in r["rows"]
                    ],
                }
            )
            for r in todo
        }
        details = compact(
            {
                "kind": kind,
                "policy_set": ps.get("name") if ps else None,
                "reset": [r["label"] for r in todo],
                "hits_lost": lost,
                "current_counts": counts,
                "skipped": [f"{r['label']}: not on this ISE" for r in skipped] or None,
                "requests": [f"POST {r['post']}" for r in todo],
            }
        )
        where = f"policy set {ps.get('name')}" if ps else f"all {kind} policy sets"
        plan = Plan(
            f"Reset {kind} hit counters ({', '.join(r['label'] for r in todo) or 'none'}) for {where}",
            details=details,
            blockers=blockers,
            # The tables' rules, not their counts: live traffic moves counts between preview and confirm.
            fingerprint=fingerprint(
                [(r["label"], sorted(str(x.get("id")) for x in r["rows"])) for r in todo]
            ),
            side_effects=[
                f"{lost} recorded hit(s) are zeroed and cannot be restored (counters only; policy and "
                "sessions are untouched). Keep this preview, or run ise_export_config first, if the "
                "current counts matter. ise_snapshot does not record hit counts",
                "ISE counters carry no timestamp: note the reset time to read zero-hit rules later "
                "(ise_policy_audit after a full business cycle)",
            ],
            blast_radius=len(todo),
        )

        async def apply() -> Any:
            results: list[dict[str, Any]] = []
            for r in todo:
                try:
                    msg = _message(await app.openapi.post(r["post"]))
                    results.append({"table": r["label"], "reset": True, "message": msg})
                except UpstreamError as e:
                    results.append({"table": r["label"], "reset": False, "error": str(e)[:200]})
            out: dict[str, Any] = {
                "reset": sum(1 for x in results if x["reset"]),
                "failed": sum(1 for x in results if not x["reset"]),
                "results": results,
                "next": f"ise_get_policy_set('{ps.get('name')}') shows the counters at 0"
                if ps
                else "ise_list_policy_sets shows the counters at 0",
            }
            return out

        return await preview_or_apply(
            ctx,
            tool="ise_reset_hitcounts",
            args={"scope": scope, "kind": kind, "policy_set": policy_set, "sections": want},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

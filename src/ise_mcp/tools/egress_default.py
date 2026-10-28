"""The ANY-ANY default egress rule (I86): the matrix cell every SGT pair without an explicit cell falls
back to. Changing it from PERMIT_IP to DENY_IP is the last step of a TrustSec rollout (default-deny),
after every needed pair has an explicit cell and the monitored hits were read, so it is dangerous tier.

The preview counts the explicit cells, names the SGT pairs that have no cell (they get the new default),
and counts the live sessions per SGT (MnT ActiveList plus a session lookup each, bounded by DETAIL_CAP).
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from ise_mcp._core import (
    Confirm,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    field_changes,
    get_client,
    preview_or_apply,
)
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list, ers_name_map, gather_limited
from ise_mcp.tools.coa_bulk import DETAIL_CAP, active_rows, session_facts
from ise_mcp.tools.trustsec import MATRIX_CELL_CAP
from ise_mcp.tools.writes import PUSH_REMINDER, CellStatus, deep_merge, ers_put, fingerprint, group_ids

# The tag ISE gives the ANY pseudo-SGT (the ANY-ANY cell's source and destination).
ANY_TAG = 65535
TRUSTSEC_DEVICES_TAG = 2
# Most uncovered pairs listed by name in the preview (the count is always complete).
PAIR_LIST_CAP = 100


async def any_any_cell(app: IseApp) -> dict[str, Any]:
    """The ANY-ANY default cell (full object). ERS can't filter cells by name; its source SGT is ANY."""
    page = await ers_list(
        app,
        "egressmatrixcell",
        filters=["sgtSrcName.EQ.ANY"],
        limit=20,
        offset=0,
        detail=True,
        detail_cap=None,
    )
    cell = next((c for c in page.items if isinstance(c, dict) and c.get("name") == "ANY-ANY"), None)
    if cell is None:
        raise NotFound("The ANY-ANY default egress cell could not be read (ERS egressmatrixcell)", 404)
    return cell


def _sgt_label(sgt: dict[str, Any]) -> str:
    return f"{sgt.get('name')} ({sgt.get('value')})"


def _sgt_name(value: Any) -> str:
    """MnT's cts_security_group ('Employees' or 'Employees (4/0004)') as the bare name."""
    return str(value).split("(")[0].strip()


async def sessions_per_sgt(app: IseApp) -> dict[str, Any]:
    """Live sessions by SGT name: ActiveList, then each session's detail (bounded by DETAIL_CAP)."""
    try:
        rows = await active_rows(app)
    except UpstreamError as e:
        return {"error": f"MnT ActiveList not readable: {str(e)[:120]}"}
    out: dict[str, Any] = {"active_sessions": len(rows)}
    if len(rows) > DETAIL_CAP:
        out["note"] = (
            f"{len(rows)} live sessions: per-SGT counts skipped above {DETAIL_CAP} lookups "
            "(ise_list_active_sessions(sgt=...) counts one SGT)"
        )
        return out
    facts = await gather_limited(rows, lambda r: session_facts(app, r, need_authz=False))
    counts: dict[str, int] = {}
    for f in facts:
        if f.get("active") is False:
            continue
        key = _sgt_name(f["sgt"]) if f.get("sgt") else "(no SGT)"
        counts[key] = counts.get(key, 0) + 1
    out["by_sgt"] = dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Set the ANY-ANY default egress rule")
    async def ise_set_default_egress_rule(
        ctx: Context,
        rule: Annotated[
            Literal["PERMIT_IP", "DENY_IP"],
            Field(
                description="Catch-all for every SGT pair without its own cell: PERMIT_IP (open matrix) or "
                "DENY_IP (default-deny, the last step of a TrustSec rollout)"
            ),
        ],
        sgacls: Annotated[
            list[str],
            Field(
                description="SGACLs applied before the catch-all, in order (see ise_list_sgacls); replaces "
                "the cell's list, so [] leaves only the catch-all"
            ),
        ] = [],  # noqa: B006 - FastMCP schema default; never mutated
        status: Annotated[
            CellStatus,
            Field(
                description="ENABLED (enforced), MONITOR (devices count hits on the default and let the "
                "traffic through) or DISABLED"
            ),
        ] = "ENABLED",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change the TrustSec matrix default (the ANY-ANY egress cell): the catch-all, SGACLs and status
        that apply to every source/destination SGT pair without an explicit cell. Moving it to DENY_IP
        (default-deny) drops all traffic between SGTs that have no cell of their own, so the preview lists
        those pairs, counts the explicit cells and the live sessions per SGT, and flags a missing
        TrustSec_Devices cell. Typical order: explicit cells (ise_set_egress_policy) -> status MONITOR
        here and read the monitored hits on the switches -> DENY_IP ENABLED -> ise_push_trustsec_matrix.
        Preview-first."""
        app: IseApp = get_client(ctx)
        current = await any_any_cell(app)
        acl_ids = await group_ids(app, "sgacl", sgacls, "SGACL", "ise_list_sgacls")
        desired = deep_merge(current, {"defaultRule": rule, "matrixCellStatus": status, "sgacls": acl_ids})
        desired["sgacls"] = acl_ids  # a list replaces, never merges

        sgt_page = await ers_list(app, "sgt", limit=5000, offset=0, detail=True, detail_cap=None)
        sgts = [s for s in sgt_page.items if isinstance(s, dict) and s.get("id")]
        real = [s for s in sgts if s.get("value") != ANY_TAG and str(s.get("name")).upper() != "ANY"]
        cells_page = await ers_list(
            app, "egressmatrixcell", limit=MATRIX_CELL_CAP, offset=0, detail=True, detail_cap=None
        )
        explicit = [c for c in cells_page.items if isinstance(c, dict) and c.get("name") != "ANY-ANY"]
        covered = {(str(c.get("sourceSgtId")), str(c.get("destinationSgtId"))) for c in explicit}
        sessions = await sessions_per_sgt(app)
        live = sessions.get("by_sgt") or {}

        uncovered = [(s, d) for s in real for d in real if (str(s["id"]), str(d["id"])) not in covered]
        # Pairs whose source has live sessions first: those are the flows the change hits now.
        uncovered.sort(
            key=lambda p: (-live.get(str(p[0].get("name")), 0), str(p[0].get("name")), str(p[1].get("name")))
        )
        by_status: dict[str, int] = {}
        for c in explicit:
            key = str(c.get("matrixCellStatus") or "UNKNOWN")
            by_status[key] = by_status.get(key, 0) + 1
        acls = await ers_name_map(app, "sgacl")
        details: dict[str, Any] = {
            "cell": "ANY-ANY",
            "changes": field_changes(current, desired, replace=True),
            "from": {
                "default_rule": current.get("defaultRule"),
                "sgacls": [acls.get(str(a), a) for a in current.get("sgacls") or []],
                "status": current.get("matrixCellStatus"),
            },
            "to": {"default_rule": rule, "sgacls": sgacls, "status": status},
            "explicit_cells": len(explicit),
            "explicit_cells_by_status": by_status,
            "sgts": len(real),
            "pairs_without_cell": len(uncovered),
            "pairs_without_cell_list": [
                f"{_sgt_label(s)} -> {_sgt_label(d)}" for s, d in uncovered[:PAIR_LIST_CAP]
            ],
            "sessions": sessions,
        }
        if len(uncovered) > PAIR_LIST_CAP:
            details["pairs_without_cell_note"] = (
                f"First {PAIR_LIST_CAP} of {len(uncovered)} listed (pairs with live sessions first)"
            )
        if not cells_page.complete:
            details["partial"] = (
                f"Only the first {MATRIX_CELL_CAP} cells were read: pairs_without_cell over-counts"
            )

        side: list[str] = []
        denying = rule == "DENY_IP" and status != "DISABLED"
        if denying:
            verb = "is counted (MONITOR) but passes" if status == "MONITOR" else "is DENIED"
            side.append(
                f"Traffic between the {len(uncovered)} SGT pair(s) without an explicit cell {verb} "
                "(pairs_without_cell_list)"
            )
            if status == "ENABLED" and current.get("matrixCellStatus") != "MONITOR":
                side.append(
                    "The default was not in MONITOR first: the validated order is MONITOR, read "
                    "'show cts role-based counters', then ENABLED"
                )
            tsd = [s for s in real if s.get("value") == TRUSTSEC_DEVICES_TAG]
            if tsd and (str(tsd[0]["id"]), str(tsd[0]["id"])) not in covered:
                side.append(
                    "No TrustSec_Devices -> TrustSec_Devices cell: network device traffic tagged SGT 2 "
                    "(routing, management between TrustSec devices) falls to DENY; add a permit cell first"
                )
            if any(str(a).lower().replace("_", " ") == "permit ip" for a in sgacls):
                side.append(f"SGACL {sgacls!r} permits everything before the DENY_IP catch-all")
        elif rule == "PERMIT_IP" and current.get("defaultRule") == "DENY_IP":
            side.append(
                f"The {len(uncovered)} SGT pair(s) without an explicit cell are permitted again "
                "(the matrix leaves default-deny)"
            )
        if status == "DISABLED":
            side.append("A DISABLED default cell is not enforced: pairs without a cell are not filtered")
        side.append(PUSH_REMINDER)

        blockers = []
        if (
            current.get("defaultRule") == rule
            and current.get("matrixCellStatus") == status
            and [str(a) for a in current.get("sgacls") or []] == acl_ids
        ):
            blockers.append(f"ANY-ANY is already {rule} {status} with these SGACLs")
        acl_text = ", ".join(sgacls) or "(no SGACL)"
        plan = Plan(
            f"Set the ANY-ANY default egress rule: {acl_text} then {rule} ({status})",
            details=details,
            fingerprint=fingerprint(current),
            blockers=blockers,
            side_effects=side,
            blast_radius=sessions.get("active_sessions") if isinstance(sessions, dict) else None,
        )
        return await preview_or_apply(
            ctx,
            tool="ise_set_default_egress_rule",
            args={"rule": rule, "sgacls": sgacls, "status": status},
            confirm=confirm,
            plan=plan,
            apply=lambda: ers_put(app, "egressmatrixcell", "EgressMatrixCell", desired),
        )

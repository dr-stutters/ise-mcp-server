"""Patch, upgrade and rollback readiness (roadmap I92): run ISE's own deployment pre-checks before a change
window and report the blockers per node, with the fix ISE names.

Cisco's procedure (ISE 3.5 Upgrade Guide; Administrator Guide, Patch Management) is to run the pre-checks
(repository reachability, bundle validity, disk space, certificates, node sync, PAN/MnT state, configuration
database) from the Primary PAN, fix what fails and only then install. ISE 3.5's OpenAPI (groups 'Patch' and
'Upgrade', 'Patch and Upgrade') exposes them:

- patch:    POST /api/v1/upgrade-patch/patch-install/pre-checks, GET .../pre-checks-status
- upgrade:  POST /api/v1/upgrade/prepare/pre-checks,             GET /api/v1/upgrade/prepare/get-status
- rollback: POST /api/v1/rollback/patch-rollback/pre-checks,     GET .../pre-checks-status

The POST answers an UpgradeTaskResponse ({"response": {"id", "message"}}) whose id is the pre-check report
id; the status GETs take it as `preCheckReportID` and answer an UpgradePrecheckResponse (status, isValid,
iseVersion, nodecount, patchNo, preChecks[] of PrecheckType: name, displayname, status, message,
remediationMsg, successMsg, onFailure, percentage, nodes[] of {name, status, msg}). With no report yet the
lab ISE 3.5 answers 400 'No valid PreCheckReport found' (patch) or 'PreCheckReport is Empty/invalid'
(upgrade), 2026-10-28.

Pre-checks change nothing on the nodes, so ise_patch_readiness is write tier (it starts a job on the PAN).
Installing a patch, rolling one back and upgrading stay out of this server: they restart or reimage
controller nodes.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.
from collections import Counter
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import (
    AuthError,
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    UpstreamTimeout,
    ValidationFailed,
    get_client,
    object_result,
    poll_until,
    preview_or_apply,
)
from ise_mcp.client import IseApp
from ise_mcp.tools.backup import HOST_KEY, NO_REPOSITORY, REPOS, repo_row, repositories

KIND = Literal["patch", "upgrade", "rollback"]
START = {
    "patch": "/api/v1/upgrade-patch/patch-install/pre-checks",
    "upgrade": "/api/v1/upgrade/prepare/pre-checks",
    "rollback": "/api/v1/rollback/patch-rollback/pre-checks",
}
STATUS = {
    "patch": "/api/v1/upgrade-patch/patch-install/pre-checks-status",
    "upgrade": "/api/v1/upgrade/prepare/get-status",
    "rollback": "/api/v1/rollback/patch-rollback/pre-checks-status",
}
# upgradeType per kind and mode (patch and rollback values from the 3.5 OpenAPI descriptions).
UPGRADE_TYPE = {
    ("patch", False): "FULL_PATCH",
    ("patch", True): "SEQUENTIAL_PATCH",
    ("rollback", False): "PATCH_ROLLBACK",
    ("rollback", True): "PATCH_ROLLBACK_SEQUENTIAL",
    ("upgrade", False): "FULL_UPGRADE",
}
WHAT = {"patch": "patch install", "upgrade": "upgrade", "rollback": "patch rollback"}
OUT_OF_SCOPE = (
    "Pre-checks only: this server never installs a patch, rolls one back or upgrades ISE (they restart or "
    "reimage controller nodes). Do that in Administration > System > Maintenance > Patch Management / "
    "Upgrade after a configuration backup (ise_create_backup), in a change window."
)
DENIED = (
    "ISE refused the pre-checks ({status}): the account needs Super Admin or System Admin (Administration > "
    "System > Maintenance); see docs/least-privilege.md."
)
NO_REPORT = (
    "ISE has no {what} pre-check report yet: run ise_patch_readiness(kind={kind!r}, ...) to start one."
)
# Polling: the pre-checks take a few minutes on a small deployment, longer with many nodes.
WAIT_FLOOR = 1800.0
POLL_INTERVAL = 10.0
POLL_MAX_INTERVAL = 30.0

PASS = {"SUCCESS", "SUCCESSFUL", "SUCCEEDED", "PASS", "PASSED", "OK", "COMPLETED", "COMPLETE", "DONE"}
WARN = {"WARNING", "WARN", "WARNINGS"}
FAIL = {"FAILED", "FAILURE", "FAIL", "ERROR", "ABORTED"}
RUNNING = {"IN_PROGRESS", "INPROGRESS", "RUNNING", "STARTED", "NOT_STARTED", "PENDING", "QUEUED", "INITIATED"}


def _response(data: Any) -> Any:
    return data.get("response", data) if isinstance(data, dict) else data


def verdict(status: Any, on_failure: Any = None, check_type: Any = None) -> str:
    """pass / warn / fail / running for one check or node status. A failed check ISE marks as only a
    warning on failure (onFailure WARN..., or an optional checkType) is a warn: it doesn't block."""
    s = str(status or "").strip().upper().replace(" ", "_")
    if s in PASS:
        return "pass"
    if s in WARN:
        return "warn"
    if s in FAIL:
        soft = str(on_failure or "").upper()
        if "WARN" in soft or "CONTINUE" in soft or "OPTIONAL" in str(check_type or "").upper():
            return "warn"
        return "fail"
    if s in RUNNING or not s:
        return "running"
    return "warn"  # a status this server doesn't know: shown raw, never counted as a pass


def _check_rows(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(one row per check, one row per node and check) from an UpgradePrecheckResponse."""
    checks: list[dict[str, Any]] = []
    per_node: list[dict[str, Any]] = []
    for c in report.get("preChecks") or []:
        if not isinstance(c, dict):
            continue
        name = str(c.get("displayname") or c.get("name") or "?")
        result = verdict(c.get("status"), c.get("onFailure"), c.get("checkType"))
        fix = c.get("remediationMsg") if result in ("fail", "warn") else None
        row: dict[str, Any] = {
            "check": name,
            "result": result,
            "status": c.get("status"),
            "message": c.get("message") or (c.get("successMsg") if result == "pass" else None),
            "fix": fix,
        }
        if result == "running" and c.get("percentage") is not None:
            row["percent"] = c.get("percentage")
        nodes = [n for n in c.get("nodes") or [] if isinstance(n, dict)]
        if nodes:
            bad = [
                n for n in nodes if verdict(n.get("status"), c.get("onFailure"), c.get("checkType")) != "pass"
            ]
            row["nodes"] = f"{len(nodes) - len(bad)}/{len(nodes)} ok"
            if bad:
                row["failing_nodes"] = [str(n.get("name")) for n in bad]
        checks.append({k: v for k, v in row.items() if v not in (None, "")})
        for n in nodes or [{"name": "deployment", "status": c.get("status"), "msg": None}]:
            node_result = verdict(n.get("status"), c.get("onFailure"), c.get("checkType"))
            node_row = {
                "node": n.get("name") or "?",
                "check": name,
                "result": node_result,
                "message": n.get("msg") or (c.get("message") if not nodes else None),
                "fix": c.get("remediationMsg") if node_result in ("fail", "warn") else None,
            }
            per_node.append({k: v for k, v in node_row.items() if v not in (None, "")})
    order = {"fail": 0, "warn": 1, "running": 2, "pass": 3}
    checks.sort(key=lambda r: order.get(r["result"], 9))
    per_node.sort(key=lambda r: (str(r["node"]), order.get(r["result"], 9)))
    return checks, per_node


def finished(report: dict[str, Any]) -> bool:
    """The report is final: ISE's overall status is no longer running and no check is still running."""
    checks = [c for c in report.get("preChecks") or [] if isinstance(c, dict)]
    overall = str(report.get("status") or "").strip().upper()
    if overall in RUNNING:
        return False
    if not checks:
        return bool(overall)
    return all(verdict(c.get("status")) != "running" for c in checks)


def render(kind: str, report: dict[str, Any], *, complete: bool = True) -> dict[str, Any]:
    checks, per_node = _check_rows(report)
    counts = Counter(c["result"] for c in checks)
    fails, warns, running = counts.get("fail", 0), counts.get("warn", 0), counts.get("running", 0)
    ready = complete and not fails and not running and bool(checks)
    if not checks:
        summary = f"ISE returned no {WHAT[kind]} pre-checks (status {report.get('status')!r})."
    elif ready:
        summary = f"Ready for the {WHAT[kind]}: {len(checks)} pre-checks passed" + (
            f", {warns} with a warning to review." if warns else "."
        )
    elif fails:
        summary = (
            f"Not ready for the {WHAT[kind]}: {fails} pre-check(s) failed"
            + (f", {warns} warned" if warns else "")
            + ". Fix them (see 'fix') and run the pre-checks again."
        )
    else:
        summary = (
            f"Pre-checks still running ({running} of {len(checks)} not finished): no verdict yet. "
            f"Read the report again with ise_get_patch_readiness(kind={kind!r}, report_id=...)."
        )
    out: dict[str, Any] = {
        "kind": kind,
        "ready": ready,
        "complete": complete and not running,
        "summary": summary,
        "report_id": report.get("preCheckReportID"),
        "status": report.get("status"),
        "valid": report.get("isValid"),
        "ise_version": report.get("iseVersion"),
        "patch": report.get("patchNo"),
        "node_count": report.get("nodecount"),
        "counts": {k: counts.get(k, 0) for k in ("pass", "warn", "fail", "running")},
        "checks": checks,
        "nodes": per_node,
        "out_of_scope": OUT_OF_SCOPE,
    }
    return {k: v for k, v in out.items() if v is not None}


async def read_report(app: IseApp, kind: str, report_id: str | None) -> dict[str, Any] | None:
    """The pre-check report (the latest when report_id is None), or None when ISE has none (its 400)."""
    params = {"preCheckReportID": report_id} if report_id else None
    try:
        data = _response(await app.openapi.get(STATUS[kind], params))
    except (ValidationFailed, NotFound) as e:
        text = str(e).lower()
        if "precheckreport" in text.replace(" ", "") or isinstance(e, NotFound):
            return None
        raise
    return data if isinstance(data, dict) else None


async def deployment_nodes(app: IseApp) -> list[str]:
    try:
        nodes = _response(await app.openapi.get("/api/v1/deployment/node")) or []
    except UpstreamError:
        return []
    return [str(n.get("hostname")) for n in nodes if isinstance(n, dict) and n.get("hostname")]


async def installed_patches(app: IseApp) -> dict[str, Any]:
    try:
        data = _response(await app.openapi.get("/api/v1/patch")) or {}
    except UpstreamError:
        return {}
    if not isinstance(data, dict):
        return {}
    numbers = [p.get("patchNumber") for p in data.get("patchVersion") or [] if isinstance(p, dict)]
    return {"ise_version": data.get("iseVersion"), "patches": [n for n in numbers if n is not None]}


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Patch / upgrade / rollback readiness", destructive=False, task=True)
    async def ise_patch_readiness(
        ctx: Context,
        kind: Annotated[
            KIND,
            Field(
                description="patch: before installing a patch bundle; upgrade: before an upgrade bundle; "
                "rollback: before rolling back the installed patch"
            ),
        ],
        repository: Annotated[
            str | None,
            Field(description="Repository holding the bundle (ise_list_repositories); not for rollback"),
        ] = None,
        bundle: Annotated[
            str | None,
            Field(
                description="Bundle file name in the repository, e.g. 'ise-patchbundle-3.5.0.527-Patch2-"
                "...SPA.x86_64.tar.gz' or 'ise-upgradebundle-...tar.gz'; not for rollback"
            ),
        ] = None,
        sequential: Annotated[
            bool,
            Field(
                description="Check for a sequential install/rollback (one node after another) instead of "
                "the PAN first, then all others in parallel. Patch and rollback only"
            ),
        ] = False,
        wait: Annotated[
            bool,
            Field(
                description="Wait for the pre-checks and return the report (default). False: return the "
                "report id at once; read it with ise_get_patch_readiness"
            ),
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Run ISE's own patch / upgrade / rollback pre-checks on the whole deployment and report each
        check per node as pass / warn / fail with the fix ISE names, and `ready` ('is this deployment ready
        for patch N?'). ISE runs them from the Primary PAN: repository and bundle, disk space, certificates,
        node sync, PAN/MnT state, configuration database and more. The preview checks the repository exists
        and lists the bundle, and shows the nodes and the installed patches. Pre-checks change nothing on the
        nodes; installing, rolling back and upgrading are out of scope (the result says so). Preview-first."""
        app: IseApp = get_client(ctx)
        if kind == "rollback" and (repository or bundle):
            raise InvalidRequest("A rollback pre-check needs no repository or bundle: leave them out")
        if kind != "rollback" and not (repository and bundle):
            raise InvalidRequest(f"A {WHAT[kind]} pre-check needs repository and bundle")
        if kind == "upgrade" and sequential:
            raise InvalidRequest("sequential applies to patch and rollback pre-checks only")
        upgrade_type = UPGRADE_TYPE[(kind, sequential)]

        blockers: list[str] = []
        warnings: list[str] = []
        repo: dict[str, Any] | None = None
        bundle_listed: bool | None = None
        if kind != "rollback":
            repos = await repositories(app)
            repo = next((r for r in repos if str(r.get("name")) == repository), None)
            if not repos:
                blockers.append(NO_REPOSITORY.replace("a configuration backup has", "a bundle has"))
            elif repo is None:
                blockers.append(
                    f"No repository named {repository!r}; ISE has: "
                    + ", ".join(str(r.get("name")) for r in repos)
                    + "."
                )
            else:
                path = f"{REPOS}/{quote(str(repository), safe='')}/files"
                try:
                    files = _response(await app.openapi.get(path))
                except UpstreamError as e:
                    warnings.append(
                        f"ISE can't list repository {repository!r} now ({e}): the pre-checks' repository "
                        "check will most likely fail."
                        + (f" {HOST_KEY}" if str(repo.get("protocol", "")).upper() == "SFTP" else "")
                    )
                else:
                    names = [str(f) for f in files or [] if isinstance(f, str)]
                    bundle_listed = bundle in names
                    if not bundle_listed:
                        bundles = [n for n in names if n.endswith((".tar.gz", ".tgz"))]
                        blockers.append(
                            f"Bundle {bundle!r} is not in repository {repository!r}"
                            + (f"; it has: {', '.join(bundles[:10])}." if bundles else " (no bundles in it).")
                            + " Copy the bundle from software.cisco.com to the repository first."
                        )
        installed = await installed_patches(app)
        if kind == "rollback" and installed and not installed.get("patches"):
            blockers.append("No patch is installed on ISE, so there is nothing to roll back.")
        nodes = await deployment_nodes(app)

        body: dict[str, Any] = {"upgradeType": upgrade_type}
        if kind == "patch":
            body |= {"repoName": repository, "patchBundleName": bundle, "hostnames": []}
        elif kind == "upgrade":
            body |= {"repoName": repository, "bundleName": bundle, "hostnames": []}
        else:
            body["preChecks"] = []

        plan = Plan(
            f"Run the {WHAT[kind]} pre-checks"
            + (f" for {bundle!r} from repository {repository!r}" if bundle else "")
            + f" on the whole deployment ({len(nodes) or '?'} nodes)",
            details={
                "nodes": nodes or "unknown (GET /api/v1/deployment/node failed)",
                "installed": installed or "unknown",
                "repository": repo_row(repo) if repo else repository,
                "bundle_listed": bundle_listed,
                "method": "POST",
                "path": START[kind],
                "body": body,
                "then": f"GET {STATUS[kind]}?preCheckReportID=<id> until every check has finished",
                "out_of_scope": OUT_OF_SCOPE,
            },
            side_effects=[
                "ISE runs its pre-check job from the Primary PAN against every node: it reads the repository "
                "and the bundle, disk, certificates and sync state. Nothing is installed, no service "
                "restarts and authentication carries on.",
                "A new pre-check report replaces the previous one for this kind.",
                *warnings,
            ],
            fingerprint={"repository": repo_row(repo) if repo else None, "bundle_listed": bundle_listed},
            blockers=blockers,
        )

        async def apply() -> Any:
            try:
                started = _response(await app.openapi.post(START[kind], body))
            except AuthError as denied:
                raise AuthError(DENIED.format(status=denied.status_code or 403), denied.status_code) from None
            report_id = str(started.get("id")) if isinstance(started, dict) and started.get("id") else None
            message = started.get("message") if isinstance(started, dict) else None
            if not wait:
                return {
                    "kind": kind,
                    "report_id": report_id,
                    "status": "started",
                    "message": message,
                    "check_with": "ise_get_patch_readiness",
                    "out_of_scope": OUT_OF_SCOPE,
                }
            latest: dict[str, Any] = {}

            async def fetch() -> dict[str, Any]:
                nonlocal latest
                latest = await read_report(app, kind, report_id) or {}
                return latest

            try:
                report = await poll_until(
                    fetch,
                    done=finished,
                    describe=lambda r: f"{r.get('status')}",
                    timeout=max(app.settings.mcp_task_timeout, WAIT_FLOOR),
                    interval=POLL_INTERVAL,
                    max_interval=POLL_MAX_INTERVAL,
                    ctx=ctx,
                    what=f"ISE {WHAT[kind]} pre-checks",
                )
            except UpstreamTimeout:
                out = render(kind, {"preCheckReportID": report_id, **latest}, complete=False)
                out["summary"] = (
                    "The pre-checks are still running on ISE (no verdict yet): read the report with "
                    f"ise_get_patch_readiness(kind={kind!r}, report_id={report_id!r})."
                )
                return out
            return render(kind, {"preCheckReportID": report_id, **report})

        return await preview_or_apply(
            ctx,
            tool="ise_patch_readiness",
            args={
                "kind": kind,
                "repository": repository,
                "bundle": bundle,
                "sequential": sequential,
                "wait": wait,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.read(title="Patch / upgrade / rollback pre-check report")
    async def ise_get_patch_readiness(
        ctx: Context,
        kind: Annotated[KIND, Field(description="Which pre-checks: patch, upgrade or rollback")],
        report_id: Annotated[
            str | None,
            Field(description="Pre-check report id from ise_patch_readiness; default: the latest report"),
        ] = None,
    ) -> ToolResult:
        """The last (or a given) patch / upgrade / rollback pre-check report: each check per node as pass /
        warn / fail with the fix ISE names, and whether the deployment is `ready`. Says so when ISE has no
        report; start one with ise_patch_readiness (write tier). Reads only."""
        app: IseApp = get_client(ctx)
        report = await read_report(app, kind, report_id)
        if report is None:
            return object_result({"kind": kind, "note": NO_REPORT.format(what=WHAT[kind], kind=kind)})
        return object_result(render(kind, report, complete=finished(report)))

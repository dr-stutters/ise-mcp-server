"""I92: patch / upgrade / rollback readiness (respx). Synthetic fixtures in the ISE 3.5 OpenAPI shapes
(UpgradeTaskResponse, UpgradePrecheckResponse > PrecheckType > ListNode); the 400 for 'no report yet' is the
lab ISE 3.5's live answer (2026-10-28). Addresses and names are documentation ones."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ise_mcp._core.testing import call_tool
from ise_mcp.tools import patch_readiness
from ise_mcp.tools.patch_readiness import OUT_OF_SCOPE, finished, verdict
from tests.unit.conftest import make_server

PATCH_START = "/api/v1/upgrade-patch/patch-install/pre-checks"
PATCH_STATUS = "/api/v1/upgrade-patch/patch-install/pre-checks-status"
UPGRADE_START = "/api/v1/upgrade/prepare/pre-checks"
UPGRADE_STATUS = "/api/v1/upgrade/prepare/get-status"
ROLLBACK_START = "/api/v1/rollback/patch-rollback/pre-checks"
ROLLBACK_STATUS = "/api/v1/rollback/patch-rollback/pre-checks-status"
BUNDLE = "ise-patchbundle-3.5.0.527-Patch2-26101.SPA.x86_64.tar.gz"
REPO = {
    "name": "lab-sftp",
    "protocol": "SFTP",
    "serverName": "192.0.2.50",
    "path": "/srv/ise",
    "userName": "u",
}
NODES = [
    {"hostname": "ise-pan1", "fqdn": "ise-pan1.example.com", "ipAddress": "192.0.2.11"},
    {"hostname": "ise-psn1", "fqdn": "ise-psn1.example.com", "ipAddress": "192.0.2.12"},
]
NO_REPORT_400 = {
    "version": "1.0.0",
    "response": {"message": "No valid PreCheckReport found. Please trigger prechecks again and validate."},
}


def check(name: str, status: str, nodes: list[tuple[str, str, str | None]] | None = None, **kw: Any) -> dict:
    return {
        "name": name,
        "displayname": name.replace("_", " ").title(),
        "status": status,
        "message": kw.get("message"),
        "remediationMsg": kw.get("fix"),
        "successMsg": kw.get("ok"),
        "onFailure": kw.get("on_failure"),
        "percentage": kw.get("percent", 100),
        "nodes": [{"name": n, "status": s, "msg": m} for n, s, m in nodes or []],
    }


def report(checks: list[dict], status: str = "COMPLETED", valid: bool = True) -> dict:
    return {
        "version": "1.0.0",
        "response": {
            "preCheckReportID": "rep-1",
            "status": status,
            "isValid": valid,
            "iseVersion": "3.5.0.527",
            "nodecount": 2,
            "patchNo": 2,
            "preChecks": checks,
        },
    }


PASSING = [
    check(
        "repository_check",
        "SUCCESS",
        [("ise-pan1", "SUCCESS", None), ("ise-psn1", "SUCCESS", None)],
        ok="Repository reachable",
    ),
    check("disk_space_check", "SUCCESS", [("ise-pan1", "SUCCESS", None), ("ise-psn1", "SUCCESS", None)]),
]
WARNING = [
    *PASSING,
    check(
        "certificate_check",
        "WARNING",
        [("ise-psn1", "WARNING", "Admin certificate expires in 20 days")],
        message="A certificate expires soon",
        fix="Renew the Admin certificate before the window",
    ),
]
FAILING = [
    *PASSING,
    check(
        "node_sync_check",
        "FAILED",
        [("ise-pan1", "SUCCESS", None), ("ise-psn1", "FAILED", "Out of sync")],
        message="Node not in sync",
        fix="Administration > System > Deployment > Syncup the node",
    ),
    check(
        "bundle_check",
        "FAILED",
        message="Signature check failed",
        fix="Download the bundle again",
        on_failure="WARNING_CONTINUE",
    ),
]


def base(mock: respx.MockRouter, *, files: list[str] | None = None, patches: list[int] | None = None) -> None:
    mock.get("/api/v1/repository").respond(json={"response": [REPO]})
    mock.get("/api/v1/repository/lab-sftp/files").respond(
        json={"response": files if files is not None else [BUNDLE, "nightly-CFG10-261027-0200.tar.gpg"]}
    )
    mock.get("/api/v1/deployment/node", name="nodes").respond(json={"response": NODES})
    mock.get("/api/v1/patch").respond(
        json={
            "response": {
                "iseVersion": "3.5.0.527",
                "patchVersion": [{"patchNumber": n, "installDate": "2026-10-01"} for n in (patches or [])],
            }
        }
    )


async def two_step(
    args: dict[str, Any], *, apply: bool = True, **settings: Any
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    server = make_server(mcp_enable_writes=True, **settings)
    async with Client(server) as c:
        preview = (await c.call_tool("ise_patch_readiness", args)).structured_content
        assert preview is not None
        if preview.get("status") != "preview" or not apply:
            return preview, None
        done = (
            await c.call_tool("ise_patch_readiness", {**args, "confirm": preview["confirm"]})
        ).structured_content
        return preview, done


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(patch_readiness, "POLL_INTERVAL", 0.001)
    monkeypatch.setattr(patch_readiness, "POLL_MAX_INTERVAL", 0.001)


PATCH = {"kind": "patch", "repository": "lab-sftp", "bundle": BUNDLE}


async def test_patch_all_pass(mock: respx.MockRouter) -> None:
    base(mock, patches=[1])
    post = mock.post(PATCH_START).respond(
        202, json={"response": {"id": "rep-1", "message": "Prechecks started"}}
    )
    polls = iter(
        [
            report(PASSING[:1] + [check("disk_space_check", "IN_PROGRESS", percent=40)], "IN_PROGRESS"),
            report(PASSING),
        ]
    )
    status = mock.get(PATCH_STATUS).mock(side_effect=lambda r: httpx.Response(200, json=next(polls)))
    preview, done = await two_step(PATCH)
    p = preview["preview"]
    assert preview["action"].startswith(f"Run the patch install pre-checks for {BUNDLE!r}")
    assert "(2 nodes)" in preview["action"] and p["nodes"] == ["ise-pan1", "ise-psn1"]
    assert p["bundle_listed"] is True and p["installed"]["patches"] == [1]
    assert p["out_of_scope"] == OUT_OF_SCOPE
    assert json.loads(post.calls.last.request.content) == {
        "upgradeType": "FULL_PATCH",
        "repoName": "lab-sftp",
        "patchBundleName": BUNDLE,
        "hostnames": [],
    }
    assert status.calls.last.request.url.params["preCheckReportID"] == "rep-1"
    r = done["result"]  # type: ignore[index]
    assert r["ready"] is True and r["complete"] is True and r["counts"]["pass"] == 2
    assert r["summary"] == "Ready for the patch install: 2 pre-checks passed."
    assert r["checks"][0]["nodes"] == "2/2 ok"
    assert {(n["node"], n["result"]) for n in r["nodes"]} == {("ise-pan1", "pass"), ("ise-psn1", "pass")}
    assert r["out_of_scope"] == OUT_OF_SCOPE


async def test_warning_is_ready_with_the_fix(mock: respx.MockRouter) -> None:
    base(mock)
    mock.post(PATCH_START).respond(202, json={"response": {"id": "rep-1"}})
    mock.get(PATCH_STATUS).respond(json=report(WARNING))
    _, done = await two_step(PATCH)
    r = done["result"]  # type: ignore[index]
    assert r["ready"] is True and r["counts"] == {"pass": 2, "warn": 1, "fail": 0, "running": 0}
    first = r["checks"][0]
    assert first["result"] == "warn" and first["fix"] == "Renew the Admin certificate before the window"
    psn = [n for n in r["nodes"] if n["node"] == "ise-psn1" and n["result"] == "warn"]
    assert psn[0]["message"] == "Admin certificate expires in 20 days"


async def test_failures_block_and_name_the_fix(mock: respx.MockRouter) -> None:
    base(mock)
    mock.post(PATCH_START).respond(202, json={"response": {"id": "rep-1"}})
    mock.get(PATCH_STATUS).respond(json=report(FAILING, valid=False))
    _, done = await two_step(PATCH)
    r = done["result"]  # type: ignore[index]
    assert r["ready"] is False and r["valid"] is False
    assert r["counts"] == {"pass": 2, "warn": 1, "fail": 1, "running": 0}
    assert r["summary"].startswith(
        "Not ready for the patch install: 1 pre-check(s) failed, 2 passed, 1 warned."
    )
    sync = r["checks"][0]
    assert sync["check"] == "Node Sync Check" and sync["failing_nodes"] == ["ise-psn1"]
    assert sync["nodes"] == "1/2 ok" and sync["fix"].startswith("Administration > System > Deployment")
    # onFailure WARNING_CONTINUE: a failed check ISE lets through is a warning, not a blocker.
    assert next(c for c in r["checks"] if c["check"] == "Bundle Check")["result"] == "warn"
    failed_node = [n for n in r["nodes"] if n["result"] == "fail"]
    assert failed_node == [
        {
            "node": "ise-psn1",
            "check": "Node Sync Check",
            "result": "fail",
            "message": "Out of sync",
            "fix": "Administration > System > Deployment > Syncup the node",
        }
    ]


async def test_timeout_returns_partial_report(
    mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(patch_readiness, "WAIT_FLOOR", 0.0)
    base(mock)
    mock.post(PATCH_START).respond(202, json={"response": {"id": "rep-1"}})
    mock.get(PATCH_STATUS).respond(
        json=report(PASSING[:1] + [check("disk_space_check", "IN_PROGRESS", percent=40)], "IN_PROGRESS")
    )
    _, done = await two_step(PATCH, mcp_task_timeout=0.05)
    r = done["result"]  # type: ignore[index]
    assert r["ready"] is False and r["complete"] is False and r["counts"]["running"] == 1
    assert "still running" in r["summary"] and "report_id='rep-1'" in r["summary"]
    assert next(c for c in r["checks"] if c["result"] == "running")["percent"] == 40


async def test_report_not_there_yet_keeps_polling(mock: respx.MockRouter) -> None:
    base(mock)
    mock.post(PATCH_START).respond(202, json={"response": {"id": "rep-1"}})
    answers = iter([httpx.Response(400, json=NO_REPORT_400), httpx.Response(200, json=report(PASSING))])
    mock.get(PATCH_STATUS).mock(side_effect=lambda r: next(answers))
    _, done = await two_step(PATCH)
    assert done["result"]["ready"] is True  # type: ignore[index]


async def test_no_wait_returns_report_id(mock: respx.MockRouter) -> None:
    base(mock)
    mock.post(PATCH_START).respond(202, json={"response": {"id": "rep-9", "message": "Prechecks started"}})
    status = mock.get(PATCH_STATUS).respond(json=report(PASSING))
    _, done = await two_step({**PATCH, "wait": False, "sequential": True})
    r = done["result"]  # type: ignore[index]
    assert (
        r["report_id"] == "rep-9"
        and r["status"] == "started"
        and r["check_with"] == "ise_get_patch_readiness"
    )
    assert not status.called


async def test_sequential_patch_body(mock: respx.MockRouter) -> None:
    base(mock)
    post = mock.post(PATCH_START).respond(202, json={"response": {"id": "rep-1"}})
    mock.get(PATCH_STATUS).respond(json=report(PASSING))
    await two_step({**PATCH, "sequential": True})
    assert json.loads(post.calls.last.request.content)["upgradeType"] == "SEQUENTIAL_PATCH"


async def test_upgrade_uses_its_own_paths(mock: respx.MockRouter) -> None:
    upgrade = "ise-upgradebundle-3.4.x-to-3.5.0.527.SPA.x86_64.tar.gz"
    base(mock, files=[upgrade])
    post = mock.post(UPGRADE_START).respond(202, json={"response": {"id": "up-1"}})
    status = mock.get(UPGRADE_STATUS).respond(json=report(PASSING))
    _, done = await two_step({"kind": "upgrade", "repository": "lab-sftp", "bundle": upgrade})
    assert json.loads(post.calls.last.request.content) == {
        "upgradeType": "FULL_UPGRADE",
        "repoName": "lab-sftp",
        "bundleName": upgrade,
        "hostnames": [],
    }
    assert status.calls.last.request.url.params["preCheckReportID"] == "up-1"
    assert done["result"]["summary"] == "Ready for the upgrade: 2 pre-checks passed."  # type: ignore[index]


async def test_rollback_needs_an_installed_patch(mock: respx.MockRouter) -> None:
    base(mock, patches=[])
    post = mock.post(ROLLBACK_START).respond(202, json={"response": {"id": "rb-1"}})
    preview, done = await two_step({"kind": "rollback"})
    assert preview["status"] == "blocked" and done is None and not post.called
    assert preview["blockers"] == ["No patch is installed on ISE, so there is nothing to roll back."]


async def test_rollback(mock: respx.MockRouter) -> None:
    base(mock, patches=[1, 2])
    post = mock.post(ROLLBACK_START).respond(202, json={"response": {"id": "rb-1"}})
    mock.get(ROLLBACK_STATUS).respond(json=report(PASSING))
    preview, done = await two_step({"kind": "rollback", "sequential": True})
    assert preview["preview"]["repository"] is None
    assert json.loads(post.calls.last.request.content) == {
        "upgradeType": "PATCH_ROLLBACK_SEQUENTIAL",
        "preChecks": [],
    }
    assert done["result"]["summary"] == "Ready for the patch rollback: 2 pre-checks passed."  # type: ignore[index]


@pytest.mark.parametrize(
    ("files", "repos", "blocker"),
    [
        (["other-bundle.tar.gz"], [REPO], "is not in repository 'lab-sftp'; it has: other-bundle.tar.gz."),
        ([], [REPO], "(no bundles in it)"),
        ([BUNDLE], [{**REPO, "name": "elsewhere"}], "No repository named 'lab-sftp'; ISE has: elsewhere."),
        ([BUNDLE], [], "No repository is configured on ISE, so a bundle has nowhere to go"),
    ],
)
async def test_preview_blockers(
    mock: respx.MockRouter, files: list[str], repos: list[dict], blocker: str
) -> None:
    base(mock, files=files)
    mock.get("/api/v1/repository").respond(json={"response": repos or None})
    post = mock.post(PATCH_START).respond(202, json={})
    preview, done = await two_step(PATCH)
    assert preview["status"] == "blocked" and done is None and not post.called
    assert blocker in preview["blockers"][0]


async def test_unlistable_repository_warns(mock: respx.MockRouter) -> None:
    base(mock)
    mock.get("/api/v1/repository/lab-sftp/files").respond(500, json={"message": "Connection refused"})
    preview, _ = await two_step(PATCH, apply=False)
    assert preview["status"] == "preview" and preview["preview"]["bundle_listed"] is None
    assert any("can't list repository" in s and "crypto host_key" in s for s in preview["side_effects"])


@pytest.mark.parametrize(
    ("args", "match"),
    [
        ({"kind": "patch", "repository": "lab-sftp"}, "needs repository and bundle"),
        ({"kind": "rollback", "bundle": BUNDLE}, "needs no repository or bundle"),
        ({"kind": "upgrade", "repository": "lab-sftp", "bundle": BUNDLE, "sequential": True}, "sequential"),
    ],
)
async def test_bad_arguments(mock: respx.MockRouter, args: dict[str, Any], match: str) -> None:
    base(mock)
    with pytest.raises(ToolError, match=match):
        await two_step(args)


async def test_403_names_the_admin_role(mock: respx.MockRouter) -> None:
    base(mock)
    mock.post(PATCH_START).respond(403, json={"message": "Forbidden"})
    with pytest.raises(ToolError, match="Super Admin or System Admin"):
        await two_step(PATCH)


async def test_write_tier() -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_get_patch_readiness" in names and "ise_patch_readiness" not in names


# --- ise_get_patch_readiness -----------------------------------------------------------------------


async def test_get_without_report(mock: respx.MockRouter) -> None:
    mock.get(UPGRADE_STATUS).respond(400, json={"response": {"message": "PreCheckReport is Empty/invalid"}})
    out = await call_tool(make_server(), "ise_get_patch_readiness", {"kind": "upgrade"})
    assert "report" not in out and "checks" not in out and "ise_patch_readiness(kind='upgrade'" in out["note"]


async def test_get_report_by_id(mock: respx.MockRouter) -> None:
    route = mock.get(PATCH_STATUS).respond(json=report(FAILING))
    out = await call_tool(make_server(), "ise_get_patch_readiness", {"kind": "patch", "report_id": "rep-1"})
    assert route.calls.last.request.url.params["preCheckReportID"] == "rep-1"
    assert out["ready"] is False and out["complete"] is True and out["counts"]["fail"] == 1


async def test_get_other_400_is_raised(mock: respx.MockRouter) -> None:
    mock.get(PATCH_STATUS).respond(400, json={"message": "Invalid request id"})
    with pytest.raises(ToolError, match="Invalid request id"):
        await call_tool(make_server(), "ise_get_patch_readiness", {"kind": "patch", "report_id": "x"})


@pytest.mark.parametrize(
    ("status", "on_failure", "expect"),
    [
        ("SUCCESS", None, "pass"),
        ("Passed", None, "pass"),
        ("WARNING", None, "warn"),
        ("FAILED", None, "fail"),
        ("FAILED", "WARNING", "warn"),
        ("IN_PROGRESS", None, "running"),
        ("", None, "running"),
        ("SOMETHING_NEW", None, "unknown"),
        ("in-progress", None, "running"),
        ("Success", "fail", "pass"),
        ("Failure", "fail", "fail"),
        ("Failure", "info", "warn"),
    ],
)
def test_verdict(status: str, on_failure: str | None, expect: str) -> None:
    assert verdict(status, on_failure) == expect


def test_initiated_message_is_running() -> None:
    assert (
        verdict("WARNING", "fail", "local", "ise-pan1.example.com-precheck execution initiated $ ")
        == "running"
    )
    assert verdict("Success", None, None, "precheck execution initiated") == "pass"


def test_finished() -> None:
    assert not finished({"status": "IN_PROGRESS", "preChecks": []})
    assert not finished({"status": "COMPLETED", "preChecks": [{"status": "IN_PROGRESS"}]})
    assert finished({"status": "COMPLETED", "preChecks": [{"status": "SUCCESS"}]})
    assert finished({"preChecks": [{"status": "FAILED"}]})
    assert not finished({})
    assert not finished({"status": "valid", "preChecks": [{"status": "in-progress"}]})
    assert not finished({"status": "valid", "preChecks": [{"status": "SOMETHING_NEW"}]})
    assert finished({"status": "valid", "preChecks": [{"status": "Failure"}, {"status": "Success"}]})


# --- ISE 3.5 live shapes (lab 3.5.0.527 Patch 4, 2026-10-28; names and addresses replaced) -------------

LIVE_CHECKS = [
    ("REPOSITORY_CHECK", "Repository Validation", "local", "fail", "Success", "repository precheck passed"),
    (
        "PAN_FAILOVER_CHECK",
        "PAN Failover Validation",
        "global",
        "fail",
        "Success",
        "PAN failover is disabled",
    ),
    (
        "ADMIN_CERT_CHECK",
        "Admin Certificate Check in Trusted store",
        "global",
        "fail",
        "Failure",
        "Admin Certificate Not Found in trust cert store",
    ),
    (
        "PATCH_BUNDLE_DOWNLOAD_CHECK",
        "Patch Bundle Download and Metadata Validation",
        "local",
        "fail",
        "Failure",
        "Patch bundle download failed : Patch is already installed.",
    ),
    ("DNS_CHECK", "DNS Resolvability", "local", "warning", "Success", "DNS resolution succeeded"),
    ("SYSTEM_CERT_CHECK", "System Certificate Validation", "local", "fail", "Success", ""),
    (
        "SERVICES_CHECK",
        "Services or Process Failures",
        "local",
        "info",
        "Success",
        "all services are running",
    ),
]
LIVE_NODE = "ise-pan1.example.com"


def live_report(final: bool) -> dict:
    checks = []
    for name, display, check_type, on_failure, status, msg in LIVE_CHECKS:
        failed = final and status == "Failure"
        checks.append(
            {
                "onFailure": on_failure,
                "remediationMsg": f"Fix {display}",
                "message": (f"{LIVE_NODE}-{msg} $ " if failed else "")
                if final
                else f"{LIVE_NODE}-precheck execution initiated $ ",
                "nodes": [
                    {
                        "msg": msg if final else "precheck execution initiated",
                        "name": LIVE_NODE,
                        "status": status if final else "in-progress",
                    }
                ],
                "checkType": check_type,
                "displayname": display,
                "percentage": 100 if final else 0,
                "name": name,
                "successMsg": f"{display} passed",
                "successNodes": int(final and status == "Success"),
                "status": status if final else "in-progress",
            }
        )
    return {
        "preChecks": checks,
        "preCheckReportID": "084c2885-0000-4000-8000-000000000001",
        "nodecount": 1,
        "isValid": False,
        "status": "valid",
        "iseVersion": "3.5.0.527",
        "patchNo": 4,
    }


async def test_live_in_progress_keeps_polling_until_the_final_report(mock: respx.MockRouter) -> None:
    base(mock, patches=[1, 2, 3, 4])
    mock.post(PATCH_START).respond(
        202, json={"response": {"id": "084c2885-0000-4000-8000-000000000001", "message": "Prechecks started"}}
    )
    polls = iter([live_report(final=False), live_report(final=False), live_report(final=True)])
    status = mock.get(PATCH_STATUS).mock(side_effect=lambda r: httpx.Response(200, json=next(polls)))
    _, done = await two_step(PATCH)
    assert status.call_count == 3
    r = done["result"]  # type: ignore[index]
    assert r["ready"] is False and r["complete"] is True and r["valid"] is False
    assert r["counts"] == {"pass": 5, "warn": 0, "fail": 2, "running": 0}
    assert r["summary"].startswith("Not ready for the patch install: 2 pre-check(s) failed, 5 passed.")
    assert [c["check"] for c in r["checks"][:2]] == [
        "Admin Certificate Check in Trusted store",
        "Patch Bundle Download and Metadata Validation",
    ]


async def test_live_in_progress_report_is_running_not_ready(mock: respx.MockRouter) -> None:
    mock.get(PATCH_STATUS).respond(json={"version": "1.0.0", "response": live_report(final=False)})
    out = await call_tool(make_server(), "ise_get_patch_readiness", {"kind": "patch"})
    assert out["ready"] is False and out["complete"] is False
    assert out["counts"] == {"pass": 0, "warn": 0, "fail": 0, "running": 7}
    assert out["summary"].startswith("Pre-checks still running (7 of 7 not finished)")
    assert all(c["result"] == "running" and "fix" not in c for c in out["checks"])
    assert {n["result"] for n in out["nodes"]} == {"running"}


async def test_live_final_report(mock: respx.MockRouter) -> None:
    mock.get(PATCH_STATUS).respond(json=live_report(final=True))
    out = await call_tool(make_server(), "ise_get_patch_readiness", {"kind": "patch", "report_id": "x"})
    assert out["ready"] is False and out["complete"] is True
    assert out["counts"] == {"pass": 5, "warn": 0, "fail": 2, "running": 0}


async def test_not_valid_blocks_ready(mock: respx.MockRouter) -> None:
    mock.get(PATCH_STATUS).respond(json=report(PASSING, valid=False))
    out = await call_tool(make_server(), "ise_get_patch_readiness", {"kind": "patch"})
    assert out["ready"] is False and out["complete"] is True and out["counts"]["fail"] == 0
    assert "ISE marks the report not valid (isValid False)" in out["summary"]


async def test_ready_summary_counts_passes_and_warnings(mock: respx.MockRouter) -> None:
    mock.get(PATCH_STATUS).respond(json=report(WARNING))
    out = await call_tool(make_server(), "ise_get_patch_readiness", {"kind": "patch"})
    assert out["ready"] is True
    assert out["summary"] == "Ready for the patch install: 2 pre-checks passed, 1 warned (review them)."


async def test_unknown_status_is_never_done(mock: respx.MockRouter) -> None:
    mock.get(PATCH_STATUS).respond(json=report([*PASSING, check("new_check", "DEFERRED")]))
    out = await call_tool(make_server(), "ise_get_patch_readiness", {"kind": "patch"})
    assert out["ready"] is False and out["complete"] is False
    assert out["counts"]["unknown"] == 1 and out["checks"][0]["result"] == "unknown"
    assert out["summary"].startswith("No verdict: 1 pre-check(s) are in a status this server doesn't know")

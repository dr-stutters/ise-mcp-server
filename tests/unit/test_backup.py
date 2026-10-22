"""I78: repositories and on-demand configuration backups (respx). The empty answers (no repository, a
last-backup-status of nulls) are the lab ISE 3.5's live ones (2026-10-22); the rest follows the 3.5 OpenAPI
groups 'Repository' and 'Backup Restore'."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ise_mcp.tools.backup import NO_KEY, NO_REPOSITORY
from tests.unit.conftest import make_server

KEY = "Lab-Backup-Key-2026"
LAST = "/api/v1/backup-restore/config/last-backup-status"
NULLS = {
    k: None
    for k in (
        "repository",
        "type",
        "name",
        "startDate",
        "error",
        "action",
        "scheduled",
        "status",
        "message",
        "justComplete",
        "percentComplete",
        "details",
        "hostName",
        "initiatedFrom",
    )
}
SFTP = {
    "name": "lab-sftp",
    "protocol": "SFTP",
    "serverName": "198.18.133.50",
    "path": "/srv/ise",
    "userName": "backup",
    "password": "*******",
    "enablePki": False,
}
DONE_BEFORE = {
    "name": "nightly",
    "repository": "lab-sftp",
    "type": "CONFIGURATION_DB",
    "status": "COMPLETED",
    "startDate": "Tue Oct 21 02:00:00 UTC 2026",
    "percentComplete": "100",
}


def status(body: dict[str, Any]) -> dict[str, Any]:
    return {"response": body, "version": "1.0.0"}


async def two_step(
    args: dict[str, Any], *, key: str | None = KEY, apply: bool = True
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    extra: dict[str, Any] = {"backup_encryption_key": key} if key else {}
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True, **extra)
    async with Client(server) as c:
        preview = (await c.call_tool("ise_create_backup", args)).structured_content
        assert preview is not None
        if preview.get("status") != "preview" or not apply:
            return preview, None
        done = (
            await c.call_tool("ise_create_backup", {**args, "confirm": preview["confirm"]})
        ).structured_content
        return preview, done


async def call(name: str, args: dict[str, Any] | None = None) -> Any:
    async with Client(make_server()) as c:
        res = await c.call_tool(name, args or {})
    return res.structured_content


# --- ise_list_repositories ------------------------------------------------------------------------


async def test_no_repository(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/repository").respond(json={"response": None, "version": "1.0.0"})  # live, 2026-10-22
    out = await call("ise_list_repositories", {"response_format": "json"})
    assert out["results"] == [] and out["note"].startswith("No repository is configured on ISE")


async def test_repositories_hide_passwords(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/repository").respond(json={"response": [SFTP]})
    out = await call("ise_list_repositories", {"response_format": "json"})
    row = out["results"][0]
    assert row["name"] == "lab-sftp" and row["protocol"] == "SFTP" and "password" not in row


async def test_repository_files(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/repository/lab-sftp/files").respond(
        json={
            "response": [
                "notes.txt",
                "nightly-CFG10-261021-0200.tar.gpg",
                "pre-gbp-CFG10-261022-0910.tar.gpg",
            ]
        }
    )
    out = await call("ise_list_repositories", {"repository": "lab-sftp", "response_format": "json"})
    assert [r["file"] for r in out["results"]][0] == "pre-gbp-CFG10-261022-0910.tar.gpg"  # newest name first
    assert [r["backup"] for r in out["results"]] == [True, True, False]
    mock.get("/api/v1/repository/nope/files").respond(404, json={"error": {"message": "Not Found"}})
    with pytest.raises(ToolError, match="No repository 'nope'"):
        await call("ise_list_repositories", {"repository": "nope"})


# --- ise_create_backup ----------------------------------------------------------------------------


async def test_refuses_without_repository_or_key(mock: respx.MockRouter) -> None:
    """The lab today: no repository, no backup ever taken, and no key configured."""
    mock.get("/api/v1/repository").respond(json={"response": None, "version": "1.0.0"})
    mock.get(LAST).respond(json=status(NULLS))
    post = mock.post("/api/v1/backup-restore/config/backup").respond(202, json={})
    out, done = await two_step({"repository": "lab-sftp", "name": "pre-gbp"}, key=None)
    assert out["status"] == "blocked" and done is None and not post.called
    assert out["blockers"] == [NO_REPOSITORY, NO_KEY]


async def test_preview_then_start(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/repository").respond(json={"response": [SFTP]})
    mock.get(LAST).respond(json=status(DONE_BEFORE))
    post = mock.post("/api/v1/backup-restore/config/backup").respond(
        202, json={"response": {"id": "task-1", "message": "Config DB backup task initiated."}}
    )
    preview, done = await two_step({"repository": "lab-sftp", "name": "pre-gbp"})
    assert preview["action"] == "Back up the ISE configuration as 'pre-gbp' to repository 'lab-sftp'"
    p = preview["preview"]
    assert p["file"] == "pre-gbp-CFG10-<yymmdd>-<hhmm>.tar.gpg" and p["last_backup"]["name"] == "nightly"
    assert p["repository"]["serverName"] == "198.18.133.50" and "password" not in p["repository"]
    assert KEY not in json.dumps(preview)  # the key is never shown
    assert post.call_count == 1 and done is not None
    assert json.loads(post.calls.last.request.content) == {
        "backupName": "pre-gbp",
        "repositoryName": "lab-sftp",
        "backupEncryptionKey": KEY,
    }
    assert done["result"] == {"task_id": "task-1", "check_with": "ise_get_backup_status", "status": "started"}
    assert KEY not in json.dumps(done)


async def test_wait_follows_last_backup_status(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/repository").respond(json={"response": [SFTP]})
    posted: list[bool] = []
    after = {**DONE_BEFORE, "name": "pre-gbp", "startDate": "Wed Oct 22 09:10:00 UTC 2026"}
    mock.get(LAST).mock(
        side_effect=lambda r: httpx.Response(200, json=status(after if posted else DONE_BEFORE))
    )

    def start(request: httpx.Request) -> httpx.Response:
        posted.append(True)
        return httpx.Response(202, json={"response": {"id": "task-2"}})

    mock.post("/api/v1/backup-restore/config/backup").mock(side_effect=start)
    _, done = await two_step({"repository": "lab-sftp", "name": "pre-gbp", "wait": True})
    assert done is not None and done["result"]["backup"]["status"] == "COMPLETED"
    assert done["result"]["backup"]["name"] == "pre-gbp"


async def test_wait_reports_an_error(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/repository").respond(json={"response": [SFTP]})
    posted: list[bool] = []
    failed = {
        "name": "pre-gbp",
        "status": "ERROR",
        "startDate": "Wed Oct 22 09:10:00 UTC 2026",
        "message": "Backup Failed Copy to repository failed",
    }
    mock.get(LAST).mock(side_effect=lambda r: httpx.Response(200, json=status(failed if posted else NULLS)))

    def start(request: httpx.Request) -> httpx.Response:
        posted.append(True)
        return httpx.Response(202, json={"response": {"id": "task-3"}})

    mock.post("/api/v1/backup-restore/config/backup").mock(side_effect=start)
    with pytest.raises(ToolError, match="Copy to repository failed.*ise_get_backup_status"):
        await two_step({"repository": "lab-sftp", "name": "pre-gbp", "wait": True})


@pytest.mark.parametrize(
    ("repos", "last", "blocker"),
    [
        ([SFTP], {**DONE_BEFORE, "status": "IN_PROGRESS", "percentComplete": "40"}, "already running"),
        ([SFTP], NULLS, "No repository named 'other'; ISE has: lab-sftp."),
        ([{"name": "other", "protocol": "HTTPS", "serverName": "x", "path": "/"}], NULLS, "only reads from"),
    ],
)
async def test_blockers(
    mock: respx.MockRouter, repos: list[dict[str, Any]], last: dict[str, Any], blocker: str
) -> None:
    mock.get("/api/v1/repository").respond(json={"response": repos})
    mock.get(LAST).respond(json=status(last))
    post = mock.post("/api/v1/backup-restore/config/backup").respond(202, json={})
    name = "lab-sftp" if blocker == "already running" else "other"
    out, _ = await two_step({"repository": name, "name": "pre-gbp"})
    assert out["status"] == "blocked" and not post.called
    assert any(blocker in b for b in out["blockers"]), out["blockers"]


async def test_errors_never_carry_the_key(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/repository").respond(json={"response": [SFTP]})
    mock.get(LAST).respond(json=status(NULLS))
    mock.post("/api/v1/backup-restore/config/backup").respond(
        400, json={"code": 400, "message": f"Invalid encryption key {KEY}"}
    )
    with pytest.raises(ToolError) as err:
        await two_step({"repository": "lab-sftp", "name": "pre-gbp"})
    assert KEY not in str(err.value)


async def test_403_names_the_admin_group(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/repository").respond(json={"response": [SFTP]})
    mock.get(LAST).respond(json=status(NULLS))
    mock.post("/api/v1/backup-restore/config/backup").respond(403)
    with pytest.raises(ToolError, match="Super Admin"):
        await two_step({"repository": "lab-sftp", "name": "pre-gbp"})


async def test_backup_hidden_without_dangerous() -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_list_repositories" in names and "ise_create_backup" not in names

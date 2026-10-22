"""Configuration backups on demand (roadmap I78, with catc D114): the repositories ISE copies backups to and
the files in them, and a configuration backup before a risky change such as Catalyst Center's group-based
policy migration (catc D108), which makes ISE's TrustSec objects read-only.

ISE's OpenAPI backs up the configuration database only (`POST /api/v1/backup-restore/config/backup`), to a
repository defined under Administration > System > Maintenance > Repository, encrypted with a key the server
takes from ISE_BACKUP_ENCRYPTION_KEY (never from a tool argument, never shown). Progress is read from
`last-backup-status`. With no repository `GET /api/v1/repository` answers `{"response": null}` and
`last-backup-status` a record of nulls (the lab ISE 3.5, 2026-10-22), so ise_create_backup refuses in its
preview. Restore is not automated: docs and the preview say how.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.
import re
from typing import Annotated, Any
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import (
    AuthError,
    Confirm,
    NotFound,
    Plan,
    ResponseFormat,
    TaskFailed,
    ToolRegistrar,
    UpstreamError,
    UpstreamTimeout,
    get_client,
    list_result,
    poll_until,
    preview_or_apply,
)
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp

REPOS = "/api/v1/repository"
BACKUP = "/api/v1/backup-restore/config/backup"
LAST = "/api/v1/backup-restore/config/last-backup-status"
REPO_FIELDS = ("name", "protocol", "serverName", "path", "userName", "enablePki")
# Repository types ISE reads from but can't write a backup to.
READ_ONLY = ("CDROM", "HTTP", "HTTPS")
DONE = ("COMPLETED", "ERROR")
STAMP = re.compile(r"-CFG\d+-(\d{6})-(\d{4})")
NO_REPOSITORY = (
    "No repository is configured on ISE, so a configuration backup has nowhere to go. Add one under "
    "Administration > System > Maintenance > Repository (SFTP, FTP, NFS or the local disk), check it with "
    "ise_list_repositories, then preview again."
)
NO_KEY = (
    "No backup encryption key is configured on this server: set ISE_BACKUP_ENCRYPTION_KEY (or _FILE / _REF) "
    "and restart it. ISE encrypts the backup with the key and needs it again to restore; it is never shown."
)
DENIED = (
    "ISE refused the backup ({status}): the account needs an admin group with Backup & Restore "
    "(Super Admin, the dangerous-tier account in docs/least-privilege.md)."
)
WAIT_FLOOR = 3600.0


def _response(data: Any) -> Any:
    return data.get("response", data) if isinstance(data, dict) else data


def repo_row(r: dict[str, Any]) -> dict[str, Any]:
    """A repository without its password (ISE returns it masked; it is left out either way)."""
    return {k: r[k] for k in REPO_FIELDS if r.get(k) not in (None, "")}


async def repositories(app: IseApp) -> list[dict[str, Any]]:
    data = _response(await app.openapi.get(REPOS))
    return [r for r in data or [] if isinstance(r, dict)]


async def last_backup(app: IseApp) -> dict[str, Any]:
    """The last configuration backup's status, without the null fields ({} when none has run)."""
    data = _response(await app.openapi.get(LAST))
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if v not in (None, "")}


def file_stamp(name: str) -> str:
    """The yymmddhhmm ISE puts in a backup file's name (-CFG10-yymmdd-hhmm), or ''."""
    m = STAMP.search(name)
    return "".join(m.groups()) if m else ""


def backup_failed(status: dict[str, Any]) -> str | bool:
    if str(status.get("status", "")).upper() != "ERROR":
        return False
    return str(status.get("message") or status.get("details") or "status ERROR")


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List backup repositories")
    async def ise_list_repositories(
        ctx: Context,
        repository: Annotated[
            str | None,
            Field(
                description="One repository's files instead (backups: '<name>-CFG10-<date>-<time>.tar.gpg')"
            ),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Repositories ISE copies configuration backups to (Administration > System > Maintenance >
        Repository): name, protocol (SFTP, FTP, NFS, DISK, ...), server, path and user; passwords are never
        shown. Says so when none is configured (ise_create_backup then has nowhere to write). With
        `repository`: the files in it, e.g. the backup to restore (configuration backups end in .tar.gpg)."""
        app: IseApp = get_client(ctx)
        if repository:
            try:
                files = _response(await app.openapi.get(f"{REPOS}/{quote(repository, safe='')}/files"))
            except NotFound as e:
                raise NotFound(f"No repository {repository!r}; see ise_list_repositories.", 404) from e
            rows: list[Any] = [
                {"file": f, "backup": str(f).endswith(".tar.gpg")} for f in files or [] if isinstance(f, str)
            ]
            # Backups first, newest first (stable sorts: name, then date stamp, then kind).
            rows.sort(key=lambda r: str(r["file"]))
            rows.sort(key=lambda r: file_stamp(str(r["file"])), reverse=True)
            rows.sort(key=lambda r: not r["backup"])
            return list_result(
                page_of(rows, limit=limit, offset=offset),
                fmt=response_format,
                extra={"repository": repository},
            )
        repos = [repo_row(r) for r in await repositories(app)]
        extra = None if repos else {"note": NO_REPOSITORY.split(", so")[0] + "."}
        return list_result(page_of(repos, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.dangerous(title="Create a configuration backup", task=True)
    async def ise_create_backup(
        ctx: Context,
        repository: Annotated[
            str, Field(description="Repository to copy the backup to (ise_list_repositories)")
        ],
        name: Annotated[
            str,
            Field(
                min_length=1,
                max_length=64,
                pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$",
                description="Backup name (letters, digits, '_', '-'); ISE adds -CFG10-<date>-<time>.tar.gpg",
            ),
        ],
        wait: Annotated[
            bool,
            Field(
                description="Wait for the backup to finish. Default false: returns at once; follow it with "
                "ise_get_backup_status"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Take an on-demand ISE configuration backup to a repository, before Catalyst Center's group-based
        policy migration or an upgrade. The key comes from the server's ISE_BACKUP_ENCRYPTION_KEY
        (never an argument, never shown). Refused in the preview when no repository is configured, the
        repository doesn't exist or is read-only (CDROM, HTTP, HTTPS), the key is not set, or a backup is
        already running. Preview-first: the repository, the file name ISE will write and the last backup.
        Configuration only (no operational/MnT data). Restore is not automated (the preview says how)."""
        app: IseApp = get_client(ctx)
        repos = await repositories(app)
        last = await last_backup(app)
        repo = next((r for r in repos if str(r.get("name")) == repository), None)
        blockers: list[str] = []
        if not repos:
            blockers.append(NO_REPOSITORY)
        elif repo is None:
            blockers.append(
                f"No repository named {repository!r}; ISE has: "
                + ", ".join(str(r.get("name")) for r in repos)
                + "."
            )
        elif str(repo.get("protocol", "")).upper() in READ_ONLY:
            blockers.append(
                f"Repository {repository!r} is {repo.get('protocol')}, which ISE only reads from; pick an "
                "SFTP, FTP, NFS or DISK repository."
            )
        key = app.settings.backup_encryption_key
        if key is None or not key.get_secret_value():
            blockers.append(NO_KEY)
        running = str(last.get("status", "")).upper() == "IN_PROGRESS"
        if running:
            blockers.append(
                f"A {str(last.get('type') or 'configuration').lower()} backup is already running "
                f"({last.get('name')}, {last.get('percentComplete', '?')}% done); wait for it "
                "(ise_get_backup_status)."
            )
        target = repo_row(repo) if repo else {"name": repository}
        plan = Plan(
            f"Back up the ISE configuration as {name!r} to repository {repository!r}",
            details={
                "repository": target,
                "file": f"{name}-CFG10-<yymmdd>-<hhmm>.tar.gpg",
                "last_backup": last or "none has run",
                "method": "POST",
                "path": BACKUP,
                "body": {
                    "backupName": name,
                    "repositoryName": repository,
                    "backupEncryptionKey": "(set, never shown)",
                },
                "restore": "Not automated: Administration > System > Backup & Restore > Restore (or "
                "POST /api/v1/backup-restore/config/restore with the file, the repository and this key). "
                "Restoring replaces ISE's whole configuration and restarts its services.",
            },
            side_effects=[
                "ISE writes an encrypted configuration database backup to the repository; it keeps "
                "authenticating, and the admin GUI may be slower until the backup finishes.",
                "Keep ISE_BACKUP_ENCRYPTION_KEY: a restore needs the same key.",
                "Configuration only: operational (MnT) data is not backed up.",
            ],
            fingerprint={"repository": target, "running": running, "key_set": key is not None},
            blockers=blockers,
        )

        async def apply() -> Any:
            secret = key.get_secret_value() if key is not None else ""
            before = await last_backup(app)
            body = {"backupName": name, "repositoryName": repository, "backupEncryptionKey": secret}
            try:
                started = await app.openapi.post(BACKUP, body)
            except AuthError as denied:
                raise AuthError(DENIED.format(status=denied.status_code or 403), denied.status_code) from None
            except UpstreamError as err:
                # Never let ISE's error text carry the key back to the caller.
                raise UpstreamError(
                    str(err).replace(secret, "***") if secret else str(err), err.status_code
                ) from None
            ref = _response(started)
            task_id = str(ref.get("id")) if isinstance(ref, dict) and ref.get("id") else None
            out: dict[str, Any] = {"task_id": task_id, "check_with": "ise_get_backup_status"}
            if not wait:
                return {**out, "status": "started"}

            def finished(s: dict[str, Any]) -> bool:
                mine = str(s.get("name") or "")
                fresh = (mine == name or mine.startswith(f"{name}-CFG")) and (
                    before.get("name") != name or s.get("startDate") != before.get("startDate")
                )
                return fresh and str(s.get("status", "")).upper() in DONE

            try:
                status = await poll_until(
                    lambda: last_backup(app),
                    done=finished,
                    failed=lambda s: backup_failed(s) if finished(s) else False,
                    describe=lambda s: f"{s.get('status')} {s.get('percentComplete', '?')}%",
                    timeout=max(app.settings.mcp_task_timeout, WAIT_FLOOR),
                    interval=10.0,
                    max_interval=60.0,
                    ctx=ctx,
                    what="ISE configuration backup",
                )
            except (TaskFailed, UpstreamTimeout) as err:
                raise type(err)(f"{err} Check it with ise_get_backup_status.") from err
            return {**out, "backup": status}

        return await preview_or_apply(
            ctx,
            tool="ise_create_backup",
            args={"repository": repository, "name": name, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

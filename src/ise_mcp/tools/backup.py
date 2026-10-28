"""Configuration backups on demand (roadmap I78, with catc D114): the repositories ISE copies backups to and
the files in them, and a configuration backup before a risky change such as Catalyst Center's group-based
policy migration (catc D108), which makes ISE's TrustSec objects read-only.

ISE's OpenAPI backs up the configuration database only (`POST /api/v1/backup-restore/config/backup`), to a
repository defined under Administration > System > Maintenance > Repository, encrypted with a key the server
takes from ISE_BACKUP_ENCRYPTION_KEY (never from a tool argument, never shown). Progress is read from
`last-backup-status`. With no repository `GET /api/v1/repository` answers `{"response": null}` and
`last-backup-status` a record of nulls (the lab ISE 3.5, 2026-10-22), so ise_create_backup refuses in its
preview. Restore is not automated: docs and the preview say how.

Repositories themselves (roadmap I62): ise_set_repository creates or updates one over
`POST /api/v1/repository` and `PUT /api/v1/repository/{name}`; ise_delete_repository removes one (`DELETE`).
A repository password is read from a server environment variable the caller names (ISE_REPOSITORY_<...>,
or its _FILE twin), never taken as a tool argument and never shown. ISE returns stored passwords masked, so
an update sends it again.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.
import os
import re
from pathlib import Path
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
from ise_mcp._core.secrets import register_secret
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

# --- repositories (I62) ------------------------------------------------------------------------
REPO_PROTOCOL = Literal["SFTP", "FTP", "NFS", "HTTPS", "DISK"]
NEEDS_SERVER = ("SFTP", "FTP", "NFS", "HTTPS")
# A repository password may only come from a variable with this prefix, so a caller can't point the tool at
# the server's own ISE credentials (or any other secret in its environment) and send them to a server.
PASSWORD_ENV = re.compile(r"ISE_REPOSITORY_[A-Z0-9_]+")
HOST_KEY = (
    "ISE only talks to an SFTP server whose host key it trusts: on each ISE node that uses this repository "
    "run 'crypto host_key add host <server>' in the ISE CLI (3.x), or file listings and backups to it fail."
)
NOT_FOR_BACKUPS = (
    "ISE reads from {protocol} repositories (patches, upgrade bundles) but can't write a configuration "
    "backup to one; use SFTP, FTP, NFS or DISK for ise_create_backup."
)


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


def repo_password(var: str) -> str | None:
    """The repository password from the server's environment: `var`, or the file `<var>_FILE` names."""
    if not PASSWORD_ENV.fullmatch(var):
        raise InvalidRequest(
            f"password_env must name a variable starting ISE_REPOSITORY_ (upper case, digits, '_'), not "
            f"{var!r}: the tool never reads the server's other secrets."
        )
    value = os.environ.get(var)
    if not value and (file := os.environ.get(f"{var}_FILE")):
        try:
            value = Path(file).expanduser().read_text().removesuffix("\n")
        except OSError:
            raise InvalidRequest(f"{var}_FILE names a file this server can't read") from None
    if value:
        register_secret(value)
    return value or None


def truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "yes", "1")


async def files_check(app: IseApp, name: str, protocol: str) -> dict[str, Any]:
    """Can ISE list the repository? {'ok': True, 'files': n} or {'ok': False, 'error': ..., 'hint': ...}."""
    try:
        files = _response(await app.openapi.get(f"{REPOS}/{quote(name, safe='')}/files"))
    except UpstreamError as e:
        out: dict[str, Any] = {"ok": False, "error": str(e)}
        if protocol == "SFTP":
            out["hint"] = HOST_KEY
        return out
    return {"ok": True, "files": len([f for f in files or [] if isinstance(f, str)])}


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

    @reg.write(title="Create or update a backup repository")
    async def ise_set_repository(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                min_length=1,
                max_length=79,
                pattern=r"^[A-Za-z0-9_.-]+$",
                description="Repository name (letters, digits, '_', '-', '.'); an existing one is updated",
            ),
        ],
        protocol: Annotated[
            REPO_PROTOCOL,
            Field(description="SFTP, FTP or NFS (a server), DISK (the node's local disk), HTTPS (read only)"),
        ],
        server: Annotated[
            str | None, Field(description="Server name or IP (not for DISK)", max_length=255)
        ] = None,
        path: Annotated[str, Field(description="Directory on the server, starting with '/'")] = "/",
        user: Annotated[str | None, Field(description="Login user (SFTP, FTP; optional for HTTPS)")] = None,
        password_env: Annotated[
            str | None,
            Field(
                description="Name of the server environment variable holding the password, e.g. "
                "'ISE_REPOSITORY_SFTP_PASSWORD' (or its _FILE twin); never the password itself"
            ),
        ] = None,
        enable_pki: Annotated[
            bool, Field(description="SFTP: authenticate with ISE's public key instead of a password")
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a repository ISE copies configuration backups to (Administration > System > Maintenance >
        Repository), or update the one with this name, so ise_create_backup has somewhere to write. The
        password comes from a server environment variable named in `password_env` (ISE_REPOSITORY_...),
        never a tool argument, never shown; ISE never returns a stored password, so an update sends it again.
        Preview-first: the repository before/after and, for an existing one, whether ISE can list its files
        now; for SFTP it says ISE must trust the server's host key (CLI 'crypto host_key add'). After the
        change it lists the files once to show ISE can reach it."""
        app: IseApp = get_client(ctx)
        if not path.startswith("/"):
            raise InvalidRequest(f"path must start with '/', e.g. '/{path}'")
        if protocol == "DISK" and (server or user or password_env):
            raise InvalidRequest(
                "A DISK repository is the ISE node's local disk: leave server, user and password_env out"
            )
        if enable_pki and protocol != "SFTP":
            raise InvalidRequest("enable_pki applies to SFTP repositories only")
        password = repo_password(password_env) if password_env else None
        current = next((r for r in await repositories(app) if str(r.get("name")) == name), None)

        desired: dict[str, Any] = {"name": name, "protocol": protocol, "path": path}
        if protocol in NEEDS_SERVER and server:
            desired["serverName"] = server
        if user and protocol != "DISK":
            desired["userName"] = user
        if protocol == "SFTP":
            desired["enablePki"] = enable_pki

        blockers: list[str] = []
        if protocol in NEEDS_SERVER and not server:
            blockers.append(f"A {protocol} repository needs a server.")
        # The 3.5 OpenAPI SFTP schema requires userName with PKI too (ISE logs in as that user with its key).
        needs_login = protocol == "FTP" or (protocol == "SFTP" and not enable_pki)
        if protocol in ("FTP", "SFTP") and not user:
            blockers.append(f"A {protocol} repository needs a user.")
        wants_password = needs_login or (protocol == "HTTPS" and bool(user))
        if wants_password and not password_env:
            blockers.append(
                "Give password_env: the name of a server environment variable (ISE_REPOSITORY_...) holding "
                "the password"
                + (" (ISE never returns a stored password, so an update sends it again)." if current else ".")
            )
        elif password_env and not password:
            blockers.append(
                f"{password_env} (or {password_env}_FILE) is not set on this server: add it to the server's "
                "environment and restart it."
            )

        before = repo_row(current) if current else None
        after = repo_row(desired)
        changes = (
            {
                k: {"from": before.get(k), "to": after.get(k)}
                for k in sorted(set(before) | set(after))
                if before.get(k) != after.get(k)
            }
            if before is not None
            else None
        )
        if current and not changes and not password:
            blockers.append(f"Nothing changes in repository {name!r}.")
        shown = dict(desired)
        if password_env:
            shown["password"] = f"(from {password_env}, never shown)"

        details: dict[str, Any] = {
            "method": "PUT" if current else "POST",
            "path": f"{REPOS}/{quote(name, safe='')}" if current else REPOS,
            "body": shown,
        }
        side_effects: list[str] = []
        if current:
            details["changes"] = changes or {}
            details["files_now"] = await files_check(app, name, str(current.get("protocol", "")).upper())
            if not details["files_now"]["ok"]:
                side_effects.append(
                    f"ISE can't list {name!r} now ({details['files_now']['error']}); check the server, path "
                    "and login" + (", and the host key" if protocol == "SFTP" else "") + "."
                )
        if protocol == "SFTP":
            side_effects.append(HOST_KEY)
            if enable_pki:
                side_effects.append(
                    "PKI login: ISE signs in with its own key pair, so generate it on the ISE CLI "
                    "('crypto key generate rsa passphrase ...'), export the public key (Administration > "
                    "System > Maintenance > Repository > Export public key) and add it to the user's "
                    "authorized_keys."
                )
        if protocol == "HTTPS":
            side_effects.append(NOT_FOR_BACKUPS.format(protocol=protocol))
        side_effects.append(
            "ISE only stores the definition; nothing is copied until a backup or export uses it."
        )

        plan = Plan(
            f"{'Update' if current else 'Create'} {protocol} repository {name!r}"
            + (f" on {server}:{path}" if server else f" at {path}"),
            details=details,
            side_effects=side_effects,
            fingerprint={"current": before, "password_set": bool(password)},
            blockers=blockers,
        )

        async def apply() -> Any:
            body = dict(desired)
            if password:
                body["password"] = password
            try:
                if current:
                    await app.openapi.put(f"{REPOS}/{quote(name, safe='')}", body)
                else:
                    await app.openapi.post(REPOS, body)
            except UpstreamError as err:
                # Never let ISE's error text carry the password back to the caller.
                text = str(err).replace(password, "***") if password else str(err)
                raise type(err)(text, err.status_code) from None
            return {
                "repository": name,
                "action": "updated" if current else "created",
                "files_check": await files_check(app, name, protocol),
            }

        return await preview_or_apply(
            ctx,
            tool="ise_set_repository",
            args={
                "name": name,
                "protocol": protocol,
                "server": server,
                "path": path,
                "user": user,
                "password_env": password_env,
                "enable_pki": enable_pki,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete a backup repository")
    async def ise_delete_repository(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, description="Repository to delete (ise_list_repositories)")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a repository definition from ISE (the files on the server stay). Refused in the preview
        when the last configuration backup was a scheduled one to this repository (a schedule still writes
        there) or a backup to it is running. The REST API has no schedule view, so the preview also says to
        check Administration > System > Backup & Restore for other schedules. Preview-first."""
        app: IseApp = get_client(ctx)
        current = next((r for r in await repositories(app) if str(r.get("name")) == name), None)
        if current is None:
            raise NotFound(f"No repository {name!r}; see ise_list_repositories.", 404)
        last = await last_backup(app)
        mine = str(last.get("repository") or "") == name
        scheduled = mine and truthy(last.get("scheduled"))
        running = mine and str(last.get("status", "")).upper() == "IN_PROGRESS"
        blockers: list[str] = []
        if scheduled:
            blockers.append(
                f"Repository {name!r} is a scheduled backup target (the last backup, {last.get('name')}, was "
                "a scheduled one to it): move or delete the schedule under Administration > System > "
                "Backup & Restore first."
            )
        if running:
            blockers.append(
                f"A backup to {name!r} is running now ({last.get('percentComplete', '?')}% done); "
                "wait for it."
            )
        plan = Plan(
            f"Delete repository {name!r}",
            details={
                "repository": repo_row(current),
                "last_backup": last or "none has run",
                "method": "DELETE",
                "path": f"{REPOS}/{quote(name, safe='')}",
            },
            side_effects=[
                "The backup files on the server stay; ISE forgets the definition, so it can't restore from "
                "or list them until the repository is added again.",
                "The REST API shows no backup schedules, only the last backup's record: check "
                "Administration > System > Backup & Restore (and log/report exports) for anything else that "
                "uses this repository.",
            ],
            fingerprint={"current": repo_row(current), "scheduled": scheduled, "running": running},
            blockers=blockers,
        )
        return await preview_or_apply(
            ctx,
            tool="ise_delete_repository",
            args={"name": name},
            confirm=confirm,
            plan=plan,
            apply=lambda: app.openapi.delete(f"{REPOS}/{quote(name, safe='')}"),
        )

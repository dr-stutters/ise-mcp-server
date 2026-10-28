"""RADIUS proxy (I88): external RADIUS servers and RADIUS server sequences (ERS
/ers/config/externalradiusserver and /ers/config/radiusserversequence).

A network-access policy set whose `service` is a RADIUS server sequence proxies its requests to the
sequence's servers instead of authenticating them itself: the validated way to cut over from Microsoft NPS
or another AAA server one site (NDG) at a time, or to forward a partner realm (eduroam-style) or a VPN
headend's realm. ise_create_policy_set / ise_update_policy_set accept the sequence name as `service`
(ISE's service-names list holds both allowed-protocols services and server sequences). Deletes go through
ise_delete_object (kinds external_radius_server and radius_server_sequence), refused while a sequence lists
the server or a policy set uses the sequence.

Secrets work like NAD secrets: given per call (`shared_secret`, never echoed) or, better, by reference to a
server environment variable (`secret_env='ISE_RADIUS_SECRET_<NAME>'`, also `<var>_FILE`), so the secret never
passes through the tool arguments. Previews and diffs only say whether a secret is set or changes.
Message-Authenticator on responses defaults to required (the BlastRADIUS mitigation, CVE-2024-3596).
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import os
import re
from pathlib import Path
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from ise_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    field_changes,
    get_client,
    preview_or_apply,
)
from ise_mcp._core.formatting import EXTRA_SECRET_KEYS
from ise_mcp._core.secrets import register_secret
from ise_mcp.client import IseApp
from ise_mcp.tools._common import ers_list, parse_ip
from ise_mcp.tools.writes import ers_post, ers_put, fingerprint, masked_changes, put_body, unchanged

SERVERS = "externalradiusserver"
SERVER_WRAPPER = "ExternalRadiusServer"
SEQUENCES = "radiusserversequence"
SEQUENCE_WRAPPER = "RadiusServerSequence"
NA_POLICY_SETS = "/api/v1/policy/network-access/policy-set"

# The key-wrap authenticator key doesn't match the core secret pattern (encryptionKey does).
EXTRA_SECRET_KEYS.update({"authenticatorKey"})

# A secret may only come from a variable with this prefix, so a caller can't point the tool at the
# server's own ISE credentials (or any other secret in its environment) and send them to a RADIUS server.
SECRET_ENV = re.compile(r"ISE_RADIUS_SECRET_[A-Z0-9_]+")
_NAME = re.compile(r"^[A-Za-z0-9_.\- ]{1,64}$")
# #158: ISE 3.5 refuses anything but letters, digits and '_' in an external RADIUS server name, at confirm
# time ("The valid name can contain alphanumeric and underscore(_)"), so check it before the preview.
_SERVER_NAME = re.compile(r"^[A-Za-z0-9_]{1,64}$")
BLASTRADIUS = (
    "ISE stops requiring Message-Authenticator on this server's responses: forged Access-Accepts "
    "(BlastRADIUS, CVE-2024-3596) are no longer rejected. Only for an old server that can't send it"
)


def env_secret(var: str, arg: str = "secret_env") -> str:
    """The value of `var` (or of the file `<var>_FILE` names) from the server's environment."""
    if not SECRET_ENV.fullmatch(var):
        raise InvalidRequest(
            f"{arg} must name a variable starting ISE_RADIUS_SECRET_ (upper case, digits, '_'), not {var!r}: "
            "the tool never reads the server's other secrets."
        )
    value = os.environ.get(var)
    if not value and (file := os.environ.get(f"{var}_FILE")):
        try:
            value = Path(file).expanduser().read_text().removesuffix("\n")
        except OSError:
            raise InvalidRequest(f"{var}_FILE names a file this server can't read") from None
    if not value:
        raise InvalidRequest(
            f"{var} (or {var}_FILE) is not set on this server: add it to the server's environment and "
            "restart it"
        )
    register_secret(value)
    return value


def one_secret(value: str | None, env: str | None, what: str, env_arg: str) -> str | None:
    if value is not None and env is not None:
        raise InvalidRequest(f"Give {what} or {env_arg}, not both")
    if env is not None:
        return env_secret(env, env_arg)
    if value is not None and not value:
        raise InvalidRequest(f"{what} can't be empty")
    return value


def server_row(s: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": s.get("name"),
        "host": s.get("hostIP"),
        "auth_port": s.get("authenticationPort"),
        "acct_port": s.get("accountingPort"),
        "timeout": s.get("timeout"),
        "retries": s.get("retries"),
        "msg_auth_required": s.get("msgAuthIsRequiredOnResponse"),
        "key_wrap": s.get("enableKeyWrap"),
        "shared_secret_set": bool(s.get("sharedSecret")),
        "description": s.get("description") or None,
        "id": s.get("id"),
    }


def sequence_servers(q: dict[str, Any]) -> list[str]:
    raw = q.get("RadiusServerList") or []
    if isinstance(raw, str):  # tolerate a comma string, as the TACACS+ sequences store it
        raw = raw.split(",")
    return [str(x).strip() for x in raw if str(x).strip()]


def sequence_row(q: dict[str, Any], known: set[str] | None = None) -> dict[str, Any]:
    names = sequence_servers(q)
    row: dict[str, Any] = {
        "name": q.get("name"),
        "servers": names,
        "strip_prefix": q.get("prefixSeparator") if q.get("stripPrefix") else None,
        "strip_suffix": q.get("suffixSeparator") if q.get("stripSuffix") else None,
        "remote_accounting": q.get("remoteAccounting"),
        "local_accounting": q.get("localAccounting"),
        "continue_authz_policy": q.get("continueAuthorzPolicy"),
        "description": q.get("description") or None,
        "id": q.get("id"),
    }
    if known is not None and (missing := [n for n in names if n.lower() not in known]):
        row["missing_servers"] = missing
    return row


async def by_name(app: IseApp, resource: str, name: str) -> dict[str, Any] | None:
    hit = await app.ers_find(resource, name)
    return await app.ers_get(resource, str(hit["id"])) if hit else None


async def all_detail(app: IseApp, resource: str) -> list[dict[str, Any]]:
    page = await ers_list(app, resource, limit=500, offset=0, detail=True)
    return [x for x in page.items if isinstance(x, dict)]


async def proxy_references(app: IseApp, kind: str, obj: dict[str, Any]) -> list[str]:
    """Delete blockers: a server listed in a sequence, a sequence a network-access policy set uses."""
    name = str(obj.get("name")).lower()
    if kind == "external_radius_server":
        return [
            f"Listed in RADIUS server sequence {q.get('name')}: take it out (ise_set_radius_server_sequence) "
            "or delete the sequence first"
            for q in await all_detail(app, SEQUENCES)
            if name in [s.lower() for s in sequence_servers(q)]
        ]
    if kind == "radius_server_sequence":
        data = await app.openapi.get(NA_POLICY_SETS)
        sets = data.get("response", data) if isinstance(data, dict) else data
        return [
            f"Policy set {ps.get('name')} proxies to it (serviceName): point the policy set at another "
            "service first (ise_update_policy_set allowed_protocols)"
            for ps in sets or []
            if isinstance(ps, dict) and str(ps.get("serviceName") or "").lower() == name
        ]
    return []


def _delimiter(value: str, arg: str) -> str:
    if len(value) != 1:
        raise InvalidRequest(f"{arg} is one delimiter character (e.g. '\\\\' or '@'), or '' to turn it off")
    return value


def register(reg: ToolRegistrar) -> None:  # noqa: C901 - one registration block per tool
    @reg.write(title="Create or update an external RADIUS server")
    async def ise_set_external_radius_server(
        ctx: Context,
        name: Annotated[str, Field(description="External RADIUS server name, e.g. 'nps1'")],
        host: Annotated[str | None, Field(description="Server IPv4 address (required to create)")] = None,
        secret_env: Annotated[
            str | None,
            Field(
                description="Server environment variable holding the shared secret, e.g. "
                "'ISE_RADIUS_SECRET_NPS1' (also <var>_FILE; preferred over shared_secret)"
            ),
        ] = None,
        shared_secret: Annotated[
            str | None, Field(description="RADIUS shared secret (never echoed); or use secret_env")
        ] = None,
        auth_port: Annotated[
            int | None, Field(ge=1, le=65535, description="Authentication port (default 1812)")
        ] = None,
        acct_port: Annotated[
            int | None, Field(ge=1, le=65535, description="Accounting port (default 1813)")
        ] = None,
        timeout_seconds: Annotated[
            int | None, Field(ge=1, le=120, description="Seconds before ISE retries (default 5)")
        ] = None,
        retries: Annotated[int | None, Field(ge=1, le=9, description="Retries (default 3)")] = None,
        msg_auth_required: Annotated[
            bool | None,
            Field(
                description="Require Message-Authenticator on responses (default true: the BlastRADIUS "
                "mitigation; false only for a server that can't send it)"
            ),
        ] = None,
        key_wrap: Annotated[
            bool | None,
            Field(
                description="RADIUS key wrap (needs encryption_key_env and authenticator_key_env to turn on)"
            ),
        ] = None,
        encryption_key_env: Annotated[
            str | None, Field(description="ISE_RADIUS_SECRET_* variable with the key-wrap encryption key")
        ] = None,
        authenticator_key_env: Annotated[
            str | None, Field(description="ISE_RADIUS_SECRET_* variable with the key-wrap authenticator key")
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an external RADIUS server ISE can proxy to (an NPS or other AAA server being migrated
        from, or a partner realm's server), used through a RADIUS server sequence; or update one: given
        fields change, others are kept. The shared secret comes from a server environment variable
        (secret_env) or shared_secret and is never shown. Preview-first with a diff."""
        app: IseApp = get_client(ctx)
        if not _SERVER_NAME.match(name):
            raise InvalidRequest(
                f"External RADIUS server names are 1-64 letters, digits and '_' (ISE refuses '-', '.' "
                f"and spaces): {name!r}"
            )
        if host is not None and not parse_ip(host):
            raise InvalidRequest(f"host must be an IPv4 address: {host!r}")
        secret = one_secret(shared_secret, secret_env, "shared_secret", "secret_env")
        enc = env_secret(encryption_key_env, "encryption_key_env") if encryption_key_env else None
        auth = env_secret(authenticator_key_env, "authenticator_key_env") if authenticator_key_env else None
        patch = {
            k: v
            for k, v in {
                "hostIP": host,
                "sharedSecret": secret,
                "authenticationPort": auth_port,
                "accountingPort": acct_port,
                "timeout": timeout_seconds,
                "retries": retries,
                "msgAuthIsRequiredOnResponse": msg_auth_required,
                "enableKeyWrap": key_wrap,
                "encryptionKey": enc,
                "authenticatorKey": auth,
                "description": description,
            }.items()
            if v is not None
        }
        args = {
            "name": name,
            "host": host,
            "secret_env": secret_env,
            "shared_secret": shared_secret,
            "auth_port": auth_port,
            "acct_port": acct_port,
            "timeout_seconds": timeout_seconds,
            "retries": retries,
            "msg_auth_required": msg_auth_required,
            "key_wrap": key_wrap,
            "encryption_key_env": encryption_key_env,
            "authenticator_key_env": authenticator_key_env,
            "description": description,
        }
        existing = await by_name(app, SERVERS, name)
        base = put_body(existing) if existing else {}
        desired: dict[str, Any] = {
            **(
                base
                or {
                    "name": name,
                    "description": "",
                    "authenticationPort": 1812,
                    "accountingPort": 1813,
                    "timeout": 5,
                    "retries": 3,
                    "msgAuthIsRequiredOnResponse": True,
                    "enableKeyWrap": False,
                    "keyInputFormat": "ASCII",
                    # #158: ISE 3.5 answers 502 to a create without both key fields, even with key
                    # wrap off; a GET of a created server shows them as "".
                    "encryptionKey": "",
                    "authenticatorKey": "",
                }
            ),
            **patch,
        }
        blockers: list[str] = []
        side: list[str] = []
        if desired.get("enableKeyWrap") and not (
            desired.get("encryptionKey") and desired.get("authenticatorKey")
        ):
            blockers.append("Key wrap needs both keys: give encryption_key_env and authenticator_key_env")
        if desired.get("msgAuthIsRequiredOnResponse") is False and (
            not existing or existing.get("msgAuthIsRequiredOnResponse") is not False
        ):
            side.append(BLASTRADIUS)
        if existing:
            changes = masked_changes(base, desired)
            noop = unchanged(changes, secret, enc, auth)
            plan = Plan(
                f"Update external RADIUS server {existing.get('name')}",
                details={"changes": changes},
                blockers=blockers,
                fingerprint=fingerprint(existing),
                side_effects=[]
                if noop
                else [*side, "Sequences listing this server use it at the next request"],
                noop=noop,
                noop_reason=f"External RADIUS server {existing.get('name')} already as requested"
                if noop
                else None,
            )
            return await preview_or_apply(
                ctx,
                tool="ise_set_external_radius_server",
                args=args,
                confirm=confirm,
                plan=plan,
                apply=lambda: ers_put(app, SERVERS, SERVER_WRAPPER, desired),
            )
        blockers += [
            f"{arg} is required to create a server"
            for arg, v in (("host", host), ("secret_env (or shared_secret)", secret))
            if v is None
        ]
        return await preview_or_apply(
            ctx,
            tool="ise_set_external_radius_server",
            args=args,
            confirm=confirm,
            plan=Plan(
                f"Create external RADIUS server {name}",
                details=server_row(desired),
                blockers=blockers,
                side_effects=side,
            ),
            apply=lambda: ers_post(app, SERVERS, SERVER_WRAPPER, desired),
        )

    @reg.write(title="Create or update a RADIUS server sequence")
    async def ise_set_radius_server_sequence(
        ctx: Context,
        name: Annotated[
            str, Field(description="Sequence name; network-access policy sets use it as their service")
        ],
        servers: Annotated[
            list[str] | None,
            Field(
                description="External RADIUS server names in the order ISE tries them (required to create)"
            ),
        ] = None,
        strip_prefix: Annotated[
            str | None,
            Field(description="Strip a username prefix up to this delimiter, e.g. '\\'; '' = off"),
        ] = None,
        strip_suffix: Annotated[
            str | None,
            Field(description="Strip a username suffix from this delimiter, e.g. '@' for realms; '' = off"),
        ] = None,
        remote_accounting: Annotated[
            bool | None, Field(description="Forward accounting to the servers (default true)")
        ] = None,
        local_accounting: Annotated[
            bool | None, Field(description="Also keep accounting on ISE (default false)")
        ] = None,
        continue_authz_policy: Annotated[
            bool | None,
            Field(
                description="Run the policy set's authorization rules on the proxied result instead of "
                "returning the server's answer as is (default false)"
            ),
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a RADIUS server sequence (an ordered list of external RADIUS servers a network-access
        policy set proxies to: an NPS migration or a partner realm), or update one: given fields change,
        others are kept. The servers must exist (ise_set_external_radius_server). Then set the sequence as
        a policy set's service. Preview-first with a diff."""
        app: IseApp = get_client(ctx)
        if not _NAME.match(name):
            raise InvalidRequest(
                f"RADIUS server sequence names are 1-64 letters, digits, ' ', '_', '-', '.': {name!r}"
            )
        if servers is not None and not servers:
            raise InvalidRequest("A sequence needs at least one server")
        known = {str(x.get("name")).lower(): str(x.get("name")) for x in await all_detail(app, SERVERS)}
        blockers = [
            f"No external RADIUS server named {s_!r}: create it with ise_set_external_radius_server"
            for s_ in servers or []
            if s_.lower() not in known
        ]
        if servers and len({s_.lower() for s_ in servers}) != len(servers):
            blockers.append("A server is listed twice")
        patch: dict[str, Any] = {}
        if servers:
            patch["RadiusServerList"] = [known.get(s_.lower(), s_) for s_ in servers]
        for flag, sep, value, arg in (
            ("stripPrefix", "prefixSeparator", strip_prefix, "strip_prefix"),
            ("stripSuffix", "suffixSeparator", strip_suffix, "strip_suffix"),
        ):
            if value is not None:
                patch[flag] = bool(value)
                if value:
                    patch[sep] = _delimiter(value, arg)
        for key, on in (
            ("remoteAccounting", remote_accounting),
            ("localAccounting", local_accounting),
            ("continueAuthorzPolicy", continue_authz_policy),
        ):
            if on is not None:
                patch[key] = on
        if description is not None:
            patch["description"] = description
        args = {
            "name": name,
            "servers": servers,
            "strip_prefix": strip_prefix,
            "strip_suffix": strip_suffix,
            "remote_accounting": remote_accounting,
            "local_accounting": local_accounting,
            "continue_authz_policy": continue_authz_policy,
            "description": description,
        }
        side: list[str] = []
        if continue_authz_policy:
            side.append(
                "The policy set's authorization rules run on proxied logins (they need matching rules)"
            )
        existing = await by_name(app, SEQUENCES, name)
        if existing:
            base = put_body(existing)
            desired = {**base, **patch}
            changes = field_changes(sequence_row(base), sequence_row(desired))
            noop = unchanged(changes)
            plan = Plan(
                f"Update RADIUS server sequence {existing.get('name')}",
                details={"changes": changes},
                blockers=blockers,
                fingerprint=fingerprint(existing),
                side_effects=[]
                if noop
                else [*side, "Policy sets proxying to this sequence use it at the next request"],
                noop=noop,
                noop_reason=f"RADIUS server sequence {existing.get('name')} already as requested"
                if noop
                else None,
            )
            return await preview_or_apply(
                ctx,
                tool="ise_set_radius_server_sequence",
                args=args,
                confirm=confirm,
                plan=plan,
                apply=lambda: ers_put(app, SEQUENCES, SEQUENCE_WRAPPER, desired),
            )
        if not servers:
            raise InvalidRequest("Give servers to create a sequence")
        body = {
            "name": name,
            "description": "",
            "stripPrefix": False,
            "stripSuffix": False,
            "prefixSeparator": "\\",
            "suffixSeparator": "@",
            "remoteAccounting": True,
            "localAccounting": False,
            "useAttrSetOnRequest": False,
            "useAttrSetBeforeAcc": False,
            "continueAuthorzPolicy": False,
            **patch,
        }
        side.append(
            "Nothing is proxied until a network-access policy set uses it: ise_create_policy_set / "
            f"ise_update_policy_set with service {name!r}"
        )
        return await preview_or_apply(
            ctx,
            tool="ise_set_radius_server_sequence",
            args=args,
            confirm=confirm,
            plan=Plan(
                f"Create RADIUS server sequence {name}",
                details=sequence_row(body),
                blockers=blockers,
                side_effects=side,
            ),
            apply=lambda: ers_post(app, SEQUENCES, SEQUENCE_WRAPPER, body),
        )

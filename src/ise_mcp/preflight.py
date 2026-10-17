"""`ise-mcp-server check` (I36): what an operator needs to know before connecting a client.

One row per REST surface (OpenAPI, ERS on ISE_ERS_PORT, MnT), TLS trust, credentials, the account's ISE admin
groups vs the enabled tiers (docs/least-privilege.md) and the ISE version vs the tested matrix.
"""

from __future__ import annotations

from ise_mcp._core import AuthError, UpstreamError
from ise_mcp._core.preflight import Outcome, Preflight
from ise_mcp.client import SPONSOR_AUTH_HINT, IseApp
from ise_mcp.config import Settings
from ise_mcp.xmlutil import parse_xml

TESTED = ("3.5",)  # live-tested releases (README); I17 adds 3.2-3.4
MINIMUM = "3.1"  # the OpenAPI surface this server relies on arrived in 3.1

# ISE admin groups (docs/least-privilege.md): ERS writes need ERS Admin; the dangerous tier (CoA, ANC apply,
# node services, deletes of live policy) needs Super Admin.
WRITE_GROUPS = frozenset({"ERS Admin", "Super Admin"})
DANGEROUS_GROUPS = frozenset({"Super Admin"})
ERS_PORT_HINT = (
    "Enable ERS (Administration > System > Settings > API Settings) and check ISE_ERS_PORT (443 on ISE 3.1+, "
    "9060 on older releases or when ERS isn't enabled on 443). Without ERS: NADs, internal users, groups, "
    "SGTs, authz profiles, dACLs and ANC tools fail."
)


async def _openapi(app: IseApp) -> int:
    data = await app.openapi.request(
        "GET", "/api/v1/deployment/node", timeout=app.settings.probe_timeout, retry=False
    )
    return len(data.get("response") or []) if isinstance(data, dict) else 0


async def _ers(app: IseApp) -> str | None:
    data = await app.ers.request(
        "GET", "/ers/config/op/systemconfig/iseversion", timeout=app.settings.probe_timeout, retry=False
    )
    result = (data or {}).get("OperationResult") if isinstance(data, dict) else None
    if not isinstance(result, dict):
        raise UpstreamError("ERS answered without a version (OperationResult missing)")
    values = {
        str(v.get("name")): v.get("value") for v in result.get("resultValue") or [] if isinstance(v, dict)
    }
    return str(values["version"]) if values.get("version") else None


async def _mnt(app: IseApp) -> str | None:
    resp = await app.mnt.request(
        "GET", "/admin/API/mnt/Version", timeout=app.settings.probe_timeout, retry=False, expect="text"
    )
    _, info = parse_xml(resp)
    return str(info["version"]) if isinstance(info, dict) and info.get("version") else None


async def admin_groups(app: IseApp) -> list[str] | None:
    """The API account's admin groups from ERS `adminuser`, or None when ISE won't say (ERS down or the
    account can't read admin users)."""
    try:
        page = await app.ers.request(
            "GET", "/ers/config/adminuser", params={"filter": f"name.EQ.{app.username}"}, retry=False
        )
        resources = (page or {}).get("SearchResult", {}).get("resources") or []
        if not resources:
            return None
        detail = await app.ers.request("GET", f"/ers/config/adminuser/{resources[0]['id']}", retry=False)
    except (UpstreamError, KeyError, TypeError, AttributeError):
        return None
    user = (detail or {}).get("AdminUser") if isinstance(detail, dict) else None
    groups = (user or {}).get("adminGroups") if isinstance(user, dict) else None
    if not groups:
        return None
    return [g.strip() for g in str(groups).split(",") if g.strip()]


async def sponsor_check(app: IseApp, pf: Preflight) -> None:
    """The guest sponsor account (I31): set or not, and whether ERS accepts it for guestuser."""
    if app.sponsor is None:
        pf.skip(
            "sponsor",
            "ISE_SPONSOR_USERNAME/PASSWORD not set: guest-account tools are unavailable (guest types, "
            "sponsor groups and portals use the admin account)",
        )
        return
    try:
        await app.sponsor.request(
            "GET",
            "/ers/config/guestuser",
            params={"size": 1},
            timeout=app.settings.probe_timeout,
            retry=False,
        )
    except AuthError:
        pf.fail(
            "sponsor",
            f"ISE refused sponsor {app.sponsor_username!r} for the guest API",
            hint=SPONSOR_AUTH_HINT,
        )
    except UpstreamError as e:
        pf.warn("sponsor", f"guest API check for sponsor {app.sponsor_username!r} failed: {e}")
    else:
        pf.ok("sponsor", f"sponsor {app.sponsor_username!r} can use the guest API")


async def preflight(settings: Settings, pf: Preflight) -> None:
    app = IseApp(settings)
    try:
        nodes = await pf.reach("openapi", _openapi(app), detail=lambda n: f"OpenAPI answered ({n} node(s))")
        ers_version = await pf.reach("ers", _ers(app), detail=f"ERS answered on {app.ers_url}")
        ers_row = pf.results[-1]
        if ers_row.outcome is Outcome.FAIL and ers_row.check == "reachability":
            ers_row.hint = f"{ers_row.hint} {ERS_PORT_HINT}"
        elif ers_row.outcome is Outcome.FAIL and ers_row.check in ("auth", "role"):
            if nodes is not None:  # the same credentials work on OpenAPI: ERS refuses the account's groups
                ers_row.check = "role"
            ers_row.hint = (
                "ERS needs the ERS Operator (read) or ERS Admin (write) admin group, whatever other "
                "groups the account has (docs/least-privilege.md); or enable ERS in API Settings."
            )
        mnt_version = await pf.reach("mnt", _mnt(app), detail="MnT answered")
        if not any(r.outcome is Outcome.OK and r.check == "reachability" for r in pf.results):
            return

        groups = await admin_groups(app)
        if groups is None:
            pf.access(
                write=None,
                detail="ISE did not list this account's admin groups (needs ERS and read access to "
                "admin users)",
            )
        else:
            names = set(groups)
            pf.access(
                write=bool(names & WRITE_GROUPS),
                dangerous=bool(names & DANGEROUS_GROUPS),
                role=", ".join(groups),
            )
        pf.version(ers_version or mnt_version, tested=TESTED, minimum=MINIMUM)
        if ers_version is not None or ers_row.outcome is Outcome.OK:
            await sponsor_check(app, pf)
    finally:
        await app.aclose()

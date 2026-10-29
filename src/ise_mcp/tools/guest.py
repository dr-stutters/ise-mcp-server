"""Guest access (I31): guest types, sponsor groups, guest portals and locations (admin ERS), and the
guest-account lifecycle (ERS guestuser) run as a *sponsor*.

ERS quirks (ISE 3.5, checked live):
- guestuser answers only to a sponsor account (ISE_SPONSOR_USERNAME/PASSWORD) whose sponsor group has
  "Access Cisco ISE guest accounts using the programmatic interface"; the ERS admin gets 401. Sponsors
  may be internal or AD users (through the sponsor portal's identity source sequence). A sponsor sees
  only the guests its group's manage permission allows (own / group / all accounts).
- Creating or updating a guest needs `portalId`: the *sponsor* portal's id. A guest portal's id is
  refused ("please specify the portalID of the sponsor portal").
- `fromDate` and `toDate` ("MM/dd/yyyy HH:mm") are mandatory and read in the guest location's local
  time; ISE has no API for that zone (ISE_GUEST_TIMEZONE). Past start dates are accepted. `validDays`
  must equal the calendar days between the two dates, and the guest type's maximum duration is enforced.
- Extending is a full PUT with a new toDate/validDays; suspend (`/suspend/{id}` with an optional reason)
  and reinstate (`/reinstate/{id}`) are PUTs. guestlocation and sponsorgroupmember are list-only.
- Guest passwords: returned once by ise_create_guest_user / ise_reset_guest_password on confirm and
  never shown anywhere else (not in previews, audit events or the other tools).
- Service-desk operations (I72), PUTs of the same unlisted class as suspend/reinstate (Cisco ERS SDK):
  `resetpassword/{id}` (ISE generates the password; OperationResult resultValue carries it),
  `email/{id}/portalId/{portalId}` and `sms/{id}/portalId/{portalId}` (send the account details with the
  portal's notification template; optional additionalData senderEmail), `approve/{id}` and `deny/{id}`
  (self-registered guests in PENDING_APPROVAL). The sponsor group's permissions (canResetGuestPasswords,
  canSendSmsNotifications, canApproveSelfregGuests) decide whether ISE accepts each. The reset needs
  canViewGuestPasswords too, because it returns the new password (ISE 3.5, #182): without it ISE answers
  400 "Sponsor user does not have permission to reset/view passwords on guest accounts".
- Portal pages, themes and most portal settings stay in the GUI; the tools read the key settings.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
import secrets
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal
from urllib.parse import quote
from zoneinfo import ZoneInfo

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
    ToolRegistrar,
    ValidationFailed,
    compact,
    get_client,
    object_result,
    preview_or_apply,
)
from ise_mcp._core.formatting import NOT_SECRET_KEYS
from ise_mcp._core.http import page_of
from ise_mcp.client import IseApp, unwrap
from ise_mcp.tools._common import (
    ErsPage,
    ers_list,
    ers_name_map,
    ers_resolve,
    gather_limited,
    is_uuid,
    list_result,
)
from ise_mcp.tools.writes import deep_merge, fingerprint, masked_changes, put_body, unchanged

DATE_FMT = "%m/%d/%Y %H:%M"
# Without ISE_GUEST_TIMEZONE, "now" is taken in the earliest zone on earth (UTC-12) so a new account
# never starts in the future at the location (ISE accepts past start dates); it may end up to a day early.
FALLBACK_ZONE = "Etc/GMT+12"
GUEST_USERNAME = re.compile(r"[A-Za-z0-9_.@+-]{1,64}")
UNITS = {"DAYS": timedelta(days=1), "HOURS": timedelta(hours=1), "MINUTES": timedelta(minutes=1)}
STATUS_HINTS = {
    "AWAITING_INITIAL_LOGIN": "Created, never logged in yet",
    "ACTIVE": "Has logged in; valid until valid_to",
    "SUSPENDED": "Suspended by a sponsor: logins fail until ise_reinstate_guest_user",
    "EXPIRED": "Past valid_to: logins fail (ise_extend_guest_user, or create a new account)",
    "DENIED": "A self-registration request a sponsor denied",
    "PENDING_APPROVAL": "A self-registered guest waiting for sponsor approval (ise_approve_guest)",
}
# Statuses a sponsor can't reset the password of or notify (no usable account behind them yet / any more).
NOT_ISSUED = ("PENDING_APPROVAL", "DENIED")
PORTAL_KINDS = {
    "sponsor": "sponsorportal",
    "sponsored_guest": "sponsoredguestportal",
    "self_registration": "selfregportal",
    "hotspot": "hotspotportal",
}
MANAGE = {"own": "OWNACCOUNTS", "group": "GROUPACCOUNTS", "all": "ALLACCOUNTS"}
SPONSOR_PERMISSIONS = (
    "canUpdateGuestContactInfo",
    "canViewGuestPasswords",
    "canSendSmsNotifications",
    "canResetGuestPasswords",
    "canExtendGuestAccounts",
    "canDeleteGuestAccounts",
    "canSuspendGuestAccounts",
    "requireSuspensionReason",
    "canReinstateSuspendedAccounts",
    "canApproveSelfregGuests",
    "limitApprovalToSponsorsGuests",
)
# Sponsor-group permission flags whose names match the core secret pattern ("password"): booleans, show them.
NOT_SECRET_KEYS.update({"canViewGuestPasswords", "canResetGuestPasswords"})
# ISE's 400 when the sponsor group lacks 'view guest passwords' (or 'reset'), and what fixes it (#182).
RESET_DENIED = re.compile(r"does not have permission to reset/view passwords", re.IGNORECASE)
RESET_HINT = (
    "The sponsor group of {sponsor!r} needs both 'reset guest passwords' and 'view guest passwords' "
    "(ISE returns the new password). Fix: ise_set_sponsor_group(name=<the sponsor's group>, "
    "permissions={{'canViewGuestPasswords': true, 'canResetGuestPasswords': true}})"
)
GUEST_COLUMNS = ["username", "status", "guest_type", "valid_from", "valid_to", "sponsor", "company"]
# Markdown columns (the rows carry more than 10 keys; json has them all). id and description stay visible.
SPONSOR_GROUP_COLUMNS = [
    "name",
    "enabled",
    "members",
    "guest_types",
    "manage",
    "rest_access",
    "description",
    "id",
]
GUEST_TYPE_COLUMNS = [
    "name",
    "default_duration",
    "max_duration",
    "from_first_login",
    "sponsor_groups",
    "description",
    "id",
]
PORTAL_COLUMNS = ["name", "kind", "https_port", "auth_source", "test_url"]


# --- helpers --------------------------------------------------------------------------------------


def guest_zone(app: IseApp) -> ZoneInfo:
    return ZoneInfo(app.settings.guest_timezone or FALLBACK_ZONE)


def parse_when(value: str, what: str) -> datetime:
    """'YYYY-MM-DD', 'YYYY-MM-DD HH:MM' (or with T) or ISE's 'MM/DD/YYYY HH:MM' -> naive datetime."""
    text = value.strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d", DATE_FMT, "%m/%d/%Y"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise InvalidRequest(f"{what} {value!r}: use 'YYYY-MM-DD HH:MM' (the guest location's local time)")


def ise_date(dt: datetime) -> str:
    return dt.strftime(DATE_FMT)


def valid_days(start: datetime, end: datetime) -> int:
    """ISE's validDays: calendar days between the two dates (times ignored)."""
    return (end.date() - start.date()).days


def type_limits(gtype: dict[str, Any]) -> dict[str, Any]:
    access = gtype.get("accessTime") or {}
    unit = str(access.get("durationTimeUnit") or "DAYS").upper()
    step = UNITS.get(unit, UNITS["DAYS"])
    return {
        "unit": unit.lower(),
        "default": step * int(access.get("defaultDuration") or 1),
        "max": step * int(access.get("maxAccountDuration") or 1),
        "from_first_login": bool(access.get("fromFirstLogin")),
    }


def fmt_duration(delta: timedelta) -> str:
    if delta % timedelta(days=1) == timedelta(0):
        return f"{delta.days} day(s)"
    if delta % timedelta(hours=1) == timedelta(0):
        return f"{int(delta.total_seconds() // 3600)} hour(s)"
    return f"{int(delta.total_seconds() // 60)} minute(s)"


def guest_row(g: dict[str, Any]) -> dict[str, Any]:
    """A guest account for output. The password is never included."""
    info = g.get("guestInfo") or {}
    access = g.get("guestAccessInfo") or {}
    status = str(g.get("status") or "")
    row = {
        "username": info.get("userName") or g.get("name"),
        "status": status or None,
        "status_reason": g.get("statusReason"),
        "guest_type": g.get("guestType"),
        "valid_from": access.get("fromDate"),
        "valid_to": access.get("toDate"),
        "valid_days": access.get("validDays"),
        "location": access.get("location"),
        "ssid": access.get("ssid"),
        "sponsor": g.get("sponsorUserName"),
        "enabled": info.get("enabled"),
        "first_name": info.get("firstName"),
        "last_name": info.get("lastName"),
        "email": info.get("emailAddress"),
        "phone": info.get("phoneNumber"),
        "company": info.get("company"),
        "person_being_visited": g.get("personBeingVisited"),
        "reason_for_visit": g.get("reasonForVisit"),
        "created": info.get("creationTime"),
        "id": g.get("id"),
    }
    out = {k: v for k, v in row.items() if v not in (None, "")}
    if status in STATUS_HINTS:
        out["status_meaning"] = STATUS_HINTS[status]
    return out


def sponsor_group_row(g: dict[str, Any]) -> dict[str, Any]:
    other = g.get("otherPermissions") or {}
    create = g.get("createPermissions") or {}
    members = [str(m) for m in g.get("memberGroups") or []]
    return {
        "name": g.get("name"),
        "enabled": g.get("isEnabled"),
        "default": g.get("isDefaultGroup"),
        "members": members,
        "ad_members": [m for m in members if ":" in m],
        "guest_types": g.get("guestTypes") or [],
        "locations": g.get("locations") or [],
        "manage": {v: k for k, v in MANAGE.items()}.get(str(g.get("managePermission")).upper()),
        "rest_access": bool(other.get("canAccessViaRest")),
        "permissions": sorted(k for k in SPONSOR_PERMISSIONS if other.get(k)),
        "create": {k: v for k, v in create.items() if v not in (None, "")},
        "description": g.get("description"),
        "id": g.get("id"),
    }


def reset_warning(group: dict[str, Any]) -> list[str]:
    """#182: ISE refuses a password reset (ERS and sponsor portal) when 'view guest passwords' is off."""
    other = group.get("otherPermissions") or {}
    if other.get("canResetGuestPasswords") and not other.get("canViewGuestPasswords"):
        return [
            "canResetGuestPasswords is on but canViewGuestPasswords is off: ISE refuses password resets "
            "(ise_reset_guest_password) until both are on"
        ]
    return []


def guest_type_row(t: dict[str, Any], groups: dict[str, str]) -> dict[str, Any]:
    access = t.get("accessTime") or {}
    login = t.get("loginOptions") or {}
    unit = str(access.get("durationTimeUnit") or "DAYS").lower()
    return {
        "name": t.get("name"),
        "default": t.get("isDefaultType"),
        "default_duration": f"{access.get('defaultDuration')} {unit}",
        "max_duration": f"{access.get('maxAccountDuration')} {unit}",
        "from_first_login": access.get("fromFirstLogin"),
        "day_time_limits": access.get("dayTimeLimits")
        if access.get("allowAccessOnSpecificDaysTimes")
        else None,
        "max_simultaneous_logins": login.get("maxSimultaneousLogins")
        if login.get("limitSimultaneousLogins")
        else None,
        "max_devices": login.get("maxRegisteredDevices"),
        "identity_group": groups.get(str(login.get("identityGroupId")), login.get("identityGroupId")),
        "sponsor_groups": t.get("sponsorGroups") or [],
        "description": t.get("description"),
        "id": t.get("id"),
    }


def portal_row(p: dict[str, Any], kind: str, sequences: dict[str, str]) -> dict[str, Any]:
    settings = p.get("settings") or {}
    ps = settings.get("portalSettings") or {}
    login = settings.get("loginPageSettings") or {}
    auth = str(ps.get("authenticationMethod") or "")
    row: dict[str, Any] = {
        "name": p.get("name"),
        "kind": kind,
        "https_port": ps.get("httpsPort"),
        "auth_source": sequences.get(auth, auth or None),
        "certificate_group": ps.get("certificateGroupTag"),
        "employee_guest_type": ps.get("assignedGuestTypeForEmployee"),
        "available_ssids": ps.get("availableSsids"),
        "require_access_code": login.get("requireAccessCode"),
        "allow_self_registration": login.get("allowGuestToCreateAccounts"),
        "include_aup": (settings.get("aupSettings") or {}).get("includeAup"),
        "test_url": p.get("portalTestUrl"),
        "description": p.get("description"),
        "id": p.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, "", [])}


async def sponsor_portal_id(app: IseApp) -> str:
    """The sponsor portal whose id goes in guestuser portalId (ISE_SPONSOR_PORTAL, else the only one,
    else 'Sponsor Portal (default)'). Cached for the server's lifetime."""
    cached = app.__dict__.get("_sponsor_portal_id")
    if cached:
        return str(cached)
    want = app.settings.sponsor_portal
    if want and is_uuid(want):
        pid = want
    else:
        page = await app.ers_pager.fetch_page(app.ers, "/ers/config/sponsorportal", limit=100)
        portals = [p for p in page.items if isinstance(p, dict)]
        if want:
            hit = [p for p in portals if str(p.get("name")).lower() == want.lower()]
            if not hit:
                names = ", ".join(repr(p.get("name")) for p in portals)
                raise NotFound(f"ISE_SPONSOR_PORTAL {want!r} is not a sponsor portal (have: {names})", 404)
        else:
            hit = (
                portals
                if len(portals) == 1
                else [p for p in portals if p.get("name") == "Sponsor Portal (default)"]
            )
            if not hit:
                raise InvalidRequest(
                    "Several sponsor portals and none is 'Sponsor Portal (default)': set ISE_SPONSOR_PORTAL"
                )
        pid = str(hit[0]["id"])
    app.__dict__["_sponsor_portal_id"] = pid
    return pid


async def resolve_guest(app: IseApp, user: str) -> dict[str, Any]:
    """A guest account (as the sponsor sees it) by id or username."""
    key = user.strip()
    if not key:
        raise InvalidRequest("Give a guest username or id")
    path = (
        f"/ers/config/guestuser/{quote(key, safe='')}"
        if is_uuid(key)
        else f"/ers/config/guestuser/name/{quote(key, safe='')}"
    )
    try:
        data = await app.sponsor_request("GET", path)
    except NotFound:
        raise NotFound(
            f"No guest account {key!r} that sponsor {app.sponsor_username!r} can manage (a sponsor sees "
            "only the accounts its sponsor group's manage permission allows); see ise_list_guest_users",
            404,
        ) from None
    out: dict[str, Any] = unwrap(data)
    return out


def guest_put(current: dict[str, Any], portal_id: str, **patch: Any) -> dict[str, Any]:
    """A guestuser PUT body from a GET: read-only fields dropped, portalId added, `patch` merged in
    (guestInfo / guestAccessInfo as nested dicts). The password is never sent, so ISE keeps it."""
    info = {
        k: v
        for k, v in (current.get("guestInfo") or {}).items()
        if k not in ("password", "creationTime", "enabled")
    }
    body: dict[str, Any] = {
        k: v
        for k, v in current.items()
        if k not in ("link", "status", "sponsorUserId", "sponsorUserName", "guestInfo", "statusReason")
    }
    body["guestInfo"] = info
    body["portalId"] = portal_id
    return deep_merge(body, patch)


async def guest_type_by_name(app: IseApp, name: str) -> dict[str, Any]:
    return await ers_resolve(app, "guesttype", name, what="guest type", list_tool="ise_list_guest_types")


async def all_details(app: IseApp, resource: str) -> list[dict[str, Any]]:
    page = await ers_list(app, resource, limit=1000, offset=0, detail=True, detail_cap=None)
    return [i for i in page.items if isinstance(i, dict)]


# ISE's default guest password policy draws from these sets (no look-alikes: l, I, O, 0, 1) and, as
# checked on 3.5, wants at least 4 digits. A customised policy that refuses this shows ISE's error on
# confirm; pass `password` then.
PW_LOWER = "abcdefghijkmnopqrstuvwxyz"
PW_UPPER = "ABCDEFGHJKMNPQRSTUVWXYZ"
PW_DIGITS = "23456789"


def new_password(length: int = 10) -> str:
    """A random guest password that fits ISE's default guest password policy: half digits, the rest
    mixed-case letters."""
    digits = max(5, length // 2)
    chars = [secrets.choice(PW_LOWER), secrets.choice(PW_UPPER)]
    chars += [secrets.choice(PW_DIGITS) for _ in range(digits)]
    chars += [secrets.choice(PW_LOWER + PW_UPPER) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def reset_password_value(data: Any) -> str | None:
    """The new password from resetpassword's OperationResult ({"resultValue": [{"name": "password",
    "value": ...}]}); a lone unnamed value counts too. None when ISE returned none."""
    if not isinstance(data, dict):
        return None
    result = data.get("OperationResult", data)
    values = result.get("resultValue") if isinstance(result, dict) else None
    if isinstance(values, dict):
        values = [values]
    items = [v for v in values or [] if isinstance(v, dict) and v.get("value") not in (None, "")]
    named = [v for v in items if str(v.get("name") or "").lower() == "password"]
    pick = named or (items if len(items) == 1 else [])
    return str(pick[0]["value"]) if pick else None


def match_names(wanted: list[str], available: list[str], what: str) -> tuple[list[str], list[str]]:
    """Map names to ISE's exact spelling: exact (case-insensitive), else a unique match on the last
    path element (AD groups: 'mcp-sponsors' -> 'CORP:corp.com/Users/mcp-sponsors'). Returns (names,
    blockers)."""
    out: list[str] = []
    blockers: list[str] = []
    for w in wanted:
        key = w.strip().lower()
        hits = [a for a in available if a.lower() == key] or [
            a for a in available if re.split(r"[/:]", a)[-1].lower() == key
        ]
        if not hits:
            blockers.append(f"No {what} {w!r} (have: {', '.join(available[:15])})")
        elif len(hits) > 1:
            blockers.append(f"{w!r} matches several {what}s ({', '.join(hits)}): give the full name")
        elif hits[0] not in out:
            out.append(hits[0])
    return out, blockers


async def list_names(app: IseApp, resource: str) -> list[str]:
    page = await app.ers_pager.fetch_page(app.ers, f"/ers/config/{resource}", limit=1000)
    return [str(i.get("name")) for i in page.items if isinstance(i, dict) and i.get("name")]


# --- tools ----------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:  # noqa: C901 - one registration block per tool
    # --- read: configuration (admin) ------------------------------------------------------------

    @reg.read(title="List guest types")
    async def ise_list_guest_types(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Guest types (Daily, Weekly, Contractor, custom): default and maximum account duration, whether
        time counts from first login, day/time limits, simultaneous-login and device limits, the identity
        group guests land in (what authz rules match), and the sponsor groups allowed to use the type."""
        app: IseApp = get_client(ctx)
        groups = await ers_name_map(app, "identitygroup")
        rows = [guest_type_row(t, groups) for t in await all_details(app, "guesttype")]
        rows = [{k: v for k, v in r.items() if v not in (None, "")} for r in rows]
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=GUEST_TYPE_COLUMNS
        )

    @reg.read(title="List sponsor groups")
    async def ise_list_sponsor_groups(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Sponsor groups: member groups (ISE identity groups, or AD groups as
        '<join point>:<domain>/<path>/<group>'), the guest types and locations their sponsors may use,
        which guests they manage (own / group / all), whether they may use the guest REST API
        (rest_access, needed by ISE_SPONSOR_USERNAME) and their other permissions."""
        app: IseApp = get_client(ctx)
        rows = [sponsor_group_row(g) for g in await all_details(app, "sponsorgroup")]
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=SPONSOR_GROUP_COLUMNS
        )

    @reg.read(title="List guest and sponsor portals")
    async def ise_list_guest_portals(
        ctx: Context,
        kind: Annotated[
            Literal["all", "sponsor", "sponsored_guest", "self_registration", "hotspot"],
            Field(description="Which portals"),
        ] = "all",
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Sponsor, sponsored-guest, self-registration and hotspot portals with their key settings: HTTPS
        port, identity source (sequence) for logins, certificate group, SSIDs, AUP, access code,
        self-registration, and the test URL. The sponsor portal's id is the guest API's portalId.
        Portal creation, pages and themes are GUI-only here (Work Centers > Guest Access > Portals)."""
        app: IseApp = get_client(ctx)
        sequences = await ers_name_map(app, "idstoresequence")
        kinds = list(PORTAL_KINDS) if kind == "all" else [kind]
        rows: list[dict[str, Any]] = []
        for k in kinds:
            rows += [portal_row(p, k, sequences) for p in await all_details(app, PORTAL_KINDS[k])]
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=PORTAL_COLUMNS
        )

    @reg.read(title="Guest locations and SSIDs")
    async def ise_get_guest_locations(ctx: Context) -> dict[str, Any]:
        """Guest locations (each carries a time zone in the GUI; guest dates are in that local time) and
        the guest SSIDs sponsors can pick. Sponsor groups limit which locations their sponsors use. ERS
        lists names only: time zones are GUI-only (set ISE_GUEST_TIMEZONE to the location's zone)."""
        app: IseApp = get_client(ctx)
        locations = await list_names(app, "guestlocation")
        ssids = await list_names(app, "guestssid")
        return {
            "locations": locations,
            "ssids": ssids,
            "guest_timezone": app.settings.guest_timezone
            or f"not set: new accounts start at 'now' in {FALLBACK_ZONE} (see ISE_GUEST_TIMEZONE)",
        }

    # --- read: guest accounts (sponsor) -----------------------------------------------------------

    @reg.read(title="List guest accounts")
    async def ise_list_guest_users(
        ctx: Context,
        name: Annotated[str | None, Field(description="Username contains this")] = None,
        status: Annotated[
            Literal["AWAITING_INITIAL_LOGIN", "ACTIVE", "SUSPENDED", "EXPIRED", "DENIED", "PENDING_APPROVAL"]
            | None,
            Field(description="Only accounts in this state"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Guest accounts the sponsor (ISE_SPONSOR_USERNAME) can manage: status, guest type, valid
        from/to (location time), location, the sponsor who created each, and contact details. Passwords
        are never shown. A sponsor sees only what its sponsor group's manage permission allows."""
        app: IseApp = get_client(ctx)
        client = app.require_sponsor()
        filters = [f"name.CONTAINS.{name}"] if name else []
        if status:
            filters.append(f"status.EQ.{status}")
        try:
            page = await app.ers_pager.fetch_page(
                client,
                "/ers/config/guestuser",
                {"filter": filters} if filters else None,
                limit=limit,
                offset=offset,
            )
        except AuthError as e:
            raise app.sponsor_refused(e) from None
        items = [i for i in page.items if isinstance(i, dict) and i.get("id")]
        cap = app.settings.detail_threshold
        note = None
        if len(items) > cap:
            note = f"{len(items)} accounts exceed ISE_DETAIL_THRESHOLD ({cap}): names and ids only"
            rows = [{"username": i.get("name"), "id": i.get("id")} for i in items]
        else:
            full = await gather_limited(
                items,
                lambda i: app.sponsor_request("GET", f"/ers/config/guestuser/{quote(str(i['id']), safe='')}"),
                app.settings.detail_concurrency,
            )
            rows = [guest_row(unwrap(f)) for f in full]
        return list_result(
            ErsPage(rows, page.offset, page.total, more=page.more, note=note),
            fmt=response_format,
            columns=GUEST_COLUMNS,
            extra={"sponsor": app.sponsor_username},
        )

    @reg.read(title="Get a guest account")
    async def ise_get_guest_user(
        ctx: Context,
        user: Annotated[str, Field(description="Guest username or id")],
    ) -> ToolResult:
        """One guest account: status (with what it means), guest type, validity window, location/SSID,
        sponsor, contact details, visit reason. The password is never shown (it is returned once by
        ise_create_guest_user)."""
        app: IseApp = get_client(ctx)
        return object_result(guest_row(await resolve_guest(app, user)))

    # --- write: guest accounts (sponsor) ----------------------------------------------------------

    @reg.write(title="Create a guest account")
    async def ise_create_guest_user(
        ctx: Context,
        username: Annotated[str, Field(description="Guest username (letters, digits, _ . @ + -)")],
        guest_type: Annotated[
            str, Field(description="Guest type name, e.g. 'Daily (default)' (ise_list_guest_types)")
        ],
        first_name: Annotated[str | None, Field(description="First name")] = None,
        last_name: Annotated[str | None, Field(description="Last name")] = None,
        email: Annotated[str | None, Field(description="Email address")] = None,
        phone: Annotated[str | None, Field(description="Mobile number, E.164 (+15551234567)")] = None,
        company: Annotated[str | None, Field(description="Company")] = None,
        person_being_visited: Annotated[str | None, Field(description="Host employee")] = None,
        reason_for_visit: Annotated[str | None, Field(description="Reason for the visit")] = None,
        location: Annotated[
            str | None, Field(description="Guest location (ise_get_guest_locations); default the only one")
        ] = None,
        start: Annotated[
            str | None, Field(description="Start 'YYYY-MM-DD HH:MM' in location time; default now")
        ] = None,
        end: Annotated[
            str | None,
            Field(description="End 'YYYY-MM-DD HH:MM'; default start + the guest type's default duration"),
        ] = None,
        password: Annotated[
            str | None, Field(description="Guest password; default a random one (returned once)")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a guest account as the sponsor (ISE_SPONSOR_USERNAME), like the sponsor portal does.
        The preview shows the validity window checked against the guest type's maximum; on confirm the
        result carries the guest's password, the only time it is ever shown (hand it to the guest).
        Guests authenticate against the 'Guest Users' store and land in the guest type's identity group
        (authz rules on IdentityGroup:Name EQUALS 'Endpoint Identity Groups:...' / guest type group)."""
        app: IseApp = get_client(ctx)
        app.require_sponsor()
        if not GUEST_USERNAME.fullmatch(username):
            raise InvalidRequest("Guest usernames are 1-64 letters, digits, '_', '.', '@', '+' or '-'")
        gtype = await guest_type_by_name(app, guest_type)
        limits = type_limits(gtype)
        locations = await list_names(app, "guestlocation")
        blockers: list[str] = []
        if location:
            loc, problems = match_names([location], locations, "guest location")
            blockers += problems
            loc_name = loc[0] if loc else location
        elif len(locations) == 1:
            loc_name = locations[0]
        else:
            raise InvalidRequest(f"Give a location: one of {', '.join(locations)}")
        zone = guest_zone(app)
        begin = (
            parse_when(start, "start")
            if start
            else datetime.now(zone).replace(tzinfo=None, second=0, microsecond=0)
        )
        finish = parse_when(end, "end") if end else begin + limits["default"]
        if finish <= begin:
            blockers.append("end must be after start")
        if finish - begin > limits["max"]:
            blockers.append(
                f"{fmt_duration(finish - begin)} exceeds guest type {gtype.get('name')!r}'s maximum of "
                f"{fmt_duration(limits['max'])}"
            )
        try:
            await resolve_guest(app, username)
            blockers.append(f"Guest {username!r} already exists")
        except NotFound:
            pass
        portal = await sponsor_portal_id(app)
        info = compact(
            {
                "userName": username,
                "firstName": first_name,
                "lastName": last_name,
                "emailAddress": email,
                "phoneNumber": phone,
                "company": company,
                "enabled": True,
            }
        )
        access = {
            "validDays": valid_days(begin, finish),
            "fromDate": ise_date(begin),
            "toDate": ise_date(finish),
            "location": loc_name,
        }
        body: dict[str, Any] = compact(
            {
                "guestType": gtype.get("name"),
                "portalId": portal,
                "guestInfo": info,
                "guestAccessInfo": access,
                "personBeingVisited": person_being_visited,
                "reasonForVisit": reason_for_visit,
            }
        )
        shown = {
            "sponsor": app.sponsor_username,
            "guest_type": gtype.get("name"),
            "valid_from": access["fromDate"],
            "valid_to": access["toDate"],
            "duration": fmt_duration(finish - begin),
            "location": loc_name,
            "time_basis": app.settings.guest_timezone or f"{FALLBACK_ZONE} (ISE_GUEST_TIMEZONE not set)",
            "guest": {k: v for k, v in info.items() if k != "enabled"},
            "password": "given (never shown)" if password else "random, returned once on confirm",
        }
        if limits["from_first_login"]:
            shown["note"] = "This guest type counts the duration from the first login"

        async def apply() -> dict[str, Any]:
            secret = password or new_password()
            payload = deep_merge(body, {"guestInfo": {"password": secret}})
            created = await app.sponsor_request(
                "POST", "/ers/config/guestuser", json={"GuestUser": payload}, expect="response"
            )
            loc_header = created.headers.get("Location", "")
            return {
                "id": loc_header.rstrip("/").rsplit("/", 1)[-1] if loc_header else None,
                "username": username,
                "password": secret,
                "valid_from": access["fromDate"],
                "valid_to": access["toDate"],
                "guest_type": gtype.get("name"),
                "note": "The password is shown only now; ISE and these tools never show it again.",
            }

        return await preview_or_apply(
            ctx,
            tool="ise_create_guest_user",
            args={
                "username": username,
                "guest_type": guest_type,
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "phone": phone,
                "company": company,
                "person_being_visited": person_being_visited,
                "reason_for_visit": reason_for_visit,
                "location": location,
                "start": start,
                "end": end,
                "password": password,
            },
            confirm=confirm,
            plan=Plan(f"Create guest account {username}", details=shown, blockers=blockers),
            apply=apply,
        )

    @reg.write(title="Update a guest account's details")
    async def ise_update_guest_user(
        ctx: Context,
        user: Annotated[str, Field(description="Guest username or id")],
        first_name: Annotated[str | None, Field(description="New first name")] = None,
        last_name: Annotated[str | None, Field(description="New last name")] = None,
        email: Annotated[str | None, Field(description="New email")] = None,
        phone: Annotated[str | None, Field(description="New mobile number (E.164)")] = None,
        company: Annotated[str | None, Field(description="New company")] = None,
        person_being_visited: Annotated[str | None, Field(description="New host employee")] = None,
        reason_for_visit: Annotated[str | None, Field(description="New visit reason")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a guest's contact or visit details as the sponsor. Only the given fields change; the
        password and validity stay (ise_extend_guest_user for dates). Preview-first with a diff."""
        app: IseApp = get_client(ctx)
        current = await resolve_guest(app, user)
        info_patch = compact(
            {
                "firstName": first_name,
                "lastName": last_name,
                "emailAddress": email,
                "phoneNumber": phone,
                "company": company,
            }
        )
        top = compact({"personBeingVisited": person_being_visited, "reasonForVisit": reason_for_visit})
        if not info_patch and not top:
            raise InvalidRequest("Nothing to change: give at least one field")
        portal = await sponsor_portal_id(app)
        desired = guest_put(current, portal, guestInfo=info_patch, **top)
        before = guest_put(current, portal)
        return await preview_or_apply(
            ctx,
            tool="ise_update_guest_user",
            args={
                "user": user,
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "phone": phone,
                "company": company,
                "person_being_visited": person_being_visited,
                "reason_for_visit": reason_for_visit,
            },
            confirm=confirm,
            plan=Plan(
                f"Update guest account {current.get('name')}",
                details={"changes": masked_changes(before, desired)},
                fingerprint=fingerprint(current),
            ),
            apply=lambda: app.sponsor_request(
                "PUT", f"/ers/config/guestuser/{current['id']}", json={"GuestUser": desired}
            ),
        )

    @reg.write(title="Extend a guest account")
    async def ise_extend_guest_user(
        ctx: Context,
        user: Annotated[str, Field(description="Guest username or id")],
        days: Annotated[
            int | None, Field(ge=1, le=3650, description="Add this many days to valid_to")
        ] = None,
        until: Annotated[
            str | None, Field(description="Or set valid_to to 'YYYY-MM-DD HH:MM' (location time)")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Move a guest account's end date (as the sponsor). The whole window, start to new end, must stay
        within the guest type's maximum duration; the preview blocks it otherwise. An expired account
        becomes usable again if the new end is in the future. Preview-first."""
        app: IseApp = get_client(ctx)
        if (days is None) == (until is None):
            raise InvalidRequest("Give either days or until")
        current = await resolve_guest(app, user)
        access = current.get("guestAccessInfo") or {}
        begin = parse_when(str(access.get("fromDate") or ""), "current valid_from")
        old_end = parse_when(str(access.get("toDate") or ""), "current valid_to")
        new_end = old_end + timedelta(days=days) if days else parse_when(str(until), "until")
        gtype = await guest_type_by_name(app, str(current.get("guestType")))
        limits = type_limits(gtype)
        blockers: list[str] = []
        if new_end <= old_end:
            blockers.append(
                f"The new end {ise_date(new_end)} is not after the current end {ise_date(old_end)}"
            )
        if new_end - begin > limits["max"]:
            blockers.append(
                f"{ise_date(begin)} to {ise_date(new_end)} is {fmt_duration(new_end - begin)}, over "
                f"guest type {gtype.get('name')!r}'s maximum of {fmt_duration(limits['max'])}: "
                "create a new account or use a longer guest type"
            )
        portal = await sponsor_portal_id(app)
        desired = guest_put(
            current,
            portal,
            guestAccessInfo={"toDate": ise_date(new_end), "validDays": valid_days(begin, new_end)},
        )
        return await preview_or_apply(
            ctx,
            tool="ise_extend_guest_user",
            args={"user": user, "days": days, "until": until},
            confirm=confirm,
            plan=Plan(
                f"Extend guest account {current.get('name')} to {ise_date(new_end)}",
                details={
                    "status": current.get("status"),
                    "valid_from": ise_date(begin),
                    "valid_to": {"from": ise_date(old_end), "to": ise_date(new_end)},
                    "guest_type_max": fmt_duration(limits["max"]),
                },
                blockers=blockers,
                fingerprint=fingerprint(current),
            ),
            apply=lambda: app.sponsor_request(
                "PUT", f"/ers/config/guestuser/{current['id']}", json={"GuestUser": desired}
            ),
        )

    async def _set_suspended(
        ctx: Context, *, tool: str, user: str, suspend: bool, reason: str | None, confirm: str | None
    ) -> dict[str, Any]:
        app: IseApp = get_client(ctx)
        current = await resolve_guest(app, user)
        status = str(current.get("status") or "")
        blockers: list[str] = []
        if suspend and status == "SUSPENDED":
            blockers.append("The account is already suspended")
        if not suspend and status != "SUSPENDED":
            blockers.append(f"The account is not suspended (status {status or 'unknown'})")
        gid = quote(str(current["id"]), safe="")
        if suspend:
            path = f"/ers/config/guestuser/suspend/{gid}"
            body: Any = (
                {"OperationAdditionalData": {"additionalData": [{"name": "reason", "value": reason}]}}
                if reason
                else None
            )
            side = [
                "New logins with this account fail until reinstated",
                "Sessions already connected stay up until they re-authenticate (ise_find_session, CoA)",
            ]
        else:
            path, body, side = (
                f"/ers/config/guestuser/reinstate/{gid}",
                None,
                ["Logins work again until valid_to"],
            )
        verb = "Suspend" if suspend else "Reinstate"
        return await preview_or_apply(
            ctx,
            tool=tool,
            args={"user": user, **({"reason": reason} if suspend else {})},
            confirm=confirm,
            plan=Plan(
                f"{verb} guest account {current.get('name')}",
                details=compact(
                    {
                        "status": status,
                        "valid_to": (current.get("guestAccessInfo") or {}).get("toDate"),
                        "reason": reason,
                    }
                ),
                blockers=blockers,
                side_effects=side,
                fingerprint=fingerprint(current),
            ),
            apply=lambda: app.sponsor_request("PUT", path, json=body),
        )

    @reg.write(title="Suspend a guest account")
    async def ise_suspend_guest_user(
        ctx: Context,
        user: Annotated[str, Field(description="Guest username or id")],
        reason: Annotated[
            str | None, Field(description="Why (required when the sponsor group demands a reason)")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Suspend a guest account as the sponsor: logins fail until ise_reinstate_guest_user. Sessions
        already up are not disconnected (end one with a CoA). Preview-first."""
        return await _set_suspended(
            ctx, tool="ise_suspend_guest_user", user=user, suspend=True, reason=reason, confirm=confirm
        )

    @reg.write(title="Reinstate a suspended guest account")
    async def ise_reinstate_guest_user(
        ctx: Context,
        user: Annotated[str, Field(description="Guest username or id")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Reinstate a suspended guest account as the sponsor (logins work again until valid_to).
        Preview-first."""
        return await _set_suspended(
            ctx, tool="ise_reinstate_guest_user", user=user, suspend=False, reason=None, confirm=confirm
        )

    # --- write: service desk (sponsor, I72) -------------------------------------------------------

    @reg.write(title="Reset a guest's password")
    async def ise_reset_guest_password(
        ctx: Context,
        user: Annotated[str, Field(description="Guest username or id")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Reset a guest account's password as the sponsor ("I lost my password"): ISE generates a new one
        under the guest password policy and the old one stops working. On confirm the result carries the
        new password, the only time it is shown (not in the preview or the audit log); hand it to the
        guest or send it with ise_notify_guest. Needs both of the sponsor group's 'reset guest passwords'
        and 'view guest passwords' permissions (canResetGuestPasswords, canViewGuestPasswords; ISE refuses
        the reset without the second). Preview-first."""
        app: IseApp = get_client(ctx)
        current = await resolve_guest(app, user)
        status = str(current.get("status") or "")
        blockers: list[str] = []
        if status in NOT_ISSUED:
            blockers.append(
                f"The account is {status}: approve it first (ise_approve_guest)"
                if status == "PENDING_APPROVAL"
                else f"The account is {status}: there is no password to reset"
            )
        name = current.get("name")
        gid = quote(str(current["id"]), safe="")

        async def apply() -> dict[str, Any]:
            try:
                data = await app.sponsor_request("PUT", f"/ers/config/guestuser/resetpassword/{gid}")
            except ValidationFailed as e:
                if not RESET_DENIED.search(str(e)):
                    raise
                raise ValidationFailed(
                    f"{e} {RESET_HINT.format(sponsor=app.sponsor_username)}", e.status_code
                ) from None
            secret = reset_password_value(data)
            out: dict[str, Any] = {"username": name, "password": secret}
            out["note"] = (
                "The new password is shown only now; ISE and these tools never show it again."
                if secret
                else "ISE reset the password but returned none: send it to the guest with "
                "ise_notify_guest, or view it in the sponsor portal (needs 'view guest passwords')."
            )
            return out

        return await preview_or_apply(
            ctx,
            tool="ise_reset_guest_password",
            args={"user": user},
            confirm=confirm,
            plan=Plan(
                f"Reset the password of guest account {name}",
                details={
                    **compact(
                        {
                            "sponsor": app.sponsor_username,
                            "status": status,
                            "valid_to": (current.get("guestAccessInfo") or {}).get("toDate"),
                        }
                    ),
                    # Outside compact(), which masks any 'password' key.
                    "password": "generated by ISE, returned once on confirm",
                },
                blockers=blockers,
                side_effects=[
                    "The old password stops working at once",
                    "Sessions already connected stay up until they re-authenticate",
                ],
                fingerprint=fingerprint(current),
            ),
            apply=apply,
        )

    @reg.write(title="Send a guest their account details")
    async def ise_notify_guest(
        ctx: Context,
        user: Annotated[str, Field(description="Guest username or id")],
        via: Annotated[
            Literal["email", "sms"], Field(description="email (the guest's address) or sms (mobile number)")
        ] = "email",
        sender_email: Annotated[
            str | None, Field(description="From address for the email; default the portal's setting")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Send a guest their account details (username, password, validity) by email or SMS as the
        sponsor, with the sponsor portal's notification template ("resend my credentials"). ISE needs an
        SMTP server (email) or an SMS gateway (sms) configured, and SMS needs the sponsor group's 'send SMS
        notifications' permission; ISE's notification log shows the delivery. Preview-first."""
        app: IseApp = get_client(ctx)
        if sender_email and via != "email":
            raise InvalidRequest("sender_email goes with via='email'")
        current = await resolve_guest(app, user)
        info = current.get("guestInfo") or {}
        status = str(current.get("status") or "")
        to = info.get("emailAddress") if via == "email" else info.get("phoneNumber")
        blockers: list[str] = []
        if not to:
            field = "email" if via == "email" else "phone"
            blockers.append(f"The account has no {field}: set one with ise_update_guest_user({field}=...)")
        if status in NOT_ISSUED:
            blockers.append(f"The account is {status}: there are no credentials to send")
        portal = await sponsor_portal_id(app)
        gid = quote(str(current["id"]), safe="")
        path = f"/ers/config/guestuser/{via}/{gid}/portalId/{quote(portal, safe='')}"
        body: Any = (
            {"OperationAdditionalData": {"additionalData": [{"name": "senderEmail", "value": sender_email}]}}
            if sender_email
            else None
        )
        return await preview_or_apply(
            ctx,
            tool="ise_notify_guest",
            args={"user": user, "via": via, "sender_email": sender_email},
            confirm=confirm,
            plan=Plan(
                f"Send guest {current.get('name')} their account details by {via}",
                details=compact(
                    {
                        "sponsor": app.sponsor_username,
                        "to": to,
                        "status": status,
                        "sender_email": sender_email,
                        "sponsor_portal": portal,
                    }
                ),
                blockers=blockers,
                side_effects=[
                    f"ISE sends an {via} with the portal's template (it usually includes the password)",
                ],
                fingerprint=fingerprint(current),
            ),
            apply=lambda: app.sponsor_request("PUT", path, json=body),
        )

    @reg.write(title="Approve or deny a self-registered guest")
    async def ise_approve_guest(
        ctx: Context,
        user: Annotated[str, Field(description="Guest username or id (ise_list_guest_users status=...)")],
        approve: Annotated[bool, Field(description="True approves the request, False denies it")] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Approve or deny a self-registered guest waiting for sponsor approval ("approve my visitor"):
        find them with ise_list_guest_users(status='PENDING_APPROVAL'). Approved, the account becomes
        usable and ISE sends the credentials as the self-registration portal is set to; denied, it moves to
        DENIED and can't log in. Needs the sponsor group's 'approve self-registered guests' permission
        (and, with 'only guests that named this sponsor', the guest must have named the sponsor).
        Preview-first."""
        app: IseApp = get_client(ctx)
        current = await resolve_guest(app, user)
        status = str(current.get("status") or "")
        blockers: list[str] = []
        if status != "PENDING_APPROVAL":
            blockers.append(f"The account is not waiting for approval (status {status or 'unknown'})")
        op = "approve" if approve else "deny"
        verb = "Approve" if approve else "Deny"
        side = (
            ["The guest can log in until valid_to", "ISE sends the credentials as the portal is set to"]
            if approve
            else ["The account moves to DENIED; logins fail"]
        )
        return await preview_or_apply(
            ctx,
            tool="ise_approve_guest",
            args={"user": user, "approve": approve},
            confirm=confirm,
            plan=Plan(
                f"{verb} self-registered guest {current.get('name')}",
                details=guest_row(current),
                blockers=blockers,
                side_effects=side,
                fingerprint=fingerprint(current),
            ),
            apply=lambda: app.sponsor_request(
                "PUT", f"/ers/config/guestuser/{op}/{quote(str(current['id']), safe='')}"
            ),
        )

    @reg.write(title="Delete a guest account")
    async def ise_delete_guest_user(
        ctx: Context,
        user: Annotated[str, Field(description="Guest username or id")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a guest account as the sponsor. New logins fail at once; connected sessions stay up until
        they re-authenticate. Preview-first."""
        app: IseApp = get_client(ctx)
        current = await resolve_guest(app, user)
        return await preview_or_apply(
            ctx,
            tool="ise_delete_guest_user",
            args={"user": user},
            confirm=confirm,
            plan=Plan(
                f"Delete guest account {current.get('name')}",
                details=guest_row(current),
                side_effects=["Connected sessions stay up until they re-authenticate"],
                fingerprint=fingerprint(current),
            ),
            apply=lambda: app.sponsor_request(
                "DELETE", f"/ers/config/guestuser/{quote(str(current['id']), safe='')}"
            ),
        )

    # --- write: sponsor groups and guest types (admin) -------------------------------------------

    @reg.write(title="Create or update a sponsor group")
    async def ise_set_sponsor_group(
        ctx: Context,
        name: Annotated[str, Field(description="Sponsor group name (created when it doesn't exist)")],
        member_groups: Annotated[
            list[str] | None,
            Field(
                description="Who the sponsors are: ISE identity groups or AD groups added to a join point "
                "(full '<join point>:<domain>/<path>/<group>' or the short group name)"
            ),
        ] = None,
        guest_types: Annotated[
            list[str] | None, Field(description="Guest types its sponsors may use")
        ] = None,
        locations: Annotated[
            list[str] | None, Field(description="Guest locations its sponsors may use")
        ] = None,
        manage: Annotated[
            Literal["own", "group", "all"] | None,
            Field(description="Which guests its sponsors manage: own, the group's, or all"),
        ] = None,
        rest_access: Annotated[
            bool | None, Field(description="Allow the guest REST API (what ISE_SPONSOR_USERNAME needs)")
        ] = None,
        permissions: Annotated[
            dict[str, bool] | None,
            Field(
                description="Other permissions to set, e.g. {'canExtendGuestAccounts': true, "
                "'canViewGuestPasswords': false}; keys: " + ", ".join(SPONSOR_PERMISSIONS)
            ),
        ] = None,
        enabled: Annotated[bool | None, Field(description="Enable or disable the group")] = None,
        description: Annotated[str | None, Field(description="Description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a sponsor group, or change one: map AD groups (ise_add_ad_groups first, so the join
        point offers them) or ISE identity groups as sponsors, pick the guest types and locations they may
        use, what they manage, and REST access. Only the given fields change on an existing group. A new
        group defaults to own accounts, no REST access, and the permissions of ISE's shipped sponsor
        groups (view and reset guest passwords both on: ise_reset_guest_password needs both).
        Preview-first."""
        app: IseApp = get_client(ctx)
        bad = sorted(set(permissions or {}) - set(SPONSOR_PERMISSIONS))
        if bad:
            raise InvalidRequest(
                f"Unknown permission(s) {', '.join(bad)}; use: {', '.join(SPONSOR_PERMISSIONS)}"
            )
        found = await app.ers_find("sponsorgroup", name)
        current = await app.ers_get("sponsorgroup", str(found["id"])) if found else None
        blockers: list[str] = []
        patch: dict[str, Any] = {}
        if member_groups is not None:
            names, problems = match_names(
                member_groups, await list_names(app, "sponsorgroupmember"), "sponsor member group"
            )
            blockers += problems
            if problems and any(":" not in m for m in member_groups):
                blockers.append("AD groups must be added to the join point first (ise_add_ad_groups)")
            patch["memberGroups"] = names
        if guest_types is not None:
            names, problems = match_names(guest_types, await list_names(app, "guesttype"), "guest type")
            blockers += problems
            patch["guestTypes"] = names
        if locations is not None:
            names, problems = match_names(locations, await list_names(app, "guestlocation"), "guest location")
            blockers += problems
            patch["locations"] = names
        if manage is not None:
            patch["managePermission"] = MANAGE[manage]
        other = dict(permissions or {})
        if rest_access is not None:
            other["canAccessViaRest"] = rest_access
        if other:
            patch["otherPermissions"] = other
        if enabled is not None:
            patch["isEnabled"] = enabled
        if description is not None:
            patch["description"] = description
        if current is None:
            base: dict[str, Any] = {
                "name": name,
                "description": "",
                "isEnabled": True,
                "memberGroups": [],
                "guestTypes": [],
                "locations": [],
                "autoNotification": False,
                "managePermission": MANAGE["own"],
                "createPermissions": {
                    "canImportMultipleAccounts": False,
                    "importBatchSizeLimit": 200,
                    "canCreateRandomAccounts": False,
                    "randomBatchSizeLimit": 200,
                    "canSpecifyUsernamePrefix": True,
                    "canSetFutureStartDate": False,
                    "startDateFutureLimitDays": 1,
                },
                "otherPermissions": {
                    "canUpdateGuestContactInfo": True,
                    # On, like ISE's shipped sponsor groups: the ERS password reset needs it (#182).
                    "canViewGuestPasswords": True,
                    "canSendSmsNotifications": False,
                    "canResetGuestPasswords": True,
                    "canExtendGuestAccounts": True,
                    "canDeleteGuestAccounts": True,
                    "canSuspendGuestAccounts": True,
                    "requireSuspensionReason": False,
                    "canReinstateSuspendedAccounts": True,
                    "canApproveSelfregGuests": False,
                    "limitApprovalToSponsorsGuests": True,
                    "canAccessViaRest": False,
                },
            }
            desired = deep_merge(base, patch)
            if not desired["memberGroups"]:
                blockers.append("A new sponsor group needs member_groups")
            if not desired["guestTypes"]:
                blockers.append("A new sponsor group needs guest_types")
            if not desired["locations"]:
                blockers.append("A new sponsor group needs locations")
            plan = Plan(
                f"Create sponsor group {name}",
                details=sponsor_group_row(desired),
                blockers=blockers,
                side_effects=reset_warning(desired),
            )

            async def apply() -> Any:
                return await app.ers_create("sponsorgroup", {"SponsorGroup": desired})

        else:
            if not patch:
                raise InvalidRequest("Nothing to change: give at least one field")
            desired = deep_merge(put_body(current), patch)
            changes = masked_changes(put_body(current), desired)
            noop = unchanged(changes)
            plan = Plan(
                f"Update sponsor group {current.get('name')}",
                details={"changes": changes},
                blockers=blockers,
                side_effects=reset_warning(desired),
                fingerprint=fingerprint(current),
                noop=noop,
                noop_reason=f"Sponsor group {current.get('name')} already as requested" if noop else None,
            )

            async def apply() -> Any:
                return await app.ers_request(
                    "PUT", f"/ers/config/sponsorgroup/{current['id']}", json={"SponsorGroup": desired}
                )

        return await preview_or_apply(
            ctx,
            tool="ise_set_sponsor_group",
            args={
                "name": name,
                "member_groups": member_groups,
                "guest_types": guest_types,
                "locations": locations,
                "manage": manage,
                "rest_access": rest_access,
                "permissions": permissions,
                "enabled": enabled,
                "description": description,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Create or update a guest type")
    async def ise_set_guest_type(
        ctx: Context,
        name: Annotated[str, Field(description="Guest type name (created when it doesn't exist)")],
        default_duration: Annotated[int | None, Field(ge=1, description="Default account duration")] = None,
        max_duration: Annotated[int | None, Field(ge=1, description="Maximum account duration")] = None,
        duration_unit: Annotated[
            Literal["days", "hours", "minutes"] | None, Field(description="Unit of both durations")
        ] = None,
        from_first_login: Annotated[
            bool | None, Field(description="Count the duration from the guest's first login")
        ] = None,
        max_simultaneous_logins: Annotated[
            int | None, Field(ge=1, le=999, description="Limit concurrent logins (oldest is disconnected)")
        ] = None,
        max_devices: Annotated[int | None, Field(ge=1, le=999, description="Max registered devices")] = None,
        identity_group: Annotated[
            str | None,
            Field(
                description="Identity group guests land in (what authz rules match); new types default "
                "to the Daily type's group"
            ),
        ] = None,
        sponsor_groups: Annotated[
            list[str] | None, Field(description="Sponsor groups allowed to create this type")
        ] = None,
        description: Annotated[str | None, Field(description="Description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a guest type, or change one: account duration (default and maximum, in days, hours or
        minutes, optionally from first login), login and device limits, the identity group guests get, and
        the sponsor groups that may use it. Only the given fields change on an existing type.
        Notifications and day/time limits stay as the GUI set them. Preview-first."""
        app: IseApp = get_client(ctx)
        found = await app.ers_find("guesttype", name)
        current = await app.ers_get("guesttype", str(found["id"])) if found else None
        blockers: list[str] = []
        access: dict[str, Any] = compact(
            {
                "defaultDuration": default_duration,
                "maxAccountDuration": max_duration,
                "durationTimeUnit": duration_unit.upper() if duration_unit else None,
                "fromFirstLogin": from_first_login,
            }
        )
        login: dict[str, Any] = {}
        if max_simultaneous_logins is not None:
            login.update(limitSimultaneousLogins=True, maxSimultaneousLogins=max_simultaneous_logins)
        if max_devices is not None:
            login["maxRegisteredDevices"] = max_devices
        groups = await ers_name_map(app, "identitygroup")
        if identity_group is not None:
            by_name = {v.lower(): k for k, v in groups.items()}
            gid = identity_group if identity_group in groups else by_name.get(identity_group.lower())
            if not gid:
                blockers.append(f"No identity group {identity_group!r} (ise_list_identity_groups)")
            else:
                login["identityGroupId"] = gid
        patch: dict[str, Any] = {}
        if access:
            patch["accessTime"] = access
        if login:
            patch["loginOptions"] = login
        if sponsor_groups is not None:
            names, problems = match_names(
                sponsor_groups, await list_names(app, "sponsorgroup"), "sponsor group"
            )
            blockers += problems
            patch["sponsorGroups"] = names
        if description is not None:
            patch["description"] = description
        if current is None:
            if "identityGroupId" not in login:
                daily = await app.ers_find("guesttype", "Daily (default)")
                template = await app.ers_get("guesttype", str(daily["id"])) if daily else {}
                tgid = (template.get("loginOptions") or {}).get("identityGroupId")
                if not tgid:
                    blockers.append("Give identity_group (no 'Daily (default)' guest type to copy it from)")
                login.setdefault("identityGroupId", tgid)
            base: dict[str, Any] = {
                "name": name,
                "description": "",
                "accessTime": {
                    "fromFirstLogin": False,
                    "maxAccountDuration": 5,
                    "durationTimeUnit": "DAYS",
                    "defaultDuration": 1,
                    "allowAccessOnSpecificDaysTimes": False,
                },
                "loginOptions": {
                    "limitSimultaneousLogins": True,
                    "maxSimultaneousLogins": 3,
                    "failureAction": "Disconnect_Oldest_Connection",
                    "maxRegisteredDevices": 5,
                    "allowGuestPortalBypass": False,
                },
                "expirationNotification": {"enableNotification": False},
                "sponsorGroups": [],
            }
            desired = deep_merge(base, {**patch, "loginOptions": login})
        else:
            if not patch:
                raise InvalidRequest("Nothing to change: give at least one field")
            desired = deep_merge(put_body(current), patch)
        acc = desired["accessTime"]
        if int(acc.get("defaultDuration") or 0) > int(acc.get("maxAccountDuration") or 0):
            blockers.append("default_duration is longer than max_duration")
        row = guest_type_row(desired, groups)
        if current is None:
            plan = Plan(f"Create guest type {name}", details=compact(row), blockers=blockers)

            async def apply() -> Any:
                return await app.ers_create("guesttype", {"GuestType": desired})

        else:
            changes = masked_changes(put_body(current), desired)
            noop = unchanged(changes)
            plan = Plan(
                f"Update guest type {current.get('name')}",
                details={"changes": changes},
                blockers=blockers,
                fingerprint=fingerprint(current),
                noop=noop,
                noop_reason=f"Guest type {current.get('name')} already as requested" if noop else None,
            )

            async def apply() -> Any:
                return await app.ers_request(
                    "PUT", f"/ers/config/guesttype/{current['id']}", json={"GuestType": desired}
                )

        return await preview_or_apply(
            ctx,
            tool="ise_set_guest_type",
            args={
                "name": name,
                "default_duration": default_duration,
                "max_duration": max_duration,
                "duration_unit": duration_unit,
                "from_first_login": from_first_login,
                "max_simultaneous_logins": max_simultaneous_logins,
                "max_devices": max_devices,
                "identity_group": identity_group,
                "sponsor_groups": sponsor_groups,
                "description": description,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

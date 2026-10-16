"""Product safety rails for disruptive ISE actions (I18), layered on core G7.

Core G7 provides the operator-policy rails (dry-run, change window, blast-radius limits, deny lists,
two-person). This module adds the ISE-specific checks that go in a tool's `Plan.blockers`:

- a protect-list of MACs, usernames and NADs that a CoA / ANC / NAD-delete must never touch
  (ISE_PROTECT_MACS / ISE_PROTECT_USERS / ISE_PROTECT_NADS);
- counting the live sessions a port_bounce / port_shutdown CoA would disrupt, so the blast radius is
  truthful and a shared port (an uplink or trunk) is blocked unless ISE_COA_ALLOW_SHARED_PORT is set.

Tools set `Plan.blast_radius` to the number of sessions or endpoints affected so MCP_MAX_BLAST_RADIUS
can bound them.
"""

from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING, Any

from ise_mcp._core import InvalidRequest
from ise_mcp.tools._common import normalize_mac
from ise_mcp.xmlutil import as_list

if TYPE_CHECKING:
    from ise_mcp.client import IseApp
    from ise_mcp.config import Settings

# ANC/CoA actions that take the whole switch port down (so they get the shared-port rail).
PORT_ACTIONS = ("BOUNCE", "SHUT")


def _items(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]


def _norm_macs(raw: str) -> set[str]:
    out: set[str] = set()
    for m in _items(raw):
        with suppress(InvalidRequest):  # a malformed protect entry must not break every CoA
            out.add(normalize_mac(m))
    return out


def protect_blockers(
    settings: Settings,
    *,
    mac: str | None = None,
    user: str | None = None,
    nad: str | None = None,
    nad_ips: list[str] | None = None,
) -> list[str]:
    """Blockers when a disruptive action targets a protected endpoint, user or NAD. `nad` matches the
    NAD name and `nad_ips` its IP(s), both against ISE_PROTECT_NADS (case-insensitive)."""
    out: list[str] = []
    if mac:
        mac_n = normalize_mac(mac)
        if mac_n in _norm_macs(settings.protect_macs):
            out.append(f"{mac_n} is in the protected-MAC list (ISE_PROTECT_MACS); refusing.")
    if user and user.casefold() in {u.casefold() for u in _items(settings.protect_users)}:
        out.append(f"User {user!r} is in the protected-user list (ISE_PROTECT_USERS); refusing.")
    prot_nads = {n.casefold() for n in _items(settings.protect_nads)}
    for value in [nad, *(nad_ips or [])]:
        if value and value.casefold() in prot_nads:
            out.append(f"NAD {value!r} is in the protected-NAD list (ISE_PROTECT_NADS); refusing.")
            break
    return out


async def port_coa_guard(
    app: IseApp, session: dict[str, Any] | None, action_label: str
) -> tuple[int, list[str], list[str]]:
    """Blast radius, blockers and side effects for an action that bounces/shuts a switch port (a CoA
    port_bounce/port_shutdown, or an ANC policy with such an action). Counts the live sessions on the
    port: >1 means an uplink/trunk, blocked unless ISE_COA_ALLOW_SHARED_PORT. Falls open (blast 1, no
    blocker) when MnT doesn't report the port, so it never blocks on missing data."""
    s = session or {}
    nas_ip = str(s.get("nas_ip_address") or s.get("device_ip_address") or "")
    on_port = await sessions_on_port(app, nas_ip, str(s.get("nas_port_id") or ""))
    if not on_port or on_port <= 1:
        return (on_port or 1), [], []
    side = [f"{on_port} live sessions share this port and all go down"]
    blockers = []
    if not app.settings.coa_allow_shared_port:
        blockers.append(
            f"{on_port} live sessions share port {s.get('nas_port_id')} on "
            f"{s.get('network_device_name') or nas_ip} (an uplink or trunk). {action_label} disrupts "
            "them all; set ISE_COA_ALLOW_SHARED_PORT=true to override, or use a session-only action."
        )
    return on_port, blockers, side


async def sessions_on_port(app: IseApp, nas_ip: str, nas_port: str) -> int | None:
    """How many live sessions share this switch port (same NAS IP + NAS-Port), or None if MnT doesn't
    report the port on its active sessions (then the caller can't tell, and shouldn't guess)."""
    if not nas_ip or not nas_port:
        return None
    try:
        data = await app.mnt_get("Session/ActiveList")
    except Exception:  # noqa: BLE001 - counting is best-effort; the CoA still previews without it
        return None
    rows = (
        [s for s in as_list(data.get("activeSession")) if isinstance(s, dict)]
        if isinstance(data, dict)
        else []
    )
    if not any(r.get("nas_port_id") for r in rows):
        return None  # this MnT build doesn't include the port on ActiveList
    return sum(
        1
        for r in rows
        if r.get("nas_ip_address") == nas_ip and str(r.get("nas_port_id") or "") == str(nas_port)
    )

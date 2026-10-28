"""Random and changing MAC (RCM) and endpoint ownership: ISE's Light Session Directory (LSD) settings (I89).

iOS, Android and Windows private Wi-Fi addresses give one device a new MAC per SSID (or per day), which
breaks MAB, profiling, guest remember-me and endpoint ownership. ISE 3.x tracks which PSN owns an
endpoint (endpoint ownership, EPO) and, on top of that, detects a device coming back with a new random
MAC (RCM). Both switches live in one OpenAPI resource, GET/PUT /api/v1/lsd/updateLsdSettings
({"enableEPO": bool, "enableRCM": bool}). The PUT needs both fields, and ISE forces RCM off whenever EPO
is off (verified on 3.5; the spec says the same), so the write always sends both and refuses RCM on
with ownership off instead of letting ISE drop it silently.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from ise_mcp._core import (
    Confirm,
    Plan,
    ToolRegistrar,
    UpstreamError,
    field_changes,
    get_client,
    preview_or_apply,
)
from ise_mcp.client import IseApp

LSD_SETTINGS = "/api/v1/lsd/updateLsdSettings"
GUI_PATH = "Administration > System > Settings > Light Data Distribution"


def _flag(data: Any, key: str) -> bool | None:
    value = data.get(key) if isinstance(data, dict) else None
    return value if isinstance(value, bool) else None


async def read_lsd(app: IseApp) -> dict[str, Any]:
    """The raw LSD settings ({"enableEPO", "enableRCM"}); some releases wrap them in "response"."""
    data = await app.openapi.get(LSD_SETTINGS)
    if isinstance(data, dict) and isinstance(data.get("response"), dict):
        data = data["response"]
    if not isinstance(data, dict) or ("enableEPO" not in data and "enableRCM" not in data):
        raise UpstreamError(f"Unexpected LSD settings response from {LSD_SETTINGS}: {str(data)[:200]}")
    return data


def lsd_view(data: dict[str, Any]) -> dict[str, Any]:
    epo = _flag(data, "enableEPO")
    rcm = _flag(data, "enableRCM")
    out: dict[str, Any] = {
        "endpoint_ownership": epo,
        "rcm": rcm,
        "rcm_effective": bool(epo and rcm),
        "gui": GUI_PATH,
    }
    if epo is False:
        out["note"] = (
            "Endpoint ownership is off, so ISE treats RCM as off too: a device that returns with a new "
            "random MAC is a new endpoint (new MAB/profiling/guest record)"
        )
    elif rcm is False:
        out["note"] = (
            "RCM is off: private (randomized) MACs are tracked as separate endpoints; "
            "ise_set_mac_randomization(rcm=true) turns detection on"
        )
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Random MAC (RCM) and endpoint ownership settings")
    async def ise_get_mac_randomization(ctx: Context) -> dict[str, Any]:
        """ISE's random and changing MAC (RCM) and endpoint ownership settings (Light Session Directory):
        whether ISE tracks which PSN owns each endpoint and whether it detects a device that comes back
        with a new private/randomized MAC (iOS, Android and Windows private Wi-Fi addresses), which
        otherwise breaks MAB, profiling and guest remember-me. RCM only works with endpoint ownership on
        (rcm_effective). Change them with ise_set_mac_randomization."""
        app: IseApp = get_client(ctx)
        return lsd_view(await read_lsd(app))

    @reg.write(title="Set random MAC (RCM) and endpoint ownership")
    async def ise_set_mac_randomization(
        ctx: Context,
        endpoint_ownership: Annotated[
            bool | None,
            Field(
                description="Endpoint ownership (EPO): ISE tracks which PSN owns each endpoint across the "
                "deployment. Off forces RCM off too. Omit to keep the current value"
            ),
        ] = None,
        rcm: Annotated[
            bool | None,
            Field(
                description="Random and changing MAC detection: link a device's new private MAC to its "
                "existing endpoint. Needs endpoint ownership on. Omit to keep the current value"
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Turn ISE's random and changing MAC (RCM) detection and endpoint ownership (Light Session
        Directory settings) on or off. ISE writes both together, so the value not given keeps its current
        setting; turning endpoint ownership off also turns RCM off (ISE forces it), and RCM on with
        ownership off is refused. Already in the requested state: no_change, nothing to confirm.
        Preview-first, with the current values."""
        app: IseApp = get_client(ctx)
        current = await read_lsd(app)
        cur_epo = _flag(current, "enableEPO")
        cur_rcm = _flag(current, "enableRCM")
        epo = cur_epo if endpoint_ownership is None else endpoint_ownership
        want_rcm = cur_rcm if rcm is None else rcm
        blockers: list[str] = []
        side: list[str] = []
        if epo is None:
            blockers.append("ISE did not report enableEPO: give endpoint_ownership explicitly")
        if want_rcm is None:
            blockers.append("ISE did not report enableRCM: give rcm explicitly")
        if epo is False and rcm is True:
            blockers.append(
                "RCM needs endpoint ownership: ISE forces enableRCM off while enableEPO is off. "
                "Pass endpoint_ownership=true with rcm=true"
            )
        if epo is False and want_rcm:
            # rcm omitted and currently on: ISE would drop it anyway, so send what will actually be stored.
            want_rcm = False
            side.append("RCM is turned off too: ISE forces enableRCM off while endpoint ownership is off")
        body = {"enableEPO": bool(epo), "enableRCM": bool(want_rcm)}
        before = {"enableEPO": cur_epo, "enableRCM": cur_rcm}

        if cur_epo and not epo:
            side.append(
                "PSNs stop sharing endpoint ownership: an endpoint that moves between PSNs is no longer "
                "followed across them (profiling and session ownership per PSN)"
            )
        if not cur_epo and epo:
            side.append(
                "PSNs start tracking and sharing which PSN owns each endpoint (Light Session Directory)"
            )
        rcm_was = bool(cur_epo and cur_rcm)
        rcm_now = bool(body["enableEPO"] and body["enableRCM"])
        if rcm_now and not rcm_was:
            side.append(
                "Devices that return with a new random MAC are linked to their existing endpoint "
                "(applies to new authentications, not existing sessions)"
            )
        if rcm_was and not rcm_now:
            side.append(
                "Randomized MACs are no longer linked: each new private MAC becomes a new endpoint "
                "(MAB lists, profiling and guest remember-me stop following the device)"
            )

        noop = not blockers and before == body
        plan = Plan(
            "Set LSD settings: endpoint ownership "
            f"{'on' if body['enableEPO'] else 'off'}, RCM {'on' if body['enableRCM'] else 'off'}",
            details={
                "changes": field_changes(before, body),
                "current": lsd_view(current),
                "request": body,
            },
            fingerprint=current,
            blockers=blockers,
            side_effects=[] if noop else side,
            noop=noop,
            noop_reason=(
                f"Endpoint ownership already {'on' if cur_epo else 'off'}, "
                f"RCM already {'on' if cur_rcm else 'off'}"
                if noop
                else None
            ),
        )
        return await preview_or_apply(
            ctx,
            tool="ise_set_mac_randomization",
            args={"endpoint_ownership": endpoint_ownership, "rcm": rcm},
            confirm=confirm,
            plan=plan,
            apply=lambda: app.openapi.put(LSD_SETTINGS, json=body),
        )

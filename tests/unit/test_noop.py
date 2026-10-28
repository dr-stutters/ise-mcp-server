"""C71 adoption (#136): update tools answer `status: no_change` (no confirm token, nothing sent) when the
request leaves the object as it is, and a preview with a token as soon as one field differs."""

from __future__ import annotations

import json
from typing import Any

import respx

from tests.unit.conftest import ers_page, fixture_json
from tests.unit.test_writes import two_step

NAD = {
    "NetworkDevice": {
        "id": "n1",
        "name": "mcp-noop-nad",
        "description": "lab switch",
        "coaPort": 1700,
        "authenticationSettings": {"radiusSharedSecret": "stored-secret", "networkProtocol": "RADIUS"},
        "NetworkDeviceIPList": [{"ipaddress": "192.0.2.21", "mask": 32}],
        "NetworkDeviceGroupList": ["Location#All Locations", "Device Type#All Device Types"],
        "link": {"href": "x"},
    }
}
SGT = {
    "Sgt": {"id": "s1", "name": "mcp_noop", "value": 16, "description": "noop test", "propogateToApic": False}
}
DACL = {
    "DownloadableAcl": {
        "id": "d1",
        "name": "mcp-noop-dacl",
        "description": "",
        "dacl": "permit udp any any eq 53\ndeny ip any any",
        "daclType": "IPV4",
    }
}
GENERAL = "/api/v1/trustsec/general-settings"
TRUSTSEC = {"httpsServerConfig": {"enableHttps": True, "enableAuditLog": False}, "allowMultipleSGACLs": False}
GUEST = fixture_json("ers_guest.json")


def mock_nad(mock: respx.MockRouter) -> respx.Route:
    mock.get("/ers/config/networkdevice", params={"filter": "name.EQ.mcp-noop-nad"}).respond(
        json=ers_page([{"id": "n1", "name": "mcp-noop-nad"}])
    )
    mock.get("/ers/config/networkdevice/n1").respond(json=NAD)
    return mock.put("/ers/config/networkdevice/n1").respond(json={"UpdatedFieldsList": {}})


def mock_sgt(mock: respx.MockRouter) -> respx.Route:
    mock.get("/ers/config/sgt", params={"filter": "name.EQ.mcp_noop"}).respond(
        json=ers_page([{"id": "s1", "name": "mcp_noop"}])
    )
    mock.get("/ers/config/sgt/s1").respond(json=SGT)
    return mock.put("/ers/config/sgt/s1").respond(json={})


def mock_dacl(mock: respx.MockRouter) -> respx.Route:
    mock.get("/ers/config/downloadableacl", params={"filter": "name.EQ.mcp-noop-dacl"}).respond(
        json=ers_page([{"id": "d1", "name": "mcp-noop-dacl"}])
    )
    mock.get("/ers/config/downloadableacl/d1").respond(json=DACL)
    return mock.put("/ers/config/downloadableacl/d1").respond(json={})


def mock_trustsec(mock: respx.MockRouter) -> respx.Route:
    mock.get(GENERAL).respond(json=TRUSTSEC)
    return mock.put(GENERAL).respond(json={"success": {"message": "ok"}})


def mock_sponsor_group(mock: respx.MockRouter) -> respx.Route:
    sg = GUEST["sponsorgroup"]
    sg_id = sg["SponsorGroup"]["id"]
    mock.get("/ers/config/sponsorgroup", params={"filter": "name.EQ.mcp-guest-sponsors"}).respond(
        json=ers_page([{"id": sg_id, "name": "mcp-guest-sponsors"}])
    )
    mock.get(f"/ers/config/sponsorgroup/{sg_id}").respond(json=sg)
    return mock.put(f"/ers/config/sponsorgroup/{sg_id}").respond(json={})


def mock_guest_type(mock: respx.MockRouter) -> respx.Route:
    daily = GUEST["guesttype_daily"]
    gt_id = daily["GuestType"]["id"]
    mock.get("/ers/config/guesttype", params={"filter": "name.EQ.Daily (default)"}).respond(
        json=ers_page([{"id": gt_id, "name": "Daily (default)"}])
    )
    mock.get(f"/ers/config/guesttype/{gt_id}").respond(json=daily)
    mock.get("/ers/config/identitygroup").respond(json=ers_page([]))
    return mock.put(f"/ers/config/guesttype/{gt_id}").respond(json={})


def mock_custom_attributes(mock: respx.MockRouter) -> respx.Route:
    mock.get("/api/v1/endpoint-custom-attribute").respond(
        json=[{"attributeName": "assetTier", "attributeType": "String"}]
    )
    return mock.post("/api/v1/endpoint-custom-attribute").respond(201, text='"Created"')


def assert_noop(out: dict[str, Any], words: str) -> None:
    assert out["status"] == "no_change", out
    assert "confirm" not in out and words in out["summary"]


# --- ise_update_nad -------------------------------------------------------------------------------


async def test_update_nad_identical_rerun_is_no_change(mock: respx.MockRouter) -> None:
    put = mock_nad(mock)
    args = {"device": "mcp-noop-nad", "description": "lab switch", "coa_port": 1700, "ips": ["192.0.2.21"]}
    out, applied = await two_step("ise_update_nad", args)
    assert_noop(out, "already as requested")
    assert applied is None and not put.called


async def test_update_nad_one_field_changed_is_a_preview(mock: respx.MockRouter) -> None:
    put = mock_nad(mock)
    args = {"device": "mcp-noop-nad", "description": "lab switch", "coa_port": 3799}
    preview, applied = await two_step("ise_update_nad", args)
    assert preview["status"] == "preview" and preview["confirm"]
    assert preview["preview"]["changes"] == {"coaPort": {"from": 1700, "to": 3799}}
    assert applied["status"] == "applied" and put.called


async def test_update_nad_a_given_secret_is_always_a_change(mock: respx.MockRouter) -> None:
    # Even the stored value: secrets are never compared, so the operator confirms the re-send.
    mock_nad(mock)
    preview, _ = await two_step(
        "ise_update_nad", {"device": "mcp-noop-nad", "radius_secret": "stored-secret"}
    )
    assert preview["status"] == "preview" and preview["confirm"]
    assert "stored-secret" not in json.dumps(preview)


# --- ise_set_sgt ----------------------------------------------------------------------------------


async def test_set_sgt_identical_rerun_is_no_change(mock: respx.MockRouter) -> None:
    put = mock_sgt(mock)
    out, applied = await two_step(
        "ise_set_sgt", {"name": "mcp_noop", "value": 16, "description": "noop test"}
    )
    assert_noop(out, "SGT mcp_noop already as requested (value 16)")
    assert applied is None and not put.called
    assert "side_effects" not in out


async def test_set_sgt_value_changed_is_a_preview_with_retag(mock: respx.MockRouter) -> None:
    put = mock_sgt(mock)
    preview, applied = await two_step(
        "ise_set_sgt", {"name": "mcp_noop", "value": 17, "description": "noop test"}
    )
    assert preview["status"] == "preview" and preview["confirm"]
    assert preview["preview"]["changes"] == {"value": {"from": 16, "to": 17}}
    assert any("Re-tags" in s for s in preview["side_effects"])
    assert applied["status"] == "applied" and put.called


async def test_set_sgt_same_value_new_description_does_not_warn_retag(mock: respx.MockRouter) -> None:
    mock_sgt(mock)
    preview, _ = await two_step("ise_set_sgt", {"name": "mcp_noop", "value": 16, "description": "renamed"})
    assert preview["status"] == "preview"
    assert list(preview["preview"]["changes"]) == ["description"]
    assert not any("Re-tags" in s for s in preview.get("side_effects", []))


# --- ise_set_dacl ---------------------------------------------------------------------------------


async def test_set_dacl_identical_rerun_is_no_change(mock: respx.MockRouter) -> None:
    put = mock_dacl(mock)
    args = {"name": "mcp-noop-dacl", "aces": ["permit udp any any eq 53", "deny ip any any"]}
    out, applied = await two_step("ise_set_dacl", args)
    assert_noop(out, "already has exactly these ACEs")
    assert applied is None and not put.called
    preview, _ = await two_step("ise_set_dacl", {**args, "aces": ["permit ip any any"]})
    assert preview["status"] == "preview" and preview["confirm"]


# --- ise_set_trustsec_settings --------------------------------------------------------------------


async def test_set_trustsec_settings_identical_is_no_change(mock: respx.MockRouter) -> None:
    put = mock_trustsec(mock)
    out, applied = await two_step(
        "ise_set_trustsec_settings", {"https_server": True, "multiple_sgacls": False}
    )
    assert_noop(out, "already as requested")
    assert applied is None and not put.called
    preview, _ = await two_step("ise_set_trustsec_settings", {"audit_log": True})
    assert preview["status"] == "preview" and preview["confirm"]


# --- guest: sponsor group, guest type -------------------------------------------------------------


async def test_set_sponsor_group_identical_is_no_change(mock: respx.MockRouter) -> None:
    put = mock_sponsor_group(mock)
    args = {
        "name": "mcp-guest-sponsors",
        "manage": "own",
        "rest_access": True,
        "description": "test sponsors",
    }
    out, applied = await two_step("ise_set_sponsor_group", args)
    assert_noop(out, "Sponsor group mcp-guest-sponsors already as requested")
    assert applied is None and not put.called
    preview, _ = await two_step("ise_set_sponsor_group", {**args, "manage": "all"})
    assert preview["status"] == "preview" and preview["confirm"]


async def test_set_guest_type_identical_is_no_change(mock: respx.MockRouter) -> None:
    put = mock_guest_type(mock)
    args = {"name": "Daily (default)", "default_duration": 1, "max_duration": 5, "max_devices": 5}
    out, applied = await two_step("ise_set_guest_type", args)
    assert_noop(out, "Guest type Daily (default) already as requested")
    assert applied is None and not put.called
    preview, _ = await two_step("ise_set_guest_type", {**args, "default_duration": 2})
    assert preview["status"] == "preview" and preview["confirm"]


# --- ise_set_custom_attribute ---------------------------------------------------------------------


async def test_custom_attribute_existing_same_type_is_no_change(mock: respx.MockRouter) -> None:
    post = mock_custom_attributes(mock)
    out, applied = await two_step(
        "ise_set_custom_attribute", {"name": "assetTier", "attribute_type": "String"}
    )
    assert_noop(out, "already exists as String")
    assert applied is None and not post.called
    other, _ = await two_step("ise_set_custom_attribute", {"name": "assetTier", "attribute_type": "Int"})
    assert other["status"] == "blocked" and "already exists (String)" in other["blockers"][0]


# --- blockers still win over no_change ------------------------------------------------------------


async def test_blocker_wins_over_noop(mock: respx.MockRouter) -> None:
    mock_nad(mock)  # the NAD has no TACACS+: removing it is blocked, not "already as requested"
    out, _ = await two_step("ise_update_nad", {"device": "mcp-noop-nad", "remove_tacacs": True})
    assert out["status"] == "blocked"


# The contract test (tests/unit/test_contract.py) calls these on the mocks above.
NOOP_CALLS: dict[str, dict[str, Any]] = {
    "ise_update_nad": {"device": "mcp-noop-nad", "description": "lab switch", "ips": ["192.0.2.21"]},
    "ise_set_sgt": {"name": "mcp_noop", "value": 16, "description": "noop test"},
    "ise_set_dacl": {"name": "mcp-noop-dacl", "aces": ["permit udp any any eq 53", "deny ip any any"]},
    "ise_set_trustsec_settings": {"https_server": True},
    "ise_set_sponsor_group": {"name": "mcp-guest-sponsors", "manage": "own"},
    "ise_set_guest_type": {"name": "Daily (default)", "default_duration": 1},
    "ise_set_custom_attribute": {"name": "assetTier", "attribute_type": "String"},
}


def mock_all(mock: respx.MockRouter) -> None:
    for setup in (
        mock_nad,
        mock_sgt,
        mock_dacl,
        mock_trustsec,
        mock_sponsor_group,
        mock_guest_type,
        mock_custom_attributes,
    ):
        setup(mock)

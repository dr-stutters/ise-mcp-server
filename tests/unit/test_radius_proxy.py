"""RADIUS proxy (I88): ise_set_external_radius_server, ise_set_radius_server_sequence and their deletes,
against an in-memory ERS fake shaped like ISE 3.5's ExternalRadiusServer / RadiusServerSequence."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from ise_mcp._core.testing import call_tool
from tests.unit.conftest import ers_page, make_server
from tests.unit.test_writes import two_step

# Fake secrets, built so they aren't secret-looking literals (scrub_check).
NPS_KEY = "npskey" + "-fake-0123"
ENV_KEY = "envkey" + "-fake-4567"
WRAP_ENC = "wrapenc" + "0123456789"
WRAP_AUTH = "wrapauth" + "01234567890"

WRAPPERS = {"externalradiusserver": "ExternalRadiusServer", "radiusserversequence": "RadiusServerSequence"}

NPS = {
    "id": "r1",
    "name": "mcp_nps1",
    "description": "legacy NPS",
    "hostIP": "192.0.2.60",
    "sharedSecret": NPS_KEY,
    "enableKeyWrap": False,
    "keyInputFormat": "ASCII",
    "authenticationPort": 1812,
    "accountingPort": 1813,
    "timeout": 5,
    "retries": 3,
    "proxyTimeout": 300,
    "msgAuthIsRequiredOnResponse": True,
    "link": {"rel": "self", "href": "https://ise.test/ers/config/externalradiusserver/r1"},
}
SEQ = {
    "id": "q1",
    "name": "mcp_proxy",
    "description": "",
    "stripPrefix": False,
    "stripSuffix": True,
    "prefixSeparator": "\\",
    "suffixSeparator": "@",
    "remoteAccounting": True,
    "localAccounting": False,
    "useAttrSetOnRequest": False,
    "useAttrSetBeforeAcc": False,
    "continueAuthorzPolicy": False,
    "RadiusServerList": ["mcp_nps1"],
    "link": {"rel": "self", "href": "https://ise.test/ers/config/radiusserversequence/q1"},
}


def fake_ers(mock: respx.MockRouter, store: dict[str, list[dict[str, Any]]]) -> dict[str, respx.Route]:
    def listing(request: httpx.Request, res: str) -> httpx.Response:
        items = store.get(res, [])
        filt = request.url.params.get("filter", "")
        if filt.startswith("name.EQ."):
            items = [i for i in items if i["name"] == filt.removeprefix("name.EQ.")]
        return httpx.Response(200, json=ers_page([{"id": i["id"], "name": i["name"]} for i in items]))

    def get(request: httpx.Request, res: str, oid: str) -> httpx.Response:
        for i in store.get(res, []):
            if i["id"] == oid:
                return httpx.Response(200, json={WRAPPERS[res]: i})
        return httpx.Response(404, json={})

    mock.get(path__regex=r"^/ers/config/(?P<res>[a-z]+)$").mock(side_effect=listing)
    mock.get(path__regex=r"^/ers/config/(?P<res>[a-z]+)/(?P<oid>[^/]+)$").mock(side_effect=get)
    loc = {"Location": "https://ise.test/ers/config/x/new-id"}
    return {
        "post_server": mock.post("/ers/config/externalradiusserver").respond(201, headers=loc),
        "put_server": mock.put("/ers/config/externalradiusserver/r1").respond(json={"UpdatedFieldsList": {}}),
        "post_seq": mock.post("/ers/config/radiusserversequence").respond(201, headers=loc),
        "put_seq": mock.put("/ers/config/radiusserversequence/q1").respond(json={"UpdatedFieldsList": {}}),
        "delete_seq": mock.delete("/ers/config/radiusserversequence/q1").respond(204),
    }


def store(*, seq: bool = True) -> dict[str, list[dict[str, Any]]]:
    return {"externalradiusserver": [dict(NPS)], "radiusserversequence": [dict(SEQ)] if seq else []}


def sent(route: respx.Route, wrapper: str) -> dict[str, Any]:
    out: dict[str, Any] = json.loads(route.calls.last.request.content)[wrapper]
    return out


# --- external RADIUS server -----------------------------------------------------------------------


async def test_create_server_from_env_secret(mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ISE_RADIUS_SECRET_NPS2", ENV_KEY)
    routes = fake_ers(mock, store())
    args = {"name": "mcp_nps2", "host": "192.0.2.61", "secret_env": "ISE_RADIUS_SECRET_NPS2"}
    preview, applied = await two_step("ise_set_external_radius_server", args)
    assert preview["status"] == "preview", preview
    assert ENV_KEY not in json.dumps(preview)
    row = preview["preview"]
    assert row["shared_secret_set"] is True and row["auth_port"] == 1812 and row["acct_port"] == 1813
    assert row["msg_auth_required"] is True  # BlastRADIUS mitigation on by default
    assert applied["status"] == "applied"
    body = sent(routes["post_server"], "ExternalRadiusServer")
    assert body["sharedSecret"] == ENV_KEY and body["hostIP"] == "192.0.2.61"
    assert body["msgAuthIsRequiredOnResponse"] is True and body["enableKeyWrap"] is False
    assert {"timeout", "retries", "keyInputFormat"} <= set(body)
    assert ENV_KEY not in json.dumps(applied)


async def test_create_server_needs_host_and_secret(mock: respx.MockRouter) -> None:
    fake_ers(mock, store())
    out, _ = await two_step("ise_set_external_radius_server", {"name": "half", "host": "192.0.2.62"})
    assert out["status"] == "blocked" and "secret_env" in out["blockers"][0]


async def test_secret_env_must_use_prefix_and_be_set(mock: respx.MockRouter) -> None:
    fake_ers(mock, store())
    server = make_server(mcp_enable_writes=True)
    with pytest.raises(Exception, match="ISE_RADIUS_SECRET_"):
        await call_tool(server, "ise_set_external_radius_server", {"name": "x", "secret_env": "ISE_PASSWORD"})
    with pytest.raises(Exception, match="not set on this server"):
        await call_tool(
            server, "ise_set_external_radius_server", {"name": "x", "secret_env": "ISE_RADIUS_SECRET_NOPE"}
        )
    with pytest.raises(Exception, match="not both"):
        await call_tool(
            server,
            "ise_set_external_radius_server",
            {"name": "x", "shared_secret": "a", "secret_env": "ISE_RADIUS_SECRET_NOPE"},
        )


async def test_update_server_diff_masks_secret(mock: respx.MockRouter) -> None:
    routes = fake_ers(mock, store())
    args = {"name": "mcp_nps1", "timeout_seconds": 10, "shared_secret": "rotated" + "-fake"}
    preview, applied = await two_step("ise_set_external_radius_server", args)
    assert preview["status"] == "preview"
    changes = preview["preview"]["changes"]
    assert changes["timeout"] == {"from": 5, "to": 10}
    assert changes["sharedSecret"] == {"from": "********", "to": "********"}
    assert NPS_KEY not in json.dumps(preview) and "rotated-fake" not in json.dumps(preview)
    assert applied["status"] == "applied"
    body = sent(routes["put_server"], "ExternalRadiusServer")
    assert body["timeout"] == 10 and body["retries"] == 3 and "link" not in body


async def test_update_server_identical_is_no_change(mock: respx.MockRouter) -> None:
    routes = fake_ers(mock, store())
    args = {"name": "mcp_nps1", "host": "192.0.2.60", "timeout_seconds": 5, "msg_auth_required": True}
    out, applied = await two_step("ise_set_external_radius_server", args)
    assert out["status"] == "no_change" and "confirm" not in out
    assert "already as requested" in out["summary"]
    assert applied is None and not routes["put_server"].called


async def test_given_secret_is_always_a_change(mock: respx.MockRouter) -> None:
    fake_ers(mock, store())
    out, _ = await two_step("ise_set_external_radius_server", {"name": "mcp_nps1", "shared_secret": NPS_KEY})
    assert out["status"] == "preview" and NPS_KEY not in json.dumps(out)


async def test_turning_off_message_authenticator_warns(mock: respx.MockRouter) -> None:
    fake_ers(mock, store())
    out, _ = await two_step(
        "ise_set_external_radius_server", {"name": "mcp_nps1", "msg_auth_required": False}
    )
    assert out["status"] == "preview"
    assert any("BlastRADIUS" in s for s in out["side_effects"])


async def test_key_wrap_needs_both_keys(mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    routes = fake_ers(mock, store())
    out, _ = await two_step("ise_set_external_radius_server", {"name": "mcp_nps1", "key_wrap": True})
    assert out["status"] == "blocked" and "Key wrap" in out["blockers"][0]
    monkeypatch.setenv("ISE_RADIUS_SECRET_WRAP_ENC", WRAP_ENC)
    monkeypatch.setenv("ISE_RADIUS_SECRET_WRAP_AUTH", WRAP_AUTH)
    args = {
        "name": "mcp_nps1",
        "key_wrap": True,
        "encryption_key_env": "ISE_RADIUS_SECRET_WRAP_ENC",
        "authenticator_key_env": "ISE_RADIUS_SECRET_WRAP_AUTH",
    }
    preview, applied = await two_step("ise_set_external_radius_server", args)
    assert preview["status"] == "preview"
    text = json.dumps(preview)
    assert WRAP_ENC not in text and WRAP_AUTH not in text
    assert preview["preview"]["changes"]["authenticatorKey"]["to"] == "********"
    body = sent(routes["put_server"], "ExternalRadiusServer")
    assert body["enableKeyWrap"] is True and body["authenticatorKey"] == WRAP_AUTH
    assert WRAP_AUTH not in json.dumps(applied)


# --- RADIUS server sequence -----------------------------------------------------------------------


async def test_create_sequence(mock: respx.MockRouter) -> None:
    routes = fake_ers(mock, store(seq=False))
    args = {"name": "mcp_proxy2", "servers": ["MCP_NPS1"], "strip_suffix": "@", "continue_authz_policy": True}
    preview, applied = await two_step("ise_set_radius_server_sequence", args)
    assert preview["status"] == "preview", preview
    row = preview["preview"]
    assert row["servers"] == ["mcp_nps1"] and row["strip_suffix"] == "@" and row["strip_prefix"] is None
    assert row["remote_accounting"] is True and row["local_accounting"] is False
    assert any("ise_update_policy_set" in s for s in preview["side_effects"])
    assert applied["status"] == "applied"
    body = sent(routes["post_seq"], "RadiusServerSequence")
    assert body["RadiusServerList"] == ["mcp_nps1"] and body["stripSuffix"] is True
    assert body["suffixSeparator"] == "@" and body["continueAuthorzPolicy"] is True


async def test_sequence_unknown_server_is_blocked(mock: respx.MockRouter) -> None:
    fake_ers(mock, store(seq=False))
    out, _ = await two_step("ise_set_radius_server_sequence", {"name": "p", "servers": ["mcp_nps1", "ghost"]})
    assert out["status"] == "blocked" and "ghost" in out["blockers"][0]


async def test_update_sequence_diff_and_no_change(mock: respx.MockRouter) -> None:
    routes = fake_ers(mock, store())
    same, applied = await two_step(
        "ise_set_radius_server_sequence", {"name": "mcp_proxy", "servers": ["mcp_nps1"], "strip_suffix": "@"}
    )
    assert same["status"] == "no_change" and applied is None and not routes["put_seq"].called
    preview, applied = await two_step(
        "ise_set_radius_server_sequence", {"name": "mcp_proxy", "strip_suffix": "", "local_accounting": True}
    )
    assert preview["status"] == "preview"
    assert preview["preview"]["changes"] == {
        "strip_suffix": {"from": "@", "to": None},
        "local_accounting": {"from": False, "to": True},
    }
    body = sent(routes["put_seq"], "RadiusServerSequence")
    assert body["stripSuffix"] is False and body["localAccounting"] is True and "link" not in body


async def test_bad_delimiter(mock: respx.MockRouter) -> None:
    fake_ers(mock, store())
    with pytest.raises(Exception, match="one delimiter character"):
        await call_tool(
            make_server(mcp_enable_writes=True),
            "ise_set_radius_server_sequence",
            {"name": "mcp_proxy", "strip_suffix": "@@"},
        )


# --- deletes ----------------------------------------------------------------------------------------


async def test_delete_sequence_blocked_while_a_policy_set_uses_it(mock: respx.MockRouter) -> None:
    routes = fake_ers(mock, store())
    mock.get("/api/v1/policy/network-access/policy-set").respond(
        json={"response": [{"id": "p1", "name": "mcp-proxy", "serviceName": "MCP_PROXY"}]}
    )
    out, _ = await two_step("ise_delete_object", {"kind": "radius_server_sequence", "target": "mcp_proxy"})
    assert out["status"] == "blocked" and "mcp-proxy" in out["blockers"][0]
    assert not routes["delete_seq"].called


async def test_delete_sequence_when_unused(mock: respx.MockRouter) -> None:
    routes = fake_ers(mock, store())
    mock.get("/api/v1/policy/network-access/policy-set").respond(
        json={"response": [{"id": "p0", "name": "Default", "serviceName": "Default Network Access"}]}
    )
    preview, applied = await two_step(
        "ise_delete_object", {"kind": "radius_server_sequence", "target": "mcp_proxy"}
    )
    assert preview["status"] == "preview" and applied["status"] == "applied"
    assert routes["delete_seq"].called


async def test_delete_server_blocked_while_listed(mock: respx.MockRouter) -> None:
    fake_ers(mock, store())
    out, _ = await two_step("ise_delete_object", {"kind": "external_radius_server", "target": "mcp_nps1"})
    assert out["status"] == "blocked" and "mcp_proxy" in out["blockers"][0]
    assert NPS_KEY not in json.dumps(out)

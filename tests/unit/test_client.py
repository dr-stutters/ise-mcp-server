from __future__ import annotations

import httpx
import pytest
import respx
from stutters_mcp_core import AuthError, ValidationFailed
from stutters_mcp_core.testing import call_tool

from ise_mcp.client import IseApp, ers_error_detail, unwrap, with_port
from ise_mcp.xmlutil import as_list, mnt_error_detail, parse_xml
from tests.unit.conftest import BASE, make_server, make_settings, xml

ISEVERSION = {
    "OperationResult": {
        "resultValue": [
            {"name": "version", "value": "3.5.0.527"},
            {"name": "patch information", "value": "3,4"},
        ]
    }
}
NODES = {
    "response": [
        {"hostname": "ise", "roles": ["Standalone"], "services": ["Session"], "nodeStatus": "Connected"}
    ]
}
MNT_VERSION = xml(
    '<product name="Cisco Identity Services Engine"><version>3.5.0.527</version>'
    "<type_of_node>0</type_of_node></product>"
)


def test_with_port() -> None:
    assert with_port("https://ise.test", 443) == "https://ise.test"
    assert with_port("https://ise.test", 9060) == "https://ise.test:9060"
    assert with_port("https://ise.test:8443", 9060) == "https://ise.test:9060"
    assert with_port("https://[2001:db8::1]", 9060) == "https://[2001:db8::1]:9060"


def test_unwrap() -> None:
    assert unwrap({"NetworkDevice": {"id": "1"}}) == {"id": "1"}
    assert unwrap({"a": 1, "b": 2}) == {"a": 1, "b": 2}


def test_ers_error_detail() -> None:
    body = {"ERSResponse": {"messages": [{"title": "size must be <= 100", "type": "ERROR"}]}}
    assert ers_error_detail(body) == "size must be <= 100"
    assert ers_error_detail({"message": "x"}) == "x"


def test_parse_xml_repeated_and_attrs() -> None:
    tag, data = parse_xml(
        xml(
            '<activeList noOfActiveSession="2"><activeSession><user_name>a</user_name>'
            "</activeSession><activeSession><user_name>b</user_name></activeSession></activeList>"
        )
    )
    assert tag == "activeList"
    assert data["noOfActiveSession"] == "2"
    assert [s["user_name"] for s in as_list(data["activeSession"])] == ["a", "b"]


def test_parse_xml_rejects_entities() -> None:
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>'
    with pytest.raises(ValueError):
        parse_xml(evil)


def test_mnt_error_detail() -> None:
    body = xml(
        "<mnt-rest-result><http-code>500</http-code><cpm-code>34110</cpm-code><description>Server error"
        "</description><internal-error-info>Session data is not available for x.</internal-error-info>"
        "</mnt-rest-result>"
    )
    assert mnt_error_detail(body) == "Server error - Session data is not available for x."


async def test_status_all_surfaces(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    mock.get("/ers/config/op/systemconfig/iseversion", name="iseversion").respond(json=ISEVERSION)
    mock.get("/admin/API/mnt/Version", name="mntversion").respond(text=MNT_VERSION)
    out = await call_tool(make_server(), "ise_status")
    ise = out["ise"]
    assert ise["version"] == "3.5.0.527"
    assert ise["patches"] == "3,4"
    assert ise["nodes"][0]["hostname"] == "ise"
    assert all(ise["surfaces"][s]["ok"] for s in ("openapi", "ers", "mnt"))
    assert "warning" not in ise


async def test_status_ers_down(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    mock.get("/ers/config/op/systemconfig/iseversion", name="iseversion").mock(
        side_effect=httpx.ConnectTimeout("t")
    )
    mock.get("/admin/API/mnt/Version", name="mntversion").respond(text=MNT_VERSION)
    out = await call_tool(make_server(), "ise_status")
    ise = out["ise"]
    assert ise["surfaces"]["ers"]["ok"] is False
    assert "ISE_ERS_PORT" in ise["surfaces"]["ers"]["hint"]
    assert "ers" in ise["warning"]
    assert ise["version"] == "3.5.0.527"  # falls back to MnT


async def test_status_nothing_answers() -> None:
    with respx.mock(base_url=BASE) as r:
        r.route().mock(side_effect=httpx.ConnectError("refused"))
        out = await call_tool(make_server(), "ise_status")
    assert "No ISE API surface answered" in out["ise"]["error"]


async def test_ers_port_used(mock: respx.MockRouter) -> None:
    with respx.mock(assert_all_called=True) as r:
        r.get("https://ise.test:9060/ers/config/sgt/1").respond(json={"Sgt": {"id": "1"}})
        app = IseApp(make_settings(ers_port=9060))
        assert await app.ers_get("sgt", "1") == {"id": "1"}
        await app.aclose()


async def test_ers_csrf_retry(mock: respx.MockRouter) -> None:
    calls = {"n": 0}

    def post(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if request.headers.get("X-CSRF-Token") != "tok123":
            return httpx.Response(403, json={"ERSResponse": {"messages": [{"title": "CSRF token required"}]}})
        return httpx.Response(201, headers={"Location": f"{BASE}/ers/config/sgt/abc"})

    mock.post("/ers/config/sgt").mock(side_effect=post)
    mock.get("/ers/config/networkdevice/versioninfo").respond(headers={"X-CSRF-Token": "tok123"}, json={})
    app = IseApp(make_settings())
    out = await app.ers_create("sgt", {"Sgt": {"name": "x"}})
    assert out["id"] == "abc"
    assert calls["n"] == 2
    await app.aclose()


async def test_ers_403_without_csrf_is_auth_error(mock: respx.MockRouter) -> None:
    mock.post("/ers/config/sgt").respond(403, json={"ERSResponse": {"messages": [{"title": "Forbidden"}]}})
    app = IseApp(make_settings())
    with pytest.raises(AuthError):
        await app.ers_create("sgt", {"Sgt": {"name": "x"}})
    await app.aclose()


async def test_ers_validation_error(mock: respx.MockRouter) -> None:
    mock.post("/ers/config/sgt").respond(
        400, json={"ERSResponse": {"messages": [{"title": "Sgt name already exists"}]}}
    )
    app = IseApp(make_settings())
    with pytest.raises(ValidationFailed, match="already exists"):
        await app.ers_create("sgt", {"Sgt": {"name": "x"}})
    await app.aclose()


async def test_mnt_missing_session_is_none(mock: respx.MockRouter) -> None:
    mock.get("/admin/API/mnt/Session/MACAddress/AA:BB:CC:DD:EE:FF").respond(
        500,
        text=xml(
            "<mnt-rest-result><cpm-code>34110</cpm-code><internal-error-info>Session data is not "
            "available for AA:BB:CC:DD:EE:FF.</internal-error-info></mnt-rest-result>"
        ),
    )
    app = IseApp(make_settings())
    assert await app.mnt_get("Session/MACAddress/AA:BB:CC:DD:EE:FF") is None
    await app.aclose()


async def test_failure_reasons_cached(mock: respx.MockRouter) -> None:
    route = mock.get("/admin/API/mnt/FailureReasons").respond(
        text=xml(
            '<failureReasonList><failureReason id="22056"><code>22056 Subject not found in the applicable '
            "identity store(s)</code><cause>c</cause><resolution>r</resolution></failureReason>"
            '<failureReason id="5400"><code>5400 Authentication failed</code></failureReason>'
            "</failureReasonList>"
        )
    )
    app = IseApp(make_settings())
    reasons = await app.failure_reasons()
    assert reasons["22056"]["reason"] == "Subject not found in the applicable identity store(s)"
    assert reasons["22056"]["resolution"] == "r"
    await app.failure_reasons()
    assert route.call_count == 1
    await app.aclose()


async def test_status_malformed_surface(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    mock.get("/ers/config/op/systemconfig/iseversion", name="iseversion").respond(
        json={"OperationResult": None}
    )
    mock.get("/admin/API/mnt/Version", name="mntversion").respond(text=MNT_VERSION)
    out = await call_tool(make_server(), "ise_status")
    assert out["ise"]["surfaces"]["ers"]["ok"] is False
    assert out["ise"]["surfaces"]["mnt"]["ok"] is True


async def test_mnt_path_validation() -> None:
    from stutters_mcp_core import InvalidRequest

    app = IseApp(make_settings())
    with pytest.raises(InvalidRequest):
        await app.mnt_get("../../api/v1/x")
    with pytest.raises(InvalidRequest):
        await app.mnt_get("Session?x=1")
    await app.aclose()

"""I36: `ise-mcp-server check` against mocked ISE surfaces, one test per failure mode."""

import json
from typing import Any

import httpx
import pytest
import respx

from ise_mcp import main
from ise_mcp._core.preflight import run_preflight
from ise_mcp.preflight import preflight
from tests.unit.conftest import BASE, make_settings, xml

RO_GROUPS = "ERS Operator,Read Only Admin"


def _iseversion(version: str) -> dict[str, Any]:
    return {"OperationResult": {"resultValue": [{"name": "version", "value": version}]}}


def _mock(
    router: respx.MockRouter,
    *,
    version: str = "3.5.0.527",
    groups: str | None = RO_GROUPS,
    ers: httpx.Response | Exception | None = None,
) -> None:
    router.get("/api/v1/deployment/node").respond(json={"response": [{"hostname": "ise"}]})
    ers_route = router.get("/ers/config/op/systemconfig/iseversion")
    if isinstance(ers, Exception):
        ers_route.mock(side_effect=ers)
    else:
        ers_route.mock(return_value=ers or httpx.Response(200, json=_iseversion(version)))
    router.get("/admin/API/mnt/Version").respond(text=xml(f"<product><version>{version}</version></product>"))
    if groups is None:
        router.get("/ers/config/adminuser").respond(403)
    else:
        router.get("/ers/config/adminuser").respond(
            json={"SearchResult": {"total": 1, "resources": [{"id": "u1", "name": "admin"}]}}
        )
        router.get("/ers/config/adminuser/u1").respond(
            json={"AdminUser": {"name": "admin", "adminGroups": groups}}
        )


async def _run(**kw: Any) -> dict[str, Any]:
    return await run_preflight(
        make_settings(**kw), preflight, server="ise-mcp-server", product="ISE", env_prefix="ISE_"
    )


def _rows(report: dict[str, Any], check: str, inst: int = 0) -> list[dict[str, Any]]:
    return [c for c in report["instances"][inst]["checks"] if c["check"] == check]


def _one(report: dict[str, Any], check: str) -> dict[str, Any]:
    (row,) = _rows(report, check)
    return row


@pytest.fixture
def router() -> Any:
    with respx.mock(base_url=BASE, assert_all_called=False) as r:
        yield r


async def test_healthy_read_only(router: respx.MockRouter) -> None:
    _mock(router)
    report = await _run()
    assert report["ok"]
    reach = _rows(report, "reachability")
    assert [r["surface"] for r in reach] == ["openapi", "ers", "mnt"]
    assert all(r["outcome"] == "ok" for r in reach) and "1 node" in reach[0]["detail"]
    assert _one(report, "tls")["outcome"] == "ok"
    assert _one(report, "auth")["outcome"] == "ok"
    role = _one(report, "role")
    assert role["outcome"] == "ok" and "ERS Operator" in role["detail"]
    assert _one(report, "version")["outcome"] == "ok"
    assert "pw" not in json.dumps(report)


async def test_ers_unreachable_names_the_port(router: respx.MockRouter) -> None:
    _mock(router, ers=httpx.ConnectTimeout("timed out"))
    report = await _run()
    (ers,) = [r for r in _rows(report, "reachability") if r["surface"] == "ers"]
    assert ers["outcome"] == "fail" and "ISE_ERS_PORT" in ers["hint"]
    assert not report["ok"]
    assert _one(report, "version")["outcome"] == "ok"  # MnT still reports it


async def test_tls_not_trusted(router: respx.MockRouter) -> None:
    err = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed")
    router.route().mock(side_effect=err)
    report = await _run()
    tls = _rows(report, "tls")
    assert tls and all(r["outcome"] == "fail" for r in tls) and "ISE_CA_BUNDLE" in tls[0]["hint"]
    assert _one(report, "role")["outcome"] == "skip"


async def test_wrong_password(router: respx.MockRouter) -> None:
    router.route().respond(401)
    report = await _run()
    auth = _rows(report, "auth")
    assert auth and auth[0]["outcome"] == "fail" and "ISE_PASSWORD" in auth[0]["hint"]
    assert _one(report, "version")["outcome"] == "skip"


async def test_account_without_ers_group(router: respx.MockRouter) -> None:
    _mock(router, ers=httpx.Response(401), groups=None)
    report = await _run()
    (ers,) = [r for r in report["instances"][0]["checks"] if r.get("surface") == "ers"]
    assert ers["check"] == "role" and ers["outcome"] == "fail" and "ERS Operator" in ers["hint"]


async def test_writes_enabled_on_read_only_account(router: respx.MockRouter) -> None:
    _mock(router)
    report = await _run(mcp_enable_writes=True)
    role = _one(report, "role")
    assert role["outcome"] == "fail" and "write" in role["detail"]
    assert "MCP_ENABLE_WRITES=false" in role["hint"]


async def test_dangerous_needs_super_admin(router: respx.MockRouter) -> None:
    _mock(router, groups="ERS Admin,Policy Admin")
    report = await _run(mcp_enable_writes=True, mcp_enable_dangerous=True)
    role = _one(report, "role")
    assert role["outcome"] == "fail" and "dangerous" in role["detail"]


async def test_super_admin_on_read_only_server_warns(router: respx.MockRouter) -> None:
    _mock(router, groups="Super Admin")
    report = await _run()
    role = _one(report, "role")
    assert role["outcome"] == "warn" and "read-only account" in role["hint"]
    assert report["ok"]


async def test_groups_unreadable(router: respx.MockRouter) -> None:
    _mock(router, groups=None)
    assert _one(await _run(), "role")["outcome"] == "ok"  # reads work; nothing more is enabled
    assert _one(await _run(mcp_enable_writes=True), "role")["outcome"] == "warn"  # can't tell about writes


@pytest.mark.parametrize(("version", "outcome"), [("3.4.0.608", "warn"), ("3.0.0.458", "fail")])
async def test_version_matrix(router: respx.MockRouter, version: str, outcome: str) -> None:
    _mock(router, version=version)
    assert _one(await _run(), "version")["outcome"] == outcome


async def test_two_instances(router: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ISE_DR_URL", "https://ise-dr.test")
    monkeypatch.setenv("ISE_DR_USERNAME", "ro")
    monkeypatch.setenv("ISE_DR_PASSWORD", "x")
    _mock(router)
    respx.route(host="ise-dr.test").mock(side_effect=httpx.ConnectError("no route to host"))
    report = await _run(instances="dr")
    assert [i["instance"] for i in report["instances"]] == ["default", "dr"]
    assert report["instances"][0]["ok"] and not report["instances"][1]["ok"]


def test_cli_check_json(
    router: respx.MockRouter,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    for k, v in {
        "ISE_URL": BASE,
        "ISE_USERNAME": "admin",
        "ISE_PASSWORD": "s3cret",
        "ISE_RETRIES": "0",
    }.items():
        monkeypatch.setenv(k, v)
    _mock(router)
    monkeypatch.setattr("sys.argv", ["ise-mcp-server", "check", "--json"])
    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 0
    out = capsys.readouterr().out
    assert json.loads(out)["ok"] is True and "s3cret" not in out

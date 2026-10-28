from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
import respx
from fastmcp import FastMCP

from ise_mcp.config import Settings
from ise_mcp.server import create_server

BASE = "https://ise.test"


def make_settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "url": BASE,
        "username": "admin",
        "password": "pw",
        "retries": 0,
        "mcp_cache_dir": "",
    }
    base.update(kw)
    return Settings(_env_file=None, **base)  # type: ignore[call-arg]


def make_server(**kw: Any) -> FastMCP[Any]:
    return create_server(make_settings(**kw))


@pytest.fixture
def mock() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        # Startup status probe; tests that care re-register these routes under the same names.
        router.get("/api/v1/deployment/node", name="nodes").respond(json={"response": []})
        router.get("/ers/config/op/systemconfig/iseversion", name="iseversion").respond(
            json={"OperationResult": {"resultValue": [{"name": "version", "value": "3.5.0.527"}]}}
        )
        router.get("/admin/API/mnt/Version", name="mntversion").respond(
            text=xml("<product><version>3.5.0.527</version></product>")
        )
        yield router


def xml(body: str) -> str:
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + body


def ers_page(resources: list[dict[str, Any]], total: int | None = None) -> dict[str, Any]:
    return {"SearchResult": {"total": len(resources) if total is None else total, "resources": resources}}


FIXTURES = __import__("pathlib").Path(__file__).parent.parent / "fixtures"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text()


def fixture_json(name: str) -> Any:
    import json

    return json.loads(fixture_text(name))


FAILURE_REASONS_XML = xml(
    '<failureReasonList><failureReason id="22040"><code>22040 Wrong password</code><cause>Wrong password'
    "</cause><resolution>Check the user for credentials.</resolution></failureReason>"
    '<failureReason id="22056"><code>22056 Subject not found in the applicable identity store(s)</code>'
    "<cause>Subject not found.</cause><resolution>Check the stores.</resolution></failureReason>"
    '<failureReason id="11036"><code>11036 The Message-Authenticator RADIUS attribute is invalid</code>'
    "<cause>Mismatched Shared Secrets.</cause><resolution>Check the shared secrets.</resolution>"
    "</failureReason></failureReasonList>"
)

MISSING_SESSION = xml(
    "<mnt-rest-result><http-code>500</http-code><cpm-code>34110</cpm-code><internal-error-info>Session data "
    "is not available.</internal-error-info></mnt-rest-result>"
)


def mock_no_policy(mock: respx.MockRouter, *, own_sets: tuple[str, ...] = ()) -> None:
    """Empty policy (no policy sets, global exceptions or library conditions) for the ise_where_used scan
    that ise_delete_object runs. respx replaces a route registered twice, so `own_sets` names the kinds
    whose policy-set list the test mocks itself."""
    for kind in ("network-access", "device-admin"):
        base = f"/api/v1/policy/{kind}"
        if kind not in own_sets:
            mock.get(f"{base}/policy-set").respond(json={"response": []})
        mock.get(f"{base}/policy-set/global-exception").respond(json={"response": []})
        mock.get(f"{base}/condition").respond(json={"response": []})

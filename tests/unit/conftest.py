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
        yield router


def xml(body: str) -> str:
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + body


def ers_page(resources: list[dict[str, Any]], total: int | None = None) -> dict[str, Any]:
    return {"SearchResult": {"total": len(resources) if total is None else total, "resources": resources}}

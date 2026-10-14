from __future__ import annotations

from typing import Any

import pytest
from fastmcp import FastMCP
from stutters_mcp_core.testing import live_settings

from ise_mcp.config import Settings
from ise_mcp.server import create_server


def live_server(**overrides: Any) -> FastMCP[Any]:
    return create_server(live_settings(Settings, "ISE_", **overrides))


@pytest.fixture
def server() -> FastMCP[Any]:
    return live_server()

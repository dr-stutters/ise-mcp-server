import pytest
from fastmcp import FastMCP
from stutters_mcp_core.testing import call_tool

pytestmark = pytest.mark.live


async def test_status_all_surfaces(server: FastMCP) -> None:  # type: ignore[type-arg]
    out = await call_tool(server, "ise_status")
    ise = out["ise"]
    assert ise["version"].startswith("3.")
    for surface in ("openapi", "ers", "mnt"):
        assert ise["surfaces"][surface]["ok"], ise["surfaces"][surface]

"""MCP server for Cisco Identity Services Engine."""

from ise_mcp._core import run_cli
from ise_mcp.config import Settings
from ise_mcp.server import SPEC, create_server


def main() -> None:
    run_cli(SPEC, Settings, create_server)


__all__ = ["SPEC", "Settings", "create_server", "main"]

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastmcp import Client, FastMCP
from stutters_mcp_core.testing import live_settings

from ise_mcp.config import Settings
from ise_mcp.server import create_server


def live_server(**overrides: Any) -> FastMCP[Any]:
    return create_server(live_settings(Settings, "ISE_", **overrides))


@pytest.fixture
def server() -> FastMCP[Any]:
    return live_server()


class Session:
    def __init__(self, client: Client) -> None:  # type: ignore[type-arg]
        self.client = client

    async def call(self, name: str, args: dict[str, Any], *, ok: bool = True) -> Any:
        r = await self.client.call_tool(name, args, raise_on_error=False)
        text = "\n".join(getattr(x, "text", "") for x in r.content)
        if ok:
            assert not r.is_error, f"{name} failed: {text}"
        if r.is_error:
            return {"error": text}
        if r.structured_content is not None:
            return r.structured_content
        try:
            return json.loads(text)
        except ValueError:
            return text

    async def apply(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        preview = await self.call(name, args)
        assert preview["status"] == "preview", preview
        done = await self.call(name, {**args, "confirm": preview["confirm"]})
        assert done["status"] == "applied", done
        return {"preview": preview, "applied": done}


@pytest.fixture
async def ise() -> AsyncIterator[Session]:
    server = live_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(server) as c:
        yield Session(c)

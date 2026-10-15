"""Print the README tool tables (all tiers on): `uv run python scripts/tool_table.py`."""

from __future__ import annotations

import asyncio
import re

from fastmcp import Client

from ise_mcp.config import Settings
from ise_mcp.server import create_server


def first_sentence(text: str) -> str:
    one = " ".join(text.split())
    m = re.match(r"(.+?[.!?])(\s|$)", one)
    out = m.group(1) if m else one
    return out.replace("|", "\\|")


async def main() -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        url="https://ise.invalid",
        username="x",
        password="x",
        mcp_enable_writes=True,
        mcp_enable_dangerous=True,
        mcp_cache_dir="",
    )
    server = create_server(settings)
    tiers = server._stutters_tiers  # type: ignore[attr-defined]
    async with Client(server) as c:
        tools = {t.name: t for t in await c.list_tools()}
        prompts = await c.list_prompts()
    for tier in ("read", "write", "dangerous"):
        names = sorted(n for n, t in tiers.items() if t.value == tier and n in tools)
        untiered = [n for n in tools if n not in tiers]
        names += sorted(n for n in untiered if tier == ("dangerous" if n.endswith("api_call") else "read"))
        print(f"### {tier.capitalize()} ({len(names)})\n\n| Tool | What it does |\n|---|---|")
        for n in names:
            print(f"| `{n}` | {first_sentence(tools[n].description or '')} |")
        print()
    print(f"### Prompts ({len(prompts)})\n\n| Prompt | What it does |\n|---|---|")
    for p in prompts:
        print(f"| `{p.name}` | {first_sentence(p.description or '')} |")


if __name__ == "__main__":
    asyncio.run(main())

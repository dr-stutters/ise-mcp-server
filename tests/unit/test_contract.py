from stutters_mcp_core.testing import assert_tool_contract

from tests.unit.conftest import make_server


async def test_contract_all_tiers() -> None:
    await assert_tool_contract(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True), "ise")


async def test_contract_read_only() -> None:
    await assert_tool_contract(make_server(), "ise")

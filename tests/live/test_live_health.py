"""Live: ise_deployment_health on any deployment returns nodes, a summary and ranked findings."""

from __future__ import annotations

import pytest

from tests.live.conftest import Session

pytestmark = pytest.mark.live


async def test_deployment_health(ise: Session) -> None:
    out = await ise.call("ise_deployment_health", {})
    assert out["nodes"] and out["summary"]
    assert isinstance(out["findings"], list)

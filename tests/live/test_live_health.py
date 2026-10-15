"""Live: ise_deployment_health on the lab ISE 3.5 standalone node (evaluation licence, self-signed
Admin/EAP certificate, no AD join point, no backup)."""

from __future__ import annotations

import json

import pytest

from tests.live.conftest import Session

pytestmark = pytest.mark.live


async def test_deployment_health_lab(ise: Session) -> None:
    out = await ise.call("ise_deployment_health", {})
    text = json.dumps(out["findings"])
    assert out["nodes"] and out["summary"]
    assert "EVALUATION" in text or "out of compliance" in text or out["licence"]
    assert "self-signed" in text
    assert "Active Directory" in text
    assert "patch" in text

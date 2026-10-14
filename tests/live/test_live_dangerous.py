"""Live dangerous-tier tests (the lab is throwaway). CoA goes to the seeded RADIUS client (this host),
which doesn't answer CoA, so the tests accept an unacknowledged CoA."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.live.conftest import Session
from tests.live.test_live_writes import RUN

pytestmark = pytest.mark.live

SEED_MAC = "02:00:5E:00:00:01"


async def seeded_session(ise: Session) -> bool:
    out = await ise.call("ise_find_session", {"mac": SEED_MAC})
    return bool(out.get("found"))


async def test_coa_reauth_and_disconnect(ise: Session) -> None:
    if not await seeded_session(ise):
        pytest.skip("no live session (run scripts/seed_lab.py)")
    res = await ise.apply("ise_coa_reauth", {"mac": SEED_MAC})
    assert isinstance(res["applied"]["result"]["coa_acknowledged"], bool)
    res = await ise.apply("ise_coa_disconnect", {"mac": SEED_MAC})
    assert isinstance(res["applied"]["result"]["coa_acknowledged"], bool)


async def test_coa_blocked_without_session(ise: Session) -> None:
    out = await ise.call("ise_coa_reauth", {"mac": "02:00:5E:FF:FF:FD"})
    assert out["status"] == "blocked"


async def test_anc_apply_and_clear(ise: Session) -> None:
    policy = f"mcp-test-anc-{RUN}"
    mac = "02:00:5E:20:00:01"
    try:
        await ise.apply("ise_create_anc_policy", {"name": policy, "actions": ["REAUTHENTICATE"]})
        await ise.apply("ise_apply_anc", {"mac": mac, "policy": policy})
        listed = await ise.call("ise_list_anc_endpoints", {"mac": mac, "response_format": "json"})
        assert listed["results"][0]["policy"] == policy
        out = await ise.call("ise_endpoint_360", {"mac": mac})
        assert out["anc_policy"] == policy
        await ise.apply("ise_clear_anc", {"mac": mac})
        listed = await ise.call("ise_list_anc_endpoints", {"mac": mac, "response_format": "json"})
        assert listed["results"] == []
    finally:
        await ise.call("ise_clear_anc", {"mac": mac}, ok=False)
        await ise.apply("ise_delete_object", {"kind": "anc_policy", "target": policy})


async def test_policy_set_delete(ise: Session) -> None:
    name = f"mcp-test-ps-{RUN}"
    conds = await ise.call("ise_list_conditions", {"name": "Wired_MAB", "response_format": "json"})
    cond_id = conds["results"][0]["id"]
    body: dict[str, Any] = {
        "name": name,
        "description": "mcp-test",
        "state": "disabled",
        "rank": 0,
        "serviceName": "Default Network Access",
        "default": False,
        "condition": {"conditionType": "ConditionReference", "isNegate": False, "id": cond_id},
    }
    await ise.apply(
        "ise_api_call", {"method": "POST", "path": "/api/v1/policy/network-access/policy-set", "body": body}
    )
    sets = await ise.call("ise_list_policy_sets", {"response_format": "json"})
    assert name in [s["name"] for s in sets["results"]]
    blocked = await ise.call("ise_delete_policy_set", {"policy_set": "Default"})
    assert blocked["status"] == "blocked"
    res = await ise.apply("ise_delete_policy_set", {"policy_set": name})
    assert "authorization" in res["preview"]["preview"]["rules"]
    sets = await ise.call("ise_list_policy_sets", {"response_format": "json"})
    assert name not in [s["name"] for s in sets["results"]]


async def test_trusted_certificate_delete(ise: Session, tmp_path: Path) -> None:
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    await asyncio.to_thread(
        subprocess.run,
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(crt),
            "-days",
            "30",
            "-subj",
            f"/CN=mcp-test-ca-{RUN}",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
        check=True,
        capture_output=True,
    )
    name = f"mcp-test-ca-{RUN}"
    await ise.apply(
        "ise_api_call",
        {
            "method": "POST",
            "path": "/api/v1/certs/trusted-certificate/import",
            "body": {
                "name": name,
                "data": crt.read_text(),
                "trustForIseAuth": True,
                "allowBasicConstraintCAFalse": True,
                "allowOutOfDateCert": False,
                "allowSHA1Certificates": False,
                "validateCertificateExtensions": False,
            },
        },
    )
    certs = await ise.call(
        "ise_list_certificates", {"kind": "trusted", "limit": 500, "response_format": "json"}
    )
    mine = [c for c in certs["results"] if c["name"] == name]
    assert mine, "import failed"
    await ise.apply("ise_delete_certificate", {"cert_id": mine[0]["id"], "kind": "trusted"})
    certs = await ise.call(
        "ise_list_certificates", {"kind": "trusted", "limit": 500, "response_format": "json"}
    )
    assert name not in [c["name"] for c in certs["results"]]

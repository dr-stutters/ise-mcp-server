"""Live (I30): pxGrid client certificate from your CA, a simulated consumer, approval through the tools.

The consumer is simulated by ONE-OFF pxGrid control calls (AccountActivate) from this test with the issued
certificate, the way FMC registers. The server itself never talks to pxGrid (ADR-003). Needs ISE's pxGrid
certificate issued by ISE_LIVE_CA_NAME, that CA's root in ISE_LIVE_CA_PEM, a signer command in
ISE_LIVE_PXGRID_SIGNER (CSR on stdin, signed PEM on stdout; server + client auth EKU) and the client
certificate domain in ISE_LIVE_PXGRID_DOMAIN (see docs/live-tests.md). Auto-approve is switched off for the
test and restored to on afterwards.
"""

from __future__ import annotations

import os
import shlex
import ssl
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.live.conftest import Session, live_env, need_env
from tests.live.test_live_writes import RUN

pytestmark = pytest.mark.live

SIGNER = live_env("ISE_LIVE_PXGRID_SIGNER")
CA_PEM = Path(live_env("ISE_LIVE_CA_PEM") or "/nonexistent").expanduser()


def sign(csr: str) -> str:
    cmd = [os.path.expanduser(p) for p in shlex.split(SIGNER)]
    r = subprocess.run(cmd, input=csr, capture_output=True, text=True, check=False, timeout=300)  # noqa: S603
    if "BEGIN CERTIFICATE" not in r.stdout:
        pytest.skip(f"ISE_LIVE_PXGRID_SIGNER failed: {r.stderr.strip()[-200:]}")
    return r.stdout


def activate(node: dict[str, Any], name: str, cert: Path, key: Path) -> str:
    """One pxGrid AccountActivate as the consumer would send it (cert auth, verified against ISE_LIVE_CA_PEM,
    hostname = the node FQDN)."""
    ctx = ssl.create_default_context(cafile=str(CA_PEM))
    ctx.load_cert_chain(str(cert), str(key))
    with httpx.Client(verify=ctx, timeout=30) as c:
        r = c.post(
            f"https://{node['ip']}:8910/pxgrid/control/AccountActivate",
            json={"description": f"mcp-test {RUN}"},
            auth=(name, ""),
            extensions={"sni_hostname": node["fqdn"]},
        )
    r.raise_for_status()
    return str(r.json()["accountState"])


async def test_pxgrid_client_cert_and_approval(ise: Session, tmp_path: Path) -> None:
    ca = need_env("ISE_LIVE_CA_NAME", "the CA that issued ISE's pxGrid certificate")
    need_env("ISE_LIVE_CA_PEM", "path to that CA's root certificate (PEM)")
    need_env("ISE_LIVE_PXGRID_SIGNER", "command that signs a CSR at that CA")
    domain = need_env("ISE_LIVE_PXGRID_DOMAIN", "DNS domain for the test client certificate CN")
    if not CA_PEM.exists():
        pytest.skip(f"ISE_LIVE_CA_PEM={CA_PEM} does not exist")
    status = await ise.call("ise_pxgrid_status", {})
    if not status["pxgrid_enabled"]:
        pytest.skip("pxGrid persona is off")
    cert_report = status["certificates"][0]
    if cert_report.get("bound", {}).get("root") != ca:
        pytest.skip(f"ISE's pxGrid certificate is not from ISE_LIVE_CA_NAME={ca}")
    assert cert_report["listener"]["hostname_matches_fqdn"], cert_report
    assert cert_report["listener"]["chain_complete"]
    node = next(n for n in status["nodes"] if n["pxgrid"])

    # issue the client certificate through the tool, signed at ISE_LIVE_CA_NAME
    cn = f"mcp-test-pxgrid-{RUN}.{domain}"
    step1 = await ise.apply("ise_issue_pxgrid_client_cert", {"common_name": cn})
    req = step1["applied"]["result"]
    signed = sign(req["csr_pem"])
    args = {"common_name": cn, "request_id": req["request_id"], "certificate_pem": signed}
    step2 = await ise.apply("ise_issue_pxgrid_client_cert", args)
    assert step2["preview"]["preview"]["trusted_in_ise"] == [ca]
    assert "warnings" not in step2["preview"]["preview"], step2["preview"]
    bundle = step2["applied"]["result"]
    key, cert = tmp_path / "client.key", tmp_path / "client.pem"
    key.touch(mode=0o600)
    key.write_text(bundle["private_key_pem"])
    cert.write_text(bundle["certificate_pem"])

    approved, declined = f"mcp-test-pxgrid-{RUN}", f"mcp-test-pxgrid-{RUN}-b"
    await ise.apply(
        "ise_set_pxgrid_settings", {"auto_approve_cert_accounts": False, "allow_password_accounts": True}
    )
    try:
        assert activate(node, approved, cert, key) == "PENDING"
        pending = await ise.call("ise_list_pxgrid_clients", {"state": "pending", "response_format": "json"})
        assert approved in [r["name"] for r in pending["results"]]
        await ise.apply("ise_approve_pxgrid_client", {"name": approved})
        assert activate(node, approved, cert, key) == "ENABLED"
        got = await ise.call("ise_get_pxgrid_client", {"name": approved})
        assert got["state"] == "enabled" and got["description"] == f"mcp-test {RUN}"

        assert activate(node, declined, cert, key) == "PENDING"
        await ise.apply("ise_decline_pxgrid_client", {"name": declined})
        gone = await ise.call("ise_get_pxgrid_client", {"name": declined}, ok=False)
        assert "error" in gone
    finally:
        await ise.apply(
            "ise_set_pxgrid_settings", {"auto_approve_cert_accounts": True, "allow_password_accounts": True}
        )
        for name in (approved, declined):
            listed = await ise.call(
                "ise_list_pxgrid_clients", {"name_contains": name, "response_format": "json"}
            )
            if any(r["name"] == name for r in listed["results"]):
                await ise.apply("ise_delete_pxgrid_client", {"name": name})
    listed = await ise.call("ise_list_pxgrid_clients", {"name_contains": approved, "response_format": "json"})
    assert listed["results"] == []

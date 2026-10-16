"""Live (I30): pxGrid client certificate from the lab CA, a simulated consumer, approval through the tools.

The consumer is simulated by ONE-OFF pxGrid control calls (AccountActivate) from this test with the issued
certificate, the way FMC registers. The server itself never talks to pxGrid (ADR-003). Needs
`lab_policy.py pxgrid` (ISE pxGrid cert from mitchcloud-CA) and the DC signer (LAB_PXGRID_SIGNER, default
~/MCP-Suite/scripts/dc-sign-csr.py --template mcpPxGrid). Auto-approve is switched off for the test and
restored to on (the lab default) afterwards.
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

from tests.live.conftest import Session
from tests.live.test_live_writes import RUN

pytestmark = pytest.mark.live

SIGNER = os.environ.get(
    "LAB_PXGRID_SIGNER",
    "uv run -q --no-project --with pypsrp python ~/MCP-Suite/scripts/dc-sign-csr.py --template mcpPxGrid",
)
CA_PEM = Path("~/MCP-Suite/lab-ca/mitchcloud-CA.pem").expanduser()


def sign(csr: str) -> str:
    cmd = [os.path.expanduser(p) for p in shlex.split(SIGNER)]
    r = subprocess.run(cmd, input=csr, capture_output=True, text=True, check=False, timeout=300)  # noqa: S603
    if "BEGIN CERTIFICATE" not in r.stdout:
        pytest.skip(f"lab CA signer unavailable: {r.stderr.strip()[-200:]}")
    return r.stdout


def activate(node: dict[str, Any], name: str, cert: Path, key: Path) -> str:
    """One pxGrid AccountActivate as the consumer would send it (cert auth, verified against the lab CA,
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
    if not CA_PEM.exists():
        pytest.skip("lab CA root missing (build-dc.py)")
    status = await ise.call("ise_pxgrid_status", {})
    if not status["pxgrid_enabled"]:
        pytest.skip("pxGrid persona is off")
    cert_report = status["certificates"][0]
    if cert_report.get("bound", {}).get("root") != "mitchcloud-CA":
        pytest.skip("ISE's pxGrid certificate is not from mitchcloud-CA (lab_policy.py pxgrid)")
    assert cert_report["listener"]["hostname_matches_fqdn"], cert_report
    assert cert_report["listener"]["chain_complete"]
    node = next(n for n in status["nodes"] if n["pxgrid"])

    # issue the client certificate through the tool, signed at the lab CA
    cn = f"mcp-test-pxgrid-{RUN}.mitchcloud.lab"
    step1 = await ise.apply("ise_issue_pxgrid_client_cert", {"common_name": cn})
    req = step1["applied"]["result"]
    signed = sign(req["csr_pem"])
    args = {"common_name": cn, "request_id": req["request_id"], "certificate_pem": signed}
    step2 = await ise.apply("ise_issue_pxgrid_client_cert", args)
    assert step2["preview"]["preview"]["trusted_in_ise"] == ["mitchcloud-CA"]
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

"""Live: CSR lifecycle and the EAP-TLS identity objects. The EAP certificate check needs ISE_LIVE_CA_NAME
(the trusted CA that issued ISE's EAP certificate; see docs/live-tests.md)."""

from __future__ import annotations

import json

import pytest

from tests.live.conftest import Session, need_env
from tests.live.test_live_writes import RUN

pytestmark = pytest.mark.live


async def test_csr_generate_export_delete(ise: Session) -> None:
    res = await ise.apply("ise_generate_csr", {"usage": "PXGRID", "org_unit": f"mcp-test-{RUN}"})
    csr_id = res["applied"]["result"]["response"][0]["id"]
    try:
        out = await ise.call("ise_export_csr", {"csr": csr_id})
        assert "BEGIN CERTIFICATE REQUEST" in out["csr_pem"]
        listed = await ise.call("ise_list_csrs", {"response_format": "json"})
        assert any(r["id"] == csr_id for r in listed["results"])
    finally:
        await ise.apply("ise_delete_csr", {"csr": csr_id})
    listed = await ise.call("ise_list_csrs", {"response_format": "json"})
    assert not any(r["id"] == csr_id for r in listed["results"])


async def test_cert_profile_and_sequence(ise: Session) -> None:
    prof, seq = f"mcp_test_prof_{RUN}", f"mcp_test_seq_{RUN}"
    try:
        await ise.apply("ise_set_cert_auth_profile", {"name": prof})
        res = await ise.apply(
            "ise_set_cert_auth_profile", {"name": prof, "username_from": "SUBJECT_ALTERNATIVE_NAME_EMAIL"}
        )
        assert "certificateAttributeName" in res["preview"]["preview"]["changes"]
        await ise.apply(
            "ise_set_identity_sequence", {"name": seq, "stores": ["Internal Users"], "cert_profile": prof}
        )
        again = await ise.call(
            "ise_set_identity_sequence", {"name": seq, "stores": ["Internal Users"], "cert_profile": prof}
        )
        assert again["status"] == "blocked"
        sources = await ise.call("ise_list_identity_sources", {"response_format": "json"})
        assert seq in str(sources)
    finally:
        for resource, name in (("idstoresequence", seq), ("certificateprofile", prof)):
            page = await ise.call(
                "ise_api_call",
                {
                    "source": "ers",
                    "method": "GET",
                    "path": f"/ers/config/{resource}",
                },
            )
            if isinstance(page, dict) and isinstance(page.get("result"), str):
                page = json.loads(page["result"])
            for item in page.get("SearchResult", {}).get("resources", []):
                if item.get("name") != name:
                    continue
                await ise.apply(
                    "ise_api_call",
                    {"source": "ers", "method": "DELETE", "path": f"/ers/config/{resource}/{item['id']}"},
                )


async def test_eap_cert_from_ca(ise: Session) -> None:
    """ISE trusts ISE_LIVE_CA_NAME and its EAP certificate is issued by it."""
    ca = need_env("ISE_LIVE_CA_NAME", "the trusted CA that issued ISE's EAP certificate")
    certs = await ise.call("ise_list_certificates", {"response_format": "json", "limit": 500})
    trusted = await ise.call(
        "ise_list_certificates", {"kind": "trusted", "response_format": "json", "limit": 500}
    )
    if not any(r.get("name") == ca for r in trusted["results"]):
        pytest.skip(f"ISE_LIVE_CA_NAME={ca} is not a trusted certificate on this ISE")
    eap = [r for r in certs["results"] if "EAP Authentication" in str(r.get("used_by"))]
    assert eap and eap[0]["issued_by"] == ca
    blocked = await ise.call(
        "ise_delete_certificate",
        {
            "cert_id": next(r["id"] for r in trusted["results"] if r["name"] == ca),
            "kind": "trusted",
        },
    )
    assert blocked["status"] == "blocked"

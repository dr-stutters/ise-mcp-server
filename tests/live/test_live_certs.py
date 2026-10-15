"""Live: CSR lifecycle and the EAP-TLS identity objects on the lab ISE. The full chain (CSR -> lab CA on
CML dc1 -> bind for EAP -> EAP-TLS PASS / 12514 on the ise-access client) was run by hand; see the notes."""

from __future__ import annotations

import json

import pytest

from tests.live.conftest import Session
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

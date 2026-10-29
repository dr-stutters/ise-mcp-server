from __future__ import annotations

import base64
import json

import pytest
import respx
from fastmcp import Client

from ise_mcp._core import InvalidRequest
from ise_mcp.tools.certs import pem_certs
from tests.unit.conftest import BASE, ers_page, make_server
from tests.unit.test_writes import two_step

B64 = base64.b64encode(b"x" * 90).decode()
PEM = f"-----BEGIN CERTIFICATE-----\n{B64[:64]}\n{B64[64:]}\n-----END CERTIFICATE-----\n"
NODES = {"response": [{"hostname": "ise", "ipAddress": "10.0.0.5", "services": ["Session"]}]}
CSR = {
    "id": "csr1",
    "hostName": "ise",
    "friendlyName": "ise#EAP Authentication",
    "usedFor": "EAP Authentication",
}


def test_pem_certs() -> None:
    assert pem_certs("junk\n" + PEM + PEM) == [PEM.strip(), PEM.strip()]
    with pytest.raises(InvalidRequest):
        pem_certs("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n" + PEM)
    with pytest.raises(InvalidRequest):
        pem_certs("no cert here")


async def test_generate_csr_body(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    post = mock.post("/api/v1/certs/certificate-signing-request").respond(
        json={"response": [{"id": "csr1", "message": "ok"}]}
    )
    preview, applied = await two_step(
        "ise_generate_csr", {"usage": "EAP-AUTH", "san_dns": ["ise.lab"], "organization": "Lab"}
    )
    assert preview["action"] == "Generate EAP-AUTH CSR for ise"
    body = json.loads(post.calls.last.request.content)
    assert body["hostnames"] == ["ise"] and body["subjectCommonName"] == "$FQDN$"
    assert body["sanDNS"] == ["ise.lab"] and body["keyLength"] == "2048"
    assert applied["status"] == "applied"


async def test_generate_csr_rejects_bad_key(mock: respx.MockRouter) -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool(
            "ise_generate_csr", {"usage": "EAP-AUTH", "key_length": "256"}, raise_on_error=False
        )
    assert r.is_error


async def test_generate_csr_int_key_length_same_preview(mock: respx.MockRouter) -> None:
    """#190: key_length=2048 as an int gives the same preview (and body) as '2048'."""
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    post = mock.post("/api/v1/certs/certificate-signing-request").respond(
        json={"response": [{"id": "csr1", "message": "ok"}]}
    )
    async with Client(make_server(mcp_enable_writes=True)) as c:
        as_int = await c.call_tool("ise_generate_csr", {"usage": "EAP-AUTH", "key_length": 2048})
        as_str = await c.call_tool("ise_generate_csr", {"usage": "EAP-AUTH", "key_length": "2048"})
        ecdsa = await c.call_tool(
            "ise_generate_csr", {"usage": "EAP-AUTH", "key_type": "ECDSA", "key_length": 384}
        )
        a, b = as_int.structured_content, as_str.structured_content
        assert a is not None and b is not None and ecdsa.structured_content is not None
        assert a["action"] == b["action"] and a["preview"] == b["preview"]
        assert a["preview"]["keyLength"] == "2048"
        assert ecdsa.structured_content["preview"]["keyLength"] == "384"
        # The int call's token confirms the string form: both normalise to the same arguments.
        applied = await c.call_tool(
            "ise_generate_csr", {"usage": "EAP-AUTH", "key_length": "2048", "confirm": a["confirm"]}
        )
    assert applied.structured_content is not None and applied.structured_content["status"] == "applied"
    assert json.loads(post.calls.last.request.content)["keyLength"] == "2048"


@pytest.mark.parametrize(
    "args",
    [
        {"key_length": 1024},  # not a size ISE offers
        {"key_length": 256},  # an ECDSA size for an RSA key
        {"key_type": "ECDSA", "key_length": 4096},
    ],
)
async def test_generate_csr_refuses_bad_int_key(mock: respx.MockRouter, args: dict[str, object]) -> None:
    post = mock.post("/api/v1/certs/certificate-signing-request").respond(json={"response": []})
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool("ise_generate_csr", {"usage": "EAP-AUTH", **args}, raise_on_error=False)
    assert r.is_error and not post.called


async def test_system_cert_row_has_key_and_signature(mock: respx.MockRouter) -> None:
    """#190: the system row carries what a renewal copies (key size, signature algorithm, validity)."""
    mock.get("/api/v1/certs/system-certificate/ise").respond(
        json={
            "response": [
                {
                    "id": "c1",
                    "friendlyName": "ise EAP",
                    "usedBy": "EAP Authentication",
                    "issuedTo": "ise.example.com",
                    "issuedBy": "Example Root CA",
                    "expirationDate": "Thu Jan 01 00:00:00 UTC 2099",
                    "validFrom": "Mon Oct 26 00:00:00 UTC 2026",
                    "keySize": 2048,
                    "signatureAlgorithm": "SHA256withRSA",
                    "selfSigned": False,
                    "sha256Fingerprint": "ab:cd",
                }
            ]
        }
    )
    async with Client(make_server()) as c:
        r = await c.call_tool(
            "ise_list_certificates", {"kind": "system", "node": "ise", "response_format": "json"}
        )
    row = json.loads(r.content[0].text)["results"][0]  # type: ignore[union-attr]
    assert row["key_size"] == 2048 and row["signature_algorithm"] == "SHA256withRSA"
    assert row["valid_from"] == "Mon Oct 26 00:00:00 UTC 2026" and row["self_signed"] is False
    assert row["issued_to"] == "ise.example.com" and row["days_left"] > 0


async def test_export_csr(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    mock.get("/api/v1/certs/certificate-signing-request").respond(json={"response": [CSR]})
    mock.get("/api/v1/certs/certificate-signing-request/export/ise/csr1").respond(
        text="-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----\n"
    )
    async with Client(make_server()) as c:
        r = await c.call_tool("ise_export_csr", {"csr": "ise#EAP Authentication"})
    out = r.structured_content
    assert out is not None and out["id"] == "csr1"
    assert out["csr_pem"].startswith("-----BEGIN CERTIFICATE REQUEST-----")


async def test_bind_certificate_eap(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    mock.get("/api/v1/certs/certificate-signing-request").respond(json={"response": [CSR]})
    mock.get("/api/v1/certs/system-certificate/ise").respond(
        json={"response": [{"friendlyName": "Default self-signed", "usedBy": "EAP Authentication, Admin"}]}
    )
    bind = mock.post("/api/v1/certs/signed-certificate/bind").respond(
        json={"response": {"status": "Success"}}
    )
    args = {"csr": "csr1", "certificate_pem": PEM, "use_for": ["eap"]}
    preview, applied = await two_step("ise_bind_certificate", args, mcp_enable_dangerous=True)
    assert "EAP Authentication moves off: Default self-signed" in preview["side_effects"]
    assert not any("restarts" in s for s in preview["side_effects"])
    assert "data" not in preview["preview"]
    body = json.loads(bind.calls.last.request.content)
    assert body["eap"] is True and "admin" not in body and body["id"] == "csr1"
    assert applied["status"] == "applied"


async def test_bind_admin_warns_restart(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    mock.get("/api/v1/certs/certificate-signing-request").respond(json={"response": [CSR]})
    mock.get("/api/v1/certs/system-certificate/ise").respond(json={"response": []})
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        r = await c.call_tool(
            "ise_bind_certificate", {"csr": "csr1", "certificate_pem": PEM, "use_for": ["admin"]}
        )
    out = r.structured_content
    assert out is not None and "restarts the application server" in out["side_effects"][0]


async def test_import_trusted_cert(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/certs/trusted-certificate").respond(json={"response": []})
    post = mock.post("/api/v1/certs/trusted-certificate/import").respond(json={"response": {"id": "t1"}})
    preview, applied = await two_step(
        "ise_import_trusted_cert",
        {"name": "lab-ca", "certificate_pem": PEM, "trust_for": ["client_auth", "ise_auth"]},
    )
    assert "data" not in preview["preview"]
    body = json.loads(post.calls.last.request.content)
    assert body["trustForClientAuth"] is True and body["trustForIseAuth"] is True
    assert "trustForCertificateBasedAdminAuth" not in body
    assert applied["status"] == "applied"


async def test_import_trusted_cert_client_auth_needs_ise_auth(mock: respx.MockRouter) -> None:
    """ISE answers 417 to client_auth without ise_auth (#169): blocked in the preview, nothing sent."""
    mock.get("/api/v1/certs/trusted-certificate").respond(json={"response": []})
    post = mock.post("/api/v1/certs/trusted-certificate/import").respond(json={"response": {"id": "t1"}})
    preview, applied = await two_step(
        "ise_import_trusted_cert", {"name": "lab-ca", "certificate_pem": PEM, "trust_for": ["client_auth"]}
    )
    assert preview["status"] == "blocked"
    assert any("ise_auth" in b and "417" in b for b in preview["blockers"])
    assert applied is None and not post.called


async def test_import_trusted_cert_refuses_unsafe_description(mock: respx.MockRouter) -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool(
            "ise_import_trusted_cert",
            {"name": "lab-ca", "certificate_pem": PEM, "description": "Lab CA (dc1)"},
            raise_on_error=False,
        )
    assert r.is_error


async def test_cert_profile_create_and_name_check(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/certificateprofile", params={"filter": "name.EQ.lab_prof"}).respond(
        json=ers_page([])
    )
    post = mock.post("/ers/config/certificateprofile").respond(
        201, headers={"Location": f"{BASE}/ers/config/certificateprofile/p1"}
    )
    _, applied = await two_step("ise_set_cert_auth_profile", {"name": "lab_prof"})
    body = json.loads(post.calls.last.request.content)["CertificateProfile"]
    assert body["certificateAttributeName"] == "SUBJECT_COMMON_NAME"
    assert body["externalIdentityStoreName"] == "[not applicable]"
    assert applied["result"]["id"] == "p1"
    async with Client(make_server(mcp_enable_writes=True)) as c:
        r = await c.call_tool("ise_set_cert_auth_profile", {"name": "lab-prof"}, raise_on_error=False)
    assert r.is_error


async def test_identity_sequence_blocked_without_profile(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/certificateprofile", params={"filter": "name.EQ.nope"}).respond(json=ers_page([]))
    mock.get("/ers/config/idstoresequence", params={"filter": "name.EQ.lab_seq"}).respond(json=ers_page([]))
    preview, _ = await two_step(
        "ise_set_identity_sequence", {"name": "lab_seq", "stores": ["Internal Users"], "cert_profile": "nope"}
    )
    assert preview["status"] == "blocked"


async def test_identity_sequence_create(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/certificateprofile", params={"filter": "name.EQ.lab_prof"}).respond(
        json=ers_page([{"id": "p1", "name": "lab_prof"}])
    )
    mock.get("/ers/config/idstoresequence", params={"filter": "name.EQ.lab_seq"}).respond(json=ers_page([]))
    post = mock.post("/ers/config/idstoresequence").respond(
        201, headers={"Location": f"{BASE}/ers/config/idstoresequence/s1"}
    )
    await two_step(
        "ise_set_identity_sequence",
        {"name": "lab_seq", "stores": ["Internal Users", "Guest Users"], "cert_profile": "lab_prof"},
    )
    body = json.loads(post.calls.last.request.content)["IdStoreSequence"]
    assert body["idSeqItem"] == [
        {"idstore": "Internal Users", "order": 1},
        {"idstore": "Guest Users", "order": 2},
    ]
    assert body["certificateAuthenticationProfile"] == "lab_prof"

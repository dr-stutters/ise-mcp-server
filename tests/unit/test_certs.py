from __future__ import annotations

import base64
import json

import pytest
import respx
from fastmcp import Client
from stutters_mcp_core import InvalidRequest

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
        "ise_import_trusted_cert", {"name": "lab-ca", "certificate_pem": PEM, "trust_for": ["client_auth"]}
    )
    assert "data" not in preview["preview"]
    body = json.loads(post.calls.last.request.content)
    assert body["trustForClientAuth"] is True and "trustForIseAuth" not in body
    assert applied["status"] == "applied"


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

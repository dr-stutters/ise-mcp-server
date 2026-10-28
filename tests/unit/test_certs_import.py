"""I58: ise_import_system_certificate (files from ISE_CERT_DIR) and ise_set_trusted_cert (trust usages,
CRL/OCSP). Certificates are synthetic, generated per test with documentation names (example.com)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from fastmcp import Client

from ise_mcp.tools.certs import trust_settings
from tests.unit.conftest import make_server

NODES = {
    "response": [{"hostname": "ise", "fqdn": "ise.test", "ipAddress": "192.0.2.5", "roles": ["Standalone"]}]
}
TRUST_PATH = "/api/v1/certs/trusted-certificate"
PW = "unit-test-pass"


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca() -> tuple[Any, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Example Lab CA"))
        .issuer_name(_name("Example Lab CA"))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(
    ca: tuple[Any, x509.Certificate], cn: str = "portal.example.com", sans: list[str] | None = None
) -> tuple[Any, x509.Certificate]:
    ca_key, ca_cert = ca
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans or [cn]]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def write_pem(dirpath: Path, key: Any, cert: x509.Certificate, *, password: str | None = PW) -> None:
    enc = (
        serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    )
    (dirpath / "leaf.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (dirpath / "leaf.key").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    )


def route_import(
    mock: respx.MockRouter,
    *,
    trusted: list[dict[str, Any]] | None = None,
    system: list[dict[str, Any]] | None = None,
) -> respx.Route:
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    mock.get("/api/v1/certs/system-certificate/ise").respond(json={"response": system or []})
    mock.get(TRUST_PATH).respond(
        json={"response": trusted if trusted is not None else [{"id": "t1", "issuedTo": "Example Lab CA"}]}
    )
    return mock.post("/api/v1/certs/system-certificate/import").respond(json={"response": {"id": "new"}})


async def call(name: str, args: dict[str, Any], tmp_path: Path, *, confirm: bool = True) -> tuple[Any, Any]:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True, cert_dir=str(tmp_path))
    async with Client(server) as c:
        r1 = await c.call_tool(name, args, raise_on_error=False)
        if r1.is_error:
            return r1, None
        preview = r1.structured_content
        if not confirm or preview is None or preview.get("status") != "preview":
            return preview, None
        r2 = await c.call_tool(name, {**args, "confirm": preview["confirm"]})
        return preview, r2.structured_content


@pytest.fixture
def cert_pw(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("ISE_CERT_PORTAL", PW)
    return "ISE_CERT_PORTAL"


# --- ise_import_system_certificate ---------------------------------------------------------------


async def test_import_pem_portal(mock: respx.MockRouter, tmp_path: Path, cert_pw: str) -> None:
    key, leaf = make_leaf(make_ca())
    write_pem(tmp_path, key, leaf)
    post = route_import(
        mock, system=[{"id": "s1", "friendlyName": "Default self-signed", "usedBy": "Admin, Portal"}]
    )
    args = {"usages": ["portal"], "cert_file": "leaf.pem", "key_file": "leaf.key", "password_env": cert_pw}
    preview, applied = await call("ise_import_system_certificate", args, tmp_path)
    assert preview["status"] == "preview", preview
    shown = preview["preview"]
    assert "data" not in shown and "privateKeyData" not in shown and PW not in json.dumps(preview)
    assert shown["certificate"]["dns_names"] == ["portal.example.com", "portal.example.com"]
    assert "Portal moves off: Default self-signed" in preview["side_effects"]
    assert not any("restarts" in s for s in preview["side_effects"])
    body = json.loads(post.calls.last.request.content)
    assert body["portal"] is True and "admin" not in body and "eap" not in body
    assert body["portalGroupTag"] == "Default Portal Certificate Group"
    assert body["password"] == PW and "BEGIN ENCRYPTED PRIVATE KEY" in body["privateKeyData"]
    assert body["data"].startswith("-----BEGIN CERTIFICATE-----")
    assert body["allowWildCardCertificates"] is False and body["allowSHA1Certificates"] is False
    # The key ISE gets opens with the password it gets, and matches the certificate.
    sent = serialization.load_pem_private_key(body["privateKeyData"].encode(), PW.encode())
    assert sent.public_key() == key.public_key()
    assert applied["status"] == "applied"


async def test_import_plain_key_gets_one_time_password(mock: respx.MockRouter, tmp_path: Path) -> None:
    key, leaf = make_leaf(make_ca())
    write_pem(tmp_path, key, leaf, password=None)
    post = route_import(mock)
    args = {"usages": ["eap"], "cert_file": "leaf.pem", "key_file": "leaf.key"}
    preview, applied = await call("ise_import_system_certificate", args, tmp_path)
    assert preview["status"] == "preview", preview
    body = json.loads(post.calls.last.request.content)
    assert body["eap"] is True and len(body["password"]) >= 24
    serialization.load_pem_private_key(body["privateKeyData"].encode(), body["password"].encode())
    assert applied["status"] == "applied"


async def test_import_pkcs12(mock: respx.MockRouter, tmp_path: Path, cert_pw: str) -> None:
    ca = make_ca()
    key, leaf = make_leaf(ca)
    blob = pkcs12.serialize_key_and_certificates(
        b"portal", key, leaf, [ca[1]], serialization.BestAvailableEncryption(PW.encode())
    )
    (tmp_path / "portal.p12").write_bytes(blob)
    post = route_import(mock)
    args = {"usages": ["portal"], "pkcs12_file": "portal.p12", "password_env": cert_pw, "name": "mcp-portal"}
    preview, applied = await call("ise_import_system_certificate", args, tmp_path)
    assert preview["status"] == "preview", preview
    assert any("1 chain certificate" in s for s in preview["side_effects"])
    body = json.loads(post.calls.last.request.content)
    assert body["name"] == "mcp-portal"
    assert x509.load_pem_x509_certificate(body["data"].encode()) == leaf
    assert applied["status"] == "applied"


async def test_import_admin_warns_restart(mock: respx.MockRouter, tmp_path: Path, cert_pw: str) -> None:
    key, leaf = make_leaf(make_ca())
    write_pem(tmp_path, key, leaf)
    route_import(mock)
    args = {"usages": ["admin"], "cert_file": "leaf.pem", "key_file": "leaf.key", "password_env": cert_pw}
    preview, _ = await call("ise_import_system_certificate", args, tmp_path, confirm=False)
    assert "restarts the application server on ise" in preview["side_effects"][0]


async def test_import_blockers(mock: respx.MockRouter, tmp_path: Path, cert_pw: str) -> None:
    other_key = ec.generate_private_key(ec.SECP256R1())
    _, leaf = make_leaf(make_ca(), cn="*.example.com")
    write_pem(tmp_path, other_key, leaf)  # a key that is not the certificate's
    post = route_import(mock, trusted=[])
    args = {"usages": ["portal"], "cert_file": "leaf.pem", "key_file": "leaf.key", "password_env": cert_pw}
    preview, _ = await call("ise_import_system_certificate", args, tmp_path)
    assert preview["status"] == "blocked"
    text = " ".join(preview["blockers"])
    assert "does not belong to the certificate" in text
    assert "allow_wildcard=true" in text
    assert "not in ISE's trusted store" in text
    assert not post.called


async def test_import_wildcard_allowed(mock: respx.MockRouter, tmp_path: Path, cert_pw: str) -> None:
    key, leaf = make_leaf(make_ca(), cn="portal.example.com", sans=["portal.example.com", "*.example.com"])
    write_pem(tmp_path, key, leaf)
    post = route_import(mock)
    args = {
        "usages": ["portal", "eap"],
        "cert_file": "leaf.pem",
        "key_file": "leaf.key",
        "password_env": cert_pw,
        "allow_wildcard": True,
    }
    preview, applied = await call("ise_import_system_certificate", args, tmp_path)
    assert preview["status"] == "preview", preview
    assert any("wildcard server certificate" in s for s in preview["side_effects"])
    assert json.loads(post.calls.last.request.content)["allowWildCardCertificates"] is True
    assert applied["status"] == "applied"


@pytest.mark.parametrize(
    ("cert_file", "message"),
    [
        ("../outside.pem", "outside ISE_CERT_DIR"),
        ("/etc/passwd.pem", "outside ISE_CERT_DIR"),
        ("leaf.txt", "expected a"),
        ("missing.pem", "is not a file"),
    ],
)
async def test_import_file_guard(
    mock: respx.MockRouter, tmp_path: Path, cert_pw: str, cert_file: str, message: str
) -> None:
    certs = tmp_path / "certs"
    certs.mkdir()
    key, leaf = make_leaf(make_ca())
    write_pem(certs, key, leaf)
    write_pem(tmp_path, key, leaf)
    (tmp_path / "outside.pem").write_bytes((tmp_path / "leaf.pem").read_bytes())
    post = route_import(mock)
    args = {"usages": ["portal"], "cert_file": cert_file, "key_file": "leaf.key", "password_env": cert_pw}
    result, _ = await call("ise_import_system_certificate", args, certs)
    assert result.is_error and message in str(result.content)
    assert not post.called


async def test_import_needs_cert_dir(mock: respx.MockRouter) -> None:
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        r = await c.call_tool(
            "ise_import_system_certificate",
            {"usages": ["portal"], "cert_file": "/tmp/leaf.pem", "key_file": "/tmp/leaf.key"},
            raise_on_error=False,
        )
    assert r.is_error and "ISE_CERT_DIR" in str(r.content)


async def test_import_password_env_must_be_cert_var(mock: respx.MockRouter, tmp_path: Path) -> None:
    args = {"usages": ["portal"], "pkcs12_file": "x.p12", "password_env": "ISE_PASSWORD"}
    result, _ = await call("ise_import_system_certificate", args, tmp_path)
    assert result.is_error and "ISE_CERT_" in str(result.content)


async def test_import_is_dangerous_tier(mock: respx.MockRouter) -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:
        names = {t.name for t in await c.list_tools()}
    assert "ise_import_system_certificate" not in names and "ise_set_trusted_cert" in names


# --- ise_set_trusted_cert ------------------------------------------------------------------------

LAB_CA = {
    "id": "t1",
    "friendlyName": "Example-Lab-CA",
    "issuedTo": "Example Lab CA",
    "issuedBy": "Example Lab CA",
    "description": "",
    "status": "Enabled",
    "trustedFor": "Infrastructure,Endpoints",
    "downloadCRL": "off",
    "crlDistributionUrl": None,
    "automaticCRLUpdate": "on",
    "automaticCRLUpdatePeriod": "5",
    "automaticCRLUpdateUnits": "Minutes",
    "nonAutomaticCRLUpdatePeriod": "1",
    "nonAutomaticCRLUpdateUnits": "Hours",
    "crlDownloadFailureRetries": "10",
    "crlDownloadFailureRetriesUnits": "Minutes",
    "authenticateBeforeCRLReceived": "off",
    "ignoreCRLExpiration": "off",
    "enableServerIdentityCheck": "off",
    "enableOCSPValidation": "off",
    "selectedOCSPService": "",
    "rejectIfNoStatusFromOCSP": "off",
    "rejectIfUnreachableFromOCSP": "off",
    "isReferredInPolicy": False,
}


def route_trust(
    mock: respx.MockRouter, ca: dict[str, Any] | None = None, system: list[dict[str, Any]] | None = None
) -> respx.Route:
    ca = ca or LAB_CA
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    mock.get(TRUST_PATH).respond(json={"response": [ca]})
    mock.get(f"{TRUST_PATH}/t1").respond(json={"response": ca, "version": "1.0.1"})
    mock.get("/api/v1/certs/system-certificate/ise").respond(json={"response": system or []})
    return mock.put(f"{TRUST_PATH}/t1").respond(json={"response": {"id": "t1", "message": "ok"}})


def test_trust_settings_parses_get() -> None:
    body, unknown = trust_settings(LAB_CA)
    assert body["trustForIseAuth"] and body["trustForClientAuth"] and not body["trustForCiscoServicesAuth"]
    assert body["automaticCRLUpdate"] is True and body["downloadCRL"] is False
    assert body["automaticCRLUpdatePeriod"] == 5 and unknown == []


async def test_set_trusted_cert_crl_preview(mock: respx.MockRouter, tmp_path: Path) -> None:
    put = route_trust(mock)
    args = {
        "cert": "Example-Lab-CA",
        "crl_download": True,
        "crl_url": "http://pki.example.com/lab.crl",
        "crl_auto_update": False,
        "crl_update_period": 2,
        "crl_update_units": "Hours",
    }
    preview, applied = await call("ise_set_trusted_cert", args, tmp_path)
    assert preview["status"] == "preview", preview
    changes = preview["preview"]["changes"]
    assert changes["downloadCRL"] == {"from": False, "to": True}
    assert changes["crlDistributionUrl"]["to"] == "http://pki.example.com/lab.crl"
    assert changes["automaticCRLUpdate"] == {"from": True, "to": False}
    assert changes["nonAutomaticCRLUpdatePeriod"] == {"from": 1, "to": 2}
    assert "automaticCRLUpdatePeriod" not in changes
    assert any("rejected until ISE has downloaded the first CRL" in s for s in preview["side_effects"])
    body = json.loads(put.calls.last.request.content)
    assert body["name"] == "Example-Lab-CA" and body["downloadCRL"] is True
    assert body["trustForClientAuth"] is True and body["trustForIseAuth"] is True
    assert body["status"] == "Enabled" and body["crlDownloadFailureRetries"] == 10
    assert applied["status"] == "applied"


async def test_set_trusted_cert_trust_for_and_ocsp(mock: respx.MockRouter, tmp_path: Path) -> None:
    put = route_trust(mock)
    args = {
        "cert": "t1",
        "trust_for": ["client_auth"],
        "ocsp_service": "lab-ocsp",
        "ocsp_reject_unreachable": True,
    }
    preview, _ = await call("ise_set_trusted_cert", args, tmp_path)
    assert preview["status"] == "preview", preview
    changes = preview["preview"]["changes"]
    assert changes["trustForIseAuth"] == {"from": True, "to": False}
    assert changes["enableOCSPValidation"]["to"] is True
    body = json.loads(put.calls.last.request.content)
    assert body["selectedOCSPService"] == "lab-ocsp" and body["rejectIfUnreachableFromOCSP"] is True


async def test_set_trusted_cert_no_change(mock: respx.MockRouter, tmp_path: Path) -> None:
    put = route_trust(mock)
    args = {"cert": "Example-Lab-CA", "trust_for": ["ise_auth", "client_auth"], "status": "enabled"}
    preview, applied = await call("ise_set_trusted_cert", args, tmp_path)
    assert preview["status"] == "no_change" and "confirm" not in preview and applied is None
    assert not put.called


async def test_set_trusted_cert_blocks_disabling_in_use_ca(mock: respx.MockRouter, tmp_path: Path) -> None:
    put = route_trust(
        mock,
        system=[
            {"friendlyName": "mcp-eap", "usedBy": "EAP Authentication", "issuedBy": "Example Lab CA"},
            {"friendlyName": "self", "usedBy": "Admin, Portal", "issuedBy": "ise.test"},
        ],
    )
    preview, _ = await call(
        "ise_set_trusted_cert", {"cert": "Example-Lab-CA", "status": "disabled"}, tmp_path
    )
    assert preview["status"] == "blocked"
    assert any("ise EAP Authentication certificate mcp-eap" in b for b in preview["blockers"])
    assert not put.called


async def test_set_trusted_cert_crl_needs_url(mock: respx.MockRouter, tmp_path: Path) -> None:
    route_trust(mock)
    preview, _ = await call(
        "ise_set_trusted_cert", {"cert": "Example-Lab-CA", "crl_download": True}, tmp_path
    )
    assert preview["status"] == "blocked" and any("crl_url" in b for b in preview["blockers"])


async def test_set_trusted_cert_unknown_usage_needs_trust_for(mock: respx.MockRouter, tmp_path: Path) -> None:
    route_trust(mock, ca={**LAB_CA, "trustedFor": "Infrastructure,Something New"})
    preview, _ = await call(
        "ise_set_trusted_cert", {"cert": "Example-Lab-CA", "crl_download": False}, tmp_path
    )
    assert preview["status"] == "blocked"
    assert any("Something New" in b for b in preview["blockers"])


async def test_set_trusted_cert_rejects_bad_url(mock: respx.MockRouter, tmp_path: Path) -> None:
    result, _ = await call(
        "ise_set_trusted_cert", {"cert": "Example-Lab-CA", "crl_url": "ldap://dc/crl"}, tmp_path
    )
    assert result.is_error

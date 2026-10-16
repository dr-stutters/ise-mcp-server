"""I30: pxGrid clients, settings, status (certificate chain + hostname) and client-certificate issuance."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastmcp import Client

from ise_mcp.tools import pxgrid
from tests.unit.conftest import ers_page, make_server
from tests.unit.test_writes import two_step

NODES = {
    "response": [
        {
            "hostname": "ise",
            "fqdn": "ise.corp.lab",
            "ipAddress": "10.0.0.5",
            "services": ["Session", "pxGrid"],
            "nodeStatus": "Connected",
        }
    ]
}
NOW = dt.datetime.now(dt.UTC)


def ca(cn: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issue(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    public_key: Any,
    cn: str,
    *,
    sans: list[str] | None = None,
    ekus: list[x509.ObjectIdentifier] | None = None,
) -> x509.Certificate:
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=700))
    )
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    b = b.add_extension(
        x509.ExtendedKeyUsage(
            ekus if ekus is not None else [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
        ),
        critical=False,
    )
    return b.sign(ca_key, hashes.SHA256())


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


ROOT_KEY, ROOT = ca("corp-CA")
OTHER_KEY, OTHER = ca("other-CA")
SERVER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SERVER = issue(ROOT_KEY, ROOT, SERVER_KEY.public_key(), "ise.corp.lab", sans=["ise.corp.lab"])
TRUSTED = [
    {
        "id": "t-corp",
        "friendlyName": "corp-CA",
        "subject": "CN=corp-CA",
        "issuedTo": "corp-CA",
        "issuedBy": "corp-CA",
        "trustedFor": "Infrastructure,Endpoints",
        "status": "Enabled",
    }
]
SYSTEM = [
    {
        "id": "s-px",
        "friendlyName": "mcp-pxgrid",
        "usedBy": "pxGrid",
        "issuedTo": "ise.corp.lab",
        "issuedBy": "corp-CA",
        "expirationDate": "Sun Oct 15 01:44:01 UTC 2028",
        "sha256Fingerprint": SERVER.fingerprint(hashes.SHA256()).hex(),
    }
]


def mock_certs(mock: respx.MockRouter, *, trusted: list[dict[str, Any]] | None = None) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    mock.get("/api/v1/certs/trusted-certificate").respond(
        json={"response": TRUSTED if trusted is None else trusted}
    )
    mock.get("/api/v1/certs/trusted-certificate/export/t-corp").respond(text=pem(ROOT))
    mock.get("/api/v1/certs/system-certificate/ise").respond(json={"response": SYSTEM})


CLIENTS = {
    "fmc": {"id": "iseagent-fmc-1@xgrid.cisco.com", "name": "iseagent-fmc-1", "status": "pendingApproval"},
    "catc": {
        "id": "pxgrid_client_1@xgrid.cisco.com",
        "name": "pxgrid_client_1",
        "description": "Cisco DNA Center ise-bridge service",
        "status": "enabled",
    },
}


def mock_clients(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/pxgridnode").respond(
        json=ers_page([{"id": c["id"], "name": c["name"]} for c in CLIENTS.values()])
    )
    for c in CLIENTS.values():
        mock.get(f"/ers/config/pxgridnode/{c['id']}").respond(json={"PxgridNode": c})
        mock.get(f"/ers/config/pxgridnode/name/{c['name']}").respond(json={"PxgridNode": c})


async def call(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(make_server(**settings)) as c:
        r = await c.call_tool(name, args, raise_on_error=False)
    return r


async def test_list_clients_states_and_consumers(mock: respx.MockRouter) -> None:
    mock_clients(mock)
    r = await call("ise_list_pxgrid_clients", {"response_format": "json"})
    rows = r.structured_content["results"]
    assert [x["name"] for x in rows] == ["iseagent-fmc-1", "pxgrid_client_1"]  # pending first
    assert rows[0]["state"] == "pending" and "FMC" in rows[0]["consumer"]
    assert rows[1]["consumer"] == "Catalyst Center"
    r = await call("ise_list_pxgrid_clients", {"state": "enabled", "response_format": "json"})
    assert [x["name"] for x in r.structured_content["results"]] == ["pxgrid_client_1"]


async def test_get_client_not_found_names_candidates(mock: respx.MockRouter) -> None:
    mock_clients(mock)
    mock.get("/ers/config/pxgridnode/name/iseagent").respond(404, json={})
    r = await call("ise_get_pxgrid_client", {"name": "iseagent"})
    assert r.is_error and "iseagent-fmc-1" in r.content[0].text
    r = await call("ise_get_pxgrid_client", {"name": "iseagent-fmc-1@xgrid.cisco.com"})
    assert r.structured_content["next"].startswith("Waiting for approval")


async def test_approve_pending_client(mock: respx.MockRouter) -> None:
    mock_clients(mock)
    put = mock.put("/ers/config/pxgridnode/name/iseagent-fmc-1/approve").respond(204)
    preview, applied = await two_step("ise_approve_pxgrid_client", {"name": "iseagent-fmc-1"})
    assert preview["action"] == "Approve pxGrid client iseagent-fmc-1"
    assert applied["status"] == "applied" and put.called


async def test_approve_blocked_when_enabled(mock: respx.MockRouter) -> None:
    mock_clients(mock)
    preview, _ = await two_step("ise_approve_pxgrid_client", {"name": "pxgrid_client_1"})
    assert preview["status"] == "blocked" and "already approved" in preview["blockers"][0]


async def test_decline_only_pending_and_delete(mock: respx.MockRouter) -> None:
    mock_clients(mock)
    delete = mock.delete("/ers/config/pxgridnode/name/iseagent-fmc-1").respond(204)
    mock.delete("/ers/config/pxgridnode/name/pxgrid_client_1").respond(204)
    preview, applied = await two_step("ise_decline_pxgrid_client", {"name": "iseagent-fmc-1"})
    assert applied["status"] == "applied" and delete.called
    assert any("no Decline" in s for s in preview["side_effects"])
    preview, _ = await two_step("ise_decline_pxgrid_client", {"name": "pxgrid_client_1"})
    assert preview["status"] == "blocked" and "ise_delete_pxgrid_client" in preview["blockers"][0]
    preview, _ = await two_step("ise_delete_pxgrid_client", {"name": "pxgrid_client_1"})
    assert preview["status"] == "preview"
    assert any("Catalyst Center stops" in s for s in preview["side_effects"])


async def test_delete_refuses_ise_internal_client(mock: respx.MockRouter) -> None:
    c = {"id": "~ise-mnt-ise@xgrid.cisco.com", "name": "~ise-mnt-ise", "status": "enabled"}
    mock.get("/ers/config/pxgridnode/name/~ise-mnt-ise").respond(json={"PxgridNode": c})
    preview, _ = await two_step("ise_delete_pxgrid_client", {"name": "~ise-mnt-ise"})
    assert preview["status"] == "blocked" and "ISE's own" in preview["blockers"][0]


async def test_set_settings_body(mock: respx.MockRouter) -> None:
    put = mock.put("/ers/config/pxgridsettings/autoapprove").respond(204)
    args = {"auto_approve_cert_accounts": False, "allow_password_accounts": True}
    preview, applied = await two_step("ise_set_pxgrid_settings", args)
    assert "auto-approve cert-based off" in preview["action"]
    assert applied["status"] == "applied"
    assert json.loads(put.calls.last.request.content) == {
        "PxgridSettings": {"autoApproveCertBasedAccounts": False, "allowPasswordBasedAccounts": True}
    }


async def test_status_reports_hostname_mismatch_and_chain(
    mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_certs(mock)
    mock_clients(mock)
    wrong = issue(ROOT_KEY, ROOT, SERVER_KEY.public_key(), "old.name.lab", sans=["old.name.lab"])

    async def presented(host: str, sni: str, timeout: float) -> x509.Certificate:  # noqa: ASYNC109
        assert (host, sni) == ("10.0.0.5", "ise.corp.lab")
        return wrong

    monkeypatch.setattr(pxgrid, "presented_cert", presented)
    r = await call("ise_pxgrid_status", {})
    out = r.structured_content
    cert = out["certificates"][0]
    assert cert["bound"]["root"] == "corp-CA"
    assert cert["listener"]["chain_verified"] == ["corp-CA"] and cert["listener"]["chain_complete"]
    assert cert["listener"]["matches_bound"] is False
    assert any("old.name.lab, not ise.corp.lab" in p for p in out["problems"])
    assert out["clients"]["pending"] == ["iseagent-fmc-1"]
    assert out["settings"]["readable"] is False

    async def good(host: str, sni: str, timeout: float) -> x509.Certificate:  # noqa: ASYNC109
        return SERVER

    monkeypatch.setattr(pxgrid, "presented_cert", good)
    out = (await call("ise_pxgrid_status", {})).structured_content
    assert "problems" not in out and out["certificates"][0]["listener"]["matches_bound"] is True


async def test_status_unreachable_listener_falls_back_to_bound_name(
    mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(json=NODES)
    mock.get("/api/v1/certs/trusted-certificate").respond(json={"response": TRUSTED})
    mock.get("/api/v1/certs/system-certificate/ise").respond(
        json={"response": [{**SYSTEM[0], "issuedTo": "old.name.lab"}]}
    )
    mock_clients(mock)

    async def refused(host: str, sni: str, timeout: float) -> x509.Certificate:  # noqa: ASYNC109
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(pxgrid, "presented_cert", refused)
    out = (await call("ise_pxgrid_status", {})).structured_content
    assert out["certificates"][0]["listener"]["reachable"] is False
    assert any("issued to old.name.lab" in p for p in out["problems"])


async def test_status_without_pxgrid_persona(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(
        json={"response": [{"hostname": "ise", "services": ["Session"]}]}
    )
    out = (await call("ise_pxgrid_status", {"probe": False})).structured_content
    assert out["pxgrid_enabled"] is False and "ise_update_node_services" in out["hint"]


def csr_key(csr_pem: str) -> Any:
    return x509.load_pem_x509_csr(csr_pem.encode()).public_key()


async def issue_flow(c: Client, cert_for: Any, **step2: Any) -> tuple[Any, Any]:  # type: ignore[type-arg]
    args = {"common_name": "fmc.corp.lab"}
    p1 = (await c.call_tool("ise_issue_pxgrid_client_cert", args)).structured_content
    assert p1["status"] == "preview" and p1["preview"]["san_dns"] == ["fmc.corp.lab"]
    a1 = (
        await c.call_tool("ise_issue_pxgrid_client_cert", {**args, "confirm": p1["confirm"]})
    ).structured_content
    req = a1["result"]
    csr = x509.load_pem_x509_csr(req["csr_pem"].encode())
    assert csr.subject.rfc4514_string() == "CN=fmc.corp.lab"
    assert "PRIVATE KEY" not in json.dumps(a1)
    cert = cert_for(csr.public_key())
    args2 = {**args, "request_id": req["request_id"], "certificate_pem": pem(cert), **step2}
    p2 = (await c.call_tool("ise_issue_pxgrid_client_cert", args2)).structured_content
    if p2["status"] != "preview":
        return p2, None
    a2 = await c.call_tool(
        "ise_issue_pxgrid_client_cert", {**args2, "confirm": p2["confirm"]}, raise_on_error=False
    )
    return p2, a2


async def test_issue_client_cert_bundle(mock: respx.MockRouter) -> None:
    mock_certs(mock)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        p2, a2 = await issue_flow(
            c, lambda k: issue(ROOT_KEY, ROOT, k, "fmc.corp.lab", sans=["fmc.corp.lab"])
        )
        assert p2["preview"]["key_matches"] and p2["preview"]["trusted_in_ise"] == ["corp-CA"]
        bundle = a2.structured_content["result"]
        key = serialization.load_pem_private_key(bundle["private_key_pem"].encode(), None)
        cert = x509.load_pem_x509_certificate(bundle["certificate_pem"].encode())
        assert key.public_key().public_numbers() == cert.public_key().public_numbers()  # type: ignore[union-attr]
        assert x509.load_pem_x509_certificate(bundle["chain_pem"].encode()) == ROOT
        assert x509.load_pem_x509_certificate(bundle["server_ca_pem"].encode()) == ROOT
        assert bundle["server"]["root"] == "corp-CA"
        # single use: the key is gone
        again = await c.call_tool(
            "ise_issue_pxgrid_client_cert",
            {
                "common_name": "fmc.corp.lab",
                "request_id": "pxr_nope",
                "certificate_pem": bundle["certificate_pem"],
            },
            raise_on_error=False,
        )
        assert again.is_error


async def test_issue_encrypted_key(mock: respx.MockRouter) -> None:
    mock_certs(mock)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        _, a2 = await issue_flow(
            c, lambda k: issue(ROOT_KEY, ROOT, k, "fmc.corp.lab"), key_passphrase="s3cret-pass"
        )
        b = a2.structured_content["result"]
        assert b["private_key_encrypted"] and "ENCRYPTED" in b["private_key_pem"]
        serialization.load_pem_private_key(b["private_key_pem"].encode(), b"s3cret-pass")


async def test_issue_blocks_server_only_eku_untrusted_issuer_and_wrong_key(mock: respx.MockRouter) -> None:
    mock_certs(mock)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        p2, _ = await issue_flow(
            c, lambda k: issue(ROOT_KEY, ROOT, k, "fmc.corp.lab", ekus=[ExtendedKeyUsageOID.SERVER_AUTH])
        )
        assert p2["status"] == "blocked" and any("Client Authentication" in b for b in p2["blockers"])
        p2, _ = await issue_flow(c, lambda k: issue(OTHER_KEY, OTHER, k, "fmc.corp.lab"))
        assert any("not in ISE's trusted store" in b for b in p2["blockers"])
        stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        p2, _ = await issue_flow(c, lambda k: issue(ROOT_KEY, ROOT, stranger, "fmc.corp.lab"))
        assert any("not for this request's key" in b for b in p2["blockers"])


async def test_issue_blocks_ca_not_trusted_for_ise_auth(mock: respx.MockRouter) -> None:
    mock_certs(mock, trusted=[{**TRUSTED[0], "trustedFor": "Endpoints"}])
    async with Client(make_server(mcp_enable_writes=True)) as c:
        p2, _ = await issue_flow(c, lambda k: issue(ROOT_KEY, ROOT, k, "fmc.corp.lab"))
        assert any("authentication within ISE" in b for b in p2["blockers"])


async def test_issue_rejects_bad_input(mock: respx.MockRouter) -> None:
    for args in (
        {"common_name": "a/b"},
        {"common_name": "fmc.corp.lab", "san_dns": ["bad name"]},
        {"common_name": "fmc.corp.lab", "certificate_pem": "x"},
        {"common_name": "fmc.corp.lab", "request_id": "pxr_unknown", "certificate_pem": pem(SERVER)},
    ):
        r = await call("ise_issue_pxgrid_client_cert", args, mcp_enable_writes=True)
        assert r.is_error, args


def test_name_matches_wildcard() -> None:
    wild = issue(ROOT_KEY, ROOT, SERVER_KEY.public_key(), "x", sans=["*.corp.lab"])
    assert pxgrid.name_matches("ise.corp.lab", wild)
    assert not pxgrid.name_matches("a.b.corp.lab", wild)
    assert pxgrid.name_matches("ise.corp.lab", issue(ROOT_KEY, ROOT, SERVER_KEY.public_key(), "ise.corp.lab"))


async def test_issue_step2_refused_for_another_caller(
    mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_certs(mock)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        args = {"common_name": "fmc.corp.lab"}
        p1 = (await c.call_tool("ise_issue_pxgrid_client_cert", args)).structured_content
        req = (
            await c.call_tool("ise_issue_pxgrid_client_cert", {**args, "confirm": p1["confirm"]})
        ).structured_content["result"]
        monkeypatch.setattr(pxgrid, "current_caller", lambda: "mallory")
        cert = issue(ROOT_KEY, ROOT, csr_key(req["csr_pem"]), "fmc.corp.lab")
        r = await c.call_tool(
            "ise_issue_pxgrid_client_cert",
            {**args, "request_id": req["request_id"], "certificate_pem": pem(cert)},
            raise_on_error=False,
        )
        assert r.is_error and "No open certificate request" in r.content[0].text
        r = await c.call_tool(
            "ise_issue_pxgrid_client_cert",
            {
                **args,
                "request_id": req["request_id"],
                "certificate_pem": pem(cert),
                "key_passphrase": "short",
            },
            raise_on_error=False,
        )
        assert r.is_error


async def test_issue_request_limit_is_per_caller(
    mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pxgrid, "MAX_REQUESTS", 1)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        args = {"common_name": "fmc.corp.lab"}
        p1 = (await c.call_tool("ise_issue_pxgrid_client_cert", args)).structured_content
        await c.call_tool("ise_issue_pxgrid_client_cert", {**args, "confirm": p1["confirm"]})
        assert (await c.call_tool("ise_issue_pxgrid_client_cert", args)).structured_content[
            "status"
        ] == "blocked"
        monkeypatch.setattr(pxgrid, "current_caller", lambda: "bob")
        assert (await c.call_tool("ise_issue_pxgrid_client_cert", args)).structured_content[
            "status"
        ] == "preview"


async def test_issue_ip_common_name_gets_no_dns_san(mock: respx.MockRouter) -> None:
    r = await call("ise_issue_pxgrid_client_cert", {"common_name": "10.1.1.1"}, mcp_enable_writes=True)
    assert r.structured_content["preview"]["san_dns"] == []

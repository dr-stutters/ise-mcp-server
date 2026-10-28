"""Certificate lifecycle (OpenAPI certs) and EAP-TLS building blocks (ERS certificateprofile,
idstoresequence): CSR -> signed by any CA -> bind; trusted CA import; certificate authentication
profile and identity source sequence.

CA-agnostic: the tools exchange PEM text, so the signing step can be a Windows AD CS (win_sign_csr), an
OpenSSL or step-ca lab CA, or a public CA.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import base64
import hashlib
import os
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import quote, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from ise_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    compact,
    field_changes,
    get_client,
    preview_or_apply,
)
from ise_mcp._core.http import page_of
from ise_mcp._core.secrets import register_secret
from ise_mcp.client import IseApp
from ise_mcp.config import Settings
from ise_mcp.tools._common import list_result, openapi_all
from ise_mcp.tools.writes import fingerprint, put_body, unchanged

USAGES = Literal["MULTI-USE", "ADMIN", "EAP-AUTH", "DTLS-AUTH", "PORTAL", "PXGRID", "SAML", "IMS", "TACACS"]
BIND_ROLES = Literal["admin", "eap", "radius", "portal", "pxgrid", "saml", "ims", "tacacs"]
TRUST_FOR = Literal["client_auth", "ise_auth", "admin_auth", "cisco_services"]
TRUST_FIELDS = {
    "client_auth": "trustForClientAuth",
    "ise_auth": "trustForIseAuth",
    "admin_auth": "trustForCertificateBasedAdminAuth",
    "cisco_services": "trustForCiscoServicesAuth",
}
CERT_ATTRIBUTES = Literal[
    "SUBJECT_COMMON_NAME",
    "SUBJECT_ALTERNATIVE_NAME",
    "SUBJECT_SERIAL_NUMBER",
    "SUBJECT",
    "SUBJECT_ALTERNATIVE_NAME_OTHER_NAME",
    "SUBJECT_ALTERNATIVE_NAME_EMAIL",
    "SUBJECT_ALTERNATIVE_NAME_DNS",
]
SAFE_TEXT = re.compile(r"[\w .,:/@-]*")
PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")


def pem_certs(text: str) -> list[str]:
    """The PEM certificate blocks in `text` (a leaf, or a chain); refuses private keys outright."""
    if "PRIVATE KEY" in text:
        raise InvalidRequest("That text contains a private key: pass only the certificate (PEM)")
    certs = PEM_CERT.findall(text or "")
    if not certs:
        raise InvalidRequest("No PEM certificate found (expected -----BEGIN CERTIFICATE----- ...)")
    for c in certs:
        body = "".join(c.splitlines()[1:-1])
        try:
            base64.b64decode(body, validate=True)
        except ValueError as e:
            raise InvalidRequest("A certificate block is not valid base64") from e
    return certs


def csr_row(c: dict[str, Any]) -> dict[str, Any]:
    return {
        "friendly_name": c.get("friendlyName"),
        "node": c.get("hostName"),
        "used_for": c.get("usedFor"),
        "key_size": c.get("keySize"),
        "created": c.get("timeStamp"),
        "id": c.get("id"),
    }


async def node_names(app: IseApp) -> list[str]:
    nodes = (await app.openapi.get("/api/v1/deployment/node")).get("response") or []
    return [str(n.get("hostname")) for n in nodes]


async def resolve_node(app: IseApp, node: str | None) -> str:
    names = await node_names(app)
    if node is None:
        if len(names) != 1:
            raise InvalidRequest(f"{len(names)} nodes: give `node` (one of {', '.join(names)})")
        return names[0]
    hit = [n for n in names if n.lower() == node.strip().lower()]
    if not hit:
        raise NotFound(f"No node {node!r}; see ise_list_nodes", 404)
    return hit[0]


async def find_csr(app: IseApp, node: str, csr: str) -> dict[str, Any]:
    rows = [
        c for c in await openapi_all(app, "/api/v1/certs/certificate-signing-request") if isinstance(c, dict)
    ]
    hits = [
        c
        for c in rows
        if str(c.get("hostName", "")).lower() == node.lower() and csr in (c.get("id"), c.get("friendlyName"))
    ]
    if not hits:
        raise NotFound(f"No CSR {csr!r} on {node}; see ise_list_csrs", 404)
    if len(hits) > 1:
        ids = ", ".join(str(h.get("id")) for h in hits)
        raise InvalidRequest(f"{len(hits)} CSRs on {node} are named {csr!r}: give the id ({ids})")
    hit: dict[str, Any] = hits[0]
    return hit


# --- system certificate import (I58) -------------------------------------------------------------

SYSTEM_USAGES = Literal["admin", "eap", "radius_dtls", "portal", "pxgrid", "saml", "ims", "tacacs"]
# tool usage -> (SystemCert body flag, the name ISE shows in a system certificate's usedBy)
USAGE_FIELDS: dict[str, tuple[str, str]] = {
    "admin": ("admin", "Admin"),
    "eap": ("eap", "EAP Authentication"),
    "radius_dtls": ("radius", "RADIUS DTLS"),
    "portal": ("portal", "Portal"),
    "pxgrid": ("pxgrid", "pxGrid"),
    "saml": ("saml", "SAML"),
    "ims": ("ims", "ISE Messaging Service"),
    "tacacs": ("tacacs", "TACACS"),
}
DEFAULT_PORTAL_TAG = "Default Portal Certificate Group"
CERT_PASSWORD_ENV = re.compile(r"ISE_CERT_[A-Z0-9_]+")
MAX_CERT_FILE = 1 << 20  # a certificate, key or PKCS#12 bundle is a few KB
CERT_SUFFIXES = (".pem", ".crt", ".cer")
KEY_SUFFIXES = (".pem", ".key")
PKCS12_SUFFIXES = (".p12", ".pfx")


def cert_file(settings: Settings, path: str, suffixes: tuple[str, ...]) -> Path:
    """A certificate/key/PKCS#12 file the server may read: only inside ISE_CERT_DIR (relative paths
    resolve there), with one of the expected suffixes. Key files are secrets, so there is no fallback
    to arbitrary absolute paths."""
    base = settings.cert_dir
    if base is None:
        raise InvalidRequest(
            "Set ISE_CERT_DIR on the server (the directory certificate and key files are read from) "
            "before importing a system certificate"
        )
    raw = Path(path.strip()).expanduser()
    if raw.suffix.lower() not in suffixes:
        raise InvalidRequest(f"{path!r}: expected a {' / '.join(suffixes)} file")
    root = base.resolve()
    target = (root / raw).resolve()
    if not target.is_relative_to(root):
        raise InvalidRequest(f"{path!r} is outside ISE_CERT_DIR")
    if not target.is_file():
        raise InvalidRequest(f"{path!r} is not a file in ISE_CERT_DIR")
    if target.stat().st_size > MAX_CERT_FILE:
        raise InvalidRequest(f"{path!r} is larger than 1 MB: not a certificate, key or PKCS#12 file")
    return target


def cert_password(var: str) -> str | None:
    """A key/PKCS#12 password from the server's environment: `var`, or the file `<var>_FILE` names."""
    if not CERT_PASSWORD_ENV.fullmatch(var):
        raise InvalidRequest(
            f"password_env must name a variable starting ISE_CERT_ (upper case, digits, '_'), not {var!r}: "
            "the tool never reads the server's other secrets."
        )
    value = os.environ.get(var)
    if not value and (file := os.environ.get(f"{var}_FILE")):
        try:
            value = Path(file).expanduser().read_text().removesuffix("\n")
        except OSError:
            raise InvalidRequest(f"{var}_FILE names a file this server can't read") from None
    if value:
        register_secret(value)
    return value or None


def load_key(data: bytes, password: str | None) -> Any:
    try:
        return serialization.load_pem_private_key(data, password.encode() if password else None)
    except TypeError as e:  # encrypted key without a password, or a password for a plain key
        raise InvalidRequest(
            "The private key is encrypted: give password_env" if not password else str(e)
        ) from None
    except ValueError:
        raise InvalidRequest("Could not read the private key (wrong password, or not a PEM key)") from None


def load_bundle(
    settings: Settings,
    cert_path: str | None,
    key_path: str | None,
    pkcs12_path: str | None,
    password: str | None,
) -> tuple[x509.Certificate, Any, list[x509.Certificate], bytes]:
    """(leaf certificate, private key, extra chain certificates, raw file bytes for the fingerprint)."""
    if pkcs12_path:
        if cert_path or key_path:
            raise InvalidRequest("Give pkcs12_file alone, or cert_file + key_file, not both")
        raw = cert_file(settings, pkcs12_path, PKCS12_SUFFIXES).read_bytes()
        try:
            key, leaf, extra = pkcs12.load_key_and_certificates(raw, password.encode() if password else None)
        except ValueError:
            raise InvalidRequest(
                "Could not open the PKCS#12 file (wrong password, or not a PKCS#12 bundle)"
            ) from None
        if leaf is None or key is None:
            raise InvalidRequest("The PKCS#12 file must hold the certificate and its private key")
        return leaf, key, list(extra or []), raw
    if not (cert_path and key_path):
        raise InvalidRequest("Give cert_file and key_file (PEM), or pkcs12_file")
    cert_raw = cert_file(settings, cert_path, CERT_SUFFIXES).read_bytes()
    key_raw = cert_file(settings, key_path, KEY_SUFFIXES).read_bytes()
    blocks = pem_certs(cert_raw.decode("ascii", errors="replace"))
    try:
        chain = [x509.load_pem_x509_certificate(b.encode()) for b in blocks]
    except ValueError:
        raise InvalidRequest("cert_file holds a certificate block that is not valid X.509") from None
    if b"PRIVATE KEY" not in key_raw:
        raise InvalidRequest("key_file holds no PEM private key")
    return chain[0], load_key(key_raw, password), chain[1:], cert_raw + key_raw


def name_cn(name: x509.Name) -> str:
    cns = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(cns[0].value) if cns else name.rfc4514_string()


def cert_dns_names(cert: x509.Certificate) -> list[str]:
    names = [name_cn(cert.subject)]
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names += [str(n) for n in san.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        pass
    return names


def public_der(key: Any) -> bytes:
    data: bytes = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return data


def api_node(settings: Settings, nodes: list[dict[str, Any]]) -> str | None:
    """The node the OpenAPI import lands on: the one this server's ISE URL points at."""
    host = (urlparse(settings.url).hostname or "").lower()
    for n in nodes:
        if host and host in {str(n.get(k) or "").lower() for k in ("hostname", "fqdn", "ipAddress")}:
            return str(n.get("hostname"))
    if host and host.split(".")[0] in {str(n.get("hostname") or "").lower() for n in nodes}:
        return host.split(".")[0]
    return str(nodes[0].get("hostname")) if len(nodes) == 1 else None


# --- trusted certificate settings (I58) ----------------------------------------------------------

STATUS = Literal["enabled", "disabled"]
TIME_UNITS = Literal["Minutes", "Hours", "Days", "Weeks"]
# What ISE's GET shows in trustedFor -> the flag on PUT.
TRUSTED_FOR_TOKENS = {
    "infrastructure": "trustForIseAuth",
    "endpoints": "trustForClientAuth",
    "cisco services": "trustForCiscoServicesAuth",
    "adminauth": "trustForCertificateBasedAdminAuth",
    "admin auth": "trustForCertificateBasedAdminAuth",
    "certificate based admin authentication": "trustForCertificateBasedAdminAuth",
}
TRUST_BOOLS = (
    "downloadCRL",
    "automaticCRLUpdate",
    "authenticateBeforeCRLReceived",
    "ignoreCRLExpiration",
    "enableServerIdentityCheck",
    "enableOCSPValidation",
    "rejectIfNoStatusFromOCSP",
    "rejectIfUnreachableFromOCSP",
)
TRUST_INTS = ("automaticCRLUpdatePeriod", "nonAutomaticCRLUpdatePeriod", "crlDownloadFailureRetries")
TRUST_UNITS = ("automaticCRLUpdateUnits", "nonAutomaticCRLUpdateUnits", "crlDownloadFailureRetriesUnits")


def on(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("on", "true", "1", "yes", "enabled")


def trust_settings(cur: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """ISE's GET of a trusted certificate ('on'/'off', numbers as strings, trustedFor as a list of
    names) as the typed PUT body, plus any trustedFor names this tool does not know."""
    out: dict[str, Any] = {
        "name": cur.get("friendlyName"),
        "description": cur.get("description") or "",
        "status": "Disabled" if str(cur.get("status")).lower() == "disabled" else "Enabled",
        "crlDistributionUrl": cur.get("crlDistributionUrl") or "",
        "selectedOCSPService": cur.get("selectedOCSPService") or "",
    }
    for k in TRUST_BOOLS:
        out[k] = on(cur.get(k))
    for k in TRUST_INTS:
        try:
            out[k] = int(cur.get(k) or 0)
        except (TypeError, ValueError):
            out[k] = 0
    for k in TRUST_UNITS:
        out[k] = cur.get(k) or "Hours"
    for flag in TRUST_FIELDS.values():
        out[flag] = False
    unknown = []
    for token in str(cur.get("trustedFor") or "").split(","):
        t = token.strip()
        if not t:
            continue
        if hit := TRUSTED_FOR_TOKENS.get(t.lower()):
            out[hit] = True
        else:
            unknown.append(t)
    return out, unknown


def register(reg: ToolRegistrar) -> None:  # noqa: C901 - one registration block per tool
    # --- CSRs --------------------------------------------------------------------------------

    @reg.read(title="List certificate signing requests")
    async def ise_list_csrs(
        ctx: Context,
        node: Annotated[str | None, Field(description="Only CSRs for this node")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List pending certificate signing requests (CSRs) ISE holds a private key for: friendly name,
        node, usage, key size, creation time and id. Export one with ise_export_csr, have a CA sign it,
        then bind the result with ise_bind_certificate."""
        app: IseApp = get_client(ctx)
        rows = [
            csr_row(c)
            for c in await openapi_all(app, "/api/v1/certs/certificate-signing-request")
            if isinstance(c, dict)
        ]
        if node:
            rows = [r for r in rows if str(r["node"]).lower() == node.lower()]
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=["friendly_name", "node", "used_for", "key_size", "created", "id"],
        )

    @reg.read(title="Export a CSR (PEM)")
    async def ise_export_csr(
        ctx: Context,
        csr: Annotated[str, Field(description="CSR id or friendly name (see ise_list_csrs)")],
        node: Annotated[str | None, Field(description="Node hostname; optional with a single node")] = None,
    ) -> dict[str, Any]:
        """The PEM text of a CSR, ready for any CA (Windows AD CS win_sign_csr, OpenSSL, step-ca, a
        public CA). The private key never leaves ISE."""
        app: IseApp = get_client(ctx)
        host = await resolve_node(app, node)
        found = await find_csr(app, host, csr)
        path = "/api/v1/certs/certificate-signing-request/export/{}/{}".format(
            quote(host, safe=""), quote(str(found["id"]), safe="")
        )
        pem = await app.openapi.request("GET", path, expect="text")
        return {"node": host, "id": found["id"], "friendly_name": found.get("friendlyName"), "csr_pem": pem}

    @reg.write(title="Generate a CSR")
    async def ise_generate_csr(
        ctx: Context,
        usage: Annotated[USAGES, Field(description="What the certificate will be used for, e.g. EAP-AUTH")],
        common_name: Annotated[
            str, Field(description="Subject CN; '$FQDN$' = each node's FQDN (ISE fills it in)")
        ] = "$FQDN$",
        nodes: Annotated[
            list[str] | None, Field(description="Node hostnames; default every node in the deployment")
        ] = None,
        san_dns: Annotated[list[str] | None, Field(description="DNS subject alternative names")] = None,
        san_ip: Annotated[list[str] | None, Field(description="IP subject alternative names")] = None,
        organization: Annotated[str | None, Field(description="Subject O")] = None,
        org_unit: Annotated[str | None, Field(description="Subject OU")] = None,
        country: Annotated[str | None, Field(description="Subject C (2 letters)")] = None,
        key_type: Annotated[Literal["RSA", "ECDSA"], Field(description="Key type")] = "RSA",
        key_length: Annotated[
            Literal["2048", "4096", "256", "384"], Field(description="RSA 2048/4096 or ECDSA 256/384")
        ] = "2048",
        digest: Annotated[Literal["SHA-256", "SHA-384", "SHA-512"], Field(description="Signature hash")] = (
            "SHA-256"
        ),
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Have ISE generate a key pair and a certificate signing request (one per node). Nothing in
        service changes: the CSR waits until a CA-signed certificate is bound to it with
        ise_bind_certificate. Next: ise_export_csr -> sign it at your CA. Preview-first."""
        app: IseApp = get_client(ctx)
        if key_type == "RSA" and key_length not in ("2048", "4096"):
            raise InvalidRequest("RSA keys are 2048 or 4096 bits")
        if key_type == "ECDSA" and key_length not in ("256", "384"):
            raise InvalidRequest("ECDSA keys are 256 or 384 bits")
        if country is not None and not re.fullmatch(r"[A-Za-z]{2}", country):
            raise InvalidRequest("country is a 2-letter code")
        known = await node_names(app)
        hosts = []
        for n in nodes or known:
            match = [k for k in known if k.lower() == n.lower()]
            if not match:
                raise NotFound(f"No node {n!r}; see ise_list_nodes", 404)
            hosts.append(match[0])
        body: dict[str, Any] = {
            "hostnames": hosts,
            "usedFor": usage,
            "subjectCommonName": common_name,
            "keyType": key_type,
            "keyLength": key_length,
            "digestType": digest,
            "allowWildCardCert": common_name.startswith("*."),
        }
        if usage in ("PORTAL", "MULTI-USE"):
            body["portalGroupTag"] = "Default Portal Certificate Group"
        for key, val in (
            ("sanDNS", san_dns),
            ("sanIP", san_ip),
            ("subjectOrg", organization),
            ("subjectOrgUnit", org_unit),
            ("subjectCountry", country),
        ):
            if val:
                body[key] = val
        args = {
            "usage": usage,
            "common_name": common_name,
            "nodes": nodes,
            "san_dns": san_dns,
            "san_ip": san_ip,
            "organization": organization,
            "org_unit": org_unit,
            "country": country,
            "key_type": key_type,
            "key_length": key_length,
            "digest": digest,
        }
        return await preview_or_apply(
            ctx,
            tool="ise_generate_csr",
            args=args,
            confirm=confirm,
            plan=Plan(f"Generate {usage} CSR for {', '.join(hosts)}", details=body),
            apply=lambda: app.openapi.post("/api/v1/certs/certificate-signing-request", json=body),
        )

    @reg.dangerous(title="Bind a CA-signed certificate to its CSR")
    async def ise_bind_certificate(
        ctx: Context,
        csr: Annotated[str, Field(description="CSR id or friendly name (see ise_list_csrs)")],
        certificate_pem: Annotated[str, Field(description="The CA-signed certificate (PEM); no private key")],
        use_for: Annotated[
            list[BIND_ROLES],
            Field(description="Roles to give the certificate, e.g. ['eap']; 'admin' restarts ISE services"),
        ],
        name: Annotated[str | None, Field(description="Friendly name; default from the CSR")] = None,
        node: Annotated[str | None, Field(description="Node hostname; optional with a single node")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Install a CA-signed certificate on the node that generated its CSR and put it into service
        for the given roles (EAP, Admin, RADIUS DTLS, portal, pxGrid, SAML, messaging, TACACS). The
        certificate it replaces in those roles stops being used. The issuing CA must already be trusted
        (ise_import_trusted_cert). Binding the Admin role RESTARTS the application server on that node
        (several minutes of no GUI/API); the preview says so. Preview-first."""
        app: IseApp = get_client(ctx)
        certs = pem_certs(certificate_pem)
        if not use_for:
            raise InvalidRequest("Give at least one role in use_for")
        host = await resolve_node(app, node)
        found = await find_csr(app, host, csr)
        system = [
            c
            for c in await openapi_all(app, f"/api/v1/certs/system-certificate/{quote(host, safe='')}")
            if isinstance(c, dict)
        ]
        role_names = {
            "admin": "Admin",
            "eap": "EAP Authentication",
            "radius": "RADIUS DTLS",
            "portal": "Portal",
            "pxgrid": "pxGrid",
            "saml": "SAML",
            "ims": "ISE Messaging Service",
            "tacacs": "TACACS",
        }
        replaced = {
            r: [c.get("friendlyName") for c in system if role_names[r] in str(c.get("usedBy") or "")]
            for r in use_for
        }
        body: dict[str, Any] = {
            "hostName": host,
            "id": found["id"],
            "data": certs[0],
            "name": name or found.get("friendlyName"),
            "allowExtendedValidity": True,
            "allowOutOfDateCert": False,
            "allowReplacementOfCertificates": True,
            "allowReplacementOfPortalGroupTag": True,
            "validateCertificateExtensions": False,
        }
        for r in use_for:
            body[r] = True
        if "portal" in use_for:
            body["portalGroupTag"] = "Default Portal Certificate Group"
        side = [f"{role_names[r]} moves off: {', '.join(map(str, v))}" for r, v in replaced.items() if v]
        if "admin" in use_for:
            side.insert(
                0, f"Admin role: ISE restarts the application server on {host} (GUI/API down for minutes)"
            )
        shown = {k: v for k, v in body.items() if k != "data"}
        shown["certificate"] = f"{len(certs)} PEM block(s); the first is bound"
        plan = Plan(
            f"Bind certificate to CSR {found.get('friendlyName')} on {host} for {', '.join(use_for)}",
            details=shown,
            fingerprint=fingerprint([found, replaced]),
            side_effects=side,
        )
        return await preview_or_apply(
            ctx,
            tool="ise_bind_certificate",
            args={
                "csr": csr,
                "certificate_pem": certificate_pem,
                "use_for": use_for,
                "name": name,
                "node": node,
            },
            confirm=confirm,
            plan=plan,
            apply=lambda: app.openapi.post("/api/v1/certs/signed-certificate/bind", json=body),
        )

    # --- trust store -------------------------------------------------------------------------

    @reg.write(title="Import a trusted (CA) certificate")
    async def ise_import_trusted_cert(
        ctx: Context,
        name: Annotated[str, Field(description="Friendly name in the trust store")],
        certificate_pem: Annotated[str, Field(description="The CA certificate (PEM)")],
        trust_for: Annotated[
            list[TRUST_FOR],
            Field(
                description="client_auth = EAP-TLS client certificates and syslog; ise_auth = inside "
                "ISE (node/pxGrid) and server certificates; admin_auth = certificate-based admin login; "
                "cisco_services = Cisco cloud services"
            ),
        ] = ["client_auth", "ise_auth"],  # noqa: B006 - FastMCP defaults are copied per call
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a CA certificate to ISE's trusted store, so ISE accepts certificates it issued: client
        certificates for EAP-TLS (client_auth), CA-signed node certificates being bound (ise_auth).
        Needed before ise_bind_certificate with a new CA. Preview-first; a certificate already in the
        store is refused by ISE."""
        app: IseApp = get_client(ctx)
        if description and not SAFE_TEXT.fullmatch(description):
            raise InvalidRequest(
                "ISE refuses descriptions with characters like ( ) < > ; % ('Security Check Failed'): "
                "use letters, digits, spaces and . , : / @ _ -"
            )
        certs = pem_certs(certificate_pem)
        if len(certs) != 1:
            raise InvalidRequest("Import one CA certificate at a time (got a chain)")
        existing = [
            c for c in await openapi_all(app, "/api/v1/certs/trusted-certificate") if isinstance(c, dict)
        ]
        blockers = (
            [f"A trusted certificate named {name!r} exists"]
            if any(c.get("friendlyName") == name for c in existing)
            else []
        )
        body: dict[str, Any] = {
            "name": name,
            "data": certs[0],
            "description": description or "",
            "allowBasicConstraintCAFalse": False,
            "allowOutOfDateCert": False,
            "allowSHA1Certificates": False,
            "validateCertificateExtensions": False,
        }
        for t in trust_for:
            body[TRUST_FIELDS[t]] = True
        shown = {k: v for k, v in body.items() if k != "data"}
        return await preview_or_apply(
            ctx,
            tool="ise_import_trusted_cert",
            args={
                "name": name,
                "certificate_pem": certificate_pem,
                "trust_for": trust_for,
                "description": description,
            },
            confirm=confirm,
            plan=Plan(f"Import trusted certificate {name}", details=shown, blockers=blockers),
            apply=lambda: app.openapi.post("/api/v1/certs/trusted-certificate/import", json=body),
        )

    @reg.dangerous(title="Import a system certificate with its private key")
    async def ise_import_system_certificate(
        ctx: Context,
        usages: Annotated[
            list[SYSTEM_USAGES],
            Field(
                description="Roles to give the certificate, e.g. ['portal'] or ['eap']; 'admin' restarts "
                "the application server on the node"
            ),
        ],
        cert_file: Annotated[
            str | None,
            Field(description="PEM certificate (leaf first, chain after) in ISE_CERT_DIR (.pem/.crt/.cer)"),
        ] = None,
        key_file: Annotated[
            str | None, Field(description="PEM private key in ISE_CERT_DIR (.pem/.key)")
        ] = None,
        pkcs12_file: Annotated[
            str | None, Field(description="PKCS#12 bundle (certificate + key) in ISE_CERT_DIR (.p12/.pfx)")
        ] = None,
        password_env: Annotated[
            str | None,
            Field(
                description="Name of a server environment variable (ISE_CERT_...) holding the key or "
                "PKCS#12 password; never the password itself"
            ),
        ] = None,
        name: Annotated[
            str | None, Field(description="Friendly name; default ISE's (from the subject)")
        ] = None,
        node: Annotated[
            str | None,
            Field(description="Node to import on; must be the node this server's ISE URL points at"),
        ] = None,
        allow_wildcard: Annotated[
            bool, Field(description="Allow a wildcard certificate (*.example.com in CN or SAN)")
        ] = False,
        portal_group_tag: Annotated[
            str | None,
            Field(description=f"Portal certificate group tag (portal usage); default {DEFAULT_PORTAL_TAG!r}"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Import an existing certificate and its private key (a public wildcard for the portals, an
        enterprise certificate issued outside ISE) as a system certificate and put it into service for the
        given roles. No CSR is needed (for a CSR flow use ise_generate_csr -> ise_bind_certificate). Files
        are read only from the server's ISE_CERT_DIR; the password comes from a server environment
        variable named in `password_env` (ISE_CERT_...). The preview checks the key matches the
        certificate, its validity, a SHA-1 signature, wildcards (allow_wildcard) and that the issuing CA is
        already trusted (ise_import_trusted_cert), and names the certificates it moves roles off. ISE
        imports on the node its API is called on. The Admin role RESTARTS the application server on that
        node (GUI/API down for minutes). Preview-first."""
        app: IseApp = get_client(ctx)
        if not usages:
            raise InvalidRequest("Give at least one role in usages")
        if portal_group_tag is not None and "portal" not in usages:
            raise InvalidRequest("portal_group_tag only applies with the 'portal' usage")
        password = cert_password(password_env) if password_env else None
        if password_env and not password:
            raise InvalidRequest(
                f"{password_env} (or {password_env}_FILE) is not set on this server: add it to the server's "
                "environment"
            )
        leaf, key, extra, raw = load_bundle(app.settings, cert_file, key_file, pkcs12_file, password)
        nodes = [
            n
            for n in (await app.openapi.get("/api/v1/deployment/node")).get("response") or []
            if isinstance(n, dict)
        ]
        target = api_node(app.settings, nodes)
        blockers: list[str] = []
        side: list[str] = []
        if node:
            host = await resolve_node(app, node)
            if target and host != target:
                blockers.append(
                    f"ISE imports a system certificate on the node its API is called on ({target}), not "
                    f"{host}: run this against a server pointed at {host}, or use the GUI"
                )
            target = target or host
        if target is None:
            raise InvalidRequest(
                f"{len(nodes)} nodes and this server's ISE URL matches none of them: give `node` "
                "(the node the URL reaches)"
            )
        system = [
            c
            for c in await openapi_all(app, f"/api/v1/certs/system-certificate/{quote(target, safe='')}")
            if isinstance(c, dict)
        ]
        trusted = [
            c for c in await openapi_all(app, "/api/v1/certs/trusted-certificate") if isinstance(c, dict)
        ]
        now = datetime.now(UTC)
        if not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
            blockers.append(
                f"The certificate is not valid now (valid {leaf.not_valid_before_utc:%Y-%m-%d} to "
                f"{leaf.not_valid_after_utc:%Y-%m-%d})"
            )
        if public_der(leaf.public_key()) != public_der(key.public_key()):
            blockers.append("The private key does not belong to the certificate")
        if isinstance(leaf.signature_hash_algorithm, hashes.SHA1):
            blockers.append("The certificate is signed with SHA-1, which ISE refuses for system certificates")
        names = cert_dns_names(leaf)
        wildcard = any(n.startswith("*.") for n in names)
        if wildcard and not allow_wildcard:
            blockers.append(
                f"Wildcard certificate ({', '.join(n for n in names if n.startswith('*.'))}): pass "
                "allow_wildcard=true"
            )
        if wildcard and "eap" in usages:
            side.append(
                "EAP with a wildcard certificate: some supplicants refuse a wildcard server certificate; "
                "Cisco recommends the node FQDN as CN with the wildcard in the SAN, or a non-wildcard EAP "
                "certificate"
            )
        issuer = name_cn(leaf.issuer)
        if leaf.issuer != leaf.subject and not any(str(c.get("issuedTo")) == issuer for c in trusted):
            blockers.append(
                f"The issuing CA {issuer!r} is not in ISE's trusted store: import it (and any intermediate) "
                "with ise_import_trusted_cert first"
            )
        if name and any(c.get("friendlyName") == name for c in system):
            blockers.append(f"{target} already has a system certificate named {name!r}")
        replaced = {
            u: [
                str(c.get("friendlyName")) for c in system if USAGE_FIELDS[u][1] in str(c.get("usedBy") or "")
            ]
            for u in usages
        }
        side += [f"{USAGE_FIELDS[u][1]} moves off: {', '.join(v)}" for u, v in replaced.items() if v]
        if "admin" in usages:
            side.insert(
                0, f"Admin role: ISE restarts the application server on {target} (GUI/API down for minutes)"
            )
        if extra:
            side.append(
                f"{len(extra)} chain certificate(s) in the file are not imported: ISE builds the chain from "
                "its trusted store"
            )
        body: dict[str, Any] = {
            "allowExtendedValidity": True,
            "allowOutOfDateCert": False,
            "allowPortalTagTransferForSameSubject": False,
            "allowReplacementOfCertificates": True,
            "allowReplacementOfPortalGroupTag": True,
            "allowRoleTransferForSameSubject": False,
            "allowSHA1Certificates": False,
            "allowWildCardCertificates": allow_wildcard,
            "validateCertificateExtensions": False,
        }
        if name:
            body["name"] = name
        for u in usages:
            body[USAGE_FIELDS[u][0]] = True
        if "portal" in usages:
            body["portalGroupTag"] = portal_group_tag or DEFAULT_PORTAL_TAG
        shown = dict(body)
        shown["node"] = target
        shown["certificate"] = {
            "subject": leaf.subject.rfc4514_string(),
            "issuer": leaf.issuer.rfc4514_string(),
            "dns_names": names,
            "serial": format(leaf.serial_number, "x"),
            "not_after": leaf.not_valid_after_utc.isoformat(),
            "sha256": leaf.fingerprint(hashes.SHA256()).hex(),
        }
        shown["private_key"] = "read from the file, sent encrypted (never shown)"
        if password_env:
            shown["password"] = f"(from {password_env}, never shown)"

        async def apply() -> Any:
            # ISE requires a key password: send the key encrypted (PKCS#8) with the given password, or a
            # one-time random one for an unencrypted key.
            pw = password or secrets.token_urlsafe(24)
            register_secret(pw)
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(pw.encode()),
            ).decode()
            full = {
                **body,
                "data": leaf.public_bytes(serialization.Encoding.PEM).decode(),
                "privateKeyData": key_pem,
                "password": pw,
            }
            return await app.openapi.post("/api/v1/certs/system-certificate/import", json=full)

        plan = Plan(
            f"Import system certificate {name or name_cn(leaf.subject)} on {target} for {', '.join(usages)}",
            details=shown,
            fingerprint=fingerprint(
                [hashlib.sha256(raw).hexdigest(), [(c.get("id"), c.get("usedBy")) for c in system]]
            ),
            blockers=blockers,
            side_effects=side,
            blast_radius=1,
        )
        return await preview_or_apply(
            ctx,
            tool="ise_import_system_certificate",
            args={
                "usages": usages,
                "cert_file": cert_file,
                "key_file": key_file,
                "pkcs12_file": pkcs12_file,
                "password_env": password_env,
                "name": name,
                "node": node,
                "allow_wildcard": allow_wildcard,
                "portal_group_tag": portal_group_tag,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Change a trusted certificate's trust and revocation settings")
    async def ise_set_trusted_cert(
        ctx: Context,
        cert: Annotated[
            str,
            Field(
                description="Trusted certificate friendly name or id (ise_list_certificates kind='trusted')"
            ),
        ],
        trust_for: Annotated[
            list[TRUST_FOR] | None,
            Field(
                description="The full set of trust usages (others are turned off): client_auth = EAP-TLS "
                "client certificates and syslog; ise_auth = inside ISE and server certificates; admin_auth = "
                "certificate-based admin login; cisco_services = Cisco cloud services. Omit to keep"
            ),
        ] = None,
        status: Annotated[
            STATUS | None, Field(description="Enable or disable the certificate in the trust store")
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        crl_download: Annotated[bool | None, Field(description="Download and check this CA's CRL")] = None,
        crl_url: Annotated[
            str | None, Field(description="CRL distribution URL (http:// or https://)")
        ] = None,
        crl_auto_update: Annotated[
            bool | None,
            Field(description="true: fetch the CRL a period before it expires; false: fetch it every period"),
        ] = None,
        crl_update_period: Annotated[
            int | None, Field(ge=1, description="The CRL fetch period (before expiry, or the fixed interval)")
        ] = None,
        crl_update_units: Annotated[
            TIME_UNITS | None, Field(description="Units of crl_update_period")
        ] = None,
        crl_bypass_if_not_received: Annotated[
            bool | None,
            Field(description="Accept client certificates while no CRL has been received yet"),
        ] = None,
        ignore_crl_expiration: Annotated[bool | None, Field(description="Keep using an expired CRL")] = None,
        ocsp_service: Annotated[
            str | None, Field(description="OCSP client profile name to validate with; '' turns OCSP off")
        ] = None,
        ocsp_reject_unreachable: Annotated[
            bool | None, Field(description="Reject the certificate when the OCSP responder is unreachable")
        ] = None,
        ocsp_reject_no_status: Annotated[
            bool | None, Field(description="Reject the certificate when OCSP returns no status")
        ] = None,
        server_identity_check: Annotated[
            bool | None,
            Field(description="Check that HTTPS/LDAP server certificate names fit the server URL"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a trusted (CA) certificate in ISE's trust store: what it is trusted for (the 'Trust for
        client authentication' flag is the classic EAP-TLS 'unknown CA' fix), enable/disable it, and
        revocation checking (CRL download from a distribution URL, OCSP). Only the given settings change;
        the preview diffs ISE's current settings against the PUT and is a no_change when nothing would.
        Disabling a CA that issued a node's in-use Admin or EAP certificate is blocked. Turning on CRL
        checking without crl_bypass_if_not_received rejects this CA's client certificates until the first
        CRL arrives (the preview says so). Preview-first."""
        app: IseApp = get_client(ctx)
        if description is not None and not SAFE_TEXT.fullmatch(description):
            raise InvalidRequest(
                "ISE refuses descriptions with characters like ( ) < > ; % ('Security Check Failed'): "
                "use letters, digits, spaces and . , : / @ _ -"
            )
        if crl_url and not re.fullmatch(r"https?://\S+", crl_url):
            raise InvalidRequest("crl_url must be an http:// or https:// URL")
        rows = [c for c in await openapi_all(app, "/api/v1/certs/trusted-certificate") if isinstance(c, dict)]
        hits = [c for c in rows if cert in (c.get("id"), c.get("friendlyName"))] or [
            c for c in rows if str(c.get("friendlyName", "")).lower() == cert.strip().lower()
        ]
        if not hits:
            raise NotFound(f"No trusted certificate {cert!r}; see ise_list_certificates kind='trusted'", 404)
        if len(hits) > 1:
            raise InvalidRequest(
                f"{len(hits)} trusted certificates match {cert!r}: give the id "
                f"({', '.join(str(h.get('id')) for h in hits)})"
            )
        cert_id = str(hits[0]["id"])
        path = f"/api/v1/certs/trusted-certificate/{quote(cert_id, safe='')}"
        got = await app.openapi.get(path)
        raw_cur = (
            got.get("response") if isinstance(got, dict) and isinstance(got.get("response"), dict) else got
        )
        if not isinstance(raw_cur, dict):
            raise NotFound(f"Trusted certificate {cert_id} vanished", 404)
        current, unknown = trust_settings(raw_cur)
        desired = dict(current)
        blockers: list[str] = []
        side: list[str] = []
        if trust_for is not None:
            for flag in TRUST_FIELDS.values():
                desired[flag] = False
            for t in trust_for:
                desired[TRUST_FIELDS[t]] = True
            if unknown:
                side.append(
                    f"ISE also lists trust usages this tool does not set ({', '.join(unknown)}): "
                    "they are replaced"
                )
        elif unknown:
            blockers.append(
                f"ISE lists trust usages this tool does not know ({', '.join(unknown)}): give trust_for "
                "explicitly so the PUT doesn't drop them silently"
            )
        if status is not None:
            desired["status"] = "Enabled" if status == "enabled" else "Disabled"
        if description is not None:
            desired["description"] = description
        for key, val in (
            ("downloadCRL", crl_download),
            ("automaticCRLUpdate", crl_auto_update),
            ("authenticateBeforeCRLReceived", crl_bypass_if_not_received),
            ("ignoreCRLExpiration", ignore_crl_expiration),
            ("rejectIfUnreachableFromOCSP", ocsp_reject_unreachable),
            ("rejectIfNoStatusFromOCSP", ocsp_reject_no_status),
            ("enableServerIdentityCheck", server_identity_check),
        ):
            if val is not None:
                desired[key] = val
        if crl_url is not None:
            desired["crlDistributionUrl"] = crl_url
        auto = desired["automaticCRLUpdate"]
        if crl_update_period is not None:
            desired["automaticCRLUpdatePeriod" if auto else "nonAutomaticCRLUpdatePeriod"] = crl_update_period
        if crl_update_units is not None:
            desired["automaticCRLUpdateUnits" if auto else "nonAutomaticCRLUpdateUnits"] = crl_update_units
        if ocsp_service is not None:
            desired["selectedOCSPService"] = ocsp_service
            desired["enableOCSPValidation"] = bool(ocsp_service)
        if desired["downloadCRL"] and not desired["crlDistributionUrl"]:
            blockers.append("CRL download needs a distribution URL: give crl_url")
        if not desired["enableOCSPValidation"] and (ocsp_reject_unreachable or ocsp_reject_no_status):
            blockers.append("The OCSP reject options need OCSP on: give ocsp_service")
        # Which in-use Admin / EAP certificates did this CA issue?
        issued = str(raw_cur.get("issuedTo") or "")
        in_use = []
        for host in await node_names(app):
            for c in await openapi_all(app, f"/api/v1/certs/system-certificate/{quote(host, safe='')}"):
                used = str((c or {}).get("usedBy") or "") if isinstance(c, dict) else ""
                roles = [r for r in ("Admin", "EAP Authentication") if r in used]
                if roles and issued and str(c.get("issuedBy")) == issued:
                    in_use.append(f"{host} {'/'.join(roles)} certificate {c.get('friendlyName')}")
        if in_use and current["status"] == "Enabled" and desired["status"] == "Disabled":
            blockers.append(
                f"{current['name']} issued certificates in use: {'; '.join(in_use)}. Disabling it breaks "
                "them: move those roles to another certificate first"
            )
        if in_use and current["trustForIseAuth"] and not desired["trustForIseAuth"]:
            side.append(
                f"ise_auth (Infrastructure) is turned off on the CA of {'; '.join(in_use)}: nodes and "
                "clients validating those certificates against ISE's store may fail"
            )
        if current["trustForClientAuth"] and not desired["trustForClientAuth"]:
            side.append("EAP-TLS client certificates this CA issued stop being accepted (client_auth off)")
        if (
            desired["status"] == "Disabled"
            and current["status"] == "Enabled"
            and raw_cur.get("isReferredInPolicy")
        ):
            side.append(f"{current['name']} is referenced in policy: rules relying on it stop matching")
        if (
            desired["downloadCRL"]
            and not current["downloadCRL"]
            and not desired["authenticateBeforeCRLReceived"]
        ):
            side.append(
                "CRL checking on without crl_bypass_if_not_received: client certificates this CA issued are "
                "rejected until ISE has downloaded the first CRL"
            )
        changes = field_changes(current, desired)
        plan = Plan(
            f"Update trusted certificate {current['name']}",
            details={"id": cert_id, "changes": changes},
            fingerprint=fingerprint(raw_cur),
            blockers=blockers,
            side_effects=side,
            noop=unchanged(changes),
            noop_reason=f"{current['name']} already has these settings" if unchanged(changes) else None,
        )
        return await preview_or_apply(
            ctx,
            tool="ise_set_trusted_cert",
            args={
                "cert": cert,
                "trust_for": trust_for,
                "status": status,
                "description": description,
                "crl_download": crl_download,
                "crl_url": crl_url,
                "crl_auto_update": crl_auto_update,
                "crl_update_period": crl_update_period,
                "crl_update_units": crl_update_units,
                "crl_bypass_if_not_received": crl_bypass_if_not_received,
                "ignore_crl_expiration": ignore_crl_expiration,
                "ocsp_service": ocsp_service,
                "ocsp_reject_unreachable": ocsp_reject_unreachable,
                "ocsp_reject_no_status": ocsp_reject_no_status,
                "server_identity_check": server_identity_check,
            },
            confirm=confirm,
            plan=plan,
            apply=lambda: app.openapi.put(path, json=desired),
        )

    # --- EAP-TLS identity --------------------------------------------------------------------

    @reg.write(title="Create or update a certificate authentication profile")
    async def ise_set_cert_auth_profile(
        ctx: Context,
        name: Annotated[str, Field(description="Profile name (letters, digits and _ only)")],
        username_from: Annotated[
            CERT_ATTRIBUTES, Field(description="Certificate field that becomes the username")
        ] = "SUBJECT_COMMON_NAME",
        identity_store: Annotated[
            str | None,
            Field(
                description="Optional store to look the user up in (an AD join point or LDAP); default none"
            ),
        ] = None,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """A certificate authentication profile tells ISE how to read an EAP-TLS client certificate:
        which field is the username, and optionally which identity store to look it up in. Use it as
        an authentication rule's identity source (directly, or inside ise_set_identity_sequence).
        Creates the profile or updates the one with this name. Preview-first."""
        app: IseApp = get_client(ctx)
        if not re.fullmatch(r"[A-Za-z0-9_]+", name):
            raise InvalidRequest("Certificate profile names may only contain letters, digits and _")
        hit = await app.ers_find("certificateprofile", name)
        current = await app.ers_get("certificateprofile", str(hit["id"])) if hit else None
        desired: dict[str, Any] = dict(current) if current else {"name": name}
        desired.update(
            {
                "certificateAttributeName": username_from,
                "usernameFrom": "CERTIFICATE",
                "externalIdentityStoreName": identity_store or "[not applicable]",
                "matchMode": (current or {}).get("matchMode") or "NEVER",
                "allowedAsUserName": bool((current or {}).get("allowedAsUserName")),
            }
        )
        if description is not None:
            desired["description"] = description
        args = {
            "name": name,
            "username_from": username_from,
            "identity_store": identity_store,
            "description": description,
        }
        if current:
            changes = field_changes(current, desired, replace=True)
            plan = Plan(
                f"Update certificate profile {name}",
                details={"changes": changes},
                fingerprint=fingerprint(current),
                blockers=[] if changes else [f"Nothing changes in {name}"],
            )
            return await preview_or_apply(
                ctx,
                tool="ise_set_cert_auth_profile",
                args=args,
                confirm=confirm,
                plan=plan,
                apply=lambda: app.ers_request(
                    "PUT",
                    f"/ers/config/certificateprofile/{current['id']}",
                    json={"CertificateProfile": put_body(desired)},
                ),
            )
        return await preview_or_apply(
            ctx,
            tool="ise_set_cert_auth_profile",
            args=args,
            confirm=confirm,
            plan=Plan(
                f"Create certificate profile {name}",
                details=desired,
                fingerprint=fingerprint({"absent": name}),
            ),
            apply=lambda: app.ers_create("certificateprofile", {"CertificateProfile": desired}),
        )

    @reg.write(title="Create or update an identity source sequence")
    async def ise_set_identity_sequence(
        ctx: Context,
        name: Annotated[str, Field(description="Sequence name (letters, digits and _ only)")],
        stores: Annotated[
            list[str],
            Field(
                description="Identity stores to try, in order, e.g. ['Internal Users'] (see "
                "ise_list_identity_sources)"
            ),
        ],
        cert_profile: Annotated[
            str | None,
            Field(
                description="Certificate authentication profile for EAP-TLS (see ise_set_cert_auth_profile)"
            ),
        ] = None,
        stop_on_store_error: Annotated[
            bool,
            Field(description="Stop (process error) if a store can't be reached instead of trying the next"),
        ] = False,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """An identity source sequence lets one authentication rule handle both certificate (EAP-TLS,
        via cert_profile) and password users (the stores, tried in order). Use its name as an
        authentication rule's identity source. Creates it or updates the one with this name.
        Preview-first."""
        app: IseApp = get_client(ctx)
        if not re.fullmatch(r"[A-Za-z0-9_]+", name):
            raise InvalidRequest("Identity sequence names may only contain letters, digits and _")
        if not stores and not cert_profile:
            raise InvalidRequest("Give stores and/or a cert_profile")
        blockers: list[str] = []
        if cert_profile and await app.ers_find("certificateprofile", cert_profile) is None:
            blockers.append(
                f"No certificate profile {cert_profile!r} (create it with ise_set_cert_auth_profile)"
            )
        hit = await app.ers_find("idstoresequence", name)
        current = await app.ers_get("idstoresequence", str(hit["id"])) if hit else None
        desired: dict[str, Any] = dict(current) if current else {"name": name}
        desired.update(
            {
                "idSeqItem": [{"idstore": s, "order": i} for i, s in enumerate(stores, start=1)],
                "certificateAuthenticationProfile": cert_profile or "",
                "breakOnStoreFail": stop_on_store_error,
            }
        )
        if description is not None:
            desired["description"] = description
        args = {
            "name": name,
            "stores": stores,
            "cert_profile": cert_profile,
            "stop_on_store_error": stop_on_store_error,
            "description": description,
        }
        if current:
            changes = field_changes(current, desired, replace=True)
            if not changes:
                blockers.append(f"Nothing changes in {name}")
            plan = Plan(
                f"Update identity sequence {name}",
                details={"changes": changes},
                fingerprint=fingerprint(current),
                blockers=blockers,
                side_effects=["Authentication rules using this sequence change behaviour at once"],
            )
            return await preview_or_apply(
                ctx,
                tool="ise_set_identity_sequence",
                args=args,
                confirm=confirm,
                plan=plan,
                apply=lambda: app.ers_request(
                    "PUT",
                    f"/ers/config/idstoresequence/{current['id']}",
                    json={"IdStoreSequence": put_body(desired)},
                ),
            )
        return await preview_or_apply(
            ctx,
            tool="ise_set_identity_sequence",
            args=args,
            confirm=confirm,
            plan=Plan(
                f"Create identity sequence {name}",
                details=compact(desired),
                blockers=blockers,
                fingerprint=fingerprint({"absent": name}),
            ),
            apply=lambda: app.ers_create("idstoresequence", {"IdStoreSequence": desired}),
        )

    @reg.write(title="Delete a CSR", destructive=True)
    async def ise_delete_csr(
        ctx: Context,
        csr: Annotated[str, Field(description="CSR id or friendly name (see ise_list_csrs)")],
        node: Annotated[str | None, Field(description="Node hostname; optional with a single node")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a pending CSR and its private key on ISE (e.g. an abandoned request). A certificate
        already bound from it is not affected. Preview-first."""
        app: IseApp = get_client(ctx)
        host = await resolve_node(app, node)
        found = await find_csr(app, host, csr)
        path = "/api/v1/certs/certificate-signing-request/{}/{}".format(
            quote(host, safe=""), quote(str(found["id"]), safe="")
        )
        return await preview_or_apply(
            ctx,
            tool="ise_delete_csr",
            args={"csr": csr, "node": node},
            confirm=confirm,
            plan=Plan(
                f"Delete CSR {found.get('friendlyName')} on {host}",
                details=csr_row(found),
                fingerprint=fingerprint(found),
            ),
            apply=lambda: app.openapi.delete(path),
        )

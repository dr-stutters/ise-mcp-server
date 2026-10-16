"""pxGrid 2.0 administration (ERS pxgridnode / pxgridsettings) and certificates for pxGrid consumers
(FMC, Catalyst Center, SIEMs).

Appliance to appliance only (core ADR-003): this server never connects to pxGrid as a client, never
subscribes and never relays. It approves or removes the clients other products register, sets the
approval policy, checks the trust chain both ways and issues client certificates. The one connection to
the pxGrid port (8910) is an optional TLS handshake in ise_pxgrid_status that reads the certificate the
controller presents; no pxGrid request is sent.

ISE 3.5 quirks: ERS pxgridnode answers GET (list, by id `<name>@xgrid.cisco.com`, by /name/<name>), PUT
/name/<name>/approve and DELETE /name/<name> (DELETE by id is 405). There is no decline, enable or
disable operation. Client status is `init` (account created, never activated), `pendingApproval`,
`enabled` or `disabled`. pxgridsettings is write-only: PUT /pxgridsettings/autoapprove with both flags;
nothing reads them back (GET lists nothing, /autoapprove is 404).
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import asyncio
import contextlib
import ipaddress
import re
import secrets
import ssl
import time
from typing import Annotated, Any, Literal
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    current_caller,
    get_client,
    preview_or_apply,
)
from stutters_mcp_core.http import page_of

from ise_mcp.client import IseApp
from ise_mcp.tools._common import gather_limited, list_result, openapi_all
from ise_mcp.tools.certs import pem_certs
from ise_mcp.tools.writes import fingerprint

PXGRID_PORT = 8910
STATES = {
    "init": "created",
    "pendingApproval": "pending",
    "enabled": "enabled",
    "disabled": "disabled",
}
STATE = Literal["pending", "enabled", "disabled", "created"]
CLIENT_COLUMNS = ["name", "state", "consumer", "description", "groups"]
CLIENT_NAME = re.compile(r"~?[A-Za-z0-9._@-]{1,128}")
DNS_NAME = re.compile(r"(?=.{1,253}$)(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*")
# ISE's own pxGrid clients (they live on the ISE nodes); removing them breaks pxGrid inside ISE.
# ISE names its own clients "~ise-<service>-<node>"; a registered client can't start with "~".
ISE_INTERNAL = re.compile(r"^~ise-(admin|mnt|fanout|pubsub|bridge|sxp|ers|pxgrid)-", re.IGNORECASE)
REQUEST_TTL_SECONDS = 2 * 3600
MAX_REQUESTS = 20
SIGN_HINT = (
    "Sign the CSR at a CA ISE trusts, with a template that has Client Authentication (and Server "
    "Authentication) EKU: Windows AD CS win_sign_csr, or in this lab `dc-sign-csr.py --template "
    "mcpPxGrid` (the WebServer template has server auth only, which ISE's pxGrid refuses). Then call "
    "this tool again with request_id and certificate_pem."
)


# --- clients -------------------------------------------------------------------------------------


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def consumer_of(name: str, description: str | None) -> str | None:
    """Which product registered a client, from the names those products use."""
    low, desc = name.lower(), (description or "").lower()
    if low.startswith(("iseagent-", "firesightisetest-")):
        return "Secure Firewall Management Center (FMC)"
    if "dna center" in desc or "catalyst center" in desc:
        return "Catalyst Center"
    if ISE_INTERNAL.match(name):
        return "ISE (internal)"
    return None


def client_row(d: dict[str, Any]) -> dict[str, Any]:
    raw = str(d.get("status") or "")
    name = str(d.get("name") or "")
    return {
        "name": name,
        "state": STATES.get(raw, raw or None),
        "consumer": consumer_of(name, d.get("description")),
        "description": d.get("description"),
        "groups": d.get("groups") or None,
        "auth_method": d.get("authMethod") or None,
        "status_raw": raw or None,
        "id": d.get("id"),
    }


def client_path(name: str, op: str | None = None) -> str:
    path = f"/ers/config/pxgridnode/name/{quote(name, safe='')}"
    return f"{path}/{op}" if op else path


async def all_clients(app: IseApp) -> list[dict[str, Any]]:
    page = await app.ers_pager.fetch_page(app.ers, "/ers/config/pxgridnode", limit=5000)
    items = [i for i in page.items if isinstance(i, dict) and i.get("name")]
    full = await gather_limited(items, lambda i: app.ers_get("pxgridnode", str(i.get("id") or i["name"])), 5)
    return [client_row(f) for f in full]


async def find_client(app: IseApp, name: str) -> dict[str, Any]:
    key = name.strip().removesuffix("@xgrid.cisco.com")
    if not CLIENT_NAME.fullmatch(key):
        raise InvalidRequest(f"{name!r} is not a pxGrid client name")
    try:
        data = await app.ers_request("GET", client_path(key))
    except NotFound:
        page = await app.ers_pager.fetch_page(app.ers, "/ers/config/pxgridnode", limit=5000)
        near = [str(i.get("name")) for i in page.items if key.lower() in str(i.get("name", "")).lower()]
        hint = f" Names containing it: {', '.join(near[:5])}." if near else " See ise_list_pxgrid_clients."
        raise NotFound(f"No pxGrid client named {key!r}.{hint}", 404) from None
    body = data.get("PxgridNode", data) if isinstance(data, dict) else {}
    return client_row(body)


def next_step(row: dict[str, Any]) -> str | None:
    state = row.get("state")
    if state == "pending":
        return "Waiting for approval: ise_approve_pxgrid_client, or ise_decline_pxgrid_client"
    if state == "created":
        return (
            "Account created (password-based AccountCreate) but the client never activated it; it "
            "becomes pending at its first AccountActivate"
        )
    if state == "disabled":
        return "Disabled in the ISE GUI: the client can't use pxGrid until it is enabled there (no REST call)"
    return None


# --- certificates --------------------------------------------------------------------------------


def load_cert(pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(pem.encode())
    except ValueError as e:
        raise InvalidRequest(f"Not a readable PEM certificate: {e}") from None


def cn_of(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def sans_of(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return [str(v) for v in ext.value.get_values_for_type(x509.DNSName)]


def ekus_of(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return []
    names = {ExtendedKeyUsageOID.CLIENT_AUTH: "client_auth", ExtendedKeyUsageOID.SERVER_AUTH: "server_auth"}
    return [names.get(o, o.dotted_string) for o in ext.value]


def cert_facts(cert: x509.Certificate) -> dict[str, Any]:
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "san_dns": sans_of(cert),
        "eku": ekus_of(cert),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }


def name_matches(host: str, cert: x509.Certificate) -> bool:
    """RFC 6125-style: SAN DNS names (one leading wildcard label), else the CN when there are none."""
    names = sans_of(cert) or [cn_of(cert.subject) or ""]
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host or (n.startswith("*.") and host.split(".", 1)[-1] == n[2:] and "." in host):
            return True
    return False


def signed_by(cert: x509.Certificate, ca: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(ca)
    except Exception:  # noqa: BLE001 - InvalidSignature, wrong key type, ...
        return False
    return True


class TrustStore:
    """ISE's trusted certificates, with PEMs exported on demand (once each)."""

    def __init__(self, app: IseApp) -> None:
        self.app = app
        self.rows: list[dict[str, Any]] | None = None
        self.pems: dict[str, x509.Certificate | None] = {}

    async def all(self) -> list[dict[str, Any]]:
        if self.rows is None:
            self.rows = [
                r
                for r in await openapi_all(self.app, "/api/v1/certs/trusted-certificate")
                if isinstance(r, dict)
            ]
        return self.rows

    async def cert(self, row: dict[str, Any]) -> x509.Certificate | None:
        rid = str(row.get("id"))
        if rid not in self.pems:
            try:
                pem = await self.app.openapi.request(
                    "GET", f"/api/v1/certs/trusted-certificate/export/{quote(rid, safe='')}", expect="text"
                )
                self.pems[rid] = x509.load_pem_x509_certificate(str(pem).encode())
            except (UpstreamError, NotFound, ValueError):
                self.pems[rid] = None
        return self.pems[rid]

    async def by_cn(self, cn: str | None) -> list[dict[str, Any]]:
        return [r for r in await self.all() if cn and str(r.get("issuedTo")) == cn]

    async def chain(self, cert: x509.Certificate) -> dict[str, Any]:
        """Walk from `cert` up through ISE's trusted store, verifying each signature."""
        links: list[dict[str, Any]] = []
        pems: list[str] = []
        current = cert
        for _ in range(6):
            issuer = None
            for row in await self.by_cn(cn_of(current.issuer)):
                ca = await self.cert(row)
                if ca is not None and signed_by(current, ca):
                    issuer = (row, ca)
                    break
            if issuer is None:
                break
            row, ca = issuer
            links.append(
                {
                    "name": row.get("friendlyName"),
                    "subject": row.get("subject"),
                    "trusted_for": row.get("trustedFor"),
                    "status": row.get("status"),
                    "expires": row.get("expirationDate"),
                }
            )
            pems.append(ca.public_bytes(serialization.Encoding.PEM).decode())
            if ca.subject == ca.issuer:
                return {"trusted": True, "complete": True, "chain": links, "pems": pems}
            current = ca
        return {"trusted": bool(links), "complete": False, "chain": links, "pems": pems}

    async def chain_by_name(self, issued_by: str | None) -> list[str]:
        """Issuer names upwards for a bound system certificate (ISE gives names, not the PEM)."""
        out: list[str] = []
        name = issued_by
        for _ in range(6):
            rows = await self.by_cn(name)
            if not rows:
                break
            out.append(str(rows[0].get("issuedTo")))
            if rows[0].get("issuedBy") == rows[0].get("issuedTo"):
                break
            name = rows[0].get("issuedBy")
        return out


async def presented_cert(host: str, sni: str, timeout: float) -> x509.Certificate:  # noqa: ASYNC109
    """The certificate the pxGrid controller presents on 8910 (TLS handshake only, nothing sent)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, PXGRID_PORT, ssl=ctx, server_hostname=sni), timeout
    )
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()
    return x509.load_der_x509_certificate(der)


async def pxgrid_nodes(app: IseApp) -> list[dict[str, Any]]:
    nodes = (await app.openapi.get("/api/v1/deployment/node")).get("response") or []
    return [n for n in nodes if isinstance(n, dict)]


def runs_pxgrid(node: dict[str, Any]) -> bool:
    return any(str(s).lower() == "pxgrid" for s in node.get("services") or [])


async def server_cert_report(
    app: IseApp, store: TrustStore, node: dict[str, Any], *, probe: bool
) -> dict[str, Any]:
    """The pxGrid certificate on one node: issuer chain, hostname match, what 8910 presents."""
    host = str(node.get("hostname"))
    fqdn = str(node.get("fqdn") or host)
    system = [
        c
        for c in await openapi_all(app, f"/api/v1/certs/system-certificate/{quote(host, safe='')}")
        if isinstance(c, dict)
    ]
    bound = [c for c in system if "pxgrid" in str(c.get("usedBy") or "").lower()]
    out: dict[str, Any] = {"node": host, "fqdn": fqdn}
    problems: list[str] = []
    bound_mismatch: str | None = None
    if not bound:
        problems.append("No certificate is bound to the pxGrid role on this node")
    else:
        b = bound[0]
        names = await store.chain_by_name(b.get("issuedBy"))
        out["bound"] = {
            "name": b.get("friendlyName"),
            "issued_to": b.get("issuedTo"),
            "issued_by": b.get("issuedBy"),
            "expires": b.get("expirationDate"),
            "issuer_chain": names,
            "root": names[-1] if names else None,
        }
        if str(b.get("issuedTo") or "").lower() != fqdn.lower():
            bound_mismatch = (
                f"The pxGrid certificate is issued to {b.get('issuedTo')}, not {fqdn}: clients that "
                "check the hostname (FMC does) refuse it"
            )
        if names and "certificate services" in names[-1].lower():
            out["bound"]["note"] = (
                "Issued by ISE's internal CA: consumers must import ISE's internal CA chain, or bind a "
                "pxGrid certificate from your enterprise CA instead (ise_generate_csr usage=PXGRID -> "
                "sign -> ise_bind_certificate use_for=['pxgrid'])"
            )
    presented_ok = False
    if probe:
        target = str(node.get("ipAddress") or fqdn)
        try:
            cert = await presented_cert(target, fqdn, app.settings.probe_timeout)
        except (OSError, TimeoutError, ssl.SSLError, ValueError) as e:
            out["listener"] = {
                "address": f"{target}:{PXGRID_PORT}",
                "reachable": False,
                "detail": f"{type(e).__name__}: {str(e)[:150]} (from this server; clients may differ)",
            }
        else:
            facts = cert_facts(cert)
            chain = await store.chain(cert)
            hostname_ok = name_matches(fqdn, cert)
            presented_ok = True
            out["listener"] = {
                "address": f"{target}:{PXGRID_PORT}",
                "reachable": True,
                "presented": {k: v for k, v in facts.items() if k != "sha256"},
                "matches_bound": bool(bound) and facts["sha256"] == str(bound[0].get("sha256Fingerprint")),
                "hostname_matches_fqdn": hostname_ok,
                "chain_verified": [c["name"] for c in chain["chain"]],
                "chain_complete": chain["complete"],
            }
            if not hostname_ok:
                shown = ", ".join(facts["san_dns"]) or facts["subject"]
                problems.append(
                    f"8910 presents a certificate for {shown}, not {fqdn}: "
                    "clients that check the hostname (FMC does) refuse it"
                )
            if "client_auth" not in facts["eku"] or "server_auth" not in facts["eku"]:
                problems.append(
                    "The pxGrid certificate needs both Server and Client Authentication EKU "
                    f"(has {facts['eku'] or 'none'})"
                )
            if not chain["complete"]:
                problems.append(
                    "Could not verify the presented certificate up to a trusted root in ISE's store"
                )
    if bound_mismatch and not presented_ok:
        problems.append(bound_mismatch)
    if problems:
        out["problems"] = problems
    return out


# --- client-certificate requests (held in memory, single-use) ------------------------------------


def request_store(app: IseApp) -> dict[str, dict[str, Any]]:
    store: dict[str, dict[str, Any]] = app.__dict__.setdefault("_pxgrid_requests", {})
    now = time.monotonic()
    for rid in [r for r, v in store.items() if now - v["created"] > REQUEST_TTL_SECONDS]:
        store.pop(rid, None)
    return store


def make_csr(
    common_name: str, san_dns: list[str], key_size: int, org: str | None
) -> tuple[rsa.RSAPrivateKey, x509.CertificateSigningRequest]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san_dns]), critical=False
        )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    return key, builder.sign(key, hashes.SHA256())


def key_pem(key: rsa.RSAPrivateKey, passphrase: str | None) -> str:
    enc: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc).decode()


def public_der(key: Any) -> bytes:
    return bytes(
        key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


async def server_trust(app: IseApp, store: TrustStore) -> dict[str, Any]:
    """What a consumer must trust to verify ISE's pxGrid controller (its 'pxGrid Server CA')."""
    out: dict[str, Any] = {}
    for node in await pxgrid_nodes(app):
        if not runs_pxgrid(node):
            continue
        host = str(node.get("hostname"))
        system = [
            c
            for c in await openapi_all(app, f"/api/v1/certs/system-certificate/{quote(host, safe='')}")
            if isinstance(c, dict)
        ]
        bound = [c for c in system if "pxgrid" in str(c.get("usedBy") or "").lower()]
        if not bound:
            continue
        names = await store.chain_by_name(bound[0].get("issuedBy"))
        root_rows = await store.by_cn(names[-1]) if names else []
        root = await store.cert(root_rows[0]) if root_rows else None
        out = {
            "node": host,
            "fqdn": node.get("fqdn"),
            "pxgrid_cert_issued_to": bound[0].get("issuedTo"),
            "issuer_chain": names,
            "root": names[-1] if names else None,
            "root_pem": root.public_bytes(serialization.Encoding.PEM).decode() if root else None,
        }
        break
    return out


# --- tools ---------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:  # noqa: C901 - one registration block per tool
    @reg.read(title="List pxGrid clients")
    async def ise_list_pxgrid_clients(
        ctx: Context,
        state: Annotated[
            STATE | None,
            Field(description="Only clients in this state (pending = waiting for approval)"),
        ] = None,
        name_contains: Annotated[str | None, Field(description="Only names containing this text")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The pxGrid 2.0 clients registered with ISE (FMC, Catalyst Center, SIEMs, scripts): name,
        state (pending / enabled / disabled / created), the product that registered it when the name
        shows it (FMC uses iseagent-* and firesightisetest-*), description and groups. Pending clients
        wait for ise_approve_pxgrid_client."""
        app: IseApp = get_client(ctx)
        rows = await all_clients(app)
        if state:
            rows = [r for r in rows if r["state"] == state]
        if name_contains:
            rows = [r for r in rows if name_contains.lower() in r["name"].lower()]
        rows.sort(key=lambda r: (r["state"] != "pending", r["name"].lower()))
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=CLIENT_COLUMNS
        )

    @reg.read(title="Get a pxGrid client")
    async def ise_get_pxgrid_client(
        ctx: Context,
        name: Annotated[str, Field(description="pxGrid client (node) name, e.g. 'iseagent-fmc-...'")],
    ) -> dict[str, Any]:
        """One pxGrid client: state, the product that registered it, description, groups, and what to
        do next (approve a pending one; a 'created' account never activated)."""
        app: IseApp = get_client(ctx)
        row = await find_client(app, name)
        hint = next_step(row)
        return {k: v for k, v in {**row, "next": hint}.items() if v is not None}

    @reg.read(title="pxGrid service status")
    async def ise_pxgrid_status(
        ctx: Context,
        probe: Annotated[
            bool,
            Field(
                description="Also open a TLS handshake to each pxGrid node on 8910 to read the "
                "certificate it presents (nothing is sent)"
            ),
        ] = True,
    ) -> dict[str, Any]:
        """Is pxGrid usable for an external consumer such as FMC? Per node: whether the pxGrid persona
        runs and its node status; the certificate bound to pxGrid (issuer chain to a trusted root,
        hostname vs the node FQDN, both EKUs) and what port 8910 actually presents; the clients by
        state with the pending ones named. Lists the problems a consumer would hit (hostname mismatch,
        internal-CA chain it doesn't trust). The approval settings can't be read over ISE's REST API
        (write-only): see the `settings` note."""
        app: IseApp = get_client(ctx)
        nodes = await pxgrid_nodes(app)
        store = TrustStore(app)
        px = [n for n in nodes if runs_pxgrid(n)]
        out: dict[str, Any] = {
            "pxgrid_enabled": bool(px),
            "nodes": [
                {
                    "hostname": n.get("hostname"),
                    "fqdn": n.get("fqdn"),
                    "ip": n.get("ipAddress"),
                    "pxgrid": runs_pxgrid(n),
                    "status": n.get("nodeStatus"),
                }
                for n in nodes
            ],
        }
        if not px:
            out["hint"] = (
                "No node runs the pxGrid persona: enable it with ise_update_node_services (dangerous) "
                "on one or two PSNs/PANs"
            )
            return out
        out["certificates"] = [await server_cert_report(app, store, n, probe=probe) for n in px]
        rows = await all_clients(app)
        by_state: dict[str, int] = {}
        for r in rows:
            by_state[str(r["state"])] = by_state.get(str(r["state"]), 0) + 1
        out["clients"] = {
            "total": len(rows),
            "by_state": by_state,
            "pending": [r["name"] for r in rows if r["state"] == "pending"],
            "consumers": sorted({str(r["consumer"]) for r in rows if r["consumer"]}),
        }
        out["settings"] = {
            "readable": False,
            "note": "ISE 3.5's REST API only writes the pxGrid approval settings "
            "(ise_set_pxgrid_settings sets both); read them in the GUI: Administration > pxGrid "
            "Services > Settings. A cert-based client that lands 'pending' means auto-approve is off.",
        }
        problems = [p for c in out["certificates"] for p in c.get("problems", [])]
        if problems:
            out["problems"] = problems
        return out

    # --- writes -----------------------------------------------------------------------------------

    @reg.write(title="Approve a pxGrid client")
    async def ise_approve_pxgrid_client(
        ctx: Context,
        name: Annotated[str, Field(description="pxGrid client name (ise_list_pxgrid_clients state=pending)")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Approve a pending pxGrid client so it can look up and subscribe to ISE's pxGrid services
        (sessions, TrustSec, ANC). The client must already have registered (AccountActivate). Check
        who it is first: an approved client reads every live session. Preview-first."""
        app: IseApp = get_client(ctx)
        row = await find_client(app, name)
        blockers = []
        if row["state"] == "enabled":
            blockers.append(f"{row['name']} is already approved (enabled)")
        side = [f"{row['name']} can use pxGrid at its next AccountActivate (clients retry on their own)"]
        if row.get("consumer"):
            side.append(
                f"Looks like {row['consumer']} (inferred from the name/description the client set; verify it)"
            )
        return await preview_or_apply(
            ctx,
            tool="ise_approve_pxgrid_client",
            args={"name": name},
            confirm=confirm,
            plan=Plan(
                f"Approve pxGrid client {row['name']}",
                details={k: v for k, v in row.items() if v is not None},
                blockers=blockers,
                side_effects=side,
                fingerprint=fingerprint(row),
            ),
            apply=lambda: app.ers_request("PUT", client_path(row["name"], "approve"), json={}),
        )

    async def _remove(
        ctx: Context, *, tool: str, name: str, confirm: str | None, decline: bool
    ) -> dict[str, Any]:
        app: IseApp = get_client(ctx)
        row = await find_client(app, name)
        blockers: list[str] = []
        side: list[str] = []
        if row.get("consumer") == "ISE (internal)":
            blockers.append(f"{row['name']} is one of ISE's own pxGrid clients; removing it breaks pxGrid")
        if decline:
            if row["state"] not in ("pending", "created"):
                blockers.append(f"{row['name']} is {row['state']}, not pending: use ise_delete_pxgrid_client")
            side.append(
                "ISE's REST API has no Decline: the pending registration is deleted. The client may "
                "register again, and a cert-based client is then auto-approved if that setting is on"
            )
        else:
            if row["state"] == "enabled":
                side.append(
                    f"{row['name']} loses pxGrid access: it can't look up services or reconnect"
                    + (f" ({row['consumer']} stops getting ISE data)" if row.get("consumer") else "")
                )
            side.append(
                "A client that registers again reappears (auto-approved if cert-based auto-approve is on)"
            )
        verb = "Decline" if decline else "Delete"
        return await preview_or_apply(
            ctx,
            tool=tool,
            args={"name": name},
            confirm=confirm,
            plan=Plan(
                f"{verb} pxGrid client {row['name']}",
                details={k: v for k, v in row.items() if v is not None},
                blockers=blockers,
                side_effects=side,
                fingerprint=fingerprint(row),
                blast_radius=1,
            ),
            apply=lambda: app.ers_request("DELETE", client_path(row["name"])),
        )

    @reg.write(title="Decline a pending pxGrid client", destructive=True)
    async def ise_decline_pxgrid_client(
        ctx: Context,
        name: Annotated[str, Field(description="Pending pxGrid client name")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Refuse a pending pxGrid registration (an unknown or unwanted client). ISE's REST API has no
        Decline, so the pending registration is removed; the client can ask again. Only for pending or
        never-activated clients; an approved client is removed with ise_delete_pxgrid_client.
        Preview-first."""
        return await _remove(ctx, tool="ise_decline_pxgrid_client", name=name, confirm=confirm, decline=True)

    @reg.write(title="Delete a pxGrid client", destructive=True)
    async def ise_delete_pxgrid_client(
        ctx: Context,
        name: Annotated[str, Field(description="pxGrid client name")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Remove a pxGrid client (any state). An approved consumer (e.g. FMC's iseagent-*) loses
        access and stops receiving ISE sessions until it registers again. ISE's own internal clients are
        refused. Preview-first."""
        return await _remove(ctx, tool="ise_delete_pxgrid_client", name=name, confirm=confirm, decline=False)

    @reg.write(title="Set the pxGrid approval settings")
    async def ise_set_pxgrid_settings(
        ctx: Context,
        auto_approve_cert_accounts: Annotated[
            bool,
            Field(
                description="Approve clients that authenticate with a certificate from a CA ISE trusts "
                "without review (FMC and Catalyst Center use certificates)"
            ),
        ],
        allow_password_accounts: Annotated[
            bool,
            Field(description="Allow clients to create password-based accounts (AccountCreate)"),
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set pxGrid's approval policy (Administration > pxGrid Services > Settings). ISE's API writes
        both flags together and can't read them back, so give both. Auto-approve means any client with a
        certificate ISE trusts gets session data without an admin looking at it; off means each new
        client waits for ise_approve_pxgrid_client. Preview-first."""
        app: IseApp = get_client(ctx)
        body = {
            "PxgridSettings": {
                "autoApproveCertBasedAccounts": auto_approve_cert_accounts,
                "allowPasswordBasedAccounts": allow_password_accounts,
            }
        }
        side = ["ISE can't report the current values over REST; both are set to the values shown"]
        side.append(
            "New cert-based clients are approved automatically"
            if auto_approve_cert_accounts
            else "New cert-based clients wait as pending until approved (existing approvals stay)"
        )
        if not allow_password_accounts:
            side.append("New password-based AccountCreate requests are refused")
        return await preview_or_apply(
            ctx,
            tool="ise_set_pxgrid_settings",
            args={
                "auto_approve_cert_accounts": auto_approve_cert_accounts,
                "allow_password_accounts": allow_password_accounts,
            },
            confirm=confirm,
            plan=Plan(
                "Set pxGrid settings: auto-approve cert-based "
                f"{'on' if auto_approve_cert_accounts else 'off'}, password-based accounts "
                f"{'allowed' if allow_password_accounts else 'refused'}",
                details=body["PxgridSettings"],
                side_effects=side,
                fingerprint=fingerprint(body),
            ),
            apply=lambda: app.ers_request("PUT", "/ers/config/pxgridsettings/autoapprove", json=body),
        )

    @reg.write(title="Issue a pxGrid client certificate")
    async def ise_issue_pxgrid_client_cert(
        ctx: Context,
        common_name: Annotated[
            str, Field(description="Subject CN of the consumer, e.g. FMC's FQDN 'fmc.example.com'")
        ],
        san_dns: Annotated[
            list[str] | None, Field(description="DNS subject alternative names; default [common_name]")
        ] = None,
        organization: Annotated[str | None, Field(description="Subject O")] = None,
        key_size: Annotated[Literal[2048, 3072, 4096], Field(description="RSA key size")] = 2048,
        request_id: Annotated[str | None, Field(description="Step 2: the request_id step 1 returned")] = None,
        certificate_pem: Annotated[
            str | None, Field(description="Step 2: the certificate the CA signed (PEM)")
        ] = None,
        chain_pem: Annotated[
            str | None,
            Field(description="Step 2, optional: the issuing CA chain (PEM); default from ISE's trust store"),
        ] = None,
        key_passphrase: Annotated[
            str | None,
            Field(description="Step 2, optional: encrypt the returned private key with this passphrase"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Issue the certificate an external pxGrid consumer (FMC, a SIEM) authenticates to ISE with.
        Step 1 (common_name only): this server generates an RSA key and a CSR (Client + Server
        Authentication EKU); the key stays in server memory (2 h, never logged) and the CSR comes back
        with a request_id. Sign it at a CA ISE trusts. Step 2 (same common_name + request_id +
        certificate_pem): the preview checks the certificate matches the key, has Client
        Authentication, is valid, and chains to a CA ISE trusts for pxGrid; confirming returns the
        bundle once (certificate, private key, CA chain, and the CA the consumer must trust for ISE's
        pxGrid server) and forgets the key. ISE itself is not changed. Preview-first."""
        app: IseApp = get_client(ctx)
        cn = common_name.strip()
        if not cn or any(c in cn for c in '\r\n/\\,+=<>;"') or len(cn) > 64:
            raise InvalidRequest("common_name: up to 64 characters, no / \\ , + = < > ; or quotes")
        sans = [
            s.strip()
            for s in (san_dns if san_dns is not None else ([cn] if "." in cn and not is_ip(cn) else []))
        ]
        for s in sans:
            if not DNS_NAME.fullmatch(s):
                raise InvalidRequest(f"{s!r} is not a DNS name")
        requests = request_store(app)
        caller = current_caller()
        args = {
            "common_name": common_name,
            "san_dns": san_dns,
            "organization": organization,
            "key_size": key_size,
            "request_id": request_id,
            "certificate_pem": certificate_pem,
            "chain_pem": chain_pem,
            "key_passphrase": key_passphrase,
        }

        if request_id is None:
            if certificate_pem or chain_pem or key_passphrase:
                raise InvalidRequest(
                    "certificate_pem/chain_pem/key_passphrase belong to step 2 (with request_id)"
                )
            blockers = []
            if sum(1 for r in requests.values() if r["caller"] == caller) >= MAX_REQUESTS:
                blockers.append(
                    f"{MAX_REQUESTS} certificate requests are open; finish or let them expire (2 h)"
                )

            async def start() -> dict[str, Any]:
                key, csr = await asyncio.to_thread(make_csr, cn, sans, key_size, organization)
                rid = "pxr_" + secrets.token_hex(12)
                requests[rid] = {"key": key, "cn": cn, "caller": caller, "created": time.monotonic()}
                return {
                    "request_id": rid,
                    "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
                    "expires_in_seconds": REQUEST_TTL_SECONDS,
                    "next": SIGN_HINT,
                }

            return await preview_or_apply(
                ctx,
                tool="ise_issue_pxgrid_client_cert",
                args=args,
                confirm=confirm,
                plan=Plan(
                    f"Generate a key and CSR for pxGrid client certificate CN={cn}",
                    details={
                        "subject": f"CN={cn}" + (f", O={organization}" if organization else ""),
                        "san_dns": sans,
                        "key": f"RSA {key_size} (generated here, held in memory, returned once at step 2)",
                        "eku_requested": ["client_auth", "server_auth"],
                    },
                    blockers=blockers,
                    side_effects=["Nothing changes on ISE"],
                    fingerprint=fingerprint({"new": cn, "sans": sans}),
                ),
                apply=start,
            )

        # --- step 2: check the signed certificate, then release the bundle ----------------------
        req = requests.get(request_id)
        if req is None:
            raise NotFound(
                f"No open certificate request {request_id!r} (expired after 2 h, or already used)", 404
            )
        if req["caller"] != caller:  # same answer as an unknown id: don't reveal other callers' requests
            raise NotFound(
                f"No open certificate request {request_id!r} (expired after 2 h, or already used)", 404
            )
        if req["cn"] != cn:
            raise InvalidRequest(f"Request {request_id} is for CN={req['cn']}, not {cn}")
        if key_passphrase is not None and len(key_passphrase) < 8:
            raise InvalidRequest(
                "key_passphrase must be at least 8 characters (omit it for an unencrypted key)"
            )
        if not certificate_pem:
            raise InvalidRequest("Step 2 needs certificate_pem (the signed certificate)")
        leaf_pem = pem_certs(certificate_pem)
        cert = load_cert(leaf_pem[0])
        given_chain = [load_cert(p) for p in pem_certs(chain_pem)] if chain_pem else []
        given_chain += [load_cert(p) for p in leaf_pem[1:]]
        facts = cert_facts(cert)
        blockers = []
        warnings: list[str] = []
        if public_der(cert.public_key()) != public_der(req["key"].public_key()):
            blockers.append("The certificate is not for this request's key (wrong CSR signed?)")
        if "client_auth" not in facts["eku"]:
            blockers.append(
                f"No Client Authentication EKU (has {facts['eku'] or 'none'}): ISE's pxGrid refuses the "
                "client. Sign with a template that includes it (lab: mcpPxGrid)"
            )
        if "server_auth" not in facts["eku"]:
            warnings.append("No Server Authentication EKU: FMC expects both on its pxGrid certificate")
        now = time.time()
        if cert.not_valid_after_utc.timestamp() < now or cert.not_valid_before_utc.timestamp() > now:
            blockers.append(f"The certificate is not valid now (until {facts['not_after']})")
        if cn_of(cert.subject) != cn:
            warnings.append(f"The CA changed the subject to {facts['subject']}")
        store = TrustStore(app)
        chain = await store.chain(cert)
        if not chain["trusted"]:
            blockers.append(
                f"The issuer ({facts['issuer']}) is not in ISE's trusted store, so ISE refuses this "
                "client on 8910: ise_import_trusted_cert (trust_for ise_auth + client_auth) first"
            )
        elif "infrastructure" not in str(chain["chain"][0].get("trusted_for") or "").lower():
            blockers.append(
                f"ISE trusts {chain['chain'][0]['name']} only for {chain['chain'][0].get('trusted_for')}; "
                "pxGrid clients need 'Trust for authentication within ISE' (ise_auth)"
            )
        if given_chain:
            ok = all(
                any(signed_by(c, p) for p in given_chain) or c.subject == c.issuer
                for c in [cert, *given_chain]
            )
            if not ok:
                blockers.append("chain_pem does not link up to the certificate's issuer")
            chain_out = [c.public_bytes(serialization.Encoding.PEM).decode() for c in given_chain]
        else:
            chain_out = chain["pems"]
        server = await server_trust(app, store)
        if server.get("root") and chain["chain"] and server["root"] != chain["chain"][-1].get("name"):
            warnings.append(
                f"ISE's pxGrid server certificate chains to {server['root']}, not to this certificate's "
                f"root: the consumer must trust {server['root']} too (server_ca_pem)"
            )
        if (
            server.get("pxgrid_cert_issued_to")
            and server.get("fqdn")
            and (str(server["pxgrid_cert_issued_to"]).lower() != str(server["fqdn"]).lower())
        ):
            warnings.append(
                f"ISE's pxGrid certificate is issued to {server['pxgrid_cert_issued_to']}, not "
                f"{server['fqdn']}: the consumer's hostname check fails (ise_pxgrid_status)"
            )

        def bundle() -> dict[str, Any]:
            held = requests.get(request_id)
            if held is None:
                raise NotFound(f"Certificate request {request_id} was already used", 404)
            private = key_pem(held["key"], key_passphrase)  # serialise first: a failure keeps the key
            requests.pop(request_id, None)
            return {
                "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
                "private_key_pem": private,
                "private_key_encrypted": bool(key_passphrase),
                "chain_pem": "".join(chain_out),
                "server_ca_pem": server.get("root_pem"),
                "server": {k: v for k, v in server.items() if k != "root_pem"},
                "note": "The private key is shown only now and is no longer held by this server. Store it "
                "with restricted permissions; FMC: Objects > PKI > Internal Certs (certificate + key), the "
                "CA chain as a Trusted CA, and server_ca_pem as the pxGrid Server CA and MNT Server CA.",
            }

        async def release() -> dict[str, Any]:
            return bundle()

        details = {
            "certificate": {k: v for k, v in facts.items()},
            "key_matches": public_der(cert.public_key()) == public_der(req["key"].public_key()),
            "trusted_in_ise": [c["name"] for c in chain["chain"]],
            "chain_complete": chain["complete"],
            "pxgrid_server": {k: v for k, v in server.items() if k != "root_pem"},
            "private_key": "returned once on confirm"
            + (" (PKCS#8, encrypted with key_passphrase)" if key_passphrase else " (PKCS#8, unencrypted)"),
        }
        if warnings:
            details["warnings"] = warnings
        return await preview_or_apply(
            ctx,
            tool="ise_issue_pxgrid_client_cert",
            args=args,
            confirm=confirm,
            plan=Plan(
                f"Release the pxGrid client certificate bundle for CN={cn}",
                details=details,
                blockers=blockers,
                side_effects=["Nothing changes on ISE; the private key leaves this server's memory"],
                fingerprint=fingerprint([request_id, facts["sha256"]]),
            ),
            apply=release,
        )

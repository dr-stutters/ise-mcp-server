"""Certificate lifecycle (OpenAPI certs) and EAP-TLS building blocks (ERS certificateprofile,
idstoresequence): CSR -> signed by any CA -> bind; trusted CA import; certificate authentication
profile and identity source sequence.

CA-agnostic: the tools exchange PEM text, so the signing step can be a Windows AD CS (win_sign_csr), an
OpenSSL or step-ca lab CA, or a public CA.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import base64
import re
from typing import Annotated, Any, Literal
from urllib.parse import quote

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
    compact,
    field_changes,
    get_client,
    preview_or_apply,
)
from stutters_mcp_core.http import page_of

from ise_mcp.client import IseApp
from ise_mcp.tools._common import list_result, openapi_all
from ise_mcp.tools.writes import fingerprint, put_body

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
            changes = field_changes(current, desired)
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
            changes = field_changes(current, desired)
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

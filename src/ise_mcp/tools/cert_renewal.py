"""Prompt ise_cert_renewal (I52): renew an expiring ISE system certificate end to end.

Expiring certificate (ise_list_certificates) -> CSR (ise_generate_csr, ise_export_csr) -> signed by the lab
CA through the Windows_Server MCP (win_sign_csr) or any CA the user runs -> the issuing chain in the trust
store (ise_import_trusted_cert) -> bound in a change window (ise_bind_certificate; the Admin role restarts the
application server, so it is the dangerous tier and always previewed) -> EAP-TLS checked again in MnT.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from typing import Annotated, Literal

from pydantic import Field

from ise_mcp._core import InvalidRequest, Tier, ToolRegistrar, tool_ref
from ise_mcp.tools._common import normalize_mac

# Prompt arguments are interpolated into instructions, so they are held to strict shapes.
SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
SAFE_TEMPLATE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")

ROLES = Literal["eap", "admin", "portal", "pxgrid", "radius", "saml", "ims", "tacacs"]
# role (ise_bind_certificate use_for) -> (ise_generate_csr usage, the name ISE shows in used_by)
ROLE_INFO: dict[str, tuple[str, str]] = {
    "eap": ("EAP-AUTH", "EAP Authentication"),
    "admin": ("ADMIN", "Admin"),
    "portal": ("PORTAL", "Portal"),
    "pxgrid": ("PXGRID", "pxGrid"),
    "radius": ("DTLS-AUTH", "RADIUS DTLS"),
    "saml": ("SAML", "SAML"),
    "ims": ("IMS", "ISE Messaging Service"),
    "tacacs": ("TACACS", "TACACS"),
}
# ISE tools the prompt runs (write tier at least: the prompt is hidden on a read-only server).
READ_TOOLS = [
    "ise_list_nodes",
    "ise_list_certificates",
    "ise_list_csrs",
    "ise_export_csr",
    "ise_get_auth_history",
    "ise_recent_auth_failures",
    "ise_status",
]
WRITE_TOOLS = ["ise_generate_csr", "ise_import_trusted_cert", "ise_delete_csr"]
DANGEROUS_TOOLS = ["ise_bind_certificate"]
WIN_TOOLS = ["win_adcs_ca_info", "win_list_ca_templates", "win_sign_csr", "win_get_ca_certificate"]


def register(reg: ToolRegistrar) -> None:
    on = {t: t in reg.tiers for t in DANGEROUS_TOOLS}

    @reg.prompt(
        title="Renew an expiring ISE certificate",
        uses=["ise", "win"],
        tier=Tier.WRITE,
        example={"role": "eap", "node": "ise-psn1", "days": "60", "test_mac": "AA:BB:CC:DD:EE:FF"},
        tools=[*READ_TOOLS, *WRITE_TOOLS, *(t for t, enabled in on.items() if enabled), *WIN_TOOLS],
    )
    def ise_cert_renewal(
        role: Annotated[
            ROLES,
            Field(
                description="Certificate role to renew: eap (EAP-TLS/PEAP server certificate), admin "
                "(restarts the application server), portal, pxgrid, radius (RADIUS DTLS), saml, ims, tacacs"
            ),
        ] = "eap",
        node: Annotated[
            str, Field(description="ISE node hostname (see ise_list_nodes); empty: every node in turn")
        ] = "",
        days: Annotated[
            int, Field(ge=1, le=730, description="Renew certificates that expire within this many days")
        ] = 60,
        template: Annotated[
            str,
            Field(
                description="AD CS certificate template for win_sign_csr (e.g. 'WebServer'; pxGrid needs one "
                "with client and server authentication)"
            ),
        ] = "WebServer",
        test_mac: Annotated[
            str,
            Field(description="Optional: MAC of an EAP-TLS client to re-authenticate and check afterwards"),
        ] = "",
        change_ref: Annotated[
            str, Field(description="Optional change/ticket number the window runs under, e.g. 'CHG0012345'")
        ] = "",
    ) -> str:
        """Renew an expiring ISE system certificate the way a change window does it: find what expires
        (ise_list_certificates) and the EAP-TLS baseline, generate a CSR with the same subject and SANs
        (ise_generate_csr, ise_export_csr), sign it at the lab CA with win_sign_csr (Windows_Server MCP;
        without it any CA, marked skipped), import the issuing chain (ise_import_trusted_cert), bind the
        signed certificate in the change window (ise_bind_certificate: the Admin role restarts the
        application server, dangerous and previewed), then verify the new certificate is in service and
        EAP-TLS still works (ise_get_auth_history, ise_recent_auth_failures). Every change is a preview the
        user approves."""
        node = node.strip()
        if node and not SAFE_HOST.match(node):
            raise InvalidRequest("node must be an ISE node hostname (letters, digits, . -)")
        template = template.strip() or "WebServer"
        if not SAFE_TEMPLATE.match(template):
            raise InvalidRequest("template must be an AD CS template name (letters, digits, spaces, _ . -)")
        mac = normalize_mac(test_mac) if test_mac.strip() else ""
        change_ref = change_ref.strip()
        if change_ref and not SAFE_REF.match(change_ref):
            raise InvalidRequest("change_ref must be a ticket number (letters, digits, _ . -)")

        usage, used_by = ROLE_INFO[role]
        node_arg = f', node="{node}"' if node else ""
        nodes_arg = f'nodes=["{node}"]' if node else "nodes=[<the node>]"
        scope = f"on {node}" if node else "on each node that has one (one node per pass, PSNs one at a time)"
        window = f" under change {change_ref}" if change_ref else ""
        change_line = (
            f"Change: {change_ref}."
            if change_ref
            else "Change window: ask the user for the change number and the window; keep both in the report."
        )
        restart = role == "admin"

        bind_ref = tool_ref("ise_bind_certificate") if on["ise_bind_certificate"] else ""
        if bind_ref:
            bind_step = f"""{bind_ref} with csr=<the CSR id from step 4>, certificate_pem=<the signed
   leaf from step 5, PEM>, use_for=["{role}"]{node_arg} WITHOUT confirm (dangerous tier). Read the
   preview to the user: the node, the role, and the certificate that "moves off" the role (it stays
   on the node, unused, for rollback)."""
        else:
            bind_step = f"""ise_bind_certificate is not enabled on this server (dangerous tier: set
   MCP_ENABLE_DANGEROUS to run it here). Give the user the GUI step instead: Administration > System >
   Certificates > Certificate Signing Requests > select the CSR > Bind Certificate, upload the signed
   leaf from step 5, tick {used_by} only. Wait for them to say it is done."""
        restart_text = (
            f"""   The Admin role RESTARTS the application server on the node: its GUI and API (and this
   server's calls to it) are down for several minutes, and on a PSN its RADIUS is down too. Bind only
   inside the window{window}, one node at a time, never every PSN at once. After confirming, poll
   {tool_ref("ise_status")} every minute or two (no tight loop) until the node answers again."""
            if restart
            else f"""   {used_by} needs no restart, but every client that validates the server certificate
   sees the new one at its next handshake. If the issuer changed (step 1 vs step 5), make sure the clients
   trust the new CA first (GPO/MDM): otherwise they reject ISE and EAP fails (step 8)."""
        )
        if mac:
            baseline = f"""{tool_ref("ise_get_auth_history")} with mac="{mac}", minutes=1440,
   include_steps=true: the last EAP-TLS pass for this client (keep the time, NAD, method and policy
   hit as the baseline).
   No pass in a day: ask the user to connect the client once before the window."""
            verify_mac = f"""{tool_ref("ise_get_auth_history")} with mac="{mac}", minutes=30,
      include_steps=true after the user re-authenticates the client (unplug/replug, Wi-Fi off/on or a
      CoA): a pass with the same method and policy hit as the baseline is the proof."""
        else:
            baseline = """no test client given: ask the user for the MAC of one EAP-TLS client to re-test, or
   rely on the failure view in step 8 alone (say so in the report)."""
            verify_mac = """no test client: ask the user to re-authenticate one EAP-TLS client and give
      its MAC, then read its history the same way."""
        cleanup = f"""   A CSR the window did not use: {tool_ref("ise_delete_csr")} (preview first)."""

        return f"""Renew the ISE {used_by} certificate {scope}: certificates that expire within {days} days.
{change_line}

Rules for every write below: call the tool WITHOUT confirm, show the preview and wait for the user's
approval; never pass confirm yourself. The private key never leaves ISE: only the CSR and the signed
certificate (both public) move. The win_* tools need the Windows_Server server: if it is not
connected, mark the signing steps "skipped (server not connected)", hand the CSR to the user for any
CA they run, and wait for the signed certificate and the CA chain as PEM.

1. What expires. {tool_ref("ise_list_certificates")} with kind="system"{node_arg},
   expiring_within_days={days}, response_format="json". Keep the rows whose used_by has "{used_by}":
   name, id, node, issued_to, issued_by, expires, days_left. None: say "nothing to renew within {days}
   days" with the current {used_by} certificate's expiry (the same call without expiring_within_days)
   and stop. Also {tool_ref("ise_list_certificates")} with kind="trusted", expiring_within_days={days}:
   an expiring issuing CA is renewed with the leaf (step 6).

2. Baseline before the change. {baseline}
   Then {tool_ref("ise_recent_auth_failures")} with since_minutes=60: the failure count and reasons now,
   so step 8 compares like with like.

3. CSR. {tool_ref("ise_list_csrs")}{node_arg.replace(", ", " with ")}: a pending {usage} CSR for the node
   can be reused. Otherwise {tool_ref("ise_generate_csr")} with usage="{usage}", {nodes_arg},
   common_name=<the CN of the certificate from step 1, or "$FQDN$">, san_dns=<its DNS names: the node
   FQDN plus any alias clients use>, key_type and key_length as before (RSA 2048 at least),
   digest="SHA-256". Preview first; generating a CSR changes nothing in service.

4. Export. {tool_ref("ise_list_csrs")} for the new CSR's id, then {tool_ref("ise_export_csr")} with
   csr=<that id>{node_arg}: the csr_pem.

5. Sign. {tool_ref("win_adcs_ca_info")} (the CA's name) and {tool_ref("win_list_ca_templates")}: the
   template "{template}" must be listed and give server authentication (pxGrid: client and server).
   Then {tool_ref("win_sign_csr")} with csr_pem=<step 4>, template="{template}": the signed leaf.
   {tool_ref("win_get_ca_certificate")}: the CA certificate (root, and any intermediate the user
   names). Without the Windows_Server server: "skipped (server not connected)", the user signs at their
   CA and pastes the leaf and the chain. Check the leaf before going on: subject and SANs as in step 3,
   issuer as expected, valid from now, and the expiry well past the old one.

6. Trust the chain. {tool_ref("ise_list_certificates")} with kind="trusted": every CA in the new
   chain must be there and not expiring. For each missing one, root first, then intermediates:
   {tool_ref("ise_import_trusted_cert")} with name=<the CA name and year>, certificate_pem=<that one CA
   certificate>, trust_for=["client_auth", "ise_auth"] (EAP-TLS client certificates and the bind need
   both). Preview first. ISE refuses to bind a certificate whose issuer it does not trust.

7. Bind in the change window. {bind_step}
{restart_text}

8. Verify.
   a. {tool_ref("ise_list_certificates")} with kind="system"{node_arg}: the new certificate's used_by
      has "{used_by}", its expiry is the new one, and the old certificate shows "Not in use".
   b. {verify_mac}
   c. {tool_ref("ise_recent_auth_failures")} with since_minutes=30 against the step 2 count. New
      12520 / 12321 failures (the client rejected ISE's certificate in the TLS handshake) mean the
      clients do not trust the new server certificate or its issuer: roll back (9) or push the CA.

9. Rollback (keep it ready, only on the user's word). The old certificate stays on the node: give it
   back the {used_by} role in the GUI (Administration > System > Certificates > System Certificates >
   edit > Usage){" (another application server restart)" if restart else ""}, then re-run step 8.
{cleanup}

Report: node(s), role, old and new certificate (issuer, expiry), CSR id, the CA that signed it (or
"skipped (server not connected)"), the chain imported, the bind time{window}, and the step 8 evidence
(certificate in use, test client pass, failure counts before and after). Leave the old certificate
in place until the clients have been fine for a while; deleting it is a separate change."""

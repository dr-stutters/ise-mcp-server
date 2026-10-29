# ise_cert_renewal

title: Renew an expiring ISE certificate
arguments: {"change_ref": "CHG0012345", "days": "60", "node": "ise-psn1", "role": "eap", "template": "WebServer", "test_mac": "aa:bb:cc:dd:ee:ff"}

Renew an expiring ISE system certificate the way a change window does it: find what expires
(ise_list_certificates) and the EAP-TLS baseline, generate a CSR with the same subject and SANs
(ise_generate_csr, ise_export_csr), sign it at the lab CA with win_sign_csr (Windows_Server MCP;
without it any CA, marked skipped), import the issuing chain (ise_import_trusted_cert), bind the
signed certificate in the change window (ise_bind_certificate: the Admin role restarts the
application server, dangerous and previewed), then verify the new certificate is in service and
EAP-TLS still works (ise_get_auth_history, ise_recent_auth_failures). Every change is a preview the
user approves.

## user

Renew the ISE EAP Authentication certificate on ise-psn1: certificates that expire within 60 days.
Change: CHG0012345.

Rules for every write below: call the tool WITHOUT confirm, show the preview and wait for the user's
approval; never pass confirm yourself. The private key never leaves ISE: only the CSR and the signed
certificate (both public) move. The win_* tools need the Windows_Server server: if it is not
connected, mark the signing steps "skipped (server not connected)", hand the CSR to the user for any
CA they run, and wait for the signed certificate and the CA chain as PEM.

1. What expires. `ise_list_certificates` with kind="system", node="ise-psn1",
   expiring_within_days=60, response_format="json". Keep the rows whose used_by has "EAP Authentication":
   name, id, node, issued_to, issued_by, expires, days_left. None: say "nothing to renew within 60
   days" with the current EAP Authentication certificate's expiry (the same call without expiring_within_days)
   and stop. Also `ise_list_certificates` with kind="trusted", expiring_within_days=60:
   an expiring issuing CA is renewed with the leaf (step 6).

2. Baseline before the change. `ise_get_auth_history` with mac="AA:BB:CC:DD:EE:FF", minutes=1440,
   include_steps=true: the last EAP-TLS pass for this client (keep the time, NAD, method and policy
   hit as the baseline).
   No pass in a day: ask the user to connect the client once before the window.
   Then `ise_recent_auth_failures` with since_minutes=60: the failure count and reasons now,
   so step 8 compares like with like.

3. CSR. `ise_list_csrs` with node="ise-psn1": a pending EAP-AUTH CSR for the node
   can be reused. Otherwise `ise_generate_csr` with usage="EAP-AUTH", nodes=["ise-psn1"],
   common_name=<the CN of the certificate from step 1, or "$FQDN$">, san_dns=<its DNS names: the node
   FQDN plus any alias clients use>, key_type and key_length as before (RSA 2048 at least),
   digest="SHA-256". Preview first; generating a CSR changes nothing in service.

4. Export. `ise_list_csrs` for the new CSR's id, then `ise_export_csr` with
   csr=<that id>, node="ise-psn1": the csr_pem.

5. Sign. `win_adcs_ca_info` (the CA's name) and `win_list_ca_templates`: the
   template "WebServer" must be listed and give server authentication (pxGrid: client and server).
   Then `win_sign_csr` with csr_pem=<step 4>, template="WebServer": the signed leaf.
   `win_get_ca_certificate`: the CA certificate (root, and any intermediate the user
   names). Without the Windows_Server server: "skipped (server not connected)", the user signs at their
   CA and pastes the leaf and the chain. Check the leaf before going on: subject and SANs as in step 3,
   issuer as expected, valid from now, and the expiry well past the old one.

6. Trust the chain. `ise_list_certificates` with kind="trusted": every CA in the new
   chain must be there and not expiring. For each missing one, root first, then intermediates:
   `ise_import_trusted_cert` with name=<the CA name and year>, certificate_pem=<that one CA
   certificate>, trust_for=["client_auth", "ise_auth"] (EAP-TLS client certificates and the bind need
   both). Preview first. ISE refuses to bind a certificate whose issuer it does not trust.

7. Bind in the change window. `ise_bind_certificate` with csr=<the CSR id from step 4>, certificate_pem=<the signed
   leaf from step 5, PEM>, use_for=["eap"], node="ise-psn1" WITHOUT confirm (dangerous tier). Read the
   preview to the user: the node, the role, and the certificate that "moves off" the role (it stays
   on the node, unused, for rollback).
   EAP Authentication needs no restart, but every client that validates the server certificate
   sees the new one at its next handshake. If the issuer changed (step 1 vs step 5), make sure the clients
   trust the new CA first (GPO/MDM): otherwise they reject ISE and EAP fails (step 8).

8. Verify.
   a. `ise_list_certificates` with kind="system", node="ise-psn1": the new certificate's used_by
      has "EAP Authentication", its expiry is the new one, and the old certificate shows "Not in use".
   b. `ise_get_auth_history` with mac="AA:BB:CC:DD:EE:FF", minutes=30,
      include_steps=true after the user re-authenticates the client (unplug/replug, Wi-Fi off/on or a
      CoA): a pass with the same method and policy hit as the baseline is the proof.
   c. `ise_recent_auth_failures` with since_minutes=30 against the step 2 count. New
      12520 / 12321 failures (the client rejected ISE's certificate in the TLS handshake) mean the
      clients do not trust the new server certificate or its issuer: roll back (9) or push the CA.

9. Rollback (keep it ready, only on the user's word). The old certificate stays on the node: give it
   back the EAP Authentication role in the GUI (Administration > System > Certificates > System Certificates >
   edit > Usage), then re-run step 8.
   A CSR the window did not use: `ise_delete_csr` (preview first).

Report: node(s), role, old and new certificate (issuer, expiry), CSR id, the CA that signed it (or
"skipped (server not connected)"), the chain imported, the bind time under change CHG0012345, and the step 8 evidence
(certificate in use, test client pass, failure counts before and after). Leave the old certificate
in place until the clients have been fine for a while; deleting it is a separate change.

"""Hand-curated ISE knowledge used by the troubleshooting tools.

MnT's FailureReasons catalog only covers failure codes. Execution steps (11001, 15041, ...) are
message codes from the ISE Live Log details; the common ones are listed here (best effort).
"""

from __future__ import annotations

STEP_CODES: dict[str, str] = {
    "11001": "Received RADIUS Access-Request",
    "11002": "Returned RADIUS Access-Accept",
    "11003": "Returned RADIUS Access-Reject",
    "11004": "Received RADIUS Accounting-Request",
    "11005": "Returned RADIUS Accounting-Response",
    "11006": "Returned RADIUS Access-Challenge",
    "11017": "RADIUS created a new session",
    "11018": "RADIUS is re-using an existing session",
    "11027": "Detected Host Lookup UseCase (Service-Type = Call Check (10))",
    "11117": "Generated a new session ID",
    "11507": "Extracted EAP-Response/Identity",
    "11504": "Prepared EAP-Failure",
    "11503": "Prepared EAP-Success",
    "12000": "Prepared EAP-Request proposing EAP-MD5 with challenge",
    "12001": "Extracted EAP-Response/NAK requesting to use EAP-MD5 instead",
    "12002": "Extracted EAP-Response containing EAP-MD5 challenge-response",
    "12004": "Prepared EAP-Request proposing EAP-MSCHAPv2 with challenge",
    "12300": "Prepared EAP-Request proposing PEAP with challenge",
    "12301": "Extracted EAP-Response/NAK requesting to use PEAP instead",
    "12302": "Extracted EAP-Response containing PEAP challenge-response and accepting PEAP as negotiated",
    "12305": "Prepared EAP-Request with another PEAP challenge",
    "12304": "Extracted EAP-Response containing PEAP challenge-response",
    "12306": "PEAP authentication succeeded",
    "12625": "Valid EAP-Key-Name attribute received",
    "12500": "Prepared EAP-Request proposing EAP-TLS with challenge",
    "12502": "Extracted EAP-Response with EAP-TLS challenge-response; EAP-TLS negotiated",
    "12800": "Extracted first TLS record; TLS handshake started",
    "12816": "TLS handshake succeeded",
    "13015": "Returned TACACS+ Authentication Reply",
    "13013": "Received TACACS+ Authentication START Request",
    "15004": "Matched rule",
    "15006": "Matched Default Rule",
    "15008": "Evaluating Service Selection Policy",
    "15012": "Selected Access Service",
    "15013": "Selected Identity Source",
    "15016": "Selected Authorization Profile",
    "15036": "Evaluating Authorization Policy",
    "15041": "Evaluating Identity Policy",
    "15048": "Queried PIP (policy information point) for an attribute",
    "15049": "Evaluating Policy Group",
    "22016": "Identity sequence completed iterating the identity stores",
    "22037": "Authentication Passed",
    "22056": "Subject not found in the applicable identity store(s)",
    "22057": "The advanced option configured for a failed authentication request is used",
    "22058": "The advanced option configured for an unknown user is used",
    "22061": "The 'Reject' advanced option is configured in case of a failed authentication request",
    "22063": "Wrong password; the 'Reject' advanced option applies",
    "22072": "Selected identity source sequence",
    "22080": "New accounting session created in Session cache",
    "22081": "Max sessions policy passed",
    "22083": "Accounting session updated in Session cache",
    "22085": "Session cache entry closed (Accounting Stop)",
    "24209": "Looking up Endpoint in Internal Endpoints identity store",
    "24210": "Looking up User in Internal Users identity store",
    "24211": "Found Endpoint in Internal Endpoints identity store",
    "24212": "Found User in Internal Users identity store",
    "24216": "The user is not found in the internal users identity store",
    "24217": "The host is not found in the internal endpoints identity store",
    "24313": "Search for matching accounts at join point",
    "24318": "No matching account found in forest",
    "24319": "Single matching account found in forest",
    "24323": "Identity resolution detected single matching account",
    "24325": "Resolving identity (Active Directory)",
    "24343": "RPC Logon request succeeded (Active Directory)",
    "24344": "RPC Logon request failed (Active Directory)",
    "24355": "LDAP fetch succeeded (Active Directory)",
    "24402": "User authentication against Active Directory succeeded",
    "24416": "User's groups retrieval from Active Directory succeeded",
    "24430": "Authenticating user against Active Directory",
    "24432": "Looking up user in Active Directory",
    "24715": "ISE has not confirmed locally previous successful machine authentication for user in AD",
    "5200": "Authentication succeeded",
    "5400": "Authentication failed",
    "5405": "RADIUS request dropped",
    "5434": "Endpoint conducted several failed authentications of the same scenario",
    "5440": "Endpoint abandoned EAP session and started new",
}

# Likely cause / next step for the most common failure codes, phrased for an operator. The MnT
# catalog's own cause/resolution text is added alongside this.
FAILURE_HINTS: dict[str, dict[str, str]] = {
    "11007": {
        "likely": "ISE has no network device (NAD) for the RADIUS source IP.",
        "check": "ise_get_nad with the NAS IP; add the switch/WLC as a NAD (ise_create_nad).",
    },
    "11036": {
        "likely": "Message-Authenticator invalid: the RADIUS shared secret on the NAD and in ISE differ.",
        "check": "Re-enter the shared secret on both sides (ise_update_nad).",
    },
    "5411": {
        "likely": "The supplicant stopped responding (often the client rejected the ISE EAP certificate).",
        "check": "Check the client trusts the CA of the ISE EAP certificate (ise_list_certificates).",
    },
    "12321": {
        "likely": "The client rejected the ISE EAP certificate during PEAP.",
        "check": "Ensure clients trust the issuer of the EAP system certificate (ise_list_certificates).",
    },
    "12514": {
        "likely": "The client certificate was issued by a CA that ISE doesn't trust for client "
        "authentication (unknown CA in the chain).",
        "check": "Check the issuer is in ise_list_certificates kind=trusted with client auth; add it with "
        "ise_import_trusted_cert trust_for=['client_auth', 'ise_auth'] (ISE refuses client_auth alone).",
    },
    "12520": {
        "likely": "EAP-TLS failed: the client rejected the ISE EAP certificate (untrusted issuer or name).",
        "check": "Make the client trust the issuer of the EAP system certificate (ise_list_certificates).",
    },
    "15039": {
        "likely": "An authorization rule matched whose profile is DenyAccess (or the default rule denies).",
        "check": "Inspect the matched policy set's authorization rules (ise_get_policy_set).",
    },
    "22040": {
        "likely": "Wrong password for an internal user.",
        "check": "Verify the user (ise_get_internal_user), reset the password, check it is enabled.",
    },
    "22056": {
        "likely": "The username/MAC is not in any identity store the authentication rule searched.",
        "check": "For users: ise_get_internal_user / AD join point. For MAB: the endpoint must exist "
        "(ise_endpoint_360) or the rule's 'If user not found' should be CONTINUE.",
    },
    # Active Directory (codes checked against the ISE 3.5 MnT catalog and live failures on a joined
    # node; ise_why_auth_failed adds the join status and the user's groups for these).
    "24408": {
        "likely": "Active Directory rejected the password (wrong password).",
        "check": "Have the user re-enter or reset their AD password; repeated failures can lock the account.",
    },
    "24406": {
        "likely": "Active Directory says the credentials are invalid.",
        "check": "Check the username/domain and password; ise_test_ad_user shows whether AD knows the user.",
    },
    "24409": {
        "likely": "The user's AD account is disabled.",
        "check": "Enable the account in Active Directory (Users and Computers, or Enable-ADAccount).",
    },
    "24414": {
        "likely": "The user's AD account has expired.",
        "check": "Extend the account expiry in Active Directory.",
    },
    "24415": {
        "likely": "The user's AD account is locked out (too many wrong passwords).",
        "check": "Unlock it in AD (Unlock-ADAccount) and find the device still sending the old password.",
    },
    "24407": {
        "likely": "AD requires the user to change their password at next logon; 802.1X can't do that.",
        "check": "Have the user change the password elsewhere, or clear 'must change password' in AD.",
    },
    "24410": {
        "likely": "The user is outside their AD logon hours.",
        "check": "Check the account's Logon Hours in Active Directory.",
    },
    "24412": {
        "likely": "The user is not in Active Directory (or not in the join point's domains/scope).",
        "check": "ise_test_ad_user with the username; check spelling, the domain suffix and the join "
        "point's allowed domains.",
    },
    "24413": {
        "likely": "The user's domain (prefix or UPN suffix) isn't one the join point knows.",
        "check": "Check the identity format (DOMAIN\\user or user@domain) and the trusted domains "
        "(ise_get_ad_join_point).",
    },
    "24419": {
        "likely": "ISE could not read the user's attributes from Active Directory.",
        "check": "Check the DC is reachable and the join is healthy (ise_get_ad_join_point).",
    },
    "24417": {
        "likely": "ISE could not read the user's groups from Active Directory.",
        "check": "Check the DC is reachable and the join is healthy (ise_get_ad_join_point).",
    },
    "24428": {
        "likely": "ISE could not talk to the DC (LRPC, LDAP or Kerberos error).",
        "check": "Check DNS SRV records, ports 88/389/445/3268 and NTP sync; ise_get_ad_join_point.",
    },
    "24429": {
        "likely": "ISE could not connect to Active Directory.",
        "check": "Check DNS, routing/firewall to the DC and time sync; ise_get_ad_join_point.",
    },
    "24446": {
        "likely": "The domain controller is unreachable.",
        "check": "Check DNS SRV records and ports 88/389/445/3268 to the DC; ise_get_ad_join_point.",
    },
    "24447": {
        "likely": "ISE's computer account in AD is disabled, deleted or reset.",
        "check": "Re-join the node (ise_leave_ad then ise_join_ad).",
    },
    "24493": {
        "likely": "ISE's machine credentials no longer work against AD.",
        "check": "Re-join the node (ise_join_ad); check the computer account in AD.",
    },
    "24465": {
        "likely": "ISE is not joined to the AD domain.",
        "check": "ise_get_ad_join_point; join with ise_join_ad.",
    },
    "25058": {
        "likely": "ISE is not joined to the AD domain.",
        "check": "ise_get_ad_join_point; join with ise_join_ad.",
    },
    "24494": {
        "likely": "No DNS server can resolve the AD domain's SRV records.",
        "check": "Point ISE's name server at the domain's DNS (ISE CLI 'ip name-server').",
    },
    "24708": {
        "likely": "The user wasn't found, and some AD domains could not be searched.",
        "check": "ise_get_ad_join_point (unusable domains) and ise_test_ad_user.",
    },
    "15024": {
        "likely": "PAP is not allowed by the policy set's Allowed Protocols.",
        "check": "Check the policy set's allowed protocols (ise_list_allowed_protocols).",
    },
    "11509": {
        "likely": "The matched policy set's Allowed Protocols service allows no EAP method.",
        "check": "Check the policy set's allowed protocols (ise_list_allowed_protocols).",
    },
    "22063": {
        "likely": "Wrong password (EAP-MD5/PAP/MSCHAP inner method) for a user that exists.",
        "check": "Verify the user (ise_get_internal_user), reset the password, check the supplicant config.",
    },
    "22044": {
        "likely": "The identity policy rule's identity source failed (e.g. certificate profile mismatch).",
        "check": "Check the authentication rule and identity source sequence (ise_get_policy_set).",
    },
    "5440": {
        "likely": "The endpoint abandoned the EAP session (supplicant timeout or misconfiguration).",
        "check": "Check the client supplicant and that it trusts the ISE certificate.",
    },
    "24206": {
        "likely": "The internal user is disabled.",
        "check": "Enable the user (ise_update_internal_user).",
    },
    "22041": {
        "likely": "The internal user account is disabled.",
        "check": "Enable it (ise_update_internal_user).",
    },
}


def decode_steps(steps: str | None, catalog: dict[str, dict[str, object]] | None = None) -> list[str]:
    """'11001,11017,...' -> ['11001 Received RADIUS Access-Request', ...]; failure codes are looked up in
    the MnT failure-reason catalog when given."""
    out = []
    for code in (steps or "").split(","):
        code = code.strip()
        if not code:
            continue
        text = STEP_CODES.get(code) or str((catalog or {}).get(code, {}).get("reason") or "")
        out.append(f"{code} {text}".strip())
    return out

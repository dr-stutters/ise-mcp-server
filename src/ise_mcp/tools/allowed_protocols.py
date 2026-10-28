"""Allowed-protocols services (I71): create or harden the service a policy set selects, from a preset.

ERS `allowedprotocols` takes eighteen required top-level booleans and five nested EAP objects (eapTls,
peap, eapFast, eapTtls, teap; shapes from the ERS data model and a GET of ISE 3.5's 'Default Network
Access'). A preset fills all of them, so the body is complete and nothing is left at ISE's permissive
defaults. Conditional fields ("required only if X is true, otherwise it must be ignored") are only sent
when X is true, and a nested object only with its protocol allowed: ISE 3.5 refuses the settings of a
protocol that is off (#122), and an allow that turns one on gets hardened defaults (NESTED_DEFAULTS).

Presets follow Cisco's ISE secure-access guidance and the campus / SD-Access validated designs: one
service per use case, PAP/ASCII, EAP-MD5, LEAP and MS-CHAPv1 off, no EAP-TLS with expired certificates,
no weak EAP ciphers, and "Require Message-Authenticator" on for EAP-only services (RFC 3579 makes it
mandatory in every EAP request; it is the BlastRADIUS mitigation, CVE-2024-3596). MAB is a host lookup:
the service needs Process Host Lookup, and a Cisco switch's default MAB request is PAP-encoded
(password = MAC), so mab-only and include_mab keep PAP/ASCII on for that lookup and leave
Message-Authenticator to the NAD. TEAP internals stay with I33; a preset turns TEAP off.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import copy
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastmcp import Context
from pydantic import Field

from ise_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    get_client,
    preview_or_apply,
)
from ise_mcp.client import IseApp
from ise_mcp.tools.where_used import find_references
from ise_mcp.tools.writes import ers_post, ers_put, fingerprint

RESOURCE = "allowedprotocols"
WRAPPER = "AllowedProtocols"

# Friendly protocol name -> top-level ERS flag, in the order ISE's GUI lists them.
PROTOCOLS: dict[str, str] = {
    "host-lookup": "processHostLookup",
    "pap": "allowPapAscii",
    "chap": "allowChap",
    "mschapv1": "allowMsChapV1",
    "mschapv2": "allowMsChapV2",
    "eap-md5": "allowEapMd5",
    "leap": "allowLeap",
    "eap-tls": "allowEapTls",
    "eap-ttls": "allowEapTtls",
    "eap-fast": "allowEapFast",
    "peap": "allowPeap",
    "teap": "allowTeap",
}
# Turned off on day 1 by Cisco's hardening guidance; allowing one needs allow_weak=true.
WEAK = {"pap", "mschapv1", "eap-md5", "leap"}
WEAK_REASON = {
    "pap": "PAP/ASCII sends the password in a reversible form",
    "mschapv1": "MS-CHAPv1 is broken (DES, crackable offline)",
    "eap-md5": "EAP-MD5 has no server authentication and no keys for 802.1X/WPA",
    "leap": "LEAP is crackable offline (asleap)",
    "allowEapTlsAuthOfExpiredCerts": "EAP-TLS would accept expired client certificates",
    "allowPeapEapTlsAuthOfExpiredCerts": "PEAP inner EAP-TLS would accept expired client certificates",
    "allowPeapV0": "PEAPv0 (Microsoft's original) without cryptobinding allows tunnel-MitM",
}

Preset = Literal["eap-tls-only", "peap-mschapv2", "eap-tls-and-peap", "mab-only"]
PRESETS: dict[str, dict[str, Any]] = {
    "eap-tls-only": {"on": {"eap-tls"}, "peap_inner": None},
    "peap-mschapv2": {"on": {"peap"}, "peap_inner": "mschapv2"},
    "eap-tls-and-peap": {"on": {"eap-tls", "peap"}, "peap_inner": "mschapv2"},
    "mab-only": {"on": {"host-lookup", "pap"}, "peap_inner": None},
}

EAP_TLS_FIELDS = {
    "allowEapTlsAuthOfExpiredCerts": bool,
    "eapTlsEnableStatelessSessionResume": bool,
    "eapTlsSessionTicketTtl": int,
    "eapTlsSessionTicketTtlUnits": str,
    "eapTlsSessionTicketPrecentage": int,
}
PEAP_FIELDS = {
    "allowPeapEapMsChapV2": bool,
    "allowPeapEapMsChapV2PwdChange": bool,
    "allowPeapEapMsChapV2PwdChangeRetries": int,
    "allowPeapEapGtc": bool,
    "allowPeapEapGtcPwdChange": bool,
    "allowPeapEapGtcPwdChangeRetries": int,
    "allowPeapEapTls": bool,
    "allowPeapEapTlsAuthOfExpiredCerts": bool,
    "requireCryptobinding": bool,
    "allowPeapV0": bool,
}
TTL_UNITS = {"SECONDS", "MINUTES", "HOURS", "DAYS", "WEEKS"}


# Protocol name -> its nested ERS settings object. ISE 3.5 refuses a body that carries the object of a
# protocol that is not allowed ("Peap protocol is not allowed but settings are not null", #122) and
# leaves it out of a GET, so the object goes only with an allowed protocol.
NESTED: dict[str, str] = {
    "eap-tls": "eapTls",
    "peap": "peap",
    "eap-fast": "eapFast",
    "eap-ttls": "eapTtls",
    "teap": "teap",
}
# Settings for a protocol turned on (preset or allow) that has no object yet: ISE's own defaults with the
# weak inner methods off (EAP-GTC, EAP-TTLS PAP/CHAP/MS-CHAPv1/EAP-MD5, expired certificates, anonymous
# PAC provisioning, MSK downgrade), so an `allow` never re-opens what a preset closed.
NESTED_DEFAULTS: dict[str, dict[str, Any]] = {
    "eapTls": {"allowEapTlsAuthOfExpiredCerts": False, "eapTlsEnableStatelessSessionResume": False},
    "peap": {
        "allowPeapEapMsChapV2": True,
        "allowPeapEapMsChapV2PwdChange": True,
        "allowPeapEapMsChapV2PwdChangeRetries": 1,
        "allowPeapEapGtc": False,
        "allowPeapEapTls": False,
        "requireCryptobinding": False,
        "allowPeapV0": False,
    },
    "eapFast": {
        "allowEapFastEapMsChapV2": True,
        "allowEapFastEapMsChapV2PwdChange": True,
        "allowEapFastEapMsChapV2PwdChangeRetries": 3,
        "allowEapFastEapGtc": False,
        "allowEapFastEapTls": True,
        "allowEapFastEapTlsAuthOfExpiredCerts": False,
        "eapFastUsePacs": True,
        "eapFastUsePacsTunnelPacTtl": 90,
        "eapFastUsePacsTunnelPacTtlUnits": "DAYS",
        "eapFastUsePacsUseProactivePacUpdatePrecentage": 90,
        "eapFastUsePacsAllowAnonymProvisioning": False,
        "eapFastUsePacsAllowAuthenProvisioning": True,
        "eapFastUsePacsServerReturns": True,
        "eapFastUsePacsAcceptClientCert": False,
        "eapFastUsePacsAllowMachineAuthentication": True,
        "eapFastUsePacsMachinePacTtl": 1,
        "eapFastUsePacsMachinePacTtlUnits": "WEEKS",
        "eapFastUsePacsStatelessSessionResume": True,
        "eapFastUsePacsAuthorizationPacTtl": 1,
        "eapFastUsePacsAuthorizationPacTtlUnits": "HOURS",
        "eapFastEnableEAPChaining": False,
    },
    "eapTtls": {
        "eapTtlsPapAscii": False,
        "eapTtlsChap": False,
        "eapTtlsMsChapV1": False,
        "eapTtlsMsChapV2": True,
        "eapTtlsEapMd5": False,
        "eapTtlsEapMsChapV2": True,
        "eapTtlsEapMsChapV2PwdChange": True,
        "eapTtlsEapMsChapV2PwdChangeRetries": 1,
    },
    "teap": {
        "allowTeapEapMsChapV2": True,
        "allowTeapEapMsChapV2PwdChange": True,
        "allowTeapEapMsChapV2PwdChangeRetries": 3,
        "allowTeapEapTls": True,
        "allowTeapEapTlsAuthOfExpiredCerts": False,
        "acceptClientCertDuringTunnelEst": False,
        "enableEapChaining": False,
        "allowDowngradeMsk": False,
    },
}


def sync_nested(body: dict[str, Any]) -> list[str]:
    """Make the nested objects follow the protocol flags, in place: drop the object of every protocol
    that is not allowed, and give an allowed one that has none the defaults above. Returns the
    sections filled from the defaults."""
    filled: list[str] = []
    for name, section in NESTED.items():
        if not body.get(PROTOCOLS[name]):
            body.pop(section, None)
        elif not body.get(section):
            body[section] = copy.deepcopy(NESTED_DEFAULTS[section])
            filled.append(section)
    return filled


def preset_body(preset: str, *, include_mab: bool = False) -> dict[str, Any]:
    """The full ERS body (minus name/description/id) for a preset."""
    spec = PRESETS[preset]
    on = set(spec["on"])
    if include_mab:
        on |= {"host-lookup", "pap"}
    eap_only = not ({"host-lookup", "pap"} & on)
    body: dict[str, Any] = {flag: name in on for name, flag in PROTOCOLS.items()}
    body.update(
        {
            "allowPreferredEapProtocol": False,
            "eapTlsLBit": False,
            "allowWeakCiphersForEap": False,
            "fiveG": False,
            "rsaPss": True,
            "displayAdditionalTLSParams": False,
            "requireMessageAuth": eap_only,
        }
    )
    mschap = spec["peap_inner"] == "mschapv2"
    peap: dict[str, Any] = {"allowPeapEapMsChapV2": mschap}
    if mschap:
        peap.update({"allowPeapEapMsChapV2PwdChange": True, "allowPeapEapMsChapV2PwdChangeRetries": 1})
    peap.update(
        {
            "allowPeapEapGtc": False,
            "allowPeapEapTls": False,
            "requireCryptobinding": False,
            "allowPeapV0": False,
        }
    )
    body["peap"] = peap
    sync_nested(body)
    return body


def _check_fields(given: dict[str, Any], fields: dict[str, type], what: str) -> None:
    for k, v in given.items():
        if k not in fields:
            raise InvalidRequest(f"Unknown {what} option {k!r}; known: {', '.join(sorted(fields))}")
        want = fields[k]
        if want is int and (isinstance(v, bool) or not isinstance(v, int)):
            raise InvalidRequest(f"{what} option {k} takes an integer")
        if want is bool and not isinstance(v, bool):
            raise InvalidRequest(f"{what} option {k} takes true or false")
        if want is str and str(v).upper() not in TTL_UNITS:
            raise InvalidRequest(f"{what} option {k} takes one of {', '.join(sorted(TTL_UNITS))}")


def _names(values: list[str], arg: str) -> list[str]:
    out = []
    for v in values:
        key = v.strip().lower().replace("_", "-").replace("/ascii", "")
        if key not in PROTOCOLS:
            raise InvalidRequest(f"Unknown protocol {v!r} in {arg}; known: {', '.join(PROTOCOLS)}")
        out.append(key)
    return out


def apply_overrides(
    body: dict[str, Any],
    *,
    allow: list[str],
    deny: list[str],
    eap_tls: dict[str, Any],
    peap: dict[str, Any],
) -> list[str]:
    """Apply allow/deny/eap_tls/peap to `body` in place. Returns the weak settings this turned on."""
    allowed, denied = _names(allow, "allow"), _names(deny, "deny")
    if both := sorted(set(allowed) & set(denied)):
        raise InvalidRequest(f"{', '.join(both)} given in both allow and deny")
    _check_fields(eap_tls, EAP_TLS_FIELDS, "eap_tls")
    _check_fields(peap, PEAP_FIELDS, "peap")
    weak: list[str] = []
    for name in allowed:
        if name in WEAK and not body.get(PROTOCOLS[name]):
            weak.append(name)
        body[PROTOCOLS[name]] = True
    for name in denied:
        body[PROTOCOLS[name]] = False
    for proto, given in (("eap-tls", eap_tls), ("peap", peap)):
        if given and not body.get(PROTOCOLS[proto]):
            arg = proto.replace("-", "_")
            raise InvalidRequest(
                f"{arg} options given but {proto} is not allowed on this service: add allow=['{proto}']"
            )
    sync_nested(body)
    for section, given in (("eapTls", eap_tls), ("peap", peap)):
        if not given:
            continue
        current = dict(body.get(section) or {})
        for k, v in given.items():
            if k in WEAK_REASON and v is True and not current.get(k):
                weak.append(k)
            current[k] = v.upper() if isinstance(v, str) else v
        body[section] = current
    if (
        "peap" in allowed
        and body.get("peap")
        and not any(
            body["peap"].get(k) for k in ("allowPeapEapMsChapV2", "allowPeapEapGtc", "allowPeapEapTls")
        )
    ):
        body["peap"] = {
            **body["peap"],
            "allowPeapEapMsChapV2": True,
            "allowPeapEapMsChapV2PwdChange": True,
            "allowPeapEapMsChapV2PwdChangeRetries": 1,
        }
    # Fields ERS requires once their inner method is on ("required only if X is true"): fill ISE's
    # defaults so a peap override that turns an inner method on is not answered with a 400.
    inner = dict(body.get("peap") or {})
    for method in ("MsChapV2", "Gtc"):
        if inner.get(f"allowPeapEap{method}"):
            inner.setdefault(f"allowPeapEap{method}PwdChange", True)
            inner.setdefault(f"allowPeapEap{method}PwdChangeRetries", 1)
    if inner.get("allowPeapEapTls"):
        inner.setdefault("allowPeapEapTlsAuthOfExpiredCerts", False)
    if inner:
        body["peap"] = inner
    tls = body.get("eapTls") or {}
    if tls.get("eapTlsEnableStatelessSessionResume") and "eapTlsSessionTicketTtl" not in tls:
        body["eapTls"] = {
            **tls,
            "eapTlsSessionTicketTtl": 2,
            "eapTlsSessionTicketTtlUnits": "HOURS",
            "eapTlsSessionTicketPrecentage": 10,
        }
    return weak


def protocol_table(obj: dict[str, Any] | None) -> dict[str, bool]:
    return {name: bool((obj or {}).get(flag)) for name, flag in PROTOCOLS.items()}


def inner_methods(obj: dict[str, Any] | None) -> dict[str, Any]:
    o = obj or {}
    peap = o.get("peap") or {}
    tls = o.get("eapTls") or {}
    return {
        "peap_inner": [
            n
            for n, k in (
                ("mschapv2", "allowPeapEapMsChapV2"),
                ("gtc", "allowPeapEapGtc"),
                ("eap-tls", "allowPeapEapTls"),
            )
            if peap.get(k)
        ],
        "eap_tls_expired_certs": bool(tls.get("allowEapTlsAuthOfExpiredCerts")),
        "require_message_authenticator": bool(o.get("requireMessageAuth")),
        "weak_eap_ciphers": bool(o.get("allowWeakCiphersForEap")),
    }


def weak_enabled(obj: dict[str, Any]) -> list[str]:
    out = [n for n in sorted(WEAK) if obj.get(PROTOCOLS[n])]
    if (obj.get("eapTls") or {}).get("allowEapTlsAuthOfExpiredCerts"):
        out.append("allowEapTlsAuthOfExpiredCerts")
    if obj.get("allowWeakCiphersForEap"):
        out.append("allowWeakCiphersForEap")
    return out


async def find_service(app: IseApp, name: str) -> dict[str, Any] | None:
    """ERS allowedprotocols has no name filter (400 on ISE 3.5) but answers GET .../name/{name}."""
    try:
        data = await app.ers_request("GET", f"/ers/config/{RESOURCE}/name/{quote(name, safe='')}")
    except NotFound:
        return None
    obj = data.get(WRAPPER, data) if isinstance(data, dict) else None
    return obj if isinstance(obj, dict) and obj.get("id") else None


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create or harden an allowed-protocols service")
    async def ise_set_allowed_protocols(
        ctx: Context,
        name: Annotated[str, Field(description="Service name, e.g. 'mcp-EAP-TLS-only'")],
        preset: Annotated[
            Preset | None,
            Field(
                description="Hardened starting point that sets every protocol: "
                "'eap-tls-only' (certificates), "
                "'peap-mschapv2' (passwords in a PEAP tunnel), 'eap-tls-and-peap' (migration), 'mab-only' "
                "(host lookup for headless devices). Required for a new service; on an existing one it "
                "replaces every protocol setting, omitted = change only what allow/deny/eap_tls/peap give"
            ),
        ] = None,
        allow: Annotated[
            list[str] | None,
            Field(
                description="Protocols to turn on: host-lookup, pap, chap, mschapv1, mschapv2, "
                "eap-md5, leap, "
                "eap-tls, eap-ttls, eap-fast, peap, teap. Weak ones (pap, mschapv1, eap-md5, leap) need "
                "allow_weak=true"
            ),
        ] = None,
        deny: Annotated[
            list[str] | None, Field(description="Protocols to turn off (same names as allow)")
        ] = None,
        eap_tls: Annotated[
            dict[str, Any] | None,
            Field(
                description="EAP-TLS options (ERS eapTls fields), e.g. "
                "{'eapTlsEnableStatelessSessionResume': "
                "true}; allowEapTlsAuthOfExpiredCerts=true needs allow_weak=true"
            ),
        ] = None,
        peap: Annotated[
            dict[str, Any] | None,
            Field(
                description="PEAP options (ERS peap fields), e.g. {'allowPeapEapTls': true, "
                "'requireCryptobinding': true}"
            ),
        ] = None,
        include_mab: Annotated[
            bool,
            Field(
                description="Also allow MAB (host lookup + PAP for the switch's MAB request) with an EAP "
                "preset, for a policy set that handles both 802.1X and MAB"
            ),
        ] = False,
        allow_weak: Annotated[
            bool,
            Field(description="Accept turning on a protocol or option Cisco's hardening guidance turns off"),
        ] = False,
        description: Annotated[str | None, Field(description="Free-text description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an allowed-protocols service (the one a policy set selects) from a hardening preset,
        or harden or adjust an existing one. Auths using a protocol the service doesn't allow fail with
        'protocol not allowed' (12001, 15024, 11509). Presets turn PAP, EAP-MD5, LEAP and MS-CHAPv1 off
        and require Message-Authenticator for EAP-only services; weak overrides need allow_weak. The
        preview shows the protocol table before and after and the policy sets that use the service.
        Preview-first."""
        app: IseApp = get_client(ctx)
        if include_mab and preset is None:
            raise InvalidRequest("include_mab goes with a preset; to change one protocol use allow/deny")
        existing = await find_service(app, name)
        if existing is None and preset is None:
            raise InvalidRequest(f"No allowed-protocols service {name!r} yet: give a preset to create it")
        if preset is not None:
            desired: dict[str, Any] = preset_body(preset, include_mab=include_mab)
        else:
            desired = copy.deepcopy(
                {k: v for k, v in (existing or {}).items() if k not in ("id", "name", "link")}
            )
        if preset is None and not (allow or deny or eap_tls or peap or description is not None):
            raise InvalidRequest("Give a preset, allow, deny, eap_tls, peap or description")
        weak = apply_overrides(
            desired, allow=allow or [], deny=deny or [], eap_tls=eap_tls or {}, peap=peap or {}
        )
        if weak and not allow_weak:
            reasons = "; ".join(f"{w}: {WEAK_REASON[w]}" for w in weak)
            raise InvalidRequest(
                f"Refused: turning on {', '.join(weak)} weakens the service ({reasons}). "
                "Cisco's ISE hardening "
                "guidance turns these off; repeat with allow_weak=true if a legacy client really needs it"
            )
        args = {
            "name": name,
            "preset": preset,
            "allow": allow,
            "deny": deny,
            "eap_tls": eap_tls,
            "peap": peap,
            "include_mab": include_mab,
            "allow_weak": allow_weak,
            "description": description,
        }
        if not any(desired.get(PROTOCOLS[p]) for p in PROTOCOLS if p != "host-lookup"):
            raise InvalidRequest("That leaves the service with no protocol allowed: every login would fail")
        warnings: list[str] = []
        if weak:
            warnings.append(
                "Weak setting(s) turned on with allow_weak: "
                + "; ".join(f"{w} ({WEAK_REASON[w]})" for w in weak)
            )
        if preset is None:
            still = [w for w in weak_enabled(desired) if w not in weak]
            if still:
                warnings.append(f"Still on (kept from the current service): {', '.join(still)}")
        elif desired.get("allowPapAscii") and "pap" not in weak:
            warnings.append(
                "PAP/ASCII stays on for the MAB host lookup (a Cisco switch's MAB request is PAP-encoded); "
                "select this service only in policy sets whose password logins use EAP"
            )
        blockers: list[str] = []
        refs: list[dict[str, Any]] = []
        incomplete: list[str] = []
        if existing:
            found = await find_references(app, "allowed_protocols", existing)
            refs = list(found.get("references") or [])
            incomplete = list(found.get("incomplete") or [])
            admin = [r["policy_set"] for r in refs if r.get("policy_kind") == "device-admin"]
            if admin and preset is not None:
                blockers.append(
                    f"Device-admin (TACACS+) policy set(s) {', '.join(map(str, admin))} use this service: a "
                    "RADIUS preset would turn off the PAP/CHAP their logins need. Give a separate service "
                    "or use allow/deny without a preset"
                )
        if description is not None:
            desired["description"] = description
        policy_sets = [{"policy_set": r.get("policy_set"), "kind": r.get("policy_kind")} for r in refs]
        before, after = protocol_table(existing), protocol_table(desired)
        table = [
            {"protocol": p, **({"before": before[p]} if existing else {}), "after": after[p]}
            for p in PROTOCOLS
        ]
        details: dict[str, Any] = {
            "service": name,
            "preset": preset,
            "protocols": table,
            "inner": {
                "after": inner_methods(desired),
                **({"before": inner_methods(existing)} if existing else {}),
            },
            "policy_sets_using_it": policy_sets,
        }
        if existing:
            filled = [sec for sec in NESTED.values() if sec in desired and not existing.get(sec)]
            if filled:
                details["settings_from_defaults"] = {sec: desired[sec] for sec in filled}
        if incomplete:
            details["references_incomplete"] = incomplete
        if warnings:
            details["warnings"] = warnings
        turned_off = [p for p in PROTOCOLS if before[p] and not after[p]]
        side_effects: list[str] = []
        if existing and policy_sets and turned_off:
            side_effects.append(
                f"Clients using {', '.join(turned_off)} in policy set(s) "
                f"{', '.join(str(p['policy_set']) for p in policy_sets)} fail at their next authentication "
                "('protocol not allowed', e.g. 12001/15024/11509)"
            )
        if desired.get("requireMessageAuth") and not (existing or {}).get("requireMessageAuth"):
            side_effects.append(
                "Requests without a Message-Authenticator attribute are dropped (every EAP request carries "
                "one, RFC 3579; a non-EAP request on this service would fail)"
            )
        if existing:
            full = {**existing, **desired, "id": existing["id"], "name": existing["name"]}
            sync_nested(full)  # the copied objects of protocols this turns off go too
            noop = full == existing
            return await preview_or_apply(
                ctx,
                tool="ise_set_allowed_protocols",
                args=args,
                confirm=confirm,
                plan=Plan(
                    f"Update allowed-protocols service {name}",
                    details=details,
                    fingerprint=fingerprint(existing),
                    blockers=blockers,
                    side_effects=[] if noop else side_effects,
                    blast_radius=0 if noop else len(policy_sets),
                    noop=noop,
                    noop_reason=f"Allowed-protocols service {name} already has exactly these settings"
                    if noop
                    else None,
                ),
                apply=lambda: ers_put(app, RESOURCE, WRAPPER, full),
            )
        body = {"name": name, "description": description or "", **desired}
        return await preview_or_apply(
            ctx,
            tool="ise_set_allowed_protocols",
            args=args,
            confirm=confirm,
            plan=Plan(
                f"Create allowed-protocols service {name}",
                details=details,
                side_effects=side_effects
                + [
                    "Nothing uses it yet: select it in a policy set "
                    "(ise_update_policy_set allowed_protocols=...)"
                ],
            ),
            apply=lambda: ers_post(app, RESOURCE, WRAPPER, body),
        )

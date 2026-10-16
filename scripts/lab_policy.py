"""Build or remove the ISE side of the CML 'ise-access' lab (cml-mcp-server recipe) through the MCP tools,
the way a model would (preview, then confirm).

    uv run python scripts/lab_policy.py up      # NAD + NDG, dACLs, profiles, policy sets, ANC, TACACS+
    uv run python scripts/lab_policy.py down    # remove everything 'up' created (reverse order)
    uv run python scripts/lab_policy.py ad      # AD join point + join + groups + AD rules (after 'up')
    uv run python scripts/lab_policy.py ad-down # leave the domain and remove the AD objects
    uv run python scripts/lab_policy.py certs   # trust the lab CA, EAP cert signed by it, EAP-TLS rule

What 'up' creates (all named mcp-test-*; idempotent: existing objects are left alone):
- NDG Location#All Locations#mcp-test-lab; NAD mcp-test-sw1 198.18.128.154 (RADIUS + TACACS+ key ***REDACTED***,
  the lab switch's key)
- dACLs mcp-test-permit-dacl / mcp-test-quarantine-dacl; authz profiles mcp-test-permit / mcp-test-quarantine
- network-access policy set mcp-test-wired (DEVICE:Location = the lab NDG AND NAS-Port-Type Ethernet):
  authn mcp-test-mab (Internal Endpoints, CONTINUE) and mcp-test-dot1x (Internal Users); authz
  mcp-test-anc-quarantine (Session:ANCPolicy = mcp-test-quarantine -> quarantine + SGT Quarantined_Systems),
  mcp-test-dot1x-netops (802.1X + group mcp-test-netops -> permit + SGT Employees),
  mcp-test-mab-permit (Wired_MAB -> permit + SGT Employees)
- ANC policy mcp-test-quarantine (QUARANTINE)
- identity group mcp-test-netops, user mcp-test-netops1 (password from MCP_LAB_USER_PASSWORD, default
  ***REDACTED***), command set mcp-test-show-only, shell profile mcp_test_priv15, device-admin policy
  set mcp-test-devadmin with rule mcp-test-netops
'ad' (needs the lab DC, ~/MCP-Suite/scripts/build-dc.py; secrets from LAB_* env vars or LAB_SECRETS_FILE,
default ~/MCP-Suite/lab-secrets.env): join point MITCHCLOUD for LAB_AD_DOMAIN, node joined with
LAB_WIN_ADMIN_USER / LAB_WIN_ADMIN_PASSWORD (only if not joined yet), groups mcp-employees / mcp-contractors /
mcp-netadmins / mcp-netreadonly, certificate profile mcp_test_certprof and identity sequence
mcp_test_eaptls_seq (Internal Users, MITCHCLOUD) on authn rule mcp-test-dot1x, and authz rules
mcp-test-ad-employees (-> SGT Employees) and mcp-test-ad-contractors (-> SGT Contractors).
'certs' (needs the DC and its CA root in ~/MCP-Suite/lab-ca/<LAB_AD_DOMAIN first label>-CA.pem, written by
build-dc.py): trusted cert mitchcloud-CA (client + ISE auth); unless the EAP certificate is already issued by
it: EAP CSR (CN = node FQDN) -> signed with the WebServer template by LAB_CSR_SIGNER (default
~/MCP-Suite/scripts/dc-sign-csr.py over WinRM) -> bound for EAP; authz rule mcp-test-eaptls-mitchcloud
(802.1X + EAP-TLS + certificate issuer CN = the CA -> SGT Production_Users). Client certificates (User
template) are issued per user: dc-sign-csr.py <csr> --template User --as mcp-alice.
ISE's name server must point at the DC (ISE CLI: ip name-server <LAB_AD_DC_IP>).
The Device Admin service is NOT turned on here (dangerous; ise_update_node_services enable=['DeviceAdmin']).
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from fastmcp import Client
from stutters_mcp_core.testing import live_settings

from ise_mcp.config import Settings
from ise_mcp.server import create_server

LAB_NDG = "Location#All Locations#mcp-test-lab"
PASSWORD = os.environ.get("MCP_LAB_USER_PASSWORD", "***REDACTED***")

UP: list[tuple[str, dict[str, Any]]] = [
    ("ise_create_ndg", {"path": LAB_NDG, "description": "mcp-test CML lab"}),
    (
        "ise_create_nad",
        {
            "name": "mcp-test-sw1",
            "ips": ["198.18.128.154"],
            "radius_secret": "***REDACTED***",
            "tacacs_secret": "***REDACTED***",
            "groups": [LAB_NDG, "Device Type#All Device Types"],
            "description": "mcp-test CML sw1",
        },
    ),
    (
        "ise_set_dacl",
        {
            "name": "mcp-test-permit-dacl",
            "aces": [
                "permit udp any any eq 67",
                "permit udp any any eq 53",
                "permit icmp any any",
                "permit ip any any",
            ],
            "ip_version": "IPV4",
            "description": "mcp-test",
        },
    ),
    (
        "ise_set_dacl",
        {
            "name": "mcp-test-quarantine-dacl",
            "aces": ["permit udp any any eq 67", "permit udp any any eq 53", "deny ip any any"],
            "ip_version": "IPV4",
            "description": "mcp-test",
        },
    ),
    (
        "ise_create_authz_profile",
        {"name": "mcp-test-permit", "access": "accept", "dacl": "mcp-test-permit-dacl"},
    ),
    (
        "ise_create_authz_profile",
        {"name": "mcp-test-quarantine", "access": "accept", "dacl": "mcp-test-quarantine-dacl"},
    ),
    ("ise_create_anc_policy", {"name": "mcp-test-quarantine", "actions": ["QUARANTINE"]}),
    ("ise_create_group", {"kind": "identity", "name": "mcp-test-netops", "description": "mcp-test"}),
    (
        "ise_create_internal_user",
        {"name": "mcp-test-netops1", "password": PASSWORD, "groups": ["mcp-test-netops"]},
    ),
    (
        "ise_create_policy_set",
        {
            "name": "mcp-test-wired",
            "conditions": [f"DEVICE:Location equals {LAB_NDG}", "Radius:NAS-Port-Type equals Ethernet"],
            "description": "mcp-test CML lab",
        },
    ),
    (
        "ise_create_authn_rule",
        {
            "policy_set": "mcp-test-wired",
            "name": "mcp-test-mab",
            "conditions": ["Wired_MAB"],
            "identity_source": "Internal Endpoints",
            "if_user_not_found": "CONTINUE",
        },
    ),
    (
        "ise_create_authn_rule",
        {
            "policy_set": "mcp-test-wired",
            "name": "mcp-test-dot1x",
            "conditions": ["Wired_802.1X"],
            "identity_source": "Internal Users",
            "rank": 1,
        },
    ),
    (
        "ise_create_authz_rule",
        {
            "policy_set": "mcp-test-wired",
            "name": "mcp-test-mab-permit",
            "conditions": ["Wired_MAB"],
            "profiles": ["mcp-test-permit"],
            "sgt": "Employees",
        },
    ),
    (
        "ise_create_authz_rule",
        {
            "policy_set": "mcp-test-wired",
            "name": "mcp-test-dot1x-netops",
            "conditions": ["Wired_802.1X", "IdentityGroup:Name equals User Identity Groups:mcp-test-netops"],
            "profiles": ["mcp-test-permit"],
            "sgt": "Employees",
        },
    ),
    (
        "ise_create_authz_rule",
        {
            "policy_set": "mcp-test-wired",
            "name": "mcp-test-anc-quarantine",
            "conditions": ["Session:ANCPolicy equals mcp-test-quarantine"],
            "profiles": ["mcp-test-quarantine"],
            "sgt": "Quarantined_Systems",
            "rank": 0,
        },
    ),
    (
        "ise_set_command_set",
        {
            "name": "mcp-test-show-only",
            "commands": ["PERMIT show .*", "PERMIT exit", "PERMIT terminal .*", "DENY_ALWAYS reload"],
            "description": "mcp-test",
        },
    ),
    (
        "ise_set_shell_profile",
        {"name": "mcp_test_priv15", "privilege": 15, "idle_timeout": 30, "description": "mcp-test"},
    ),
    (
        "ise_create_policy_set",
        {
            "kind": "device-admin",
            "name": "mcp-test-devadmin",
            "conditions": [f"DEVICE:Location equals {LAB_NDG}"],
        },
    ),
    (
        "ise_create_authz_rule",
        {
            "kind": "device-admin",
            "policy_set": "mcp-test-devadmin",
            "name": "mcp-test-netops",
            "conditions": ["IdentityGroup:Name equals User Identity Groups:mcp-test-netops"],
            "command_sets": ["mcp-test-show-only"],
            "shell_profile": "mcp_test_priv15",
        },
    ),
]

DOWN: list[tuple[str, dict[str, Any]]] = [
    ("ise_delete_policy_set", {"policy_set": "mcp-test-devadmin", "kind": "device-admin"}),
    ("ise_delete_policy_set", {"policy_set": "mcp-test-wired"}),
    ("ise_delete_object", {"kind": "command_set", "target": "mcp-test-show-only"}),
    ("ise_delete_object", {"kind": "shell_profile", "target": "mcp_test_priv15"}),
    ("ise_delete_object", {"kind": "internal_user", "target": "mcp-test-netops1"}),
    ("ise_delete_object", {"kind": "identity_group", "target": "mcp-test-netops"}),
    ("ise_delete_object", {"kind": "anc_policy", "target": "mcp-test-quarantine"}),
    ("ise_delete_object", {"kind": "authz_profile", "target": "mcp-test-permit"}),
    ("ise_delete_object", {"kind": "authz_profile", "target": "mcp-test-quarantine"}),
    ("ise_delete_object", {"kind": "dacl", "target": "mcp-test-permit-dacl"}),
    ("ise_delete_object", {"kind": "dacl", "target": "mcp-test-quarantine-dacl"}),
    ("ise_delete_nad", {"device": "mcp-test-sw1"}),
    ("ise_delete_object", {"kind": "ndg", "target": LAB_NDG}),
]


JOIN_POINT = "MITCHCLOUD"
AD_GROUPS = ["mcp-employees", "mcp-contractors", "mcp-netadmins", "mcp-netreadonly"]


def lab_secrets() -> dict[str, str]:
    """LAB_* values from the environment, else from LAB_SECRETS_FILE (never printed)."""
    out: dict[str, str] = {}
    path = os.path.expanduser(os.environ.get("LAB_SECRETS_FILE", "~/MCP-Suite/lab-secrets.env"))
    if os.path.exists(path):
        for line in open(path):  # noqa: SIM115 - tiny file
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    out.update({k: v for k, v in os.environ.items() if k.startswith("LAB_")})
    return out


def ad_steps(sec: dict[str, str]) -> list[tuple[str, dict[str, Any]]]:
    domain = sec.get("LAB_AD_DOMAIN", "mitchcloud.lab")
    return [
        ("ise_create_ad_join_point", {"name": JOIN_POINT, "domain": domain, "description": "mcp lab AD"}),
        ("ise_add_ad_groups", {"join_point": JOIN_POINT, "groups": AD_GROUPS}),
        ("ise_set_cert_auth_profile", {"name": "mcp_test_certprof", "description": "mcp-test"}),
        (
            "ise_set_identity_sequence",
            {
                "name": "mcp_test_eaptls_seq",
                "stores": ["Internal Users", JOIN_POINT],
                "cert_profile": "mcp_test_certprof",
                "description": "mcp-test",
            },
        ),
        (
            "ise_update_policy_rule",
            {
                "policy_set": "mcp-test-wired",
                "rule": "mcp-test-dot1x",
                "section": "authentication",
                "identity_source": "mcp_test_eaptls_seq",
            },
        ),
        (
            "ise_create_authz_rule",
            {
                "policy_set": "mcp-test-wired",
                "name": "mcp-test-ad-employees",
                "conditions": ["Wired_802.1X", f"{JOIN_POINT}:ExternalGroups equals mcp-employees"],
                "profiles": ["mcp-test-permit"],
                "sgt": "Employees",
                "rank": 1,
            },
        ),
        (
            "ise_create_authz_rule",
            {
                "policy_set": "mcp-test-wired",
                "name": "mcp-test-ad-contractors",
                "conditions": ["Wired_802.1X", f"{JOIN_POINT}:ExternalGroups equals mcp-contractors"],
                "profiles": ["mcp-test-permit"],
                "sgt": "Contractors",
                "rank": 2,
            },
        ),
    ]


async def join(c: Client, sec: dict[str, str]) -> None:  # type: ignore[type-arg]
    r = await c.call_tool("ise_get_ad_join_point", {"join_point": JOIN_POINT}, raise_on_error=False)
    if not r.is_error and isinstance(r.structured_content, dict) and r.structured_content["join"]["joined"]:
        print(f"- ise_join_ad: skipped ({JOIN_POINT} already joined)")
        return
    user, pw = sec.get("LAB_WIN_ADMIN_USER", "Administrator"), sec.get("LAB_WIN_ADMIN_PASSWORD")
    if not pw:
        print("- ise_join_ad: skipped (LAB_WIN_ADMIN_PASSWORD not set)")
        return
    await run(c, "ise_join_ad", {"join_point": JOIN_POINT, "username": user.split("\\")[-1], "password": pw})


async def ad_down(c: Client, sec: dict[str, str]) -> None:  # type: ignore[type-arg]
    for name in ("mcp-test-ad-employees", "mcp-test-ad-contractors"):
        await run(c, "ise_delete_policy_rule", {"policy_set": "mcp-test-wired", "rule": name})
    await run(
        c,
        "ise_set_identity_sequence",
        {
            "name": "mcp_test_eaptls_seq",
            "stores": ["Internal Users"],
            "cert_profile": "mcp_test_certprof",
            "description": "mcp-test",
        },
    )
    user, pw = sec.get("LAB_WIN_ADMIN_USER", "Administrator"), sec.get("LAB_WIN_ADMIN_PASSWORD", "")
    await run(c, "ise_leave_ad", {"join_point": JOIN_POINT, "username": user.split("\\")[-1], "password": pw})
    await run(c, "ise_delete_object", {"kind": "ad_join_point", "target": JOIN_POINT})


SIGNER = os.environ.get(
    "LAB_CSR_SIGNER",
    "uv run -q --no-project --with pypsrp python ~/MCP-Suite/scripts/dc-sign-csr.py --template WebServer",
)


async def call(c: Client, tool: str, args: dict[str, Any]) -> Any:  # type: ignore[type-arg]
    r = await c.call_tool(tool, args, raise_on_error=False)
    if r.is_error:
        raise RuntimeError(f"{tool}: {r.content[0].text[:300] if r.content else 'error'}")
    return r.structured_content


async def confirm(c: Client, tool: str, args: dict[str, Any]) -> Any:  # type: ignore[type-arg]
    preview = await call(c, tool, args)
    if preview.get("status") != "preview":
        raise RuntimeError(f"{tool}: {'; '.join(preview.get('blockers') or [])[:300]}")
    return await call(c, tool, {**args, "confirm": preview["confirm"]})


def read_ca(ca: str) -> str | None:
    path = os.path.expanduser(f"~/MCP-Suite/lab-ca/{ca}.pem")
    if not os.path.exists(path):
        return None
    with open(path) as fh:
        return fh.read()


def sign(csr: str) -> tuple[str, str]:
    import shlex  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    cmd = [os.path.expanduser(part) for part in shlex.split(SIGNER)]
    try:
        r = subprocess.run(cmd, input=csr, capture_output=True, text=True, check=False, timeout=300)  # noqa: S603
    except subprocess.TimeoutExpired:
        return "", "signer timed out after 300 s"
    if r.returncode != 0:
        return "", f"signer exit {r.returncode}: {r.stderr}"
    return r.stdout, r.stderr


async def bind(c: Client, csr_id: str, pem: str, ca: str, host: str) -> None:  # type: ignore[type-arg]
    import time  # noqa: PLC0415

    await confirm(
        c,
        "ise_bind_certificate",
        {
            "csr": csr_id,
            "certificate_pem": pem,
            "use_for": ["eap"],
            "name": f"mcp-eap-{ca.lower()}-{time.strftime('%Y%m%d%H%M')}",
            "node": host,
        },
    )


async def certs(c: Client, sec: dict[str, str]) -> None:  # type: ignore[type-arg]
    import asyncio as aio  # noqa: PLC0415

    ca = sec.get("LAB_AD_DOMAIN", "mitchcloud.lab").split(".")[0] + "-CA"
    ca_pem = await aio.to_thread(read_ca, ca)
    if ca_pem is None:
        print(f"- certs: skipped (~/MCP-Suite/lab-ca/{ca}.pem missing: run build-dc.py first)")
        return
    force = os.environ.get("LAB_FORCE_EAP_CERT") == "1"
    await run(
        c,
        "ise_import_trusted_cert",
        {
            "name": ca,
            "certificate_pem": ca_pem,
            "trust_for": ["client_auth", "ise_auth"],
            "description": "lab AD CS root",
        },
    )
    nodes = (await call(c, "ise_list_nodes", {"response_format": "json"}))["results"]
    system = await call(c, "ise_list_certificates", {"response_format": "json", "limit": 500})
    for node in nodes:
        host, fqdn = node["hostname"], node.get("fqdn") or node["hostname"]
        eap = [
            r
            for r in system["results"]
            if r.get("node") == host and "EAP Authentication" in str(r.get("used_by"))
        ]
        if eap and eap[0].get("issued_by") == ca and not force:
            print(f"- EAP certificate on {host}: skipped (already issued by {ca}: {eap[0].get('name')})")
            continue
        out = await confirm(
            c,
            "ise_generate_csr",
            {
                "usage": "EAP-AUTH",
                "common_name": fqdn,
                "san_dns": [fqdn],
                "organization": "mcp lab",
                "nodes": [host],
            },
        )
        try:
            csr_id = out["result"]["response"][0]["id"]
        except (KeyError, IndexError, TypeError):
            print(f"- EAP certificate on {host}: FAILED (unexpected CSR response {str(out)[:200]})")
            continue
        csr = (await call(c, "ise_export_csr", {"csr": csr_id, "node": host}))["csr_pem"]
        signed, err = await aio.to_thread(sign, csr)
        if "BEGIN CERTIFICATE" not in signed:
            print(f"- EAP certificate on {host}: FAILED to sign ({err.strip()[-300:]})")
            await run(c, "ise_delete_csr", {"csr": csr_id, "node": host})
            continue
        try:
            await bind(c, csr_id, signed, ca, host)
        except RuntimeError as e:
            print(f"- EAP certificate on {host}: FAILED to bind ({e}); removing the CSR")
            await run(c, "ise_delete_csr", {"csr": csr_id, "node": host})
            continue
        print(f"- EAP certificate on {host}: signed by {ca} and bound for EAP")
    await run(
        c,
        "ise_create_authz_rule",
        {
            "policy_set": "mcp-test-wired",
            "name": "mcp-test-eaptls-mitchcloud",
            "conditions": [
                "Wired_802.1X",
                "Network Access:EapAuthentication equals EAP-TLS",
                f"CERTIFICATE:Issuer - Common Name equals {ca}",
            ],
            "profiles": ["mcp-test-permit"],
            "sgt": "Production_Users",
            "rank": 1,
        },
    )


async def run(c: Client, tool: str, args: dict[str, Any]) -> None:  # type: ignore[type-arg]
    r = await c.call_tool(tool, args, raise_on_error=False)
    data = r.structured_content
    if r.is_error or not isinstance(data, dict):
        text = r.content[0].text if r.content else ""
        print(f"- {tool}: skipped ({text[:160]})")
        return
    if data.get("status") == "blocked":
        print(f"- {tool}: skipped ({'; '.join(data.get('blockers') or [])[:160]})")
        return
    r = await c.call_tool(tool, {**args, "confirm": data["confirm"]}, raise_on_error=False)
    print(f"- {tool}: {'FAILED ' + r.content[0].text[:200] if r.is_error else data.get('action')}")


async def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("up", "down", "ad", "ad-down", "certs"):
        sys.exit(__doc__)
    stage = sys.argv[1]
    settings = live_settings(Settings, "ISE_", mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(create_server(settings), timeout=300) as c:
        if stage == "ad":
            sec = lab_secrets()
            steps = ad_steps(sec)
            await run(c, *steps[0])
            await join(c, sec)
            for tool, args in steps[1:]:
                await run(c, tool, args)
            return
        if stage == "certs":
            await certs(c, lab_secrets())
            return
        if stage == "ad-down":
            await ad_down(c, lab_secrets())
            return
        for tool, args in UP if stage == "up" else DOWN:
            await run(c, tool, args)


if __name__ == "__main__":
    asyncio.run(main())

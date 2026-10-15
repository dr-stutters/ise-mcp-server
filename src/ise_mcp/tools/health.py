"""Deployment health check: nodes, patches, backups, repositories, certificates, licence, AD (OpenAPI/ERS)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import asyncio
from datetime import UTC, datetime
from typing import Annotated, Any
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import NotFound, ToolRegistrar, UpstreamError, get_client, object_result

from ise_mcp.client import IseApp
from ise_mcp.tools._common import gather_limited, openapi_all
from ise_mcp.tools.system import _cert_row, _parse_date, _response

BACKUP_MAX_AGE_DAYS = 7
SEVERITIES = ("critical", "high", "medium", "low", "info")
# Certificate roles that break authentication or administration when the certificate is bad.
KEY_CERT_ROLES = ("EAP Authentication", "Admin", "RADIUS DTLS", "pxGrid", "Portal", "SAML", "TACACS")


class Findings:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def add(self, severity: str, area: str, finding: str, action: str | None = None) -> None:
        item = {"severity": severity, "area": area, "finding": finding}
        if action:
            item["action"] = action
        self.items.append(item)

    def ranked(self) -> list[dict[str, Any]]:
        return sorted(self.items, key=lambda f: SEVERITIES.index(f["severity"]))

    def summary(self) -> dict[str, int]:
        return {s: n for s in SEVERITIES if (n := sum(1 for f in self.items if f["severity"] == s))}


async def _get(app: IseApp, path: str) -> Any:
    """OpenAPI GET returning the payload, or {"error": ...} so one failing area doesn't sink the check."""
    try:
        return _response(await app.openapi.get(path))
    except (UpstreamError, NotFound) as e:
        return {"error": str(e)[:200]}


def _err(value: Any) -> str | None:
    # Only _get's own wrapper ({"error": "..."}); ISE payloads may carry an "error": null field.
    if isinstance(value, dict) and set(value) == {"error"} and value["error"]:
        return str(value["error"])
    return None


def check_nodes(nodes: Any, pan_ha: Any, f: Findings) -> list[dict[str, Any]]:
    if _err(nodes):
        f.add("high", "nodes", f"Could not read the deployment nodes: {_err(nodes)}")
        return []
    rows = [
        {
            "hostname": n.get("hostname"),
            "ip": n.get("ipAddress"),
            "roles": n.get("roles"),
            "services": n.get("services"),
            "status": n.get("nodeStatus"),
        }
        for n in nodes or []
        if isinstance(n, dict)
    ]
    for r in rows:
        if str(r.get("status") or "").lower() not in ("connected", ""):
            f.add(
                "high",
                "nodes",
                f"Node {r['hostname']} is {r['status']} (not in sync with the PAN)",
                "Check the node's reachability and certificates; resync from Administration > Deployment.",
            )
    roles = [str(x) for r in rows for x in r.get("roles") or []]
    if len(rows) == 1 and "Standalone" in roles:
        f.add("info", "nodes", "Standalone deployment: one node holds every persona (no redundancy).")
    elif len(rows) > 1:
        if not any("Secondary" in x and ("Admin" in x or "PAP" in x) for x in roles):
            f.add(
                "medium", "nodes", "No secondary Administration node: the PAN is a single point of failure."
            )
        if not any("Secondary" in x and ("Monitoring" in x or "MNT" in x.upper()) for x in roles):
            f.add(
                "low", "nodes", "No secondary Monitoring node: live logs and MnT queries depend on one node."
            )
        if isinstance(pan_ha, dict) and pan_ha.get("isEnabled") is False:
            f.add("low", "nodes", "Automatic PAN failover (PAN HA) is disabled.")
    psns = [r for r in rows if "Session" in (r.get("services") or [])]
    if rows and not psns:
        f.add("high", "nodes", "No node runs the Session service: nothing can process RADIUS.")
    return rows


def check_patches(patch: Any, hot: Any, f: Findings) -> dict[str, Any]:
    if _err(patch):
        f.add("low", "patches", f"Could not read patches: {_err(patch)}")
        return {}
    patch = patch if isinstance(patch, dict) else {}
    numbers = [p.get("patchNumber") for p in patch.get("patchVersion") or [] if isinstance(p, dict)]
    hotpatches = [h.get("hotpatchName") for h in hot or [] if isinstance(h, dict)] if not _err(hot) else []
    out = {"ise_version": patch.get("iseVersion"), "patches": numbers, "hotpatches": hotpatches}
    latest = max((n for n in numbers if isinstance(n, int)), default=None)
    f.add(
        "info",
        "patches",
        f"ISE {patch.get('iseVersion')} patch {latest if latest is not None else 'none'}"
        + (f", hot patches: {', '.join(map(str, hotpatches))}" if hotpatches else "")
        + ". REST reports the PAN's patch level; per-node levels are only shown in the GUI.",
    )
    return out


def check_backup(last: Any, repos: Any, f: Findings) -> dict[str, Any]:
    out: dict[str, Any] = {}
    repo_names = [str(r.get("name")) for r in repos or [] if isinstance(r, dict)] if not _err(repos) else []
    out["repositories"] = repo_names
    if _err(repos):
        f.add("low", "backup", f"Could not read repositories: {_err(repos)}")
    elif not repo_names:
        f.add(
            "medium",
            "backup",
            "No repository is defined, so configuration backups have nowhere to go.",
            "Add one (Administration > Maintenance > Repository), then schedule a configuration backup.",
        )
    if _err(last):
        f.add("low", "backup", f"Could not read the last backup status: {_err(last)}")
        return out
    data = {k: v for k, v in (last or {}).items() if v not in (None, "")} if isinstance(last, dict) else {}
    out["last_backup"] = data or None
    if not data:
        f.add(
            "high",
            "backup",
            "No configuration backup has ever run on this deployment.",
            "Run and schedule a configuration backup to a repository (the REST API has no schedule view).",
        )
        return out
    status = str(data.get("status") or "").upper()
    when = _parse_date(data.get("startDate"))
    if status and status not in ("COMPLETED", "SUCCESS", "SUCCEEDED", "IN_PROGRESS", "RUNNING"):
        f.add("high", "backup", f"The last configuration backup ended with {status}: {data.get('message')}")
    if data.get("startDate") and when is None:
        f.add("low", "backup", f"Could not parse the last backup time {data.get('startDate')!r}.")
    if when and (age := (datetime.now(UTC) - when).days) > BACKUP_MAX_AGE_DAYS:
        f.add(
            "medium", "backup", f"The last configuration backup is {age} days old ({data.get('startDate')})."
        )
    return out


def check_certs(rows: list[dict[str, Any]], f: Findings, warn_days: int) -> list[dict[str, Any]]:
    flagged: list[dict[str, Any]] = []
    for c in rows:
        used = str(c.get("used_by") or "")
        roles = [r for r in KEY_CERT_ROLES if r in used]
        days = c.get("days_left")
        label = f"{c.get('node')}: '{c.get('name')}'" + (f" ({used})" if used else "")
        if days is not None and days < 0:
            f.add(
                "critical" if roles else "low",
                "certificates",
                f"{label} expired {-days} days ago",
                "Renew and bind a new certificate for these roles." if roles else None,
            )
            flagged.append(c)
        elif days is not None and days <= warn_days and roles:
            f.add(
                "high" if days <= 30 else "medium",
                "certificates",
                f"{label} expires in {days} days",
                "Renew it before it expires (CSR, sign, bind).",
            )
            flagged.append(c)
        if c.get("self_signed") and any(r in roles for r in ("EAP Authentication", "Admin", "Portal")):
            f.add(
                "medium",
                "certificates",
                f"{label} is self-signed: supplicants and browsers will not trust it by default",
                "Replace it with a CA-signed certificate for EAP/Admin/Portal.",
            )
            if c not in flagged:
                flagged.append(c)
    return flagged


def check_license(tiers: Any, evaluation: Any, smart: Any, f: Findings) -> dict[str, Any]:
    if _err(tiers):
        f.add("low", "licence", f"Could not read licence tiers: {_err(tiers)}")
        return {}
    rows = [
        {
            "tier": t.get("name"),
            "status": t.get("status"),
            "compliance": t.get("compliance"),
            "consumption": t.get("consumptionCounter"),
            "days_out_of_compliance": t.get("daysOutOfCompliance"),
        }
        for t in tiers or []
        if isinstance(t, dict)
    ]
    days = evaluation.get("daysRemaining") if isinstance(evaluation, dict) else None
    eval_tiers = [str(r["tier"]) for r in rows if str(r.get("compliance")).upper() == "EVALUATION"]
    if eval_tiers:
        sev = "high" if isinstance(days, int) and days <= 30 else "medium"
        f.add(
            sev,
            "licence",
            f"Running on an EVALUATION licence ({', '.join(eval_tiers)})"
            + (f", {days} days left" if days is not None else ""),
            "Register with Smart Licensing before the evaluation ends; features stop working after it.",
        )
    for r in rows:
        comp = str(r.get("compliance") or "").upper()
        if comp in ("OUT_OF_COMPLIANCE", "NON_COMPLIANT", "OUTOFCOMPLIANCE"):
            f.add(
                "high",
                "licence",
                f"Tier {r['tier']} is out of compliance ({r.get('days_out_of_compliance')} days)",
            )
    out: dict[str, Any] = {"tiers": rows}
    if days is not None:
        out["evaluation_days_left"] = days
    if isinstance(smart, dict) and not _err(smart):
        out["smart_licensing"] = {k: smart.get(k) for k in ("state", "connectionType") if k in smart}
    return out


async def check_ad(app: IseApp, f: Findings) -> dict[str, Any]:
    try:
        page = await app.ers_pager.fetch_page(app.ers, "/ers/config/activedirectory", limit=50)
    except (UpstreamError, NotFound) as e:
        f.add("low", "active_directory", f"Could not read AD join points (ERS): {str(e)[:150]}")
        return {}
    points = [p for p in page.items if isinstance(p, dict) and p.get("id")]
    if not points:
        f.add("info", "active_directory", "No Active Directory join point is configured.")
        return {"join_points": []}

    async def detail(p: dict[str, Any]) -> dict[str, Any]:
        try:
            return await app.ers_get("activedirectory", str(p["id"]))
        except (UpstreamError, NotFound):
            return p

    full = await gather_limited(points, detail)
    rows = [{"name": p.get("name"), "domain": p.get("domain"), "id": p.get("id")} for p in full]
    f.add(
        "info",
        "active_directory",
        f"{len(rows)} AD join point(s): {', '.join(str(r['name']) for r in rows)}. Per-node join status is "
        "not exposed by the REST API; check Administration > Identity Management > External Identity "
        "Sources > Active Directory.",
    )
    return {"join_points": rows}


# Smallest built-in admin group set per server tier (see docs/least-privilege.md). The server's own
# account should hold the groups for the tiers it enables and no more.
TIER_GROUPS: dict[str, set[str]] = {
    "read": {"ERS Operator", "Read Only Admin"},
    "write": {"ERS Admin", "Policy Admin", "Network Device Admin", "Identity Admin", "MnT Admin"},
    "dangerous": {"Super Admin"},
}


async def check_admin_privilege(app: IseApp, f: Findings) -> dict[str, Any]:
    """Report the server's own ISE admin account and the RBAC admin groups it holds, and flag when it
    is more privileged than the enabled tiers need (least-privilege, I16). ERS GET-only, so it works
    for every tier. Returns {} silently if ERS can't be read (another finding already covers that)."""
    name = app.settings.username
    if not name:
        return {}
    try:
        page = await app.ers_pager.fetch_page(app.ers, "/ers/config/adminuser", limit=200)
        match = next((r for r in page.items if str(r.get("name", "")).lower() == name.lower()), None)
        if match is None:
            return {}
        detail = await app.ers_get("adminuser", str(match["id"]))
    except (UpstreamError, NotFound, KeyError):
        return {}
    raw = detail.get("adminGroups") if isinstance(detail, dict) else None
    parts = [str(g) for g in raw] if isinstance(raw, list) else str(raw or "").split(",")
    groups = {g.strip() for g in parts if g.strip()}
    enabled = ["read"]
    if app.settings.mcp_enable_writes:
        enabled.append("write")
    if app.settings.mcp_enable_dangerous:
        enabled.append("dangerous")
    out = {"account": name, "admin_groups": sorted(groups), "tiers_enabled": enabled}
    if "Super Admin" in groups and "dangerous" not in enabled:
        f.add(
            "medium",
            "privilege",
            f"The server account '{name}' is a Super Admin, but only {', '.join(enabled)} "
            "tier(s) are enabled.",
            "Use a least-privilege account (docs/least-privilege.md): "
            f"{', '.join(sorted(g for t in enabled for g in TIER_GROUPS[t]))}.",
        )
    elif "dangerous" in enabled and "Super Admin" not in groups:
        f.add(
            "info",
            "privilege",
            f"The server account '{name}' holds {', '.join(sorted(groups)) or 'no admin groups'}; "
            "the dangerous tier (CoA, ANC, node/persona and certificate changes) needs Super Admin.",
        )
    else:
        f.add("info", "privilege", f"The server account '{name}' holds: {', '.join(sorted(groups))}.")
    return out


async def system_certs(app: IseApp, hosts: list[str], f: Findings) -> list[dict[str, Any]]:
    async def one(host: str) -> list[dict[str, Any]]:
        try:
            certs = await openapi_all(app, f"/api/v1/certs/system-certificate/{quote(host, safe='')}")
        except (UpstreamError, NotFound) as e:
            f.add(
                "medium", "certificates", f"Could not read the system certificates of {host}: {str(e)[:150]}"
            )
            return []
        out = []
        for c in certs:
            if isinstance(c, dict):
                row = _cert_row(c, host)
                if c.get("selfSigned"):
                    row["self_signed"] = True
                if c.get("expirationDate") and row.get("days_left") is None:
                    f.add("low", "certificates", f"{host}: could not parse the expiry of '{row.get('name')}'")
                out.append(row)
        return out

    return [c for rows in await gather_limited(hosts, one) for c in rows]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Deployment health check")
    async def ise_deployment_health(
        ctx: Context,
        cert_warn_days: Annotated[
            int, Field(ge=1, le=730, description="Flag certificates that expire within this many days")
        ] = 90,
    ) -> ToolResult:
        """One-call ISE health check with severity-ranked findings (critical > high > medium > low >
        info): node sync status, personas/services and redundancy (PAN HA, secondary PAN/MnT, a PSN
        present); patch and hot-patch level; last configuration backup (flagged when failed or older
        than 7 days) and repositories; system certificates per node (expired, expiring within
        cert_warn_days, self-signed EAP/Admin/Portal certs); licence tiers and compliance (flags
        evaluation licences and days left); AD join points; and the server's own ISE admin account
        and RBAC groups, flagged when more privileged than the enabled tiers need (I16). Use it weekly
        or before a change.
        Details: ise_list_nodes, ise_list_patches, ise_get_backup_status, ise_list_certificates,
        ise_get_license_status."""
        app: IseApp = get_client(ctx)
        f = Findings()
        nodes, pan_ha, patch, hot, last, repos, tiers, evaluation, smart = await asyncio.gather(
            _get(app, "/api/v1/deployment/node"),
            _get(app, "/api/v1/deployment/pan-ha"),
            _get(app, "/api/v1/patch"),
            _get(app, "/api/v1/hotpatch"),
            _get(app, "/api/v1/backup-restore/config/last-backup-status"),
            _get(app, "/api/v1/repository"),
            _get(app, "/api/v1/license/system/tier-state"),
            _get(app, "/api/v1/license/system/eval-license"),
            _get(app, "/api/v1/license/system/smart-state"),
        )
        node_rows = check_nodes(nodes, pan_ha, f)
        hosts = [str(n["hostname"]) for n in node_rows if n.get("hostname")]
        certs, ad, privilege = await asyncio.gather(
            system_certs(app, hosts, f), check_ad(app, f), check_admin_privilege(app, f)
        )
        if not hosts:
            f.add("medium", "certificates", "System certificates were not checked: no node list.")
        sections: dict[str, Any] = {
            "nodes": node_rows,
            "patches": check_patches(patch, hot, f),
            "backup": check_backup(last, repos, f),
            "certificates_flagged": check_certs(certs, f, cert_warn_days),
            "licence": check_license(tiers, evaluation, smart, f),
            "active_directory": ad,
            "server_privilege": privilege,
        }
        sections["certificates_checked"] = len(certs)
        summary = f.summary()
        worst = next((s for s in SEVERITIES if s in summary and s != "info"), None)
        return object_result(
            {
                "verdict": f"Worst finding: {worst}" if worst else "Healthy: no problems above info level",
                "summary": summary,
                "findings": f.ranked(),
                **sections,
            }
        )

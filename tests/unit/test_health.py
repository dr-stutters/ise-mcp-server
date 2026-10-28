from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import respx

from ise_mcp._core.testing import call_tool
from tests.unit.conftest import ers_page, make_server


def _d(days: int) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).strftime("%a %b %d %H:%M:%S UTC %Y")


LSD = "/api/v1/lsd/updateLsdSettings"

NODES = [
    {
        "hostname": "pan1",
        "ipAddress": "10.0.0.1",
        "roles": ["PrimaryAdmin", "PrimaryMonitoring"],
        "services": [],
        "nodeStatus": "Connected",
    },
    {
        "hostname": "psn1",
        "ipAddress": "10.0.0.2",
        "roles": [],
        "services": ["Session", "Profiler"],
        "nodeStatus": "Connected",
    },
    {
        "hostname": "psn2",
        "ipAddress": "10.0.0.3",
        "roles": [],
        "services": ["Session"],
        "nodeStatus": "Disconnected",
    },
]


def cert(name: str, used: str, days: int, self_signed: bool = False) -> dict:  # type: ignore[type-arg]
    return {
        "id": name,
        "friendlyName": name,
        "usedBy": used,
        "issuedBy": "CA",
        "expirationDate": _d(days),
        "selfSigned": self_signed,
    }


def mock_deployment(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(json={"response": NODES})
    mock.get("/api/v1/deployment/pan-ha").respond(json={"response": {"isEnabled": False}})
    mock.get("/api/v1/patch").respond(
        json={"iseVersion": "3.3.0.430", "patchVersion": [{"patchNumber": 2}, {"patchNumber": 4}]}
    )
    mock.get("/api/v1/hotpatch").respond(json={"response": [{"hotpatchName": "CSCwx12345"}]})
    mock.get("/api/v1/backup-restore/config/last-backup-status").respond(
        json={
            "response": {
                "name": "nightly",
                "status": "FAILED",
                "message": "repository unreachable",
                "startDate": _d(-10),
                "error": None,
            }
        }
    )
    mock.get("/api/v1/repository").respond(json={"response": [{"name": "sftp-repo"}]})
    mock.get("/api/v1/rbac/admin-user").respond(json={"adminUserList": []})  # I74 admins section
    mock.get(LSD).respond(json={"enableEPO": True, "enableRCM": False})  # I89 settings section
    mock.get("/api/v1/license/system/tier-state").respond(
        json=[
            {"name": "ESSENTIAL", "status": "ENABLED", "compliance": "COMPLIANT"},
            {
                "name": "ADVANTAGE",
                "status": "ENABLED",
                "compliance": "OUT_OF_COMPLIANCE",
                "daysOutOfCompliance": "12",
            },
        ]
    )
    mock.get("/api/v1/license/system/eval-license").respond(json={"daysRemaining": 0})
    mock.get("/api/v1/license/system/smart-state").respond(json={"response": {"state": "ENABLED"}})
    mock.get("/api/v1/certs/system-certificate/pan1").respond(
        json={"response": [cert("admin", "Admin", 20), cert("old-unused", "", -5)]}
    )
    mock.get("/api/v1/certs/system-certificate/psn1").respond(
        json={"response": [cert("eap", "EAP Authentication", -3), cert("portal", "Portal", 400, True)]}
    )
    mock.get("/api/v1/certs/system-certificate/psn2").respond(503)
    mock.get("/ers/config/activedirectory").respond(json=ers_page([{"id": "ad1", "name": "corp"}]))
    mock.get("/ers/config/activedirectory/ad1").respond(
        json={"ERSActiveDirectory": {"id": "ad1", "name": "corp", "domain": "corp.example"}}
    )
    mock_adminuser(mock, "Super Admin")


def mock_adminuser(mock: respx.MockRouter, groups: str, name: str = "admin") -> None:
    mock.get("/ers/config/adminuser").respond(json=ers_page([{"id": "au1", "name": name}]))
    mock.get("/ers/config/adminuser/au1").respond(
        json={"AdminUser": {"id": "au1", "name": name, "adminGroups": groups}}
    )


async def test_health_multi_node(mock: respx.MockRouter) -> None:
    mock_deployment(mock)
    out = await call_tool(make_server(), "ise_deployment_health")
    out = out if isinstance(out, dict) else json.loads(str(out))
    sev = [f["severity"] for f in out["findings"]]
    assert sev == sorted(sev, key=["critical", "high", "medium", "low", "info"].index)
    text = json.dumps(out["findings"])
    assert out["verdict"] == "Worst finding: critical"
    assert "psn1: 'eap' (EAP Authentication) expired" in text
    assert "pan1: 'admin' (Admin) expires in" in text
    assert "Node psn2 is Disconnected" in text
    assert "FAILED" in text and "days old" in text
    assert "Tier ADVANTAGE is out of compliance" in text
    assert "No secondary Administration node" in text and "PAN HA" in text
    assert "self-signed" in text and "portal" in text
    assert "corp" in text
    assert "Could not read the system certificates of psn2" in text
    assert "EVALUATION" not in text
    expired_unused = [f for f in out["findings"] if "old-unused" in f["finding"]]
    assert expired_unused and expired_unused[0]["severity"] == "low"
    assert out["summary"]["critical"] == 1
    assert out["patches"]["hotpatches"] == ["CSCwx12345"]
    assert out["admins"]["admins"] == 0  # I74 section present


async def test_health_standalone_evaluation_no_backup(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(
        json={
            "response": [
                {
                    "hostname": "ise",
                    "roles": ["Standalone"],
                    "services": ["Session"],
                    "nodeStatus": "Connected",
                }
            ]
        }
    )
    mock.get("/api/v1/deployment/pan-ha").respond(json={"response": {"isEnabled": False}})
    mock.get("/api/v1/patch").respond(json={"iseVersion": "3.5.0.527", "patchVersion": []})
    mock.get("/api/v1/hotpatch").respond(json={"response": []})
    mock.get("/api/v1/backup-restore/config/last-backup-status").respond(
        json={"response": {"name": None, "status": None, "error": None}}
    )
    mock.get("/api/v1/repository").respond(json={"response": None})
    mock.get("/api/v1/license/system/tier-state").respond(
        json=[{"name": "ADVANTAGE", "status": "ENABLED", "compliance": "EVALUATION"}]
    )
    mock.get("/api/v1/license/system/eval-license").respond(json={"daysRemaining": 12})
    mock.get("/api/v1/license/system/smart-state").respond(500, json={"message": "boom"})
    mock.get("/api/v1/certs/system-certificate/ise").respond(
        json={
            "response": [
                cert("Default self-signed server certificate", "EAP Authentication, Admin", 500, True)
            ]
        }
    )
    mock.get("/ers/config/activedirectory").respond(json=ers_page([]))
    mock_adminuser(mock, "Super Admin")
    mock.get("/api/v1/rbac/admin-user").respond(json={"adminUserList": []})
    mock.get(LSD).respond(404, json={"message": "not found"})  # older release: no LSD settings
    out = await call_tool(make_server(), "ise_deployment_health")
    out = out if isinstance(out, dict) else json.loads(str(out))
    text = json.dumps(out["findings"])
    assert "No configuration backup has ever run" in text
    assert "No repository is defined" in text
    assert "EVALUATION licence (ADVANTAGE), 12 days left" in text
    assert [f["severity"] for f in out["findings"] if "EVALUATION" in f["finding"]] == ["high"]
    assert "Standalone deployment" in text and "No Active Directory join point" in text
    assert "patch none" in text


async def test_health_survives_area_errors(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(500, json={"message": "down"})
    for path in (
        "/api/v1/deployment/pan-ha",
        "/api/v1/patch",
        "/api/v1/hotpatch",
        "/api/v1/backup-restore/config/last-backup-status",
        "/api/v1/repository",
        "/api/v1/license/system/tier-state",
        "/api/v1/license/system/eval-license",
        "/api/v1/license/system/smart-state",
    ):
        mock.get(path).respond(500, json={"message": "down"})
    mock.get("/ers/config/activedirectory").respond(json=ers_page([{"id": "ad1", "name": "corp"}]))
    mock.get("/ers/config/activedirectory/ad1").respond(500, json={})
    mock.get("/ers/config/adminuser").respond(500, json={})
    mock.get("/api/v1/rbac/admin-user").respond(500, json={})
    mock.get(LSD).respond(500, json={"message": "down"})
    out = await call_tool(make_server(), "ise_deployment_health")
    out = out if isinstance(out, dict) else json.loads(str(out))
    assert out["summary"]["high"] >= 1
    text = json.dumps(out["findings"])
    assert "Could not read the deployment nodes" in text
    assert "no node list" in text and "1 AD join point(s): corp" in text
    assert not out.get("server_privilege")  # ERS adminuser unreadable: reported silently
    assert not [f for f in out["findings"] if f["area"] == "privilege"]
    assert not out.get("admins") and "Admin accounts were not reviewed" in text  # I74


async def test_health_flags_over_privileged_account(mock: respx.MockRouter) -> None:
    mock_deployment(mock)  # account 'admin' is Super Admin
    out = await call_tool(make_server(), "ise_deployment_health")  # read-only server
    out = out if isinstance(out, dict) else json.loads(str(out))
    assert out["server_privilege"]["admin_groups"] == ["Super Admin"]
    assert out["server_privilege"]["tiers_enabled"] == ["read"]
    priv = [f for f in out["findings"] if f["area"] == "privilege"]
    assert priv and priv[0]["severity"] == "medium" and "Super Admin" in priv[0]["finding"]


async def test_health_privilege_ok_when_dangerous_enabled(mock: respx.MockRouter) -> None:
    mock_deployment(mock)
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    out = await call_tool(server, "ise_deployment_health")
    out = out if isinstance(out, dict) else json.loads(str(out))
    assert out["server_privilege"]["tiers_enabled"] == ["read", "write", "dangerous"]
    priv = [f for f in out["findings"] if f["area"] == "privilege"]
    assert priv and priv[0]["severity"] == "info"


async def test_health_settings_mac_randomization(mock: respx.MockRouter) -> None:
    """I89: endpoint ownership and RCM appear in the settings section."""
    mock_deployment(mock)
    out = await call_tool(make_server(), "ise_deployment_health")
    out = out if isinstance(out, dict) else json.loads(str(out))
    assert out["settings"]["mac_randomization"] == {"endpoint_ownership": True, "rcm": False}


async def test_health_settings_unknown_when_unreadable(mock: respx.MockRouter) -> None:
    mock_deployment(mock)
    mock.get(LSD).respond(500, json={"message": "down"})
    out = await call_tool(make_server(), "ise_deployment_health")
    out = out if isinstance(out, dict) else json.loads(str(out))
    assert out["settings"]["mac_randomization"] == {"endpoint_ownership": "unknown", "rcm": "unknown"}
    assert out["nodes"]  # the rest of the check still ran

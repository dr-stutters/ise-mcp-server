"""NADs, endpoints, identity, policy, TrustSec and system tools."""

from __future__ import annotations

import json
from typing import Any

import respx

from ise_mcp._core.testing import call_tool
from tests.unit.conftest import ers_page, fixture_json, make_server


def as_json(out: Any) -> Any:
    return out if isinstance(out, dict) else json.loads(str(out))


def nad(
    nid: str,
    name: str,
    ips: list[tuple[str, int]],
    secret: str | None,
    groups: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    auth = {"networkProtocol": "RADIUS", "enableMultiSecret": "false"}
    if secret:
        auth["radiusSharedSecret"] = secret
    return {
        "NetworkDevice": {
            "id": nid,
            "name": name,
            "authenticationSettings": auth,
            "NetworkDeviceIPList": [{"ipaddress": ip, "mask": m} for ip, m in ips],
            "NetworkDeviceGroupList": groups or ["Location#All Locations", "Device Type#All Device Types"],
            **extra,
        }
    }


def mock_nads(mock: respx.MockRouter, nads: list[dict[str, Any]]) -> None:
    mock.get("/ers/config/networkdevice", params={"filter": "ipaddress.EQ.10.1.1.5"}).respond(
        json=ers_page([])
    )
    mock.get("/ers/config/networkdevice").respond(
        json=ers_page([{"id": n["NetworkDevice"]["id"], "name": n["NetworkDevice"]["name"]} for n in nads])
    )
    for n in nads:
        mock.get(f"/ers/config/networkdevice/{n['NetworkDevice']['id']}").respond(json=n)


async def test_list_nads_never_leaks_secrets(mock: respx.MockRouter) -> None:
    raw = fixture_json("ers_networkdevice.json")
    nid = raw["NetworkDevice"]["id"]
    mock.get("/ers/config/networkdevice").respond(json=ers_page([{"id": nid, "name": "sw1"}]))
    mock.get(f"/ers/config/networkdevice/{nid}").respond(json=raw)
    server = make_server()
    for fmt in ("json", "markdown"):
        out = await call_tool(server, "ise_list_nads", {"response_format": fmt})
        assert "REDACTED" not in json.dumps(out)
    out = as_json(await call_tool(server, "ise_list_nads", {"response_format": "json"}))
    assert out["results"][0]["radius"] == "secret set"
    assert out["results"][0]["tacacs"] == "secret set"
    got = await call_tool(server, "ise_get_nad", {"device": nid})
    text = json.dumps(got)
    assert "REDACTED" not in text
    assert got["authenticationSettings"]["radiusSharedSecret"] == "********"
    assert got["snmpsettings"]["roCommunity"] == "********"
    assert got["tacacsSettings"]["sharedSecret"] == "********"
    assert got["authenticationSettings"]["multiSecretEnabled"] is False


async def test_get_nad_by_ip_in_subnet(mock: respx.MockRouter) -> None:
    nads = [
        nad("n1", "core", [("10.1.0.0", 16)], "s1"),
        nad("n2", "access", [("10.1.1.0", 24)], "s2"),
        nad("n3", "other", [("10.2.0.0", 16)], "s3"),
    ]
    mock_nads(mock, nads)
    got = await call_tool(make_server(), "ise_get_nad", {"device": "10.1.1.5"})
    assert got["name"] == "access"  # most specific subnet wins


async def test_get_nad_by_ip_none(mock: respx.MockRouter) -> None:
    mock_nads(mock, [nad("n3", "other", [("10.2.0.0", 16)], "s3")])
    async with __import__("fastmcp").Client(make_server()) as c:
        r = await c.call_tool("ise_get_nad", {"device": "10.1.1.5"}, raise_on_error=False)
    assert r.is_error and "11007" in r.content[0].text


async def test_audit_nads(mock: respx.MockRouter) -> None:
    nads = [
        nad("n1", "a", [("10.1.0.0", 16)], "same-secret-long-1", ["Location#All Locations#SYD"]),
        nad("n2", "b", [("10.1.1.0", 24)], "same-secret-long-1", ["Location#All Locations#SYD"]),
        nad("n3", "c", [("10.9.9.9", 32)], None),
        nad(
            "n4",
            "d",
            [("10.8.8.8", 32)],
            "short",
            ["Device Type#All Device Types#Switch"],
            snmpsettings={"version": "TWO_C", "roCommunity": "public"},
        ),
    ]
    mock_nads(mock, nads)
    out = as_json(await call_tool(make_server(), "ise_audit_nads", {}))
    findings = {r["name"]: " | ".join(r["findings"]) for r in out["results"]}
    assert "reused on 1 other device(s): b" in findings["a"]
    assert "overlaps b" in findings["a"]
    assert "no RADIUS or TACACS+" in findings["c"]
    assert "only default device groups" in findings["c"]
    assert "short" in findings["d"] and "well-known default community" in findings["d"]
    assert "same-secret" not in json.dumps(out) and "public" not in json.dumps(out)
    assert out["with_findings"] == 4


async def test_policy_set_with_rules(mock: respx.MockRouter) -> None:
    sets = fixture_json("policy_sets.json")
    pid = sets["response"][0]["id"]
    mock.get("/api/v1/policy/network-access/policy-set").respond(json=sets)
    mock.get(f"/api/v1/policy/network-access/policy-set/{pid}/authorization").respond(
        json=fixture_json("authz_rules.json")
    )
    mock.get(f"/api/v1/policy/network-access/policy-set/{pid}/authentication").respond(
        json=fixture_json("authn_rules.json")
    )
    mock.get(f"/api/v1/policy/network-access/policy-set/{pid}/exception").respond(json={"response": []})
    out = await call_tool(make_server(), "ise_get_policy_set", {"policy_set": "DEFAULT"})
    assert out["policy_set"]["name"] == "Default"
    assert [r["name"] for r in out["authentication"]] == ["MAB", "Dot1X", "Default"]
    first = out["authorization"][0]
    assert first["condition"].startswith("(Wireless_Access AND IdentityGroup:Name equals")
    assert out["authorization"][-1]["condition"] == "DEFAULT"


async def test_authz_profile_lookup_by_name_path(mock: respx.MockRouter) -> None:
    # ERS has no name filter for authz profiles and listing them is slow: GET .../name/{name}.
    mock.get("/ers/config/authorizationprofile/name/PermitAccess").respond(
        json={"AuthorizationProfile": {"id": "p1", "name": "PermitAccess"}}
    )
    listing = mock.get("/ers/config/authorizationprofile")
    mock.get("/ers/config/authorizationprofile/p1").respond(
        json={"AuthorizationProfile": {"id": "p1", "name": "PermitAccess", "accessType": "ACCESS_ACCEPT"}}
    )
    mock.get("/api/v1/policy/network-access/policy-set").respond(json={"response": []})
    out = await call_tool(make_server(), "ise_get_authz_profile", {"profile": "PermitAccess"})
    assert out["accessType"] == "ACCESS_ACCEPT"
    assert not listing.called


async def test_egress_matrix(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/egressmatrixcell").respond(json=ers_page([{"id": "c1"}, {"id": "c2"}]))
    mock.get("/ers/config/egressmatrixcell/c1").respond(
        json={
            "EgressMatrixCell": {
                "id": "c1",
                "name": "ANY-ANY",
                "sgacls": ["a1"],
                "defaultRule": "PERMIT_IP",
                "matrixCellStatus": "ENABLED",
            }
        }
    )
    mock.get("/ers/config/egressmatrixcell/c2").respond(
        json={
            "EgressMatrixCell": {
                "id": "c2",
                "name": "Emp-Dev",
                "sourceSgtId": "s1",
                "destinationSgtId": "s2",
                "sgacls": ["a2"],
                "defaultRule": "DENY_IP",
                "matrixCellStatus": "ENABLED",
            }
        }
    )
    mock.get("/ers/config/sgt").respond(json=ers_page([{"id": "s1"}, {"id": "s2"}]))
    mock.get("/ers/config/sgt/s1").respond(json={"Sgt": {"id": "s1", "name": "Employees", "value": 4}})
    mock.get("/ers/config/sgt/s2").respond(json={"Sgt": {"id": "s2", "name": "Dev_Servers", "value": 12}})
    mock.get("/ers/config/sgacl").respond(
        json=ers_page([{"id": "a1", "name": "Permit IP"}, {"id": "a2", "name": "Deny IP"}])
    )
    out = as_json(
        await call_tool(
            make_server(), "ise_get_egress_matrix", {"source": "employ", "response_format": "json"}
        )
    )
    assert out["results"] == [
        {
            "source": "Employees (4)",
            "destination": "Dev_Servers (12)",
            "sgacls": ["Deny IP"],
            "default_rule": "DENY_IP",
            "status": "ENABLED",
            "name": "Emp-Dev",
            "id": "c2",
        }
    ]


async def test_list_endpoints_filters(mock: respx.MockRouter) -> None:
    route = mock.get("/api/v1/endpoint").respond(
        json=[{"id": "e1", "mac": "AA:BB:CC:00:00:01", "groupId": "g1"}]
    )
    mock.get("/ers/config/endpointgroup").respond(json=ers_page([{"id": "g1", "name": "Printers"}]))
    mock.get("/ers/config/endpointgroup", params={"filter": "name.EQ.Printers"}).respond(
        json=ers_page([{"id": "g1", "name": "Printers"}])
    )
    out = as_json(
        await call_tool(
            make_server(),
            "ise_list_endpoints",
            {"mac": "aa:bb", "group": "Printers", "response_format": "json"},
        )
    )
    assert out["results"][0]["group"] == "Printers"
    sent = route.calls.last.request.url.params.get_list("filter")
    assert sent == ["mac.CONTAINS.AA:BB", "groupId.EQ.g1"]


async def test_internal_users_hide_passwords(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/identitygroup").respond(json=ers_page([{"id": "g1", "name": "Employees"}]))
    mock.get("/ers/config/internaluser").respond(json=ers_page([{"id": "u1", "name": "alice"}]))
    mock.get("/ers/config/internaluser/u1").respond(
        json={
            "InternalUser": {
                "id": "u1",
                "name": "alice",
                "enabled": True,
                "identityGroups": "g1",
                "password": "hunter2",
                "enablePassword": "hunter3",
                "passwordIDStore": "Internal Users",
            }
        }
    )
    out = as_json(await call_tool(make_server(), "ise_list_internal_users", {"response_format": "json"}))
    assert out["results"][0]["groups"] == ["Employees"]
    assert out["results"][0]["auth_store"] == "Internal Users"
    assert "hunter" not in json.dumps(out)


async def test_certificates_expiring(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/deployment/node", name="nodes").respond(json={"response": [{"hostname": "ise1"}]})
    mock.get("/api/v1/certs/system-certificate/ise1").respond(
        json={
            "response": [
                {
                    "id": "c1",
                    "friendlyName": "old",
                    "usedBy": "EAP",
                    "expirationDate": "Thu Jan 01 00:00:00 UTC 2026",
                },
                {
                    "id": "c2",
                    "friendlyName": "new",
                    "usedBy": "Admin",
                    "expirationDate": "Thu Jan 01 00:00:00 UTC 2099",
                },
            ]
        }
    )
    out = as_json(
        await call_tool(
            make_server(), "ise_list_certificates", {"expiring_within_days": 30, "response_format": "json"}
        )
    )
    assert [c["name"] for c in out["results"]] == ["old"]
    assert out["results"][0]["days_left"] < 0


async def test_backup_none(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/backup-restore/config/last-backup-status").respond(
        json={"response": {"status": None, "name": None}}
    )
    out = await call_tool(make_server(), "ise_get_backup_status")
    assert out["status"] == "none"


async def test_patches(mock: respx.MockRouter) -> None:
    mock.get("/api/v1/patch").respond(
        json={"iseVersion": "3.5.0.527", "patchVersion": [{"patchNumber": 4, "installDate": "x"}]}
    )
    mock.get("/api/v1/hotpatch").respond(json={"response": [{"hotpatchName": "HP1", "installDate": "y"}]})
    out = as_json(await call_tool(make_server(), "ise_list_patches", {"response_format": "json"}))
    assert out["ise_version"] == "3.5.0.527"
    assert [r["name"] for r in out["results"]] == ["Patch 4", "HP1"]


async def test_egress_matrix_effective_default(mock: respx.MockRouter) -> None:
    await test_egress_matrix(mock)  # same mocks; the reverse pair has no explicit cell
    out = as_json(
        await call_tool(
            make_server(),
            "ise_get_egress_matrix",
            {"source": "Dev_Servers", "destination": "Employees", "response_format": "json"},
        )
    )
    assert out["results"] == []
    assert out["effective"]["applies"] == "ANY-ANY default"
    assert out["effective"]["sgacls"] == ["Permit IP"] and out["effective"]["default_rule"] == "PERMIT_IP"
    out = as_json(
        await call_tool(
            make_server(),
            "ise_get_egress_matrix",
            {"source": "Nope", "destination": "Employees", "response_format": "json"},
        )
    )
    assert "No SGT name contains 'Nope'" in out["effective"]


async def test_authz_profile_name_path_404_falls_back_to_scan(mock: respx.MockRouter) -> None:
    mock.get("/ers/config/authorizationprofile/name/permitaccess").respond(404, json={})
    mock.get("/ers/config/authorizationprofile", params={"filter": "name.EQ.permitaccess"}).respond(
        400, json={"ERSResponse": {"messages": [{"title": "The filter field 'name' is not supported"}]}}
    )
    mock.get("/ers/config/authorizationprofile").respond(
        json=ers_page([{"id": "p1", "name": "PermitAccess"}])
    )
    mock.get("/ers/config/authorizationprofile/p1").respond(
        json={"AuthorizationProfile": {"id": "p1", "name": "PermitAccess", "accessType": "ACCESS_ACCEPT"}}
    )
    mock.get("/api/v1/policy/network-access/policy-set").respond(json={"response": []})
    out = await call_tool(make_server(), "ise_get_authz_profile", {"profile": "permitaccess"})
    assert out["accessType"] == "ACCESS_ACCEPT"


# --- I67: ise_audit_nads(expected=...) ---------------------------------------------------------
# The lab on 2026-10-21: ISE's four NADs and Catalyst Center's inventory, with sw1 in both. Catalyst
# Center reused the NAD mcp-test-sw1 when it provisioned sw1 (inventory name mcp-sw1.mcp.lab).

LAB = "Location#All Locations#mcp-test-lab"
LAB_NADS = [
    nad("n1", "mcp-test-sw1", [("198.18.128.154", 32)], "secret-sw1-long-xx", [LAB, "IPSEC#Is IPSEC Device"]),
    nad("n2", "mcp-test-cml-identity-sw", [("198.18.128.194", 32)], "secret-id-long-xxx", [LAB]),
    nad("n3", "mcp-test-radius-client", [("10.16.138.131", 32)], "secret-rc-long-xxx"),
    nad("n4", "mcp-test-cml-ap", [("198.18.128.196", 32)], "secret-ap-long-xxx"),
]
SW1_ROW = {"hostname": "mcp-sw1.mcp.lab", "managementIpAddress": "198.18.128.154", "role": "ACCESS"}


def mock_nodes(mock: respx.MockRouter) -> respx.Route:
    return mock.get("/api/v1/deployment/node").respond(
        json={"response": [{"hostname": "ise", "fqdn": "ise.mitchcloud.lab", "ipAddress": "198.18.134.35"}]}
    )


async def test_audit_nads_expected_clean_positive_case(mock: respx.MockRouter) -> None:
    mock_nads(mock, LAB_NADS)
    mock_nodes(mock)
    out = as_json(
        await call_tool(
            make_server(),
            "ise_audit_nads",
            # A catc_list_devices row as it comes (hostname / managementIpAddress), plus the site group.
            {
                "expected": [{**SW1_ROW, "ndg": "mcp-test-lab", "aaa_server": "198.18.134.35"}],
                "check_stale": False,
            },
        )
    )
    cov = out["coverage"]
    assert cov["devices"] == [
        {
            "device": "mcp-sw1.mcp.lab",
            "ip": "198.18.128.154",
            "nad": "mcp-test-sw1",
            "match": "ip",
            "nad_name_differs": True,
            "findings": ["ok"],
        }
    ]
    assert cov["ok"] == 1 and "missing_nad" not in cov and "stale_nads" not in cov
    assert cov["verdict"].startswith(
        "1 of 1 expected device(s) are NADs in ISE (matched by IP; 1 under another"
    )
    assert "Stale NADs not checked" in cov["verdict"]
    assert not any("stale_nad" in f for r in out["results"] for f in r["findings"])


async def test_audit_nads_expected_full_inventory(mock: respx.MockRouter) -> None:
    mock_nads(mock, LAB_NADS)
    mock_nodes(mock)
    inventory = [
        SW1_ROW,
        {"hostname": "r1.mcp.lab", "managementIpAddress": "198.18.128.152"},
        {"hostname": "mcp-catc-wlc.mcp.lab", "managementIpAddress": "198.18.128.173"},
    ]
    out = as_json(await call_tool(make_server(), "ise_audit_nads", {"expected": inventory}))
    cov = out["coverage"]
    assert cov["missing_nad"] == 2 and cov["stale_nad"] == 3 and cov["ok"] == 1
    missing = {r["device"]: r for r in cov["devices"] if r["findings"] != ["ok"]}
    assert set(missing) == {"r1.mcp.lab", "mcp-catc-wlc.mcp.lab"}
    assert "11007" in missing["r1.mcp.lab"]["findings"][0]
    assert missing["r1.mcp.lab"]["fix"][0].startswith(
        "ise_create_nad(name='r1.mcp.lab', ips=['198.18.128.152/32']"
    )
    assert [s["nad"] for s in cov["stale_nads"]] == [
        "mcp-test-cml-identity-sw",
        "mcp-test-radius-client",
        "mcp-test-cml-ap",
    ]
    assert cov["stale_scope"] == "every NAD"
    stale_rows = {r["name"] for r in out["results"] if any("stale_nad" in f for f in r["findings"])}
    assert stale_rows == {"mcp-test-cml-identity-sw", "mcp-test-radius-client", "mcp-test-cml-ap"}
    assert "secret-" not in json.dumps(out)


async def test_audit_nads_expected_scoped_stale_wrong_ndg_and_aaa(mock: respx.MockRouter) -> None:
    mock_nads(mock, LAB_NADS)
    mock_nodes(mock)
    row = {
        "name": "mcp-sw1",
        "ip": "198.18.128.154",
        "ndg": ["mcp-test-lab", "Switch"],
        "aaa_server": "10.9.9.9",
    }
    out = as_json(
        await call_tool(make_server(), "ise_audit_nads", {"expected": [row], "stale_within": "mcp-test-lab"})
    )
    cov = out["coverage"]
    findings = cov["devices"][0]["findings"]
    assert findings[0].startswith("wrong_ndg: NAD mcp-test-sw1 is not in Switch")
    assert findings[1].startswith("aaa_elsewhere: its RADIUS server 10.9.9.9 is not an ISE node")
    assert "ise.mitchcloud.lab" in findings[1]
    assert cov["devices"][0]["nad_name_differs"] is True
    # Only NADs in the site's location group can be stale.
    assert [s["nad"] for s in cov["stale_nads"]] == ["mcp-test-cml-identity-sw"]
    assert cov["stale_scope"] == "NADs in mcp-test-lab"


async def test_audit_nads_expected_ip_mismatch_and_subnet(mock: respx.MockRouter) -> None:
    nads = [
        nad("n1", "edge-sw7", [("10.20.0.7", 32)], "secret-e7-long-xxx", [LAB]),  # re-addressed switch
        nad("n2", "syd-access", [("10.30.0.0", 24)], "secret-sy-long-xxx", [LAB]),
    ]
    mock_nads(mock, nads)
    expected = [
        {"name": "edge-sw7.corp.local", "ip": "10.20.9.7"},
        {"name": "syd-sw3", "ip": "10.30.0.33"},
    ]
    out = as_json(await call_tool(make_server(), "ise_audit_nads", {"expected": expected}))
    rows = {r["device"]: r for r in out["coverage"]["devices"]}
    moved = rows["edge-sw7.corp.local"]
    assert [f.split(":")[0] for f in moved["findings"]] == ["missing_nad", "ip_mismatch"]
    assert "NAD edge-sw7 has the device's name but 10.20.0.7/32, not 10.20.9.7" in moved["findings"][1]
    assert "ise_update_nad(device='edge-sw7', ips=['10.20.9.7/32'])" in moved["fix"][1]
    sub = rows["syd-sw3"]
    assert (
        sub["nad"] == "syd-access" and sub["match"] == "subnet (10.30.0.0/24)" and sub["findings"] == ["ok"]
    )
    assert "stale_nads" not in out["coverage"]  # both NADs matched a device (by name or subnet)


async def test_audit_nads_expected_refuses_bad_ips(mock: respx.MockRouter) -> None:
    mock_nads(mock, LAB_NADS)
    async with __import__("fastmcp").Client(make_server()) as c:
        r = await c.call_tool(
            "ise_audit_nads", {"expected": [{"name": "x", "ip": "not-an-ip"}]}, raise_on_error=False
        )
    assert r.is_error and "not-an-ip" in r.content[0].text

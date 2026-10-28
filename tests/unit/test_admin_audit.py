"""I74: admin access audit reads (respx). Payload shapes are the lab ISE 3.5's live OpenAPI RBAC answers
(2026-10-28: admin-user list + detail, admin-group list + detail, policy list, menu-access and data-access
detail; the admin-group list leaving out a group a policy names), with synthetic admins: a disabled
Helpdesk admin, a never-disabled Super Admin and an external admin group mapped to AD groups."""

from __future__ import annotations

from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from tests.unit.conftest import make_server

R = "/api/v1/rbac"

USERS = [
    {
        "id": "00000000-0000-4000-8000-000000000001",
        "name": "admin",
        "firstName": "",
        "lastName": "",
        "description": "Default Admin User",
        "statusEnabled": True,
        "emailAddr": "",
        "rbacGroupNames": ["Super Admin"],
    },
    {
        "id": "00000000-0000-4000-8000-000000000002",
        "name": "noc-breakglass",
        "firstName": "Break",
        "lastName": "Glass",
        "description": "",
        "statusEnabled": True,
        "emailAddr": "noc@example.com",
        "rbacGroupNames": ["Super Admin"],
    },
    {
        "id": "00000000-0000-4000-8000-000000000003",
        "name": "helpdesk-old",
        "description": "left 2026-09",
        "statusEnabled": False,
        "rbacGroupNames": ["Helpdesk Admin"],
    },
    {
        "id": "00000000-0000-4000-8000-000000000004",
        "name": "api-trustsec",
        "description": "ERSUser",
        "statusEnabled": True,
        "rbacGroupNames": ["ERS Trustsec"],
    },
]


def detail(name: str, groups: list[str], **flags: Any) -> dict[str, Any]:
    base = {
        "name": name,
        "firstName": "",
        "lastName": "",
        "password": "",
        "description": "",
        "status": True,
        "email": "",
        "includeSystemAlarmsInEmails": False,
        "changePasswordOnNextLogin": False,
        "external": False,
        "readOnly": False,
        "inactiveAccountNeverDisabled": False,
        "rbacGroups": groups,
    }
    base.update(flags)
    return {"statusCode": 200, "message": f"User: {name} retrived successfully", "adminUserDetails": base}


DETAILS = {
    "admin": detail("admin", ["Super Admin"]),
    "noc-breakglass": detail("noc-breakglass", ["Super Admin"], inactiveAccountNeverDisabled=True),
    "helpdesk-old": detail("helpdesk-old", ["Helpdesk Admin"], status=False),
    "api-trustsec": detail("api-trustsec", ["ERS Trustsec"], changePasswordOnNextLogin=True),
}
GROUPS = [
    {
        "name": "Helpdesk Admin",
        "description": "Access permission for Operations tab.",
        "externalGroupCount": 0,
    },
    {"name": "Policy Admin", "description": "Operations and Policy tabs.", "externalGroupCount": 2},
    {
        "name": "Super Admin",
        "description": "Operations, Policy and Administration tabs.",
        "externalGroupCount": 0,
    },
]
GROUP_DETAIL = {
    "Helpdesk Admin": {
        "name": "Helpdesk Admin",
        "description": "Access permission for Operations tab.",
        "isExternal": False,
        "externalIdenSourceName": None,
        "externalGroups": None,
        "rbacUsers": [
            {"name": "helpdesk-old", "firstName": "", "lastName": "", "isEnabled": False, "email": ""}
        ],
    },
    "Policy Admin": {
        "name": "Policy Admin",
        "description": "Operations and Policy tabs.",
        "isExternal": True,
        "externalIdenSourceName": "corp-ad",
        "externalGroups": ["example.com/Groups/ISE-Policy-Admins", "example.com/Groups/NetOps"],
        "rbacUsers": [],
    },
    "Super Admin": {
        "name": "Super Admin",
        "description": "Operations, Policy and Administration tabs.",
        "isExternal": False,
        "externalIdenSourceName": None,
        "externalGroups": None,
        "rbacUsers": [
            {"name": "admin", "isEnabled": True},
            {"name": "noc-breakglass", "isEnabled": True},
        ],
    },
    "ERS Trustsec": {
        "name": "ERS Trustsec",
        "description": "Full access permission to Trustsec ERS APIs.",
        "isExternal": False,
        "externalIdenSourceName": None,
        "externalGroups": None,
        "rbacUsers": [{"name": "api-trustsec", "isEnabled": True}],
    },
}
POLICIES = {
    "code": 200,
    "message": "Rbac policy retrieved successfully.",
    "RbacPolicyList": [
        {
            "policyName": "Helpdesk Admin Policy",
            "enabled": True,
            "adminGroups": ["Helpdesk Admin"],
            "Permission": {"menuAccessName": "Helpdesk Admin Menu Access", "dataAccessName": None},
        },
        {
            "policyName": "Policy Admin Policy",
            "enabled": True,
            "adminGroups": ["Policy Admin"],
            "Permission": {
                "menuAccessName": "Policy Admin Menu Access",
                "dataAccessName": "Policy Admin Data Access",
            },
        },
        {
            "policyName": "Policy Admin Extra",
            "enabled": False,
            "adminGroups": ["Policy Admin"],
            "Permission": {"menuAccessName": "Super Admin Menu Access", "dataAccessName": None},
        },
        {
            "policyName": "ERS Trustsec Policy",
            "enabled": True,
            "adminGroups": ["ERS Trustsec"],
            "Permission": {"menuAccessName": None, "dataAccessName": "Super Admin Data Access"},
        },
        {
            "policyName": "Super Admin Policy",
            "enabled": True,
            "adminGroups": ["Super Admin"],
            "Permission": {
                "menuAccessName": "Super Admin Menu Access",
                "dataAccessName": "Super Admin Data Access",
            },
        },
    ],
}


def leaf(name: str, perm: str) -> dict[str, Any]:
    return {"name": name, "id": name.lower(), "permission": perm, "childPermissions": []}


MENU = {
    "code": 200,
    "message": "Policy Admin Menu Access- retrived successfully",
    "name": "Policy Admin Menu Access",
    "description": "Operations and Policy tabs.",
    "menuAccessPrivileges": [
        {
            "name": "Operations",
            "id": "monitor",
            "permission": "Show",
            "childPermissions": [leaf("Live Logs", "Show"), leaf("TCP Dump", "Hide")],
        },
        {
            "name": "Policy",
            "id": "policy",
            "permission": "Show",
            "childPermissions": [leaf("Policy Sets", "Show")],
        },
        {
            "name": "Administration",
            "id": "administration",
            "permission": "Hide",
            "childPermissions": [leaf("Admin Users", "Hide")],
        },
    ],
}
DATA = {
    "code": 200,
    "message": "Policy Admin Data Access - retrieved successfully",
    "name": "Policy Admin Data Access",
    "description": "",
    "dataAccessPrivileges": [
        {
            "name": "Admin Groups",
            "id": "a",
            "permission": "No Access",
            "childPermissions": [leaf("Super Admin", "No Access"), leaf("Policy Admin", "No Access")],
        },
        {
            "name": "User Identity Groups",
            "id": "b",
            "permission": "Full Access",
            "childPermissions": [leaf("Employee", "Full Access"), leaf("Contractor", "Read Only Access")],
        },
        {"name": "Network Device Groups", "id": "c", "permission": "No Access", "childPermissions": []},
    ],
}


def mock_users(mock: respx.MockRouter) -> None:
    mock.get(f"{R}/admin-user").respond(
        json={"statusCode": 200, "message": "success", "adminUserList": USERS}
    )
    for name, body in DETAILS.items():
        mock.get(f"{R}/admin-user/{name}").respond(json=body)


def mock_groups(mock: respx.MockRouter) -> None:
    mock.get(f"{R}/admin-group").respond(
        json={"statusCode": 200, "message": "Admin groups retrieved successfully.", "adminGroupList": GROUPS}
    )
    for name, body in GROUP_DETAIL.items():
        mock.get(f"{R}/admin-group/{name.replace(' ', '%20')}").respond(json=body)
    mock.get(f"{R}/policy").respond(json=POLICIES)


async def call(name: str, args: dict[str, Any] | None = None) -> Any:
    async with Client(make_server()) as c:
        res = await c.call_tool(name, args or {})
    return res.structured_content


# --- ise_list_admin_users ---------------------------------------------------------------------------


async def test_admin_users_with_flags_and_summary(mock: respx.MockRouter) -> None:
    mock_users(mock)
    out = await call("ise_list_admin_users", {"response_format": "json"})
    rows = {r["name"]: r for r in out["results"]}
    assert list(rows) == ["admin", "api-trustsec", "helpdesk-old", "noc-breakglass"]
    assert rows["noc-breakglass"]["never_disabled"] is True and rows["noc-breakglass"]["super_admin"] is True
    assert rows["noc-breakglass"]["full_name"] == "Break Glass"
    assert rows["helpdesk-old"]["enabled"] is False
    assert rows["api-trustsec"]["change_password_next_login"] is True
    assert all("password" not in r for r in out["results"])
    s = out["summary"]
    assert s["super_admins"] == 2 and s["super_admin_names"] == ["admin", "noc-breakglass"]
    assert s["disabled"] == ["helpdesk-old"] and s["never_disabled"] == ["noc-breakglass"]
    assert s["external"] == [] and s["change_password_pending"] == ["api-trustsec"]


async def test_admin_user_filters(mock: respx.MockRouter) -> None:
    mock_users(mock)
    out = await call("ise_list_admin_users", {"group": "super admin", "response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["admin", "noc-breakglass"]
    out = await call("ise_list_admin_users", {"inactive_only": True, "response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["helpdesk-old"]
    out = await call("ise_list_admin_users", {"external": True, "response_format": "json"})
    assert out["results"] == [] and out["summary"]["admins"] == 4  # summary covers every admin


async def test_admin_users_without_detail(mock: respx.MockRouter) -> None:
    mock.get(f"{R}/admin-user").respond(json={"adminUserList": USERS})
    one = mock.get(f"{R}/admin-user/admin").respond(json=DETAILS["admin"])
    out = await call("ise_list_admin_users", {"detail": False, "response_format": "json"})
    assert len(out["results"]) == 4 and not one.called
    with pytest.raises(ToolError, match="needs detail=true"):
        await call("ise_list_admin_users", {"detail": False, "external": True})


async def test_admin_users_denied_and_missing(mock: respx.MockRouter) -> None:
    mock.get(f"{R}/admin-user").respond(403, json={"message": "Forbidden"})
    with pytest.raises(ToolError, match="needs an admin group that can read Admin Access"):
        await call("ise_list_admin_users")
    mock.get(f"{R}/admin-user").respond(404, json={"message": "Not Found"})
    with pytest.raises(ToolError, match="doesn't serve the OpenAPI RBAC API"):
        await call("ise_list_admin_users")


async def test_one_admin_detail_failing_keeps_the_row(mock: respx.MockRouter) -> None:
    mock_users(mock)
    mock.get(f"{R}/admin-user/helpdesk-old").respond(404, json={"message": "Not Found"})
    out = await call("ise_list_admin_users", {"response_format": "json"})
    row = next(r for r in out["results"] if r["name"] == "helpdesk-old")
    assert row["enabled"] is False and "detail_error" in row and "note" in out["summary"]


# --- ise_list_admin_groups / ise_list_rbac_policies ---------------------------------------------------


async def test_admin_groups_with_external_mappings(mock: respx.MockRouter) -> None:
    mock_groups(mock)
    out = await call("ise_list_admin_groups", {"response_format": "json"})
    rows = {r["name"]: r for r in out["results"]}
    assert list(rows) == ["ERS Trustsec", "Helpdesk Admin", "Policy Admin", "Super Admin"]
    assert rows["ERS Trustsec"]["note"].startswith("Not returned by the admin-group list")
    assert rows["Policy Admin"]["external"] is True
    assert rows["Policy Admin"]["external_identity_source"] == "corp-ad"
    assert rows["Policy Admin"]["policies"] == ["Policy Admin Policy", "Policy Admin Extra"]
    assert rows["Helpdesk Admin"]["disabled_members"] == ["helpdesk-old"]
    assert rows["Super Admin"]["members"] == ["admin", "noc-breakglass"]
    assert out["external_mappings"] == {
        "Policy Admin": ["example.com/Groups/ISE-Policy-Admins", "example.com/Groups/NetOps"]
    }
    out = await call("ise_list_admin_groups", {"external_only": True, "response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["Policy Admin"]


async def test_admin_groups_no_external(mock: respx.MockRouter) -> None:
    mock_groups(mock)
    out = await call("ise_list_admin_groups", {"name": "help", "response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["Helpdesk Admin"]
    assert out["note"] == "No admin group is mapped to an external (AD/LDAP) group."


async def test_rbac_policies(mock: respx.MockRouter) -> None:
    mock.get(f"{R}/policy").respond(json=POLICIES)
    out = await call("ise_list_rbac_policies", {"response_format": "json"})
    first = out["results"][0]
    assert first == {
        "name": "Helpdesk Admin Policy",
        "enabled": True,
        "admin_groups": ["Helpdesk Admin"],
        "menu_access": "Helpdesk Admin Menu Access",
    }
    out = await call("ise_list_rbac_policies", {"group": "Policy Admin", "response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["Policy Admin Policy", "Policy Admin Extra"]
    mock.get(f"{R}/policy").respond(403, json={"message": "Forbidden"})
    with pytest.raises(ToolError, match="ISE refused the RBAC read"):
        await call("ise_list_rbac_policies")


# --- ise_get_admin_access -----------------------------------------------------------------------------


async def test_admin_access_for_group(mock: respx.MockRouter) -> None:
    mock_groups(mock)
    menu = mock.get(f"{R}/menu-access/Policy%20Admin%20Menu%20Access").respond(json=MENU)
    data = mock.get(f"{R}/data-access/Policy%20Admin%20Data%20Access").respond(json=DATA)
    other = mock.get(f"{R}/menu-access/Super%20Admin%20Menu%20Access").respond(json=MENU)
    out = await call("ise_get_admin_access", {"group": "policy admin"})
    assert menu.called and data.called and not other.called  # the disabled policy's set is not read
    g = out["groups"][0]
    assert g["external_groups"][0] == "example.com/Groups/ISE-Policy-Admins"
    (p,) = g["policies"]
    assert p["menu_access"] == {
        "name": "Policy Admin Menu Access",
        "tabs_shown": ["Operations", "Policy"],
        "tabs_hidden": ["Administration"],
        "pages_shown": 2,
        "pages_total": 4,
    }
    cats = {c["name"]: c for c in p["data_access"]["categories"]}
    assert cats["User Identity Groups"] == {
        "name": "User Identity Groups",
        "permission": "Full Access",
        "items": {"Full Access": 1, "Read Only Access": 1},
    }
    assert cats["Network Device Groups"] == {"name": "Network Device Groups", "permission": "No Access"}
    assert out["disabled_policies"] == ["Policy Admin Extra"]


async def test_admin_access_for_user(mock: respx.MockRouter) -> None:
    mock_groups(mock)
    mock.get(f"{R}/admin-user/api-trustsec").respond(json=DETAILS["api-trustsec"])
    mock.get(f"{R}/data-access/Super%20Admin%20Data%20Access").respond(
        json={**DATA, "name": "Super Admin Data Access"}
    )
    out = await call("ise_get_admin_access", {"user": "api-trustsec"})
    assert out["user"]["groups"] == ["ERS Trustsec"]
    (p,) = out["groups"][0]["policies"]
    assert p["name"] == "ERS Trustsec Policy" and p["menu_access"].startswith("none")
    assert p["data_access"]["name"] == "Super Admin Data Access"


async def test_admin_access_errors(mock: respx.MockRouter) -> None:
    mock_groups(mock)
    with pytest.raises(ToolError, match="exactly one"):
        await call("ise_get_admin_access", {})
    with pytest.raises(ToolError, match="No admin group named 'Policy'. Names containing it: Policy Admin"):
        await call("ise_get_admin_access", {"group": "Policy"})
    mock.get(f"{R}/admin-user/nobody").respond(404, json={"message": "Not Found"})
    with pytest.raises(ToolError, match="No admin user named 'nobody'"):
        await call("ise_get_admin_access", {"user": "nobody"})


async def test_super_admin_note(mock: respx.MockRouter) -> None:
    mock_groups(mock)
    mock.get(f"{R}/menu-access/Super%20Admin%20Menu%20Access").respond(json=MENU)
    mock.get(f"{R}/data-access/Super%20Admin%20Data%20Access").respond(json=DATA)
    out = await call("ise_get_admin_access", {"group": "Super Admin"})
    assert out["note"].startswith("Super Admin: full access")


# --- ise_deployment_health admins section --------------------------------------------------------------


async def test_health_section() -> None:
    from ise_mcp.client import IseApp
    from ise_mcp.tools.admin_audit import health_section
    from ise_mcp.tools.health import Findings
    from tests.unit.conftest import BASE, make_settings

    app = IseApp(make_settings())
    with respx.mock(base_url=BASE) as mock:
        mock_users(mock)
        f = Findings()
        s = await health_section(app, f)
    assert s["super_admins"] == 2
    lows = [x for x in f.items if x["severity"] == "low"]
    assert len(lows) == 1 and "noc-breakglass" in lows[0]["finding"]
    with respx.mock(base_url=BASE) as mock:
        mock.get(f"{R}/admin-user").respond(403, json={"message": "Forbidden"})
        f = Findings()
        assert await health_section(app, f) == {}
    assert f.items[0]["severity"] == "info" and "not reviewed" in f.items[0]["finding"]
    await app.aclose()


async def test_health_flags_many_super_admins() -> None:
    from ise_mcp.client import IseApp
    from ise_mcp.tools.admin_audit import health_section
    from ise_mcp.tools.health import Findings
    from tests.unit.conftest import BASE, make_settings

    many = [{"name": f"sa{i}", "statusEnabled": True, "rbacGroupNames": ["Super Admin"]} for i in range(5)]
    app = IseApp(make_settings())
    with respx.mock(base_url=BASE) as mock:
        mock.get(f"{R}/admin-user").respond(json={"adminUserList": many})
        for u in many:
            mock.get(f"{R}/admin-user/{u['name']}").respond(json=detail(u["name"], ["Super Admin"]))
        f = Findings()
        await health_section(app, f)
    assert any(x["severity"] == "low" and "5 enabled Super Admin" in x["finding"] for x in f.items)
    await app.aclose()

# Least-privilege accounts for `ise-mcp-server`

The server authenticates to ISE with one account (`ISE_USERNAME` / `ISE_PASSWORD`). Give it the
smallest set of built-in ISE RBAC **admin groups** that covers the tiers you enable. Never run a
hosted server as the appliance's `admin` (Super Admin).

ISE gates the three REST surfaces this server uses independently:

- **ERS** (`/ers/config`, NADs, internal users, groups, SGTs, SGACLs, authz profiles, dACLs, ANC):
  needs the **ERS Operator** group (read, GET only) or **ERS Admin** (read/write). Without one of these
  every ERS tool returns 401, whatever other groups the account holds.
- **OpenAPI** (`/api/v1`, policy sets, endpoints, TrustSec matrix, deployment, certs, licence): gated by
  the account's RBAC menu/data access. **Read Only Admin** covers all GETs; writes need the matching
  functional admin group (Policy Admin for policy, Network Device Admin for NADs, etc.).
- **MnT** (`/admin/API/mnt`, sessions, auth history, failure reasons, CoA): read works for any admin;
  **MnT Admin** is the functional group, and CoA (dangerous tier) in practice needs Super Admin.

MCP-side roles (`MCP_ROLES`, core `docs/PRODUCTION.md`) restrict *callers* of this server; this guide
restricts *the server's own* ISE account. Use both.

| Server tiers enabled | Account | ISE admin groups |
|---|---|---|
| read only (default) | `mcp-test-ro` | **ERS Operator**, **Read Only Admin** |
| read + write (`MCP_ENABLE_WRITES=true`) | `mcp-test-rw` | **ERS Admin**, **Policy Admin**, **Network Device Admin**, **Identity Admin**, **MnT Admin** |
| + dangerous (`MCP_ENABLE_DANGEROUS=true`) | `mcp-test-admin` | **Super Admin** |

**Guest accounts use a second, non-admin identity.** ERS `guestuser` answers only to a sponsor
(`ISE_SPONSOR_USERNAME` / `ISE_SPONSOR_PASSWORD`), not to any admin group: a user (internal or AD) in a
sponsor group with **Access Cisco ISE guest accounts using the programmatic interface**. Scope it like an
admin account: **own accounts** (or the group's) rather than all, only the guest types and locations it
needs, **View guests' passwords** off, and no self-registration approval unless used. Guest types,
sponsor groups and portals are read with the admin account (ERS Operator) and written with ERS Admin.
Setup: [deploying.md](deploying.md#guest-sponsor-guest-account-tools).

## 1. Read-only account: `mcp-test-ro` (ERS Operator + Read Only Admin)

**What it allows**

| Area | Permission | Needed by |
|---|---|---|
| External RESTful Services | GET only (ERS Operator) | `ise_list_nads`, `ise_get_nad`, `ise_list_internal_users`, `ise_list_identity_groups`, `ise_list_endpoint_groups`, `ise_list_sgts`, `ise_list_sgacls`, `ise_list_authz_profiles`, `ise_list_dacls`, `ise_list_anc_*` |
| All OpenAPI read menus/data (Read Only Admin) | Read | `ise_list_policy_sets`, `ise_get_policy_set`, `ise_list_endpoints`, `ise_list_certificates`, `ise_get_license_status`, `ise_deployment_health`, `ise_list_sxp_*`, `ise_get_egress_matrix` |
| Monitoring (MnT) | Read | `ise_list_active_sessions`, `ise_find_session`, `ise_get_auth_history`, `ise_why_auth_failed`, `ise_get_auth_list`, `ise_recent_auth_failures`, `ise_list_failure_reasons` |

**AD lookups need ERS Admin.** ERS implements the Active Directory queries (group search, a user's groups,
the join status) as PUT operations on the join point, even though they change nothing, so an ERS Operator
(GET-only) account can't run `ise_list_ad_groups` or `ise_test_ad_user`; `ise_get_ad_join_point` then shows
the join status as unknown, and so does the AD section of `ise_why_auth_failed`. Give the read account
ERS Admin as well if the AD tools matter more than a strict GET-only role. Joining and leaving the domain
(`ise_join_ad` / `ise_leave_ad`) is dangerous tier and takes a domain account passed per call.

**pxGrid.** `ise_list_pxgrid_clients`, `ise_get_pxgrid_client` and `ise_pxgrid_status` are ERS/OpenAPI GETs
(ERS Operator + Read Only Admin). Approving, declining or deleting clients and `ise_set_pxgrid_settings` are
ERS PUT/DELETE (ERS Admin, write tier). `ise_issue_pxgrid_client_cert` changes nothing on ISE (it reads the
trusted store), but it mints a client credential, so it is write tier too.

**What it deliberately does not allow** (these tools, all write/dangerous, are not in the read tier and
are hidden from an MCP `ro` caller anyway): any `ise_create_*` / `ise_set_*` / `ise_update_*` /
`ise_delete_*`, CoA (`ise_coa_*`), ANC apply/clear, node-service and certificate changes, `ise_api_call`.

## 2. Write account: `mcp-test-rw`

ERS Admin gives ERS read/write (NADs, users, groups, SGTs, authz profiles, dACLs, ANC policy objects).
Policy Admin covers policy-set and rule writes; Network Device Admin, Identity Admin and MnT Admin cover
the matching OpenAPI/ERS write areas. **Note:** ERS writes need the **ERS Admin** group specifically —
ERS Operator is read-only, and a functional group such as Policy Admin does not grant ERS write on its
own. The dangerous tier (CoA, ANC apply/clear, `ise_update_node_services`, certificate bind, NAD /
policy-set deletes) needs Super Admin, so a write-only deployment cannot perform those.

## 3. Dedicated users

| User | Groups | Auth | Notes |
|---|---|---|---|
| `mcp-test-ro` | ERS Operator, Read Only Admin | local password | hosted default (read-only) |
| `mcp-test-rw` | ERS Admin, Policy Admin, Network Device Admin, Identity Admin, MnT Admin | local password | when `MCP_ENABLE_WRITES=true` |
| `mcp-test-admin` | Super Admin | local password | only when `MCP_ENABLE_DANGEROUS=true` |

Store the passwords as Docker secrets (`ISE_PASSWORD_FILE`, core G4) on hosted servers, not in `.env`.

**Create them** with `POST /api/v1/rbac/admin-user` (one call per user, with the groups above) or in the
GUI, then set `ISE_RO_USERNAME` / `ISE_RO_PASSWORD` in `.env` for the read-only one. The suite's private lab
repo (stutters-mcp-lab) has an idempotent seed script that does the API calls. **Known ISE 3.5 build bug:**
`POST /api/v1/rbac/admin-user` can return a generic HTTP 500 ("Unexpected Error in admin user creation")
regardless of body; ERS `adminuser` is GET-only, so there is no API fallback. Use the GUI then:

```text
Administration > System > Admin Access > Administrators > Admin Users > Add:
  name mcp-test-ro, assign admin group(s): ERS Operator, Read Only Admin
```

(then set `ISE_RO_USERNAME` / `ISE_RO_PASSWORD` in `.env`).

## 4. Verify (tested on ISE 3.5.0.527 patch 3,4, 2026-10-15)

`ise_deployment_health` reports the server's own account and its admin groups under `server_privilege`,
and raises a **medium** finding when the account is a Super Admin but only read/write tiers are enabled
(verified live: the lab `admin` account is flagged, with the least-privilege groups to use instead).

Run the read-tier contract as the read-only account:

```bash
ISE_RO_USERNAME=mcp-test-ro ISE_RO_PASSWORD=... uv run pytest -m live tests/live/test_least_privilege.py -v
```

The helper (core `stutters_mcp_core.testing.least_privilege`) logs in as `mcp-test-ro` with MCP caller
role `ro`, calls every read tool, and fails on any appliance denial or on a write tool visible to `ro`.

**Status on this lab:** the three users could not be created via the API (the 3.5 500 above) and the ISE
GUI login requires entering the appliance password into a non-local host, which the overnight agent is
not permitted to do. The roles, the seed step and the live test are therefore complete and the
`server_privilege` check is verified live; running the suite *as* `mcp-test-ro` is pending the user
creating the three users in the GUI (one-time; see §3) on the rebuilt lab.

## 5. Lab rebuild

Creating the three users is a step of the suite's lab rebuild, in its private lab repo (stutters-mcp-lab).
On a fixed ISE build the seed script there creates them; otherwise it prints the GUI steps above.

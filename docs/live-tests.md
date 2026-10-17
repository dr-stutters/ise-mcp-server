# Live tests

`tests/live` runs the tools against a real ISE. Run them only against a lab ISE you can throw away: the
write and dangerous tests create, change and delete `mcp-test-*` objects, send CoA and apply ANC.

```bash
uv run pytest tests/live -m live            # everything; skips what is not configured
uv run pytest tests/live -m live -rs        # ... and list why each skipped test was skipped
```

Every test skips cleanly, with a message naming what is missing, when:

- `ISE_URL` / `ISE_USERNAME` / `ISE_PASSWORD` are not set, or ISE is unreachable;
- a lab-specific input below (an `ISE_LIVE_*` variable) is not set;
- the objects a test expects (the seed objects or the switch test policy below) are not on the ISE.

## Inputs (`ISE_LIVE_*`)

Set them in the environment or in `.env` (commented examples in `.env.example`). The example values
are placeholders; use your lab's.

| Variable | Used by | What | Example |
|---|---|---|---|
| `ISE_LIVE_SWITCH_MAC` | `test_live_phase2` (switch flow), `test_live_prompt`, `test_live_endpoint_bulk` (custom-attribute rule) | MAC of a real client authenticating (MAB) through a switch that is a NAD on this ISE, sending traffic | `52:54:00:12:34:56` |
| `ISE_LIVE_SWITCH_IP` | `test_live_phase2` | Optional: the switch's NAS IP; when set, the client's session must come from it | `192.0.2.10` |
| `ISE_LIVE_SWITCH_NAME` | `test_live_prompt` | Optional: the switch name passed to the prompts (default `access-switch`) | `access-sw1` |
| `ISE_LIVE_AD_JOIN_POINT` | `test_live_ad` | An AD join point that exists and is joined | `CORP` |
| `ISE_LIVE_AD_GROUP` | `test_live_ad` | A group already added to that join point, as ISE names it | `corp.example.com/Groups/employees` |
| `ISE_LIVE_AD_USER` | `test_live_ad` | An AD user who is a member of `ISE_LIVE_AD_GROUP` | `alice` |
| `ISE_LIVE_CA_NAME` | `test_live_certs` (EAP certificate), `test_live_pxgrid` | Name of the trusted CA that issued ISE's EAP and pxGrid certificates | `Example-Root-CA` |
| `ISE_LIVE_CA_PEM` | `test_live_pxgrid` | Path to that CA's root certificate (PEM) | `/path/to/example-root-ca.pem` |
| `ISE_LIVE_PXGRID_SIGNER` | `test_live_pxgrid` | Command that reads a CSR on stdin and prints the signed certificate (PEM) from that CA, with server + client auth EKUs | `/path/to/sign-csr --template pxgrid` |
| `ISE_LIVE_PXGRID_DOMAIN` | `test_live_pxgrid` | DNS domain for the test client certificate's CN (`mcp-test-pxgrid-<run>.<domain>`) | `example.com` |
| `ISE_LIVE_SXP_PEER` | `test_live_sxp` | An unused IP address to create (and delete) an SXP connection to; nothing is contacted | `192.0.2.99` |
| `ISE_LIVE_DADM_NAD` | `test_live_device_admin` | A NAD with a TACACS+ secret whose device sends VTY login, exec and level-15 command authorization to this ISE (`aaa authorization commands 15 ... group <tacacs> local`) | `access-sw1` |
| `ISE_LIVE_DADM_HOST` | `test_live_device_admin` | That device's SSH address, reachable from the test host (`ssh` and `sshpass` installed) | `192.0.2.10` |
| `ISE_LIVE_REPROFILE_MAC` | `test_live_profiler` (reprofile) | MAC of a real endpoint with a live session through a switch that answers CoA; it gets one CoA reauth. `test_live_profiler` otherwise creates and deletes only `mcp-prof-*` custom profiling rules | `52:54:00:12:34:56` |
| `ISE_LIVE_SCALE` | `test_live_scale` | `1` to run the scale test (creates and deletes many endpoints; a few minutes) | `1` |
| `ISE_RO_USERNAME` / `ISE_RO_PASSWORD` | `test_least_privilege` | The read-only admin account; see [least-privilege.md](least-privilege.md) | |

## Seed objects

Some read, activity and dangerous-tier tests are stronger with seeded data and skip without it. They
expect, on ISE:

- NAD `mcp-test-radius-client` covering the test host's source IP, identity group `mcp-test-group`
  with internal user `mcp-test-user`, endpoint group `mcp-test-endpoints` with endpoint
  `02:00:5E:00:00:01` (static assignment);
- recent RADIUS from the test host through that NAD: a PAP pass for `mcp-test-user` from
  `02:00:5E:00:00:01` with an Accounting-Start (an active session), a wrong password from
  `02:00:5E:00:00:02` (22040) and an unknown user from `02:00:5E:00:00:03` (22056).

Any RADIUS test client (for example `radtest` / `radclient`) can produce the traffic.

## Device admin test

`test_live_device_admin` needs the DeviceAdmin service on ISE and the `ISE_LIVE_DADM_*` device. It creates
its own `mcp-dadm-*` identity groups, internal users (random password), command sets, a priv-15 shell
profile and a device-admin policy set at rank 0 that matches only `mcp-dadm-*` users on that NAD (other
admins are unaffected), logs in over SSH as each user, runs level-15 commands, compares the device's
answer with `ise_admin_policy_explain` and `ise_test_command_set`, checks the rules' hit counts, and deletes
everything. A denied command prints nothing in an SSH exec session, so only commands that always print are
used; `reload cancel` stands in for `reload` and nothing disruptive runs unless it is predicted denied. It
also creates and deletes a TACACS+ external server (TEST-NET address, never contacted) and a sequence.

## Switch test policy

The switch flow tests (`ISE_LIVE_SWITCH_MAC`), `test_live_policy_explain` and the policy part of
`test_live_ad` expect a network-access policy set `mcp-test-wired` that matches the switch's NAD
(`mcp-test-sw1`, in NDG `Location#All Locations#mcp-test-lab`):

- authentication rules `mcp-test-mab` (Internal Endpoints, if user not found CONTINUE) and
  `mcp-test-dot1x` (Internal Users);
- authorization rules `mcp-test-anc-quarantine` (`Session:ANCPolicy equals mcp-test-quarantine` ->
  profile `mcp-test-quarantine`, SGT Quarantined_Systems), `mcp-test-mab-permit` (Wired_MAB -> profile
  `mcp-test-permit`, SGT Employees), `mcp-test-eaptls` (802.1X + EAP-TLS; any name
  starting with `mcp-test-eaptls` counts) and, for the AD check,
  `mcp-test-ad-employees`
  (`<join point>:ExternalGroups equals <ISE_LIVE_AD_GROUP>`);
- ANC policy `mcp-test-quarantine` (QUARANTINE).

Tests that need these skip when the policy set is missing.

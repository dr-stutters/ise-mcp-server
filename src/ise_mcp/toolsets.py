"""ISE_TOOLSETS (I44): load only some areas of the tool surface, on core's toolsets mechanism (C31).

With every tier on the server registers ~190 tools, and a client loads all their descriptions on every
turn; some clients cap the number of tools. `ISE_TOOLSETS=troubleshoot,policy` registers only those areas
plus the always-on tools (ALWAYS_ON and core's own: ise_status, ise_search_spec, ise_get_definition,
ise_api_call). The tier switches (MCP_ENABLE_WRITES, MCP_ENABLE_DANGEROUS) and MCP_ALLOW_TOOLS /
MCP_DENY_TOOLS still apply on top: `policy` without MCP_ENABLE_WRITES gives the policy reads only.

Syntax (core): comma-separated area names; unset, empty or `all` for every area; `-<area>` leaves one out
(`-guest`, `all,-guest,-pxgrid`). A tool in several areas is loaded when any of them is, and hidden when
one of them is excluded. A name no tool declares is logged at startup and listed by ise_status under
`server.toolsets.unknown`. Prompts are always registered; a step naming a tool that is not loaded says
so when the model tries it.

The tool modules don't name their toolset: `with_toolsets` wraps each module's `register(reg)` in
server.py so every `@reg.read/write/dangerous` gets `toolset=` from TOOLSETS. Every tool must be in
TOOLSETS or ALWAYS_ON; tests/unit/test_toolsets.py checks the table against the registered tools, so a new
tool has to be added here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from ise_mcp._core import Tier, ToolRegistrar
from ise_mcp._core.audit import ArgRedactor

# Registered in every selection: the change-check pair the suite prompts use, the generic task poller and
# the generic delete (it deletes objects of every area, so tying it to one would hide it oddly).
ALWAYS_ON: frozenset[str] = frozenset(
    {
        "ise_compare_snapshot",
        "ise_delete_object",
        "ise_get_task",
        "ise_snapshot",
    }
)

# area -> (one-line description, tools). Keep each list sorted. A tool may be in more than one area.
TOOLSETS: dict[str, tuple[str, tuple[str, ...]]] = {
    "troubleshoot": (
        "why can't X connect: auth history and failures, live sessions, accounting, RADIUS stats, CoA",
        (
            "ise_coa_bulk",
            "ise_coa_disconnect",
            "ise_coa_reauth",
            "ise_delete_session",
            "ise_deployment_health",
            "ise_endpoint_360",
            "ise_find_session",
            "ise_get_accounting",
            "ise_get_auth_history",
            "ise_get_auth_list",
            "ise_list_active_sessions",
            "ise_list_failure_reasons",
            "ise_nad_radius_stats",
            "ise_policy_explain",
            "ise_recent_auth_failures",
            "ise_why_auth_failed",
        ),
    ),
    "policy": (
        "policy sets, authentication and authorization rules, authorization profiles, dACLs, allowed "
        "protocols, conditions, where-used, policy audit and hit counts",
        (
            "ise_create_authn_rule",
            "ise_create_authz_profile",
            "ise_create_authz_rule",
            "ise_create_policy_set",
            "ise_delete_condition",
            "ise_delete_policy_rule",
            "ise_delete_policy_set",
            "ise_get_authz_profile",
            "ise_get_dacl",
            "ise_get_policy_set",
            "ise_list_allowed_protocols",
            "ise_list_authz_profiles",
            "ise_list_conditions",
            "ise_list_dacls",
            "ise_list_dictionary_attributes",
            "ise_list_policy_sets",
            "ise_policy_audit",
            "ise_policy_explain",
            "ise_reset_hitcounts",
            "ise_set_allowed_protocols",
            "ise_set_condition",
            "ise_set_dacl",
            "ise_unused_objects",
            "ise_update_authz_profile",
            "ise_update_policy_rule",
            "ise_update_policy_set",
            "ise_where_used",
        ),
    ),
    "network": (
        "network access devices (NADs), network device groups, external RADIUS servers and sequences",
        (
            "ise_audit_nads",
            "ise_create_nad",
            "ise_create_ndg",
            "ise_delete_nad",
            "ise_get_nad",
            "ise_list_nads",
            "ise_list_ndgs",
            "ise_set_external_radius_server",
            "ise_set_radius_server_sequence",
            "ise_update_nad",
        ),
    ),
    "identity": (
        "internal users, identity groups, identity sources and sequences, certificate authentication "
        "profiles, Active Directory join points and groups",
        (
            "ise_add_ad_groups",
            "ise_bulk_internal_users",
            "ise_create_ad_join_point",
            "ise_create_group",
            "ise_create_internal_user",
            "ise_get_ad_join_point",
            "ise_get_internal_user",
            "ise_join_ad",
            "ise_leave_ad",
            "ise_list_ad_groups",
            "ise_list_identity_groups",
            "ise_list_identity_sources",
            "ise_list_internal_users",
            "ise_set_cert_auth_profile",
            "ise_set_identity_sequence",
            "ise_test_ad_user",
            "ise_update_internal_user",
        ),
    ),
    "endpoints": (
        "endpoints and endpoint groups, bulk import, custom attributes, rejected endpoints, MAC "
        "randomization",
        (
            "ise_bulk_endpoints",
            "ise_create_group",
            "ise_endpoint_summary",
            "ise_get_mac_randomization",
            "ise_list_custom_attributes",
            "ise_list_endpoint_groups",
            "ise_list_endpoints",
            "ise_release_rejected_endpoint",
            "ise_set_custom_attribute",
            "ise_set_endpoint",
            "ise_set_mac_randomization",
        ),
    ),
    "anc": (
        "Adaptive Network Control: quarantine policies and the endpoints they are applied to",
        (
            "ise_apply_anc",
            "ise_clear_anc",
            "ise_create_anc_policy",
            "ise_list_anc_endpoints",
            "ise_list_anc_policies",
        ),
    ),
    "trustsec": (
        "SGTs, SGACLs, the egress matrix, TrustSec settings and device report, IP-SGT, SXP, SD-Access "
        "virtual networks",
        (
            "ise_delete_trustsec_object",
            "ise_deploy_ip_sgt",
            "ise_get_egress_matrix",
            "ise_get_trustsec_settings",
            "ise_list_ip_sgt_mappings",
            "ise_list_sgacls",
            "ise_list_sgt_vn_vlan",
            "ise_list_sgts",
            "ise_list_sxp_bindings",
            "ise_list_sxp_connections",
            "ise_list_virtual_networks",
            "ise_push_trustsec_matrix",
            "ise_set_default_egress_rule",
            "ise_set_egress_policy",
            "ise_set_ip_sgt",
            "ise_set_sgt",
            "ise_set_sxp_connection",
            "ise_set_trustsec_settings",
            "ise_trustsec_device_report",
        ),
    ),
    "guest": (
        "guest types, sponsor groups, portals and locations, and guest accounts (as the sponsor)",
        (
            "ise_approve_guest",
            "ise_create_guest_user",
            "ise_delete_guest_user",
            "ise_extend_guest_user",
            "ise_get_guest_locations",
            "ise_get_guest_user",
            "ise_list_guest_portals",
            "ise_list_guest_types",
            "ise_list_guest_users",
            "ise_list_sponsor_groups",
            "ise_notify_guest",
            "ise_reinstate_guest_user",
            "ise_reset_guest_password",
            "ise_set_guest_type",
            "ise_set_sponsor_group",
            "ise_suspend_guest_user",
            "ise_update_guest_user",
        ),
    ),
    "device_admin": (
        "TACACS+ device administration: command sets, shell profiles, TACACS servers and sequences",
        (
            "ise_admin_policy_explain",
            "ise_get_tacacs_servers",
            "ise_list_command_sets",
            "ise_list_shell_profiles",
            "ise_set_command_set",
            "ise_set_shell_profile",
            "ise_set_tacacs_server",
            "ise_set_tacacs_server_sequence",
            "ise_test_command_set",
        ),
    ),
    "profiler": (
        "profiling (profiles, custom rules, probes, re-profiling, SNMP scans) and posture policies",
        (
            "ise_delete_profiling_rule",
            "ise_explain_profile",
            "ise_list_posture_policies",
            "ise_list_posture_requirements",
            "ise_list_profiler_profiles",
            "ise_list_profiling_rules",
            "ise_profiler_status",
            "ise_reprofile_endpoint",
            "ise_run_snmp_scan",
            "ise_set_profiling_rule",
            "ise_set_snmp_scan",
            "ise_snmp_scan_history",
        ),
    ),
    "certs": (
        "system and trusted certificates, CSRs, certificate import and binding",
        (
            "ise_bind_certificate",
            "ise_delete_certificate",
            "ise_delete_csr",
            "ise_export_csr",
            "ise_generate_csr",
            "ise_import_system_certificate",
            "ise_import_trusted_cert",
            "ise_list_certificates",
            "ise_list_csrs",
            "ise_set_trusted_cert",
        ),
    ),
    "pxgrid": (
        "pxGrid persona, clients and certificates, and pxGrid Direct connectors",
        (
            "ise_approve_pxgrid_client",
            "ise_decline_pxgrid_client",
            "ise_delete_pxgrid_client",
            "ise_get_pxgrid_client",
            "ise_issue_pxgrid_client_cert",
            "ise_list_pxgrid_clients",
            "ise_pxgrid_direct_status",
            "ise_pxgrid_status",
            "ise_set_pxgrid_direct_connector",
            "ise_set_pxgrid_settings",
            "ise_test_pxgrid_direct",
        ),
    ),
    "admin": (
        "the deployment itself: nodes and services, health, licences, patches and upgrade pre-checks, "
        "admin users and RBAC",
        (
            "ise_deployment_health",
            "ise_get_admin_access",
            "ise_get_license_status",
            "ise_get_patch_readiness",
            "ise_list_admin_groups",
            "ise_list_admin_users",
            "ise_list_nodes",
            "ise_list_patches",
            "ise_list_rbac_policies",
            "ise_patch_readiness",
            "ise_update_node_services",
        ),
    ),
    "backup": (
        "repositories, backups, configuration export, diff and import",
        (
            "ise_create_backup",
            "ise_delete_repository",
            "ise_diff_config",
            "ise_export_config",
            "ise_get_backup_status",
            "ise_import_config",
            "ise_list_repositories",
            "ise_set_repository",
        ),
    ),
}


def _index(table: Mapping[str, tuple[str, tuple[str, ...]]]) -> dict[str, tuple[str, ...]]:
    out: dict[str, list[str]] = {}
    for area, (_, tools) in table.items():
        for tool in tools:
            out.setdefault(tool, []).append(area)
    return {tool: tuple(areas) for tool, areas in out.items()}


TOOLSET_OF: dict[str, tuple[str, ...]] = _index(TOOLSETS)


def toolsets_for(tool: str) -> tuple[str, ...] | None:
    """The areas `tool` belongs to; None for an always-on tool or one missing from the table."""
    return TOOLSET_OF.get(tool)


class _ToolsetRegistrar(ToolRegistrar):
    """The server's registrar (same state), with `toolset=` filled in from TOOLSETS by tool name."""

    def __init__(self, base: ToolRegistrar) -> None:  # noqa: D107 - shares the base registrar's state
        self.__dict__ = base.__dict__

    def _register(
        self,
        tier: Tier,
        *,
        title: str | None,
        name: str | None,
        destructive: bool | None,
        idempotent: bool | None,
        tags: set[str] | None,
        description: str | None = None,
        task: bool = False,
        redact: Mapping[str, ArgRedactor] | None = None,
        toolset: str | Iterable[str] | None = None,
    ) -> Callable[[Any], Any]:
        base = super()._register

        def deco(fn: Any) -> Any:
            tool = name or fn.__name__
            sets = toolset if toolset is not None else toolsets_for(tool)
            return base(
                tier,
                title=title,
                name=name,
                destructive=destructive,
                idempotent=idempotent,
                tags=tags,
                description=description,
                task=task,
                redact=redact,
                toolset=sets,
            )(fn)

        return deco


def with_toolsets(register: Callable[[ToolRegistrar], None]) -> Callable[[ToolRegistrar], None]:
    """Wrap a tool module's `register(reg)` so its tools carry their ISE_TOOLSETS areas."""

    def wrapped(reg: ToolRegistrar) -> None:
        register(_ToolsetRegistrar(reg))

    wrapped.__name__ = getattr(register, "__name__", "register")
    wrapped.__qualname__ = getattr(register, "__qualname__", "register")
    return wrapped

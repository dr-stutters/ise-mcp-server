"""Prompt ise_phased_8021x_rollout (I87): wired 802.1X by phases per location NDG.

Cisco's Secure Wired Access / IBNS 2.0 guidance rolls 802.1X out in three modes, one switch group at a time:
monitor (open access sessions, ISE permits everything and logs it), low-impact (a pre-auth port ACL, dACLs
from ISE for authorized endpoints) and closed (no traffic before authorization, the Default rule denies).
The prompt answers "what breaks if this NDG goes closed tonight?" from MnT before each step, then makes the
ISE side of the phase through the existing preview-first write tools. The switch-side CLI is printed (or
staged as a Catalyst Center template that is previewed, never deployed): this prompt never pushes it.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from typing import Annotated, Literal

from pydantic import Field

from ise_mcp._core import InvalidRequest, ToolRegistrar, tool_ref

# Prompt arguments are interpolated into instructions, so they are held to strict shapes.
SAFE_NDG = re.compile(r"^[\w .-]{1,64}(#[\w .-]{1,64}){0,5}$")
SAFE_POLICY_SET = re.compile(r"^[\w .()-]{1,64}$")
SAFE_SWITCH = re.compile(r"^[\w.:-]{1,128}(/[\w.:-]{1,128})?$")
SAFE_INTERFACES = re.compile(r"^[A-Za-z][\w./ ,-]{0,79}$")
SAFE_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
LOCATION_ROOT = "Location#All Locations"
PHASES = ("readiness", "monitor", "low-impact", "closed")
Phase = Literal["readiness", "monitor", "low-impact", "closed"]

READ_TOOLS = [
    "ise_list_ndgs",
    "ise_list_nads",
    "ise_list_policy_sets",
    "ise_get_policy_set",
    "ise_policy_explain",
    "ise_get_auth_list",
    "ise_recent_auth_failures",
    "ise_list_active_sessions",
    "ise_list_endpoints",
    "ise_endpoint_360",
    "ise_list_endpoint_groups",
    "ise_list_authz_profiles",
    "ise_get_authz_profile",
    "ise_list_dacls",
    "ise_get_dacl",
    "ise_snapshot",
    "ise_compare_snapshot",
]
# ISE writes a phase makes (write tier): referenced only when this server exposes them.
WRITE_TOOLS = (
    "ise_update_policy_rule",
    "ise_set_dacl",
    "ise_create_authz_profile",
    "ise_update_authz_profile",
    "ise_set_endpoint",
)
# Catalyst Center leg: reads, plus a template that is created, committed and previewed (never deployed).
CATC_TOOLS = [
    "catc_list_devices",
    "catc_run_show_commands",
    "catc_get_device_config",
    "catc_create_template",
    "catc_commit_template",
    "catc_preview_template",
]
CML_TOOLS = ["cml_run_commands"]

# Switch side (IOS XE, IBNS 2.0 new-style). Printed for the user; the prompt never applies it.
PREAUTH_ACL = "ACL-DEFAULT"
PREAUTH_ACL_LINES = [
    f"ip access-list extended {PREAUTH_ACL}",
    " remark Before authorization: DHCP, DNS, PXE/TFTP and ICMP only",
    " permit udp any eq bootpc any eq bootps",
    " permit udp any any eq domain",
    " permit udp any any eq tftp",
    " permit icmp any any",
    " deny ip any any",
]


def _ndg(value: str) -> str:
    """The location below 'Location#All Locations', e.g. 'SYD#Bldg-1'."""
    value = value.strip().strip("#")
    for root in (LOCATION_ROOT + "#", "All Locations#"):
        if value.lower().startswith(root.lower()):
            value = value[len(root) :]
    if not value or not SAFE_NDG.match(value):
        raise InvalidRequest(
            "ndg: a location group below 'Location#All Locations', e.g. 'SYD' or 'SYD#Bldg-1' (letters, "
            "digits, spaces and . - _, levels joined by '#')"
        )
    return value


def _prefix(value: str, ndg: str) -> str:
    value = value.strip() or re.sub(r"[^A-Za-z0-9_-]", "_", ndg.split("#")[-1])[:32].strip("_-")
    if not SAFE_PREFIX.match(value):
        raise InvalidRequest(
            "name_prefix: letters, digits, _ and - (at most 32), starting with a letter or digit"
        )
    return value


def _interface_lines(phase: str, interfaces: str) -> list[str]:
    """The access-port lines for one phase (IBNS 2.0)."""
    common = [
        f"interface range {interfaces}",
        " switchport mode access",
        " access-session host-mode multi-auth",
        " access-session port-control auto",
        " mab",
        " dot1x pae authenticator",
        " dot1x timeout tx-period 7",
        " service-policy type control subscriber PMAP_DOT1X_MAB",
    ]
    if phase == "monitor":
        return [*common, " no access-session closed   (open: traffic flows before and after a failure)"]
    if phase == "low-impact":
        return [
            *PREAUTH_ACL_LINES,
            *common,
            " no access-session closed",
            f" ip access-group {PREAUTH_ACL} in   (the dACL from ISE replaces it once authorized)",
        ]
    return [
        *common,
        " access-session closed   (nothing but EAPOL and the MAB learning frame before authorization)",
        f" no ip access-group {PREAUTH_ACL} in   (optional: keep it as a belt-and-braces fallback)",
    ]


def _global_lines(interfaces: str) -> list[str]:
    """Once per switch before the first phase: new-style AAA, IP device tracking, the control policy."""
    return [
        "authentication convert-to new-style   (once, if 'show run' still has legacy 'authentication' lines)",
        "dot1x system-auth-control   (802.1X does not run on any port without it)",
        "device-tracking policy IPDT_POLICY",
        " tracking enable",
        f"interface range {interfaces}",
        " device-tracking attach-policy IPDT_POLICY   (a dACL needs the endpoint's IP for 'any')",
        "class-map type control subscriber match-all DOT1X_FAILED",
        " match method dot1x",
        " match result-type method dot1x authoritative",
        "class-map type control subscriber match-all DOT1X_NO_RESP",
        " match method dot1x",
        " match result-type method dot1x agent-not-found",
        "class-map type control subscriber match-all MAB_FAILED",
        " match method mab",
        " match result-type method mab authoritative",
        "policy-map type control subscriber PMAP_DOT1X_MAB",
        " event session-started match-all",
        "  10 class always do-until-failure",
        "   10 authenticate using dot1x priority 10",
        " event authentication-failure match-first",
        "  5 class DOT1X_FAILED do-until-failure",
        "   10 terminate dot1x",
        "   20 authenticate using mab priority 20",
        "  10 class DOT1X_NO_RESP do-until-failure",
        "   10 terminate dot1x",
        "   20 authenticate using mab priority 20",
        "  20 class MAB_FAILED do-until-failure   (a rejected MAC waits 60 s, no MAB loop against ISE)",
        "   10 terminate mab",
        "   20 authentication-restart 60",
        " event agent-found match-all",
        "  10 class always do-until-failure",
        "   10 terminate mab",
        "   20 authenticate using dot1x priority 10",
    ]


def register(reg: ToolRegistrar) -> None:
    # Registered after the tool modules, so reg.tiers holds the tools this server exposes.
    writes_on = {t for t in WRITE_TOOLS if t in reg.tiers}

    def w(name: str) -> str:
        """A write tool's reference when it is enabled, else its name and the GUI fallback."""
        if name in writes_on:
            return tool_ref(name)
        return f"{name} (write tier, not enabled on this server: make the same change in the ISE GUI)"

    @reg.prompt(
        title="Phased wired 802.1X rollout (monitor, low-impact, closed) per NDG",
        uses=["ise", "catc", "cml"],
        example={"ndg": "SYD#Bldg-1", "phase": "readiness"},
        tools=[*READ_TOOLS, *(t for t in WRITE_TOOLS if t in writes_on), *CATC_TOOLS, *CML_TOOLS],
    )
    def ise_phased_8021x_rollout(
        ndg: Annotated[
            str,
            Field(
                description="Location group the switches are in, below 'Location#All Locations', e.g. "
                "'SYD#Bldg-1' (one phase per location at a time)"
            ),
        ],
        phase: Annotated[
            Phase,
            Field(
                description="readiness (the gate only, nothing changes), monitor (open, permit and log), "
                "low-impact (pre-auth port ACL + dACLs) or closed (Default rule denies)"
            ),
        ] = "readiness",
        policy_set: Annotated[
            str,
            Field(
                description="The network-access policy set the location's switches hit; empty: find it "
                "with ise_policy_explain"
            ),
        ] = "",
        days: Annotated[
            int, Field(ge=1, le=7, description="Readiness window in days (MnT keeps up to 7)")
        ] = 7,
        switch: Annotated[
            str,
            Field(
                description="Optional: one switch to check and stage the CLI for: 'lab/node' for a CML node, "
                "or its Catalyst Center name or IP; empty: every Catalyst Center switch in the NDG"
            ),
        ] = "",
        interfaces: Annotated[
            str,
            Field(description="Access ports the phase covers, e.g. 'GigabitEthernet1/0/1 - 24'"),
        ] = "GigabitEthernet1/0/1 - 24",
        name_prefix: Annotated[
            str,
            Field(
                description="Prefix for the dACLs and authorization profiles this rollout creates; empty: "
                "from the NDG's last level"
            ),
        ] = "",
    ) -> str:
        """Roll wired 802.1X out by Cisco's phases for one location NDG: a readiness gate from MnT (who
        fails, who only gets in by the open policy's Default rule, MAB endpoints with no profile or static
        group) and each switch's current mode from Catalyst Center, then per phase an ise_snapshot, the ISE
        side (monitor permits and logs, low-impact adds dACLs, closed makes the Default rule DenyAccess)
        through the preview-first write tools, the switch CLI printed or staged as a previewed template
        (never pushed), ise_compare_snapshot and the rollback."""
        loc = _ndg(ndg)
        if phase not in PHASES:  # FastMCP validates the Literal; this guards direct calls
            raise InvalidRequest(f"phase must be one of {', '.join(PHASES)}")
        policy_set = policy_set.strip()
        if policy_set and not SAFE_POLICY_SET.match(policy_set):
            raise InvalidRequest("policy_set: a policy set name (letters, digits, spaces and . ( ) - _)")
        switch = switch.strip()
        if switch and not SAFE_SWITCH.match(switch):
            raise InvalidRequest("switch must be a device name/IP or 'lab/node' (letters, digits, . : - _)")
        interfaces = interfaces.strip()
        if not SAFE_INTERFACES.match(interfaces):
            raise InvalidRequest("interfaces: an interface range like 'GigabitEthernet1/0/1 - 24'")
        prefix = _prefix(name_prefix, loc)

        group = f"{LOCATION_ROOT}#{loc}"
        minutes = days * 24 * 60
        permit_dacl = f"{prefix}-PERMIT-ALL"
        limited_dacl = f"{prefix}-LIMITED"
        permit_profile = f"{prefix}-LowImpact-Permit"
        limited_profile = f"{prefix}-LowImpact-Limited"
        ps_text = f'"{policy_set}"' if policy_set else "<the policy set from step 2>"

        if switch and "/" in switch:
            lab, node = switch.split("/", 1)
            show_cli = f'{tool_ref("cml_run_commands")} with lab="{lab}", nodes=["{node}"]'
            mode_source = f'{show_cli}, commands=["show running-config | section interface|access-session"]'
            stage = (
                f"   The switch is the CML node {node} in lab {lab}: give the user the lines above. They\n"
                "   apply them themselves (cml_configure_node on the cml server, its own preview, or the\n"
                "   console); this prompt does not call it."
            )
        else:
            target = f'["{switch}"]' if switch else "[the NDG's switches from step 1]"
            show_cli = f"{tool_ref('catc_run_show_commands')} with devices={target}"
            # `match` is a prefix of top-level section headers (not a regex): the port lines sit under
            # 'interface ...', the global lines are read with a show command.
            mode_source = (
                f'{tool_ref("catc_get_device_config")} with device=<each switch>, match="interface" (the\n'
                "     ports' access-session, ip access-group, dot1x and mab lines), plus "
                f'{show_cli}, commands=["show running-config | include ^dot1x system-auth-control|'
                '^policy-map type control"]'
            )
            stage = f"""   Stage them as a Catalyst Center template (the catc server; each a preview the user
   approves): {tool_ref("catc_create_template")} with project=<a template project the user names>,
   name="{prefix}-dot1x-{phase}", software_type="IOS-XE", content=<the lines above>,
   then {tool_ref("catc_commit_template")} and {tool_ref("catc_preview_template")} with device=<one
   switch>: the rendered CLI. Stop there: deploying
   it (catc_deploy_template) is the user's own, separate change window, not part of this prompt."""

        catc_leg = f"""   Switch side (optional; needs the catc or cml server, else ask the user for
   'show access-session'):
   - {tool_ref("catc_list_devices")} with ip=<each NAD IP> (or hostname=<NAD name>): the NDG's access
     switches as Catalyst Center knows them; a NAD Catalyst Center doesn't have is checked by hand.
   - {show_cli}, commands=["show access-session", "show authentication sessions",
     "show interfaces status"]: ports with a session (method, status) and connected ports with none.
   - Current mode per switch from {mode_source}:
     'access-session closed' = closed; 'ip access-group ... in' on open ports = low-impact; open ports
     without it ('authentication open' on legacy config) = monitor; no 'access-session port-control
     auto' / 'authentication port-control auto' = 802.1X not on yet."""

        if phase == "readiness":
            fix_text = f"""   Each fallback / no-profile row gets a fix, named in the report and not made in
   this run: a static identity group (ise_set_endpoint with mac, a group from
   {tool_ref("ise_list_endpoint_groups")}, static_group=true), a profiling fix
   ({tool_ref("ise_endpoint_360")} shows why it is Unknown), or a specific authorization rule."""
        else:
            fix_text = f"""   Each fallback / no-profile row gets a fix before closed mode: a static identity
   group with {w("ise_set_endpoint")} (mac, a group from {tool_ref("ise_list_endpoint_groups")},
   static_group=true; a preview each, the user approves), a profiling fix
   ({tool_ref("ise_endpoint_360")} shows why it is Unknown), or a specific authorization rule."""

        explain = (
            f'{tool_ref("ise_get_policy_set")} with policy_set="{policy_set}"'
            if policy_set
            else f'{tool_ref("ise_policy_explain")} with nad=<first NAD>, flow="wired-dot1x" and again\n'
            '   with flow="wired-mab"'
        )
        readiness = f"""1. NADs in the location. {tool_ref("ise_list_ndgs")} with name="{loc}": the group
   "{group}" must exist (no: stop, the switches need it first; prompt ise_onboard_nad).
   {tool_ref("ise_list_nads")} with group="{loc}", detail=true: name, IPs, groups per NAD. No NAD: stop.

2. The policy set. {explain}: which set the location's logins land in, its authentication
   rules (Dot1X, MAB and their if_user_not_found), its authorization rules in order with profiles,
   and the Default rule's profile.
   {tool_ref("ise_get_policy_set")} with the set name either way, and record every rule's current
   profiles and state: that is the rollback. A set shared with other locations: say so, since a change
   to its Default rule reaches them too; a rule scoped to this location (condition 'DEVICE:Location
   equals {group[len("Location#") :]}' or starts with) is the safer place for the phase change.

3. Readiness from MnT, per NAD of step 1 (window {days} day(s), since_minutes={minutes}):
   - {tool_ref("ise_get_auth_list")} with nad=<NAD>, since_minutes={minutes}, detail=true: passes with
     method (dot1x or mab), authorization rule and profile per MAC. MnT leaves out repeated successful
     logins, so add {tool_ref("ise_list_active_sessions")} with nad=<NAD> for what is on now.
   - {tool_ref("ise_recent_auth_failures")} with nad=<NAD>, since_minutes={minutes}: failures with the
     reason per MAC.
   - {tool_ref("ise_list_endpoints")} with static_only=true: endpoints pinned to an identity group.
   Sort every MAC seen into one row:
     ready      802.1X pass on a specific rule, or MAB pass on a rule that matches its identity group
                or profile
     fallback   passed only on the Default rule (or the monitor permit): closed mode rejects it
     no-profile MAB with endpoint profile Unknown and no static group ({tool_ref("ise_endpoint_360")}
                with mac=<MAC> when the row doesn't say): closed mode rejects it
     failing    failures and no pass in the window: already broken, and stays out after closed
{fix_text}
{catc_leg}"""

        gate = {
            "readiness": "",
            "monitor": "Gate for monitor: none (monitor mode blocks nothing); steps 1-3 are the baseline.",
            "low-impact": (
                "Gate for low-impact: every NAD of step 1 has passes in step 3 (monitor mode reached ISE)\n"
                "and the switches are in monitor mode (step 3, switch side). Otherwise stop and say what is\n"
                "missing."
            ),
            "closed": (
                "Gate for closed: no fallback and no no-profile rows left (failing rows are listed, not\n"
                "counted), and the switches are in low-impact (or monitor) mode. Any row left: stop, list\n"
                "the rows and their fixes, and change nothing. The user may waive named rows (record it)."
            ),
        }[phase]

        snapshot_before = (
            f'4. Before the change. {tool_ref("ise_snapshot")} with site="{loc}": keep the whole blob (the\n'
            "   compare in step 8 needs it). Record step 2's rules as the rollback."
        )

        if phase == "monitor":
            ise_change = f"""5. ISE side, monitor (each a preview; the user approves):
   - Authentication: the MAB rule of {ps_text} with if_user_not_found="CONTINUE" (unknown MACs reach
     authorization instead of a reject): {w("ise_update_policy_rule")} with policy_set={ps_text},
     rule=<the MAB rule>, section="authentication", if_user_not_found="CONTINUE". Skip if it already is.
   - Authorization: the Default rule permits and ISE logs every login: {w("ise_update_policy_rule")}
     with policy_set={ps_text}, rule="Default", profiles=["PermitAccess"]. Specific rules stay as they
     are. Every login is now in the live log (step 3's reads) while nobody is blocked."""
        elif phase == "low-impact":
            ise_change = f"""5. ISE side, low-impact (each a preview; the user approves).
   {tool_ref("ise_list_dacls")} and {tool_ref("ise_list_authz_profiles")} first: reuse what exists
   ({tool_ref("ise_get_dacl")}, {tool_ref("ise_get_authz_profile")}).
   a. dACLs. {w("ise_set_dacl")} with name="{permit_dacl}", aces=["permit ip any any"]
      (authorized endpoints: replaces the port ACL); and with name="{limited_dacl}",
      aces=["permit udp any eq bootpc any eq bootps", "permit udp any any eq domain",
      "permit icmp any any", "deny ip any any"] (the Default rule: DHCP, DNS, ICMP only).
   b. Profiles. A specific rule that returns a profile of yours: {w("ise_update_authz_profile")} with
      profile=<it>, dacl="{permit_dacl}". A rule that returns PermitAccess (a system profile, not
      editable): {w("ise_create_authz_profile")} with name="{permit_profile}", access="accept",
      dacl="{permit_dacl}", then {w("ise_update_policy_rule")} with policy_set={ps_text}, rule=<it>,
      profiles=["{permit_profile}"]. Rules returning a VLAN or SGT keep them; add the dACL only.
   c. Default rule. {w("ise_create_authz_profile")} with name="{limited_profile}", access="accept",
      dacl="{limited_dacl}"; then {w("ise_update_policy_rule")} with policy_set={ps_text},
      rule="Default", profiles=["{limited_profile}"]. Unknown endpoints keep DHCP and DNS only, and stay
      in the live log."""
        elif phase == "closed":
            ise_change = f"""5. ISE side, closed (a preview; the user approves):
   {w("ise_update_policy_rule")} with policy_set={ps_text}, rule="Default", profiles=["DenyAccess"].
   Specific rules stay as they are. Keep the MAB rule's if_user_not_found="CONTINUE": unknown MACs
   then hit Default and get Access-Reject, while a guest or onboarding rule above it still works."""
        else:
            ise_change = ""

        if phase == "readiness":
            body = f"""{readiness}

4. Report. One row per MAC: MAC | NAD | port | method | rule | profile | identity group (static?) |
   class (ready, fallback, no-profile, failing) | fix. Then a row per switch: current mode | ports
   with no session. Then the verdict for each next phase: monitor (always possible), low-impact
   (monitor has run: every NAD has passes), closed (no fallback and no no-profile rows). Nothing in
   this run changes anything; to move on, run this prompt again with phase="monitor", "low-impact" or
   "closed"."""
        else:
            lines = [
                *(_global_lines(interfaces) if phase == "monitor" else []),
                *_interface_lines(phase, interfaces),
            ]
            cli = "\n".join(f"     {line}" for line in lines)
            undo_switch = {
                "monitor": "'no access-session port-control auto', 'no mab', 'no dot1x pae authenticator'\n"
                "     on the ports (back to no 802.1X)",
                "low-impact": f"'no ip access-group {PREAUTH_ACL} in' on the ports (back to monitor)",
                "closed": f"'no access-session closed' (and 'ip access-group {PREAUTH_ACL} in' again if it\n"
                "     was removed): back to low-impact",
            }[phase]
            verify = {
                "monitor": "every login passes; step 3's fallback rows are the list closed mode would break",
                "low-impact": f"authorized sessions carry {permit_dacl} (or their own dACL), unknown ones\n"
                f"   {limited_dacl}; 'show access-session interface <port> details' names the dACL",
                "closed": "the ready endpoints still pass; unknown MACs fail on the Default DenyAccess",
            }[phase]
            body = f"""{readiness}

{gate}

{snapshot_before}

{ise_change}

6. Switch side, {phase} (printed; this prompt never pushes switch config). IOS XE, IBNS 2.0:
{cli}
   The ports are the user's to choose (uplinks, AP and trunk ports stay out). Compare with step 3's
   current mode and leave out lines already there. The notes in parentheses are not CLI: drop them.
{stage}

7. Verify after the user has applied the switch side. Step 3's reads again with since_minutes=30:
   {verify}. {tool_ref("ise_list_active_sessions")} with nad=<each NAD> and the switch's
   "show access-session" from step 3.

8. Compare. {tool_ref("ise_compare_snapshot")} with before=<the step 4 blob>: NADs whose failure % or
   timeouts rose, device types that went away. A regression the phase did not intend: roll back.

9. Report and rollback. One table: change (ISE rule/profile/dACL, switch lines) | preview approved |
   applied | verified. Then the rollback, in order: the switch first ({undo_switch}), then ISE:
   {w("ise_update_policy_rule")} with the profiles and state recorded in step 2 for each rule changed
   (previews again). dACLs and profiles this run created stay until no rule uses them; list them."""

        writes_rule = (
            "Rules for every write below: call the tool WITHOUT confirm, show the preview, wait for the\n"
            "user's approval; never pass confirm yourself. One phase per run, one location at a time."
            if writes_on
            else "Write tools are not enabled on this server: the ISE changes below are GUI steps (Policy >\n"
            "Policy Sets, Policy > Results) with the exact values; the reads still run."
        )
        if phase == "readiness":
            writes_rule = "Readiness only: no tool in this run changes anything."
        return f"""Phased wired 802.1X rollout for the location "{group}", phase: {phase}.
Cisco's Secure Wired Access (IBNS 2.0) order: monitor (open, ISE permits and logs), then low-impact
(pre-auth port ACL, dACLs from ISE), then closed (nothing before authorization, Default denies), one
location at a time, each with a readiness gate from the live log.
{writes_rule} The switch-side CLI is printed or staged as a previewed Catalyst Center template: this
prompt never deploys switch config. The catc_* and cml_* tools need those servers; without them, ask
the user for the switch output and give the CLI to paste.

{body}"""

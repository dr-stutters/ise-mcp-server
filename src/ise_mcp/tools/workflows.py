"""Workflow prompts started from this server (BUILDING-A-SERVER §5a)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from typing import Annotated

from pydantic import Field

from ise_mcp._core import InvalidRequest, ToolRegistrar, tool_ref
from ise_mcp.tools._common import DEFAULT_LOOKBACK_MINUTES, normalize_mac, parse_ip

# Prompt arguments are interpolated into instructions, so they are held to strict shapes.
SAFE_USER = re.compile(r"^[\w.@\\+-]{1,128}$")
SAFE_SWITCH = re.compile(r"^[\w.:-]{1,128}(/[\w.:-]{1,128})?$")


def _validated(mac: str, username: str, ip: str, switch: str) -> tuple[str, str, str, str]:
    mac = normalize_mac(mac) if mac.strip() else ""
    username = username.strip()
    if username and not SAFE_USER.match(username):
        raise InvalidRequest("username may only contain letters, digits and . @ \\ + - _")
    ip = ip.strip()
    if ip:
        parsed = parse_ip(ip)
        if parsed is None:
            raise InvalidRequest(f"{ip!r} is not an IP address")
        ip = parsed
    switch = switch.strip()
    if switch and not SAFE_SWITCH.match(switch):
        raise InvalidRequest("switch must be a device name/IP or 'lab/node' (letters, digits, . : - _)")
    return mac, username, ip, switch


def _who(mac: str, username: str, ip: str) -> str:
    if mac:
        return f"MAC {mac}"
    if username:
        return f'user "{username}"'
    return f"IP {ip}"


FIX_TOOLS = (
    "ise_create_nad",
    "ise_update_nad",
    "ise_update_policy_rule",
    "ise_update_internal_user",
    "ise_set_endpoint",
    "ise_clear_anc",
)


def fix_instructions(enabled: set[str]) -> str:
    """Step 8's fix text: preview-only write calls when write tools are on, GUI steps otherwise."""
    tools = [tool_ref(t) for t in FIX_TOOLS if t in enabled]
    if not tools:
        return (
            "   Write tools are not enabled on this server: describe the fix for the ISE GUI (menu path\n"
            "   and exact values) and how to verify it."
        )
    return (
        "   If a change would fix it, call the matching write tool WITHOUT confirm so it only returns a\n"
        f"   preview ({', '.join(tools)}).\n"
        "   Show the preview and wait for the user's approval; never pass confirm yourself.\n"
        "   A new NAD needs the RADIUS secret the switch uses (ask the user; secrets are masked\n"
        "   everywhere) and the device groups the policy set conditions match on."
    )


def register(reg: ToolRegistrar) -> None:
    # Registered after every tool module, so reg.tiers holds the tools this server exposes.
    fix_text = fix_instructions(set(reg.tiers))
    register_quarantine(reg)
    register_incident_timeline(reg)

    @reg.prompt(
        title="Troubleshoot endpoint network access",
        uses=["ise", "cml", "catc"],
        example={"mac": "AA:BB:CC:DD:EE:FF"},
        tools=[
            "ise_find_session",
            "ise_recent_auth_failures",
            "ise_why_auth_failed",
            "ise_endpoint_360",
            "ise_get_auth_history",
            "ise_get_policy_set",
            "ise_get_nad",
            "ise_list_anc_endpoints",
        ],
    )
    def ise_troubleshoot_endpoint_access(
        mac: Annotated[str, Field(description="Endpoint MAC address, any notation (best)")] = "",
        username: Annotated[str, Field(description="Username, if the MAC is not known")] = "",
        ip: Annotated[str, Field(description="Endpoint IP address, if neither MAC nor user is known")] = "",
        switch: Annotated[
            str,
            Field(
                description="Where to run switch CLI: a Catalyst Center device name/IP, or 'lab/node' "
                "for a CML node (e.g. mcp-cml-ise/sw1). Empty: use the NAD ISE reports"
            ),
        ] = "",
        minutes: Annotated[
            int,
            Field(ge=1, le=10080, description="How far back to look at authentication history, in minutes"),
        ] = DEFAULT_LOOKBACK_MINUTES,
    ) -> str:
        """Why can't this endpoint get on the network? A guided pass across ISE and the access switch:
        find the endpoint (MAC, user or IP), read its live session and auth history, decode the failure,
        check the matched policy rule, the network device (NAD) and any ANC quarantine, then look at the
        switch port through cml or catc when connected. Ends with a diagnosis and, if a change is needed,
        a fix shown as a preview only (nothing is applied without approval)."""
        mac, username, ip, switch = _validated(mac, username, ip, switch)
        if not (mac or username or ip):
            raise InvalidRequest("Give the endpoint's mac, username or ip")
        who = _who(mac, username, ip)
        mac_arg = f'mac="{mac}"' if mac else "mac=<the MAC from step 1>"
        if switch and "/" in switch:
            lab, node = switch.split("/", 1)
            cli_target = f'{tool_ref("cml_run_commands")} with lab="{lab}", nodes=["{node}"]'
        elif switch:
            cli_target = f'{tool_ref("catc_run_show_commands")} with devices=["{switch}"]'
        else:
            cli_target = (
                f"{tool_ref('catc_run_show_commands')} (catc server) with devices=[<the NAD's IP>], or "
                f"{tool_ref('cml_run_commands')} (cml server) with lab=..., nodes=[...] if the switch is a "
                f"CML node "
                f"(find it with {tool_ref('cml_list_labs')})"
            )
        return f"""Troubleshoot network access for {who}, looking back {minutes} minutes.
Work through the steps in order, keep a short evidence list (tool -> finding), and change nothing
before step 8.

1. Identify the endpoint.
   - MAC known: use it.
   - Otherwise call {tool_ref("ise_find_session")} with {"username" if username else "ip"}="{username or ip}"
     and take calling_station_id as the MAC. With no live session, call
     {tool_ref("ise_recent_auth_failures")} (user="{username}" if a user was given, since_minutes={minutes})
     to find MACs that failed for it. If there is still no MAC, ask for it (from the switch
     'show access-session' or the device itself) and stop.

2. Diagnose the authentication: call {tool_ref("ise_why_auth_failed")} with {mac_arg}, minutes={minutes}.
   Note the verdict, failure code, decoded steps, the NAD check and the internal-user check.
   For the full attempt list use {tool_ref("ise_get_auth_history")} ({mac_arg}).

3. Endpoint context: call {tool_ref("ise_endpoint_360")} with {mac_arg}: endpoint group and profile,
   live session (NAD, port, authorization profile, SGT, matched policy), ANC policy, rejected flag.

4. Policy: if a policy set / rule is known (session matched_policy), call {tool_ref("ise_get_policy_set")}
   for it and read the authentication and authorization rules in rank order: which rule matched, is a
   more specific rule disabled or ranked lower, which profile and SGT it gives. 15039 means a rule (or
   the default) returned DenyAccess.

5. Network device: call {tool_ref("ise_get_nad")} with device=<the NAS IP from step 2/3>. No NAD -> ISE
   drops the RADIUS silently (no MnT record; the switch logs 'RADIUS server not responding' /
   'AAA Server Down').
   Check the RADIUS secret is set, the device groups match the policy set conditions, and the CoA port.

6. Quarantine: if step 3 shows an ANC policy, confirm with {tool_ref("ise_list_anc_endpoints")}; the
   endpoint is contained on purpose until it is cleared.

7. Switch side (skip if neither the cml nor the catc server is connected): run on the access switch,
   using {cli_target}:
   - show access-session mac <MAC in xxxx.xxxx.xxxx form> details   (method, status, dACL, SGT)
   - show authentication sessions interface <port> details   (if the session is missing)
   - show aaa servers   (is the ISE server UP/DEAD, request/timeout counters)
   - show logging | include RADIUS|AAA|<MAC>   ('not responding' / 'AAA Server Down' = silent drop)
   - show running-config | section radius   (server address, source interface, CoA client)
   - show cts role-based sgt-map all   (when an SGT should be applied)
   Compare with ISE: same server IP, a session ISE knows about, the dACL/VLAN/SGT ISE sent.

8. Diagnosis and fix. State the root cause in one or two sentences with the evidence. Typical causes:
   - no ISE record: NAD missing or wrong IP, RADIUS server/source interface on the switch, ACL/firewall,
     or an idle MAB client that has sent no traffic;
   - 11036: shared secret mismatch; 22056 on MAB: unknown endpoint and 'If user not found' = REJECT;
   - 22040/22063: wrong password or disabled user; 12xxx: supplicant/EAP or certificate problem;
   - 15039: a deny rule or the default rule matched (often a disabled or mis-ranked rule);
   - PASS but no access: dACL/VLAN/SGT on the switch differs from ISE, or ANC quarantine.
{fix_text}
   Finish with how to verify: re-run {tool_ref("ise_why_auth_failed")} after the client retries."""


SAFE_REASON = re.compile(r"^[\w .,:;#/@()+-]{1,120}$", re.ASCII)
SAFE_NAME = re.compile(r"^[\w.-]{1,64}$")


def quarantine_apply_text(enabled: set[str], policy: str, mac_arg: str) -> tuple[str, str]:
    """(apply step, undo step) for ise_quarantine_host: tool calls when the dangerous tier is on,
    GUI steps otherwise."""
    if "ise_apply_anc" not in enabled:
        return (
            "   The dangerous tools (ise_apply_anc / ise_clear_anc) are not enabled on this server. Tell\n"
            "   the user how to apply it in the GUI: Context Visibility > Endpoints > select the MAC >\n"
            f'   ANC > "{policy}", or enable MCP_ENABLE_DANGEROUS. Stop here unless they do it.',
            "   GUI: Context Visibility > Endpoints > select the MAC > ANC > Clear.",
        )
    return (
        f'   Call {tool_ref("ise_apply_anc")} with {mac_arg}, policy="{policy}" WITHOUT confirm. Show\n'
        "   the preview (policy actions, the live session it will CoA, rule warnings) and wait for the\n"
        "   user's approval; never pass confirm yourself. ISE sends the CoA itself.",
        f"   {tool_ref('ise_clear_anc')} with {mac_arg} (preview first; the user's approval is needed\n"
        "   before the confirmed call): ISE re-authorizes the session and the normal rule applies again.",
    )


def register_quarantine(reg: ToolRegistrar) -> None:
    enabled = set(reg.tiers)

    @reg.prompt(
        title="Quarantine a host",
        uses=["ise", "fmc", "cml", "catc"],
        example={"reason": "INC-1234 malware alert", "mac": "AA:BB:CC:DD:EE:FF"},
        tools=[
            "ise_find_session",
            "ise_endpoint_360",
            "ise_list_anc_policies",
            "ise_list_anc_endpoints",
            "ise_get_policy_set",
        ],
    )
    def ise_quarantine_host(
        reason: Annotated[
            str, Field(description="Why (ticket, alert); recorded in the steps and the FMC object")
        ],
        mac: Annotated[str, Field(description="Host MAC address, any notation (best)")] = "",
        ip: Annotated[str, Field(description="Host IP address, if the MAC is not known")] = "",
        username: Annotated[str, Field(description="Username, if neither MAC nor IP is known")] = "",
        anc_policy: Annotated[
            str, Field(description="ANC policy with the QUARANTINE action; empty: find one")
        ] = "",
        fmc_block: Annotated[
            bool, Field(description="Also block the host's IP on the firewalls with fmc_contain_host")
        ] = False,
        switch: Annotated[
            str,
            Field(
                description="Where to verify on the switch: a Catalyst Center device name/IP, or "
                "'lab/node' for a CML node (e.g. mcp-cml-ise/sw1). Empty: the NAD from the session"
            ),
        ] = "",
    ) -> str:
        """Contain a host in minutes, each step previewed and verified: find its session, check that an
        ANC quarantine policy and its authorization rule exist, apply ANC (ISE sends the CoA), verify
        the quarantine dACL/SGT on the switch, optionally block the IP on the FTDs through FMC, and
        finish with the exact undo steps. Nothing changes without the user's approval of a preview."""
        mac, username, ip, switch = _validated(mac, username, ip, switch)
        if not (mac or username or ip):
            raise InvalidRequest("Give the host's mac, ip or username")
        reason = reason.strip()
        if not SAFE_REASON.match(reason):
            raise InvalidRequest(
                "reason: up to 120 ASCII letters, digits, spaces and . , : ; # / @ ( ) + - _"
            )
        anc_policy = anc_policy.strip()
        if anc_policy and not SAFE_NAME.match(anc_policy):
            raise InvalidRequest("anc_policy may only contain letters, digits, . - _")
        who = _who(mac, username, ip)
        mac_arg = f'mac="{mac}"' if mac else "mac=<the MAC from step 1>"
        policy = anc_policy or "<the policy chosen in step 2>"
        if switch and "/" in switch:
            lab, node = switch.split("/", 1)
            cli = f'{tool_ref("cml_run_commands")} with lab="{lab}", nodes=["{node}"]'
        elif switch:
            cli = f'{tool_ref("catc_run_show_commands")} with devices=["{switch}"]'
        else:
            cli = (
                f"{tool_ref('catc_run_show_commands')} with devices=[<the NAD IP>], or "
                f"{tool_ref('cml_run_commands')} if the switch is a CML node"
            )
        apply_text, undo_text = quarantine_apply_text(enabled, policy, mac_arg)
        if {"ise_create_anc_policy", "ise_create_authz_rule"} <= enabled:
            setup_text = (
                f"Propose them as previews: {tool_ref('ise_create_anc_policy')} with\n"
                f'     actions=["QUARANTINE"]; {tool_ref("ise_create_authz_rule")} with that condition\n'
                "     at rank 0."
            )
        else:
            setup_text = (
                "Write tools are off: tell the user to create them in the GUI (Operations >\n"
                "     Adaptive Network Control > Policy List; Policy > Policy Sets > Authorization)."
            )
        fmc_text = (
            f"""6. Firewall containment (fmc server). Call {tool_ref("fmc_contain_host")} with
   ip=<the host IP>, reason="{reason}" WITHOUT confirm. It maps the IP into the quarantine
   dynamic object that BLOCK rules reference, within seconds and without a deployment. Show the
   preview (object, rules, devices; a first-time setup that needs a deploy is called out) and wait
   for approval. If the fmc
   server isn't connected, say so and skip this step.
   Verify: the applied result lists the IP in the object; traffic from the host through the FTD is
   dropped (e.g. {tool_ref("fmc_packet_tracer")} from the host IP, if available)."""
            if fmc_block
            else "6. Firewall containment: not requested (fmc_block=false). Mention that "
            f"{tool_ref('fmc_contain_host')} can add it."
        )
        fmc_undo = (
            f"\n   - Firewall: {tool_ref('fmc_release_host')} with ip=<the host IP> (preview first; the\n"
            "     user's approval is needed before the confirmed call)."
            if fmc_block
            else ""
        )
        return f"""Quarantine {who}. Reason: {reason}.
Keep an evidence list (tool -> finding). Every change is a preview first: show it, wait for the
user's approval, and never pass confirm yourself.

1. Find the host. Call {tool_ref("ise_find_session")} with {
            f'mac="{mac}"' if mac else (f'ip="{ip}"' if ip else f'username="{username}"')
        }.
   Note the MAC (calling_station_id), IP, NAD IP, port, authorization profile, SGT and policy set.
   No live session: ANC still marks the endpoint, but nothing changes on the network until it
   reconnects; tell the user and ask whether to continue.

2. Check the quarantine plumbing (read only).
   - {tool_ref("ise_list_anc_policies")}: {
            f'confirm "{anc_policy}" exists and has the QUARANTINE action.'
            if anc_policy
            else "pick the policy with the QUARANTINE action (ask if there are several)."
        }
   - {tool_ref("ise_get_policy_set")} for the session's policy set: an authorization rule on
     'Session:ANCPolicy equals {policy}' must exist, be enabled and rank ABOVE the rule that
     matches the host today, with a quarantine profile (restrictive dACL and/or SGT such as
     Quarantined_Systems).
   - Missing policy or rule: stop. {setup_text} Without the rule, ANC changes nothing on the network.
   - {tool_ref("ise_list_anc_endpoints")} with {mac_arg}: already quarantined? Then report it and stop.

3. Apply the quarantine.
{apply_text}

4. Verify in ISE: {tool_ref("ise_list_anc_endpoints")} shows the MAC with the policy; {
            tool_ref("ise_endpoint_360")
        } with
   {mac_arg} shows anc_policy and, after the CoA, a session with the quarantine profile/SGT (allow
   10-30 s for the re-authentication).

5. Verify on the switch, using {cli}:
   - show access-session mac <MAC in xxxx.xxxx.xxxx form> details   (ACS ACL = the quarantine dACL,
     SGT = the quarantine SGT, status Authorized)
   - show ip access-lists   (the downloaded quarantine dACL entries)
   If the old dACL/SGT is still there, the CoA didn't reach the switch: check 'show aaa servers' and
   the switch's 'aaa server radius dynamic-author' client for ISE.

{fmc_text}

7. Report and record the undo. Summarise: host, session, policy, rule hit, what the switch shows,
   firewall state, and the time. Then list the exact undo steps:
{undo_text}{fmc_undo}
   - Verify after undo: the session is re-authorized with the normal profile/SGT (step 4 and 5 checks).
     The CoA can end the session; an 802.1X client normally re-authenticates within a minute, but a
     held supplicant may need a restart (or a port bounce) before a new session shows up."""


def register_incident_timeline(reg: ToolRegistrar) -> None:
    @reg.prompt(
        title="Incident timeline across ISE, FMC and Catalyst Center",
        uses=["ise", "fmc", "catc"],
        example={"mac": "AA:BB:CC:DD:EE:FF"},
        tools=[
            "ise_find_session",
            "ise_endpoint_360",
            "ise_get_auth_history",
            "ise_recent_auth_failures",
            "ise_list_anc_endpoints",
            "fmc_list_audit_records",
            "fmc_list_deployments",
            "fmc_device_health",
            "catc_device_360",
            "catc_client_360",
            "catc_list_events",
            "catc_list_issues",
            "catc_list_audit_logs",
        ],
    )
    def ise_incident_timeline(
        mac: Annotated[str, Field(description="Host MAC address, any notation (best)")] = "",
        ip: Annotated[str, Field(description="Host IP address, if the MAC is not known")] = "",
        username: Annotated[str, Field(description="Username, if neither MAC nor IP is known")] = "",
        minutes: Annotated[
            int, Field(ge=1, le=10080, description="How far back to look, in minutes")
        ] = DEFAULT_LOOKBACK_MINUTES,
    ) -> str:
        """Build one time-ordered incident timeline for a host across ISE, FMC (Firepower) and Catalyst
        Center, each queried on demand and merged by timestamp. ISE gives authentications, failures,
        the live session and ANC (quarantine) state; FMC gives recent config/audit and deployment
        activity and device health; Catalyst Center gives the client/device 360, events, issues and
        audit log. Read-only. The FMC and Catalyst Center steps are skipped (noted) if those servers
        are not connected to this client."""
        mac, username, ip, _ = _validated(mac, username, ip, "")
        if not (mac or username or ip):
            raise InvalidRequest("Give the host's mac, ip or username")
        who = _who(mac, username, ip)
        by_mac = f'mac="{mac}"' if mac else "mac=<the MAC from step 1>"
        finder = f"{tool_ref('ise_find_session')} with " + (
            f'mac="{mac}"' if mac else f'username="{username}"' if username else f'ip="{ip}"'
        )
        return f"""Build an incident timeline for {who} over the last {minutes} minutes. Query each
source on demand, collect (time, source, event) rows, then present them merged in time order. Every
tool here is read-only; change nothing. Use UTC and note each source's own clock in the output.

Only this server's tools (ise_*) are certain to exist. The fmc_* tools need the fmc-mcp server and
the catc_* tools the catc-mcp server to be connected to this client: if a call isn't available, write
"FMC not connected / Catalyst Center not connected - skipped" for that section and carry on.

1. Identify the host (ISE).
   - MAC known: use it. Otherwise {finder}; take calling_station_id as the MAC and
     framed_ip_address as the IP. If there is no session, keep the identifier you were given.

2. ISE events.
   - {tool_ref("ise_get_auth_history")} with {by_mac} and minutes={minutes}: each authentication
     (PASS/FAIL, policy set, authz rule, SGT, NAD) is a timeline row at its acs_timestamp.
   - {tool_ref("ise_recent_auth_failures")} with since_minutes={minutes} (and nad=/user= if known): failures
     in the window with decoded reasons, for this host and the NAD it uses.
   - {tool_ref("ise_endpoint_360")} with {by_mac}: profile, identity group, current ANC policy.
   - {tool_ref("ise_list_anc_endpoints")}: is the host quarantined now (and since when, if shown)?

3. FMC (Firepower) activity - skip with a note if fmc is not connected.
   - {tool_ref("fmc_list_audit_records")}: config/audit entries in the window (filter by the user or
     the host IP {ip or "<the IP from step 1>"} where the tool allows); each is a timeline row.
   - {tool_ref("fmc_list_deployments")}: policy deployments in the window (a deploy can change what
     the host is allowed to do - line it up against the ISE/CatC events).
   - {tool_ref("fmc_device_health")}: note any device health change in the window.

4. Catalyst Center activity - skip with a note if catc is not connected.
   - {tool_ref("catc_client_360")} with the MAC (or {tool_ref("catc_device_360")} for the NAD): client
     onboarding/health events and the connected device/port.
   - {tool_ref("catc_list_issues")} and {tool_ref("catc_list_events")}: assurance issues and events
     for the host or its NAD in the window.
   - {tool_ref("catc_list_audit_logs")}: operator changes in Catalyst Center in the window.

5. Merge and report.
   - Order every collected row by time (oldest first). Show: time (UTC), source (ISE/FMC/CatC), event,
     and the key detail (result, rule, deploy name, issue, who did it).
   - Call out correlations: e.g. an FMC deploy or a CatC change just before ISE auth failures, or an
     ANC quarantine lining up with a CatC issue.
   - End with a short "what happened" summary and the gaps (sources not connected, windows with no
     data). Suggest next steps as read-only lookups; propose no change without the user asking."""

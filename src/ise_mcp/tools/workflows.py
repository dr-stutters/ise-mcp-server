"""Workflow prompts started from this server (BUILDING-A-SERVER §5a)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from pydantic import Field

from ise_mcp._core import InvalidRequest, Tier, ToolRegistrar, tool_ref
from ise_mcp.tools._common import DEFAULT_LOOKBACK_MINUTES, normalize_mac, parse_ip

# Prompt arguments are interpolated into instructions, so they are held to strict shapes.
SAFE_USER = re.compile(r"^[\w.@\\+-]{1,128}$")
SAFE_SWITCH = re.compile(r"^[\w.:-]{1,128}(/[\w.:-]{1,128})?$")
SAFE_SITE = re.compile(r"^[\w .#()-]{1,64}(/[\w .#()-]{1,64}){0,7}$")


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
    register_aaa_chain_check(reg)
    register_onboard_nad(reg)

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


SAFE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(Z|[+-]\d{2}:?\d{2})?$")
SAFE_DEVICE = re.compile(r"^[\w.:-]{1,128}$")
SAFE_LAB = re.compile(r"^[\w .()-]{1,64}$")
MAX_TIMELINE_MINUTES = 10080
# Security-log events for a member added to / removed from a security-enabled global group. The
# script is fixed: only the validated window times are put into it.
AD_GROUP_EVENTS = (4728, 4729)


def _utc(value: str, arg: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    if not SAFE_TIME.match(value):
        raise InvalidRequest(
            f"{arg} must be an ISO 8601 date and time, e.g. 2026-10-29T09:10Z or 2026-10-29 09:10+10:00 "
            "(UTC when no offset is given)"
        )
    try:
        parsed = datetime.fromisoformat(value.replace(" ", "T"))
    except ValueError as e:
        raise InvalidRequest(f"{arg}: {e}") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _window(window_start: str, window_end: str) -> tuple[datetime | None, datetime | None]:
    start = _utc(window_start, "window_start")
    end = _utc(window_end, "window_end")
    if end is not None and start is None:
        raise InvalidRequest("window_end needs a window_start")
    if start is not None and end is not None:
        if end <= start:
            raise InvalidRequest("window_end must be after window_start")
        if end - start > timedelta(minutes=MAX_TIMELINE_MINUTES):
            raise InvalidRequest("the window may be at most 7 days (10080 minutes)")
    return start, end


def _iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _optional(value: str, pattern: re.Pattern[str], arg: str, shape: str) -> str:
    value = value.strip()
    if value and not pattern.match(value):
        raise InvalidRequest(f"{arg} must be {shape}")
    return value


def ad_group_events_script(start: str, end: str) -> str:
    """The fixed Get-WinEvent query for AD group membership changes in [start, end] (ISO, UTC)."""
    ids = ",".join(str(i) for i in AD_GROUP_EVENTS)
    return (
        f"Get-WinEvent -FilterHashtable @{{LogName='Security'; Id={ids}; "
        f"StartTime=[datetime]::Parse('{start}'); EndTime=[datetime]::Parse('{end}')}} "
        "-ErrorAction SilentlyContinue | Select-Object "
        "@{n='Time';e={$_.TimeCreated.ToUniversalTime().ToString('o')}}, Id, "
        "@{n='Member';e={$_.Properties[0].Value}}, @{n='Group';e={$_.Properties[2].Value}}, "
        "@{n='By';e={$_.Properties[6].Value}}"
    )


def register_incident_timeline(reg: ToolRegistrar) -> None:
    @reg.prompt(
        title="Incident timeline across ISE, FMC, Catalyst Center and the lab",
        uses=["ise", "fmc", "catc", "cml", "netbox", "win"],
        example={"window_start": "2026-10-29T09:10Z", "window_end": "2026-10-29T09:20Z"},
        tools=[
            "ise_find_session",
            "ise_endpoint_360",
            "ise_get_auth_history",
            "ise_get_auth_list",
            "ise_recent_auth_failures",
            "ise_list_anc_endpoints",
            "ise_why_auth_failed",
            "fmc_list_audit_records",
            "fmc_list_deployments",
            "fmc_device_health",
            "fmc_recent_activity",
            "fmc_run_show_command",
            "catc_device_360",
            "catc_client_360",
            "catc_list_events",
            "catc_list_issues",
            "catc_list_audit_logs",
            "catc_recent_activity",
            "catc_run_show_commands",
            "cml_run_commands",
            "cml_list_labs",
            "cml_list_lab_events",
            "netbox_change_history",
            "win_run_powershell_json",
        ],
    )
    def ise_incident_timeline(
        mac: Annotated[
            str, Field(description="Host MAC address, any notation (best). Empty: window-only")
        ] = "",
        ip: Annotated[str, Field(description="Host IP address, if the MAC is not known")] = "",
        username: Annotated[str, Field(description="Username, if neither MAC nor IP is known")] = "",
        minutes: Annotated[
            int,
            Field(
                ge=1,
                le=MAX_TIMELINE_MINUTES,
                description="How far back to look, in minutes (ignored when window_start is given)",
            ),
        ] = DEFAULT_LOOKBACK_MINUTES,
        window_start: Annotated[
            str,
            Field(
                description="Start of the window, ISO 8601 date and time (UTC if no offset), "
                "e.g. 2026-10-29T09:10Z"
            ),
        ] = "",
        window_end: Annotated[
            str, Field(description="End of the window, ISO 8601 (UTC if no offset); default now")
        ] = "",
        nad: Annotated[str, Field(description="Window-only: narrow ISE to this NAD (name or IP)")] = "",
        switch: Annotated[
            str,
            Field(
                description="Window-only: where to read 'show logging' on the switch: a Catalyst Center "
                "device name/IP, or 'lab/node' for a CML node"
            ),
        ] = "",
        firewall: Annotated[
            str, Field(description="Window-only: the FTD (FMC device name) to read 'show logging' on")
        ] = "",
        lab: Annotated[
            str, Field(description="Window-only: the CML lab whose events to read (default: running labs)")
        ] = "",
    ) -> str:
        """Build one time-ordered incident timeline, merged by timestamp. With a host (MAC, IP or user):
        its ISE authentications, session and ANC state, FMC audit/deployments and Catalyst Center 360,
        events, issues and audit. Without one ('what happened between 09:10 and 09:20?'): every
        operator change and event in the window - FMC activity and the FTD's show logging, Catalyst
        Center activity and the switch's logging, ISE authentications and failures by NAD and user,
        CML lab events, and NetBox changes and AD group changes when those servers are connected.
        Read-only; sources whose server is not connected are skipped with a note."""
        mac, username, ip, switch = _validated(mac, username, ip, switch)
        nad = _optional(nad, SAFE_SWITCH, "nad", "a NAD name or IP (letters, digits, . : - _)")
        firewall = _optional(
            firewall, SAFE_DEVICE, "firewall", "an FMC device name (letters, digits, . : - _)"
        )
        lab = _optional(lab, SAFE_LAB, "lab", "a CML lab title (letters, digits, space . ( ) - _)")
        start, end = _window(window_start, window_end)
        if mac or username or ip:
            return _host_timeline(mac, username, ip, minutes, start, end)
        return _window_timeline(minutes, start, end, nad=nad, switch=switch, firewall=firewall, lab=lab)


def _host_timeline(
    mac: str, username: str, ip: str, minutes: int, start: datetime | None, end: datetime | None
) -> str:
    who = _who(mac, username, ip)
    by_mac = f'mac="{mac}"' if mac else "mac=<the MAC from step 1>"
    finder = f"{tool_ref('ise_find_session')} with " + (
        f'mac="{mac}"' if mac else f'username="{username}"' if username else f'ip="{ip}"'
    )
    if start is None:
        span, lookback, clip = f"over the last {minutes} minutes", str(minutes), ""
    else:
        span = f"from {_iso(start)} to {_iso(end) if end else 'now'}"
        lookback = f"<minutes from {_iso(start)} until now, rounded up>"
        clip = " Drop rows outside the window (the look-backs below reach until now)."
    return f"""Build an incident timeline for {who} {span}. Query each
source on demand, collect (time, source, event) rows, then present them merged in time order. Every
tool here is read-only; change nothing. Use UTC and note each source's own clock in the output.{clip}

Only this server's tools (ise_*) are certain to exist. The fmc_* tools need the fmc-mcp server and
the catc_* tools the catc-mcp server to be connected to this client: if a call isn't available, write
"FMC not connected / Catalyst Center not connected - skipped" for that section and carry on.

1. Identify the host (ISE).
   - MAC known: use it. Otherwise {finder}; take calling_station_id as the MAC and
     framed_ip_address as the IP. If there is no session, keep the identifier you were given.

2. ISE events.
   - {tool_ref("ise_get_auth_history")} with {by_mac} and minutes={lookback}: each authentication
     (PASS/FAIL, policy set, authz rule, SGT, NAD) is a timeline row at its acs_timestamp.
   - {tool_ref("ise_recent_auth_failures")} with since_minutes={lookback} (and nad=/user= if known): failures
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


def _window_timeline(
    minutes: int,
    start: datetime | None,
    end: datetime | None,
    *,
    nad: str,
    switch: str,
    firewall: str,
    lab: str,
) -> str:
    if start is None:
        span = f"the last {minutes} minutes"
        lookback, hours = str(minutes), f"{minutes / 60:g}"
        start_s, end_s = f"<now minus {minutes} minutes, UTC>", "<now, UTC>"
        auth_list = f"since_minutes={minutes}"
        nb_window = f'since="{minutes}m"'
    else:
        start_s = _iso(start)
        end_s = _iso(end) if end else "<now, UTC>"
        span = f"{start_s} to {_iso(end) if end else 'now'}"
        lookback = f"<minutes from {start_s} until now, rounded up>"
        hours = f"<hours from {start_s} until now, rounded up>"
        if end is not None:
            auth_list = f'since_minutes={int((end - start).total_seconds() + 59) // 60}, until="{_iso(end)}"'
            nb_window = f'since="{start_s}", until="{_iso(end)}"'
        else:
            auth_list = f"since_minutes={lookback}"
            nb_window = f'since="{start_s}"'
    nad_arg = f', nad="{nad}"' if nad else ""
    if firewall:
        ftd = f'{tool_ref("fmc_run_show_command")} with device="{firewall}", command="show logging"'
        fmc_dev = f', device="{firewall}"'
    else:
        ftd = (
            f'{tool_ref("fmc_run_show_command")} with command="show logging" on the FTD(s) the activity '
            "above names (devices=[...], at most a few)"
        )
        fmc_dev = ""
    if switch and "/" in switch:
        sw_lab, sw_node = switch.split("/", 1)
        sw_log = (
            f'{tool_ref("cml_run_commands")} with lab="{sw_lab}", nodes=["{sw_node}"], '
            'commands=["show logging"]'
        )
        catc_dev = ""
    elif switch:
        sw_log = f'{tool_ref("catc_run_show_commands")} with devices=["{switch}"], commands=["show logging"]'
        catc_dev = f', device="{switch}"'
    else:
        sw_log = (
            f'{tool_ref("catc_run_show_commands")} with commands=["show logging"] on the switch(es) the '
            f"activity or the ISE NADs point at (a CML node: {tool_ref('cml_run_commands')})"
        )
        catc_dev = ""
    labs = (
        f'lab="{lab}"'
        if lab
        else f"each running lab from {tool_ref('cml_list_labs')} (state STARTED; lab=... narrows this)"
    )
    win_end = end_s if end is not None else "<now, UTC>"
    script = ad_group_events_script(start_s, win_end) if start is not None and end is not None else None
    ps = (
        f"script exactly:\n     {script}"
        if script
        else "the script below with the window's start and end (ISO, UTC) in place of START and END, and\n"
        f"     nothing else changed:\n     {ad_group_events_script('START', 'END')}"
    )
    return f"""Build an incident timeline for the window {span} (UTC). No host is given: collect every
operator change and event in the window first, then point at the hosts or devices worth a closer look.
Query each source on demand, collect (time, source, event, who) rows, then present them merged in time
order. Every tool here is read-only; change nothing. Use UTC and note each source's own clock offset.
Several tools only take a look-back that ends now: use the look-back given and drop rows outside the
window yourself.

Only this server's tools (ise_*) are certain to exist. The fmc_*, catc_*, cml_*, netbox_* and win_* tools
need those servers connected to this client: if a call isn't available, write "<source> not connected -
skipped" for that section and carry on.

1. ISE (authentications in the window, by NAD and user).
   - {tool_ref("ise_get_auth_list")} with {auth_list}{nad_arg}: every authentication in the window; group
     the rows by NAD and by user (count, PASS/FAIL) and keep the first and last time of each group.
   - {tool_ref("ise_recent_auth_failures")} with since_minutes={lookback}{nad_arg}: failures with decoded
     reasons; a burst of one reason on one NAD is a timeline row of its own.
   - ISE's configuration change audit is not available over REST: say so in the report (ISE GUI:
     Operations > Reports > Audit > Change Configuration Audit, or ISE syslog in a SIEM). Don't search
     for it.

2. FMC (Firepower) - skip with a note if fmc is not connected.
   - {tool_ref("fmc_recent_activity")} with since_minutes={lookback}{fmc_dev}: audit (who changed what),
     deployments and health alerts, one row each.
   - {ftd}: interface, failover, VPN and routing messages in the window (the FTD's clock may differ
     from FMC's).

3. Catalyst Center and the switch - skip with a note if catc is not connected.
   - {tool_ref("catc_recent_activity")} with hours={hours}{catc_dev}: issues, syslog, notifications and audit
     (template pushes, provisioning, who did it).
   - {sw_log}: link up/down, AAA/RADIUS server dead/alive and authentication messages in the window.

4. CML (the lab itself) - skip with a note if cml is not connected.
   - {tool_ref("cml_list_lab_events")} for {labs}: link and node state changes
     (link down, node stopped). The tool has no time filter: keep only events in the window.

5. NetBox (source of truth) - optional: skipped if not connected.
   - {tool_ref("netbox_change_history")} with {nb_window}: who created, changed or deleted which object.

6. Windows / Active Directory - optional: skipped if not connected (the tool is a raw-PowerShell tool
   that may need its server's higher tier; run only this fixed, read-only query).
   - {tool_ref("win_run_powershell_json")} with the {ps}
     Event 4728 = member added to a security group, 4729 = member removed: a row per event (who, group,
     by whom). Group changes decide ISE authorization results for AD users.

7. Merge and report.
   - Order every row by time (oldest first). Show: time (UTC), source (ISE/FMC/FTD/CatC/switch/CML/
     NetBox/AD), event, key detail and who did it.
   - Operator changes first: an FMC deploy, a CatC template push, a lab link down, an AD group change or
     a NetBox edit just before an auth failure burst or an interface/AAA message is the likely cause.
   - End with a short "what happened" summary, the gaps (sources not connected, ISE's config audit, empty
     windows) and the hosts or NADs worth a closer look: rerun this prompt with mac=/ip=/username= for a
     host, or {tool_ref("ise_why_auth_failed")} for one failure. Propose no change without the user asking."""


CHAIN_FIX_TOOLS = ("ise_create_nad", "ise_update_nad", "ise_approve_pxgrid_client")


def register_aaa_chain_check(reg: ToolRegistrar) -> None:
    # The ISE fixes it may preview: only the write tools this server exposes.
    ise_fixes = [tool_ref(t) for t in CHAIN_FIX_TOOLS if t in reg.tiers]
    ise_fix_text = (
        f"ISE fixes: {', '.join(ise_fixes)} (for a pending pxGrid consumer and for missing_nad / "
        "wrong_ndg / ip_mismatch; the RADIUS secret comes from the user, secrets are masked everywhere)"
        if ise_fixes
        else "ISE write tools are not enabled on this server: give the ISE GUI steps (menu path and exact "
        "values) for NAD and pxGrid fixes"
    )

    @reg.prompt(
        title="Check the AAA chain: switch, ISE, AD, Catalyst Center, FMC",
        uses=["ise", "catc", "fmc", "cml", "win"],
        example={"nad": "198.18.128.154", "site": "Global/mcp-test-lab/mcp-test-nac"},
        tools=[
            "ise_get_nad",
            "ise_audit_nads",
            "ise_list_nodes",
            "ise_get_auth_list",
            "ise_recent_auth_failures",
            "ise_why_auth_failed",
            "ise_list_identity_sources",
            "ise_get_ad_join_point",
            "ise_pxgrid_status",
            "ise_list_pxgrid_clients",
            "catc_get_policy_servers",
            "catc_network_services_health",
            "catc_list_devices",
            "catc_run_show_commands",
            "fmc_get_realm",
            "fmc_test_realm",
            "fmc_get_identity_sources",
            "cml_run_commands",
        ],
    )
    def ise_aaa_chain_check(
        nad: Annotated[
            str, Field(description="The switch or WLC users authenticate through: NAD name or IP")
        ] = "",
        site: Annotated[
            str,
            Field(
                description="Catalyst Center site path (e.g. 'Global/SYD/Bldg-1'): checks every device there"
            ),
        ] = "",
        switch: Annotated[
            str,
            Field(
                description="Where to run the switch's show commands: 'lab/node' for a CML lab node, or "
                "its Catalyst Center name or IP (default: the NAD's IP through Catalyst Center)"
            ),
        ] = "",
        user: Annotated[str, Field(description="Optional: a username to test against AD")] = "",
        minutes: Annotated[
            int, Field(ge=5, le=10080, description="Window for ISE and Catalyst Center counters, in minutes")
        ] = 60,
    ) -> str:
        """'802.1X is down' / 'users can't log in' across the whole chain: the switch's AAA config and
        RADIUS counters, the ISE NAD (coverage, secret, silent drops), ISE's identity sources (AD join
        and a user test), the Catalyst Center to ISE integration (policy server state and next action,
        Catalyst Center's AAA health numbers), pxGrid consumers, and FMC's realm and identity source
        with name resolution. Ends with one table: link, evidence, verdict and the fix, shown as a
        preview only. Read-only; the catc, fmc, cml and Windows_Server steps are skipped (noted) when
        those servers aren't connected."""
        nad = nad.strip()
        site = site.strip()
        if not (nad or site):
            raise InvalidRequest("Give the NAD (name or IP) or a Catalyst Center site")
        if nad and not SAFE_SWITCH.match(nad):
            raise InvalidRequest("nad must be a device name or IP (letters, digits, . : - _)")
        if site and not SAFE_SITE.match(site):
            raise InvalidRequest("site must be a site path like 'Global/Area/Building'")
        _, user, _, switch = _validated("", user, "", switch)
        nad_ip = parse_ip(nad) if nad else None
        hours = max(1, round(minutes / 60))
        scope = " and ".join(x for x in (f"NAD {nad}" if nad else "", f"site {site}" if site else "") if x)
        if switch and "/" in switch:
            lab, node = switch.split("/", 1)
            cli = f'{tool_ref("cml_run_commands")} with lab="{lab}", nodes=["{node}"]'
        else:
            target = switch or nad_ip or nad or "<each switch from step 2>"
            cli = f'{tool_ref("catc_run_show_commands")} with devices=["{target}"]'
        inventory = (
            f'{tool_ref("catc_list_devices")} with site="{site}" gives the devices '
            "(hostname, managementIpAddress)"
            if site
            else f"the NAD's IP{f' ({nad_ip})' if nad_ip else ''} is the one device"
        )
        expected = (
            "the catc_list_devices rows as they are, check_stale=false (one site is a partial inventory)"
            if site
            else f'[{{"name": "{nad}", "ip": "{nad_ip or "<its IP>"}", '
            '"aaa_server": "<the RADIUS server from step 1>"}]'
        )
        ad_user = (
            f'{tool_ref("ise_test_ad_user")} with the join point and username="{user}": the groups ISE sees.'
            if user
            else "(no user given: skip the AD user test)"
        )
        return f"""Check the authentication chain for {scope} (window {minutes} minutes). Read only: no tool
here changes anything. Each link gets a verdict (green / amber / red / not checked) with its evidence;
fixes are shown at the end as previews only and applied only if the user approves them.

Only the ise_* tools are certain to exist. catc_* needs the catc-mcp server, fmc_* the fmc-mcp server,
cml_* the cml-mcp server and win_* the Windows_Server server: if one is not connected, mark its links
"not checked (server not connected)" and carry on.

1. Switch: AAA config and RADIUS counters. {cli} and commands
   "show aaa servers", "show running-config | section radius server|aaa group server radius",
   "show access-session" (and "show dot1x statistics" if there are 802.1X ports). Green: every RADIUS
   server is UP with timeouts not rising; red: a server DEAD or timeouts rising. Note each server's
   IP and compare it with {tool_ref("ise_list_nodes")} (ipAddress/fqdn of the PSNs). Requests rising
   with no timeouts means ISE answered them, even when ISE keeps no record (step 2). A real auth probe
   is outside this check: it needs a client or 'test aaa' with a test account.

2. ISE: the NAD and what ISE recorded. {inventory}; then
   {tool_ref("ise_audit_nads")} with expected={expected}. Devices are matched by IP: a NAD under another
   name is fine (Catalyst Center reuses an existing NAD). Red on missing_nad (silent drops, 11007),
   wrong_ndg (policy conditions may miss it), ip_mismatch, aaa_elsewhere; amber on a short or reused
   secret. Then {tool_ref("ise_get_nad")} for the device (secret set, groups, CoA port),
   {tool_ref("ise_get_auth_list")} with nad= and since_minutes={minutes} (passes prove the secret works) and
   {tool_ref("ise_recent_auth_failures")} with nad= and since_minutes={minutes} (decoded reasons).
   Silent failures leave NO MnT record: a wrong shared secret (11036), an unknown NAD (11007) and a
   client that abandons EAP mid-way all look like "nothing happened" in ISE. Tell them apart with
   step 1's counters (timeouts rising = dropped; requests rising without timeouts = ISE answered,
   client side); for one endpoint, {tool_ref("ise_why_auth_failed")} with its MAC orders these causes.

3. ISE identity sources. {tool_ref("ise_list_identity_sources")}; for each Active Directory join point
   {tool_ref("ise_get_ad_join_point")} (joined on every PSN? domain reachable?). {ad_user} Red when a PSN
   is not joined or the domain is unreachable.

4. Catalyst Center to ISE (skip if catc is not connected). {tool_ref("catc_get_policy_servers")}: for
   each ISE server its state, trust and `next_action`. Green only with next_action "none" (COMPLETE,
   TRUSTED); "update_entry" (with the field Catalyst Center names, e.g. fqdn), "accept_certificate",
   "approve_pxgrid_on_ise" and "wait" are red/amber and name their own fix. Then
   {tool_ref("catc_network_services_health")} with service="aaa"{f', site="{site}"' if site else ""} and
   hours={hours}: quote its verdict line ("ISE ... answered N% of M AAA requests, average latency ...").
   Catalyst Center counts only Access-Rejects as failures, so silent drops and abandoned EAP sessions
   don't lower that percentage; Catalyst Center's own admin logins over RADIUS don't appear in MnT
   sessions (the policy set's hit counters are their evidence).

5. pxGrid. {tool_ref("ise_pxgrid_status")} (persona, certificate chain and hostname as consumers see
   them) and {tool_ref("ise_list_pxgrid_clients")}: Catalyst Center's and FMC's consumers should be
   enabled; a pending client is amber (approve it), none for an integration that needs one is red.

6. FMC identity (skip if fmc is not connected). {tool_ref("fmc_get_identity_sources")} (ISE/pxGrid
   identity source and its status), {tool_ref("fmc_get_realm")} and {tool_ref("fmc_test_realm")} for
   each realm (directory server reachable, LDAPS vs plain LDAP). A realm that can't resolve the DC's name
   is a DNS problem: check the records with `win_get_dns_records` (Windows_Server server) for the DC
   and the ISE FQDN.

7. Report one table, one row per link (switch, ISE NAD, ISE identity, Catalyst Center integration,
   Catalyst Center AAA health, pxGrid, FMC realm, FMC identity source, DNS): link | evidence (tool and
   the key value) | verdict | fix. Then the fixes, each as a preview call WITHOUT confirm:
   {tool_ref("catc_update_policy_server")} for next_action update_entry (dangerous tier: it re-runs the
   integration), {tool_ref("catc_accept_ise_certificate")} after comparing fingerprints with
   ise_pxgrid_status, the switch's `radius server` config for aaa_elsewhere; {ise_fix_text}.
   Show each preview and wait for the user's approval; never pass confirm yourself. End with the one
   link most likely to explain the outage, and what proves it fixed (step 1's counters, a pass in
   ise_get_auth_list)."""


SAFE_HOST = re.compile(r"^[\w.-]{1,64}$")
SAFE_GROUP_PATH = re.compile(r"^[\w .-]{1,64}(#[\w .-]{1,64}){0,5}$")
SAFE_INTERFACE = re.compile(r"^[A-Za-z][\w./-]{0,47}$")
SAFE_VRF = re.compile(r"^[\w.-]{1,32}$")
# Switch-side names the prompt configures and the undo removes again.
RADIUS_GROUP = "ISE-RADIUS"
TACACS_GROUP = "ISE-TACACS"
ADMIN_LIST = "ISE-ADMIN"


def _onboard_undo_text(enabled: set[str], name: str) -> str:
    """The ISE half of ise_onboard_nad's undo: ise_delete_nad with the dangerous tier, else the GUI."""
    if "ise_delete_nad" in enabled:
        nad = (
            f'{tool_ref("ise_delete_nad")} with device="{name}" (dangerous tier; preview first, the user\n'
            "     approves it)"
        )
    else:
        nad = (
            "the ISE GUI, Administration > Network Resources > Network Devices > select it > Delete\n"
            "     (ise_delete_nad needs MCP_ENABLE_DANGEROUS)"
        )
    return (
        f"   - ISE: {nad}; then the groups created in step 3, children first, with\n"
        f'     {tool_ref("ise_delete_object")} kind="ndg", target=<path> (only groups this run created and\n'
        "     no other NAD uses: the preview shows what still references them)."
    )


def _switch_aaa_lines(
    *, radius: bool, tacacs: bool, ise: str, source: str, vrf: str
) -> tuple[list[str], list[str]]:
    """(config lines, undo lines) for an IOS XE access switch, Cisco's campus NAC defaults."""
    vrf_fwd = [f" ip vrf forwarding {vrf}"] if vrf else []
    vrf_kw = f" vrf {vrf}" if vrf else ""
    lines = [
        "aaa new-model",
        "aaa authentication login default local",
        "aaa authorization exec default local",
    ]
    undo: list[str] = []
    if radius:
        lines += [
            "radius server ISE-PSN1",
            f" address ipv4 {ise} auth-port 1812 acct-port 1813",
            " key <the RADIUS secret>",
            f"aaa group server radius {RADIUS_GROUP}",
            " server name ISE-PSN1",
            *vrf_fwd,
            f" ip radius source-interface {source}",
            f"aaa authentication dot1x default group {RADIUS_GROUP}",
            f"aaa authorization network default group {RADIUS_GROUP}",
            f"aaa accounting dot1x default start-stop group {RADIUS_GROUP}",
            "aaa server radius dynamic-author",
            f" client {ise}{vrf_kw} server-key <the RADIUS secret>",
            "radius-server attribute 6 on-for-login-auth",
            "radius-server attribute 8 include-in-access-req",
            "radius-server attribute 25 access-request include",
            "radius-server dead-criteria time 5 tries 3",
            "radius-server deadtime 15",
            "dot1x system-auth-control",
        ]
        undo += [
            "no aaa server radius dynamic-author",
            f"no aaa accounting dot1x default start-stop group {RADIUS_GROUP}",
            f"no aaa authorization network default group {RADIUS_GROUP}",
            f"no aaa authentication dot1x default group {RADIUS_GROUP}",
            f"no aaa group server radius {RADIUS_GROUP}",
            "no radius server ISE-PSN1",
            "no radius-server attribute 6 on-for-login-auth",
            "no radius-server attribute 8 include-in-access-req",
            "no radius-server attribute 25 access-request include",
            "no radius-server dead-criteria time 5 tries 3",
            "no radius-server deadtime 15",
            "no dot1x system-auth-control   (only if step 1 found it off)",
        ]
    if tacacs:
        lines += [
            "tacacs server ISE-PSN1",
            f" address ipv4 {ise}",
            " key <the TACACS+ key>",
            f"aaa group server tacacs+ {TACACS_GROUP}",
            " server name ISE-PSN1",
            *vrf_fwd,
            f" ip tacacs source-interface {source}",
            f"aaa authentication login {ADMIN_LIST} group {TACACS_GROUP} local",
            f"aaa authorization exec {ADMIN_LIST} group {TACACS_GROUP} local",
            f"aaa accounting commands 15 {ADMIN_LIST} start-stop group {TACACS_GROUP}",
            "line vty 0 15",
            f" login authentication {ADMIN_LIST}",
            f" authorization exec {ADMIN_LIST}",
            f" accounting commands 15 {ADMIN_LIST}",
        ]
        undo = [
            "line vty 0 15",
            f" no login authentication {ADMIN_LIST}",
            f" no authorization exec {ADMIN_LIST}",
            f" no accounting commands 15 {ADMIN_LIST}",
            "exit",
            f"no aaa accounting commands 15 {ADMIN_LIST} start-stop group {TACACS_GROUP}",
            f"no aaa authorization exec {ADMIN_LIST} group {TACACS_GROUP} local",
            f"no aaa authentication login {ADMIN_LIST} group {TACACS_GROUP} local",
            f"no aaa group server tacacs+ {TACACS_GROUP}",
            "no tacacs server ISE-PSN1",
            *undo,
        ]
    return lines, undo


def register_onboard_nad(reg: ToolRegistrar) -> None:
    enabled = set(reg.tiers)

    @reg.prompt(
        title="Onboard a switch into ISE",
        uses=["ise", "cml", "catc"],
        tier=Tier.WRITE,
        example={"name": "syd-acc-sw01", "ip": "192.0.2.21", "location": "SYD", "switch": "lab/sw1"},
        tools=[
            "ise_get_nad",
            "ise_list_ndgs",
            "ise_list_nodes",
            "ise_create_ndg",
            "ise_create_nad",
            "ise_update_nad",
            "ise_audit_nads",
            "ise_policy_explain",
            "ise_admin_policy_explain",
            "ise_get_auth_list",
            "ise_recent_auth_failures",
            "ise_find_session",
            "ise_delete_object",
            "cml_run_commands",
            "cml_configure_node",
            "catc_get_device",
            "catc_list_devices",
            "catc_run_show_commands",
            "catc_get_site_settings",
            "catc_update_site_aaa_settings",
            "catc_provision_devices",
            "catc_create_template",
            "catc_commit_template",
            "catc_preview_template",
            "catc_deploy_template",
        ],
    )
    def ise_onboard_nad(
        name: Annotated[str, Field(description="The switch's NAD name in ISE, normally its host name")],
        ip: Annotated[
            str,
            Field(description="The address its AAA comes from (the source interface's IP); empty: find it"),
        ] = "",
        switch: Annotated[
            str,
            Field(
                description="Where to configure the switch: 'lab/node' for a CML node (e.g. lab/sw1), or "
                "its Catalyst Center name or IP. Empty: Catalyst Center with the NAD IP"
            ),
        ] = "",
        location: Annotated[
            str,
            Field(
                description="Location group under 'Location#All Locations', e.g. 'SYD' or 'SYD#Bldg-1' "
                "(created if missing)"
            ),
        ] = "",
        device_type: Annotated[
            str,
            Field(description="Device type group under 'Device Type#All Device Types' (created if missing)"),
        ] = "Switch",
        protocols: Annotated[
            Literal["radius", "tacacs", "both"],
            Field(description="RADIUS (802.1X/MAB to ISE), TACACS+ (admin logins on the vty lines), or both"),
        ] = "radius",
        source_interface: Annotated[
            str,
            Field(
                description="Switch interface that sources AAA, e.g. 'Vlan10' or 'Loopback0'; empty: the "
                "interface that holds the NAD IP"
            ),
        ] = "",
        vrf: Annotated[
            str,
            Field(description="VRF the source interface is in, e.g. 'Mgmt-vrf'; empty: the global table"),
        ] = "",
        ise_address: Annotated[
            str, Field(description="ISE PSN address the switch sends AAA to; empty: from ise_list_nodes")
        ] = "",
        site: Annotated[
            str,
            Field(
                description="Catalyst Center site path for the closing coverage check, e.g. "
                "'Global/SYD/Bldg-1'"
            ),
        ] = "",
        test_user: Annotated[
            str, Field(description="Optional: the account for the test login (never its password)")
        ] = "",
        mac: Annotated[
            str, Field(description="Optional: an endpoint on an 802.1X/MAB port of this switch, to verify")
        ] = "",
    ) -> str:
        """Day-1 onboarding of an access switch into ISE, the same way every time: the location and
        device-type groups, the NAD with its RADIUS and/or TACACS+ secret, the switch's AAA config (a
        preview through cml_configure_node, Catalyst Center's site AAA settings or a template), a test
        login seen in ISE, the endpoint session, a recorded undo (ISE and the switch's 'no' lines), and
        a closing coverage check of the site against ISE's NADs. Every change is a preview the user
        approves."""
        name = name.strip()
        if not SAFE_HOST.match(name):
            raise InvalidRequest("name: a host name (letters, digits, . - _)")
        mac, test_user, ip, switch = _validated(mac, test_user, ip, switch)
        location = location.strip().strip("#")
        device_type = device_type.strip().strip("#")
        for label, value in (("location", location), ("device_type", device_type)):
            if value and not SAFE_GROUP_PATH.match(value):
                raise InvalidRequest(f"{label}: group names (letters, digits, spaces, . - _) joined by '#'")
        if not device_type:
            raise InvalidRequest("device_type: give a device type group, e.g. 'Switch'")
        source_interface = source_interface.strip()
        if source_interface and not SAFE_INTERFACE.match(source_interface):
            raise InvalidRequest("source_interface: an interface name like 'Vlan10' or 'Loopback0'")
        vrf = vrf.strip()
        if vrf and not SAFE_VRF.match(vrf):
            raise InvalidRequest("vrf: a VRF name like 'Mgmt-vrf'")
        ise = ""
        if ise_address.strip():
            parsed = parse_ip(ise_address.strip())
            if parsed is None:
                raise InvalidRequest(f"ise_address {ise_address.strip()!r} is not an IP address")
            ise = parsed
        site = site.strip()
        if site and not SAFE_SITE.match(site):
            raise InvalidRequest("site must be a site path like 'Global/Area/Building'")

        radius = protocols in ("radius", "both")
        tacacs = protocols in ("tacacs", "both")
        what = {"both": "RADIUS and TACACS+", "radius": "RADIUS", "tacacs": "TACACS+"}[protocols]
        ip_text = ip or "<the NAD IP from step 1>"
        ise_text = ise or "<the PSN address from step 1>"
        src_text = source_interface or "<the interface that holds the NAD IP>"
        loc_group = f"Location#All Locations#{location}" if location else ""
        type_group = f"Device Type#All Device Types#{device_type}"
        groups = [g for g in (loc_group, type_group) if g]
        groups_arg = ", ".join(f'"{g}"' for g in groups)
        kinds = [k for k, on in (("radius", radius), ("tacacs", tacacs)) if on]
        nad_secrets = ", ".join(f"{k}_secret=<from the user>" for k in kinds)
        secrets = " and ".join({"radius": "the RADIUS secret", "tacacs": "the TACACS+ key"}[k] for k in kinds)
        lines, undo = _switch_aaa_lines(radius=radius, tacacs=tacacs, ise=ise_text, source=src_text, vrf=vrf)
        lines_text = "\n".join(f"     {line}" for line in lines)
        undo_text = "\n".join(f"       {line}" for line in undo)

        if switch and "/" in switch:
            lab, node = switch.split("/", 1)
            cli = f'{tool_ref("cml_run_commands")} with lab="{lab}", nodes=["{node}"]'
            where = f"the CML node {node} in lab {lab}"
            configure = tool_ref("cml_configure_node")
            apply_text = f"""   {configure} with lab="{lab}", node="{node}", lines=[the lines above],
   save=false, WITHOUT confirm. Show the preview and wait for the user's approval. Save only after
   step 6 passes: the same tool with mode="exec", lines=["write memory"] (a preview again)."""
            switch_undo = f'{tool_ref("cml_configure_node")} with lab="{lab}", node="{node}" and these lines'
            catc_check = ""
        else:
            target = switch or ip_text
            cli = f'{tool_ref("catc_run_show_commands")} with devices=["{target}"]'
            where = f"the Catalyst Center device {target}"
            get_device = tool_ref("catc_get_device")
            catc_check = (
                f'\n   - Catalyst Center: {get_device} with device="{target}": provisioned to a site whose\n'
                "     AAA is ISE? Then Catalyst Center creates the NAD (step 5); step 4 only checks it."
            )
            apply_text = f"""   Catalyst Center decides how (step 1 found which):
   - Provisioned to a site whose AAA is ISE ({tool_ref("catc_get_site_settings")} with the site, AAA
     section): Catalyst Center owns the switch's AAA. Set the site's network/client AAA to ISE with
     {tool_ref("catc_update_site_aaa_settings")} and re-provision with {tool_ref("catc_provision_devices")}
     (both previews; provisioning is dangerous tier on the catc server). Catalyst Center then pushes
     its own AAA lines and creates or updates the NAD in ISE.
   - Not provisioned (or AAA not managed there): a template.
     {tool_ref("catc_create_template")} with name="ise-onboard-{name}", software_type="IOS-XE",
     content=<the lines above>, then {tool_ref("catc_commit_template")}, {tool_ref("catc_preview_template")}
     with device="{target}" (the rendered CLI) and {tool_ref("catc_deploy_template")} with
     devices=["{target}"] WITHOUT confirm (dangerous tier on the catc server). Show each preview and
     wait for the user's approval."""
            switch_undo = (
                "a negation template with these lines (create, commit, preview, deploy as in step\n"
                "     5), or for a provisioned switch the site's previous AAA settings and a re-provision"
            )

        loc_step = (
            f'   - {tool_ref("ise_create_ndg")} with path="{loc_group}" if step 2 found it missing (each\n'
            "     missing parent first: the tool refuses a group whose parent doesn't exist)."
            if loc_group
            else "   - No location given: ask which location group the switch belongs in (policy conditions\n"
            "     usually match on it). Only the default 'All Locations' is a finding in step 8."
        )
        admin_user = test_user or "<the test account>"
        tacacs_test = (
            f"""   - TACACS+: the user opens a NEW SSH session to {ip_text} with
     {test_user or "a test account"} (keep the current session open until it works).
     {tool_ref("ise_admin_policy_explain")} with user="{admin_user}", nad="{name}" shows the
     device-admin rule it lands on (a device-admin policy set must match the NAD's groups). ISE has
     no REST live log for TACACS+: on the switch 'show tacacs' counts it, and the user reads
     Operations > TACACS > Live Logs.
   - Lockout check (TACACS+): log in once more with the LOCAL account on the console. It must still
     work; if it doesn't, undo step 5 at once."""
            if tacacs
            else ""
        )
        radius_test = (
            f"""   - RADIUS: the user types on the switch console (never here):
       test aaa group {RADIUS_GROUP} {test_user or "<user>"} <password> new-code
     The switch's answer is the proof: "User successfully authenticated" or "User rejected" both
     prove the path and the secret. A 'test aaa' login sends no RADIUS accounting, so MnT keeps no
     record of it, passed or failed: {tool_ref("ise_get_auth_list")} and {
                tool_ref("ise_recent_auth_failures")
            } stay empty, and the
     rule it hit is only in the GUI (Operations > RADIUS > Live Logs, NAS IP {ip_text}). No answer
     at all: 'show aaa servers' (requests rising, no responses = the secret, the source address or
     the route)."""
            if radius
            else ""
        )
        session_step = (
            f'{tool_ref("ise_find_session")} with mac="{mac}"'
            if mac
            else f"{tool_ref('ise_find_session')} with mac=<an endpoint on an 802.1X/MAB port>"
            + (f' or username="{test_user}"' if test_user else "")
        )
        expected = (
            f'{tool_ref("catc_list_devices")} with site="{site}" (hostname, managementIpAddress); pass the\n'
            f"   rows to {tool_ref('ise_audit_nads')} as expected=, with "
            + (f'stale_within="{loc_group}"' if loc_group else "check_stale=false")
            + " (a site is part of the inventory)"
            if site
            else f'{tool_ref("ise_audit_nads")} with expected=[{{"name": "{name}", "ip": "{ip_text}", '
            f'"ndg": [{groups_arg}]'
            + (', "aaa_server": "' + ise_text + '"' if radius else "")
            + "}], check_stale=false (no site given: just this switch)"
        )
        vrf_note = (
            f"VRF {vrf}: the server groups carry 'ip vrf forwarding {vrf}', the CoA client the vrf keyword."
            if vrf
            else "No VRF given: the source interface is in the global table (step 1 checks it)."
        )

        psn_text = "" if ise else f"{tool_ref('ise_list_nodes')}: the PSN address the switch will use."
        ping_vrf = f" with vrf {vrf}" if vrf else ""

        return f"""Onboard switch {name} into ISE for {what}, configured through {where}.
Rules for every write below: call the tool WITHOUT confirm, show the preview, wait for the user's
approval; never pass confirm yourself. Secrets ({secrets}) come from the user, are the same in ISE and
on the switch, and are never repeated back or written in the report; never invent one. The cml_* and
catc_* tools need those servers: without one, do the ISE steps and give the switch lines for the user
to paste.

Where AAA comes from: the NAD address is the IP of the interface that sources AAA. Cisco's campus
design sources it from the in-band management SVI or Loopback0, so the address stays the same
whichever uplink is up. Sourcing it from the out-of-band management port (GigabitEthernet0/0 in
Mgmt-vrf, the switch's counterpart of SD-WAN's VPN 512) is a common lab and data-centre pattern and is
fine when ISE is reachable on the management network: then set vrf="Mgmt-vrf". {vrf_note}

1. Before any change (read only).
   - ISE: {tool_ref("ise_get_nad")} with device="{ip or name}" (and with the name, if an IP was given):
     an existing NAD at that IP or name means step 4 updates it with {tool_ref("ise_update_nad")}
     instead of adding a second one. {psn_text}
   - Switch, {cli}: "show running-config | section aaa|radius|tacacs|dot1x",
     "show running-config | include ^username", "show ip interface brief", "show vrf",
     "show aaa servers". Record what is already there (the undo restores it, and 'aaa new-model'
     stays if it was on).{"" if ip else " The NAD IP is the address of the source interface."}
     A ping from the switch to {ise_text}{ping_vrf} and source {src_text} must answer.{catc_check}
   - Lockout guard: the switch must have a local privilege-15 username that logs in on the console.
     No such account: stop and say so; the config below falls back to local accounts only.

2. Device groups. {tool_ref("ise_list_ndgs")} with name="{location or "Location"}" and
   name="{device_type}": which of {groups_arg} exist.

3. Create the missing groups (previews).
{loc_step}
   - {tool_ref("ise_create_ndg")} with path="{type_group}" if it is missing.

4. The NAD (preview). {tool_ref("ise_create_nad")} with name="{name}", ips=["{ip_text}/32"],
   {nad_secrets}, groups=[{groups_arg}], coa_port=1700,
   description="Access switch, AAA from {src_text}". Then {tool_ref("ise_get_nad")} with
   device="{name}": groups, secret set, CoA port.

5. The switch's AAA config (preview). The lines (IOS XE; Cisco's campus NAC defaults):
{lines_text}
   Leave out the two 'default local' lines if step 1 found default login/exec lists already, and
   keep the existing ones. The secrets go only into the tool arguments. Console logins keep the
   local default list; {
            f"the vty lines use {ADMIN_LIST} (TACACS+, then local when ISE is unreachable)."
            if tacacs
            else "admin logins stay local (protocols=radius)."
        }
   802.1X/MAB on the access ports is a separate change: none of these lines touch an interface.
{apply_text}

6. Test the login.
{chr(10).join(x for x in (radius_test, tacacs_test) if x)}
   - {tool_ref("ise_policy_explain")} with nad="{name}", flow="wired-dot1x": which policy set and rule
     endpoints on this switch will hit.

7. Verify the session. {session_step}: NAD IP {ip_text}, the port, the authorization rule and profile.
   No endpoint yet: say so (a 'test aaa' login sends no accounting, so it has no session).

8. Coverage check. {expected}.
   The new NAD must match by IP with its groups (no missing_nad, wrong_ndg, ip_mismatch{
            ", aaa_elsewhere" if radius else ""
        });
   list any stale NADs it reports at the site for the user, without deleting them.

9. Report and record the undo. One table: NAD (created/updated, groups) | switch config (lines
   applied, saved) | test login | session | coverage findings. Then the exact undo, in this order:
   - Switch ({switch_undo}):
{undo_text}
     Leave out any line step 1 found configured before this run; 'no aaa new-model' only if step 1
     found it off.
{_onboard_undo_text(enabled, name)}"""

"""Workflow prompts started from this server (BUILDING-A-SERVER §5a)."""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from typing import Annotated

from pydantic import Field
from stutters_mcp_core import InvalidRequest, ToolRegistrar, tool_ref

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

    @reg.prompt(
        title="Troubleshoot endpoint network access",
        uses=["ise", "cml", "catc"],
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

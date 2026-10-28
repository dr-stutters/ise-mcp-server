"""Prompt ise_onboard_sdwan_edges (I81): Catalyst SD-WAN edges as ISE network devices.

Owner decision (Wave 7): AAA from the edges goes over a service VPN with a loopback source, one stable NAD
address per edge whichever transport is up (VPN 512 is optional and absent at many branches).
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import ipaddress
import re
from typing import Annotated, Literal

from pydantic import Field

from ise_mcp._core import InvalidRequest, Tier, ToolRegistrar, tool_ref

# Prompt arguments are interpolated into instructions, so they are held to strict shapes.
SAFE_SITE = re.compile(r"^[\w.-]{1,64}$")
SAFE_HOST = re.compile(r"^[\w.-]{1,64}$")
SAFE_LOOPBACK = re.compile(r"^Loopback\d{1,10}$")
SAFE_GROUP = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
SAFE_NAME = re.compile(r"^[\w .-]{1,64}$")
SAFE_USER = re.compile(r"^[\w.@\\+-]{1,64}$")
DEVICE_TYPE_GROUP = "Device Type#All Device Types#SD-WAN Edge"


def _edges(value: str) -> list[str]:
    names = [e.strip() for e in value.split(",") if e.strip()]
    for n in names:
        if not SAFE_HOST.match(n):
            raise InvalidRequest(f"edges: {n!r} is not a host name (letters, digits, . - _)")
    if len(names) > 50:
        raise InvalidRequest("edges: at most 50 per run")
    return names


def _ise_address(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise InvalidRequest(f"ise_address {value!r} is not an IP address") from None


def register(reg: ToolRegistrar) -> None:
    @reg.prompt(
        title="Onboard Catalyst SD-WAN edges into ISE",
        uses=["ise", "catsdwan"],
        tier=Tier.WRITE,
        example={"site": "200", "service_vpn": "10", "loopback": "Loopback10"},
        tools=[
            "ise_list_nodes",
            "ise_list_ndgs",
            "ise_audit_nads",
            "ise_list_policy_sets",
            "ise_list_identity_sources",
            "ise_list_command_sets",
            "ise_create_ndg",
            "ise_create_nad",
            "ise_update_nad",
            "ise_set_shell_profile",
            "ise_create_authz_profile",
            "ise_create_policy_set",
            "ise_create_authn_rule",
            "ise_create_authz_rule",
            "ise_admin_policy_explain",
            "ise_policy_explain",
            "ise_get_nad",
            "ise_get_auth_list",
            "ise_recent_auth_failures",
            "catsdwan_list_devices",
            "catsdwan_get_device",
            "catsdwan_routes",
            "catsdwan_ping",
            "catsdwan_get_feature_parcel",
            "catsdwan_set_feature_parcel",
            "catsdwan_set_device_variables",
            "catsdwan_get_device_config",
            "catsdwan_deploy_config_group",
            "catsdwan_device_state",
        ],
    )
    def ise_onboard_sdwan_edges(
        site: Annotated[
            str, Field(description="Catalyst SD-WAN site: its id (e.g. '200') or name (e.g. 'SITE_200')")
        ],
        edges: Annotated[
            str,
            Field(description="Comma-separated edge host names to onboard; empty: every edge at the site"),
        ] = "",
        service_vpn: Annotated[
            int,
            Field(
                ge=0,
                le=65527,
                description="Service VPN that carries AAA to ISE over the overlay (e.g. 10); 0: the VPN of "
                "the edge's service loopback",
            ),
        ] = 0,
        loopback: Annotated[
            str,
            Field(
                description="Loopback interface that sources AAA, e.g. 'Loopback10'; empty: find it on each "
                "edge in the service VPN"
            ),
        ] = "",
        ise_address: Annotated[
            str,
            Field(
                description="ISE PSN address the edges reach in the service VPN; empty: from ise_list_nodes"
            ),
        ] = "",
        protocols: Annotated[
            Literal["both", "tacacs", "radius"],
            Field(
                description="AAA to set up: TACACS+ (device admin), RADIUS (admin logins and 802.1X/MAB), "
                "or both"
            ),
        ] = "both",
        location_root: Annotated[
            str,
            Field(
                description="Location group the per-site groups go under, e.g. 'SD-WAN' (created if missing)"
            ),
        ] = "SD-WAN",
        sdwan_group: Annotated[
            str,
            Field(description="Catalyst SD-WAN user group the admins get, e.g. 'netadmin' or 'operator'"),
        ] = "netadmin",
        test_user: Annotated[
            str, Field(description="Optional: the account used for the test login (never its password)")
        ] = "",
    ) -> str:
        """Bring a Catalyst SD-WAN site's edges into ISE: one location group per site, a NAD per edge at
        its service-VPN loopback (AAA rides the overlay from a stable source whichever transport is up),
        a device-admin policy for the edges, then the edges' AAA parcel through
        catsdwan_set_feature_parcel with that loopback as source, a config-group deploy preview, and a
        TACACS+ and RADIUS test login checked in ISE. Every change is a preview the user approves; the
        catsdwan steps need the cat-sdwan server (without it: the GUI steps)."""
        site = site.strip()
        if not SAFE_SITE.match(site):
            raise InvalidRequest("site must be a site id like '200' or a name like 'SITE_200'")
        names = _edges(edges)
        loopback = loopback.strip()
        if loopback and not SAFE_LOOPBACK.match(loopback):
            raise InvalidRequest("loopback must be a loopback interface name like 'Loopback10'")
        if service_vpn == 512:
            raise InvalidRequest("service_vpn 512 is the management VPN; AAA goes over a service VPN")
        ise = _ise_address(ise_address)
        location_root = location_root.strip()
        if not SAFE_NAME.match(location_root) or "#" in location_root:
            raise InvalidRequest("location_root: letters, digits, spaces and . - _ (no '#')")
        sdwan_group = sdwan_group.strip()
        if not SAFE_GROUP.match(sdwan_group):
            raise InvalidRequest("sdwan_group: a Catalyst SD-WAN user group like 'netadmin'")
        test_user = test_user.strip()
        if test_user and not SAFE_USER.match(test_user):
            raise InvalidRequest("test_user may only contain letters, digits and . @ \\ + - _")

        profile_name = "SDWAN_Edge_" + re.sub(r"[^A-Za-z0-9_]", "_", sdwan_group)
        tacacs = protocols in ("both", "tacacs")
        radius = protocols in ("both", "radius")
        root = f"Location#All Locations#{location_root}"
        site_group = f"{root}#<site name from step 1, e.g. SITE_{site if site.isdigit() else '200'}>"
        scope = f"edges {', '.join(names)} at site {site}" if names else f"every edge at site {site}"
        edge_filter = f" and keep only {', '.join(names)} (stop and say which are missing)" if names else ""
        vpn_text = f"VPN {service_vpn}" if service_vpn else "the service VPN of the loopback"
        vpn_arg = str(service_vpn) if service_vpn else "<the service VPN>"
        lo_text = f'"{loopback}"' if loopback else "a Loopback<n> in a service VPN (not 0 or 512)"
        ise_text = (
            f"ISE at {ise}"
            if ise
            else f"each PSN's ipAddress from {tool_ref('ise_list_nodes')} (the PSN the edges should use)"
        )
        ise_arg = ise or "<the PSN address>"
        kinds = [*(["tacacs"] if tacacs else []), *(["radius"] if radius else [])]
        secrets = " and ".join({"tacacs": "a TACACS+ key", "radius": "a RADIUS secret"}[k] for k in kinds)
        nad_secrets = ", ".join(f"{k}_secret=<from the user>" for k in kinds)
        what = {"both": "TACACS+ and RADIUS", "tacacs": "TACACS+", "radius": "RADIUS"}[protocols]
        order = ", ".join([*kinds, "local"])
        user_text = f'"{test_user}"' if test_user else "a test account the user names"

        parcel_values = []
        if radius:
            parcel_values.append(
                f'radius[0]: group name (e.g. "ise-radius"), vpn {vpn_arg}, source interface: the loopback,\n'
                f"       server[0] address {ise_arg}, auth port 1812, acct port 1813, the RADIUS secret"
            )
        if tacacs:
            parcel_values.append(
                f'tacacs[0]: group name (e.g. "ise-tacacs"), vpn {vpn_arg}, source interface: the loopback,\n'
                f"       server[0] address {ise_arg}, port 49, the TACACS+ key"
            )
        parcel_text = "\n".join(f"     - {v}" for v in parcel_values)

        da_policy = (
            f"""5. Device-admin policy for the edges (TACACS+; skip if a device-admin set already matches
   "{DEVICE_TYPE_GROUP}" in step 3).
   a. {tool_ref("ise_set_shell_profile")} name="{profile_name}", privilege=15,
      sdwan_group="{sdwan_group}" (priv-lvl for IOS XE, viptela-group-name for the SD-WAN user group).
   b. {tool_ref("ise_list_command_sets")}: use an existing permit-all set or the one the user names.
   c. {tool_ref("ise_create_policy_set")} kind="device-admin", name="SD-WAN Edges",
      conditions=["DEVICE:Device Type equals All Device Types#SD-WAN Edge"]; then
      {tool_ref("ise_create_authn_rule")} kind="device-admin" with the identity source the admins use
      ({tool_ref("ise_list_identity_sources")}; ask the user) and {tool_ref("ise_create_authz_rule")}
      kind="device-admin" with the admins' group as the condition (ask), the shell profile from a and
      the command set from b. The Default rule stays Deny All Shell Profile.
   d. {tool_ref("ise_admin_policy_explain")} with user={user_text}, nad=<first edge>,
      command=["show running-config"]: the login should land on the rule from c with priv-lvl 15."""
            if tacacs
            else "5. Device-admin policy: skipped (protocols=radius)."
        )
        radius_policy = (
            f"""6. RADIUS admin logins (skip if step 3 found a network-access rule for the edges).
   {tool_ref("ise_create_authz_profile")} name="{profile_name}",
   av_pairs=["Cisco:cisco-av-pair=shell:priv-lvl=15"], sdwan_group="{sdwan_group}" (adds
   Viptela:Viptela-Group-Name; if the preview says the Viptela dictionary is missing, give the user its
   GUI step and carry on without sdwan_group). Then a network-access policy set the same way as 5c
   ({tool_ref("ise_create_policy_set")} with the device-type condition, an authn rule, an authz rule with
   this profile), or a rule in the set the edges already hit
   ({tool_ref("ise_policy_explain")} with nad=<first edge>)."""
            if radius
            else "6. RADIUS: skipped (protocols=tacacs)."
        )
        radius_check = (
            f"""   - RADIUS: with "{order}" an SSH login is answered by the first server group, so test
     RADIUS on the edge's console: the user types `test aaa group <the RADIUS group> <user> <password>
     new-code` there (never here). The edge's answer is the proof: "User successfully authenticated"
     or "User rejected" both prove the path and the secret. A `test aaa` login sends no RADIUS
     accounting, so MnT keeps no record of it, passed or failed ({tool_ref("ise_get_auth_list")} and
     {tool_ref("ise_recent_auth_failures")} stay empty): the rule it hit is only in the GUI,
     Operations > RADIUS > Live Logs filtered by the edge's loopback. No answer at all (timeout) = a
     wrong secret, the wrong source address or no route (step 2)."""
            if radius
            else ""
        )
        tacacs_check = (
            """   - TACACS+: an SSH login to the edge's loopback (over the service VPN) or its console. ISE
     has no REST live log for TACACS+: the evidence is the edge's AAA counters and session (next point)
     and ISE's GUI Operations > TACACS > Live Logs, which the user reads."""
            if tacacs
            else ""
        )
        checks = "\n".join(x for x in (tacacs_check, radius_check) if x)

        return f"""Onboard {scope} into ISE for {what}.
Design (owner decision): AAA from an edge goes over {vpn_text} through the overlay to ISE, sourced
from a loopback in that VPN, so each edge is one NAD at one stable address whichever transport is up.
Never use an address in VPN 0 (transport), VPN 512 (management) or the platform VRFs 65528/65529 as
the NAD address.

Rules for every write below: call the tool WITHOUT confirm, show the preview and wait for the user's
approval; never pass confirm yourself. Secrets ({secrets}) come from the user, are the same in
ISE and in the edges' AAA parcel, and are never repeated back; never invent one. The catsdwan_* tools
need the cat-sdwan server: if it is not connected, ask the user for each edge's host name and loopback
address, do the ISE steps, and give the SD-WAN Manager GUI steps for 7 and 8 instead.

1. Edges and their loopbacks. {tool_ref("catsdwan_list_devices")} with site="{site}",
   personality="edge"{edge_filter}. Note each edge's host, system IP, site name,
   configuration mode and configuration group. For each edge {tool_ref("catsdwan_get_device")} with
   device=<host>: its interfaces with name, VPN and IP; the AAA source is
   {lo_text}{f" in VPN {service_vpn}" if service_vpn else ""}. Record the loopback's address (/32).
   An edge with no such loopback can't be onboarded yet: say so, and offer to add one to its
   configuration group's service profile (a loopback in {vpn_text}) as a separate, previewed change.
   An edge on a device template (not a configuration group) gets its AAA from the template: steps 7-8
   don't apply; give the feature-template step.

2. Path from each loopback to ISE. ISE: {ise_text}. {tool_ref("catsdwan_routes")} with
   device=<edge>, vpn={vpn_arg}, prefix={ise_arg}: a route must cover it (normally OMP from the DC);
   `missing` means no path, and onboarding stops there for that edge (the service VPN must reach ISE
   first). Then {tool_ref("catsdwan_ping")} with device=<edge>, destination={ise_arg}, vpn={vpn_arg},
   source_interface=<the loopback>, count=5: replies prove the return path to the loopback too.

3. What ISE already has. {tool_ref("ise_list_ndgs")} with name="{location_root}" and name="SD-WAN Edge";
   {tool_ref("ise_audit_nads")} with
   expected=[{{"name": "<host>", "ip": "<loopback IP>", "ndg": "<site group>"}}, ...] (one row per edge)
   and check_stale=false. missing_nad = create it in 4; ip_mismatch (a NAD with the edge's name at
   another address, e.g. its VPN 512 or transport IP) = update that NAD with
   {tool_ref("ise_update_nad")} instead of adding a second one; wrong_ndg = add the groups.
   {tool_ref("ise_list_policy_sets")} kind="device-admin" and kind="network-access": does a set already
   match the SD-WAN edges?

4. Groups and NADs (previews).
   a. {tool_ref("ise_create_ndg")} path="{root}" if it is missing; one group per site:
      path="{site_group}";
      and path="{DEVICE_TYPE_GROUP}" once.
   b. Per edge {tool_ref("ise_create_nad")} name=<host>, ips=["<loopback IP>/32"],
      {nad_secrets},
      groups=["<the site group>", "{DEVICE_TYPE_GROUP}"],
      description="SD-WAN edge, system IP <system IP>, AAA from <loopback> in VPN {vpn_arg}".
      One preview per edge; {tool_ref("ise_get_nad")} after each apply.

{da_policy}

{radius_policy}

7. The edges' AAA parcel (SD-WAN Manager; stores only). {tool_ref("catsdwan_get_feature_parcel")} with
   profile=<the configuration group from step 1>, parcel="aaa", fields=true: current values, the system
   profile that holds it, and used_by (every device of the group gets this parcel, not only this site).
   Then {tool_ref("catsdwan_set_feature_parcel")} with that profile and parcel and `values` (field paths
   as the schema lists them; list items as name[0].field):
{parcel_text}
     - serverAuthOrder [{order}] (keep "local" last: local admins still log in when ISE is down)
   If the loopback name differs between edges, make the source interface a variable
   ('{{{{aaa_source_if}}}}') and set it per edge with {tool_ref("catsdwan_set_device_variables")}. The
   preview checks every value against the Manager's schema and shows the blast radius: name every
   device it reaches before asking.

8. Deploy (preview only). For each edge first {tool_ref("catsdwan_get_device_config")} with diff=true,
   so unrelated drift is not pushed with the AAA change. Then {tool_ref("catsdwan_deploy_config_group")}
   with the group and devices=[the site's edges]: the preview shows the CLI per edge (radius server,
   aaa group server ... ip vrf forwarding, ip radius / ip tacacs source-interface <loopback> vrf ...).
   Check each source-interface line names the loopback and the service VRF. Several devices need
   MCP_ENABLE_DANGEROUS on the cat-sdwan server; one edge at a time works without it.

9. Test logins. After the deploy, {tool_ref("catsdwan_device_state")} with feature="aaa",
   device=<edge>: the servers are there and not dead. Ask the user to log in to one edge with
   {user_text}; never ask for a password in chat.
{checks}
   - {tool_ref("catsdwan_device_state")} feature="aaa" again: requests/accepts counted, the session
     listed.

10. Report one row per edge: host | system IP | loopback (VPN) | path to ISE (route, ping) | NAD
   (created, updated, existed) | groups | AAA parcel / deploy | TACACS+ login | RADIUS login. Then what
   is left: edges without a loopback or a path, the Viptela dictionary GUI step if it was missing, and
   the other devices of the configuration group that get the new AAA parcel on their next deploy."""

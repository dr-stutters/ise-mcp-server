"""Prompt ise_guest_onboarding (I48): a sponsored guest end to end without the sponsor portal.

Readiness (sponsor, guest type, location, portal, the CWA rules), the guest account as the sponsor
(preview first), the credentials to the guest (ISE's notification, or the sponsor hands them over), then
proof: the guest's session, its authorization, and the CWA sequence in the auth history. The guest's
password is never repeated in the conversation or the report.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from typing import Annotated, Literal

from pydantic import Field

from ise_mcp._core import InvalidRequest, Tier, ToolRegistrar, tool_ref
from ise_mcp.tools._common import normalize_mac

# Prompt arguments are interpolated into instructions, so they are held to strict shapes.
GUEST_USERNAME = re.compile(r"^[\w.@+-]{1,64}$")
SAFE_NAME = re.compile(r"^[\w .()#-]{1,64}$")
SAFE_EMAIL = re.compile(r"^[\w.+-]{1,64}@[\w-]{1,63}(\.[\w-]{1,63}){1,8}$")
SAFE_PHONE = re.compile(r"^\+[1-9]\d{6,14}$")
SAFE_NAD = re.compile(r"^[\w./:-]{1,64}$")

# What ISE's default network-access policy does for guests (Wireless_MAB / Wired_MAB redirect, then
# Guest_Flow after the portal login and the CoA). The prompt names them as what to look for.
GUEST_FLOW = "Network Access:UseCase"
GUEST_GROUP = "Endpoint Identity Groups:GuestEndpoints"

TOOLS = [
    "ise_status",
    "ise_list_sponsor_groups",
    "ise_list_guest_types",
    "ise_get_guest_locations",
    "ise_list_guest_portals",
    "ise_list_authz_profiles",
    "ise_list_policy_sets",
    "ise_get_policy_set",
    "ise_policy_explain",
    "ise_list_guest_users",
    "ise_get_guest_user",
    "ise_create_guest_user",
    "ise_notify_guest",
    "ise_reset_guest_password",
    "ise_find_session",
    "ise_get_auth_history",
    "ise_why_auth_failed",
    "ise_suspend_guest_user",
    "ise_delete_guest_user",
]


def _check(value: str, pattern: re.Pattern[str], what: str) -> str:
    value = value.strip()
    if value and not pattern.match(value):
        raise InvalidRequest(what)
    return value


def register(reg: ToolRegistrar) -> None:
    @reg.prompt(
        title="Onboard a sponsored guest (create, deliver credentials, verify)",
        uses=["ise"],
        tier=Tier.WRITE,
        example={"username": "visitor01", "guest_type": "Daily (default)", "notify": "email"},
        tools=TOOLS,
    )
    def ise_guest_onboarding(
        username: Annotated[
            str, Field(description="Guest username to create (letters, digits and _ . @ + -)")
        ],
        guest_type: Annotated[
            str,
            Field(
                description="Guest type, e.g. 'Daily (default)'; empty: pick one from ise_list_guest_types"
            ),
        ] = "",
        email: Annotated[str, Field(description="Guest's email address (for notify='email')")] = "",
        phone: Annotated[str, Field(description="Guest's mobile number in E.164, e.g. +15551234567")] = "",
        location: Annotated[
            str, Field(description="Guest location; empty: the only one ISE has (or ask the user)")
        ] = "",
        notify: Annotated[
            Literal["email", "sms", "none"],
            Field(
                description="How the guest gets the credentials: ISE emails or texts them "
                "(ise_notify_guest), or none (the sponsor hands them over)"
            ),
        ] = "email",
        access: Annotated[
            Literal["wireless", "wired"],
            Field(description="Where the guest connects: a guest SSID (wireless) or a wired guest port"),
        ] = "wireless",
        nad: Annotated[
            str,
            Field(description="Optional: the WLC or switch the guest connects through, for the policy check"),
        ] = "",
        mac: Annotated[
            str, Field(description="Optional: the guest device's MAC, for the session and auth history")
        ] = "",
    ) -> str:
        """Onboard one sponsored guest end to end without the sponsor portal: check the sponsor (REST
        access, the guest type and location it may use), the guest type, location and portal, and that
        the central web auth (CWA) rules exist (ise_policy_explain before and after the portal login),
        then create the guest account as the sponsor (preview first), deliver the credentials by ISE's
        email or SMS (ise_notify_guest) or by the sponsor, and verify the guest's session, its
        authorization and the redirect, login, CoA sequence in the auth history. The password is never
        repeated in the conversation or the report."""
        if not GUEST_USERNAME.match(username.strip()):
            raise InvalidRequest("username: 1-64 letters, digits, '_', '.', '@', '+' or '-'")
        username = username.strip()
        guest_type = _check(guest_type, SAFE_NAME, "guest_type: a guest type name like 'Daily (default)'")
        location = _check(location, SAFE_NAME, "location: a guest location name like 'San Jose'")
        email = _check(email, SAFE_EMAIL, "email: an address like visitor@example.com")
        phone = _check(phone, SAFE_PHONE, "phone: E.164 like +15551234567")
        nad = _check(nad, SAFE_NAD, "nad: a network device name or IP address")
        mac_text = mac.strip()
        if mac_text:
            try:
                mac_text = normalize_mac(mac_text)
            except InvalidRequest:
                raise InvalidRequest("mac: a MAC address like aa:bb:cc:dd:ee:ff") from None
        if notify == "email" and not email:
            raise InvalidRequest("notify='email' needs the guest's email")
        if notify == "sms" and not phone:
            raise InvalidRequest("notify='sms' needs the guest's phone (E.164)")

        delivered = "(handed over by the sponsor)" if notify == "none" else f"(delivered by {notify})"
        type_text = f'"{guest_type}"' if guest_type else "the guest type the user picks"
        type_arg = f'"{guest_type}"' if guest_type else "<the type picked>"
        loc_arg = f', location="{location}"' if location else ""
        contact = "".join([f', email="{email}"' if email else "", f', phone="{phone}"' if phone else ""])
        flow = "wireless-mab" if access == "wireless" else "wired-mab"
        mab = "Wireless_MAB" if access == "wireless" else "Wired_MAB"
        nad_arg = f'nad="{nad}", ' if nad else ""
        nad_text = (
            f'nad="{nad}"'
            if nad
            else "no nad (the guest's WLC or switch is unknown: say so; device-group conditions stay unknown)"
        )
        connect = "join the guest SSID" if access == "wireless" else "plug into a guest port"
        session_key = f'mac="{mac_text}"' if mac_text else f'username="{username}"'
        history_mac = (
            f'mac="{mac_text}"' if mac_text else "mac=<the calling station id from the session above>"
        )

        if notify == "none":
            delivery = f"""5. Credentials (notify=none: the sponsor hands them over). The password is in the
   confirmed result of step 4, which the user sees. Tell the user to give it to the guest in person or by a
   channel they trust; do not repeat it yourself. If the guest loses it later:
   {tool_ref("ise_reset_guest_password")} with user="{username}" (preview first; the new password is in
   the confirmed result only, and the old one stops working at once)."""
        else:
            target = f'the guest\'s address "{email}"' if notify == "email" else f'the mobile "{phone}"'
            needs = (
                "ISE's SMTP server (Administration > System > Settings > SMTP Server)"
                if notify == "email"
                else "an SMS gateway and the guest type's SMS provider"
            )
            delivery = f"""5. Credentials by ISE ({notify}). {tool_ref("ise_notify_guest")} with
   user="{username}", via="{notify}" WITHOUT confirm: the preview names {target} and the
   sponsor portal's template. Show it and wait for the user's approval. Delivery needs {needs}
   and the sponsor group's notify permission; ISE's notification log shows the delivery (GUI
   only). If the send fails, or the guest says nothing arrived, fall back to the user handing
   the password over (in the confirmed result of step 4). Lost password later:
   {tool_ref("ise_reset_guest_password")} with user="{username}" (preview first), then
   {tool_ref("ise_notify_guest")} again."""

        return f"""Onboard guest "{username}" ({type_text}, {access}) as the sponsor, without the
sponsor portal.

Rules for every write below: call the tool WITHOUT confirm, show the preview and wait for the user's
approval; never pass confirm yourself. The guest's password is a secret: it appears once, in the
confirmed result of {tool_ref("ise_create_guest_user")} (or {tool_ref("ise_reset_guest_password")}),
which the user sees. Never repeat it, summarise it, put it in another tool's arguments or in the
report; write "{delivered}" instead. Never ask for the sponsor's password.

1. Sponsor and guest type.
   a. {tool_ref("ise_status")}: `guest_sponsor` must be set and accepted by ISE. Not set: stop and
      tell the user to set ISE_SPONSOR_USERNAME / ISE_SPONSOR_PASSWORD to an account in a sponsor
      group with REST access (README, Guest access).
   b. {tool_ref("ise_list_sponsor_groups")}: the sponsor's group (its members include the sponsor's
      AD or identity group) is enabled, has rest_access=true, and lists {type_text} among its guest
      types. Missing: name the group change (ise_set_sponsor_group, write tier) and stop.
   c. {tool_ref("ise_list_guest_types")}: {type_text} exists; note its default and maximum duration,
      whether time counts from first login, and the identity group its guests land in (what the
      authz rules match).
   d. {tool_ref("ise_get_guest_locations")}: the location{f' "{location}"' if location else ""} exists (more
      than one and none given: ask the user) and the guest SSIDs sponsors can pick.
   e. {tool_ref("ise_list_guest_portals")} with kind="sponsored_guest" (and "self_registration"):
      the portal the redirect sends guests to, its HTTPS port and test URL. The portal's certificate
      must be trusted by guest browsers; a self-signed portal certificate = a warning the guest sees.
   f. {tool_ref("ise_list_guest_users")} with name="{username}": an account of that name already
      exists = stop and ask (extend or reinstate it instead of a second account).

2. Is the guest flow in policy (central web auth)? Before the account, so a missing rule is found now.
   a. {tool_ref("ise_list_authz_profiles")} with name="WebAuth": a profile with redirect
      CentralizedWebAuth to the portal from 1e (ISE ships Cisco_WebAuth) and the redirect ACL the
      {"WLC" if access == "wireless" else "switch"} has (the ACL name must exist on the device).
   b. {tool_ref("ise_policy_explain")} with {nad_text}, flow="{flow}": before the portal login the
      guest's MAB should hit the redirect rule ({mab} -> the CWA profile; ISE's default is
      Wi-Fi_Redirect_to_Guest_Login with Cisco_WebAuth). The MAB authentication rule must continue
      when the user is not found (If User not found = CONTINUE); check it with
      {tool_ref("ise_list_policy_sets")} and {tool_ref("ise_get_policy_set")}.
   c. {tool_ref("ise_policy_explain")} again with {nad_arg}flow="{flow}" and
      attributes={{"{GUEST_FLOW}": "Guest Flow", "IdentityGroup:Name": "{GUEST_GROUP}"}}
      (the guest type's endpoint group from 1c in place of GuestEndpoints if it differs): after the
      login and the CoA the session should hit the guest access rule (Guest_Flow; ISE's default is
      Wi-Fi_Guest_Access with PermitAccess, often a guest dACL, VLAN or SGT).
   No redirect rule, or the second pass lands on the same rule as the first: report it as the
   blocker with the rule the user should add (ise_create_authz_rule, write tier, not run here) and
   ask whether to carry on.

3. The account plan. Validity: default start now and end start + the type's default duration;
   ask the user only if they want other dates (start/end 'YYYY-MM-DD HH:MM' in the location's time).

4. Create the guest. {tool_ref("ise_create_guest_user")} with username="{username}",
   guest_type={type_arg}{loc_arg}{contact} (first/last name, company, person_being_visited and
   reason_for_visit if the user gives them; no password: ISE's guest password policy makes one)
   WITHOUT confirm. Show the preview (the validity window against the type's maximum) and wait for the
   user's approval. On the confirmed result, say only that the account exists and its validity.

{delivery}

6. Verify the guest. {tool_ref("ise_get_guest_user")} with user="{username}": status
   AWAITING_INITIAL_LOGIN until the first login, ACTIVE after it. Ask the user to have the guest
   {connect}, open a browser, get the portal and log in. Then:
   a. {tool_ref("ise_find_session")} with {session_key}: the session's username is "{username}", the
      authorization profile is the guest access one from 2c (not the redirect profile), and the
      identity group, dACL, VLAN or SGT match it. Still the redirect profile: the CoA did not land
      (the NAD's CoA port, or the guest never finished the portal).
   b. {tool_ref("ise_get_auth_history")} with {history_mac}, include_steps=true: the CWA sequence in
      order: a MAB with the redirect profile, the guest's portal login, a record kind=coa (the CoA
      ISE sent), and the MAB again with the guest access rule. Any failed attempt:
      {tool_ref("ise_why_auth_failed")} with {history_mac}.
   c. {tool_ref("ise_get_guest_user")} again: status ACTIVE (and for a from-first-login type, the
      validity now counts from that login).
   Compare a and b with the prediction in 2b and 2c: a different rule = the prediction or the policy
   is wrong; say which.

7. Report.
   a. The account: username, guest type, validity (location time), location, sponsor, status, and
      how the credentials went ("{delivered}"): never the password.
   b. The policy: the redirect and guest access rules predicted (2b, 2c) against those the session
      hit (6a, 6b), with the authorization profile, dACL, VLAN or SGT.
   c. Evidence: the session id, the auth history rows in order (time, rule, profile, kind).
   d. Next steps, named, not run: end the visit early with {tool_ref("ise_suspend_guest_user")} (the
      session stays up until it re-authenticates: a CoA ends it) or {tool_ref("ise_delete_guest_user")};
      any readiness gap from 1 or 2 with the tool that fixes it."""

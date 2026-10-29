# ise_guest_onboarding

title: Onboard a sponsored guest (create, deliver credentials, verify)
arguments: {"access": "wireless", "email": "visitor01@example.com", "guest_type": "Daily (default)", "location": "San Jose", "mac": "aa:bb:cc:dd:ee:ff", "nad": "wlc1", "notify": "email", "phone": "+15555550123", "username": "visitor01"}

Onboard one sponsored guest end to end without the sponsor portal: check the sponsor (REST
access, the guest type and location it may use), the guest type, location and portal, and that
the central web auth (CWA) rules exist (ise_policy_explain before and after the portal login),
then create the guest account as the sponsor (preview first), deliver the credentials by ISE's
email or SMS (ise_notify_guest) or by the sponsor, and verify the guest's session, its
authorization and the redirect, login, CoA sequence in the auth history. The password is never
repeated in the conversation or the report.

## user

Onboard guest "visitor01" ("Daily (default)", wireless) as the sponsor, without the
sponsor portal.

Rules for every write below: call the tool WITHOUT confirm, show the preview and wait for the user's
approval; never pass confirm yourself. The guest's password is a secret: it appears once, in the
confirmed result of `ise_create_guest_user` (or `ise_reset_guest_password`),
which the user sees. Never repeat it, summarise it, put it in another tool's arguments or in the
report; write "(delivered by email)" instead. Never ask for the sponsor's password.

1. Sponsor and guest type.
   a. `ise_status`: `guest_sponsor` must be set and accepted by ISE. Not set: stop and
      tell the user to set ISE_SPONSOR_USERNAME / ISE_SPONSOR_PASSWORD to an account in a sponsor
      group with REST access (README, Guest access).
   b. `ise_list_sponsor_groups`: the sponsor's group (its members include the sponsor's
      AD or identity group) is enabled, has rest_access=true, and lists "Daily (default)" among its guest
      types. Missing: name the group change (ise_set_sponsor_group, write tier) and stop.
   c. `ise_list_guest_types`: "Daily (default)" exists; note its default and maximum duration,
      whether time counts from first login, and the identity group its guests land in (what the
      authz rules match).
   d. `ise_get_guest_locations`: the location "San Jose" exists (more
      than one and none given: ask the user) and the guest SSIDs sponsors can pick.
   e. `ise_list_guest_portals` with kind="sponsored_guest" (and "self_registration"):
      the portal the redirect sends guests to, its HTTPS port and test URL. The portal's certificate
      must be trusted by guest browsers; a self-signed portal certificate = a warning the guest sees.
   f. `ise_list_guest_users` with name="visitor01": an account of that name already
      exists = stop and ask (extend or reinstate it instead of a second account).

2. Is the guest flow in policy (central web auth)? Before the account, so a missing rule is found now.
   a. `ise_list_authz_profiles` with name="WebAuth": a profile with redirect
      CentralizedWebAuth to the portal from 1e (ISE ships Cisco_WebAuth) and the redirect ACL the
      WLC has (the ACL name must exist on the device).
   b. `ise_policy_explain` with nad="wlc1", flow="wireless-mab": before the portal login the
      guest's MAB should hit the redirect rule (Wireless_MAB -> the CWA profile; ISE's default is
      Wi-Fi_Redirect_to_Guest_Login with Cisco_WebAuth). The MAB authentication rule must continue
      when the user is not found (If User not found = CONTINUE); check it with
      `ise_list_policy_sets` and `ise_get_policy_set`.
   c. `ise_policy_explain` again with nad="wlc1", flow="wireless-mab" and
      attributes={"Network Access:UseCase": "Guest Flow", "IdentityGroup:Name": "Endpoint Identity Groups:GuestEndpoints"}
      (the guest type's endpoint group from 1c in place of GuestEndpoints if it differs): after the
      login and the CoA the session should hit the guest access rule (Guest_Flow; ISE's default is
      Wi-Fi_Guest_Access with PermitAccess, often a guest dACL, VLAN or SGT).
   No redirect rule, or the second pass lands on the same rule as the first: report it as the
   blocker with the rule the user should add (ise_create_authz_rule, write tier, not run here) and
   ask whether to carry on.

3. The account plan. Validity: default start now and end start + the type's default duration;
   ask the user only if they want other dates (start/end 'YYYY-MM-DD HH:MM' in the location's time).

4. Create the guest. `ise_create_guest_user` with username="visitor01",
   guest_type="Daily (default)", location="San Jose", email="visitor01@example.com", phone="+15555550123" (first/last name, company, person_being_visited and
   reason_for_visit if the user gives them; no password: ISE's guest password policy makes one)
   WITHOUT confirm. Show the preview (the validity window against the type's maximum) and wait for the
   user's approval. On the confirmed result, say only that the account exists and its validity.

5. Credentials by ISE (email). `ise_notify_guest` with
   user="visitor01", via="email" WITHOUT confirm: the preview names the guest's address "visitor01@example.com" and the
   sponsor portal's template. Show it and wait for the user's approval. Delivery needs ISE's SMTP server (Administration > System > Settings > SMTP Server)
   and the sponsor group's notify permission; ISE's notification log shows the delivery (GUI
   only). If the send fails, or the guest says nothing arrived, fall back to the user handing
   the password over (in the confirmed result of step 4). Lost password later:
   `ise_reset_guest_password` with user="visitor01" (preview first), then
   `ise_notify_guest` again.

6. Verify the guest. `ise_get_guest_user` with user="visitor01": status
   AWAITING_INITIAL_LOGIN until the first login, ACTIVE after it. Ask the user to have the guest
   join the guest SSID, open a browser, get the portal and log in. Then:
   a. `ise_find_session` with mac="AA:BB:CC:DD:EE:FF": the session's username is "visitor01", the
      authorization profile is the guest access one from 2c (not the redirect profile), and the
      identity group, dACL, VLAN or SGT match it. Still the redirect profile: the CoA did not land
      (the NAD's CoA port, or the guest never finished the portal).
   b. `ise_get_auth_history` with mac="AA:BB:CC:DD:EE:FF", include_steps=true: the CWA sequence in
      order: a MAB with the redirect profile, the guest's portal login, a record kind=coa (the CoA
      ISE sent), and the MAB again with the guest access rule. Any failed attempt:
      `ise_why_auth_failed` with mac="AA:BB:CC:DD:EE:FF".
   c. `ise_get_guest_user` again: status ACTIVE (and for a from-first-login type, the
      validity now counts from that login).
   Compare a and b with the prediction in 2b and 2c: a different rule = the prediction or the policy
   is wrong; say which.

7. Report.
   a. The account: username, guest type, validity (location time), location, sponsor, status, and
      how the credentials went ("(delivered by email)"): never the password.
   b. The policy: the redirect and guest access rules predicted (2b, 2c) against those the session
      hit (6a, 6b), with the authorization profile, dACL, VLAN or SGT.
   c. Evidence: the session id, the auth history rows in order (time, rule, profile, kind).
   d. Next steps, named, not run: end the visit early with `ise_suspend_guest_user` (the
      session stays up until it re-authenticates: a CoA ends it) or `ise_delete_guest_user`;
      any readiness gap from 1 or 2 with the tool that fixes it.

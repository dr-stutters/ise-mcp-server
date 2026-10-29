# ise_policy_change_review

title: Review an ISE authorization policy change before it is applied
arguments: {"change": "reorder", "flows": "wired-dot1x,wired-mab", "minutes": "720", "nads": "syd-acc-sw01,192.0.2.21", "policy_set": "Wired", "rank": "0", "rule": "Employees", "section": "authorization"}

Review an authorization policy change before it is applied, to catch "this rule now matches
everyone": ise_export_config as the baseline, ise_policy_explain on sample logins (each NAD with
each access flow, plus real logins from MnT) before, the change as a preview only (the user
approves it), then ise_diff_config against the baseline (only the previewed change may show),
the same samples explained again, and a summary of who gains or loses access with the rollback.

## user

Review a change to the ISE policy set "Wired" (authorization rule "Employees", change:
reorder) before it is applied. The question is who gains or loses access, and whether the rule now
matches far more logins than intended ("this rule now matches everyone").
Writes: exactly one, the change in step 4, called WITHOUT confirm so it only returns a
preview. Show the preview and wait for the user's approval; never pass confirm yourself.
ise_policy_explain predicts, it does not ask ISE: an "unknown" condition or an uncertain verdict is
reported as such, never guessed.

1. Baseline. `ise_export_config` with scope=["policy_sets", "authz_profiles"]: keep the whole YAML (step 5
   diffs against it; over the response limit, run it again with path=<a .yaml file> and keep the path).
   `ise_get_policy_set` with policy_set="Wired": the authorization rules in rank order with
   conditions, profiles, SGT, state and hits. Record "Employees"'s rank, state, conditions,
   profiles and SGT now: that is the rollback.
   The set's own condition says which logins reach it at all.

2. Samples before (4 synthetic, plus real ones).
   a. Synthetic: for each NAD in ["syd-acc-sw01", "192.0.2.21"] and each flow in ["wired-dot1x", "wired-mab"]:
      `ise_policy_explain` with nad=<NAD>, flow=<flow> (no policy_set, so the set selection
      is checked too). `ise_get_nad` with device=<NAD> when one does not resolve: drop it
      and say so.
   b. Real: `ise_get_auth_list` with nad=<NAD>, since_minutes=720, detail=true for each
      NAD: up to 5 distinct passing logins per NAD (different authorization rule, profile or identity
      group). Explain each with `ise_policy_explain` with nad=<NAD>, flow=<its flow: wired- or
      wireless- with dot1x or mab>,
      attributes=<what the row gives that the rules test: identity group, endpoint profile, EAP type>
      (ad_user=<username> for an AD login). A real login whose prediction differs from the rule MnT
      logged is a sample the evaluator cannot model: keep it, mark it.
   One row per sample: sample | NAD | flow | identity | policy set | rule | profile | SGT | uncertain.
   A sample that lands in another policy set is outside this change: list it once and leave it out.

3. Prediction. From step 1's rules and step 2's traces, before anything changes:
   Moving "Employees" to rank 0 puts it ahead of every rule between rank 0 and its
   rank now (step 1). A sample whose before-match sits in that range and that also meets "Employees"'s
   conditions moves to "Employees": evaluate its conditions against the sample's attributes. Moving it
   down: the samples it matched now reach the rules it passes first.
   For each profile the change brings in, `ise_get_authz_profile` with profile=<it> (and
   `ise_get_dacl` with dacl=<its dACL>): access accept or reject, VLAN, dACL, SGT. A
   condition naming a library condition:
   `ise_list_conditions` with name=<it> for what it tests.
   Red flags, each named in the report: the changed rule would match every sample, or every sample of a
   flow; its conditions test only the flow or NAS-Port-Type (true for every wired or wireless login);
   it would sit above a DenyAccess or quarantine rule (Session:ANCPolicy) and take its logins; a rule
   below it would never match again (shadowed).

4. The change, as a preview only.
   `ise_update_policy_rule` with policy_set="Wired", rule="Employees", section="authorization", rank=0.
   Read the preview: the field diff, the rules it lands between and any blocker. A blocker or a red flag
   from step 3: stop, report, and suggest the narrower rule (an extra condition such as
   'DEVICE:Location starts with ...' or an identity group, or a lower rank). Otherwise show the preview
   and the step 3 prediction together and wait. The user applies it (or not); nothing below runs until
   they say it is applied. Not applied: the report is steps 1-3 and the preview.

5. After it is applied: what changed. `ise_diff_config` with before=<step 1's YAML or path>,
   after="live", scope=["policy_sets", "authz_profiles"].
   Expected: only "Employees" in "Wired" (under `moved` for a
   reorder, `added` for a new rule, `changed` otherwise). Anything else in the diff is someone else's
   change, or a side effect: list it and say it was not part of this review.

6. Samples after. The same calls as step 2, same arguments, in the same order. Rule hits move only
   with real logins: ask the user to bounce one test port if a real sample needs proof.

7. Report.
   a. Who gains or loses access, one row per sample: sample | NAD | flow | identity | before (rule ->
      profile, SGT) | after (rule -> profile, SGT) | verdict. Verdicts: gains (reject -> accept, or a
      wider dACL/VLAN/SGT), loses (accept -> reject, or narrower), changes (another profile or SGT,
      same access), same. Uncertain on either side: say so in the row.
   b. Counts: N samples, how many gain, lose, change, stay the same; samples that moved to
      "Employees" out of all. Every sample moved there: flag it as "matches everyone" at the top.
   c. Prediction vs result: each sample where step 3 and step 6 disagree, and why.
   d. Rollback: `ise_update_policy_rule` with policy_set="Wired", rule="Employees",
      section="authorization" and the rank, state, conditions, profiles and SGT recorded in
      step 1 (a preview again).
      Logins already on the network keep their old result until they re-authenticate (a CoA from the
      user, not this review).

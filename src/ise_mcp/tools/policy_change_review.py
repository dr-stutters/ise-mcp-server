"""Prompt ise_policy_change_review (I46): review an authorization policy change before it is applied.

Catches the "this rule now matches everyone" mistake. The prompt exports the policy as a baseline, runs
ise_policy_explain on sample logins (a NAD + access flow each, plus real logins from MnT), makes the change
as a preview only, and stops for the user's approval. Once the user has applied it, it diffs live ISE
against the baseline (only the previewed change may show), explains the same samples again and reports who
gains or loses access, with the rollback. The prompt itself never confirms a write.
"""

# No `from __future__ import annotations`: FastMCP inspects these signatures at runtime.

import re
from typing import Annotated, Literal

from pydantic import Field

from ise_mcp._core import InvalidRequest, ToolRegistrar, tool_ref

# Prompt arguments are interpolated into instructions, so they are held to strict shapes.
SAFE_POLICY_SET = re.compile(r"^[\w .()-]{1,64}$")
SAFE_RULE = re.compile(r"^[\w .()#:/-]{1,64}$")
SAFE_NAD = re.compile(r"^[\w.:-]{1,128}$")
FLOWS = ("wired-dot1x", "wired-mab", "wireless-dot1x", "wireless-mab")
CHANGES = ("reorder", "edit", "add", "disable")
Change = Literal["reorder", "edit", "add", "disable"]
Section = Literal["authorization", "exception"]
MAX_NADS = 5
EXPORT_SCOPE = '["policy_sets", "authz_profiles"]'

READ_TOOLS = [
    "ise_export_config",
    "ise_diff_config",
    "ise_list_policy_sets",
    "ise_get_policy_set",
    "ise_policy_explain",
    "ise_get_nad",
    "ise_get_auth_list",
    "ise_get_authz_profile",
    "ise_get_dacl",
    "ise_list_conditions",
]
# The change itself (write tier): referenced only when this server exposes them.
WRITE_TOOLS = ("ise_update_policy_rule", "ise_create_authz_rule")
# Rolling back an added rule for good (dangerous tier); disabling it is the write-tier rollback.
DANGEROUS_TOOLS = ("ise_delete_policy_rule",)


def _nads(value: str) -> list[str]:
    items = [n.strip() for n in value.split(",") if n.strip()]
    if not items or len(items) > MAX_NADS or not all(SAFE_NAD.match(n) for n in items):
        raise InvalidRequest(
            f"nads: 1 to {MAX_NADS} NAD names or IPs, comma-separated (letters, digits and . : - _)"
        )
    return list(dict.fromkeys(items))


def _flows(value: str) -> list[str]:
    items = [f.strip().lower() for f in value.split(",") if f.strip()]
    if not items or any(f not in FLOWS for f in items):
        raise InvalidRequest(f"flows: comma-separated, each one of {', '.join(FLOWS)}")
    return list(dict.fromkeys(items))


def _change_call(change: str, ref: str, ps: str, rule: str, section: str, rank: int) -> str:
    """The preview call for the change kind (the user's values fill the placeholders)."""
    sec = f', section="{section}"'
    if change == "reorder":
        return f'{ref} with policy_set="{ps}", rule="{rule}"{sec}, rank={rank}'
    if change == "disable":
        return f'{ref} with policy_set="{ps}", rule="{rule}"{sec}, state="disabled"'
    if change == "add":
        return (
            f'{ref} with policy_set="{ps}", name="{rule}"{sec}, rank={rank}, conditions=<the user\'s\n'
            "   conditions>, profiles=<the user's profiles> (and sgt=<SGT> if they gave one)"
        )
    return (
        f'{ref} with policy_set="{ps}", rule="{rule}"{sec} and only the fields the user asked to change\n'
        "   (conditions, match, profiles, sgt, state or new_name)"
    )


def register(reg: ToolRegistrar) -> None:
    # Registered after the tool modules, so reg.tiers holds the tools this server exposes.
    enabled = {t for t in (*WRITE_TOOLS, *DANGEROUS_TOOLS) if t in reg.tiers}

    def w(name: str) -> str:
        """A write tool's reference when it is enabled, else its name and the GUI fallback."""
        if name in enabled:
            return tool_ref(name)
        tier = "dangerous" if name in DANGEROUS_TOOLS else "write"
        return f"{name} ({tier} tier, not enabled on this server: make the change in the ISE GUI)"

    @reg.prompt(
        title="Review an ISE authorization policy change before it is applied",
        uses=["ise"],
        example={
            "policy_set": "Wired",
            "rule": "Employees",
            "change": "reorder",
            "rank": "0",
            "nads": "syd-acc-sw01",
        },
        tools=[*READ_TOOLS, *(t for t in (*WRITE_TOOLS, *DANGEROUS_TOOLS) if t in enabled)],
    )
    def ise_policy_change_review(
        policy_set: Annotated[
            str,
            Field(description="The network-access policy set the change is in (see ise_list_policy_sets)"),
        ],
        rule: Annotated[
            str,
            Field(
                description="The authorization rule the change touches (for change='add': the new rule's "
                "name)"
            ),
        ],
        nads: Annotated[
            str,
            Field(
                description=f"Up to {MAX_NADS} NADs (names or IPs, comma-separated) whose logins are the "
                "samples, e.g. one switch per location the policy set serves"
            ),
        ],
        change: Annotated[
            Change,
            Field(
                description="reorder (move the rule to `rank`), edit (conditions, profiles, SGT, state or "
                "name, as the user describes), add (a new rule at `rank`) or disable"
            ),
        ] = "edit",
        rank: Annotated[
            int, Field(ge=0, le=999, description="Target position for reorder/add (0 = first)")
        ] = 0,
        section: Annotated[
            Section, Field(description="authorization (normal rules) or exception (local exceptions)")
        ] = "authorization",
        flows: Annotated[
            str,
            Field(
                description="Access flows to sample per NAD, comma-separated: wired-dot1x, wired-mab, "
                "wireless-dot1x, wireless-mab"
            ),
        ] = "wired-dot1x,wired-mab",
        minutes: Annotated[
            int,
            Field(
                ge=15, le=10080, description="MnT window for the real-login samples (MnT keeps up to 7 days)"
            ),
        ] = 1440,
    ) -> str:
        """Review an authorization policy change before it is applied, to catch "this rule now matches
        everyone": ise_export_config as the baseline, ise_policy_explain on sample logins (each NAD with
        each access flow, plus real logins from MnT) before, the change as a preview only (the user
        approves it), then ise_diff_config against the baseline (only the previewed change may show),
        the same samples explained again, and a summary of who gains or loses access with the rollback."""
        ps = policy_set.strip()
        if not SAFE_POLICY_SET.match(ps):
            raise InvalidRequest("policy_set: a policy set name (letters, digits, spaces and . ( ) - _)")
        rule_name = rule.strip()
        if not SAFE_RULE.match(rule_name):
            raise InvalidRequest("rule: a rule name (letters, digits, spaces and . ( ) # : / - _)")
        if change not in CHANGES:  # FastMCP validates the Literal; this guards direct calls
            raise InvalidRequest(f"change must be one of {', '.join(CHANGES)}")
        nad_list = _nads(nads)
        flow_list = _flows(flows)
        if change in ("reorder", "add") and rule_name.lower() == "default":
            raise InvalidRequest("The Default rule can't be moved, and a new rule can't be named Default")

        nad_text = ", ".join(f'"{n}"' for n in nad_list)
        flow_text = ", ".join(f'"{f}"' for f in flow_list)
        samples = len(nad_list) * len(flow_list)
        tool = "ise_create_authz_rule" if change == "add" else "ise_update_policy_rule"
        change_call = _change_call(change, w(tool), ps, rule_name, section, rank)
        writes_on = tool in enabled

        if writes_on:
            write_rule = (
                "Writes: exactly one, the change in step 4, called WITHOUT confirm so it only returns a\n"
                "preview. Show the preview and wait for the user's approval; never pass confirm yourself."
            )
        else:
            write_rule = (
                f"Writes: {tool} is not enabled on this server, so step 4 describes the change for the\n"
                "ISE GUI (Policy > Policy Sets > the set > Authorization Policy) with the exact values; the\n"
                "user makes it."
            )

        r = f'"{rule_name}"'
        if change == "reorder":
            predict = f"""   Moving {r} to rank {rank} puts it ahead of every rule between rank {rank} and its
   rank now (step 1). A sample whose before-match sits in that range and that also meets {r}'s
   conditions moves to {r}: evaluate its conditions against the sample's attributes. Moving it
   down: the samples it matched now reach the rules it passes first."""
        elif change == "disable":
            predict = f"""   Every sample that matched {r} before falls through to the next rule that matches
   (often Default). Name each one and the rule below that it would meet."""
        elif change == "add":
            predict = f"""   The new rule {r} lands at rank {rank} (the preview names the rules it lands
   between). Every sample whose before-match ranks at or below {rank} and that meets the new
   conditions moves to it. Count them: a new rule that would take every sample is the mistake this
   review exists to catch."""
        else:
            predict = f"""   Samples matched by {r} before keep it only if they meet the new conditions;
   samples that reached a lower rule move up to {r} if they now meet them. A new profile or SGT
   changes the result for every sample that stays on the rule."""

        update = w("ise_update_policy_rule")
        rollback_add = (
            f'{update} with policy_set="{ps}", rule={r},\n'
            f'      section="{section}", state="disabled" right away, then\n'
            f"      {w('ise_delete_policy_rule')} once the user agrees."
        )
        rollback_other = (
            f'{update} with policy_set="{ps}", rule={r},\n'
            f'      section="{section}" and the rank, state, conditions, profiles and SGT recorded in\n'
            "      step 1 (a preview again)."
        )
        rollback = rollback_add if change == "add" else rollback_other
        not_yet = " (it does not exist yet: change=add)" if change == "add" else ""

        return f"""Review a change to the ISE policy set "{ps}" ({section} rule "{rule_name}", change:
{change}) before it is applied. The question is who gains or loses access, and whether the rule now
matches far more logins than intended ("this rule now matches everyone").
{write_rule}
ise_policy_explain predicts, it does not ask ISE: an "unknown" condition or an uncertain verdict is
reported as such, never guessed.

1. Baseline. {tool_ref("ise_export_config")} with scope={EXPORT_SCOPE}: keep the whole YAML (step 5
   diffs against it; over the response limit, run it again with path=<a .yaml file> and keep the path).
   {tool_ref("ise_get_policy_set")} with policy_set="{ps}": the {section} rules in rank order with
   conditions, profiles, SGT, state and hits. Record "{rule_name}"'s rank, state, conditions,
   profiles and SGT now: that is the rollback{not_yet}.
   The set's own condition says which logins reach it at all.

2. Samples before ({samples} synthetic, plus real ones).
   a. Synthetic: for each NAD in [{nad_text}] and each flow in [{flow_text}]:
      {tool_ref("ise_policy_explain")} with nad=<NAD>, flow=<flow> (no policy_set, so the set selection
      is checked too). {tool_ref("ise_get_nad")} with device=<NAD> when one does not resolve: drop it
      and say so.
   b. Real: {tool_ref("ise_get_auth_list")} with nad=<NAD>, since_minutes={minutes}, detail=true for each
      NAD: up to 5 distinct passing logins per NAD (different authorization rule, profile or identity
      group). Explain each with {tool_ref("ise_policy_explain")} with nad=<NAD>, flow=<its flow: wired- or
      wireless- with dot1x or mab>,
      attributes=<what the row gives that the rules test: identity group, endpoint profile, EAP type>
      (ad_user=<username> for an AD login). A real login whose prediction differs from the rule MnT
      logged is a sample the evaluator cannot model: keep it, mark it.
   One row per sample: sample | NAD | flow | identity | policy set | rule | profile | SGT | uncertain.
   A sample that lands in another policy set is outside this change: list it once and leave it out.

3. Prediction. From step 1's rules and step 2's traces, before anything changes:
{predict}
   For each profile the change brings in, {tool_ref("ise_get_authz_profile")} with profile=<it> (and
   {tool_ref("ise_get_dacl")} with dacl=<its dACL>): access accept or reject, VLAN, dACL, SGT. A
   condition naming a library condition:
   {tool_ref("ise_list_conditions")} with name=<it> for what it tests.
   Red flags, each named in the report: the changed rule would match every sample, or every sample of a
   flow; its conditions test only the flow or NAS-Port-Type (true for every wired or wireless login);
   it would sit above a DenyAccess or quarantine rule (Session:ANCPolicy) and take its logins; a rule
   below it would never match again (shadowed).

4. The change, as a preview only.
   {change_call}.
   Read the preview: the field diff, the rules it lands between and any blocker. A blocker or a red flag
   from step 3: stop, report, and suggest the narrower rule (an extra condition such as
   'DEVICE:Location starts with ...' or an identity group, or a lower rank). Otherwise show the preview
   and the step 3 prediction together and wait. The user applies it (or not); nothing below runs until
   they say it is applied. Not applied: the report is steps 1-3 and the preview.

5. After it is applied: what changed. {tool_ref("ise_diff_config")} with before=<step 1's YAML or path>,
   after="live", scope={EXPORT_SCOPE}.
   Expected: only "{rule_name}" in "{ps}" (under `moved` for a
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
      "{rule_name}" out of all. Every sample moved there: flag it as "matches everyone" at the top.
   c. Prediction vs result: each sample where step 3 and step 6 disagree, and why.
   d. Rollback: {rollback}
      Logins already on the network keep their old result until they re-authenticate (a CoA from the
      user, not this review)."""

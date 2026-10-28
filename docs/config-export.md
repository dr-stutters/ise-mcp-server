# Config export, diff and import

`ise_export_config` writes ISE policy and objects as YAML. `ise_diff_config` compares two exports, or
an export with live ISE. ISE has no REST API for its configuration change audit, so a saved export is how
you answer "what changed since last week?". It is also the input for a review before a change and for
`ise_import_config` (I43, below).

```text
ise_export_config(path="baseline.yaml")          # save a baseline
... changes in the GUI or through the write tools ...
ise_diff_config(before="baseline.yaml")          # compare with live ISE
ise_diff_config(before="a.yaml", after="b.yaml") # compare two exports
```

## Sections and `scope`

| Section | ISE source | Contents |
|---|---|---|
| `policy_sets` | OpenAPI `/api/v1/policy/{network-access,device-admin}` | Policy sets with their `authentication`, `authorization` and `local_exceptions` rules, plus `global_exceptions`, per kind |
| `conditions` | OpenAPI `/api/v1/policy/{network-access,device-admin}/{condition,time-condition,network-condition}` | Reusable library, time-and-date and network conditions, each as `ise_set_condition` arguments (`kind`, `type`, `name`, `description`, `conditions` + `match` / `time` / `network`); imported after NADs and device groups, before the policy sets that use them |
| `allowed_protocols` | ERS `allowedprotocols` | Allowed-protocols services (the service a policy set selects); exported and diffed, not imported |
| `authz_profiles` | ERS `authorizationprofile` | Authorization profiles |
| `dacls` | ERS `downloadableacl` | Downloadable ACLs |
| `nads` | ERS `networkdevice` | Network devices (secrets masked) |
| `ndgs` | ERS `networkdevicegroup` | Network device groups |
| `identity_groups` | ERS `identitygroup` | User identity groups |
| `endpoint_groups` | ERS `endpointgroup` | Endpoint identity groups |
| `custom_attributes` | OpenAPI `/api/v1/endpoint-custom-attribute` | Endpoint custom attribute definitions |
| `sgts` | ERS `sgt` | Security group tags |
| `sgacls` | ERS `sgacl` | Security group ACLs |
| `egress_matrix` | ERS `egressmatrixcell` | TrustSec egress matrix cells |
| `command_sets` | ERS `tacacscommandsets` | TACACS+ command sets |
| `shell_profiles` | ERS `tacacsprofile` | TACACS+ shell profiles |

`scope` takes section names or these groups: `policy` (policy_sets, conditions, allowed_protocols, authz_profiles, dacls), `network` (nads,
ndgs), `groups` (identity_groups, endpoint_groups), `trustsec` (sgts, sgacls, egress_matrix) and
`device_admin` (command_sets, shell_profiles). The default is every section. Internal users, endpoints and
certificates are not exported.

## Format (version 1)

```yaml
ise_export:
  format: 1                      # bumped on any incompatible change to the shape below
  ise_version: 3.5.0.527
  hostname: ise-pan              # the Primary Admin node
  exported_at: '2026-10-17T05:52:24Z'
  server_version: 0.11.0         # ise-mcp-server that wrote it
  sections: [policy_sets, nads]  # what this export contains (diff compares only sections in both)
  counts: {policy_sets: 2, nads: 1}
  digest: sha256:...             # of everything below the header
  incomplete: {nads: first 5000 of 12000 (max_objects)}   # only when a section hit max_objects
  skipped: {policy_sets.device-admin: ...}                # only when a section could not be read
policy_sets:
  network-access:
    sets:
    - name: Wired
      rank: 0
      state: enabled
      condition:
        and:
        - DEVICE:Location equals All Locations#Branch
        - Wired_MAB
      isProxy: false
      serviceName: Default Network Access
      authentication:
      - name: MAB
        rank: 0
        state: enabled
        condition: Wired_MAB
        identitySourceName: Internal Endpoints
        ifAuthFail: REJECT
        ifProcessFail: DROP
        ifUserNotFound: CONTINUE
      authorization:
      - name: Printers
        rank: 0
        state: enabled
        condition: IdentityGroup:Name equals Endpoint Identity Groups:Printers
        profile: [Printer-Access]
        securityGroup: Printers
      - name: Default
        rank: 1
        state: enabled
        default: true
        profile: [DenyAccess]
    global_exceptions: [...]
  device-admin:
    sets: [...]                  # authorization rules carry `commands` and `profile` (shell profile)
nads:
- name: branch-sw1
  NetworkDeviceGroupList: [Device Type#All Device Types, Location#All Locations#Branch]
  NetworkDeviceIPList:
  - {ipaddress: 192.0.2.10, mask: 32}
  authenticationSettings:
    networkProtocol: RADIUS
    radiusSharedSecret: '********'
egress_matrix:
- source: ANY
  destination: ANY
  defaultRule: PERMIT_IP
  matrixCellStatus: ENABLED
  sgacls: [Permit IP]
```

Rules for every section:

- **ISE's own field names.** Objects keep the field names of the API they come from (ERS or OpenAPI), so
  an importer can send them back. Exceptions: policy rules are one flat mapping (the OpenAPI `rule` object's
  fields merged with its result fields: `profile`, `securityGroup`, `commands`, `identitySourceName`, the
  `if*` actions), and the changes listed below.
- **Names, not ids.** Every `id` is dropped. References are names: rule results (profiles, SGT, command
  sets, shell profile) and `daclName` already are; egress cells use `source` / `destination` SGT names and
  SGACL names (in ISE's order: it applies them in order); endpoint groups have `parent` (the parent's name)
  instead of `parentId`. The default egress cell is `ANY` -> `ANY`. A reference the export can't resolve is
  left as the raw id.
- **Conditions** use the strings the policy write tools accept: a library condition name (`Wired_MAB`) or
  `Dictionary:Attribute operator value`, with a `NOT ` prefix when negated. Blocks are `{and: [...]}` or
  `{or: [...]}`, a negated block `{not: {and: [...]}}`. A default rule or set has `default: true` and no
  condition.
- **Lines as lists.** dACL text (`dacl`) and SGACL text (`aclcontent`) are lists of ACE lines.
- **Left out:** ids, `link`s, `hitCounts`, `generationId`, `matrixId`, created/modified timestamps, and
  empty values (null, `""`, `[]`, `{}`). A missing field means empty.
- **Secrets are masked** as `'********'` with the server's usual rules (RADIUS and TACACS+ shared secrets,
  KeyWrap keys, SNMP communities, TrustSec device passwords). An unset secret is left out, so "set" and
  "not set" are still visible. Secrets never leave ISE through an export, so an importer takes them
  separately.

### Ordering and stability

Rules are listed by rank (evaluation order), and so are policy sets. Everything else is sorted by name
(case-insensitive). The order of a list ISE treats as a set (a NAD's IPs and device groups) is sorted;
lists where order matters (ACE lines, SGACLs in a cell, commands, advanced attributes) keep ISE's order. Keys
in every mapping are `name` (or `source`, `destination`), `rank`, `state`, `default`, `description`,
`condition` first, then the rest alphabetically, with the rule tables last.

Two exports of an unchanged ISE differ only in `exported_at`, and `digest` is identical. Parsing an export
and writing it back gives the same bytes.

## Files and `ISE_EXPORT_DIR`

Without `path`, the YAML is returned in the response (up to `MCP_MAX_RESPONSE_CHARS`; a larger export asks
for `path` or a narrower `scope` rather than being cut short). With `path`, the server writes the file and
returns its path, size, counts and digest.

- With `ISE_EXPORT_DIR` set, paths are relative to it and must stay inside it. **Set it on a shared host**:
  without it, a caller can write a `.yaml` file anywhere the server's user can.
- Without it, `path` must be absolute.
- The file must end in `.yaml` or `.yml`, its directory must exist, and an existing file is only
  overwritten when it is an earlier export.
- `ise_diff_config` reads `before` / `after` from the same places, or takes the YAML text itself.

## Diff output

```json
{
  "before": {"hostname": "ise-pan", "exported_at": "...", "digest": "sha256:..."},
  "after": {"hostname": "ise-pan", "exported_at": "...", "digest": "sha256:..."},
  "unchanged": false,
  "summary": {"added": 1, "removed": 0, "moved": 1, "changed": 1},
  "sections_compared": ["policy_sets", "sgts"],
  "sections": {
    "policy_rules": {
      "moved": {"network-access/Wired/authorization/Printers": {"from": 3, "to": 0}},
      "changed": {
        "network-access/Wired/authorization/Cameras": {
          "state": {"from": "enabled", "to": "monitor"},
          "profile": {"added": ["DenyAccess"], "removed": ["PermitAccess"]}
        }
      }
    },
    "sgts": {"added": ["Cameras"]}
  }
}
```

- Objects match by name (egress cells by `source -> destination`, custom attributes by `attributeName`).
  Policy sets are `kind/set`, and rules are `kind/set/table/rule` (`table` is `authentication`,
  `authorization`, `local_exceptions` or `global_exceptions`).
- `changed` lists field-level changes with dotted paths for nested fields (`authenticationSettings.coaPort`).
  A condition is compared as a whole. Lists of plain values report the `added` / `removed` items (or
  `reordered`). Other lists report `from` / `to`.
- A rule (or policy set) whose position relative to the others changed is listed under `moved` with its old
  and new rank. Rules that only shift because one was added or removed above them are not reported, and a
  rank is never reported as a field change.
- Only sections in both exports are compared (`not_compared` names the rest). A partial or skipped section
  in either export is listed under `notes`.
- Masked secrets compare equal, so a changed shared secret does not show up.
- `max_changes` (default 200) caps the differences listed. `truncated` says when the cap applied.
- `after="live"` exports the sections of `before` (narrowed by `scope`) from ISE first.

## Large deployments

ERS lists return only ids and names, so the export GETs every object: one request per NAD, profile, group
and so on, at `ISE_DETAIL_CONCURRENCY` requests at a time under `ISE_RATE_LIMIT` / `ISE_MAX_CONCURRENCY`.
Sections run one after another. A section stops at `max_objects` (default 5000) and the header says so under
`incomplete`. With thousands of NADs, export `nads` on its own (`scope=["nads"]`, `path=...`), or leave it out
of the routine baseline.

## Import (`ise_import_config`)

`ise_import_config(source, scope, only, secrets, prune)` applies an export to the ISE the server points at:
the same ISE (restore a baseline), another one (move a PoC policy to production), or a lab being rebuilt. It
is a **dangerous-tier** tool (`MCP_ENABLE_DANGEROUS`) and preview-first like every write. The preview is the
whole plan, and the confirm applies it.

```text
ise_import_config(source="poc.yaml", only=["Branch-*"], secrets={"branch-sw1": {"radius": "..."}})
  -> preview: summary (create / update / delete / unchanged), every step with its field changes
ise_import_config(..., confirm="pv_...")       # applies the steps in order
ise_diff_config(before="poc.yaml")             # empty, for the imported objects
```

### What the plan does

- **Matched by name**, the same keys as the diff. Rules match by policy set, table and rule name.
- **One step per object that differs:** `create` when the target lacks it, `update` when a field differs,
  `delete` only with `prune=true`. Objects that are already the same count as `unchanged`.
- **Dependency order:** NDGs (parents first), identity and endpoint groups (parents first), custom
  attributes, SGTs, SGACLs, egress cells, dACLs, authorization profiles, command sets, shell profiles, NADs,
  then policy sets and their rules in rank order. Deletes run last, in reverse order: rules before their
  set, a NAD before its device group, a profile before its dACL.
- **References are resolved when each step runs**, so a step can use an object an earlier step created: egress
  cell SGTs and SGACLs, endpoint group parents and policy set ids. Rule results (profiles, SGT, command sets,
  shell profile) and `daclName` are names in ISE's API anyway.
- **Fields:**
  - For objects and policy sets, the export is authoritative for the fields it gives. A field the export
    leaves out keeps the target's value, so a hand-written file doesn't have to spell out ISE's defaults. An
    update sends the current object with the export's fields merged over it.
  - A condition is always replaced as a whole.
  - Rules are authoritative: a rule exported without a `securityGroup` loses its SGT on the target.
  - Because an export leaves out empty values, clearing a field (an object's description, say) doesn't carry
    over. `ise_diff_config` still shows it.
- **Policy sets:**
  - A new policy set gets ISE's Default rules, and their results are set from the export.
  - The Default policy set and Default rules are only ever updated, never created or deleted.
- **Secrets:** exports mask them, so NAD secrets come in `secrets`, by NAD name:
  `{"sw1": {"radius": "...", "tacacs": "...", "snmp_ro": "..."}}`. Other keys are `radius_second`,
  `key_encryption_key`, `message_authenticator_key`, or any dotted field path. An existing NAD keeps its secrets
  unless new ones are given (they are compared with the current ones first). A new NAD needs every secret its
  export shows as set, or the plan is blocked. Secrets never appear in the preview or the audit log.

### Blockers (nothing is applied)

- A new NAD without its secrets; `secrets` naming a NAD that is not in the import.
- A condition that doesn't parse, an attribute the target's dictionaries don't have, or a value outside the
  attribute's allowed values (same checks as `ise_create_authz_rule`).
- A rule result naming an authorization profile, SGT, command set or shell profile that is neither on the
  target nor created by this import.
- A custom attribute whose type differs (ISE can't change it); a policy kind the target can't read (device
  admin off); `prune` with a partial export (it would delete what the export missed).
- Nothing to do (the target already matches).

Things the import does not create must already exist on the target: library conditions, identity sources and
sequences, allowed-protocols services, AD join points and their groups, portals.

### `only` and `prune`

- `only` takes name globs (case-insensitive) and limits the import to matching objects:
  - rules match by their own name or their policy set's;
  - egress cells match by either SGT;
  - device groups match by the full path or the last segment.
- `prune=true` deletes target objects in the imported sections, within `only`, that the export lacks. Default
  policy sets, Default rules and the ANY -> ANY cell are never deleted.
- Use both together for a scoped mirror, e.g. `only=["Branch-*"], prune=true`. To remove a set of objects,
  import an export that has the sections but none of the objects.

### Applying

- Steps run one at a time, and the import stops at the first failure.
- The error names the failed step and ISE's reason, lists what was applied before it, and counts the steps
  not attempted. Nothing is rolled back. Fix the cause and run the import again: it plans from the target's
  new state, so steps already done show as unchanged.
- The confirm token is tied to the planned steps and their field changes. If any of those objects change after
  the preview, the confirm is refused; preview again.
- The core safety rails apply as for every write:
  - `MCP_CHANGE_WINDOW`: a confirm outside the window is refused.
  - `MCP_MAX_BLAST_RADIUS` / `MCP_BLAST_RADIUS_OVERRIDES`: the blast radius is the number of steps.
  - `MCP_TWO_PERSON_TOOLS` (e.g. `@dangerous` or `ise_import_config`).
  - `MCP_DRY_RUN`.
- Policy changes take effect at the next authentication; no CoA is sent.
- TrustSec settings on the target still apply. For example, with multiple SGACLs per cell turned off, ISE
  refuses a cell with an SGACL plus a catch-all other than `NONE`.

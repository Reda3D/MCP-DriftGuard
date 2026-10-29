# Policy reference

A policy is a YAML file that turns observed changes into severities and
decisions. It is the only component allowed to decide that something matters.

- **Format:** YAML, UTF-8
- **Current version:** `1`
- **Size limit:** 4 MiB, 1 000 rules, 5 000 waivers

---

## Shape

```yaml
version: 1
fail_on: HIGH

defaults:
  schema_property_added: LOW

rules:
  - id: DG002
    description: A tool gained destructive capability
    severity: CRITICAL
    action: block
    rationale: Deletion is never a silent upgrade.
    match:
      change: [capability_escalated, capability_added]
      capability: destructive

waivers:
  - rule_id: DG005
    tool: "legacy_*"
    reason: Tracked in SEC-1234
    approved_by: security-team
    expires: 2027-01-01
```

| Key | Required | Meaning |
|---|---|---|
| `version` | no (default `1`) | Policy format version |
| `fail_on` | no (default `HIGH`) | Minimum severity that fails the run |
| `defaults` | no | Per-change-type severity override, used when no rule matches |
| `rules` | no | Ordered list of rules |
| `waivers` | no | Time-boxed, attributed exceptions |

Any other top-level key is **fatal**. A misspelled section header must not turn
into a policy with fewer rules.

---

## Rules

| Field | Required | Meaning |
|---|---|---|
| `id` | **yes** | Unique, alphanumeric plus `-`/`_`. Appears in reports and SARIF |
| `description` | **yes** | One line, shown to the reviewer |
| `severity` | **yes** | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` (case-insensitive) |
| `action` | no (default `warn`) | `warn` or `block` |
| `rationale` | no | Free text for auditors |
| `match` | **yes** | What the rule applies to |

### `match`

| Key | Required | Meaning |
|---|---|---|
| `change` | **yes** | One change type, or a list (OR) |
| `tool` | no (default `*`) | Glob or list of globs on the tool name (OR) |
| `path` | no (default `*`) | Glob or list of globs on the JSON pointer (OR) |
| `capability` | no (default `*`) | Glob or list of globs on the capability name (OR) |

All present keys must match (AND). Globs are `fnmatch`-style, **case-sensitive**,
and are never compiled as regular expressions.

A rule with `capability:` only matches changes that carry a capability, i.e.
`capability_*`. It will not match `tool_added`, even for a tool that has that
capability — that is what `capability_added` findings are for.

### Change types

| Change | Emitted when |
|---|---|
| `tool_added` | A tool exists in the candidate but not the baseline |
| `tool_removed` | A tool exists in the baseline but not the candidate |
| `tool_name_collision` | Two distinct names fold to the same visible string |
| `description_changed` | Description differs after whitespace normalisation |
| `suspicious_description` | A heuristic pattern fired (see below) |
| `schema_property_added` | New accepted input parameter |
| `schema_property_removed` | Parameter no longer accepted |
| `schema_type_changed` | `type` replaced rather than widened or narrowed |
| `schema_required_added` | A parameter became mandatory |
| `schema_required_removed` | A parameter became optional |
| `schema_constraint_loosened` | A bound, enum, pattern or format widened or removed |
| `schema_constraint_tightened` | A bound, enum or format narrowed |
| `schema_constraint_changed` | Changed in a direction the analyser will not rank |
| `schema_additional_properties_enabled` | Unknown properties are now accepted |
| `capability_escalated` | A declared capability became more dangerous |
| `capability_reduced` | A declared capability became less dangerous |
| `capability_added` | A capability appears that was not declared before |
| `capability_removed` | A capability disappeared |

### Heuristic codes

Emitted as `suspicious_description` with the code in `path`.

| Code | Signal |
|---|---|
| `DG-H001` | Instruction-override phrasing ("ignore previous instructions") |
| `DG-H002` | Instruction to conceal actions from the user |
| `DG-H003` | Reference to the system prompt |
| `DG-H004` | Embedded URL |
| `DG-H005` | Reference to credentials or secrets |
| `DG-H006` | Instruction to act without confirmation |
| `DG-H007` | Long base64-like blob |
| `DG-H010` | Invisible or bidirectional control character |

These are patterns, not a model. They are documented so a finding can be
disputed. They are non-blocking in the shipped policy.

---

## Evaluation

For each change:

1. Collect every rule whose `match` applies, in file order.
2. Remove rules covered by an active waiver.
3. If at least one rule remains: severity is the **highest** of them; action is
   `block` if **any** of them blocks. The reported `rule_id` is the rule with the
   highest severity (first one in file order on a tie).
4. If every matching rule was waived: the finding is `INFO` and marked waived.
5. If no rule matched: the severity comes from `defaults`, then from the built-in
   table, and the finding is attributed to `DG-DEFAULT`.

The built-in table is complete for every change type. A unit test asserts it
stays that way — a change type without a default would be a silent blind spot.

### Failure

The run fails when **either**:

- a non-waived finding has severity ≥ `fail_on`, **or**
- a non-waived finding came from a rule with `action: block`.

`block` therefore bypasses the threshold: it fails even if `fail_on` is
`CRITICAL` and the rule's severity is `INFO`.

---

## Waivers

| Field | Required | Meaning |
|---|---|---|
| `rule_id` | **yes** | Must reference an existing, non-blocking rule |
| `tool` | no (default `*`) | Glob on the tool name |
| `reason` | **yes** | Why the exception exists |
| `approved_by` | **yes** | Who accepted it |
| `expires` | **yes** | ISO date. After this date the waiver stops applying |

Rules:

- A waiver on a **blocking rule is rejected at load time.** If you need the
  exception, change the policy — in a commit, under review.
- A waiver on a non-existent rule is rejected: it would do nothing, silently.
- Expired waivers stop applying and are listed in the report and the JSON under
  `expired_waivers`, so they are visible rather than merely inert.
- Expiry is evaluated against `--as-of` (default: today). This is the only
  time-dependent input in the system, which is why it is explicit.

---

## Built-in default severities

Used when no rule matches.

| Severity | Change types |
|---|---|
| `CRITICAL` | *(none by default)* |
| `HIGH` | `capability_escalated`, `capability_added`, `schema_constraint_loosened`, `schema_additional_properties_enabled`, `tool_name_collision` |
| `MEDIUM` | `tool_added`, `suspicious_description`, `schema_property_added`, `schema_type_changed`, `schema_required_removed`, `schema_constraint_changed` |
| `LOW` | `tool_removed`, `description_changed`, `schema_property_removed`, `schema_required_added`, `capability_removed` |
| `INFO` | `schema_constraint_tightened`, `capability_reduced` |

Override with `defaults:` only when you have a reason; the shipped
`driftguard init` template starts from these and adds explicit rules for the
cases that deserve `block`.

---

## Writing a good policy

- **Block few things, block them hard.** Every blocking rule is a merge blocker.
  Reserve it for irreversible risk: delete, execute, secrets.
- **Never waive silently.** A waiver is a decision with an owner and a date.
- **Keep the policy in the repository it governs.** A policy stored elsewhere
  drifts from the code it protects.
- **Review policy changes like code.** A one-line change can disable every
  control in the file, which is why unknown keys are fatal.

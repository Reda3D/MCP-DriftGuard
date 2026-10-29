# Design notes and specification review

This document records the design of MCP DriftGuard and, more importantly, the
problems found in the initial specification before any code was written. A
security tool that skips this step tends to reproduce the weaknesses it claims
to detect.

---

## 1. Language choice: Python, not Rust

The specification left the choice open. Python was selected for four reasons,
in order of weight:

1. **Auditability beats throughput.** DriftGuard processes a few hundred tools
   per run. Runtime is measured in milliseconds either way. What matters is
   that a security reviewer can read the policy engine end to end and convince
   themselves it has no bypass. That takes an hour in Python and a day in Rust.
2. **The threat is not resource exhaustion of the analyser**, it is a wrong
   answer. Optimisation effort belongs in correctness tests, not in the runtime.
3. **Contribution surface.** Policy formats evolve. A readable reference
   implementation lowers the cost of a correct contribution.
4. **Distribution is already solved** for the actual deployment target: the
   GitHub Action installs from source, and `pip install mcp-driftguard` covers
   local use. A single static binary would be nicer, but it is not worth the
   implementation cost at this stage.

The decision is revisited if DriftGuard ever needs to run on tens of thousands
of snapshots per hour, which is not the shape of the problem.

---

## 2. Weaknesses in the specification, and how each was resolved

The table below is the audit. "Spec" is what the initial document said; "Risk"
is what a literal implementation would have produced; "Resolution" is what the
code does.

| # | Spec | Risk | Resolution |
|---|---|---|---|
| 1 | "Policy configuration: YAML" | YAML anchors allow billion-laughs expansion; duplicate keys let two parsers disagree about which value wins — a policy-bypass primitive | `SafeLoader` subclass that **rejects aliases** and **rejects duplicate keys** before construction |
| 2 | "Policies should support severity levels" | No validation contract. A typo in `change: tool_adde` silently disables a control and the build goes green | Strict schema: unknown keys, unknown change types, unknown capabilities are **fatal** (exit `3`) |
| 3 | "Fail closed when a required policy check cannot be completed" | Undefined behaviour. In practice "fail closed" is implemented as "log a warning" | A documented exit-code contract, and every parse/evaluation failure maps to `3` |
| 4 | "Produce reproducible results" | No mechanism. Dict ordering, locale collation and whitespace differences make reports non-reproducible, so reviewers learn to ignore diffs | Total sort order, canonical JSON, NFC normalisation, and a CI job that compares two runs **byte for byte** |
| 5 | "Detect modified tool definitions, changes to input parameters" | Direction is lost: a schema that got *stricter* is reported the same as one that got *looser*, which buries the real signal | Every schema change is classified `loosened` / `tightened` / `changed` |
| 6 | No mention of duplicate tool names | A server declaring the same tool twice can make the client resolve the malicious definition while a naive diff sees one | **Fatal error** at load time |
| 7 | No mention of visually identical names | `create_issue` and `сreate_issue` (Cyrillic es) are two tools to the parser and one to the reviewer. The reviewer approves the benign one | `tool_name_collision`, detected by compatibility and confusable folding |
| 8 | "Newly added tools" as a single change type | **The most dangerous case was invisible**: a brand-new tool with `destructive: true` and `filesystem: delete` produced only a MEDIUM "new tool" finding | Added tools emit explicit `capability_added` findings for dangerous capabilities |
| 9 | "Inspect connector snapshots" (no mention of `$ref`) | A schema containing `$ref: http://169.254.169.254/...` turns a passive analyser into an SSRF primitive inside CI | Non-local `$ref` values are **rejected**; DriftGuard never resolves references |
| 10 | "Policies should support… configured policies" (no matching language specified) | The obvious implementation compiles a user pattern with `re`, giving any policy author a ReDoS against CI | Matching uses `fnmatch` **globs only**. User input never reaches the regex engine |
| 11 | "AI must never be allowed to override a deterministic policy violation" | Stated as a rule, not enforced by structure. Rules stated only in prose erode | Enforced structurally: the policy engine has **no model dependency and no I/O**, and `block` rules are **non-waivable by construction** |
| 12 | "Waivers"/"explicit approval" implied but unspecified | Exceptions become permanent, unowned and unaudited | A waiver requires `reason`, `approved_by` and `expires`. Expired waivers stop applying and are listed in the report |
| 13 | "GitHub Action… must not expose repository secrets to untrusted code" | The standard way this goes wrong is `pull_request_target` plus a checkout of the PR head | Composite action, no `pull_request_target`, inputs passed via `env` (never interpolated into the script), `persist-credentials: false` in every example |
| 14 | "Publish a readable report" | Reports are rendered from untrusted strings. A tool description containing `</details>` or `|` reshapes the review artefact | Every snapshot-derived string is HTML- and table-escaped before rendering |
| 15 | "Code Scanning-compatible output **may** be added if it can be implemented and validated correctly" | Open-ended; usually ships broken | SARIF 2.1.0 with stable fingerprints, validated by a strict-JSON test |
| 16 | No resource limits | A 2 GB snapshot or a 10 000-deep schema is an OOM kill in CI | Bounded file size, tool count, schema depth, description length, rule and waiver counts |
| 17 | "Handle malformed data safely" | Unhandled exceptions surface as tracebacks and exit `1`, which CI reads as "policy violation" | Typed errors with distinct exit codes; unexpected exceptions exit `3`, never `1` |
| 18 | "Versioned JSON format for connector snapshots" but no version on policies | Format drift breaks silently | `schema_version` on snapshots, `version` on policies; both mismatch cases are fatal |

### Two findings worth calling out

**Finding 8 was found by running the tool, not by reading the spec.** The first
end-to-end run against the example snapshots reported `delete_file` — a new tool
that deletes files — as a MEDIUM `tool_added`. The example policy had a CRITICAL
blocking rule for `filesystem: delete`, but a newly added tool never emits a
capability change, so the rule could not fire. A new tool is an escalation from
"nothing existed", and the engine now models it that way.

**Finding 7 is why `tool_name_collision` exists at all.** Exact duplicates are
easy. The interesting case is two names that are different byte strings and the
same picture on screen, which is precisely the asymmetry between a parser and a
human reviewer.

---

## 3. Architecture

```
                    ┌──────────────┐
  baseline.json ───►│  snapshot.py │  validate, bound, canonicalise, hash
  candidate.json ──►│              │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │   diff.py    │  facts only: added / removed / modified,
                    │ schema_diff  │  loosened / tightened / escalated
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
  driftguard.yml ──►│  policy.py   │  severity, action, waivers — pure function
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │   report/    │  markdown | json | sarif
                    └──────────────┘
```

### Why facts and judgements are separate

If the diff engine assigned severities, the policy file would be decoration, and
every new detection would require a code change. If the policy engine computed
diffs, policies would need to understand JSON Schema. Keeping them apart means:

- a change can be added to the vocabulary without touching policy semantics;
- a policy can be re-tuned without touching the analyser;
- the report can state *what changed* and *why it matters* independently, which
  is exactly what a reviewer needs.

### Why the policy engine has no I/O

The specification says AI must not override a deterministic violation. The
strongest way to guarantee that is to make it structurally impossible: the
policy engine imports nothing that can reach a model, a network or a clock. The
evaluation date is injected, not read from the system.

### Determinism

Three sources of non-determinism were removed:

| Source | Remedy |
|---|---|
| Dict/set iteration order | Explicit total sort keys everywhere |
| Unicode representation | NFC normalisation at load |
| Wall-clock time | `--as-of` injected; the only time-dependent input is waiver expiry |

The result is verified by a CI job that runs the same check twice and `cmp`s the
Markdown, JSON and SARIF outputs.

---

## 4. Decisions that were deliberately not taken

| Temptation | Why not |
|---|---|
| Execute the MCP server to observe real behaviour | Turns a passive analyser into an execution primitive. The spec forbids it; the code has no code path that could. Deferred to Phase 5 behind isolation, and only after the static engine is trusted |
| Detect renamed tools by similarity scoring | Produces false positives that train reviewers to ignore alerts. A rename is reported as remove + add, which is honest and reviewable |
| Let an LLM triage findings into "probably fine" | Destroys reproducibility and hands an attacker a prompt-injection surface inside the security control |
| Auto-generate the policy from observed behaviour | A control derived from the thing it is meant to constrain is not a control |
| Use regex in policy matching | Convenient, and a ReDoS vector. Globs cover the real use cases |
| Store waivers in a database | Exceptions must live in version control, next to the code they exempt |

---

## 5. Known limitations

Stated plainly, because a security tool that overstates its coverage is worse
than one with a narrow, honest scope.

1. **The snapshot is trusted to be complete.** DriftGuard compares declarations.
   A server that behaves differently from what it declares is out of scope for
   static analysis.
2. **JSON Schema support is a practical subset.** `type`, `properties`,
   `required`, `additionalProperties`, `enum`, `const`, `items`, numeric and
   length bounds, `pattern`, `format`, `$ref` (compared, never resolved) and the
   `anyOf`/`oneOf`/`allOf` combinators. Exotic keywords are compared only as
   opaque values.
3. **Confusable folding is a short, documented table**, not the full Unicode
   confusables data. It catches the cheap attacks and will miss a determined
   one.
4. **Heuristics are pattern matches.** They are listed in
   `heuristics.py`, they are non-blocking by default, and they will produce
   false positives on legitimate documentation that quotes an attack.
5. **No semantic equivalence.** Reordering properties, or expressing the same
   constraint two different ways, is reported as a change.
6. **Single-snapshot comparison.** There is no history, no trend and no notion
   of "this changed three releases ago".

---

## 6. Roadmap, honestly scoped

| Phase | Content | State |
|---|---|---|
| 1 | Snapshot format, diff engine, policy engine, reports, tests | **Done** |
| 2 | GitHub Action and PR integration | **Done** (composite action, CI in this repo) |
| 3 | Agent Skill that explains findings | Not started |
| 4 | Read-only MCP server exposing findings | Not started |
| 5 | Isolated dynamic validation | Not started, and gated on phase 1 proving itself in real use |

Phases 3 and 4 are additive by design: they consume the JSON report. Neither can
change a verdict, because the verdict is produced before they are involved.

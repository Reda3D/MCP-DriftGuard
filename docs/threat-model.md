# Threat model

A security tool is part of the attack surface it is meant to reduce. This
document states what DriftGuard protects, against whom, and — just as
importantly — what it does not protect against.

---

## Assets

| Asset | Why it matters |
|---|---|
| The verdict | A false "pass" is worse than no check at all: it launders a risky change through review |
| The report | It is read by a human who will act on it; a report that can be reshaped is a social-engineering primitive |
| CI credentials | The analyser runs inside CI, next to secrets and a repository token |
| The policy | Whoever can change it silently can disable every control |
| The baseline | It is the definition of "trusted" |

## Actors

| Actor | Capability |
|---|---|
| A malicious MCP server author | Controls snapshot contents: names, descriptions, schemas, capabilities |
| A malicious policy contributor | Can open a PR that edits the policy file |
| A compromised dependency | Runs inside the analyser process |
| An opportunistic attacker | Scans for CI misconfiguration |

Note that the first actor controls the *data*, not the code. Almost every
mitigation below follows from that single fact.

---

## Threats and mitigations

### T1 — Shadowing through duplicate names

**Attack.** Declare the same tool twice, benign first, malicious second, hoping
the client resolves the one the reviewer did not read.

**Mitigation.** Duplicate names are a fatal load error. There is no "last one
wins" behaviour to exploit.

### T2 — Shadowing through lookalike names

**Attack.** `create_issue` versus `сreate_issue` (Cyrillic es). Different bytes,
identical pixels.

**Mitigation.** Compatibility and confusable folding produces a
`tool_name_collision` finding. This is a detector, not a proof: the fold table is
short and documented, and a determined attacker using an unlisted confusable will
get through. The finding exists so the reviewer has a chance.

### T3 — Policy bypass through a malformed policy

**Attack.** Introduce a typo (`change: tool_adde`) or a duplicate key so the
control silently stops applying, while the diff looks trivial.

**Mitigation.** Unknown change types, unknown keys, duplicate YAML keys and
duplicate rule ids are all fatal (exit `3`). A policy that cannot be fully
understood is never partially applied.

### T4 — Resource exhaustion of the analyser

**Attack.** A 2 GB snapshot, a 10 000-level schema, or a YAML anchor bomb.

**Mitigation.** Bounded file size (32 MiB), tool count (10 000), nesting depth
(32), description length, rule count and waiver count. YAML aliases are rejected
outright, which removes the exponential-expansion family.

### T5 — ReDoS through a policy pattern

**Attack.** A rule whose `tool:` pattern is `(a+)+$`, matched against a
carefully crafted name, hangs the CI job.

**Mitigation.** Matching uses `fnmatch` globs. User input never reaches the
regular-expression engine.

### T6 — SSRF through schema references

**Attack.** A schema property containing
`$ref: http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
hoping the analyser resolves it inside the runner's network.

**Mitigation.** Every `$ref` that does not start with `#` is rejected at load
time. DriftGuard never resolves references and has no HTTP client in its
dependency tree.

### T7 — Report injection

**Attack.** A tool description containing `</details>`, `|`, a backtick or an
HTML tag, so the rendered report misrepresents the findings a reviewer reads.

**Mitigation.** Every snapshot-derived string is HTML-escaped and table-escaped
before rendering; backticks are converted to entities so they cannot open a code
span. The report is inert in CommonMark and in renderers that do not honour code
spans.

### T8 — Secret exposure in CI

**Attack.** The workflow runs with a token and secrets in the environment, and a
step ends up printing or transmitting them.

**Mitigation.** The analyser never reads environment variables other than
`GITHUB_STEP_SUMMARY`, `GITHUB_OUTPUT` and `DRIFTGUARD_DEBUG`. It makes no network
call. Logs contain paths, tool names and schema fragments — never process
environment. The action passes inputs through `env:` rather than shell
interpolation, so an input value cannot become shell syntax.

### T9 — Privileged execution of PR code

**Attack.** `pull_request_target` plus a checkout of the PR head: the workflow
runs attacker code with write permissions and secrets.

**Mitigation.** The documented pattern is the plain `pull_request` trigger with
`persist-credentials: false`. DriftGuard never executes anything from the
snapshot: it is a data file, parsed and compared, nothing more.

### T10 — Waiver laundering

**Attack.** Add a permanent waiver, or one with no owner, so a risky change is
permanently exempt.

**Mitigation.** A waiver requires `reason`, `approved_by` and `expires`, is
version-controlled, cannot cover a blocking rule, and is listed in the report
once expired.

### T11 — Verdict manipulation through prompt injection

**Attack.** Put instructions in a tool description hoping that an LLM somewhere
in the pipeline downgrades the finding.

**Mitigation.** There is no LLM in the pipeline. The verdict is a pure function of
the diff and the policy. Instructions in a description are data; the heuristics
may flag them, and nothing else reads them.

### T12 — Silent schema version drift

**Attack.** Ship a snapshot with `schema_version: "2"` that a lenient parser
would read using version-1 semantics, misinterpreting fields.

**Mitigation.** Version mismatch is fatal. Unknown versions are refused rather
than guessed at.

---

## Out of scope

Stated explicitly, because a threat model that claims everything protects
nothing:

- **A lying server.** DriftGuard compares declarations. A server that behaves
  differently from what it declares is invisible to static analysis.
- **Compromised dependencies.** PyYAML is the only runtime dependency; it is
  pinned to a major version and should be tracked by Dependabot, but DriftGuard
  does not sandbox it.
- **Compromised runner.** If the machine is owned, the verdict is owned.
- **Semantic equivalence.** A change that preserves meaning but alters syntax is
  reported as a change. That is a false positive, not a vulnerability.
- **Availability of the upstream provider.** If the server disappears, that is a
  supply-chain problem outside this tool's scope.

---

## Residual risk

After all mitigations, the two that remain material:

1. **A reviewer who approves without reading.** The report is designed to make
   the important line impossible to miss — severity, tool, change, blocking
   marker — but it cannot make someone read it.
2. **A policy that is technically valid and substantively wrong.** Fatal errors
   catch typos; they cannot catch a deliberate `severity: INFO` on a rule that
   should block. That is what code review of the policy file is for, which is why
   the policy lives next to the code it governs.

---

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).

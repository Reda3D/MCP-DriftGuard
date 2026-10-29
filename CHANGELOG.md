# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-10-29

First functional release. The static-analysis engine, policy engine, reports,
CLI and GitHub Action are implemented and tested. The Agent Skill and the
read-only MCP server are **not** part of this release.

### Added

- **Snapshot format v1** — versioned JSON describing a server's tools, input
  schemas and capabilities, with canonical SHA-256 hashing.
- **Deterministic diff engine** — detects added, removed and modified tools,
  and classifies every schema change as loosened, tightened or changed.
- **Capability model** — `read_only`, `destructive`, `network_access`,
  `filesystem` (ordinal), `executes_commands`, `accesses_secrets`, each with a
  defined risky direction.
- **Policy engine** — YAML rules with glob matching, five severity levels, a
  `block` action that bypasses the threshold, and per-change-type defaults.
- **Time-boxed waivers** — requiring a reason, an approver and an expiry date;
  blocking rules are non-waivable by construction.
- **Reports** — Markdown for humans, JSON for machines, SARIF 2.1.0 for GitHub
  code scanning, with stable fingerprints.
- **CLI** — `check`, `validate`, `hash`, `init`, `version`, with a documented
  exit-code contract (`0` / `1` / `2` / `3`).
- **GitHub Action** — composite, least-privilege, inputs passed through the
  environment rather than shell interpolation.
- **Heuristics** — eight documented patterns for tool-poisoning signals in
  descriptions, plus invisible-character detection.
- **Test suite** — 158 tests covering normal cases, malformed input,
  policy-bypass attempts, report escaping and byte-level reproducibility.

### Security

- YAML aliases and duplicate keys are rejected before construction, removing the
  billion-laughs family and the "two parsers disagree" bypass.
- Non-local `$ref` values are rejected: the analyser never resolves references
  and has no HTTP client.
- Policy matching uses globs, never user-supplied regular expressions, so a
  policy file cannot introduce catastrophic backtracking.
- Duplicate tool names are fatal; visually identical names are reported as
  `tool_name_collision`.
- Resource limits on file size, tool count, nesting depth, description length,
  rule count and waiver count.
- Every snapshot-derived string is escaped before rendering, so a tool name
  cannot reshape the report a reviewer reads.

### Fixed during development

- A newly added tool carrying `destructive: true` or `filesystem: delete`
  produced only a MEDIUM `tool_added` finding, so a CRITICAL blocking rule for
  that capability could never fire. Added tools now emit explicit
  `capability_added` findings for dangerous capabilities.
- The recursive comparison of `additionalProperties` sub-schemas was
  unreachable behind an `elif` branch, so such changes were reported as one
  opaque change instead of a precise one.
- `Severity` inherits from `str`, so a comparison against a plain string fell
  back to lexical ordering — where `"HIGH" < "CRITICAL"` is `False`, the
  opposite of the intended order. Comparisons against non-`Severity` values now
  raise.
- A tool name reaching a Markdown heading was not HTML-escaped.

[0.1.0]: https://github.com/Reda3D/mcp-driftguard/releases/tag/v0.1.0

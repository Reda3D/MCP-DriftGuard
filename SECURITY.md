# Security policy

## Supported versions

| Version | Supported |
|---|---|
| `0.1.x` | Yes |

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use GitHub's private vulnerability reporting on this repository
(*Security* → *Report a vulnerability*). If that is unavailable, open a minimal
issue asking for a private channel and include no details.

Please include:

- The version (`driftguard version`) and platform.
- A minimal reproduction: the snapshot and policy that trigger it.
- What you expected versus what happened.
- The impact you believe it has.

### What counts

Anything that breaks one of the guarantees below is in scope:

| Guarantee | Example violation |
|---|---|
| The verdict is deterministic | Two runs on identical inputs produce different verdicts |
| A malformed policy fails closed | A policy that should be rejected is silently accepted |
| No network access during analysis | Any outbound request |
| No execution of untrusted content | A snapshot causing code execution |
| Reports are inert | A snapshot string producing active markup |
| Resource use is bounded | A small input causing unbounded memory or time |
| Blocking rules cannot be waived | A waiver that suppresses a `block` rule |

### What is out of scope

- A malicious server behaving differently from its declared snapshot. That is the
  documented boundary of static analysis.
- False positives from the heuristics. Report them as normal issues.
- Findings that require an already-compromised runner.
- Missing detections for schema keywords outside the documented subset.

## Response

Acknowledgement within 72 hours. A fix or a documented decision within 30 days
for confirmed issues. Credit in the changelog unless you ask otherwise.

## For users

- Pin the action to a commit SHA in high-assurance repositories.
- Keep `permissions: contents: read` on the checking job.
- Never run the check with `pull_request_target` and a checkout of the PR head.
- Treat the policy file as security-critical code: review every change to it.

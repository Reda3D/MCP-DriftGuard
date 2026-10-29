# GitHub Action

The action is a thin composite wrapper around the CLI. It installs nothing but
the package itself, requests no secrets, and never interpolates an input into a
shell script.

---

## Minimal usage

```yaml
name: MCP contract check
on: pull_request

permissions:
  contents: read

jobs:
  driftguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false

      - uses: Reda3D/MCP-DriftGuard@v1
        with:
          baseline: mcp/baseline.json
          candidate: mcp/candidate.json
          policy: driftguard.yml
```

The job fails when the policy is violated, with the report in the job summary.

---

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `baseline` | *(required)* | Trusted snapshot path |
| `candidate` | *(required)* | Candidate snapshot path |
| `policy` | `""` | Policy path. Empty means built-in defaults |
| `fail-on` | `""` | Override the policy threshold |
| `markdown-output` | `driftguard-report.md` | Where to write the Markdown report |
| `json-output` | `driftguard-report.json` | Where to write the JSON report |
| `sarif-output` | `driftguard.sarif` | Where to write the SARIF report |
| `step-summary` | `true` | Append the report to the job summary |
| `install` | `true` | Install from the action path. Set `false` on air-gapped runners |

## Outputs

| Output | Meaning |
|---|---|
| `result` | `pass` or `fail` |
| `exit-code` | `0`, `1`, `2` or `3` |
| `markdown`, `json`, `sarif` | Paths to the produced reports |

Reports are written **before** the step exits, so a failing check still produces
artefacts.

---

## Code scanning

```yaml
      - uses: Reda3D/MCP-DriftGuard@v1
        with:
          baseline: mcp/baseline.json
          candidate: mcp/candidate.json
          policy: driftguard.yml
        continue-on-error: true

      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: driftguard.sarif
```

`security-events: write` is required **only** for the upload step. Keep it off
the job's top-level `permissions` and grant it to the upload step alone if your
repository policy allows per-step permissions.

Fingerprints are derived from `(change type, tool, path, capability)`, so an
alert survives reworded messages and stays dismissed once triaged.

---

## Hardening notes

These are the failure modes that actually happen in the wild, and how this action
avoids them.

### Do not use `pull_request_target` with a checkout of the PR head

That combination gives a workflow with write permissions and repository secrets
to code the PR author controls. This action is designed for the plain
`pull_request` trigger.

### Keep inputs out of the script body

A `baseline` value containing `"; rm -rf .` must remain a filename. The action
passes every input through `env:` and references `"${VAR}"` inside the script,
never `${{ inputs.x }}` inside the shell text.

### Least privilege

```yaml
permissions:
  contents: read
```

That is all the check needs. If your workflow reads snapshots from another
repository, add `contents: read` there — not `write`.

### `persist-credentials: false`

Stops `actions/checkout` from leaving a token in `.git/config` where any later
step (including a malicious one) can read it.

### Pinned action versions

Pin third-party actions by commit SHA in high-assurance repositories. This
action itself should be pinned the same way:

```yaml
      - uses: Reda3D/MCP-DriftGuard@<commit-sha>  # v1.0.0
```

### Air-gapped runners

Set `install: false` and make `driftguard` available on `PATH` beforehand.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `exit-code 2` | Snapshot missing, malformed, or a non-local `$ref` | Run `driftguard validate <file>` locally |
| `exit-code 3` | Policy invalid, or a schema version mismatch | The message names the rule and key |
| Green build, no report | `step-summary: false` and no `--output` | Enable the summary or upload the artefact |
| SARIF upload rejects the file | Empty `results` array is valid; a malformed run is not | Validate with `python -m json.tool driftguard.sarif` |
| Different results on two runs | Almost always `--as-of` drift across a waiver expiry | Pin `--as-of` in the workflow |

---

## Using the CLI without the action

```yaml
      - run: pip install mcp-driftguard
      - run: |
          driftguard check \
            --baseline mcp/baseline.json \
            --candidate mcp/candidate.json \
            --policy driftguard.yml \
            --step-summary \
            --sarif-out driftguard.sarif
```

Identical behaviour, one less moving part.

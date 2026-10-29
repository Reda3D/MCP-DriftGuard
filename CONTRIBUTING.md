# Contributing

## Setup

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
pytest
ruff check .
ruff format --check .
```

All three run in CI on Linux, macOS and Windows across Python 3.9, 3.12 and 3.13.

## What a good change looks like

- **One concern per pull request.** A new change type and a formatting pass do
  not belong in the same diff.
- **A test that fails without the change.** For a new detection, that means a
  snapshot pair that reproduces the drift.
- **Documentation in the same commit.** `docs/policy-reference.md` lists every
  change type; a new one without a row there is incomplete.
- **No new runtime dependency without a paragraph explaining why.** The current
  runtime dependency count is one, and that is a feature.

## Adding a change type

1. Add the identifier to `CHANGE_TYPES` in `src/mcp_driftguard/changes.py`.
2. Add a default severity to `DEFAULT_SEVERITIES` in `src/mcp_driftguard/policy.py`.
   A test asserts the two sets match, so this cannot be forgotten.
3. Emit it from the diff engine.
4. Add it to the table in `docs/policy-reference.md`.
5. Add a test in `tests/test_diff.py`.

## Security-sensitive changes

Changes touching any of the following get extra scrutiny and should say so in
the description:

- `policy.py` — the trust boundary between data and verdict
- `snapshot.py` — the parser for untrusted input
- `report/markdown.py` — the renderer that humans read
- `action.yml` — runs with CI credentials

If your change makes the analyser do anything it did not do before — touch the
network, read the environment, execute something — expect the pull request to be
rejected unless it is discussed in an issue first.

## Style

- Python 3.9 compatible.
- `%`-formatting rather than f-strings in error messages, so messages stay
  identical across Python versions.
- Explicit `typing` imports.
- Comments explain *why*, not *what*. A comment restating the code is removed in
  review.

## Commit messages

Imperative mood, one line, then a body if the reasoning is not obvious:

```
Reject duplicate tool names at load time

A server that declares the same tool twice can make the client resolve a
different definition than the one under review. Failing closed is the only
safe option here.
```

## Reporting bugs

Include the version, the platform, and the smallest snapshot pair that
reproduces the problem. If the snapshot contains anything proprietary, reduce it
first — the format is small enough that a synthetic reproduction is usually
possible in a few lines.

## Code of conduct

Be precise, be kind, argue about the code. Attacks on people are not part of
technical disagreement.

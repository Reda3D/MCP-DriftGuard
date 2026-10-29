"""Command-line interface.

Exit codes are a contract (see :mod:`mcp_driftguard.errors`):

======  ==========================================================
``0``   no finding at or above the configured threshold
``1``   at least one finding at or above the threshold, or a block
``2``   the inputs could not be read or are invalid
``3``   fail-closed: a required check could not be completed
======  ==========================================================
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import traceback
from typing import Any, Optional, Sequence

from . import __version__
from .diff import diff_snapshots
from .errors import (
    EXIT_FAIL_CLOSED,
    EXIT_OK,
    EXIT_POLICY_VIOLATION,
    DriftGuardError,
    InputError,
)
from .policy import load_policy
from .report import Report, json_report, markdown, sarif
from .severity import Severity
from .snapshot import load_snapshot

_POLICY_TEMPLATE = """\
# MCP DriftGuard policy
# Every change is evaluated by this file. No model, no heuristics, no exceptions.
version: 1
fail_on: HIGH

rules:
  - id: DG001
    description: New tools require explicit review
    severity: MEDIUM
    action: warn
    match:
      change: tool_added

  - id: DG002
    description: A tool gained destructive capability
    severity: CRITICAL
    action: block
    match:
      change: [capability_escalated, capability_added]
      capability: destructive

  - id: DG003
    description: A tool gained the ability to delete files
    severity: CRITICAL
    action: block
    match:
      change: [capability_escalated, capability_added]
      capability: filesystem

  - id: DG004
    description: A tool gained the ability to execute commands
    severity: CRITICAL
    action: block
    match:
      change: [capability_escalated, capability_added]
      capability: executes_commands

  - id: DG005
    description: Input validation was weakened
    severity: HIGH
    action: warn
    match:
      change: [schema_constraint_loosened, schema_additional_properties_enabled]

  - id: DG006
    description: Description contains tool-poisoning signals
    severity: MEDIUM
    action: warn
    match:
      change: suspicious_description

  - id: DG007
    description: Two tools are visually indistinguishable
    severity: HIGH
    action: block
    match:
      change: tool_name_collision

# Waivers are exceptions with an owner and an expiry date. They are code:
# they are reviewed, versioned, and they cannot cover a blocking rule.
waivers: []
"""


def _write_text(path: str, content: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        raise InputError("output directory does not exist: %s" % directory)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _dump_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def _resolve_date(value: Optional[str]) -> _dt.date:
    if value is None:
        return _dt.date.today()
    try:
        return _dt.date.fromisoformat(value)
    except ValueError:
        raise InputError("--as-of must be an ISO date (YYYY-MM-DD), got %r" % value) from None


def _cmd_check(args: argparse.Namespace) -> int:
    as_of = _resolve_date(args.as_of)

    baseline = load_snapshot(args.baseline)
    candidate = load_snapshot(args.candidate)
    policy = load_policy(args.policy)

    if args.fail_on:
        try:
            policy = type(policy)(
                version=policy.version,
                fail_on=Severity.parse(args.fail_on),
                rules=policy.rules,
                waivers=policy.waivers,
                defaults=policy.defaults,
                origin=policy.origin,
            )
        except ValueError as exc:
            raise InputError("--fail-on: %s" % exc) from None

    diff = diff_snapshots(baseline, candidate)
    findings = policy.evaluate(diff.changes, as_of=as_of)
    report = Report(
        version=__version__,
        evaluated_on=as_of,
        baseline=baseline,
        candidate=candidate,
        policy=policy,
        diff=diff,
        findings=findings,
    )

    markdown_text = markdown.render(report)

    if args.output:
        _write_text(args.output, markdown_text)
    if args.json_out:
        _write_text(args.json_out, _dump_json(json_report.render(report)))
    if args.sarif_out:
        _write_text(args.sarif_out, _dump_json(sarif.render(report)))

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if args.step_summary and summary_path:
        with open(summary_path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(markdown_text)
            handle.write("\n")

    if args.format == "json":
        stream_text = _dump_json(json_report.render(report))
    elif args.format == "markdown":
        stream_text = markdown_text
    else:
        stream_text = ""

    if stream_text and not args.quiet:
        sys.stdout.write(stream_text)
        if not stream_text.endswith("\n"):
            sys.stdout.write("\n")

    if report.failed:
        return EXIT_POLICY_VIOLATION
    return EXIT_OK


def _cmd_validate(args: argparse.Namespace) -> int:
    for path in args.paths:
        snapshot = load_snapshot(path)
        sys.stdout.write(
            "%s: ok (%d tools, sha256 %s)\n" % (path, len(snapshot.tools), snapshot.digest)
        )
    if args.policy:
        policy = load_policy(args.policy)
        sys.stdout.write(
            "%s: ok (%d rules, %d waivers, fail_on %s)\n"
            % (args.policy, len(policy.rules), len(policy.waivers), policy.fail_on.value)
        )
    return EXIT_OK


def _cmd_hash(args: argparse.Namespace) -> int:
    snapshot = load_snapshot(args.path)
    sys.stdout.write("%s  %s\n" % (snapshot.digest, args.path))
    return EXIT_OK


def _cmd_init(args: argparse.Namespace) -> int:
    if os.path.exists(args.output) and not args.force:
        raise InputError(
            "refusing to overwrite existing file %r" % args.output,
            hint="pass --force to overwrite",
        )
    _write_text(args.output, _POLICY_TEMPLATE)
    sys.stdout.write("wrote %s\n" % args.output)
    return EXIT_OK


def _cmd_version(_args: argparse.Namespace) -> int:
    sys.stdout.write("mcp-driftguard %s\n" % __version__)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="driftguard",
        description="Deterministic contract-drift monitor for MCP servers.",
    )
    parser.add_argument("--version", action="version", version="mcp-driftguard %s" % __version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser(
        "check", help="compare a trusted baseline with a candidate snapshot"
    )
    check.add_argument("--baseline", required=True, help="trusted snapshot (JSON)")
    check.add_argument("--candidate", required=True, help="candidate snapshot (JSON)")
    check.add_argument(
        "--policy", default=None, help="policy file (YAML); defaults apply if omitted"
    )
    check.add_argument(
        "--format",
        choices=("markdown", "json", "none"),
        default="markdown",
        help="format written to stdout (default: markdown)",
    )
    check.add_argument("--output", default=None, help="write the Markdown report to this path")
    check.add_argument("--json-out", default=None, help="write the JSON report to this path")
    check.add_argument("--sarif-out", default=None, help="write a SARIF 2.1.0 report to this path")
    check.add_argument("--fail-on", default=None, help="override the policy failure threshold")
    check.add_argument(
        "--as-of",
        default=None,
        help="evaluation date for waiver expiry (YYYY-MM-DD, default: today)",
    )
    check.add_argument(
        "--step-summary",
        action="store_true",
        help="append the Markdown report to $GITHUB_STEP_SUMMARY when set",
    )
    check.add_argument("--quiet", action="store_true", help="do not write the report to stdout")
    check.set_defaults(func=_cmd_check)

    validate = subparsers.add_parser("validate", help="validate snapshot files")
    validate.add_argument("paths", nargs="+", help="snapshot file(s) to validate")
    validate.add_argument("--policy", default=None, help="also validate a policy file")
    validate.set_defaults(func=_cmd_validate)

    hash_cmd = subparsers.add_parser("hash", help="print the canonical digest of a snapshot")
    hash_cmd.add_argument("path", help="snapshot file")
    hash_cmd.set_defaults(func=_cmd_hash)

    init = subparsers.add_parser("init", help="write a starter policy file")
    init.add_argument("--output", default="driftguard.yml", help="target path")
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    init.set_defaults(func=_cmd_init)

    version = subparsers.add_parser("version", help="print the version")
    version.set_defaults(func=_cmd_version)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except DriftGuardError as exc:
        sys.stderr.write("driftguard: %s\n" % exc.render())
        return exc.exit_code
    except KeyboardInterrupt:  # pragma: no cover
        sys.stderr.write("driftguard: interrupted\n")
        return EXIT_FAIL_CLOSED
    except Exception:  # noqa: BLE001 - fail closed on anything unexpected
        if os.environ.get("DRIFTGUARD_DEBUG"):
            raise
        sys.stderr.write("driftguard: internal error, failing closed\n")
        traceback.print_exc(file=sys.stderr)
        return EXIT_FAIL_CLOSED


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

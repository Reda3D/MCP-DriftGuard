"""Human-readable Markdown report.

Everything that comes from a snapshot is untrusted text and is escaped before it
reaches the document. A tool description containing ``|`` or ``<details>`` must
not be able to reshape the report that a reviewer is reading — the report is
part of the review, so it is part of the attack surface.
"""

from __future__ import annotations

from typing import Any, List

from ..normalize import canonical_json
from ..severity import Severity
from . import Report

_MAX_CELL = 160
_MAX_VALUE = 400


def _escape(text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _text(text: str) -> str:
    """Escape a string for plain-text placement.

    HTML entities are escaped so the value renders literally, and backticks are
    turned into entities so an attacker-supplied name cannot open a code span
    and swallow the rest of the line.
    """
    return _escape(text).replace("`", "&#96;").replace("\r", " ").replace("\n", " ")


def _cell(text: Any) -> str:
    value = _escape(canonical_json(text) if not isinstance(text, str) else text)
    value = value.replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    if len(value) > _MAX_CELL:
        value = value[: _MAX_CELL - 1] + "\u2026"
    return value


def _code(text: str) -> str:
    """Render ``text`` as an inline code span, inert in any renderer.

    Code spans are already literal in CommonMark, so escaping is technically
    redundant. It is done anyway: a report is frequently copied into HTML
    mail, ticket systems and diff viewers that do not implement code spans
    faithfully, and an inert document everywhere is worth a slightly odd
    rendering of a value that contains markup characters in the first place.
    """
    safe = _escape(text)
    fence = "`"
    while fence in safe:
        fence += "`"
    return "%s%s%s" % (fence, safe, fence)


def _value(value: Any) -> str:
    if value is None:
        return "_none_"
    rendered = canonical_json(value) if not isinstance(value, str) else value
    if len(rendered) > _MAX_VALUE:
        rendered = rendered[: _MAX_VALUE - 1] + "\u2026"
    return _code(rendered)


def render(report: Report) -> str:
    lines: List[str] = []
    summary = report.summary()

    verdict = "FAIL" if report.failed else "PASS"
    lines.append("# MCP DriftGuard report")
    lines.append("")
    lines.append(
        "**Result: %s** — %d finding(s), %d waived, fail threshold `%s`."
        % (verdict, summary["total_findings"], summary["waived"], summary["fail_on"])
    )
    lines.append("")

    lines.append("| | |")
    lines.append("|---|---|")
    lines.append(
        "| Baseline | %s |"
        % _code("%s (%s)" % (report.baseline.origin, report.baseline.digest[:16]))
    )
    lines.append(
        "| Candidate | %s |"
        % _code("%s (%s)" % (report.candidate.origin, report.candidate.digest[:16]))
    )
    lines.append("| Policy | %s |" % _code(report.policy.origin))
    lines.append("| Evaluated on | %s |" % report.evaluated_on.isoformat())
    lines.append("| DriftGuard | %s |" % _code(report.version))
    lines.append("")

    if not report.diff.changes:
        lines.append("No drift detected: the candidate declares the same contract as the baseline.")
        lines.append("")
        return "\n".join(lines)

    # -- summary tables ----------------------------------------------------
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Findings |")
    lines.append("|---|---:|")
    for severity in reversed(list(Severity)):
        count = summary["by_severity"].get(severity.value, 0)
        if count:
            lines.append("| %s | %d |" % (severity.value, count))
    lines.append("")

    lines.append("| Change | Count |")
    lines.append("|---|---:|")
    for change_type, count in summary["by_change"].items():
        lines.append("| %s | %d |" % (_code(change_type), count))
    lines.append("")

    # -- findings ----------------------------------------------------------
    lines.append("## Findings")
    lines.append("")

    by_severity = {}
    for finding in report.active_findings:
        by_severity.setdefault(finding.severity, []).append(finding)

    for severity in reversed(list(Severity)):
        bucket = by_severity.get(severity)
        if not bucket:
            continue
        lines.append("### %s (%d)" % (severity.value, len(bucket)))
        lines.append("")
        lines.append("| Tool | Change | Path | Rule | Note |")
        lines.append("|---|---|---|---|---|")
        for finding in bucket:
            change = finding.change
            marker = " (blocking)" if finding.blocking else ""
            lines.append(
                "| %s | %s | %s | %s | %s |"
                % (
                    _cell(change.tool),
                    _code(change.change_type),
                    _cell(change.path) if change.path else "",
                    _cell(finding.rule_id) + marker,
                    _cell(finding.message or change.note),
                )
            )
        lines.append("")

    # -- details -----------------------------------------------------------
    lines.append("<details>")
    lines.append("<summary>Before / after values</summary>")
    lines.append("")
    for finding in report.active_findings:
        change = finding.change
        heading = "%s \u2014 %s" % (_text(change.tool), _code(change.change_type))
        if change.capability:
            heading += " (%s)" % _code(change.capability)
        lines.append("#### %s" % heading)
        lines.append("")
        if change.path:
            lines.append("- Path: %s" % _code(change.path))
        lines.append("- Rule: %s — %s" % (_code(finding.rule_id), _escape(finding.message)))
        if change.note:
            lines.append("- Note: %s" % _escape(change.note))
        lines.append("- Before: %s" % _value(change.before))
        lines.append("- After: %s" % _value(change.after))
        lines.append("")
    lines.append("</details>")
    lines.append("")

    if report.waived_findings:
        lines.append("### Waived")
        lines.append("")
        lines.append("| Tool | Change | Rule | Reason |")
        lines.append("|---|---|---|---|")
        for finding in report.waived_findings:
            lines.append(
                "| %s | %s | %s | %s |"
                % (
                    _cell(finding.change.tool),
                    _code(finding.change.change_type),
                    _cell(finding.rule_id),
                    _cell(finding.waiver_reason),
                )
            )
        lines.append("")

    expired = report.policy.expired_waivers(as_of=report.evaluated_on)
    if expired:
        lines.append("### Expired waivers")
        lines.append("")
        for waiver in expired:
            lines.append(
                "- `%s` on `%s` expired on %s (approved by %s)"
                % (
                    waiver.rule_id,
                    waiver.tool,
                    waiver.expires.isoformat(),
                    _escape(waiver.approved_by),
                )
            )
        lines.append("")

    lines.append("---")
    lines.append(
        "_Generated by MCP DriftGuard %s. Policy engine output is authoritative; "
        "no model was consulted._" % report.version
    )
    lines.append("")
    return "\n".join(lines)

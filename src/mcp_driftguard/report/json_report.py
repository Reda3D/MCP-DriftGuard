"""Machine-readable JSON report.

Consumers are expected to parse this file, so its shape is a contract: keys are
added, never renamed, within a schema version.
"""

from __future__ import annotations

from typing import Any, Dict

from ..severity import Severity
from . import Report


def render(report: Report) -> Dict[str, Any]:
    return {
        "tool": "mcp-driftguard",
        "version": report.version,
        "schema_version": "1",
        "evaluated_on": report.evaluated_on.isoformat(),
        "baseline": {
            "origin": report.baseline.origin,
            "digest": report.baseline.digest,
            "server": dict(report.baseline.server),
            "tools": len(report.baseline.tools),
        },
        "candidate": {
            "origin": report.candidate.origin,
            "digest": report.candidate.digest,
            "server": dict(report.candidate.server),
            "tools": len(report.candidate.tools),
        },
        "policy": {
            "origin": report.policy.origin,
            "fail_on": report.policy.fail_on.value,
            "rules": len(report.policy.rules),
            "waivers": len(report.policy.waivers),
        },
        "summary": report.summary(),
        "findings": [finding.to_dict() for finding in report.findings],
        "expired_waivers": [
            {
                "rule_id": waiver.rule_id,
                "tool": waiver.tool,
                "expires": waiver.expires.isoformat(),
                "approved_by": waiver.approved_by,
            }
            for waiver in report.policy.expired_waivers(as_of=report.evaluated_on)
        ],
    }


def severity_order() -> Dict[str, int]:
    return {severity.value: severity.rank for severity in Severity}

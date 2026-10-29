"""SARIF 2.1.0 output for GitHub code scanning.

SARIF is what turns a finding into an alert that survives across runs. The
fingerprint is therefore derived only from stable identity fields (change type,
tool, path, capability) — never from the message text, which is expected to be
reworded over time.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..normalize import sha256_hex
from . import Report

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _artifact_uri(path: str) -> str:
    return path.replace("\\", "/")


def _fingerprint(finding: Any) -> str:
    change = finding.change
    return sha256_hex(
        {
            "change": change.change_type,
            "tool": change.tool,
            "path": change.path,
            "capability": change.capability,
        }
    )


def render(report: Report) -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in report.active_findings:
        change = finding.change
        rule_id = finding.rule_id

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": change.change_type,
                "shortDescription": {"text": finding.message or change.change_type},
                "defaultConfiguration": {"level": finding.severity.sarif_level},
                "properties": {
                    "severity": finding.severity.value,
                    "change": change.change_type,
                },
            }

        message_parts = ["%s: %s" % (change.tool, change.change_type)]
        if change.capability:
            message_parts.append("capability=%s" % change.capability)
        if change.path:
            message_parts.append("at %s" % change.path)
        if finding.message:
            message_parts.append("- %s" % finding.message)
        if change.note:
            message_parts.append("(%s)" % change.note)

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": finding.severity.sarif_level,
            "message": {"text": " ".join(message_parts)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _artifact_uri(report.candidate.origin),
                        }
                    }
                }
            ],
            "partialFingerprints": {"mcpDriftGuard/v1": _fingerprint(finding)},
            "properties": {
                "severity": finding.severity.value,
                "change": change.change_type,
                "tool": change.tool,
                "waived": finding.waived,
            },
        }
        results.append(result)

    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-driftguard",
                        "version": report.version,
                        "informationUri": "https://github.com/Reda3D/MCP-DriftGuard",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {"result": report.summary()["result"]},
                    }
                ],
                "results": results,
            }
        ],
    }

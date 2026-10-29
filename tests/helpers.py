"""Shared builders for the test suite."""

from __future__ import annotations

import datetime
import json
from typing import Any, Dict, List, Mapping, Optional

from mcp_driftguard.diff import diff_snapshots
from mcp_driftguard.policy import parse_policy
from mcp_driftguard.report import Report
from mcp_driftguard.snapshot import Snapshot, parse_snapshot

SAFE_CAPS = {
    "read_only": True,
    "destructive": False,
    "network_access": False,
    "filesystem": "none",
    "executes_commands": False,
    "accesses_secrets": False,
}


def caps(**overrides: Any) -> Dict[str, Any]:
    """Safe capability set with targeted overrides."""
    merged = dict(SAFE_CAPS)
    merged.update(overrides)
    return merged


def make_tool(
    name: str,
    description: str = "A tool.",
    properties: Optional[Mapping[str, Any]] = None,
    required: Optional[List[str]] = None,
    capabilities: Optional[Mapping[str, Any]] = None,
    additional_properties: Any = False,
) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "input_schema": {
            "type": "object",
            "properties": dict(properties or {}),
            "required": list(required or []),
            "additionalProperties": additional_properties,
        },
        "capabilities": dict(capabilities if capabilities is not None else SAFE_CAPS),
    }


def make_snapshot(tools: List[Mapping[str, Any]], name: str = "test-server") -> Dict[str, Any]:
    return {
        "schema_version": "1",
        "server": {"name": name, "version": "1.0.0"},
        "tools": list(tools),
    }


def build(tools: List[Mapping[str, Any]], name: str = "test-server") -> Snapshot:
    return parse_snapshot(make_snapshot(tools, name))


def write_json(path, payload: Any) -> str:
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    path.write_text(text, encoding="utf-8")
    return str(path)


def change_types(changes) -> List[str]:
    return [change.change_type for change in changes]


DEFAULT_DATE = datetime.date(2026, 6, 1)


def make_report(before_tools, after_tools, policy_document=None, as_of=DEFAULT_DATE):
    """Build a fully evaluated report without touching the filesystem."""
    baseline = build(before_tools)
    candidate = build(after_tools)
    policy = parse_policy(policy_document or {"version": 1})
    diff = diff_snapshots(baseline, candidate)
    findings = policy.evaluate(diff.changes, as_of=as_of)
    return Report(
        version="0.0.0-test",
        evaluated_on=as_of,
        baseline=baseline,
        candidate=candidate,
        policy=policy,
        diff=diff,
        findings=findings,
    )

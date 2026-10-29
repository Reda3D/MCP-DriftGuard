"""Report rendering: shape, determinism and escaping."""

from __future__ import annotations

import json

from mcp_driftguard.report import json_report, markdown, sarif

from .helpers import make_report, make_tool

STRICT_POLICY = {
    "version": 1,
    "fail_on": "HIGH",
    "rules": [
        {
            "id": "DG001",
            "description": "Destructive capability is not allowed",
            "severity": "CRITICAL",
            "action": "block",
            "match": {
                "change": ["capability_escalated", "capability_added"],
                "capability": "destructive",
            },
        }
    ],
}


def test_clean_diff_passes():
    report = make_report([make_tool("a")], [make_tool("a")])
    assert report.failed is False
    assert report.diff.is_empty
    assert "No drift detected" in markdown.render(report)


def test_summary_counts_by_severity():
    report = make_report([], [make_tool("new")], policy_document={"version": 1})
    summary = report.summary()
    assert summary["total_changes"] == 1
    assert summary["by_severity"]["MEDIUM"] == 1
    assert summary["result"] == "pass"


def test_blocking_rule_makes_the_report_fail():
    before = [make_tool("a")]
    after = [
        make_tool(
            "a",
            capabilities={
                "read_only": True,
                "destructive": True,
                "network_access": False,
                "filesystem": "none",
                "executes_commands": False,
                "accesses_secrets": False,
            },
        )
    ]
    report = make_report(before, after, policy_document=STRICT_POLICY)
    assert report.failed is True
    assert report.summary()["blocking"] is True


def test_markdown_is_deterministic():
    before = [make_tool("a", description="x")]
    after = [make_tool("a", description="y"), make_tool("b")]
    report = make_report(before, after)
    assert markdown.render(report) == markdown.render(report)


def test_json_report_is_deterministic():
    before = [make_tool("a")]
    after = [make_tool("b")]
    report = make_report(before, after)
    first = json.dumps(json_report.render(report), sort_keys=True)
    second = json.dumps(json_report.render(report), sort_keys=True)
    assert first == second


def test_json_report_contains_the_contract_fields():
    report = make_report([make_tool("a")], [make_tool("a", description="changed")])
    payload = json_report.render(report)
    for key in (
        "tool",
        "version",
        "schema_version",
        "evaluated_on",
        "baseline",
        "candidate",
        "policy",
        "summary",
        "findings",
    ):
        assert key in payload
    assert payload["baseline"]["digest"] != payload["candidate"]["digest"]


def test_sarif_rules_are_deduplicated():
    report = make_report(
        [make_tool("a"), make_tool("b")],
        [make_tool("a", description="changed"), make_tool("b", description="changed")],
    )
    payload = sarif.render(report)
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids))


def test_sarif_fingerprints_are_stable():
    report = make_report([], [make_tool("a", description="changed")])
    first = sarif.render(report)["runs"][0]["results"]
    second = sarif.render(report)["runs"][0]["results"]
    assert [r["partialFingerprints"] for r in first] == [r["partialFingerprints"] for r in second]


def test_sarif_levels_follow_severity():
    report = make_report([], [make_tool("a")])
    payload = sarif.render(report)
    assert payload["runs"][0]["results"][0]["level"] == "warning"


def test_waived_findings_are_listed_separately():
    policy = {
        "version": 1,
        "fail_on": "HIGH",
        "rules": [
            {"id": "R1", "description": "x", "severity": "HIGH", "match": {"change": "tool_added"}}
        ],
        "waivers": [
            {
                "rule_id": "R1",
                "tool": "*",
                "reason": "accepted risk",
                "approved_by": "team",
                "expires": "2030-01-01",
            }
        ],
    }
    report = make_report([], [make_tool("a")], policy_document=policy)
    assert len(report.waived_findings) == 1
    assert report.failed is False
    assert "accepted risk" in markdown.render(report)

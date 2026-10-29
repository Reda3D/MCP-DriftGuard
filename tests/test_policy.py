"""Policy parsing and evaluation."""

from __future__ import annotations

import datetime as dt

import pytest

from mcp_driftguard.changes import CHANGE_TYPES, Change
from mcp_driftguard.errors import PolicyError
from mcp_driftguard.policy import (
    DEFAULT_SEVERITIES,
    load_policy,
    parse_policy,
)
from mcp_driftguard.severity import Severity

AS_OF = dt.date(2026, 6, 1)


def ch(change_type="tool_added", tool="t", **kwargs):
    return Change(change_type=change_type, tool=tool, **kwargs)


def policy(**overrides):
    document = {"version": 1, "fail_on": "HIGH"}
    document.update(overrides)
    return parse_policy(document)


# --- invariants ------------------------------------------------------------


def test_every_change_type_has_a_default_severity():
    """A change type without a default would be a silent blind spot."""
    assert set(DEFAULT_SEVERITIES) == set(CHANGE_TYPES)


def test_builtin_policy_has_no_rules_but_still_evaluates():
    builtin = load_policy(None)
    findings = builtin.evaluate([ch("capability_escalated")], as_of=AS_OF)
    assert findings[0].severity is Severity.HIGH
    assert findings[0].rule_id == "DG-DEFAULT"


# --- parsing errors (fail closed) -----------------------------------------


def test_rejects_unknown_change_type():
    with pytest.raises(PolicyError, match="unknown change type"):
        policy(
            rules=[
                {
                    "id": "R1",
                    "description": "x",
                    "severity": "LOW",
                    "match": {"change": "tool_adde"},
                }
            ]
        )


def test_rejects_unknown_match_key():
    with pytest.raises(PolicyError, match="unknown match key"):
        policy(
            rules=[
                {
                    "id": "R1",
                    "description": "x",
                    "severity": "LOW",
                    "match": {"change": "tool_added", "capabilty": "x"},
                }
            ]
        )


def test_rejects_unknown_rule_key():
    with pytest.raises(PolicyError, match="unknown key"):
        policy(
            rules=[
                {
                    "id": "R1",
                    "description": "x",
                    "severity": "LOW",
                    "match": {"change": "tool_added"},
                    "sevrity": "HIGH",
                }
            ]
        )


def test_rejects_duplicate_rule_ids():
    rule = {"id": "R1", "description": "x", "severity": "LOW", "match": {"change": "tool_added"}}
    with pytest.raises(PolicyError, match="duplicate rule id"):
        policy(rules=[rule, dict(rule)])


def test_rejects_invalid_severity():
    with pytest.raises(PolicyError, match="unknown severity"):
        policy(
            rules=[
                {
                    "id": "R1",
                    "description": "x",
                    "severity": "SEVERE",
                    "match": {"change": "tool_added"},
                }
            ]
        )


def test_rejects_invalid_action():
    with pytest.raises(PolicyError, match="action must be one of"):
        policy(
            rules=[
                {
                    "id": "R1",
                    "description": "x",
                    "severity": "LOW",
                    "action": "deny",
                    "match": {"change": "tool_added"},
                }
            ]
        )


def test_rejects_unknown_top_level_key():
    with pytest.raises(PolicyError, match="unknown top-level key"):
        parse_policy({"version": 1, "rule": []})


def test_rejects_unsupported_version():
    with pytest.raises(PolicyError, match="unsupported policy version"):
        parse_policy({"version": 2})


# --- waivers ---------------------------------------------------------------


def test_waiver_on_blocking_rule_is_rejected():
    """Blocking rules are exception-free by construction."""
    with pytest.raises(PolicyError, match="blocking and cannot be waived"):
        policy(
            rules=[
                {
                    "id": "R1",
                    "description": "x",
                    "severity": "CRITICAL",
                    "action": "block",
                    "match": {"change": "tool_added"},
                }
            ],
            waivers=[
                {
                    "rule_id": "R1",
                    "reason": "trust me",
                    "approved_by": "me",
                    "expires": "2030-01-01",
                }
            ],
        )


def test_waiver_for_unknown_rule_is_rejected():
    with pytest.raises(PolicyError, match="does not match any rule"):
        policy(
            waivers=[
                {"rule_id": "NOPE", "reason": "x", "approved_by": "y", "expires": "2030-01-01"}
            ]
        )


def test_waiver_requires_an_owner_and_an_expiry():
    rule = {"id": "R1", "description": "x", "severity": "LOW", "match": {"change": "tool_added"}}
    with pytest.raises(PolicyError, match="expires is required"):
        policy(rules=[rule], waivers=[{"rule_id": "R1", "reason": "x", "approved_by": "y"}])


def test_valid_waiver_suppresses_the_finding():
    p = policy(
        rules=[
            {"id": "R1", "description": "x", "severity": "HIGH", "match": {"change": "tool_added"}}
        ],
        waivers=[
            {
                "rule_id": "R1",
                "tool": "legacy_*",
                "reason": "tracked in SEC-1",
                "approved_by": "security-team",
                "expires": "2027-01-01",
            }
        ],
    )
    finding = p.evaluate([ch("tool_added", tool="legacy_import")], as_of=AS_OF)[0]
    assert finding.waived is True
    assert p.must_fail([finding]) is False


def test_expired_waiver_no_longer_applies():
    p = policy(
        rules=[
            {"id": "R1", "description": "x", "severity": "HIGH", "match": {"change": "tool_added"}}
        ],
        waivers=[
            {
                "rule_id": "R1",
                "tool": "*",
                "reason": "x",
                "approved_by": "y",
                "expires": "2026-01-01",
            }
        ],
    )
    finding = p.evaluate([ch("tool_added")], as_of=AS_OF)[0]
    assert finding.waived is False
    assert len(p.expired_waivers(as_of=AS_OF)) == 1


# --- evaluation ------------------------------------------------------------


def test_blocking_rule_fails_even_below_threshold():
    p = policy(
        fail_on="CRITICAL",
        rules=[
            {
                "id": "R1",
                "description": "never",
                "severity": "INFO",
                "action": "block",
                "match": {"change": "tool_added"},
            }
        ],
    )
    finding = p.evaluate([ch("tool_added")], as_of=AS_OF)[0]
    assert finding.severity is Severity.INFO
    assert p.must_fail([finding]) is True


def test_threshold_is_respected():
    p = policy(fail_on="CRITICAL")
    findings = p.evaluate([ch("schema_property_added")], as_of=AS_OF)
    assert findings[0].severity is Severity.MEDIUM
    assert p.must_fail(findings) is False


def test_highest_severity_wins_when_multiple_rules_match():
    p = policy(
        rules=[
            {
                "id": "R1",
                "description": "low",
                "severity": "LOW",
                "match": {"change": "tool_added"},
            },
            {
                "id": "R2",
                "description": "high",
                "severity": "HIGH",
                "match": {"change": "tool_added"},
            },
        ]
    )
    finding = p.evaluate([ch("tool_added")], as_of=AS_OF)[0]
    assert finding.severity is Severity.HIGH
    assert finding.rule_id == "R2"


def test_tool_glob_matches_and_is_case_sensitive():
    p = policy(
        rules=[
            {
                "id": "R1",
                "description": "x",
                "severity": "HIGH",
                "match": {"change": "tool_added", "tool": "admin_*"},
            }
        ]
    )
    assert p.evaluate([ch("tool_added", tool="admin_delete")], as_of=AS_OF)[0].rule_id == "R1"
    assert (
        p.evaluate([ch("tool_added", tool="Admin_delete")], as_of=AS_OF)[0].rule_id == "DG-DEFAULT"
    )


def test_capability_match_only_applies_to_capability_changes():
    p = policy(
        rules=[
            {
                "id": "R1",
                "description": "x",
                "severity": "CRITICAL",
                "match": {"change": "capability_escalated", "capability": "destructive"},
            }
        ]
    )
    hit = p.evaluate([ch("capability_escalated", capability="destructive")], as_of=AS_OF)[0]
    miss = p.evaluate([ch("capability_escalated", capability="network_access")], as_of=AS_OF)[0]
    assert hit.rule_id == "R1"
    assert miss.rule_id == "DG-DEFAULT"


def test_defaults_override_builtin_severity():
    p = policy(defaults={"tool_added": "CRITICAL"})
    finding = p.evaluate([ch("tool_added")], as_of=AS_OF)[0]
    assert finding.severity is Severity.CRITICAL


def test_rejects_defaults_for_unknown_change_type():
    with pytest.raises(PolicyError, match="unknown change type"):
        policy(defaults={"tool_exploded": "HIGH"})


def test_fail_on_accepts_lowercase():
    p = policy(fail_on="medium")
    assert p.fail_on is Severity.MEDIUM

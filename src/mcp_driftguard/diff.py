"""The comparison engine.

Pure functions, no I/O, no network, no model. Given two snapshots the output is
deterministic and fully ordered, which is what makes reports diffable in review
and reproducible in CI.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .changes import Change, DiffResult
from .heuristics import confusable_fold, find_suspicious_patterns
from .normalize import clean_text, stable_sort_key
from .schema_diff import diff_schema
from .snapshot import CAPABILITY_RISK, FILESYSTEM_LEVELS, Snapshot, Tool


def _risk_rank(capability: str, value: Any) -> int:
    """Map a capability value onto a monotone risk scale.

    Unknown or unexpected value types rank highest on purpose: if the analyser
    cannot prove a change is safe, it must not be the analyser that decides it
    is safe.
    """
    if capability == "filesystem":
        if isinstance(value, str) and value in FILESYSTEM_LEVELS:
            return FILESYSTEM_LEVELS.index(value)
        return len(FILESYSTEM_LEVELS)
    direction = CAPABILITY_RISK.get(capability, "higher_is_riskier")
    if isinstance(value, bool):
        return (1 if value else 0) if direction == "higher_is_riskier" else (0 if value else 1)
    return 2


#: Capabilities that are dangerous on their own, regardless of what they were
#: before. A brand-new tool carrying one of these is an escalation from "nothing
#: was there" — treating it as a plain ``tool_added`` would bury the real signal
#: under a MEDIUM "new tool" finding.
_DANGEROUS_LEVELS = {
    "filesystem": ("write", "delete"),
}


def _is_dangerous(capability: str, value: Any) -> bool:
    if capability == "filesystem":
        return isinstance(value, str) and value in _DANGEROUS_LEVELS["filesystem"]
    if capability == "read_only":
        return value is False
    if capability in CAPABILITY_RISK:
        return value is True
    # Unknown capability with a truthy value: assume it matters.
    return bool(value)


def _added_tool_capabilities(tool: Tool) -> List[Change]:
    """Emit explicit capability findings for a newly introduced tool."""
    changes: List[Change] = []
    for key in sorted(tool.capabilities):
        value = tool.capabilities[key]
        if not _is_dangerous(key, value):
            continue
        changes.append(
            Change(
                change_type="capability_added",
                tool=tool.name,
                capability=key,
                after=value,
                note="introduced by a tool that did not exist in the baseline",
            )
        )
    return changes


def _diff_capabilities(before: Tool, after: Tool) -> List[Change]:
    changes: List[Change] = []
    keys = sorted(set(before.capabilities) | set(after.capabilities))

    for key in keys:
        old_present = key in before.capabilities
        new_present = key in after.capabilities
        old_value = before.capabilities.get(key)
        new_value = after.capabilities.get(key)

        if not old_present and new_present:
            changes.append(
                Change(
                    change_type="capability_added",
                    tool=after.name,
                    capability=key,
                    after=new_value,
                    note="capability not declared in the baseline",
                )
            )
            continue
        if old_present and not new_present:
            changes.append(
                Change(
                    change_type="capability_removed",
                    tool=after.name,
                    capability=key,
                    before=old_value,
                )
            )
            continue
        if old_value == new_value:
            continue

        before_rank = _risk_rank(key, old_value)
        after_rank = _risk_rank(key, new_value)
        known = key in CAPABILITY_RISK or key == "filesystem"

        if after_rank > before_rank:
            changes.append(
                Change(
                    change_type="capability_escalated",
                    tool=after.name,
                    capability=key,
                    before=old_value,
                    after=new_value,
                    note="" if known else "unrecognised capability changed",
                )
            )
        elif after_rank < before_rank:
            changes.append(
                Change(
                    change_type="capability_reduced",
                    tool=after.name,
                    capability=key,
                    before=old_value,
                    after=new_value,
                )
            )
        else:
            # Same rank, different value: unclassifiable, so treated as an
            # escalation rather than silently ignored.
            changes.append(
                Change(
                    change_type="capability_escalated",
                    tool=after.name,
                    capability=key,
                    before=old_value,
                    after=new_value,
                    note="value changed in a way DriftGuard cannot rank",
                )
            )

    return changes


def _name_collisions(tools: List[Tool]) -> List[Change]:
    """Detect names that are visually identical but byte-different.

    ``create_issue`` and ``сreate_issue`` (Cyrillic es) are two distinct tools
    to the parser and one tool to a human reviewer. That asymmetry is the
    attack: the reviewer approves the benign one, the client resolves the other.
    """
    buckets: Dict[str, List[str]] = {}
    for tool in tools:
        buckets.setdefault(confusable_fold(tool.name), []).append(tool.name)

    changes: List[Change] = []
    for _folded_key, names in sorted(buckets.items()):
        distinct = sorted(set(names))
        if len(distinct) > 1:
            changes.append(
                Change(
                    change_type="tool_name_collision",
                    tool=distinct[0],
                    before=distinct[1] if len(distinct) > 1 else None,
                    after=distinct,
                    note="distinct tool names fold to the same visible string",
                )
            )
    return changes


def diff_snapshots(baseline: Snapshot, candidate: Snapshot) -> DiffResult:
    """Compare a trusted baseline against a candidate snapshot."""
    before_map = baseline.tool_map()
    after_map = candidate.tool_map()

    changes: List[Change] = []

    for name in sorted(set(after_map) - set(before_map), key=stable_sort_key):
        tool = after_map[name]
        changes.append(
            Change(
                change_type="tool_added",
                tool=name,
                after=tool.to_dict(),
                note="tool absent from the baseline",
            )
        )
        changes.extend(_added_tool_capabilities(tool))

    for name in sorted(set(before_map) - set(after_map), key=stable_sort_key):
        changes.append(
            Change(
                change_type="tool_removed",
                tool=name,
                before=before_map[name].to_dict(),
            )
        )

    for name in sorted(set(before_map) & set(after_map), key=stable_sort_key):
        before_tool = before_map[name]
        after_tool = after_map[name]

        if clean_text(before_tool.description) != clean_text(after_tool.description):
            changes.append(
                Change(
                    change_type="description_changed",
                    tool=name,
                    before=before_tool.description,
                    after=after_tool.description,
                )
            )

        changes.extend(_diff_capabilities(before_tool, after_tool))
        changes.extend(diff_schema(before_tool.input_schema, after_tool.input_schema, name))

    # Heuristics are evaluated on the candidate: the candidate is what a human
    # is being asked to approve, whether or not the wording drifted.
    for name in sorted(after_map, key=stable_sort_key):
        for code, label in find_suspicious_patterns(after_map[name].description):
            changes.append(
                Change(
                    change_type="suspicious_description",
                    tool=name,
                    path=code,
                    note=label,
                )
            )

    changes.extend(_name_collisions(list(candidate.tools)))

    ordered = tuple(sorted(changes, key=lambda change: change.sort_key()))

    return DiffResult(
        baseline_digest=baseline.digest,
        candidate_digest=candidate.digest,
        baseline_origin=baseline.origin,
        candidate_origin=candidate.origin,
        changes=ordered,
    )

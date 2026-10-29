"""The vocabulary of observable changes.

A :class:`Change` is a *fact*, never a judgement. It records what differs
between two snapshots. Whether that fact matters, and how much, is decided
later by the policy engine — never here, and never by a model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Optional, Tuple

#: Every change this build can emit. The policy loader validates rule targets
#: against this set so a typo cannot silently disable a rule.
CHANGE_TYPES: FrozenSet[str] = frozenset(
    {
        "tool_added",
        "tool_removed",
        "tool_name_collision",
        "description_changed",
        "suspicious_description",
        "schema_property_added",
        "schema_property_removed",
        "schema_type_changed",
        "schema_required_added",
        "schema_required_removed",
        "schema_constraint_loosened",
        "schema_constraint_tightened",
        "schema_constraint_changed",
        "schema_additional_properties_enabled",
        "capability_escalated",
        "capability_reduced",
        "capability_added",
        "capability_removed",
    }
)


@dataclass(frozen=True)
class Change:
    """A single, atomic difference between a baseline and a candidate."""

    change_type: str
    tool: str
    path: str = ""
    before: Any = None
    after: Any = None
    capability: Optional[str] = None
    note: str = ""

    def __post_init__(self) -> None:
        if self.change_type not in CHANGE_TYPES:
            raise ValueError("unknown change type %r" % (self.change_type,))

    def sort_key(self) -> Tuple[str, str, str, str]:
        return (self.tool, self.change_type, self.path, self.capability or "")

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "change": self.change_type,
            "tool": self.tool,
        }
        if self.path:
            payload["path"] = self.path
        if self.capability:
            payload["capability"] = self.capability
        if self.before is not None:
            payload["before"] = self.before
        if self.after is not None:
            payload["after"] = self.after
        if self.note:
            payload["note"] = self.note
        return payload


@dataclass
class DiffResult:
    """The complete, ordered set of changes between two snapshots."""

    baseline_digest: str
    candidate_digest: str
    baseline_origin: str
    candidate_origin: str
    changes: Tuple[Change, ...] = field(default_factory=tuple)

    @property
    def is_empty(self) -> bool:
        return not self.changes

    def count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for change in self.changes:
            counts[change.change_type] = counts.get(change.change_type, 0) + 1
        return dict(sorted(counts.items()))

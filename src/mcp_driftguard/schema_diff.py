"""Structural comparison of two JSON Schema documents.

The interesting signal is not "the schema changed" but *in which direction*.
Widening the accepted input of a tool that deletes files is a different event
from tightening it, and a naive text diff cannot tell them apart. Every branch
below is therefore classified as loosening, tightening or neutral change.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional, Set

from .changes import Change
from .normalize import canonical_json, json_pointer

_MAX_DEPTH = 32

_NUMERIC_UPPER = ("maximum", "exclusiveMaximum", "maxLength", "maxItems", "maxProperties")
_NUMERIC_LOWER = ("minimum", "exclusiveMinimum", "minLength", "minItems", "minProperties")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _type_set(value: Any) -> Optional[Set[str]]:
    if value is None:
        return None
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    return None


def _as_schema(value: Any) -> Optional[Mapping[str, Any]]:
    return value if isinstance(value, dict) else None


def _loosen(tool: str, path: str, keyword: str, before: Any, after: Any) -> Change:
    return Change(
        change_type="schema_constraint_loosened",
        tool=tool,
        path=path,
        before=before,
        after=after,
        note="%s widened the accepted input" % keyword,
    )


def _tighten(tool: str, path: str, keyword: str, before: Any, after: Any) -> Change:
    return Change(
        change_type="schema_constraint_tightened",
        tool=tool,
        path=path,
        before=before,
        after=after,
        note="%s narrowed the accepted input" % keyword,
    )


def _changed(tool: str, path: str, keyword: str, before: Any, after: Any) -> Change:
    return Change(
        change_type="schema_constraint_changed",
        tool=tool,
        path=path,
        before=before,
        after=after,
        note="%s changed" % keyword,
    )


def _compare_upper_bound(
    tool: str, path: str, keyword: str, before: Any, after: Any
) -> Optional[Change]:
    if before == after:
        return None
    if not _is_number(before) and before is not None:
        return _changed(tool, path, keyword, before, after)
    if not _is_number(after) and after is not None:
        return _changed(tool, path, keyword, before, after)
    if after is None:
        return _loosen(tool, path, keyword, before, after)
    if before is None:
        return _tighten(tool, path, keyword, before, after)
    if after > before:
        return _loosen(tool, path, keyword, before, after)
    return _tighten(tool, path, keyword, before, after)


def _compare_lower_bound(
    tool: str, path: str, keyword: str, before: Any, after: Any
) -> Optional[Change]:
    if before == after:
        return None
    if not _is_number(before) and before is not None:
        return _changed(tool, path, keyword, before, after)
    if not _is_number(after) and after is not None:
        return _changed(tool, path, keyword, before, after)
    if after is None:
        return _loosen(tool, path, keyword, before, after)
    if before is None:
        return _tighten(tool, path, keyword, before, after)
    if after < before:
        return _loosen(tool, path, keyword, before, after)
    return _tighten(tool, path, keyword, before, after)


def _enum_values(value: Any) -> Optional[Set[str]]:
    if not isinstance(value, list):
        return None
    return {canonical_json(item) for item in value}


def diff_schema(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    tool: str,
    base_path: str = "",
    _depth: int = 0,
) -> List[Change]:
    """Return the ordered list of changes between two schema fragments."""
    changes: List[Change] = []
    if _depth > _MAX_DEPTH:
        # Already rejected at load time; this is a defensive backstop.
        return changes

    def path_for(*parts: Any) -> str:
        joined = json_pointer(*parts) if parts else ""
        return base_path + joined

    # --- type -------------------------------------------------------------
    before_types = _type_set(baseline.get("type"))
    after_types = _type_set(candidate.get("type"))
    if before_types != after_types:
        if before_types is not None and after_types is not None:
            added = after_types - before_types
            removed = before_types - after_types
            if added and not removed:
                changes.append(
                    _loosen(
                        tool, path_for("type"), "type", sorted(before_types), sorted(after_types)
                    )
                )
            elif removed and not added:
                changes.append(
                    _tighten(
                        tool, path_for("type"), "type", sorted(before_types), sorted(after_types)
                    )
                )
            else:
                changes.append(
                    Change(
                        change_type="schema_type_changed",
                        tool=tool,
                        path=path_for("type"),
                        before=sorted(before_types),
                        after=sorted(after_types),
                    )
                )
        else:
            changes.append(
                Change(
                    change_type="schema_type_changed",
                    tool=tool,
                    path=path_for("type"),
                    before=baseline.get("type"),
                    after=candidate.get("type"),
                )
            )

    # --- properties -------------------------------------------------------
    before_props = baseline.get("properties")
    after_props = candidate.get("properties")
    before_props = before_props if isinstance(before_props, dict) else {}
    after_props = after_props if isinstance(after_props, dict) else {}

    for name in sorted(set(after_props) - set(before_props)):
        changes.append(
            Change(
                change_type="schema_property_added",
                tool=tool,
                path=path_for("properties", name),
                after=after_props[name],
                note="new input parameter accepted by the tool",
            )
        )
    for name in sorted(set(before_props) - set(after_props)):
        changes.append(
            Change(
                change_type="schema_property_removed",
                tool=tool,
                path=path_for("properties", name),
                before=before_props[name],
            )
        )
    for name in sorted(set(before_props) & set(after_props)):
        sub_before = _as_schema(before_props[name])
        sub_after = _as_schema(after_props[name])
        if sub_before is None or sub_after is None:
            if before_props[name] != after_props[name]:
                changes.append(
                    _changed(
                        tool,
                        path_for("properties", name),
                        "property definition",
                        before_props[name],
                        after_props[name],
                    )
                )
            continue
        changes.extend(
            diff_schema(
                sub_before,
                sub_after,
                tool,
                base_path=path_for("properties", name),
                _depth=_depth + 1,
            )
        )

    # --- required ---------------------------------------------------------
    before_req = set(baseline.get("required") or [])
    after_req = set(candidate.get("required") or [])
    for name in sorted(after_req - before_req):
        changes.append(
            Change(
                change_type="schema_required_added",
                tool=tool,
                path=path_for("required", name),
                note="parameter is now mandatory",
            )
        )
    for name in sorted(before_req - after_req):
        changes.append(
            Change(
                change_type="schema_required_removed",
                tool=tool,
                path=path_for("required", name),
                note="parameter is now optional, callers may omit it",
            )
        )

    # --- additionalProperties --------------------------------------------
    # Absent means "true" in JSON Schema, so absent -> present(false) is a
    # tightening and present(false) -> absent is a loosening.
    before_add = baseline.get("additionalProperties", True)
    after_add = candidate.get("additionalProperties", True)
    if isinstance(before_add, dict) and isinstance(after_add, dict):
        # Both sides constrain the shape of unknown properties: recurse into it
        # rather than treating the whole sub-schema as one opaque change.
        changes.extend(
            diff_schema(
                before_add,
                after_add,
                tool,
                base_path=path_for("additionalProperties"),
                _depth=_depth + 1,
            )
        )
    elif before_add != after_add:
        if before_add is False and after_add is not False:
            changes.append(
                Change(
                    change_type="schema_additional_properties_enabled",
                    tool=tool,
                    path=path_for("additionalProperties"),
                    before=before_add,
                    after=after_add,
                    note="unknown properties are now accepted",
                )
            )
        elif before_add is not False and after_add is False:
            changes.append(
                _tighten(
                    tool,
                    path_for("additionalProperties"),
                    "additionalProperties",
                    before_add,
                    after_add,
                )
            )
        else:
            changes.append(
                _changed(
                    tool,
                    path_for("additionalProperties"),
                    "additionalProperties",
                    before_add,
                    after_add,
                )
            )

    # --- enum / const -----------------------------------------------------
    before_enum = _enum_values(baseline.get("enum"))
    after_enum = _enum_values(candidate.get("enum"))
    if before_enum is not None and after_enum is not None and before_enum != after_enum:
        if after_enum - before_enum and not before_enum - after_enum:
            changes.append(
                _loosen(
                    tool,
                    path_for("enum"),
                    "enum",
                    sorted(before_enum),
                    sorted(after_enum),
                )
            )
        elif before_enum - after_enum and not after_enum - before_enum:
            changes.append(
                _tighten(
                    tool,
                    path_for("enum"),
                    "enum",
                    sorted(before_enum),
                    sorted(after_enum),
                )
            )
        else:
            changes.append(
                _changed(
                    tool,
                    path_for("enum"),
                    "enum",
                    sorted(before_enum),
                    sorted(after_enum),
                )
            )
    elif (before_enum is None) != (after_enum is None):
        changes.append(
            _changed(tool, path_for("enum"), "enum", baseline.get("enum"), candidate.get("enum"))
        )

    if baseline.get("const", _MISSING) != candidate.get("const", _MISSING):
        changes.append(
            _changed(
                tool,
                path_for("const"),
                "const",
                baseline.get("const"),
                candidate.get("const"),
            )
        )

    # --- numeric / length bounds -----------------------------------------
    for keyword in _NUMERIC_UPPER:
        change = _compare_upper_bound(
            tool,
            path_for(keyword),
            keyword,
            baseline.get(keyword),
            candidate.get(keyword),
        )
        if change is not None:
            changes.append(change)
    for keyword in _NUMERIC_LOWER:
        change = _compare_lower_bound(
            tool,
            path_for(keyword),
            keyword,
            baseline.get(keyword),
            candidate.get(keyword),
        )
        if change is not None:
            changes.append(change)

    # --- pattern / format -------------------------------------------------
    for keyword in ("pattern", "format"):
        before = baseline.get(keyword)
        after = candidate.get(keyword)
        if before == after:
            continue
        if before is not None and after is None:
            changes.append(_loosen(tool, path_for(keyword), keyword, before, after))
        else:
            changes.append(_changed(tool, path_for(keyword), keyword, before, after))

    # --- $ref -------------------------------------------------------------
    if baseline.get("$ref") != candidate.get("$ref"):
        changes.append(
            _changed(tool, path_for("$ref"), "$ref", baseline.get("$ref"), candidate.get("$ref"))
        )

    # --- items ------------------------------------------------------------
    before_items = _as_schema(baseline.get("items"))
    after_items = _as_schema(candidate.get("items"))
    if before_items is not None and after_items is not None:
        changes.extend(
            diff_schema(
                before_items,
                after_items,
                tool,
                base_path=path_for("items"),
                _depth=_depth + 1,
            )
        )
    elif (before_items is None) != (after_items is None):
        changes.append(
            _changed(
                tool, path_for("items"), "items", baseline.get("items"), candidate.get("items")
            )
        )

    # --- combinators ------------------------------------------------------
    for keyword in ("anyOf", "oneOf", "allOf"):
        before_branch = baseline.get(keyword)
        after_branch = candidate.get(keyword)
        if before_branch == after_branch:
            continue
        if not isinstance(before_branch, list) or not isinstance(after_branch, list):
            changes.append(_changed(tool, path_for(keyword), keyword, before_branch, after_branch))
            continue
        if len(before_branch) != len(after_branch):
            changes.append(
                _changed(
                    tool,
                    path_for(keyword),
                    keyword,
                    "%d branch(es)" % len(before_branch),
                    "%d branch(es)" % len(after_branch),
                )
            )
            continue
        for index, (sub_before, sub_after) in enumerate(zip(before_branch, after_branch)):
            sb, sa = _as_schema(sub_before), _as_schema(sub_after)
            if sb is not None and sa is not None:
                changes.extend(
                    diff_schema(
                        sb,
                        sa,
                        tool,
                        base_path=path_for(keyword, index),
                        _depth=_depth + 1,
                    )
                )
            elif sub_before != sub_after:
                changes.append(
                    _changed(tool, path_for(keyword, index), keyword, sub_before, sub_after)
                )

    return changes


class _Missing:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<missing>"


_MISSING = _Missing()

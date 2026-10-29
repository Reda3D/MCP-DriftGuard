"""Deterministic policy engine.

Design rules that are not negotiable:

1. The engine is pure. It never calls a model, never reads the network and never
   consults anything outside the two inputs it is given.
2. An unparseable or ambiguous policy is a hard error, never "no rules matched".
   A typo in ``change:`` would otherwise silently disable a control.
3. A ``block`` rule cannot be waived. Exceptions are made by editing the policy
   under review, not by an allowance granted at runtime.
4. Matching uses globs, never user-supplied regular expressions, so a policy
   file cannot introduce a catastrophic-backtracking path into CI.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import yaml

from . import POLICY_SCHEMA_VERSION
from .changes import CHANGE_TYPES, Change
from .errors import InputError, PolicyError
from .severity import Severity, max_severity

MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_RULES = 1_000
MAX_WAIVERS = 5_000

_ACTIONS = ("warn", "block")
_RULE_KEYS = {"id", "description", "severity", "action", "match", "rationale"}
_MATCH_KEYS = {"change", "tool", "path", "capability"}
_WAIVER_KEYS = {"rule_id", "tool", "reason", "approved_by", "expires"}
_TOP_KEYS = {"version", "fail_on", "defaults", "rules", "waivers"}

#: Fallback severity per change type, used when no rule matches. The table is
#: complete by construction and a unit test asserts it stays that way: a change
#: type without a default would be a silent blind spot.
DEFAULT_SEVERITIES: Dict[str, Severity] = {
    "tool_added": Severity.MEDIUM,
    "tool_removed": Severity.LOW,
    "tool_name_collision": Severity.HIGH,
    "description_changed": Severity.LOW,
    "suspicious_description": Severity.MEDIUM,
    "schema_property_added": Severity.MEDIUM,
    "schema_property_removed": Severity.LOW,
    "schema_type_changed": Severity.MEDIUM,
    "schema_required_added": Severity.LOW,
    "schema_required_removed": Severity.MEDIUM,
    "schema_constraint_loosened": Severity.HIGH,
    "schema_constraint_tightened": Severity.INFO,
    "schema_constraint_changed": Severity.MEDIUM,
    "schema_additional_properties_enabled": Severity.HIGH,
    "capability_escalated": Severity.HIGH,
    "capability_reduced": Severity.INFO,
    "capability_added": Severity.HIGH,
    "capability_removed": Severity.LOW,
}


# --- Hardened YAML loading -------------------------------------------------


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader with aliases and duplicate keys rejected.

    YAML anchors let a 1 KB file expand to gigabytes (the "billion laughs"
    family). Duplicate keys let two parsers disagree about which value is
    authoritative — a classic policy-bypass trick. Neither is needed in a
    policy file, so neither is allowed.
    """

    def compose_node(self, parent: Any, index: Any) -> Any:  # type: ignore[override]
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise PolicyError(
                "YAML aliases are not allowed in policy files (found '*%s')" % event.anchor
            )
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:  # type: ignore[override]
        if not isinstance(node, yaml.MappingNode):
            raise PolicyError("expected a mapping in policy file")
        seen: Dict[Any, int] = {}
        for key_node, _value_node in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise PolicyError(
                    "duplicate key %r in policy file (line %d)"
                    % (key, key_node.start_mark.line + 1)
                )
            seen[key] = 1
        return super().construct_mapping(node, deep=deep)


def _load_yaml(path: str) -> Mapping[str, Any]:
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise InputError("cannot read policy %r: %s" % (path, exc.strerror or exc)) from None
    if size > MAX_POLICY_BYTES:
        raise InputError("policy %r is %d bytes, limit is %d" % (path, size, MAX_POLICY_BYTES))

    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise InputError("cannot read policy %r: %s" % (path, exc.strerror or exc)) from None
    except UnicodeDecodeError as exc:
        raise InputError("policy %r is not valid UTF-8: %s" % (path, exc)) from None

    try:
        # _StrictLoader subclasses yaml.SafeLoader: arbitrary object
        # instantiation is impossible, and aliases plus duplicate keys are
        # rejected before construction. The static check cannot see the
        # subclass relationship, hence the explicit suppression.
        document = yaml.load(text, Loader=_StrictLoader)  # noqa: S506
    except PolicyError:
        raise
    except yaml.YAMLError as exc:
        raise PolicyError("policy %r is not valid YAML: %s" % (path, exc)) from None

    if document is None:
        raise PolicyError("policy %r is empty" % path)
    if not isinstance(document, dict):
        raise PolicyError("policy %r must contain a mapping at the top level" % path)
    return document


# --- Model -----------------------------------------------------------------


def _as_str_list(value: Any, where: str) -> Tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise PolicyError("%s must be a string or a list of strings" % where)


@dataclass(frozen=True)
class Match:
    change: Tuple[str, ...]
    tool: Tuple[str, ...] = ("*",)
    path: Tuple[str, ...] = ("*",)
    capability: Tuple[str, ...] = ("*",)

    def matches(self, change: Change) -> bool:
        if change.change_type not in self.change:
            return False
        if not any(fnmatch.fnmatchcase(change.tool, pattern) for pattern in self.tool):
            return False
        if not any(fnmatch.fnmatchcase(change.path, pattern) for pattern in self.path):
            return False
        if change.capability is None:
            return self.capability == ("*",)
        return any(fnmatch.fnmatchcase(change.capability, pattern) for pattern in self.capability)


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: Severity
    action: str
    match: Match
    rationale: str = ""

    @property
    def waivable(self) -> bool:
        return self.action != "block"


@dataclass(frozen=True)
class Waiver:
    rule_id: str
    tool: str
    reason: str
    approved_by: str
    expires: _dt.date

    def applies_to(self, rule: Rule, change: Change) -> bool:
        return rule.id == self.rule_id and fnmatch.fnmatchcase(change.tool, self.tool)


@dataclass(frozen=True)
class Finding:
    change: Change
    severity: Severity
    rule_id: str
    action: str
    waived: bool = False
    waiver_reason: str = ""
    message: str = ""

    @property
    def blocking(self) -> bool:
        return self.action == "block" and not self.waived

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "change": self.change.change_type,
            "tool": self.change.tool,
            "severity": self.severity.value,
            "rule": self.rule_id,
            "action": self.action,
            "waived": self.waived,
        }
        if self.change.path:
            payload["path"] = self.change.path
        if self.change.capability:
            payload["capability"] = self.change.capability
        if self.change.before is not None:
            payload["before"] = self.change.before
        if self.change.after is not None:
            payload["after"] = self.change.after
        if self.change.note:
            payload["note"] = self.change.note
        if self.waived and self.waiver_reason:
            payload["waiver_reason"] = self.waiver_reason
        return payload


@dataclass
class Policy:
    version: int
    fail_on: Severity
    rules: Tuple[Rule, ...]
    waivers: Tuple[Waiver, ...]
    defaults: Dict[str, Severity] = field(default_factory=dict)
    origin: str = "<built-in>"

    # -- evaluation --------------------------------------------------------

    def default_severity(self, change_type: str) -> Severity:
        return self.defaults.get(change_type) or DEFAULT_SEVERITIES[change_type]

    def matching_rules(self, change: Change) -> List[Rule]:
        return [rule for rule in self.rules if rule.match.matches(change)]

    def evaluate(self, changes: Sequence[Change], *, as_of: _dt.date) -> List[Finding]:
        findings: List[Finding] = []
        for change in changes:
            findings.append(self._evaluate_one(change, as_of=as_of))
        return findings

    def _evaluate_one(self, change: Change, *, as_of: _dt.date) -> Finding:
        matched = self.matching_rules(change)

        if not matched:
            return Finding(
                change=change,
                severity=self.default_severity(change.change_type),
                rule_id="DG-DEFAULT",
                action="warn",
                message="no policy rule matched; built-in default severity applied",
            )

        active: List[Rule] = []
        waived_rule: Optional[Rule] = None
        waiver_reason = ""

        for rule in matched:
            waiver = self._active_waiver(rule, change, as_of=as_of)
            if waiver is not None and rule.waivable:
                waived_rule = waived_rule or rule
                waiver_reason = waiver.reason
                continue
            active.append(rule)

        if not active:
            rule = waived_rule  # type: ignore[assignment]
            return Finding(
                change=change,
                severity=Severity.INFO,
                rule_id=rule.id,
                action=rule.action,
                waived=True,
                waiver_reason=waiver_reason,
                message="waived by %s (approved by %s)" % (rule.id, "policy waiver"),
            )

        severity = max_severity(rule.severity for rule in active)
        action = "block" if any(rule.action == "block" for rule in active) else "warn"
        primary = max(active, key=lambda rule: rule.severity.rank)

        return Finding(
            change=change,
            severity=severity,
            rule_id=primary.id,
            action=action,
            message=primary.description,
        )

    def _active_waiver(self, rule: Rule, change: Change, *, as_of: _dt.date) -> Optional[Waiver]:
        for waiver in self.waivers:
            if not waiver.applies_to(rule, change):
                continue
            if waiver.expires < as_of:
                continue
            return waiver
        return None

    def expired_waivers(self, *, as_of: _dt.date) -> List[Waiver]:
        return [waiver for waiver in self.waivers if waiver.expires < as_of]

    def must_fail(self, findings: Iterable[Finding]) -> bool:
        for finding in findings:
            if finding.waived:
                continue
            if finding.blocking:
                return True
            if finding.severity >= self.fail_on:
                return True
        return False


# --- Parsing ---------------------------------------------------------------


def _parse_match(raw: Any, rule_id: str) -> Match:
    if not isinstance(raw, dict):
        raise PolicyError("rule %s: match must be a mapping" % rule_id)
    unknown = set(raw) - _MATCH_KEYS
    if unknown:
        raise PolicyError(
            "rule %s: unknown match key(s): %s" % (rule_id, ", ".join(sorted(unknown))),
            hint="allowed keys are: %s" % ", ".join(sorted(_MATCH_KEYS)),
        )
    if "change" not in raw:
        raise PolicyError("rule %s: match.change is required" % rule_id)

    changes = _as_str_list(raw["change"], "rule %s: match.change" % rule_id)
    for change_type in changes:
        if change_type not in CHANGE_TYPES:
            raise PolicyError(
                "rule %s: unknown change type %r" % (rule_id, change_type),
                hint="a rule that matches nothing is a disabled control, so this is fatal",
            )

    return Match(
        change=changes,
        tool=_as_str_list(raw.get("tool", "*"), "rule %s: match.tool" % rule_id),
        path=_as_str_list(raw.get("path", "*"), "rule %s: match.path" % rule_id),
        capability=_as_str_list(raw.get("capability", "*"), "rule %s: match.capability" % rule_id),
    )


def _parse_rule(raw: Any, index: int) -> Rule:
    where = "rules[%d]" % index
    if not isinstance(raw, dict):
        raise PolicyError("%s must be a mapping" % where)
    unknown = set(raw) - _RULE_KEYS
    if unknown:
        raise PolicyError("%s: unknown key(s): %s" % (where, ", ".join(sorted(unknown))))

    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise PolicyError("%s: id must be a non-empty string" % where)
    rule_id = rule_id.strip()
    if not rule_id.replace("-", "").replace("_", "").isalnum():
        raise PolicyError(
            "%s: id %r must be alphanumeric (dashes and underscores allowed)" % (where, rule_id)
        )

    description = raw.get("description")
    if not isinstance(description, str) or not description.strip():
        raise PolicyError("rule %s: description must be a non-empty string" % rule_id)

    try:
        severity = Severity.parse(raw.get("severity"))
    except (ValueError, TypeError) as exc:
        raise PolicyError("rule %s: %s" % (rule_id, exc)) from None

    action = raw.get("action", "warn")
    if action not in _ACTIONS:
        raise PolicyError(
            "rule %s: action must be one of %s, got %r" % (rule_id, ", ".join(_ACTIONS), action)
        )

    rationale = raw.get("rationale", "")
    if rationale is not None and not isinstance(rationale, str):
        raise PolicyError("rule %s: rationale must be a string" % rule_id)

    return Rule(
        id=rule_id,
        description=description.strip(),
        severity=severity,
        action=action,
        match=_parse_match(raw.get("match"), rule_id),
        rationale=rationale or "",
    )


def _parse_date(value: Any, where: str) -> _dt.date:
    if isinstance(value, _dt.date):
        return value
    if not isinstance(value, str):
        raise PolicyError("%s must be an ISO date (YYYY-MM-DD)" % where)
    try:
        return _dt.date.fromisoformat(value.strip())
    except ValueError:
        raise PolicyError("%s is not a valid ISO date: %r" % (where, value)) from None


def _parse_waiver(raw: Any, index: int, rules_by_id: Mapping[str, Rule]) -> Waiver:
    where = "waivers[%d]" % index
    if not isinstance(raw, dict):
        raise PolicyError("%s must be a mapping" % where)
    unknown = set(raw) - _WAIVER_KEYS
    if unknown:
        raise PolicyError("%s: unknown key(s): %s" % (where, ", ".join(sorted(unknown))))

    rule_id = raw.get("rule_id")
    if not isinstance(rule_id, str) or rule_id not in rules_by_id:
        raise PolicyError(
            "%s: rule_id %r does not match any rule" % (where, rule_id),
            hint="a waiver for a non-existent rule would silently do nothing",
        )
    rule = rules_by_id[rule_id]
    if not rule.waivable:
        raise PolicyError(
            "%s: rule %s is blocking and cannot be waived" % (where, rule_id),
            hint="blocking rules are exceptions-free by design; change the policy instead",
        )

    for required in ("reason", "approved_by", "expires"):
        if required not in raw:
            raise PolicyError("%s: %s is required" % (where, required))

    reason = raw["reason"]
    approved_by = raw["approved_by"]
    if not isinstance(reason, str) or not reason.strip():
        raise PolicyError("%s: reason must be a non-empty string" % where)
    if not isinstance(approved_by, str) or not approved_by.strip():
        raise PolicyError("%s: approved_by must be a non-empty string" % where)

    tool = raw.get("tool", "*")
    if not isinstance(tool, str) or not tool:
        raise PolicyError("%s: tool must be a non-empty glob string" % where)

    return Waiver(
        rule_id=rule_id,
        tool=tool,
        reason=reason.strip(),
        approved_by=approved_by.strip(),
        expires=_parse_date(raw["expires"], "%s: expires" % where),
    )


def parse_policy(document: Mapping[str, Any], origin: str = "<memory>") -> Policy:
    """Validate a decoded policy document."""
    if not isinstance(document, dict):
        raise PolicyError("policy must be a mapping")

    unknown = set(document) - _TOP_KEYS
    if unknown:
        raise PolicyError("policy: unknown top-level key(s): %s" % ", ".join(sorted(unknown)))

    version = document.get("version", POLICY_SCHEMA_VERSION)
    if version != POLICY_SCHEMA_VERSION:
        raise PolicyError(
            "unsupported policy version %r (this build understands %r)"
            % (version, POLICY_SCHEMA_VERSION)
        )

    try:
        fail_on = Severity.parse(document.get("fail_on", "HIGH"))
    except (ValueError, TypeError) as exc:
        raise PolicyError("policy: %s" % exc) from None

    defaults: Dict[str, Severity] = {}
    raw_defaults = document.get("defaults", {}) or {}
    if not isinstance(raw_defaults, dict):
        raise PolicyError("policy: defaults must be a mapping")
    for change_type, severity in raw_defaults.items():
        if change_type not in CHANGE_TYPES:
            raise PolicyError("policy: defaults has unknown change type %r" % (change_type,))
        try:
            defaults[change_type] = Severity.parse(severity)
        except (ValueError, TypeError) as exc:
            raise PolicyError("policy: defaults[%s]: %s" % (change_type, exc)) from None

    raw_rules = document.get("rules", []) or []
    if not isinstance(raw_rules, list):
        raise PolicyError("policy: rules must be a list")
    if len(raw_rules) > MAX_RULES:
        raise PolicyError("policy: %d rules exceeds the limit of %d" % (len(raw_rules), MAX_RULES))

    rules = [_parse_rule(raw, index) for index, raw in enumerate(raw_rules)]

    seen_ids: Dict[str, int] = {}
    for index, rule in enumerate(rules):
        if rule.id in seen_ids:
            raise PolicyError(
                "policy: duplicate rule id %r (rules[%d] and rules[%d])"
                % (rule.id, seen_ids[rule.id], index)
            )
        seen_ids[rule.id] = index

    raw_waivers = document.get("waivers", []) or []
    if not isinstance(raw_waivers, list):
        raise PolicyError("policy: waivers must be a list")
    if len(raw_waivers) > MAX_WAIVERS:
        raise PolicyError(
            "policy: %d waivers exceeds the limit of %d" % (len(raw_waivers), MAX_WAIVERS)
        )

    rules_by_id = {rule.id: rule for rule in rules}
    waivers = [_parse_waiver(raw, index, rules_by_id) for index, raw in enumerate(raw_waivers)]

    return Policy(
        version=version,
        fail_on=fail_on,
        rules=tuple(rules),
        waivers=tuple(waivers),
        defaults=defaults,
        origin=origin,
    )


def load_policy(path: Optional[str]) -> Policy:
    """Load a policy from disk, or return the built-in defaults."""
    if path is None:
        return Policy(
            version=POLICY_SCHEMA_VERSION,
            fail_on=Severity.HIGH,
            rules=(),
            waivers=(),
            defaults={},
            origin="<built-in>",
        )
    return parse_policy(_load_yaml(path), origin=path)

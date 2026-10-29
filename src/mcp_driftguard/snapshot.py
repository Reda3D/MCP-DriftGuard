"""Snapshot model, loading and validation.

A *snapshot* is a static, versioned description of what an MCP server declares:
its tools, their input schemas and their capabilities. DriftGuard never talks to
a server to obtain one — snapshots are produced elsewhere and treated as
untrusted input here.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Tuple

from . import SNAPSHOT_SCHEMA_VERSION
from .errors import InputError
from .normalize import clean_text, nfc, sha256_hex, stable_sort_key

# --- Resource limits -------------------------------------------------------
# Snapshots are untrusted input. These bounds keep a malicious file from
# turning a CI job into an out-of-memory event.
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOOLS = 10_000
MAX_SCHEMA_DEPTH = 32
MAX_DESCRIPTION_CHARS = 100_000
MAX_NAME_CHARS = 256

#: Capability vocabulary. ``read_only`` is inverted on purpose: for that key a
#: *decrease* is the risky direction.
CAPABILITY_RISK: Dict[str, str] = {
    "read_only": "lower_is_riskier",
    "destructive": "higher_is_riskier",
    "network_access": "higher_is_riskier",
    "executes_commands": "higher_is_riskier",
    "accesses_secrets": "higher_is_riskier",
}

#: Ordered levels for the one ordinal capability we model.
FILESYSTEM_LEVELS: Tuple[str, ...] = ("none", "read", "write", "delete")

KNOWN_CAPABILITIES = frozenset(CAPABILITY_RISK) | {"filesystem"}


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: Mapping[str, Any]
    capabilities: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": dict(self.input_schema),
            "capabilities": dict(self.capabilities),
        }

    @property
    def digest(self) -> str:
        """Stable hash of the declared contract of this tool."""
        return sha256_hex(self.to_dict())


@dataclass(frozen=True)
class Snapshot:
    schema_version: str
    server: Mapping[str, Any]
    tools: Tuple[Tool, ...]
    digest: str
    origin: str = "<memory>"

    def tool_map(self) -> Dict[str, Tool]:
        return {tool.name: tool for tool in self.tools}

    def sorted_tools(self) -> List[Tool]:
        return sorted(self.tools, key=lambda t: stable_sort_key(t.name))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "server": dict(self.server),
            "tools": [t.to_dict() for t in self.sorted_tools()],
        }


# --- Low-level JSON helpers ------------------------------------------------


def _reject_constant(value: str) -> Any:
    raise InputError("invalid JSON literal %r in snapshot (NaN/Infinity are not allowed)" % value)


def _check_depth(value: Any, limit: int = MAX_SCHEMA_DEPTH) -> int:
    """Return the nesting depth of ``value``, raising when it exceeds ``limit``.

    Iterative on purpose: a recursive implementation would itself blow the
    stack on adversarial input.
    """
    deepest = 0
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > deepest:
            deepest = depth
            if deepest > limit:
                raise InputError(
                    "snapshot nesting exceeds the maximum depth of %d" % limit,
                    hint="flatten the schema or raise MAX_SCHEMA_DEPTH deliberately",
                )
        if isinstance(node, dict):
            for child in node.values():
                stack.append((child, depth + 1))
        elif isinstance(node, list):
            for child in node:
                stack.append((child, depth + 1))
    return deepest


def _require_object(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise InputError("%s must be a JSON object, got %s" % (where, type(value).__name__))
    return value


def _reject_external_refs(schema: Any, tool_name: str) -> None:
    """Refuse schemas that reference anything outside the document.

    DriftGuard performs static analysis only. Following a remote ``$ref`` would
    turn a passive comparison into a network request to an attacker-chosen
    host — a server-side request forgery primitive inside CI.
    """
    stack = [schema]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                raise InputError(
                    "tool %r declares a non-local $ref (%s)" % (tool_name, ref),
                    hint="DriftGuard never resolves remote references; inline the schema instead",
                )
            for child in node.values():
                stack.append(child)
        elif isinstance(node, list):
            stack.extend(node)


# --- Loading ---------------------------------------------------------------


def _parse_tool(raw: Any, index: int) -> Tool:
    where = "tools[%d]" % index
    obj = _require_object(raw, where)

    name = obj.get("name")
    if not isinstance(name, str) or not name.strip():
        raise InputError("%s.name must be a non-empty string" % where)
    name = nfc(name)
    if len(name) > MAX_NAME_CHARS:
        raise InputError("%s.name exceeds %d characters" % (where, MAX_NAME_CHARS))

    description = obj.get("description", "")
    if description is None:
        description = ""
    if not isinstance(description, str):
        raise InputError("%s.description must be a string" % where)
    if len(description) > MAX_DESCRIPTION_CHARS:
        raise InputError("%s.description exceeds %d characters" % (where, MAX_DESCRIPTION_CHARS))

    schema = obj.get("input_schema", {})
    if schema is None:
        schema = {}
    schema = _require_object(schema, "%s.input_schema" % where)
    _check_depth(schema)
    _reject_external_refs(schema, name)

    capabilities = obj.get("capabilities", {})
    if capabilities is None:
        capabilities = {}
    capabilities = _require_object(capabilities, "%s.capabilities" % where)
    for key, value in capabilities.items():
        if not isinstance(key, str):
            raise InputError("%s.capabilities keys must be strings" % where)
        if key == "filesystem":
            if value not in FILESYSTEM_LEVELS:
                raise InputError(
                    "%s.capabilities.filesystem must be one of %s, got %r"
                    % (where, ", ".join(FILESYSTEM_LEVELS), value)
                )
        elif isinstance(value, (dict, list)):
            raise InputError("%s.capabilities.%s must be a scalar" % (where, key))

    return Tool(
        name=name,
        description=description,
        input_schema=schema,
        capabilities=capabilities,
    )


def parse_snapshot(document: Any, origin: str = "<memory>") -> Snapshot:
    """Validate a decoded JSON document and build a :class:`Snapshot`."""
    obj = _require_object(document, "snapshot")

    version = obj.get("schema_version", SNAPSHOT_SCHEMA_VERSION)
    if not isinstance(version, str):
        raise InputError("schema_version must be a string")
    if version != SNAPSHOT_SCHEMA_VERSION:
        raise InputError(
            "unsupported snapshot schema_version %r (this build understands %r)"
            % (version, SNAPSHOT_SCHEMA_VERSION),
            hint="upgrade driftguard or regenerate the snapshot",
        )

    server = obj.get("server", {})
    if server is None:
        server = {}
    server = _require_object(server, "server")

    raw_tools = obj.get("tools")
    if raw_tools is None:
        raw_tools = []
    if not isinstance(raw_tools, list):
        raise InputError("tools must be a JSON array")
    if len(raw_tools) > MAX_TOOLS:
        raise InputError("snapshot declares %d tools, limit is %d" % (len(raw_tools), MAX_TOOLS))

    tools = [_parse_tool(raw, i) for i, raw in enumerate(raw_tools)]

    # Duplicate names are not a cosmetic problem: a server that declares the
    # same tool twice can make the client resolve to the malicious definition
    # while a naive diff only sees one of them.
    seen: Dict[str, int] = {}
    for index, tool in enumerate(tools):
        if tool.name in seen:
            raise InputError(
                "duplicate tool name %r (declared at indexes %d and %d)"
                % (tool.name, seen[tool.name], index),
                hint="tool names must be unique; a shadowed tool cannot be reviewed reliably",
            )
        seen[tool.name] = index

    canonical = {
        "schema_version": version,
        "server": dict(server),
        "tools": [t.to_dict() for t in sorted(tools, key=lambda t: stable_sort_key(t.name))],
    }

    return Snapshot(
        schema_version=version,
        server=server,
        tools=tuple(sorted(tools, key=lambda t: stable_sort_key(t.name))),
        digest=sha256_hex(canonical),
        origin=origin,
    )


def load_snapshot(path: str) -> Snapshot:
    """Read and validate a snapshot from disk."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise InputError("cannot read snapshot %r: %s" % (path, exc.strerror or exc)) from None
    if size > MAX_FILE_BYTES:
        raise InputError("snapshot %r is %d bytes, limit is %d" % (path, size, MAX_FILE_BYTES))
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise InputError("cannot read snapshot %r: %s" % (path, exc.strerror or exc)) from None
    except UnicodeDecodeError as exc:
        raise InputError("snapshot %r is not valid UTF-8: %s" % (path, exc)) from None

    try:
        document = json.loads(text, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise InputError(
            "snapshot %r is not valid JSON: %s (line %d, column %d)"
            % (path, exc.msg, exc.lineno, exc.colno)
        ) from None
    except RecursionError:
        raise InputError("snapshot %r is nested too deeply to parse" % path) from None

    return parse_snapshot(document, origin=path)


def description_digest(description: str) -> str:
    """Hash of the normalised description, used to detect silent edits."""
    return sha256_hex(clean_text(description))

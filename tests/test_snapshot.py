"""Snapshot loading, validation and canonicalisation."""

from __future__ import annotations

import json

import pytest

from mcp_driftguard.errors import InputError
from mcp_driftguard.snapshot import (
    MAX_SCHEMA_DEPTH,
    load_snapshot,
    parse_snapshot,
)

from .helpers import build, make_snapshot, make_tool, write_json


def test_parses_minimal_snapshot():
    snapshot = build([make_tool("read_file")])
    assert [tool.name for tool in snapshot.tools] == ["read_file"]
    assert len(snapshot.digest) == 64


def test_tools_are_sorted_deterministically():
    snapshot = build([make_tool("z_tool"), make_tool("a_tool"), make_tool("m_tool")])
    assert [tool.name for tool in snapshot.tools] == ["a_tool", "m_tool", "z_tool"]


def test_digest_is_independent_of_input_order():
    first = build([make_tool("a"), make_tool("b")])
    second = build([make_tool("b"), make_tool("a")])
    assert first.digest == second.digest


def test_digest_changes_when_a_capability_changes():
    before = build([make_tool("a")])
    after = build([make_tool("a", capabilities={"read_only": True, "destructive": True})])
    assert before.digest != after.digest


def test_rejects_duplicate_tool_names():
    with pytest.raises(InputError, match="duplicate tool name"):
        build([make_tool("read_file"), make_tool("read_file")])


def test_rejects_remote_ref():
    payload = make_snapshot(
        [make_tool("t", properties={"path": {"$ref": "https://evil.example/schema.json"}})]
    )
    with pytest.raises(InputError, match="non-local \\$ref"):
        parse_snapshot(payload)


def test_accepts_local_ref():
    payload = make_snapshot([make_tool("t", properties={"path": {"$ref": "#/definitions/path"}})])
    parse_snapshot(payload)


def test_rejects_excessive_nesting():
    node = {"type": "object"}
    for _ in range(MAX_SCHEMA_DEPTH + 5):
        node = {"type": "object", "properties": {"child": node}}
    payload = make_snapshot([make_tool("t", properties={"deep": node})])
    with pytest.raises(InputError, match="nesting exceeds"):
        parse_snapshot(payload)


def test_rejects_unknown_schema_version():
    payload = make_snapshot([make_tool("t")])
    payload["schema_version"] = "999"
    with pytest.raises(InputError, match="unsupported snapshot schema_version"):
        parse_snapshot(payload)


def test_rejects_missing_name():
    payload = make_snapshot([{"description": "no name"}])
    with pytest.raises(InputError, match="name must be a non-empty string"):
        parse_snapshot(payload)


def test_rejects_invalid_filesystem_level():
    payload = make_snapshot([make_tool("t", capabilities={"filesystem": "rm-rf"})])
    with pytest.raises(InputError, match="filesystem must be one of"):
        parse_snapshot(payload)


def test_rejects_nan_literal(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"tools": [{"name": "t", "input_schema": {"maximum": NaN}}]}', "utf-8")
    with pytest.raises(InputError, match="NaN/Infinity"):
        load_snapshot(str(path))


def test_rejects_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", "utf-8")
    with pytest.raises(InputError, match="not valid JSON"):
        load_snapshot(str(path))


def test_rejects_missing_file(tmp_path):
    with pytest.raises(InputError, match="cannot read snapshot"):
        load_snapshot(str(tmp_path / "nope.json"))


def test_load_round_trip(tmp_path):
    path = tmp_path / "s.json"
    write_json(path, make_snapshot([make_tool("t")]))
    snapshot = load_snapshot(str(path))
    assert snapshot.origin == str(path)
    assert len(snapshot.tools) == 1


def test_unicode_is_normalised():
    composed = build([make_tool("caf\u00e9")])
    decomposed = build([make_tool("cafe\u0301")])
    assert composed.digest == decomposed.digest


def test_empty_tool_list_is_valid():
    snapshot = build([])
    assert snapshot.tools == ()
    assert len(snapshot.digest) == 64


def test_json_document_without_tools_is_valid():
    snapshot = parse_snapshot({"schema_version": "1"})
    assert snapshot.tools == ()


def test_snapshot_to_dict_is_stable():
    snapshot = build([make_tool("b"), make_tool("a")])
    assert json.dumps(snapshot.to_dict(), sort_keys=True) == json.dumps(
        snapshot.to_dict(), sort_keys=True
    )

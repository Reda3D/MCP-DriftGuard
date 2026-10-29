"""Unit tests for the small building blocks."""

from __future__ import annotations

import pytest

from mcp_driftguard.changes import CHANGE_TYPES, Change
from mcp_driftguard.normalize import (
    canonical_json,
    clean_text,
    json_pointer,
    nfc,
    sha256_file,
    sha256_hex,
    stable_sort_key,
)
from mcp_driftguard.severity import Severity, max_severity

# --- severity --------------------------------------------------------------


def test_severity_ordering():
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_severity_comparison_with_other_types_is_not_implemented():
    with pytest.raises(TypeError):
        Severity.HIGH < "CRITICAL"  # type: ignore[operator]


def test_severity_parse_is_case_insensitive():
    assert Severity.parse("high") is Severity.HIGH
    assert Severity.parse(" CRITICAL ") is Severity.CRITICAL


def test_severity_parse_rejects_unknown():
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("SEVERE")


def test_severity_parse_rejects_non_string():
    with pytest.raises(ValueError, match="must be a string"):
        Severity.parse(3)  # type: ignore[arg-type]


def test_sarif_level_mapping():
    assert Severity.INFO.sarif_level == "note"
    assert Severity.LOW.sarif_level == "note"
    assert Severity.MEDIUM.sarif_level == "warning"
    assert Severity.HIGH.sarif_level == "error"
    assert Severity.CRITICAL.sarif_level == "error"


def test_max_severity_of_empty_is_info():
    assert max_severity([]) is Severity.INFO


def test_max_severity_picks_the_highest():
    assert max_severity([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL


# --- normalisation ---------------------------------------------------------


def test_canonical_json_sorts_keys_and_drops_spaces():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_canonical_json_keeps_unicode():
    assert canonical_json({"a": "\u00e9"}) == '{"a":"\u00e9"}'


def test_sha256_hex_is_order_independent():
    assert sha256_hex({"a": 1, "b": 2}) == sha256_hex({"b": 2, "a": 1})


def test_clean_text_collapses_whitespace():
    assert clean_text("  a \n\t b  ") == "a b"


def test_nfc_composes():
    assert nfc("e\u0301") == "\u00e9"


def test_json_pointer_escapes_special_characters():
    assert json_pointer("a/b") == "/a~1b"
    assert json_pointer("a~b") == "/a~0b"


def test_json_pointer_without_parts_is_empty():
    assert json_pointer() == ""


def test_stable_sort_key_is_identity_for_nfc():
    assert stable_sort_key("abc") == "abc"


def test_sha256_file(tmp_path):
    path = tmp_path / "f.bin"
    path.write_bytes(b"drift")
    assert len(sha256_file(str(path))) == 64


# --- change model ----------------------------------------------------------


def test_change_rejects_unknown_type():
    with pytest.raises(ValueError, match="unknown change type"):
        Change(change_type="something_else", tool="t")


def test_change_to_dict_omits_empty_fields():
    payload = Change(change_type="tool_added", tool="t").to_dict()
    assert payload == {"change": "tool_added", "tool": "t"}


def test_change_to_dict_includes_capability_and_values():
    payload = Change(
        change_type="capability_escalated",
        tool="t",
        capability="destructive",
        before=False,
        after=True,
        note="n",
    ).to_dict()
    assert payload["capability"] == "destructive"
    assert payload["before"] is False
    assert payload["after"] is True
    assert payload["note"] == "n"


def test_change_sort_key_is_total():
    a = Change(change_type="tool_added", tool="b")
    b = Change(change_type="tool_added", tool="a")
    assert sorted([a, b], key=lambda c: c.sort_key())[0].tool == "a"


def test_change_types_are_unique_and_non_empty():
    assert len(CHANGE_TYPES) == len(set(CHANGE_TYPES))
    assert all(isinstance(name, str) and name for name in CHANGE_TYPES)

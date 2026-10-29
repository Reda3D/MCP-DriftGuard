"""Schema comparison branches, tested directly for precision."""

from __future__ import annotations

from mcp_driftguard.schema_diff import diff_schema


def types(changes):
    return [change.change_type for change in changes]


def test_type_replacement_is_not_a_widening():
    changes = diff_schema({"type": "string"}, {"type": "object"}, "t")
    assert types(changes) == ["schema_type_changed"]


def test_type_introduced_where_none_existed():
    changes = diff_schema({}, {"type": "string"}, "t")
    assert types(changes) == ["schema_type_changed"]


def test_type_narrowed_is_a_tightening():
    changes = diff_schema({"type": ["string", "null"]}, {"type": "string"}, "t")
    assert types(changes) == ["schema_constraint_tightened"]


def test_minimum_lowered_is_a_loosening():
    changes = diff_schema({"type": "integer", "minimum": 5}, {"type": "integer", "minimum": 1}, "t")
    assert types(changes) == ["schema_constraint_loosened"]


def test_minimum_raised_is_a_tightening():
    changes = diff_schema({"type": "integer", "minimum": 1}, {"type": "integer", "minimum": 5}, "t")
    assert types(changes) == ["schema_constraint_tightened"]


def test_minimum_removed_is_a_loosening():
    changes = diff_schema({"type": "integer", "minimum": 1}, {"type": "integer"}, "t")
    assert types(changes) == ["schema_constraint_loosened"]


def test_max_items_removed_is_a_loosening():
    changes = diff_schema({"type": "array", "maxItems": 3}, {"type": "array"}, "t")
    assert types(changes) == ["schema_constraint_loosened"]


def test_non_numeric_bound_change_is_reported_as_changed():
    changes = diff_schema({"maximum": "ten"}, {"maximum": "eleven"}, "t")
    assert types(changes) == ["schema_constraint_changed"]


def test_const_change_is_reported():
    changes = diff_schema({"const": "a"}, {"const": "b"}, "t")
    assert types(changes) == ["schema_constraint_changed"]


def test_const_removed_is_reported():
    changes = diff_schema({"const": "a"}, {}, "t")
    assert types(changes) == ["schema_constraint_changed"]


def test_format_removed_is_a_loosening():
    changes = diff_schema({"type": "string", "format": "email"}, {"type": "string"}, "t")
    assert types(changes) == ["schema_constraint_loosened"]


def test_format_changed_is_reported_as_changed():
    changes = diff_schema({"format": "email"}, {"format": "uri"}, "t")
    assert types(changes) == ["schema_constraint_changed"]


def test_pattern_changed_is_reported_as_changed():
    changes = diff_schema({"pattern": "^a$"}, {"pattern": "^b$"}, "t")
    assert types(changes) == ["schema_constraint_changed"]


def test_ref_change_is_reported():
    changes = diff_schema({"$ref": "#/a"}, {"$ref": "#/b"}, "t")
    assert types(changes) == ["schema_constraint_changed"]


def test_items_introduced_is_reported():
    changes = diff_schema({"type": "array"}, {"type": "array", "items": {"type": "string"}}, "t")
    assert types(changes) == ["schema_constraint_changed"]


def test_anyof_branch_count_change_is_reported():
    before = {"anyOf": [{"type": "string"}]}
    after = {"anyOf": [{"type": "string"}, {"type": "number"}]}
    changes = diff_schema(before, after, "t")
    assert types(changes) == ["schema_constraint_changed"]


def test_anyof_branch_is_compared_recursively():
    before = {"anyOf": [{"type": "string", "maxLength": 5}]}
    after = {"anyOf": [{"type": "string"}]}
    changes = diff_schema(before, after, "t")
    assert types(changes) == ["schema_constraint_loosened"]
    assert changes[0].path == "/anyOf/0/maxLength"


def test_identical_combinators_produce_nothing():
    schema = {"oneOf": [{"type": "string"}, {"type": "number"}]}
    assert diff_schema(schema, dict(schema), "t") == []


def test_allof_is_compared():
    before = {"allOf": [{"type": "string", "minLength": 2}]}
    after = {"allOf": [{"type": "string", "minLength": 1}]}
    changes = diff_schema(before, after, "t")
    assert types(changes) == ["schema_constraint_loosened"]


def test_additional_properties_schema_is_compared_recursively():
    before = {"additionalProperties": {"type": "string", "maxLength": 3}}
    after = {"additionalProperties": {"type": "string"}}
    changes = diff_schema(before, after, "t")
    assert types(changes) == ["schema_constraint_loosened"]


def test_additional_properties_removed_counts_as_enabled():
    changes = diff_schema({"additionalProperties": False}, {}, "t")
    assert types(changes) == ["schema_additional_properties_enabled"]


def test_additional_properties_disabled_counts_as_tightening():
    changes = diff_schema({}, {"additionalProperties": False}, "t")
    assert types(changes) == ["schema_constraint_tightened"]


def test_enum_removed_is_reported_as_changed():
    changes = diff_schema({"enum": ["a"]}, {}, "t")
    assert types(changes) == ["schema_constraint_changed"]


def test_enum_replaced_is_reported_as_changed():
    changes = diff_schema({"enum": ["a"]}, {"enum": ["b"]}, "t")
    assert types(changes) == ["schema_constraint_changed"]


def test_enum_narrowed_is_a_tightening():
    changes = diff_schema({"enum": ["a", "b"]}, {"enum": ["a"]}, "t")
    assert types(changes) == ["schema_constraint_tightened"]


def test_property_definition_replaced_with_non_object_is_reported():
    changes = diff_schema(
        {"properties": {"a": True}}, {"properties": {"a": {"type": "string"}}}, "t"
    )
    assert types(changes) == ["schema_constraint_changed"]


def test_paths_are_json_pointers():
    changes = diff_schema(
        {"properties": {"a/b": {"type": "string", "maxLength": 1}}},
        {"properties": {"a/b": {"type": "string"}}},
        "t",
    )
    assert changes[0].path == "/properties/a~1b/maxLength"


def test_identical_schemas_produce_nothing():
    schema = {
        "type": "object",
        "properties": {"a": {"type": "string", "minLength": 1}},
        "required": ["a"],
        "additionalProperties": False,
    }
    assert diff_schema(schema, dict(schema), "t") == []

"""CLI contract: exit codes and produced artefacts."""

from __future__ import annotations

import json

from mcp_driftguard.cli import main

from .helpers import make_snapshot, make_tool, write_json


def write_pair(tmp_path, before_tools, after_tools):
    baseline = tmp_path / "baseline.json"
    candidate = tmp_path / "candidate.json"
    write_json(baseline, make_snapshot(before_tools))
    write_json(candidate, make_snapshot(after_tools))
    return str(baseline), str(candidate)


def test_exit_zero_when_nothing_changed(tmp_path, capsys):
    baseline, candidate = write_pair(tmp_path, [make_tool("a")], [make_tool("a")])
    code = main(["check", "--baseline", baseline, "--candidate", candidate, "--quiet"])
    assert code == 0


def test_exit_one_when_a_high_finding_exists(tmp_path, capsys):
    baseline, candidate = write_pair(
        tmp_path,
        [make_tool("a", properties={"x": {"type": "integer", "maximum": 5}})],
        [make_tool("a", properties={"x": {"type": "integer"}})],
    )
    code = main(["check", "--baseline", baseline, "--candidate", candidate, "--quiet"])
    assert code == 1


def test_exit_two_on_missing_baseline(tmp_path, capsys):
    _, candidate = write_pair(tmp_path, [], [])
    code = main(
        ["check", "--baseline", str(tmp_path / "nope.json"), "--candidate", candidate, "--quiet"]
    )
    assert code == 2
    assert "cannot read snapshot" in capsys.readouterr().err


def test_exit_three_on_invalid_policy(tmp_path, capsys):
    baseline, candidate = write_pair(tmp_path, [], [make_tool("a")])
    policy = tmp_path / "p.yml"
    policy.write_text(
        "version: 1\nrules:\n  - {id: R1, description: x, severity: LOW, match: {change: nope}}\n",
        encoding="utf-8",
    )
    code = main(
        [
            "check",
            "--baseline",
            baseline,
            "--candidate",
            candidate,
            "--policy",
            str(policy),
            "--quiet",
        ]
    )
    assert code == 3
    assert "unknown change type" in capsys.readouterr().err


def test_writes_markdown_and_json_outputs(tmp_path):
    baseline, candidate = write_pair(tmp_path, [], [make_tool("a")])
    md_path = tmp_path / "report.md"
    json_path = tmp_path / "report.json"
    main(
        [
            "check",
            "--baseline",
            baseline,
            "--candidate",
            candidate,
            "--output",
            str(md_path),
            "--json-out",
            str(json_path),
            "--quiet",
        ]
    )
    assert md_path.read_text(encoding="utf-8").startswith("# MCP DriftGuard report")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["summary"]["total_changes"] == 1


def test_json_format_goes_to_stdout(tmp_path, capsys):
    baseline, candidate = write_pair(tmp_path, [], [make_tool("a")])
    main(["check", "--baseline", baseline, "--candidate", candidate, "--format", "json"])
    out = capsys.readouterr().out
    assert json.loads(out)["tool"] == "mcp-driftguard"


def test_fail_on_override_lowers_the_threshold(tmp_path):
    baseline, candidate = write_pair(tmp_path, [], [make_tool("a")])
    assert main(["check", "--baseline", baseline, "--candidate", candidate, "--quiet"]) == 0
    assert (
        main(
            [
                "check",
                "--baseline",
                baseline,
                "--candidate",
                candidate,
                "--fail-on",
                "LOW",
                "--quiet",
            ]
        )
        == 1
    )


def test_init_writes_a_policy_and_refuses_to_overwrite(tmp_path):
    target = tmp_path / "driftguard.yml"
    assert main(["init", "--output", str(target)]) == 0
    assert "fail_on" in target.read_text(encoding="utf-8")
    assert main(["init", "--output", str(target)]) == 2
    assert main(["init", "--output", str(target), "--force"]) == 0


def test_init_policy_is_loadable(tmp_path):
    from mcp_driftguard.policy import load_policy

    target = tmp_path / "driftguard.yml"
    main(["init", "--output", str(target)])
    policy = load_policy(str(target))
    assert len(policy.rules) >= 5


def test_validate_reports_tools(tmp_path, capsys):
    baseline, _ = write_pair(tmp_path, [make_tool("a")], [])
    assert main(["validate", baseline]) == 0
    assert "1 tools" in capsys.readouterr().out


def test_hash_prints_a_digest(tmp_path, capsys):
    baseline, _ = write_pair(tmp_path, [make_tool("a")], [])
    assert main(["hash", baseline]) == 0
    line = capsys.readouterr().out.strip()
    digest, path = line.split("  ")
    assert len(digest) == 64
    assert path == baseline


def test_version_subcommand(capsys):
    assert main(["version"]) == 0
    assert "mcp-driftguard" in capsys.readouterr().out

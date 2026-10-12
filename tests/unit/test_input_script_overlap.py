"""Consolidate only a witnessed shared input splice, retaining policy fallbacks."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from taintly.engine import (
    _bind_input_script_sinks,
    coalesce_input_script_findings,
    scan_file,
    scan_repo,
)
from taintly.models import Finding, Platform, Severity

PAIR = {"SEC4-GH-008", "SEC4-GH-025"}
ROOT = Path(__file__).resolve().parents[2]


def _workflow(tmp_path, expression="inputs.package", *, inline=False, extra=""):
    path = tmp_path / ".github" / "workflows" / "input.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    script = "const value = '${{ " + expression + " }}';"
    script_field = (
        "          script: " + script + "\n"
        if inline
        else "          script: |\n            " + script + "\n"
    )
    path.write_text(
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      package:\n"
        "        type: string\n"
        "  workflow_call:\n"
        "    inputs:\n"
        "      package:\n"
        "        type: string\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/github-script@v7\n        with:\n" + script_field + extra,
        encoding="utf-8",
    )
    return path


def _pair(findings):
    return [f for f in findings if f.rule_id in PAIR]


def _cli(tmp_path, *options, config=False):
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [
            sys.executable,
            "-S",
            "-m",
            "taintly",
            str(tmp_path),
            "--platform",
            "github",
            "--no-color",
            *([] if config else ["--no-config"]),
            *options,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize(
    ("expression", "expected_raw_ids"),
    [
        ("inputs.package", PAIR),
        # Public 025 delegates event.inputs to 008; retain that fallback.
        ("github.event.inputs.package", {"SEC4-GH-008"}),
    ],
)
@pytest.mark.parametrize("inline", [False, True])
def test_repo_consolidates_only_the_shared_javascript_splice(
    tmp_path, github_rules, expression, expected_raw_ids, inline
):
    path = _workflow(tmp_path, expression, inline=inline)
    raw = _pair(scan_file(str(path), github_rules))
    assert {f.rule_id for f in raw} == expected_raw_ids
    report = scan_repo(str(tmp_path), github_rules, Platform.GITHUB)[0]
    findings = _pair(report.findings)
    expected_id = "SEC4-GH-025" if "SEC4-GH-025" in expected_raw_ids else "SEC4-GH-008"
    assert [f.rule_id for f in findings] == [expected_id]
    assert findings[0] == next(f for f in raw if f.rule_id == expected_id)
    if expected_id == "SEC4-GH-025":
        assert "process.env" in findings[0].remediation


def test_unsupported_expression_and_distinct_shell_sink_survive(tmp_path, github_rules):
    _workflow(
        tmp_path, "inputs.package || 'default'", extra="      - run: echo ${{ inputs.package }}\n"
    )
    findings = _pair(scan_repo(str(tmp_path), github_rules, Platform.GITHUB)[0].findings)
    assert len([f for f in findings if f.rule_id == "SEC4-GH-008"]) == 2


def test_same_line_different_sources_are_not_coalesced(tmp_path, github_rules):
    path = _workflow(tmp_path)
    path.write_text(
        path.read_text().replace(
            "${{ inputs.package }}",
            "${{ github.event.issue.title }} ${{ inputs.package || 'default' }}",
        ),
        encoding="utf-8",
    )
    findings = _pair(scan_repo(str(tmp_path), github_rules, Platform.GITHUB)[0].findings)
    assert {f.rule_id for f in findings} == PAIR


def test_distinct_shell_sink_and_two_javascript_sites_survive(tmp_path, github_rules):
    _workflow(
        tmp_path,
        extra="      - run: echo ${{ inputs.package }}\n      - uses: actions/github-script@v7\n        with:\n          script: console.log('${{ inputs.package }}')\n",
    )
    findings = _pair(scan_repo(str(tmp_path), github_rules, Platform.GITHUB)[0].findings)
    assert [f.rule_id for f in findings].count("SEC4-GH-008") == 1
    assert [f.rule_id for f in findings].count("SEC4-GH-025") == 2
    assert len({f.line for f in findings}) == 3


def test_disabled_canonical_rule_and_raw_api_keep_fallback(tmp_path, github_rules):
    _workflow(tmp_path)
    rules = [r for r in github_rules if r.id != "SEC4-GH-025"]
    findings = _pair(scan_repo(str(tmp_path), rules, Platform.GITHUB)[0].findings)
    assert [f.rule_id for f in findings] == ["SEC4-GH-008"]
    raw = scan_repo(str(tmp_path), github_rules, Platform.GITHUB, coalesce_overlaps=False)[0]
    assert {f.rule_id for f in _pair(raw.findings)} == PAIR


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("file", "other.yml"),
        ("line", 2),
        ("snippet", "different"),
        ("confidence", "low"),
        ("review_needed", True),
        ("severity", Severity.MEDIUM),
        ("exploitability", "low"),
        ("context_notes", ["distinct evidence"]),
        ("context_tags", ["distinct-context"]),
        ("discovery_confidence", "low"),
        ("calibration_reason", "unknown authority"),
        ("origin", "cross-workflow"),
    ],
)
def test_different_witness_or_evidence_metadata_is_retained(field, value):
    first = Finding(
        "SEC4-GH-008",
        Severity.HIGH,
        "shell",
        "",
        "f.yml",
        1,
        snippet="const value = '${{ inputs.package }}';",
        _input_script_sink=("build", 0),
    )
    second = replace(first, rule_id="SEC4-GH-025", **{field: value})
    assert coalesce_input_script_findings([first, second]) == [first, second]


@pytest.mark.parametrize(
    "expression",
    ["inputs['package']", "inputs.package || ''", "inputs.package }} ${{ inputs.other"],
)
def test_unproven_expression_coverage_retains_both(expression):
    first = Finding(
        "SEC4-GH-008",
        Severity.HIGH,
        "shell",
        "",
        "f.yml",
        1,
        snippet="const value = '${{ " + expression + " }}';",
        _input_script_sink=("build", 0),
    )
    second = replace(first, rule_id="SEC4-GH-025")
    assert coalesce_input_script_findings([first, second]) == [first, second]


@pytest.mark.parametrize("owner", [None, ("other_job", 0), ("build", 1)])
def test_unknown_or_distinct_owner_retains_both(owner):
    first = Finding(
        "SEC4-GH-008",
        Severity.HIGH,
        "shell",
        "",
        "f.yml",
        1,
        snippet="const value = '${{ inputs.package }}';",
        _input_script_sink=("build", 0),
    )
    second = replace(first, rule_id="SEC4-GH-025", _input_script_sink=owner)
    assert coalesce_input_script_findings([first, second]) == [first, second]


@pytest.mark.parametrize(
    ("options", "config"),
    [
        (["--exclude-rule", "SEC4-GH-025"], False),
        ([], True),
    ],
)
def test_cli_disabled_or_config_ignored_canonical_keeps_fallback(tmp_path, options, config):
    _workflow(tmp_path)
    if config:
        (tmp_path / ".taintly.yml").write_text(
            "version: 1\nignore:\n  - id: SEC4-GH-025\n    reason: reviewed separately\n",
            encoding="utf-8",
        )
    result = _cli(tmp_path, "--format", "json", *options, config=config)
    assert result.returncode == 1, result.stderr.decode()
    assert [
        f["rule_id"] for f in json.loads(result.stdout)["findings"] if f["rule_id"] in PAIR
    ] == ["SEC4-GH-008"]


@pytest.mark.parametrize("output_format", ["json", "sarif", "text"])
def test_cli_output_retains_javascript_remediation_without_duplicate(tmp_path, output_format):
    _workflow(tmp_path)
    result = _cli(tmp_path, "--format", output_format)
    assert result.returncode == 1, result.stderr.decode()
    output = result.stdout.decode("utf-8")
    assert "process.env" in output
    if output_format == "json":
        assert [f["rule_id"] for f in json.loads(output)["findings"] if f["rule_id"] in PAIR] == [
            "SEC4-GH-025"
        ]
    if output_format == "sarif":
        assert [
            f["ruleId"] for f in json.loads(output)["runs"][0]["results"] if f["ruleId"] in PAIR
        ] == ["SEC4-GH-025"]
    if output_format == "text":
        assert "] SEC4-GH-008:" not in output
        assert "] SEC4-GH-025:" in output


def test_canonical_baseline_does_not_resurrect_duplicate(tmp_path):
    _workflow(tmp_path)
    baseline = tmp_path / "baseline.json"
    saved = _cli(tmp_path, "--baseline", str(baseline), "--format", "json")
    assert saved.returncode == 0, saved.stderr.decode()
    result = _cli(tmp_path, "--diff", str(baseline), "--format", "json")
    assert result.returncode == 0, result.stderr.decode()
    assert not [f for f in json.loads(result.stdout)["findings"] if f["rule_id"] in PAIR]


def test_inline_ignored_canonical_keeps_fallback(tmp_path, github_rules):
    path = _workflow(tmp_path)
    path.write_text(
        path.read_text().replace("}}';", "}}'; // # taintly: ignore[SEC4-GH-025]"),
        encoding="utf-8",
    )
    findings = _pair(scan_repo(str(tmp_path), github_rules, Platform.GITHUB)[0].findings)
    assert [f.rule_id for f in findings] == ["SEC4-GH-008"]


def test_action_shaped_shell_heredoc_is_not_a_javascript_ownership_witness(tmp_path, github_rules):
    path = _workflow(tmp_path)
    content = path.read_text().replace("  workflow_call:\n", "  pull_request:\n  workflow_call:\n")
    content = content[: content.index("      - uses:")] + (
        "      - run: |\n"
        "          cat <<'EOF'\n"
        "            uses: actions/github-script@v7\n"
        "            with:\n"
        "              script: ${{ inputs.package }}\n"
        "          EOF\n"
    )
    path.write_text(content, encoding="utf-8")
    raw = _pair(scan_file(str(path), github_rules))
    assert {f.rule_id for f in raw} == PAIR
    assert len({(f.file, f.line, f.snippet, f.severity, f.confidence) for f in raw}) == 1
    assert all(f._input_script_sink is None for f in raw)
    assert coalesce_input_script_findings(raw) == raw
    assert {
        f.rule_id
        for f in _pair(scan_repo(str(tmp_path), github_rules, Platform.GITHUB)[0].findings)
    } == PAIR


def test_unknown_structural_ownership_retains_both(tmp_path, github_rules, monkeypatch):
    from taintly.parsers import structural

    path = _workflow(tmp_path)
    raw = _pair(scan_file(str(path), github_rules))
    assert len(coalesce_input_script_findings(raw)) == 1
    unknown = [replace(f, _input_script_sink=None) for f in raw]

    def unsupported(*args, **kwargs):
        raise ValueError("unsupported structure")

    monkeypatch.setattr(structural, "walk_workflow", unsupported)
    _bind_input_script_sinks(unknown, path.read_text())
    assert coalesce_input_script_findings(unknown) == unknown


def test_binding_uses_scanned_content_without_rereading_file(tmp_path, github_rules):
    path = _workflow(tmp_path)
    content = path.read_text()
    path.write_text("on: push\njobs: {}\n", encoding="utf-8")
    raw = _pair(scan_file(str(path), github_rules, _content=content))
    assert len(raw) == 2
    assert all(f._input_script_sink == ("build", 0) for f in raw)
    assert [f.rule_id for f in coalesce_input_script_findings(raw)] == ["SEC4-GH-025"]
    assert all("_input_script_sink" not in f.to_dict() for f in raw)

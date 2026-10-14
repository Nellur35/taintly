"""Env bytes must be classified by their use, not merely lack of quotes."""

from __future__ import annotations

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform, Severity


def _scan(tmp_path, github_rules, command):
    workflow = tmp_path / ".github" / "workflows" / "control.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: pull_request_target\npermissions:\n  contents: write\njobs:\n  inspect:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - shell: bash\n        env:\n"
        "          TITLE: ${{ github.event.pull_request.title }}\n        run: "
        + command
        + "\n",
        encoding="utf-8",
    )
    rules = [
        rule
        for rule in github_rules
        if rule.id in {"TAINT-GH-001", "TAINT-GH-012", "CHAIN-GH-103"}
    ]
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)
    assert len(reports) == 1
    assert reports[0].files_scanned == 1
    assert reports[0].engine_errors() == []
    return reports[0].findings


def _review_data(findings, command):
    # Keep the legacy signal and source path; qualify its actual data use.
    matches = [finding for finding in findings if finding.rule_id == "TAINT-GH-001"]
    assert len(matches) == 1
    finding = matches[0]
    assert finding.line == 11
    assert "github.event.pull_request.title -> env.TITLE" in finding.snippet
    assert command in finding.snippet
    assert finding.severity == Severity.MEDIUM
    assert finding.review_needed is True
    assert finding.confidence in {"low", "medium"}
    assert finding.exploitability != "high"
    assert not any(f.rule_id == "CHAIN-GH-103" for f in findings)


@pytest.mark.parametrize("command", ["printf '%s\\n' $TITLE", "COPY=$TITLE"])
def test_argument_and_assignment_data_keep_review_without_execution_upgrade(
    tmp_path, github_rules, command
):
    _review_data(_scan(tmp_path, github_rules, command), command)


def test_literal_eval_argument_is_not_a_code_operand(tmp_path, github_rules):
    command = "printf '%s\\n' 'eval' \"$TITLE\""
    _review_data(_scan(tmp_path, github_rules, command), command)


def test_quoted_value_piped_into_shell_is_execution_not_safe_lint(tmp_path, github_rules):
    command = "printf '%s\\n' \"$TITLE\" | sh"
    findings = _scan(tmp_path, github_rules, command)
    matches = [finding for finding in findings if finding.rule_id == "TAINT-GH-001"]
    assert len(matches) == 1
    assert matches[0].line == 11 and command in matches[0].snippet
    assert matches[0].severity == Severity.CRITICAL
    assert matches[0].confidence == "high"
    assert matches[0].review_needed is False
    assert not any(finding.rule_id == "TAINT-GH-012" for finding in findings)
    assert len([finding for finding in findings if finding.rule_id == "CHAIN-GH-103"]) == 1


@pytest.mark.parametrize(
    "command",
    [
        'eval "$TITLE"',
        'sh -c "$TITLE"',
        'bash -c "$TITLE"',
        "printf '%s\\n' \"${{ env.TITLE }}\"",
        "$TITLE",
    ],
)
def test_real_code_roles_keep_existing_execution_coverage(tmp_path, github_rules, command):
    findings = _scan(tmp_path, github_rules, command)
    matches = [finding for finding in findings if finding.rule_id == "TAINT-GH-001"]
    assert len(matches) == 1
    assert matches[0].line == 11 and command in matches[0].snippet
    assert matches[0].severity == Severity.CRITICAL
    assert matches[0].confidence == "high"
    assert matches[0].review_needed is False
    assert not any(finding.rule_id == "TAINT-GH-012" for finding in findings)
    assert len([finding for finding in findings if finding.rule_id == "CHAIN-GH-103"]) == 1

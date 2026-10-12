"""Trigger + token-consumer co-occurrence is not attacker execution proof."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import AuditReport, Platform, Severity
from taintly.reporters.json_report import format_json
from taintly.reporters.sarif import format_sarif
from taintly.reporters.text import format_text
from taintly.rules.registry import load_all_rules
from taintly.scorer import compute_score


@pytest.fixture(scope="module")
def rules():
    return load_all_rules()


def _scan(
    tmp_path,
    rules,
    *,
    inputs="",
    execution="",
    permissions="contents: write",
    event="pull_request_target",
):
    workflow = tmp_path / ".github/workflows/example.yml"
    workflow.parent.mkdir(parents=True)
    content = "on: " + event + "\n"
    if permissions is not None:
        content += "permissions:\n  " + permissions + "\n"
    content += (
        "jobs:\n  example:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        + inputs
        + execution
        + "      - run: git push origin HEAD:main\n"
    )
    workflow.write_text(content, encoding="utf-8")
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)
    assert not [f for r in reports for f in r.engine_errors()]
    return [f for r in reports for f in r.findings if f.rule_id == "CHAIN-GH-101"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {},  # default trusted-base checkout, fixed trusted command
        {"inputs": "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"},
        {
            "inputs": "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
            "execution": "      - run: make test\n",
        },  # risky shape still remains visible
        {"permissions": None},  # repository default is not in workflow bytes
        {"inputs": "        with:\n          token: ${{ secrets.RELEASE_PAT }}\n"},
        {"event": "issue_comment"},
        {"event": "\n  workflow_run:\n    workflows: [Missing]\n    types: [completed]"},
    ],
)
def test_incomplete_chain_keeps_candidate_without_inventing_execution(
    tmp_path: Path, rules, kwargs
):
    findings = _scan(tmp_path, rules, **kwargs)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.review_needed is True
    assert finding.confidence == "medium"
    assert "not proven" in finding.snippet
    assert "job 'example'" in finding.snippet
    assert f"anchor line {finding.line}" in finding.snippet
    assert "execution-unproven" in finding.context_tags
    assert "credential-authority-unproven" in finding.context_tags
    assert "does not prove" in finding.calibration_reason
    assert finding.context_notes
    assert "not a confirmed pwn request" in finding.description
    assert "If an external contributor" in finding.threat_narrative
    assert "effective scopes" in finding.remediation
    rendered_claims = " ".join((finding.snippet, finding.description, finding.threat_narrative))
    assert "A PR from a fork executes code" not in rendered_claims
    assert "The fork's code is checked out" not in rendered_claims
    assert "now arbitrary writes" not in rendered_claims


@pytest.mark.parametrize(
    "kwargs",
    [
        {"permissions": "contents: read"},
        {"event": "pull_request"},
        {"inputs": "        with:\n          persist-credentials: false\n"},
    ],
)
def test_existing_chain_exclusions_still_apply(tmp_path: Path, rules, kwargs):
    assert _scan(tmp_path, rules, **kwargs) == []


def test_reports_and_scoring_preserve_incomplete_evidence(tmp_path: Path, rules):
    (finding,) = _scan(tmp_path, rules)
    report = AuditReport(
        repo_path=str(tmp_path), platform="github", findings=[finding], files_scanned=1
    )
    score = compute_score(report.findings, files_scanned=1)
    assert score.distinct_risks == 0
    assert score.review_needed == 1
    payload = json.loads(format_json(report))
    assert payload["distinct_risk_count"] == 0
    assert payload["review_needed_count"] == 1
    assert payload["findings"][0]["review_needed"] is True
    sarif = json.loads(format_sarif(report))
    (result,) = sarif["runs"][0]["results"]
    assert result["ruleId"] == "CHAIN-GH-101"
    assert result["properties"]["review_needed"] is True
    text = format_text(report, use_color=False)
    assert "does not prove" in text
    assert "Review:" in text

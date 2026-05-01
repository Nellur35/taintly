from __future__ import annotations

import json

from taintly.deployment_context import (
    DeploymentContext,
    apply_context_notes,
    load_deployment_context,
)
from taintly.models import AuditReport, Finding, Severity
from taintly.reporters.json_report import format_json
from taintly.reporters.text import format_text


def _finding(family: str = "privileged_pr_trigger") -> Finding:
    return Finding(
        rule_id="TEST",
        severity=Severity.HIGH,
        title="Test finding",
        description="Test description",
        file=".github/workflows/ci.yml",
        line=7,
        snippet="run: echo test",
        finding_family=family,
    )


def test_load_deployment_context_from_repo_file(tmp_path):
    (tmp_path / ".taintly-context.yml").write_text(
        "repo_visibility: private\n"
        "external_prs: blocked\n"
        "runner_topology: isolated_self_hosted\n"
        "secret_scoping: oidc_only\n",
        encoding="utf-8",
    )

    ctx = load_deployment_context(str(tmp_path))

    assert ctx.repo_visibility == "private"
    assert ctx.external_prs == "blocked"
    assert ctx.runner_topology == "isolated_self_hosted"
    assert ctx.secret_scoping == "oidc_only"


def test_context_notes_do_not_mutate_severity():
    finding = _finding()

    apply_context_notes(finding, DeploymentContext(external_prs="blocked"))

    assert finding.severity == Severity.HIGH
    assert finding.triage_needed is True
    assert finding.context_tags == ["external_prs:blocked"]
    assert finding.context_notes == [
        "Exploitability may be over-weighted for deployments without open external PRs."
    ]


def test_context_notes_surface_in_json_and_text():
    finding = _finding("credential_persistence")
    apply_context_notes(finding, DeploymentContext(secret_scoping="oidc_only"))
    report = AuditReport(repo_path="/repo", platform="github")
    report.add(finding)
    report.summarize()

    data = json.loads(format_json(report))
    text = format_text(report, use_color=False, verbose=True)

    assert data["findings"][0]["triage_needed"] is True
    assert data["findings"][0]["context_tags"] == ["secret_scoping:oidc_only"]
    assert "Long-lived credential assumptions may not hold" in text
    assert "[triage-needed]" in text

"""Regression tests for job-scoped GitHub chain composition."""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def _chain_101_findings(tmp_path: Path, workflow_permissions: str, job_permissions: str) -> list:
    workflow = (
        "on: pull_request_target\n"
        "permissions:\n"
        f"  contents: {workflow_permissions}\n"
        "jobs:\n"
        "  vulnerable:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        f"      contents: {job_permissions}\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: git push origin HEAD:main\n"
    )
    path = tmp_path / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True)
    path.write_text(workflow, encoding="utf-8")

    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITHUB)
    return [f for report in reports for f in report.findings if f.rule_id == "CHAIN-GH-101"]


def test_chain_gh_101_uses_the_vulnerable_jobs_read_only_permissions(tmp_path: Path) -> None:
    """Workflow-level write must not override a read-only vulnerable job."""
    assert _chain_101_findings(tmp_path, "write", "read") == []


def test_chain_gh_101_uses_the_vulnerable_jobs_write_permissions(tmp_path: Path) -> None:
    """Workflow-level read must not hide a write-capable vulnerable job."""
    findings = _chain_101_findings(tmp_path, "read", "write")
    assert len(findings) == 1


def test_chain_gh_101_ignores_a_trusted_bot_gate_in_a_sibling_job(tmp_path: Path) -> None:
    """A guarded sibling must not suppress an exposed vulnerable job."""
    workflow = (
        "on: pull_request_target\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  vulnerable:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: git push origin HEAD:main\n"
        "  bot_only:\n"
        "    if: github.actor == 'dependabot[bot]'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo safe\n"
    )
    path = tmp_path / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True)
    path.write_text(workflow, encoding="utf-8")

    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITHUB)
    findings = [
        finding
        for report in reports
        for finding in report.findings
        if finding.rule_id == "CHAIN-GH-101"
    ]
    assert len(findings) == 1

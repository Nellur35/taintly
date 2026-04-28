"""Shared pytest fixtures for taintly test suite."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from taintly.models import AuditReport, Finding, Severity
from taintly.rules.registry import load_all_rules

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def all_rules():
    """Load all rules once per test session."""
    return load_all_rules()


@pytest.fixture(scope="session")
def github_rules(all_rules):
    from taintly.models import Platform
    return [r for r in all_rules if r.platform == Platform.GITHUB]


@pytest.fixture(scope="session")
def gitlab_rules(all_rules):
    from taintly.models import Platform
    return [r for r in all_rules if r.platform == Platform.GITLAB]


@pytest.fixture(scope="session")
def jenkins_rules(all_rules):
    from taintly.models import Platform
    return [r for r in all_rules if r.platform == Platform.JENKINS]


@pytest.fixture
def tmp_yaml(tmp_path):
    """Factory: write YAML content to a temp file, return path."""
    def _write(content: str, suffix: str = ".yml") -> str:
        p = tmp_path / f"workflow{suffix}"
        p.write_text(content, encoding="utf-8")
        return str(p)
    return _write


@pytest.fixture
def one_finding():
    """A minimal Finding for reporter tests."""
    return Finding(
        rule_id="SEC3-GH-001",
        severity=Severity.HIGH,
        title="Unpinned action",
        description="Action referenced by mutable tag.",
        file=".github/workflows/ci.yml",
        line=12,
        snippet="      - uses: actions/checkout@v4",
        remediation="Pin to a full commit SHA.",
        reference="https://example.com",
        owasp_cicd="CICD-SEC-3",
    )


@pytest.fixture
def one_report(one_finding):
    """A minimal AuditReport with one finding."""
    report = AuditReport(repo_path="/repo", platform="github")
    report.add(one_finding)
    report.summarize()
    return report


@pytest.fixture
def empty_report():
    """An AuditReport with no findings."""
    report = AuditReport(repo_path="/repo", platform="github")
    report.summarize()
    return report

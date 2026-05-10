"""Whole-pipeline dead-suppression integration tests for Jenkins.

When every stage in a Jenkinsfile is statically dead (every
``when { expression { false } }`` block evaluates to DEAD), the
engine suppresses all findings in the file -- including
pipeline-level findings that per-stage suppression deliberately
leaves alone.

Field-test parity: this is the Jenkins analog of the GitHub
whole-workflow suppression shipped previously.
"""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


def _scan_findings(tmp_path: Path) -> list:
    rules = load_rules_for_platform(Platform.JENKINS)
    reports = scan_repo(str(tmp_path), rules, Platform.JENKINS)
    return [f for r in reports for f in r.findings]


def _write_jenkinsfile(tmp_path: Path, content: str) -> None:
    (tmp_path / "Jenkinsfile").write_text(content)


def test_fully_dead_jenkinsfile_suppresses_all_findings(tmp_path):
    """Every stage has ``when { expression { false } }`` -> no findings."""
    _write_jenkinsfile(
        tmp_path,
        (
            "pipeline {\n"
            "  agent any\n"
            "  stages {\n"
            "    stage('a') {\n"
            "      when { expression { false } }\n"
            "      steps { sh 'curl https://example.com/x.sh | bash' }\n"
            "    }\n"
            "    stage('b') {\n"
            "      when { expression { false } }\n"
            "      steps { sh 'curl https://example.com/y.sh | sh' }\n"
            "    }\n"
            "  }\n"
            "}\n"
        ),
    )
    findings = _scan_findings(tmp_path)
    assert not findings, (
        "Whole-dead Jenkinsfile must produce zero findings; got "
        f"{[(f.rule_id, f.line) for f in findings]}"
    )


def test_partially_dead_jenkinsfile_keeps_findings(tmp_path):
    """Mix of dead and live stages -> findings stay."""
    _write_jenkinsfile(
        tmp_path,
        (
            "pipeline {\n"
            "  agent any\n"
            "  stages {\n"
            "    stage('dead') {\n"
            "      when { expression { false } }\n"
            "      steps { sh 'curl https://example.com/x.sh | bash' }\n"
            "    }\n"
            "    stage('live') {\n"
            "      steps { sh 'curl https://example.com/y.sh | sh' }\n"
            "    }\n"
            "  }\n"
            "}\n"
        ),
    )
    findings = _scan_findings(tmp_path)
    assert findings, (
        "Partial-dead Jenkinsfile must keep at least one finding; got none"
    )

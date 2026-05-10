"""Whole-pipeline dead-suppression integration tests for GitLab.

When every job in a ``.gitlab-ci.yml`` is statically dead (every
``when: never`` rule chain matches unconditionally), the engine
suppresses all findings in the file -- including pipeline-level
findings that per-job suppression deliberately leaves alone.

Field-test parity: this is the GitLab analog of the GitHub
whole-workflow suppression shipped previously.  Same shape,
different syntax.
"""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


def _scan_findings(tmp_path: Path) -> list:
    rules = load_rules_for_platform(Platform.GITLAB)
    reports = scan_repo(str(tmp_path), rules, Platform.GITLAB)
    return [f for r in reports for f in r.findings]


def _write_pipeline(tmp_path: Path, content: str) -> None:
    (tmp_path / ".gitlab-ci.yml").write_text(content)


def test_fully_dead_pipeline_suppresses_all_findings(tmp_path):
    """Every job has bare ``when: never`` -> no findings."""
    _write_pipeline(
        tmp_path,
        (
            "stages:\n"
            "  - test\n"
            "\n"
            "job_a:\n"
            "  stage: test\n"
            "  rules:\n"
            "    - when: never\n"
            "  script:\n"
            "    - echo \"$CI_COMMIT_TITLE\"\n"
            "\n"
            "job_b:\n"
            "  stage: test\n"
            "  rules:\n"
            "    - when: never\n"
            "  script:\n"
            "    - echo b\n"
        ),
    )
    findings = _scan_findings(tmp_path)
    assert not findings, (
        "Whole-dead pipeline must produce zero findings; got "
        f"{[(f.rule_id, f.line) for f in findings]}"
    )


def test_partially_dead_pipeline_keeps_pipeline_findings(tmp_path):
    """Mix of dead and live jobs -> pipeline-level findings stay."""
    _write_pipeline(
        tmp_path,
        (
            "stages:\n"
            "  - test\n"
            "\n"
            "dead_job:\n"
            "  stage: test\n"
            "  rules:\n"
            "    - when: never\n"
            "  script:\n"
            "    - echo \"$CI_COMMIT_TITLE\"\n"
            "\n"
            "live_job:\n"
            "  stage: test\n"
            "  script:\n"
            "    - echo \"$CI_COMMIT_TITLE\"\n"
        ),
    )
    findings = _scan_findings(tmp_path)
    assert findings, (
        "Mixed-dead pipeline must keep pipeline-level findings; got none"
    )

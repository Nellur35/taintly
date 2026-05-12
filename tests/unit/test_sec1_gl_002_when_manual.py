"""SEC1-GL-002 security-job manual gate weakening coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


@pytest.fixture(scope="module")
def gitlab_rules():
    return load_rules_for_platform(Platform.GITLAB)


def _write_ci(tmp_path: Path, content: str) -> Path:
    target = tmp_path / ".gitlab-ci.yml"
    target.write_text(content, encoding="utf-8")
    return target


def _sec1_gl_002_findings(tmp_path: Path, content: str, gitlab_rules) -> list:
    ci = _write_ci(tmp_path, content)
    return [f for f in scan_file(str(ci), gitlab_rules) if f.rule_id == "SEC1-GL-002"]


def test_sast_job_when_manual_fires(tmp_path, gitlab_rules):
    findings = _sec1_gl_002_findings(
        tmp_path,
        "sast:\n"
        "  stage: security\n"
        "  script:\n"
        "    - semgrep --config=auto .\n"
        "  when: manual\n",
        gitlab_rules,
    )

    assert findings, "security scanner job made manual must fire SEC1-GL-002"
    assert findings[0].line == 5


def test_secret_detection_job_when_manual_fires(tmp_path, gitlab_rules):
    findings = _sec1_gl_002_findings(
        tmp_path,
        "secret_detection:\n"
        "  stage: security\n"
        "  image: registry.gitlab.com/security-products/secret-detection:4\n"
        "  script:\n"
        "    - /analyzer run\n"
        "  when: manual\n",
        gitlab_rules,
    )

    assert findings


def test_dependency_scanning_job_when_manual_fires(tmp_path, gitlab_rules):
    findings = _sec1_gl_002_findings(
        tmp_path,
        "dependency_scanning:\n"
        "  stage: security\n"
        "  script:\n"
        "    - /analyzer run\n"
        "  when: manual\n",
        gitlab_rules,
    )

    assert findings


def test_deploy_job_when_manual_does_not_fire(tmp_path, gitlab_rules):
    findings = _sec1_gl_002_findings(
        tmp_path,
        "deploy_prod:\n"
        "  stage: deploy\n"
        "  script:\n"
        "    - ./deploy.sh\n"
        "  when: manual\n",
        gitlab_rules,
    )

    assert findings == []


def test_security_job_normal_gate_does_not_fire(tmp_path, gitlab_rules):
    findings = _sec1_gl_002_findings(
        tmp_path,
        "sast:\n"
        "  stage: security\n"
        "  script:\n"
        "    - semgrep --config=auto .\n",
        gitlab_rules,
    )

    assert findings == []


def test_existing_allow_failure_security_job_still_fires(tmp_path, gitlab_rules):
    findings = _sec1_gl_002_findings(
        tmp_path,
        "sast:\n"
        "  stage: security\n"
        "  script:\n"
        "    - semgrep --config=auto .\n"
        "  allow_failure: true\n",
        gitlab_rules,
    )

    assert findings
    assert findings[0].line == 5


def test_allow_failure_on_non_security_job_still_does_not_fire(tmp_path, gitlab_rules):
    findings = _sec1_gl_002_findings(
        tmp_path,
        "flaky_test:\n"
        "  stage: test\n"
        "  script:\n"
        "    - pytest tests/flaky/\n"
        "  allow_failure: true\n",
        gitlab_rules,
    )

    assert findings == []

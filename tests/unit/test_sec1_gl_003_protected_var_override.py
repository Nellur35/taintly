"""SEC1-GL-003 protected GitLab security scanner variable overrides."""

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


def _rule_findings(tmp_path: Path, content: str, rule_id: str, gitlab_rules) -> list:
    ci = _write_ci(tmp_path, content)
    return [f for f in scan_file(str(ci), gitlab_rules) if f.rule_id == rule_id]


def test_top_level_sast_disabled_true_fires(tmp_path, gitlab_rules):
    findings = _rule_findings(
        tmp_path,
        'variables:\n  SAST_DISABLED: "true"\n',
        "SEC1-GL-003",
        gitlab_rules,
    )

    assert findings
    assert findings[0].line == 2


def test_job_level_secret_detection_disabled_true_fires(tmp_path, gitlab_rules):
    findings = _rule_findings(
        tmp_path,
        "secret_scan:\n"
        "  stage: security\n"
        "  variables:\n"
        "    SECRET_DETECTION_DISABLED: true\n"
        "  script:\n"
        "    - echo scan\n",
        "SEC1-GL-003",
        gitlab_rules,
    )

    assert findings


def test_dependency_scanning_disabled_one_fires(tmp_path, gitlab_rules):
    findings = _rule_findings(
        tmp_path,
        "variables:\n  DEPENDENCY_SCANNING_DISABLED: \"1\"\n",
        "SEC1-GL-003",
        gitlab_rules,
    )

    assert findings


def test_dast_disabled_yes_fires(tmp_path, gitlab_rules):
    findings = _rule_findings(
        tmp_path,
        "variables:\n  DAST_DISABLED: yes\n",
        "SEC1-GL-003",
        gitlab_rules,
    )

    assert findings


def test_sast_disabled_false_does_not_fire(tmp_path, gitlab_rules):
    findings = _rule_findings(
        tmp_path,
        'variables:\n  SAST_DISABLED: "false"\n',
        "SEC1-GL-003",
        gitlab_rules,
    )

    assert findings == []


def test_secret_detection_disabled_zero_does_not_fire(tmp_path, gitlab_rules):
    findings = _rule_findings(
        tmp_path,
        'variables:\n  SECRET_DETECTION_DISABLED: "0"\n',
        "SEC1-GL-003",
        gitlab_rules,
    )

    assert findings == []


def test_unrelated_truthy_variable_does_not_fire(tmp_path, gitlab_rules):
    findings = _rule_findings(
        tmp_path,
        'variables:\n  FEATURE_FLAG_DISABLED: "true"\n',
        "SEC1-GL-003",
        gitlab_rules,
    )

    assert findings == []


def test_commented_out_disabling_variable_does_not_fire(tmp_path, gitlab_rules):
    findings = _rule_findings(
        tmp_path,
        'variables:\n  # SAST_DISABLED: "true"\n  OTHER: "true"\n',
        "SEC1-GL-003",
        gitlab_rules,
    )

    assert findings == []


def test_variable_name_in_script_does_not_fire(tmp_path, gitlab_rules):
    findings = _rule_findings(
        tmp_path,
        "debug:\n"
        "  script:\n"
        "    - echo 'SAST_DISABLED: true'\n"
        "    - echo SECRET_DETECTION_DISABLED=true\n",
        "SEC1-GL-003",
        gitlab_rules,
    )

    assert findings == []


def test_sec1_gl_002_regression_allow_failure_and_when_manual(tmp_path, gitlab_rules):
    allow_failure = _rule_findings(
        tmp_path,
        "sast:\n"
        "  stage: security\n"
        "  script:\n"
        "    - semgrep --config=auto .\n"
        "  allow_failure: true\n",
        "SEC1-GL-002",
        gitlab_rules,
    )
    manual = _rule_findings(
        tmp_path,
        "secret_detection:\n"
        "  stage: security\n"
        "  script:\n"
        "    - /analyzer run\n"
        "  when: manual\n",
        "SEC1-GL-002",
        gitlab_rules,
    )

    assert allow_failure
    assert manual

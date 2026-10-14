"""Actual owner and three-valued activation prerequisites for GL103.

These related boundary controls are not independent attack samples.
"""

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.gitlab_taint import analyze
from taintly.models import Platform
from taintly.rules.gitlab.chain_compose import _gl103_mr_activation
from taintly.rules.gitlab.shell_role import (
    GitLabShellRole,
    classify_gitlab_shallow_use,
    validate_gitlab_shallow_use,
)
from taintly.rules.registry import load_rules_for_platform


_ALLOW_MR = "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
_DENY_MR = (
    "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
    "      when: never\n"
    "    - if: '$CI_PIPELINE_SOURCE == \"push\"'\n"
)
_TOKEN = "  id_tokens:\n    CLOUD_TOKEN:\n      aud: https://cloud.example\n"


def _workflow(root_rules: str, job_policy: str, token: str, extra_script: str = "") -> str:
    return (
        "workflow:\n  rules:\n"
        + root_rules
        + "variables:\n  TITLE: $CI_MERGE_REQUEST_TITLE\ncheck:\n"
        + job_policy
        + token
        + '  script:\n    - eval "$TITLE"\n'
        + extra_script
    )


def _assert_code_and_scan(tmp_path: Path, content: str):
    sink = content.splitlines().index('    - eval "$TITLE"') + 1
    paths = [path for path in analyze(content, content.splitlines()) if path.sink_line == sink]
    assert len(paths) == 1, "boundary fixture must contain an actual shallow path"
    assert paths[0].kind == "shallow"
    evidence = classify_gitlab_shallow_use(content, ".gitlab-ci.yml", paths[0])
    assert evidence.role is GitLabShellRole.CODE
    assert validate_gitlab_shallow_use(evidence, content, ".gitlab-ci.yml", sink)
    (tmp_path / ".gitlab-ci.yml").write_text(content, encoding="utf-8")
    reports = scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITLAB), Platform.GITLAB)
    assert reports
    assert all(not report.engine_errors() for report in reports)
    return [finding for report in reports for finding in report.findings]


@pytest.mark.parametrize(
    ("root_rules", "job_policy"),
    [
        (_DENY_MR, ""),
        (_DENY_MR, "  only:\n    - branches\n"),
        (
            "    - if: '$CUSTOM == \"yes\"'\n",
            "  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
            "      when: never\n    - when: always\n",
        ),
    ],
    ids=["denied-root-absent-job-rules", "denied-root-legacy-job-policy", "unknown-root-denied-job"],
)
def test_supported_denial_dominates_an_unknown_other_gate(
    tmp_path: Path, root_rules: str, job_policy: str
) -> None:
    content = _workflow(root_rules, job_policy, _TOKEN)
    assert _gl103_mr_activation(content, ".gitlab-ci.yml", "check") is False
    findings = _assert_code_and_scan(tmp_path, content)
    assert not any(finding.rule_id == "CHAIN-GL-103" for finding in findings)


@pytest.mark.parametrize(
    ("token", "extra_script"),
    [
        ("", "    - |\n      id_tokens:\n"),
        ("  id_tokens:\n", ""),
        ("  id_tokens:\n    CLOUD_TOKEN:\n      aud: ''\n", ""),
    ],
    ids=["script-text-is-not-token-declaration", "empty-token-mapping", "empty-audience"],
)
def test_token_like_text_or_empty_mapping_does_not_establish_oidc(
    tmp_path: Path, token: str, extra_script: str
) -> None:
    content = _workflow(_ALLOW_MR, "", token, extra_script)
    findings = _assert_code_and_scan(tmp_path, content)
    assert any(finding.rule_id == "TAINT-GL-001" for finding in findings)
    assert not any(finding.rule_id == "CHAIN-GL-103" for finding in findings)

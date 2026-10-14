"""Behavioral contract for GitLab shallow-taint shell roles and CHAIN-GL-103.

The four original command fixtures are retained byte-for-byte. The extra
unsupported-eval case is a related uncertainty control, not a separate threat.
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from taintly.engine import scan_file, scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


_FROZEN_ATOMIC = {
    "unquoted_data": (
        "workflow:\n"
        "  rules:\n"
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
        "variables:\n"
        "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
        "check:\n"
        "  image: alpine:3.21\n"
        "  script:\n"
        "    - printf '%s\\n' $TITLE\n"
    ),
    "quoted_data": (
        "workflow:\n"
        "  rules:\n"
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
        "variables:\n"
        "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
        "check:\n"
        "  image: alpine:3.21\n"
        "  script:\n"
        "    - printf '%s\\n' \"$TITLE\"\n"
    ),
    "quoted_eval": (
        "workflow:\n"
        "  rules:\n"
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
        "variables:\n"
        "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
        "check:\n"
        "  image: alpine:3.21\n"
        "  script:\n"
        '    - eval "$TITLE"\n'
    ),
    "quoted_pipeline": (
        "workflow:\n"
        "  rules:\n"
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
        "variables:\n"
        "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
        "check:\n"
        "  image: alpine:3.21\n"
        "  script:\n"
        '    - printf \'%s\\n\' "$TITLE" | sh\n'
    ),
}
_FROZEN_SHA256 = {
    "unquoted_data": "ac0e0204041f132f69b27bdff01b5915828092e1ea3172e24d4d3f334f61e340",
    "quoted_data": "b496d77deed6d40f5f23270e00b019fb398039f767d4c67f9cd32eecf6c6a09f",
    "quoted_eval": "584fc8ce407b6cb667fa7f98da08bef0c07e3c08a61b5bbcb6bf76206f5889a9",
    "quoted_pipeline": "1b0f71cfb3db575b94b8b5adf1a53b8444ce1432ed3716e554ef67f2f870cbec",
}

_UNKNOWN_EVAL = (
    "workflow:\n"
    "  rules:\n"
    "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
    "variables:\n"
    "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
    "check:\n"
    "  script:\n"
    '    - eval "$TITLE" extra\n'
)


def _taint_rule():
    return next(
        rule
        for rule in load_rules_for_platform(Platform.GITLAB)
        if rule.id == "TAINT-GL-001"
    )


def _forbidden_execution_claims(serialized: dict) -> None:
    text = json.dumps(serialized, sort_keys=True).lower()
    for phrase in (
        "gets command execution",
        "full token",
        "protected variables in scope",
        "cloud write-token",
        "cloud account compromised",
    ):
        assert phrase not in text


@pytest.mark.parametrize(
    ("case", "role"),
    [
        ("unquoted_data", "data"),
        ("quoted_data", "quiet"),
        ("quoted_eval", "code"),
        ("quoted_pipeline", "code"),
        ("unsupported_eval", "unknown"),
    ],
    ids=["fixed-printf-data", "quoted-printf", "eval-code", "printf-pipe-sh-code", "eval-unknown"],
)
def test_atomic_shallow_finding_reflects_shell_role(case: str, role: str) -> None:
    content = _UNKNOWN_EVAL if case == "unsupported_eval" else _FROZEN_ATOMIC[case]
    if case in _FROZEN_SHA256:
        assert hashlib.sha256(content.encode("utf-8")).hexdigest() == _FROZEN_SHA256[case]
    findings = scan_file(".gitlab-ci.yml", [_taint_rule()], _content=content)
    taint = [finding for finding in findings if finding.rule_id == "TAINT-GL-001"]
    assert [finding.rule_id for finding in findings if finding.rule_id == "ENGINE-ERR"] == []

    if role == "quiet":
        assert taint == []
        return

    assert len(taint) == 1
    finding = taint[0]
    rendered = finding.to_dict()
    assert rendered["line"] == len(content.splitlines())
    if role == "data":
        assert finding.severity.value in {"LOW", "MEDIUM"}
        assert finding.confidence in {"low", "medium"}
        assert finding.review_needed is True
        assert "data" in json.dumps(rendered, sort_keys=True).lower()
        _forbidden_execution_claims(rendered)
    elif role == "code":
        assert finding.severity.value == "CRITICAL"
        assert finding.confidence == "high"
        assert finding.review_needed is True
        assert finding.file == ".gitlab-ci.yml"
        assert "TITLE" in finding.snippet and "CI_MERGE_REQUEST_TITLE" in finding.snippet
        text = json.dumps(rendered, sort_keys=True).lower()
        assert "posix" in text and "conditional" in text
        _forbidden_execution_claims(rendered)
    else:
        assert role == "unknown"
        assert finding.severity.value in {"LOW", "MEDIUM"}
        assert finding.confidence in {"low", "medium"}
        assert finding.review_needed is True
        assert "unknown" in json.dumps(rendered, sort_keys=True).lower()
        _forbidden_execution_claims(rendered)


def test_shallow_source_is_owned_by_job_and_script_section() -> None:
    sections = """\
workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
variables:
  TITLE: $CI_MERGE_REQUEST_TITLE
check:
  before_script:
    - printf '%s\\n' $TITLE
  script:
    - eval "$TITLE"
  after_script:
    - printf '%s\\n' $TITLE
"""
    rule = _taint_rule()
    findings = [
        finding
        for finding in scan_file(".gitlab-ci.yml", [rule], _content=sections)
        if finding.rule_id == "TAINT-GL-001"
    ]
    assert sorted(finding.line for finding in findings) == [8, 10, 12]
    by_line = {finding.line: finding for finding in findings}
    assert by_line[8].review_needed is True
    assert by_line[10].review_needed is True
    assert by_line[12].review_needed is True

    scoped = """\
workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
job_a:
  variables:
    TITLE: $CI_MERGE_REQUEST_TITLE
  script:
    - eval "$TITLE"
job_b:
  script:
    - eval "$TITLE"
"""
    scoped_findings = [
        finding
        for finding in scan_file(".gitlab-ci.yml", [rule], _content=scoped)
        if finding.rule_id == "TAINT-GL-001"
    ]
    assert [finding.line for finding in scoped_findings] == [8]
    assert scoped_findings[0].review_needed is True

    overridden = """\
workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
variables:
  TITLE: $CI_MERGE_REQUEST_TITLE
check:
  variables:
    TITLE: release
  script:
    - eval "$TITLE"
"""
    overridden_findings = [
        finding
        for finding in scan_file(".gitlab-ci.yml", [rule], _content=overridden)
        if finding.rule_id == "TAINT-GL-001"
    ]
    assert overridden_findings == []


def _chain_findings(tmp_path: Path, content: str) -> list:
    (tmp_path / ".gitlab-ci.yml").write_text(content, encoding="utf-8")
    reports = scan_repo(
        str(tmp_path),
        load_rules_for_platform(Platform.GITLAB),
        Platform.GITLAB,
    )
    assert reports
    assert all(report.engine_errors() == [] for report in reports)
    return [finding for report in reports for finding in report.findings]


def _chain_case(command: str, *, token_job: str | None = "check") -> str:
    if token_job == "check":
        return (
            "workflow:\n"
            "  rules:\n"
            "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
            "variables:\n"
            "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
            "check:\n"
            "  id_tokens:\n"
            "    CLOUD_TOKEN:\n"
            "      aud: https://cloud.example\n"
            "  script:\n"
            f"    - {command}\n"
        )
    content = (
        "workflow:\n"
        "  rules:\n"
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
        "variables:\n"
        "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
        "check:\n"
        "  script:\n"
        f"    - {command}\n"
    )
    if token_job is not None:
        content += (
            f"{token_job}:\n"
            "  id_tokens:\n"
            "    CLOUD_TOKEN:\n"
            "      aud: https://cloud.example\n"
            "  script:\n"
            "    - echo token is declared\n"
        )
    return content


@pytest.mark.parametrize(
    ("command", "token_job", "expected_chain"),
    [
        ('eval "$TITLE"', "check", True),
        ('printf \'%s\\n\' "$TITLE" | sh', "check", True),
        ("printf '%s\\n' $TITLE", "check", False),
        ('eval "$TITLE" extra', "check", False),
        ('eval "$TITLE"', None, False),
        ('eval "$TITLE"', "cloud", False),
    ],
    ids=["same-job-eval", "same-job-interpreter-pipe", "data-only", "unknown", "no-token", "sibling-token"],
)
def test_chain_103_requires_supported_code_and_same_job_oidc(
    tmp_path: Path,
    command: str,
    token_job: str | None,
    expected_chain: bool,
) -> None:
    content = _chain_case(command, token_job=token_job)
    findings = _chain_findings(tmp_path, content)
    chain = [finding for finding in findings if finding.rule_id == "CHAIN-GL-103"]
    assert len(chain) == int(expected_chain)
    if not expected_chain:
        return

    finding = chain[0]
    serialized = finding.to_dict()
    assert finding.severity.value == "HIGH"
    assert finding.review_needed is True
    assert finding.line == len(content.splitlines())
    assert "id_tokens" in finding.snippet
    text = json.dumps(serialized, sort_keys=True).lower()
    assert "posix" in text and "conditional" in text
    assert "title" in finding.snippet.lower()
    assert "ci_merge_request_title" in finding.snippet.lower()
    assert "id_tokens" in text
    assert "audience" in text or "aud:" in text
    assert all(term in text for term in ("issuance", "federation", "permission"))
    for phrase in (
        "cloud write-token",
        "cloud account compromised",
        "direct write access",
        "executes with that job's cloud token",
        "under the attacker's control",
    ):
        assert phrase not in text

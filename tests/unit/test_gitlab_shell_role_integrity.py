"""Integrity checks for GitLab shallow-shell witnesses and consumers.

These controls cover conservative structural ownership and rejection of stale
or malformed witnesses. Related fixture variants are not independent threats.
"""

from __future__ import annotations

import json
from dataclasses import replace
from enum import Enum
from pathlib import Path

import pytest

from taintly.engine import scan_file, scan_repo
from taintly.gitlab_taint import analyze
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform
from taintly.rules.gitlab.shell_role import (
    GitLabShellEvidence,
    GitLabShellRole,
    classify_gitlab_shallow_use,
    validate_gitlab_shallow_use,
)


def _taint_rule():
    return next(
        rule
        for rule in load_rules_for_platform(Platform.GITLAB)
        if rule.id == "TAINT-GL-001"
    )


def _ambiguous_cases() -> dict[str, str]:
    common = (
        "workflow:\n"
        "  rules:\n"
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
    )
    return {
        "duplicate-variable-key": (
            common
            + "variables:\n"
            + "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
            + "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
            + "check:\n"
            + "  id_tokens:\n"
            + "    CLOUD_TOKEN:\n"
            + "      aud: https://cloud.example\n"
            + "  script:\n"
            + '    - eval "$TITLE"\n'
        ),
        "extends-hidden-static-override": (
            common
            + "variables:\n"
            + "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
            + ".base:\n"
            + "  variables:\n"
            + "    TITLE: release\n"
            + "  script:\n"
            + '    - printf \'%s\\n\' "$TITLE"\n'
            + "check:\n"
            + "  extends: .base\n"
            + "  id_tokens:\n"
            + "    CLOUD_TOKEN:\n"
            + "      aud: https://cloud.example\n"
            + "  script:\n"
            + '    - eval "$TITLE"\n'
        ),
        "merged-job-ownership": (
            common
            + "variables:\n"
            + "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
            + ".shared: &shared_job\n"
            + "  before_script:\n"
            + "    - printf '%s\\n' \"$TITLE\"\n"
            + "check:\n"
            + "  <<: *shared_job\n"
            + "  id_tokens:\n"
            + "    CLOUD_TOKEN:\n"
            + "      aud: https://cloud.example\n"
            + "  script:\n"
            + '    - eval "$TITLE"\n'
        ),
    }


def _assert_unknown_review(finding) -> None:
    serialized = finding.to_dict()
    text = json.dumps(serialized, sort_keys=True).lower()
    assert finding.severity.value == "MEDIUM"
    assert finding.confidence == "low"
    assert finding.review_needed is True
    assert "gitlab-shell-role-unknown" in finding.context_tags
    assert "unknown" in text


@pytest.mark.parametrize(
    "case",
    [
        "duplicate-variable-key",
        "extends-hidden-static-override",
        "merged-job-ownership",
    ],
    ids=["duplicate-source-key", "extends-static-override", "yaml-merge-owner"],
)
def test_ambiguous_structural_owners_stay_unknown_and_do_not_compose(
    tmp_path: Path, case: str
) -> None:
    content = _ambiguous_cases()[case]
    expected_line = content.splitlines().index('    - eval "$TITLE"') + 1
    paths = analyze(content, content.splitlines())
    actual_paths = [
        path
        for path in paths
        if path.kind == "shallow"
        and path.sink_kind == "script"
        and path.sink_line == expected_line
        and path.sink_snippet.strip() == 'eval "$TITLE"'
    ]
    assert actual_paths, "fixture must contain a real shallow source-to-script path"
    witness = classify_gitlab_shallow_use(
        content, ".gitlab-ci.yml", actual_paths[0]
    )
    assert witness.role is GitLabShellRole.UNKNOWN
    assert not validate_gitlab_shallow_use(
        witness, content, ".gitlab-ci.yml", expected_line
    )

    atomic = [
        finding
        for finding in scan_file(
            ".gitlab-ci.yml", [_taint_rule()], _content=content
        )
        if finding.rule_id == "TAINT-GL-001"
    ]
    assert len(atomic) == 1
    assert atomic[0].line == expected_line
    assert "TITLE" in atomic[0].snippet
    _assert_unknown_review(atomic[0])

    (tmp_path / ".gitlab-ci.yml").write_text(content, encoding="utf-8")
    reports = scan_repo(
        str(tmp_path), load_rules_for_platform(Platform.GITLAB), Platform.GITLAB
    )
    assert reports
    assert all(report.engine_errors() == [] for report in reports)
    all_findings = [finding for report in reports for finding in report.findings]
    assert any(finding.rule_id == "TAINT-GL-001" for finding in all_findings)
    assert not any(finding.rule_id == "CHAIN-GL-103" for finding in all_findings)


def _valid_code_content() -> str:
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
        '    - eval "$TITLE"\n'
    )


def _valid_witness(content: str) -> GitLabShellEvidence:
    paths = analyze(content, content.splitlines())
    matches = [path for path in paths if path.kind == "shallow" and path.sink_kind == "script"]
    assert len(matches) == 1
    witness = classify_gitlab_shallow_use(content, ".gitlab-ci.yml", matches[0])
    assert witness.role is GitLabShellRole.CODE
    assert validate_gitlab_shallow_use(
        witness, content, ".gitlab-ci.yml", matches[0].sink_line
    )
    return witness


class _ForeignRole(str, Enum):
    CODE = "code"


@pytest.mark.parametrize(
    "mutation",
    [
        "stale-content",
        "wrong-file",
        "wrong-owner",
        "foreign-enum",
        "raw-code-string",
        "reason-only",
    ],
    ids=[
        "stale-content-hash",
        "file-mismatch",
        "owner-mismatch",
        "foreign-str-enum",
        "raw-role-string",
        "reason-only-forgery",
    ],
)
def test_invalid_shell_witnesses_fail_closed_in_atomic_consumer(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    content = _valid_code_content()
    rule = _taint_rule()
    pattern = rule.pattern
    witness = _valid_witness(content)
    assert witness.filepath == ".gitlab-ci.yml"
    baseline = [
        finding
        for finding in scan_file(".gitlab-ci.yml", [rule], _content=content)
        if finding.rule_id == "TAINT-GL-001"
    ]
    assert len(baseline) == 1
    assert baseline[0].severity.value == "CRITICAL"
    assert baseline[0].confidence == "high"
    assert baseline[0].review_needed is True
    assert "gitlab-shell-role-code" in baseline[0].context_tags
    assert "conditional posix" in json.dumps(
        baseline[0].to_dict(), sort_keys=True
    ).lower()

    changes = {
        "stale-content": {"content_sha256": "0" * 64},
        "wrong-file": {"filepath": "other.yml"},
        "wrong-owner": {"owner_path": ("other", "script", 0)},
        "foreign-enum": {"role": _ForeignRole.CODE},
        "raw-code-string": {"role": "code"},
        "reason-only": {"reason": "forged proof: verified privileged code execution"},
    }
    forged = replace(witness, **changes[mutation])
    assert (forged.filepath != witness.filepath) is (mutation == "wrong-file")
    assert not validate_gitlab_shallow_use(
        forged, content, ".gitlab-ci.yml", witness.sink_line
    )

    monkeypatch.setattr(
        pattern,
        "context_notes_for_matches",
        lambda _content, _filepath, _matches: [forged],
    )
    findings = scan_file(".gitlab-ci.yml", [rule], _content=content)
    taint = [finding for finding in findings if finding.rule_id == "TAINT-GL-001"]
    assert len(taint) == 1
    assert [finding for finding in findings if finding.rule_id == "ENGINE-ERR"] == []
    _assert_unknown_review(taint[0])
    serialized = json.dumps(taint[0].to_dict(), sort_keys=True).lower()
    assert "forged proof" not in serialized
    assert "privileged code execution" not in serialized


def _mr_policy_case(root_rules: str, job_rules: str) -> str:
    return (
        "workflow:\n"
        "  rules:\n"
        + root_rules
        + "variables:\n"
        + "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
        + "check:\n"
        + "  id_tokens:\n"
        + "    CLOUD_TOKEN:\n"
        + "      aud: https://cloud.example\n"
        + "  rules:\n"
        + job_rules
        + "  script:\n"
        + '    - eval "$TITLE"\n'
    )


@pytest.mark.parametrize(
    ("root_rules", "job_rules", "expected_chain"),
    [
        (
            "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
            "      when: never\n"
            "    - if: '$CI_PIPELINE_SOURCE == \"push\"'\n"
            "      when: always\n",
            "    - when: always\n",
            False,
        ),
        (
            "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
            "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
            "      when: never\n"
            "    - when: always\n",
            False,
        ),
        (
            "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
            "    - when: always\n"
            "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
            "      when: never\n",
            True,
        ),
    ],
    ids=["root-mr-deny", "job-mr-deny-before-fallback", "job-first-match-allows-mr"],
)
def test_chain_mr_reachability_respects_first_matching_rule(
    tmp_path: Path, root_rules: str, job_rules: str, expected_chain: bool
) -> None:
    content = _mr_policy_case(root_rules, job_rules)
    paths = [
        path
        for path in analyze(content, content.splitlines())
        if path.kind == "shallow" and path.sink_kind == "script"
    ]
    assert len(paths) == 1, "each policy fixture must contain a real shallow script flow"
    witness = classify_gitlab_shallow_use(content, ".gitlab-ci.yml", paths[0])
    assert witness.role is GitLabShellRole.CODE
    assert validate_gitlab_shallow_use(
        witness, content, ".gitlab-ci.yml", paths[0].sink_line
    )

    (tmp_path / ".gitlab-ci.yml").write_text(content, encoding="utf-8")
    reports = scan_repo(
        str(tmp_path), load_rules_for_platform(Platform.GITLAB), Platform.GITLAB
    )
    assert reports
    assert all(report.engine_errors() == [] for report in reports)
    all_findings = [finding for report in reports for finding in report.findings]
    chain = [finding for finding in all_findings if finding.rule_id == "CHAIN-GL-103"]
    assert len(chain) == int(expected_chain)
    if expected_chain:
        rendered = json.dumps(chain[0].to_dict(), sort_keys=True).lower()
        assert chain[0].review_needed is True
        assert "conditional posix" in rendered
        assert "unverified" in rendered

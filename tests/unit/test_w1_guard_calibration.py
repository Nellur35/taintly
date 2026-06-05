"""W1 — guard / trigger-reachability calibration (phase 1, calibration only).

The pass annotates a finding's exploitability when a fork-reachable GitHub
workflow ALSO declares a strong identity/repo guard — but must never change
severity (a mis-attributed guard must not suppress a real finding).
"""

from __future__ import annotations

from taintly.engine import (
    _annotate_guarded_findings,
    _detect_github_guards,
    _detect_gitlab_guards,
)
from taintly.models import Finding, Severity


def _mk() -> Finding:
    return Finding(
        rule_id="SEC4-GH-004",
        severity=Severity.CRITICAL,
        title="t",
        description="d",
        file="wf.yml",
    )


def test_detect_github_guards():
    assert _detect_github_guards("if: github.actor == 'admin'") == ["actor-identity check"]
    assert _detect_github_guards("if: github.triggering_actor != 'bot'") == ["actor-identity check"]
    assert "same-repository check" in _detect_github_guards(
        "if: github.event.pull_request.head.repo.full_name == github.repository"
    )
    assert "author-association check" in _detect_github_guards(
        "if: github.event.comment.author_association == 'OWNER'"
    )
    assert _detect_github_guards("run: echo hi") == []


def test_fork_reachable_with_guard_is_annotated_not_downgraded():
    content = (
        "on:\n  pull_request_target:\n    types: [opened]\n"
        "jobs:\n  x:\n    if: github.actor == 'admin'\n    steps:\n      - run: echo hi\n"
    )
    f = _mk()
    _annotate_guarded_findings([f], content)
    assert f.exploitability == "low"
    assert "guard" in f.calibration_reason.lower()
    # CALIBRATION ONLY — severity must be untouched.
    assert f.severity == Severity.CRITICAL


def test_fork_reachable_without_guard_is_untouched():
    content = "on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n      - run: echo hi\n"
    f = _mk()
    _annotate_guarded_findings([f], content)
    assert f.exploitability == "medium"
    assert f.calibration_reason == ""


def test_guard_without_fork_reachability_is_untouched():
    # A guard on a maintainer-only workflow is moot — don't annotate.
    content = (
        "on:\n  push:\n    tags: [v*]\n"
        "jobs:\n  x:\n    if: github.actor == 'admin'\n    steps:\n      - run: echo hi\n"
    )
    f = _mk()
    _annotate_guarded_findings([f], content)
    assert f.exploitability == "medium"
    assert f.calibration_reason == ""


# --- GitLab ---------------------------------------------------------------


def test_detect_gitlab_guards_trustworthy_only():
    assert "same-project MR check" in _detect_gitlab_guards(
        "rules:\n  - if: '$CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID'"
    )
    assert "protected-ref check" in _detect_gitlab_guards(
        "rules:\n  - if: '$CI_COMMIT_REF_PROTECTED == \"true\"'"
    )
    # Spoofable gates are NOT trustworthy guards (SEC4-GL-007/011 flag them).
    assert _detect_gitlab_guards("rules:\n  - if: '$GITLAB_USER_LOGIN == \"admin\"'") == []
    assert _detect_gitlab_guards("rules:\n  - if: '$CI_MERGE_REQUEST_LABELS =~ /safe/'") == []


def test_gitlab_fork_reachable_with_same_project_guard_is_annotated():
    content = (
        "job:\n  rules:\n"
        '    - if: \'$CI_PIPELINE_SOURCE == "merge_request_event" '
        "&& $CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID'\n"
        '  script:\n    - echo "$CI_MERGE_REQUEST_TITLE"\n'
    )
    f = _mk()
    _annotate_guarded_findings([f], content)
    assert f.exploitability == "low"
    assert "same-project" in f.calibration_reason
    assert f.severity == Severity.CRITICAL  # calibration only


def test_gitlab_fork_reachable_with_spoofable_gate_is_untouched():
    # merge_request_event (fork-reachable) but only a spoofable $GITLAB_USER_*
    # gate — must NOT be treated as a protective guard.
    content = (
        "job:\n  rules:\n"
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
        '  script:\n    - if [ "$GITLAB_USER_LOGIN" = bot ]; then echo hi; fi\n'
    )
    f = _mk()
    _annotate_guarded_findings([f], content)
    assert f.exploitability == "medium"
    assert f.calibration_reason == ""

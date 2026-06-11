"""Guard / trigger-reachability calibration tests.

The pass annotates a finding's exploitability when its job is
fork-reachable AND that same job declares a strong identity/repo guard.
It must never change severity, must be job-scoped (a guard in one job
does not calibrate findings in another), and must recognise
fork-reachable triggers in every ``on:`` YAML shape.
"""

from __future__ import annotations

from taintly.engine import (
    _annotate_guarded_findings,
    _detect_github_guards,
    _detect_gitlab_guards,
    _propagate_guard_calibration_to_composites,
)
from taintly.models import Finding, Severity


def _mk(line: int = 0) -> Finding:
    return Finding(
        rule_id="SEC4-GH-004",
        severity=Severity.CRITICAL,
        title="t",
        description="d",
        file="wf.yml",
        line=line,
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


# A guarded job's finding is annotated (block-style trigger).
# Lines: 1 on:/2 pull_request_target:/3 types/4 jobs:/5 x:/6 if:/7 steps:/8 run
_BLOCK_GUARDED = (
    "on:\n  pull_request_target:\n    types: [opened]\n"
    "jobs:\n  x:\n    if: github.actor == 'admin'\n    steps:\n      - run: echo hi\n"
)


def test_fork_reachable_with_guard_is_annotated_not_downgraded():
    f = _mk(line=8)  # the run: step, inside guarded job x
    _annotate_guarded_findings([f], _BLOCK_GUARDED)
    assert f.exploitability == "low"
    assert "guard" in f.calibration_reason.lower()
    # CALIBRATION ONLY — severity must be untouched.
    assert f.severity == Severity.CRITICAL


def test_fork_reachable_without_guard_is_untouched():
    content = "on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n      - run: echo hi\n"
    f = _mk(line=6)
    _annotate_guarded_findings([f], content)
    assert f.exploitability == "medium"
    assert f.calibration_reason == ""


def test_guard_without_fork_reachability_is_untouched():
    # A guard on a maintainer-only workflow is moot — don't annotate.
    content = (
        "on:\n  push:\n    tags: [v*]\n"
        "jobs:\n  x:\n    if: github.actor == 'admin'\n    steps:\n      - run: echo hi\n"
    )
    f = _mk(line=8)
    _annotate_guarded_findings([f], content)
    assert f.exploitability == "medium"
    assert f.calibration_reason == ""


# --- Finding A: fork-reachability must be detected in every on: shape ----


def test_flow_mapping_trigger_is_detected():
    # on: { pull_request_target: {...} } — the block-only regex missed this.
    content = (
        "on: { pull_request_target: { types: [opened] } }\n"
        "jobs:\n  x:\n    if: github.actor == 'admin'\n    steps:\n      - run: echo hi\n"
    )
    f = _mk(line=6)  # run: step inside job x
    _annotate_guarded_findings([f], content)
    assert f.exploitability == "low"


def test_flow_list_trigger_is_detected():
    # on: [pull_request_target] — list shorthand, also previously missed.
    content = (
        "on: [pull_request_target]\n"
        "jobs:\n  x:\n    if: github.actor == 'admin'\n    steps:\n      - run: echo hi\n"
    )
    f = _mk(line=5)  # run: step inside job x
    _annotate_guarded_findings([f], content)
    assert f.exploitability == "low"


# --- Finding B: job-scoping — a guard in one job must not reach another ---

# Lines: 1 on:/2 prt:/3 jobs:/4 a:/5 if:(guard)/6 steps/7 run(a)
#        8 b:/9 steps/10 run(b)  — job b has NO guard
_TWO_JOBS_GUARD_IN_A = (
    "on:\n  pull_request_target:\n"
    "jobs:\n"
    "  a:\n    if: github.actor == 'admin'\n    steps:\n      - run: echo a\n"
    "  b:\n    steps:\n      - run: echo b\n"
)


def test_guard_in_other_job_does_not_calibrate_this_finding():
    # Finding in unguarded job b must NOT be downgraded by job a's guard.
    f_b = _mk(line=10)
    _annotate_guarded_findings([f_b], _TWO_JOBS_GUARD_IN_A)
    assert f_b.exploitability == "medium"
    assert f_b.calibration_reason == ""


def test_guard_in_same_job_still_calibrates():
    # Control: a finding in guarded job a IS downgraded.
    f_a = _mk(line=7)
    _annotate_guarded_findings([f_a], _TWO_JOBS_GUARD_IN_A)
    assert f_a.exploitability == "low"


def test_line_zero_finding_is_not_calibrated():
    # No resolvable job (line<=0) → conservative: never downgrade.
    f = _mk(line=0)
    _annotate_guarded_findings([f], _BLOCK_GUARDED)
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


# Lines: 1 job:/2 rules:/3 if(guard)/4 script:/5 echo
_GL_GUARDED = (
    "job:\n  rules:\n"
    '    - if: \'$CI_PIPELINE_SOURCE == "merge_request_event" '
    "&& $CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID'\n"
    '  script:\n    - echo "$CI_MERGE_REQUEST_TITLE"\n'
)


def test_gitlab_fork_reachable_with_same_project_guard_is_annotated():
    f = _mk(line=5)  # the script line, inside job "job"
    _annotate_guarded_findings([f], _GL_GUARDED)
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
    f = _mk(line=5)
    _annotate_guarded_findings([f], content)
    assert f.exploitability == "medium"
    assert f.calibration_reason == ""


# --- A0: a CHAIN composite inherits the guard calibration of its leg ---
# The composer (_seed_findings) drops exploitability/calibration_reason, so without
# this a CRITICAL composite contradicts the per-file "low — guard present" verdict.
# Fix PROPAGATES (never suppresses): severity unchanged, composite gains low + caveat.


def _leg(
    line: int = 8,
    exploitability: str = "low",
    calibration_reason: str = (
        "This job is fork-reachable but declares a guard (author-association check); "
        "verify it dominates this finding's step before treating it as exploitable."
    ),
) -> Finding:
    return Finding(
        rule_id="SEC4-GH-005",
        severity=Severity.MEDIUM,
        title="t",
        description="d",
        file="wf.yml",
        line=line,
        origin="file",
        exploitability=exploitability,
        calibration_reason=calibration_reason,
        finding_family="credential_persistence",
    )


def _composite(line: int = 8) -> Finding:
    return Finding(
        rule_id="CHAIN-GH-101",
        severity=Severity.CRITICAL,
        title="t",
        description="d",
        file="wf.yml",
        line=line,
        origin="cross-workflow",
        exploitability="medium",
        finding_family="chain-composition",
    )


def test_a0_composite_inherits_calibrated_leg():
    leg, comp = _leg(), _composite()
    _propagate_guard_calibration_to_composites([leg, comp])
    assert comp.exploitability == "low"
    assert "guard-calibration flagged" in comp.calibration_reason
    assert "author-association" in comp.calibration_reason
    # PROPAGATE, not suppress — severity untouched, finding still present.
    assert comp.severity == Severity.CRITICAL


def test_a0_composite_on_uncalibrated_leg_untouched():
    leg = _leg(exploitability="high", calibration_reason="")  # no guard on the leg
    comp = _composite()
    _propagate_guard_calibration_to_composites([leg, comp])
    assert comp.exploitability == "medium"
    assert comp.calibration_reason == ""


def test_a0_composite_at_different_line_untouched():
    leg, comp = _leg(line=8), _composite(line=99)  # composite not anchored on the leg
    _propagate_guard_calibration_to_composites([leg, comp])
    assert comp.exploitability == "medium"


def test_a0_non_composite_chain_finding_untouched():
    # CHAIN-GH-001 is a single-file ContextPattern (family privileged_pr_trigger),
    # already calibrated in scan_file — the family check must exclude it here.
    leg = _leg()
    other = Finding(
        rule_id="CHAIN-GH-001",
        severity=Severity.CRITICAL,
        title="t",
        description="d",
        file="wf.yml",
        line=8,
        origin="file",
        exploitability="medium",
        finding_family="privileged_pr_trigger",
    )
    _propagate_guard_calibration_to_composites([leg, other])
    assert other.exploitability == "medium"

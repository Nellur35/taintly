from pathlib import Path
from textwrap import dedent

from taintly.engine import scan_file
from taintly.gitlabguard import GitLabContext
from taintly.models import Platform
from taintly.rules.registry import load_all_rules

FIXTURES = Path(__file__).parents[1] / "fixtures" / "gitlab" / "mechanical"


def _gitlab_rules():
    return [rule for rule in load_all_rules() if rule.platform == Platform.GITLAB]


def _scan(content: str, ctx: GitLabContext | None = None):
    return scan_file(
        ".gitlab-ci.yml",
        _gitlab_rules(),
        _content=dedent(content).lstrip(),
        gitlabctx=ctx,
    )


def _scan_fixture(fixture: str, ctx: GitLabContext | None = None):
    return _scan((FIXTURES / fixture).read_text(encoding="utf-8"), ctx)


def test_dead_gitlab_job_with_literal_when_never_suppresses_findings():
    findings = _scan_fixture("dead_job_literal_never.yml")

    assert not [f for f in findings if f.rule_id == "SEC4-GL-003"]


def test_runtime_gitlab_guard_does_not_suppress_findings():
    findings = _scan_fixture("runtime_guard.yml")

    assert [f for f in findings if f.rule_id == "SEC4-GL-003"]


def test_pipeline_source_context_can_prove_when_never_job_dead():
    findings = _scan_fixture(
        "pipeline_source_never.yml", GitLabContext(pipeline_source="merge_request_event")
    )

    assert not [f for f in findings if f.rule_id == "SEC4-GL-003"]


def test_nonmatching_pipeline_source_context_does_not_suppress():
    findings = _scan_fixture("pipeline_source_never.yml", GitLabContext(pipeline_source="push"))

    assert [f for f in findings if f.rule_id == "SEC4-GL-003"]


def test_manual_pipeline_variables_remain_reported_in_v1():
    findings = _scan_fixture("manual_pipeline_input.yml", GitLabContext(pipeline_source="web"))

    assert [f for f in findings if f.rule_id == "SEC4-GL-003"]


def test_earlier_runtime_rule_prevents_later_static_never_suppression():
    findings = _scan(
        """
        maybe_live:
          rules:
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
              when: never
            - if: "true"
              when: never
          script:
            - echo $CI_COMMIT_REF_NAME
        """
    )

    assert [f for f in findings if f.rule_id == "SEC4-GL-003"]


def test_static_false_when_never_rule_does_not_suppress():
    findings = _scan(
        """
        live_job:
          rules:
            - if: "false"
              when: never
          script:
            - echo $CI_COMMIT_REF_NAME
        """
    )

    assert [f for f in findings if f.rule_id == "SEC4-GL-003"]


def test_branch_default_branch_context_can_prove_job_dead():
    findings = _scan(
        """
        default_branch_disabled:
          rules:
            - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
              when: never
          script:
            - echo $CI_COMMIT_REF_NAME
        """,
        GitLabContext(commit_branch="main", default_branch="main"),
    )

    assert not [f for f in findings if f.rule_id == "SEC4-GL-003"]

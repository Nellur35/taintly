from textwrap import dedent

from taintly.engine import scan_file
from taintly.gitlabguard import GitLabContext
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def _gitlab_rules():
    return [rule for rule in load_all_rules() if rule.platform == Platform.GITLAB]


def _scan(content: str, ctx: GitLabContext | None = None):
    return scan_file(
        ".gitlab-ci.yml",
        _gitlab_rules(),
        _content=dedent(content).lstrip(),
        gitlabctx=ctx,
    )


def test_dead_gitlab_job_with_literal_when_never_suppresses_findings():
    findings = _scan(
        """
        dead_job:
          rules:
            - if: "true"
              when: never
          script:
            - echo $CI_COMMIT_REF_NAME
        """
    )

    assert not [f for f in findings if f.rule_id == "SEC4-GL-003"]


def test_runtime_gitlab_guard_does_not_suppress_findings():
    findings = _scan(
        """
        maybe_live:
          rules:
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
              when: never
          script:
            - echo $CI_COMMIT_REF_NAME
        """
    )

    assert [f for f in findings if f.rule_id == "SEC4-GL-003"]


def test_pipeline_source_context_can_prove_when_never_job_dead():
    findings = _scan(
        """
        mr_disabled:
          rules:
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
              when: never
          script:
            - echo $CI_COMMIT_REF_NAME
        """,
        GitLabContext(pipeline_source="merge_request_event"),
    )

    assert not [f for f in findings if f.rule_id == "SEC4-GL-003"]


def test_nonmatching_pipeline_source_context_does_not_suppress():
    findings = _scan(
        """
        push_job:
          rules:
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
              when: never
          script:
            - echo $CI_COMMIT_REF_NAME
        """,
        GitLabContext(pipeline_source="push"),
    )

    assert [f for f in findings if f.rule_id == "SEC4-GL-003"]


def test_manual_pipeline_variables_remain_reported_in_v1():
    findings = _scan(
        """
        manual_release:
          rules:
            - if: '$CI_PIPELINE_SOURCE == "web"'
              when: manual
          script:
            - echo $CI_COMMIT_REF_NAME
        """,
        GitLabContext(pipeline_source="web"),
    )

    assert [f for f in findings if f.rule_id == "SEC4-GL-003"]

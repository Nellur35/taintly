from textwrap import dedent

from taintly.gitlabguard import (
    ExprVerdict,
    GitLabContext,
    GuardVerdict,
    evaluate_gitlab_if,
    evaluate_gitlab_rules,
    find_dead_gitlab_job_ranges,
    is_pipeline_whole_dead,
)


def test_gitlab_if_literal_values():
    assert evaluate_gitlab_if("true") is ExprVerdict.STATIC_TRUE
    assert evaluate_gitlab_if("false") is ExprVerdict.STATIC_FALSE


def test_gitlab_if_pipeline_source_comparison_uses_context():
    ctx = GitLabContext(pipeline_source="merge_request_event")

    assert (
        evaluate_gitlab_if('$CI_PIPELINE_SOURCE == "merge_request_event"', ctx)
        is ExprVerdict.STATIC_TRUE
    )
    assert evaluate_gitlab_if('$CI_PIPELINE_SOURCE == "push"', ctx) is ExprVerdict.STATIC_FALSE


def test_gitlab_if_branch_default_branch_comparison_uses_context():
    ctx = GitLabContext(commit_branch="main", default_branch="main")

    assert (
        evaluate_gitlab_if("$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH", ctx)
        is ExprVerdict.STATIC_TRUE
    )
    assert (
        evaluate_gitlab_if("$CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH", ctx)
        is ExprVerdict.STATIC_FALSE
    )


def test_gitlab_if_unknown_context_stays_runtime():
    assert (
        evaluate_gitlab_if('$CI_PIPELINE_SOURCE == "merge_request_event"', GitLabContext())
        is ExprVerdict.RUNTIME
    )


def test_gitlab_if_compound_expression_stays_runtime():
    ctx = GitLabContext(pipeline_source="merge_request_event")

    assert (
        evaluate_gitlab_if(
            '$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_COMMIT_BRANCH == "main"',
            ctx,
        )
        is ExprVerdict.RUNTIME
    )


def test_gitlab_rules_when_never_with_static_true_is_dead():
    job = {"rules": [{"if": "true", "when": "never"}]}

    assert evaluate_gitlab_rules(job) is GuardVerdict.DEAD


def test_gitlab_rules_when_never_with_runtime_guard_stays_runtime():
    job = {"rules": [{"if": '$CI_PIPELINE_SOURCE == "merge_request_event"', "when": "never"}]}

    assert evaluate_gitlab_rules(job, GitLabContext()) is GuardVerdict.RUNTIME


def test_gitlab_rules_when_never_with_static_false_does_not_prove_dead():
    job = {"rules": [{"if": "false", "when": "never"}]}

    assert evaluate_gitlab_rules(job) is GuardVerdict.RUNTIME


def test_gitlab_rules_earlier_runtime_blocks_later_static_dead_proof():
    job = {
        "rules": [
            {"if": '$CI_PIPELINE_SOURCE == "merge_request_event"', "when": "never"},
            {"if": "true", "when": "never"},
        ]
    }

    assert evaluate_gitlab_rules(job, GitLabContext()) is GuardVerdict.RUNTIME


def test_gitlab_rules_static_false_allows_later_static_dead_rule():
    job = {
        "rules": [
            {"if": "false", "when": "never"},
            {"if": "true", "when": "never"},
        ]
    }

    assert evaluate_gitlab_rules(job) is GuardVerdict.DEAD


def test_find_dead_gitlab_job_ranges_for_literal_when_never():
    content = dedent(
        """
        stages:
          - test

        dead_job:
          rules:
            - if: "true"
              when: never
          script:
            - echo $CI_COMMIT_REF_NAME

        live_job:
          script:
            - echo $CI_COMMIT_REF_NAME
        """
    ).lstrip()

    assert find_dead_gitlab_job_ranges(content) == [(4, 9)]


def test_pipeline_whole_dead_all_when_never():
    """Every job has bare ``when: never`` -> whole pipeline is dead."""
    content = dedent(
        """
        stages:
          - test

        job_a:
          stage: test
          rules:
            - when: never
          script: [echo a]

        job_b:
          stage: test
          rules:
            - when: never
          script: [echo b]
        """
    ).lstrip()
    assert is_pipeline_whole_dead(content) is True


def test_pipeline_whole_dead_mixed_blocks():
    """One unconditional job -> not whole-dead."""
    content = dedent(
        """
        stages:
          - test

        dead:
          stage: test
          rules:
            - when: never
          script: [echo dead]

        live:
          stage: test
          script: [echo live]
        """
    ).lstrip()
    assert is_pipeline_whole_dead(content) is False


def test_pipeline_whole_dead_empty_yields_false():
    """A file with no jobs is not 'whole-dead'."""
    assert is_pipeline_whole_dead("stages: [test]\n") is False


def test_pipeline_whole_dead_runtime_blocks():
    """A job with a RUNTIME guard prevents whole-dead classification."""
    content = dedent(
        """
        conditional:
          rules:
            - if: '$CI_PIPELINE_SOURCE == "schedule"'
              when: never
          script: [echo a]

        always_dead:
          rules:
            - when: never
          script: [echo b]
        """
    ).lstrip()
    assert is_pipeline_whole_dead(content) is False

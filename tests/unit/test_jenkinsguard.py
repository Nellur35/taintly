from textwrap import dedent

from taintly.jenkinsguard import (
    GuardVerdict,
    evaluate_jenkins_when,
    find_dead_jenkins_stage_ranges,
    is_jenkinsfile_whole_dead,
    is_literal_false_when,
)


def test_jenkins_when_without_block_is_live():
    assert evaluate_jenkins_when({}) is GuardVerdict.LIVE


def test_jenkins_when_literal_false_expression_is_dead():
    stage = {"when": "expression { false }"}

    assert evaluate_jenkins_when(stage) is GuardVerdict.DEAD


def test_jenkins_when_return_false_expression_is_dead():
    assert is_literal_false_when("expression { return false }")


def test_jenkins_when_negated_true_expression_is_dead():
    assert is_literal_false_when("not { expression { true } }")


def test_jenkins_when_parameter_expression_stays_runtime():
    stage = {"when": "expression { params.RUN_DEPLOY == 'true' }"}

    assert evaluate_jenkins_when(stage) is GuardVerdict.RUNTIME


def test_find_dead_jenkins_stage_ranges_for_literal_false_stage():
    content = dedent(
        """
        pipeline {
          agent any
          stages {
            stage('Dead') {
              when {
                expression { false }
              }
              steps {
                sh "echo ${params.BRANCH_NAME}"
              }
            }
            stage('Live') {
              steps {
                sh "echo ${params.BRANCH_NAME}"
              }
            }
          }
        }
        """
    ).lstrip()

    assert find_dead_jenkins_stage_ranges(content) == [(4, 11)]


def test_jenkinsfile_whole_dead_all_when_false():
    """Every stage has ``when { expression { false } }`` -> whole-dead."""
    content = dedent(
        """
        pipeline {
            agent any
            stages {
                stage('a') {
                    when { expression { false } }
                    steps { sh 'echo a' }
                }
                stage('b') {
                    when { expression { false } }
                    steps { sh 'echo b' }
                }
            }
        }
        """
    ).lstrip()
    assert is_jenkinsfile_whole_dead(content) is True


def test_jenkinsfile_whole_dead_mixed():
    """One unconditional stage -> not whole-dead."""
    content = dedent(
        """
        pipeline {
            agent any
            stages {
                stage('dead') {
                    when { expression { false } }
                    steps { sh 'echo dead' }
                }
                stage('live') {
                    steps { sh 'echo live' }
                }
            }
        }
        """
    ).lstrip()
    assert is_jenkinsfile_whole_dead(content) is False


def test_jenkinsfile_whole_dead_no_stages():
    """A pipeline without an explicit stages block -> not whole-dead."""
    content = "pipeline { agent any }\n"
    assert is_jenkinsfile_whole_dead(content) is False


def test_stage_blocks_ignores_stage_token_in_line_comment():
    """A ``//`` comment that mentions ``stage("…")`` must not consume
    a later real stage.  The previous regex-based implementation used
    a non-greedy ``.*?`` that could extend across the comment and the
    next real stage, then ``finditer`` would resume past the consumed
    real stage — silently dropping it from the enumeration."""
    content = dedent(
        """
        // Example doc: stage("Fake") in comment
        pipeline {
            stages {
                stage("LiveOne") { steps { sh "echo live" } }
                stage("DeadOne") {
                    when { expression { return false } }
                    steps { sh "echo dead" }
                }
            }
        }
        """
    ).lstrip()

    stages = find_dead_jenkins_stage_ranges(content)
    # Only DeadOne is dead; LiveOne must NOT be in the dead-range list.
    assert len(stages) == 1
    dead_start, _ = stages[0]
    assert "DeadOne" in content.splitlines()[dead_start - 1]

    # And the whole file must not be classed as whole-dead — the
    # earlier bug returned True here because LiveOne was swallowed
    # by the regex match starting in the comment.
    assert is_jenkinsfile_whole_dead(content) is False


def test_stage_blocks_ignores_stage_token_in_block_comment():
    """``/* … */`` block comments mentioning ``stage("…")`` must not
    suppress a later real stage either."""
    content = dedent(
        """
        /*
         * Migration note: the old `stage("Legacy")` was removed
         * in 2024 — see CHANGELOG for the replacement.
         */
        pipeline {
            stages {
                stage("Live") {
                    steps { sh "echo live" }
                }
            }
        }
        """
    ).lstrip()

    assert is_jenkinsfile_whole_dead(content) is False
    assert find_dead_jenkins_stage_ranges(content) == []

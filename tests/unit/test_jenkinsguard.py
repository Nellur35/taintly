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

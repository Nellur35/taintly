from textwrap import dedent

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def _jenkins_rules():
    return [rule for rule in load_all_rules() if rule.platform == Platform.JENKINS]


def _scan(content: str):
    return scan_file(
        "Jenkinsfile",
        _jenkins_rules(),
        _content=dedent(content).lstrip(),
    )


def test_dead_jenkins_stage_with_literal_false_when_suppresses_findings():
    findings = _scan(
        """
        pipeline {
          agent { label 'trusted-linux' }
          stages {
            stage('Dead') {
              when {
                expression { false }
              }
              steps {
                sh "echo ${params.BRANCH_NAME}"
              }
            }
          }
        }
        """
    )

    assert not [f for f in findings if f.rule_id == "SEC4-JK-001"]


def test_live_jenkins_stage_without_when_keeps_findings():
    findings = _scan(
        """
        pipeline {
          agent { label 'trusted-linux' }
          stages {
            stage('Live') {
              steps {
                sh "echo ${params.BRANCH_NAME}"
              }
            }
          }
        }
        """
    )

    assert [f for f in findings if f.rule_id == "SEC4-JK-001"]


def test_runtime_jenkins_when_keeps_findings():
    findings = _scan(
        """
        pipeline {
          agent { label 'trusted-linux' }
          stages {
            stage('Maybe') {
              when {
                expression { params.RUN_DEPLOY == 'true' }
              }
              steps {
                sh "echo ${params.BRANCH_NAME}"
              }
            }
          }
        }
        """
    )

    assert [f for f in findings if f.rule_id == "SEC4-JK-001"]


def test_dead_stage_suppression_does_not_hide_live_stage_findings():
    findings = _scan(
        """
        pipeline {
          agent { label 'trusted-linux' }
          stages {
            stage('Dead') {
              when { expression { false } }
              steps {
                sh "echo ${params.DEAD_BRANCH}"
              }
            }
            stage('Live') {
              steps {
                sh "echo ${params.LIVE_BRANCH}"
              }
            }
          }
        }
        """
    )

    sec4 = [f for f in findings if f.rule_id == "SEC4-JK-001"]
    assert len(sec4) == 1
    assert "LIVE_BRANCH" in sec4[0].snippet

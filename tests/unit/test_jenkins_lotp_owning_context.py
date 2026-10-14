"""Bounded source ownership controls for Jenkins LOTP candidates."""

from __future__ import annotations

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


def _target_findings(content: str):
    rules = [
        rule
        for rule in load_rules_for_platform(Platform.JENKINS)
        if rule.id in {"LOTP-JK-001", "LOTP-JK-003"}
    ]
    return scan_file("Jenkinsfile", rules, _content=content)


def test_lotp_jk_001_only_matches_executable_shell_build_commands():
    content = """
pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        echo "PR ${env.CHANGE_ID}"
        echo 'npm ci'
        sh 'echo npm ci'
        sh 'npm ci'
      }
    }
  }
}
"""
    rules = load_rules_for_platform(Platform.JENKINS)
    rule = next(rule for rule in rules if rule.id == "LOTP-JK-001")

    assert rule.pattern.check(content, content.splitlines()) == [(10, "sh 'npm ci'")]


def test_lotp_jk_001_maps_each_build_command_to_its_source_line():
    content = """
pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        echo "PR ${env.CHANGE_ID}"
        sh '''
          npm ci
            pip install .'''
      }
    }
  }
}
"""
    findings = [
        finding for finding in _target_findings(content) if finding.rule_id == "LOTP-JK-001"
    ]

    # Both commands belong to one Jenkins shell leaf, but each finding must
    # point to the command's own source line and retain that command as evidence.
    assert [(finding.line, finding.snippet) for finding in findings] == [
        (9, "npm ci"),
        (10, "pip install .'''"),
    ]

    same_line = """
pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        echo "PR ${env.CHANGE_ID}"
        sh 'npm ci; pip install .'
      }
    }
  }
}
"""
    same_line_findings = [
        finding for finding in _target_findings(same_line) if finding.rule_id == "LOTP-JK-001"
    ]
    assert [(finding.line, finding.snippet) for finding in same_line_findings] == [
        (8, "npm ci"),
        (8, "pip install ."),
    ]


def test_same_occurrence_checkout_and_enclosing_binding_are_described_conditionally():
    content = """
pipeline {
  agent any
  stages {
    stage('source and build') {
      steps {
        checkout([$class: 'GitSCM', branches: [[name: env.CHANGE_BRANCH]], userRemoteConfigs: [[url: 'https://example.test/repo.git']]])
        withCredentials([string(credentialsId: 'build-token', variable: 'TOKEN')]) {
          sh 'npm ci'
        }
      }
    }
  }
}
"""
    findings = _target_findings(content)

    assert {finding.rule_id for finding in findings} == {"LOTP-JK-001", "LOTP-JK-003"}
    for finding in findings:
        assert finding.confidence == "medium"
        assert finding.review_needed is True
        assert finding.exploitability == "medium"
        assert any("literal provider-ref GitSCM checkout" in note for note in finding.context_notes)
        assert any(
            "lexically enclosed by a direct withCredentials binding" in note
            for note in finding.context_notes
        )
        assert "automatic" not in finding.description.lower()


def test_identical_same_line_shell_calls_do_not_manufacture_duplicate_evidence():
    content = "node { echo env.CHANGE_ID; sh 'npm ci'; sh 'npm ci' }"
    findings = _target_findings(content)
    builds = [finding for finding in findings if finding.rule_id == "LOTP-JK-001"]

    assert len(builds) == 1
    assert (builds[0].line, builds[0].snippet) == (1, content)
    assert builds[0].review_needed is True
    assert any("ambiguous" in note for note in builds[0].context_notes)


def test_sibling_credential_closure_cannot_donate_to_same_named_stage():
    content = """
pipeline {
  agent any
  stages {
    stage('source and build') {
      steps {
        checkout([$class: 'GitSCM', branches: [[name: env.CHANGE_BRANCH]], userRemoteConfigs: [[url: 'https://example.test/repo.git']]])
        sh 'npm ci'
      }
    }
    stage('source and build') {
      steps {
        withCredentials([string(credentialsId: 'deploy-token', variable: 'TOKEN')]) {
          sh 'echo separate'
        }
      }
    }
  }
}
"""
    findings = _target_findings(content)

    assert len(findings) == 2
    for finding in findings:
        assert finding.review_needed is True
        assert any("literal provider-ref GitSCM checkout" in note for note in finding.context_notes)
        assert not any(
            "lexically enclosed by a direct withCredentials binding" in note
            for note in finding.context_notes
        )


def test_checkout_and_credential_fields_must_share_supported_direct_owners():
    conditional_checkout = """
pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        if (env.CHANGE_ID) {
          checkout([$class: 'GitSCM', branches: [[name: env.CHANGE_BRANCH]]])
        }
        withCredentials([
          string(credentialsId: 'build-token'),
          string(variable: 'TOKEN')
        ]) {
          sh 'npm ci'
        }
      }
    }
  }
}
"""
    decoy_checkout = """
pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        checkout([$class: 'GitSCM', branches: [[name: 'main']], extensions: [[name: env.CHANGE_BRANCH]]])
        withCredentials([string(credentialsId: 'build-token', variable: 'TOKEN')]) {
          sh 'npm ci'
        }
      }
    }
  }
}
"""

    for content in (conditional_checkout, decoy_checkout):
        findings = _target_findings(content)
        assert len(findings) == 2
        for finding in findings:
            assert finding.review_needed is True
            assert not any(
                "literal provider-ref GitSCM checkout" in note for note in finding.context_notes
            )
        if content is conditional_checkout:
            assert not any(
                "lexically enclosed by a direct withCredentials binding" in note
                for note in findings[0].context_notes
            )


def test_candidates_without_unique_complete_occurrence_remain_generic():
    content = """
pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        echo "PR ${env.CHANGE_ID}"
        withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {
          sh 'npm ci'
"""
    findings = _target_findings(content)

    assert {finding.rule_id for finding in findings} == {"LOTP-JK-001", "LOTP-JK-003"}
    for finding in findings:
        assert finding.review_needed is True
        assert not any(
            "lexically enclosed by a direct withCredentials binding" in note
            for note in finding.context_notes
        )


def test_distinct_same_line_shell_leaves_keep_distinct_command_snippets():
    content = "node { echo env.CHANGE_ID; sh 'npm ci'; sh 'pip install .' }"
    findings = [
        finding for finding in _target_findings(content) if finding.rule_id == "LOTP-JK-001"
    ]

    assert [(finding.line, finding.snippet) for finding in findings] == [
        (1, "npm ci"),
        (1, "pip install ."),
    ]

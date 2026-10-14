"""Direct declaration evidence controls; runtime authority remains unknown."""

from __future__ import annotations

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform

CASES = {
    "bare_main": "pipeline {\n"
    "  agent any\n"
    "  options { skipDefaultCheckout(true) }\n"
    "  stages { stage('build') { steps {\n"
    '        echo "PR ${env.CHANGE_ID}"\n'
    "    checkout([$class: 'GitSCM', branches: [[name: main]]])\n"
    "    withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) { sh 'npm "
    "ci' }\n"
    "  } } }\n"
    "}",
    "direct_binding_positive": "pipeline {\n"
    "  agent any\n"
    "  stages { stage('build') { steps {\n"
    '        echo "PR ${env.CHANGE_ID}"\n'
    "    withCredentials([string(credentialsId: 'literal', variable: "
    "'TOKEN')]) { sh 'npm ci' }\n"
    "  } } }\n"
    "}",
    "duplicate_branches": "pipeline {\n"
    "  agent any\n"
    "  options { skipDefaultCheckout(true) }\n"
    "  stages { stage('build') { steps {\n"
    '        echo "PR ${env.CHANGE_ID}"\n'
    "    checkout([$class: 'GitSCM', branches: [[name: env.CHANGE_BRANCH, name: "
    "'main']]])\n"
    "    withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) { "
    "sh 'npm ci' }\n"
    "  } } }\n"
    "}",
    "duplicate_credentials": "pipeline {\n"
    "  agent any\n"
    "  stages { stage('build') { steps {\n"
    '        echo "PR ${env.CHANGE_ID}"\n'
    "    withCredentials([string(credentialsId: 'literal', credentialsId: "
    "lookup(), variable: 'TOKEN')]) { sh 'npm ci' }\n"
    "  } } }\n"
    "}",
    "nested_wrapper": "pipeline {\n"
    "  agent any\n"
    "  stages { stage('build') { steps {\n"
    '        echo "PR ${env.CHANGE_ID}"\n'
    "    withCredentials([wrapper([string(credentialsId: 'literal', variable: "
    "'TOKEN')])]) { sh 'npm ci' }\n"
    "  } } }\n"
    "}",
    "provider_checkout_positive": "pipeline {\n"
    "  agent any\n"
    "  stages { stage('build') { steps {\n"
    '        echo "PR ${env.CHANGE_ID}"\n'
    "    checkout([$class: 'GitSCM', branches: [[name: "
    "env.CHANGE_BRANCH]]])\n"
    "    withCredentials([string(credentialsId: 'token', variable: "
    "'TOKEN')]) { sh 'npm ci' }\n"
    "  } } }\n"
    "}",
    "quoted_main": "pipeline {\n"
    "  agent any\n"
    "  options { skipDefaultCheckout(true) }\n"
    "  stages { stage('build') { steps {\n"
    '        echo "PR ${env.CHANGE_ID}"\n'
    "    checkout([$class: 'GitSCM', branches: [[name: 'main']]])\n"
    "    withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) { sh "
    "'npm ci' }\n"
    "  } } }\n"
    "}",
    "skip_outside_options": "pipeline {\n"
    "  agent any\n"
    "  stages { stage('build') { steps {\n"
    '        echo "PR ${env.CHANGE_ID}"\n'
    "    ciConfig.skipDefaultCheckout(true)\n"
    "    checkout([$class: 'GitSCM', branches: [[name: 'main']]])\n"
    "    withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) "
    "{ sh 'npm ci' }\n"
    "  } } }\n"
    "}",
    "valid_options_positive": "pipeline {\n"
    "  agent any\n"
    "  options { skipDefaultCheckout(true) }\n"
    "  stages { stage('build') { steps {\n"
    '        echo "PR ${env.CHANGE_ID}"\n'
    "    checkout([$class: 'GitSCM', branches: [[name: 'main']]])\n"
    "    withCredentials([string(credentialsId: 'token', variable: "
    "'TOKEN')]) { sh 'npm ci' }\n"
    "  } } }\n"
    "}",
}
RULES = [
    rule
    for rule in load_rules_for_platform(Platform.JENKINS)
    if rule.id in {"LOTP-JK-001", "LOTP-JK-003"}
]


def findings(case: str):
    return scan_file("Jenkinsfile", RULES, _content=CASES[case])


def notes(case: str):
    found = findings(case)
    assert {item.rule_id for item in found} == {"LOTP-JK-001", "LOTP-JK-003"}
    return found


def test_bare_main_is_not_attested_as_literal_checkout():
    assert all(
        not any("literal GitSCM main branch checkout" in note for note in item.context_notes)
        for item in notes("bare_main")
    )


def test_skip_default_checkout_must_be_owned_by_pipeline_options():
    assert all(
        not any("literal GitSCM main branch checkout" in note for note in item.context_notes)
        for item in notes("skip_outside_options")
    )
    assert all(
        any("literal GitSCM main branch checkout" in note for note in item.context_notes)
        for item in notes("valid_options_positive")
    )


def test_direct_provider_checkout_is_recognized():
    assert all(
        any("literal provider-ref GitSCM checkout" in note for note in item.context_notes)
        for item in notes("provider_checkout_positive")
    )


def test_duplicate_checkout_branch_names_do_not_prove_provider_ref():
    assert all(
        not any("literal provider-ref GitSCM checkout" in note for note in item.context_notes)
        for item in notes("duplicate_branches")
    )


def test_duplicate_or_nested_credential_binding_is_not_direct_evidence():
    for case in ("duplicate_credentials", "nested_wrapper"):
        assert all(
            not any("direct withCredentials binding" in note for note in item.context_notes)
            for item in notes(case)
        )
    assert all(
        any("direct withCredentials binding" in note for note in item.context_notes)
        for item in notes("direct_binding_positive")
    )

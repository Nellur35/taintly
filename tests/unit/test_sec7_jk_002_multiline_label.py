"""SEC7-JK-002 — declarative ``agent { node { label 'x' } }`` must not fire.

Real Jenkinsfiles (Kong build-tools, Hibernate, etc.) commonly use
the declarative pipeline's agent directive with a nested node block
whose ``label`` is on a separate line:

    agent {
      node {
        label 'bionic'
      }
    }

The prior single-line regex anchored on ``node {`` and only
excluded the inline ``node('x') { }`` form, so multi-line
declarative shapes generated false positives.

Spec:
- TP-1: bare scripted ``node { stage(...) }`` — must fire
- TP-2: ``node() { ... }`` empty-parens form — must fire
- TN-1: ``node('label') { ... }`` inline-label — must not fire (regression)
- TN-2: ``agent { node { label 'bionic' } }`` — must not fire
- TN-3: ``agent { node { customWorkspace '/foo'; label 'linux' } }``
        — label not on the immediate next line — must not fire
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


@pytest.fixture(scope="module")
def jenkins_rules():
    return load_rules_for_platform(Platform.JENKINS)


def _write(tmp_path: Path, content: str) -> Path:
    target = tmp_path / "Jenkinsfile"
    target.write_text(content, encoding="utf-8")
    return target


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_fires_on_bare_scripted_node_block(tmp_path, jenkins_rules):
    f = _write(tmp_path, "node {\n    stage('Build') { sh 'make' }\n}\n")
    findings = scan_file(str(f), jenkins_rules)
    assert "SEC7-JK-002" in _rule_ids(findings)


def test_fires_on_empty_parens_node_block(tmp_path, jenkins_rules):
    f = _write(tmp_path, "node() {\n    checkout scm\n    sh './build.sh'\n}\n")
    findings = scan_file(str(f), jenkins_rules)
    assert "SEC7-JK-002" in _rule_ids(findings)


def test_does_not_fire_on_declarative_agent_node_label(tmp_path, jenkins_rules):
    """The most common real-world FP shape."""
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  stages {\n"
        "    stage('Build') {\n"
        "      agent {\n"
        "        node {\n"
        "          label 'bionic'\n"
        "        }\n"
        "      }\n"
        "      steps { sh 'make' }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    findings = scan_file(str(f), jenkins_rules)
    assert "SEC7-JK-002" not in _rule_ids(findings)


def test_does_not_fire_on_node_with_label_second_line(tmp_path, jenkins_rules):
    """Label declaration not on the immediate next line — walker
    must scan the full node block, not just the next line."""
    f = _write(
        tmp_path,
        "agent {\n"
        "  node {\n"
        "    customWorkspace '/foo'\n"
        "    label 'linux-benchmark-node'\n"
        "  }\n"
        "}\n",
    )
    findings = scan_file(str(f), jenkins_rules)
    assert "SEC7-JK-002" not in _rule_ids(findings)


def test_does_not_fire_on_inline_label_node_call(tmp_path, jenkins_rules):
    """Regression: the inline ``node('label')`` scripted form was
    already excluded by the prior regex; must remain excluded."""
    f = _write(tmp_path, "node('linux') {\n    sh 'make'\n}\n")
    findings = scan_file(str(f), jenkins_rules)
    assert "SEC7-JK-002" not in _rule_ids(findings)


def test_does_not_fire_on_commented_node_block(tmp_path, jenkins_rules):
    f = _write(tmp_path, "// node {\n//     sh 'make'\n// }\n")
    findings = scan_file(str(f), jenkins_rules)
    assert "SEC7-JK-002" not in _rule_ids(findings)


def test_fires_on_outer_bare_node_when_inner_has_label(tmp_path, jenkins_rules):
    """Brace-depth tracking: an outer bare ``node { ... }`` with an
    inner labelled inline call should still fire on the outer."""
    f = _write(
        tmp_path,
        "node {\n"
        "  stage('outer') {\n"
        "    node('inner-label') {\n"
        "      sh 'make'\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    findings = scan_file(str(f), jenkins_rules)
    sec7 = [f for f in findings if f.rule_id == "SEC7-JK-002"]
    assert len(sec7) >= 1

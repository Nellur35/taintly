"""Focused precision regressions for three Jenkins rules.

These cases cover installer context, declarative agent labels, and pipeline
cleanup scope. They deliberately keep security-relevant positives alongside
safe controls.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


def _scan(tmp_path: Path, content: str) -> set[str]:
    path = tmp_path / "Jenkinsfile"
    path.write_text(content, encoding="utf-8")
    findings = scan_file(str(path), load_rules_for_platform(Platform.JENKINS))
    return {finding.rule_id for finding in findings}


def _pattern_matches(rule_id: str, content: str) -> list[tuple[int, str]]:
    rules = load_rules_for_platform(Platform.JENKINS)
    rule = next(rule for rule in rules if rule.id == rule_id)
    return rule.pattern.check(content, content.splitlines())


def test_lotp_jk_003_ignores_environment_names_and_stage_labels(tmp_path: Path):
    ids = _scan(
        tmp_path,
        "environment { CURRENT_VOLTO = '18-yarn' }\n"
        "pipeline {\n"
        "  stages { stage('Volto 18-yarn') { steps { sh 'echo ready' } } }\n"
        "}\n"
        "echo env.CHANGE_ID\n",
    )

    assert "LOTP-JK-003" not in ids


def test_lotp_jk_003_fires_for_pr_reachable_real_installer(tmp_path: Path):
    ids = _scan(
        tmp_path,
        "pipeline {\n"
        "  stages { stage('Build') { steps {\n"
        "    echo env.CHANGE_ID\n"
        "    sh(script: \"\"\"\n"
        "      npm ci\n"
        "    \"\"\")\n"
        "  } } }\n"
        "}\n",
    )

    assert "LOTP-JK-003" in ids


def test_lotp_jk_003_ignores_installer_tokens_in_comments_and_strings(tmp_path: Path):
    content = (
        "// env.CHANGE_ID; sh 'npm install'\n"
        "def note = 'env.CHANGE_ID and npm install'\n"
        "pipeline { stages { stage('Safe') { steps { echo note } } } }\n"
    )
    assert not _pattern_matches("LOTP-JK-003", content)


def test_lotp_jk_003_flags_unsafe_install_and_allows_ignore_scripts(tmp_path: Path):
    unsafe = "echo env.CHANGE_ID\nsh 'npm ci'\n"
    safe = "echo env.CHANGE_ID\nsh 'npm ci --ignore-scripts'\n"

    assert _pattern_matches("LOTP-JK-003", unsafe)
    assert not _pattern_matches("LOTP-JK-003", safe)


def test_sec7_jk_002_ignores_labeled_declarative_agent_node(tmp_path: Path):
    ids = _scan(
        tmp_path,
        "pipeline {\n"
        "  agent { node { label 'docker-host' } }\n"
        "  stages { stage('Build') { steps { sh 'make' } } }\n"
        "}\n",
    )

    assert "SEC7-JK-002" not in ids


def test_sec7_jk_002_ignores_multiline_labeled_declarative_agent_node(tmp_path: Path):
    ids = _scan(
        tmp_path,
        "pipeline {\n"
        "  agent {\n"
        "    node {\n"
        "      label 'docker-host'\n"
        "    }\n"
        "  }\n"
        "  stages { stage('Build') { steps { sh 'make' } } }\n"
        "}\n",
    )

    assert "SEC7-JK-002" not in ids


def test_sec7_jk_002_still_fires_for_unlabeled_scripted_node(tmp_path: Path):
    ids = _scan(
        tmp_path,
        "node {\n"
        "  echo 'agent { node { label \\\"docker-host\\\" } }'\n"
        "  sh 'make'\n"
        "}\n",
    )

    assert "SEC7-JK-002" in ids


def test_sec7_jk_002_accepts_inline_label_inside_multiline_agent(tmp_path: Path):
    content = (
        "pipeline {\n  agent {\n    node { label 'docker-host' }\n  }\n"
        "  stages { stage('Build') { steps { sh 'make' } } }\n}\n"
    )
    assert "SEC7-JK-002" not in _scan(tmp_path, content)


def test_sec7_jk_002_scripted_label_statement_does_not_constrain_allocation(tmp_path: Path):
    content = "node {\n  label 'trusted'\n  sh 'make'\n}\n"
    assert "SEC7-JK-002" in _scan(tmp_path, content)


def test_sec7_jk_002_unrelated_label_data_does_not_suppress_node(tmp_path: Path):
    ids = _scan(
        tmp_path,
        "def note = \"label 'docker-host'\"\n"
        "node {\n"
        "  sh 'make'\n"
        "}\n",
    )

    assert "SEC7-JK-002" in ids


def test_sec10_jk_001_accepts_pipeline_cleanup_after_long_pipeline(tmp_path: Path):
    lines = ["pipeline {", "  stages {"]
    lines.extend("    // stage body line" for _ in range(397))
    lines.extend(
        [
            "  }",
            "  post { always { cleanWs() } }",
            "}",
        ]
    )
    content = "\n".join(lines) + "\n"

    assert not _pattern_matches("SEC10-JK-001", content)


def test_sec10_jk_001_requires_pipeline_scope_cleanup(tmp_path: Path):
    content = (
        "pipeline {\n"
        "  stages {\n"
        "    stage('Build') {\n"
        "      steps { sh 'make' }\n"
        "      post { always { cleanWs() } }\n"
        "    }\n"
        "  }\n"
        "}\n"
    )

    assert _pattern_matches("SEC10-JK-001", content)


def test_sec10_jk_001_failure_only_post_does_not_count_as_always(tmp_path: Path):
    content = (
        "pipeline {\n"
        "  stages { stage('Build') { steps { sh 'make' } } }\n"
        "  post { failure { cleanWs() } }\n"
        "}\n"
    )

    assert _pattern_matches("SEC10-JK-001", content)


def test_sec10_jk_001_does_not_accept_comment_or_string_pseudo_post(tmp_path: Path):
    content = (
        "pipeline {\n"
        "  // post { always { cleanWs() } }\n"
        "  stages { stage('Build') { steps {\n"
        "    echo 'post { always { cleanWs() } }'\n"
        "  } } }\n"
        "}\n"
    )

    assert _pattern_matches("SEC10-JK-001", content)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("if true; then npm install; fi", True),
        ("echo $(npm install)", True),
        ("npm " + chr(92) + "\ninstall", True),
        ("npm install --ignore-scripts=true", False),
        ('npm install --prefix "a --ignore-scripts b"', True),
        ("echo '$(npm install)'", False),
        ('echo "' + chr(92) + '$(npm install)"', False),
        ("npm install '" + chr(92) + "\n--ignore-scripts'", True),
        ("npm install --ignore-scripts=false", True),
        ("npm ci --ignore-scripts; npm install", True),
    ],
)
def test_installer_executable_boundaries_and_boolean_flags(body: str, expected: bool):
    content = "echo env.CHANGE_ID\nsh '''" + body + "'''\n"
    matches = _pattern_matches("LOTP-JK-003", content)
    assert bool(matches) is expected
    if matches:
        assert matches[0][0] == 2  # Source-derived shell call-site attribution.


def test_cleanup_in_one_pipeline_cannot_satisfy_another():
    content = (
        "pipeline { post { always { cleanWs() } } }\n"
        "pipeline { stages { stage('Build') { steps { sh 'make' } } } }\n"
    )
    assert [line for line, _snippet in _pattern_matches("SEC10-JK-001", content)] == [2]


def test_sec10_jk_001_pipeline_post_does_not_cover_a_second_pipeline(tmp_path: Path):
    content = (
        "pipeline {\n  post { always { cleanWs() } }\n}\n"
        "pipeline {\n  stages { stage('Build') { steps { sh 'make' } } }\n}\n"
    )

    assert _pattern_matches("SEC10-JK-001", content)

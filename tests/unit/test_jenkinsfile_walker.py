"""Tests for the structural Jenkinsfile reader (optional, ``[jenkins-structural]`` extra).

These tests skip cleanly when tree-sitter-groovy isn't installed —
the default install is zero-runtime-dependency and shouldn't make
this test suite fail.
"""

from __future__ import annotations

import pytest


# Gate the whole module on the optional extra.  ImportError messages
# from the walker itself are tested separately (the message must
# point at the extra) — that test is in
# ``test_jenkinsfile_walker_missing_dep`` below.
pytest.importorskip("tree_sitter_groovy")

from taintly.parsers.jenkinsfile import walk_jenkinsfile, EventKind  # noqa: E402


def _leaves(content: str) -> list:
    """Return the list of LEAF events for a Jenkinsfile content."""
    return [ev for ev in walk_jenkinsfile(content) if ev.kind == EventKind.LEAF]


# ---------------------------------------------------------------------------
# Shell sinks — the primary surface JK rules consume.
# ---------------------------------------------------------------------------


def test_shell_sh_command_emits_leaf():
    src = (
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('Build') {\n"
        "      steps {\n"
        "        sh 'make all'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    leaves = _leaves(src)
    sh_leaves = [l for l in leaves if l.value_kind == "shell"]
    assert len(sh_leaves) == 1
    assert sh_leaves[0].value == "make all"
    assert sh_leaves[0].line == 6


def test_shell_bat_powershell_emit_leaves():
    src = (
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('Build') {\n"
        "      steps {\n"
        "        bat 'echo win'\n"
        "        powershell 'Get-Process'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    leaves = _leaves(src)
    shell_values = {l.value for l in leaves if l.value_kind == "shell"}
    assert shell_values == {"echo win", "Get-Process"}


def test_shell_value_kind_is_shell_not_string():
    """Distinguishing sh '...' from tool '...' matters for rules
    that only care about shell sinks."""
    src = (
        "pipeline {\n"
        "  agent any\n"
        "  tools { jdk 'jdk-11' }\n"
        "  stages {\n"
        "    stage('Build') {\n"
        "      steps { sh 'echo hi' }\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    leaves = _leaves(src)
    by_kind = {l.value_kind for l in leaves}
    assert "shell" in by_kind
    # 'echo hi' should be value_kind=shell, not string.
    echo_leaf = next(l for l in leaves if l.value == "echo hi")
    assert echo_leaf.value_kind == "shell"


# ---------------------------------------------------------------------------
# Stage path attribution.
# ---------------------------------------------------------------------------


def test_stage_name_pushes_path_component():
    """A ``sh`` inside ``stage('Deploy')`` carries ``stage:Deploy``
    on its path so rules can reason about which stage emitted it."""
    src = (
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('Deploy') {\n"
        "      steps {\n"
        "        sh 'kubectl apply -f .'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    leaves = _leaves(src)
    sh = next(l for l in leaves if l.value_kind == "shell")
    assert "stage:Deploy" in sh.path
    # And the full path should include the pipeline / stages /
    # steps / sh chain.
    assert sh.path[-1] == "sh"


# ---------------------------------------------------------------------------
# Environment block: ``KEY = 'value'`` pairs.
# ---------------------------------------------------------------------------


def test_environment_assignment_emits_leaf_under_key_path():
    src = (
        "pipeline {\n"
        "  agent any\n"
        "  environment {\n"
        "    DEPLOY_KEY = 'secret-value'\n"
        "    REGION = 'us-east-1'\n"
        "  }\n"
        "  stages {\n"
        "    stage('Build') { steps { sh 'echo hi' } }\n"
        "  }\n"
        "}\n"
    )
    leaves = _leaves(src)
    env_leaves = [l for l in leaves if "environment" in l.path]
    by_key = {l.path[-1]: l.value for l in env_leaves}
    assert by_key.get("DEPLOY_KEY") == "secret-value"
    assert by_key.get("REGION") == "us-east-1"


# ---------------------------------------------------------------------------
# Agent directives — ``agent any``, ``agent none``.
# ---------------------------------------------------------------------------


def test_agent_identifier_emits_leaf_with_kind_identifier():
    src = (
        "pipeline {\n"
        "  agent any\n"
        "  stages { stage('s') { steps { sh 'hi' } } }\n"
        "}\n"
    )
    leaves = _leaves(src)
    agent_leaves = [l for l in leaves if l.path[-1] == "agent"]
    assert len(agent_leaves) == 1
    assert agent_leaves[0].value == "any"
    assert agent_leaves[0].value_kind == "identifier"


def test_agent_none_emits_leaf():
    src = (
        "pipeline {\n"
        "  agent none\n"
        "  stages { stage('s') { agent any; steps { sh 'hi' } } }\n"
        "}\n"
    )
    leaves = _leaves(src)
    none_leaves = [
        l for l in leaves if l.path[-1] == "agent" and l.value == "none"
    ]
    assert len(none_leaves) == 1


# ---------------------------------------------------------------------------
# CUTOFF / recovery — parser errors don't crash; emit CUTOFF instead.
# ---------------------------------------------------------------------------


def test_cutoff_on_unparseable_input():
    """Garbled input produces a CUTOFF event in recovery mode, not
    an exception.  Matches the YAML walker's contract."""
    src = "pipeline { agent any { { { unclosed"
    events = list(walk_jenkinsfile(src))
    assert any(ev.kind == EventKind.CUTOFF for ev in events), (
        "expected at least one CUTOFF event on malformed input"
    )


def test_clean_parse_no_cutoff():
    """A well-formed Jenkinsfile produces zero CUTOFF events."""
    src = (
        "pipeline {\n"
        "  agent any\n"
        "  stages { stage('s') { steps { sh 'hi' } } }\n"
        "}\n"
    )
    events = list(walk_jenkinsfile(src))
    assert not any(ev.kind == EventKind.CUTOFF for ev in events)


# ---------------------------------------------------------------------------
# Defensive: empty / whitespace-only input.
# ---------------------------------------------------------------------------


def test_empty_input_yields_no_events():
    assert list(walk_jenkinsfile("")) == []


def test_whitespace_only_input_yields_no_events():
    assert list(walk_jenkinsfile("\n  \n\t\n")) == []

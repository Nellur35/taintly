"""Tests for the within-file Jenkins multi-hop taint resolver and
TAINT-JK-003.

Covers:
  * the resolver fixed point over value-preserving Groovy bindings
    (bare ref / GString interpolation), with provenance hop chains;
  * SOUNDNESS: a tainted value used only as a method-call ARGUMENT does
    NOT leak taint to the call's return value (the verify-first
    over-taint that the naive heuristic produced);
  * quote-awareness: a single-quoted sink / RHS does not interpolate, so
    no flow is reported;
  * recall-safety: the DIRECT (zero-hop) source-in-sink case is excluded
    so TAINT-JK-003 never co-fires with TAINT-JK-001;
  * the reconstructed CVE-shaped multi-hop fixtures.

These run on a bare install — the resolver consumes the zero-dependency
``groovy_lex`` tokenizer, no optional extra required.
"""

from __future__ import annotations

import re

from taintly.parsers.jenkinsfile.multihop import resolve_multihop_flows
from taintly.rules.jenkins.taint import RULES, _TAINT_JK_003_SOURCE_RE

_SRC = _TAINT_JK_003_SOURCE_RE


def _flows(content: str):
    return resolve_multihop_flows(content, _SRC)


def _jk003():
    rule = next(r for r in RULES if r.id == "TAINT-JK-003")
    return rule


def _fires(content: str) -> list[tuple[int, str]]:
    rule = _jk003()
    return rule.pattern.check(content, content.splitlines())


# ---------------------------------------------------------------------------
# Resolver — positive flows with provenance.
# ---------------------------------------------------------------------------


def test_one_hop_param_local_to_sh():
    code = 'script {\n  def t = params.FOO\n  sh "deploy ${t}"\n}'
    flows = _flows(code)
    assert len(flows) == 1
    assert flows[0].var == "t"
    assert flows[0].sink_call == "sh"
    assert flows[0].hops == ("params.FOO", "t", "sh")


def test_two_hop_gstring_chain():
    code = 'def url = "${env.CHANGE_BRANCH}/build"\ndef cmd = "curl ${url}"\nsh "${cmd}"'
    flows = _flows(code)
    assert len(flows) == 1
    assert flows[0].hops == ("env.CHANGE_BRANCH", "url", "cmd", "sh")


def test_transform_of_tainted_local_stays_tainted():
    code = 'def t = params.TARGET\nsh "echo ${t.trim()}"'
    flows = _flows(code)
    assert len(flows) == 1
    assert flows[0].hops[0] == "params.TARGET"


def test_elvis_default_truthy_path_carries_source():
    code = "def b = env.CHANGE_BRANCH ?: 'main'\nsh \"git checkout ${b}\""
    assert len(_flows(code)) == 1


def test_bat_and_powershell_and_pwsh_sinks():
    for sink in ("bat", "powershell", "pwsh"):
        code = f'def r = env.BRANCH_NAME\n{sink} "build ${{r}}"'
        flows = _flows(code)
        assert len(flows) == 1, sink
        assert flows[0].sink_call == sink


# ---------------------------------------------------------------------------
# Soundness — over-taint guards (the verify-first false positives).
# ---------------------------------------------------------------------------


def test_method_return_does_not_propagate_taint():
    # The source is only an ARGUMENT to sanitize(); the local gets
    # sanitize()'s return value, not the attacker bytes.
    code = 'def t = sanitize(env.CHANGE_ID)\nsh "echo ${t}"'
    assert _flows(code) == []


def test_local_from_non_source_not_tainted():
    code = 'def t = config.foo\nsh "echo ${t}"'
    assert _flows(code) == []


def test_tainted_local_never_reaching_sink():
    code = 'def t = params.FOO\necho "title is ${t}"'
    assert _flows(code) == []


def test_reassignment_to_a_constant_clears_taint():
    code = 'def x = params.FOO\nx = "safe"\nsh "echo ${x}"'
    assert _flows(code) == []


def test_sink_before_source_is_not_a_flow():
    code = 'sh "echo ${x}"\ndef x = params.FOO'
    assert _flows(code) == []


def test_reverse_assignment_order_is_not_a_flow():
    code = 'def y = x\ndef x = params.FOO\nsh "echo ${y}"'
    assert _flows(code) == []


def test_same_local_name_in_separate_functions_is_not_a_flow():
    code = 'def producer() {\n  def x = params.FOO\n}\ndef consumer() {\n  sh "echo ${x}"\n}\n'
    assert _flows(code) == []


def test_undeclared_script_binding_flows_between_sibling_closures():
    code = (
        "node {\n"
        "  stage('source') { version = \"${env.BRANCH_NAME}\" }\n"
        "  stage('sink') { sh \"echo ${version}\" }\n"
        "}\n"
    )
    assert len(_flows(code)) == 1


# ---------------------------------------------------------------------------
# Quote-awareness.
# ---------------------------------------------------------------------------


def test_single_quoted_sink_does_not_interpolate():
    code = "def t = params.FOO\nsh 'echo ${t}'"
    assert _flows(code) == []


def test_single_quoted_rhs_does_not_carry_source():
    # The RHS GString is single-quoted, so Groovy never substitutes the
    # source — the local is a literal string, not tainted.
    code = "def u = '${env.CHANGE_BRANCH}'\nsh \"echo ${u}\""
    assert _flows(code) == []


# ---------------------------------------------------------------------------
# Recall-safety — direct case excluded (TAINT-JK-001's job).
# ---------------------------------------------------------------------------


def test_direct_source_in_sink_excluded():
    # Direct interpolation is TAINT-JK-001; the multi-hop resolver must
    # NOT report it so the two rules never co-fire on one body.
    code = 'sh "echo ${env.CHANGE_TITLE}"'
    assert _flows(code) == []


def test_jk003_does_not_fire_where_jk001_does():
    """A pure single-hop file: JK-001 fires, JK-003 stays silent."""
    code = 'sh "echo ${env.CHANGE_TITLE}"'
    jk001 = next(r for r in RULES if r.id == "TAINT-JK-001")
    assert jk001.pattern.check(code, code.splitlines())  # JK-001 fires
    assert _fires(code) == []  # JK-003 silent


# ---------------------------------------------------------------------------
# Rule layer — snippet carries the provenance chain.
# ---------------------------------------------------------------------------


def test_rule_snippet_renders_hop_chain():
    code = 'script {\n  def t = params.FOO\n  sh "deploy ${t}"\n}'
    hits = _fires(code)
    assert len(hits) == 1
    line, snippet = hits[0]
    assert line == 3
    assert "[taint: params.FOO -> t -> sh]" in snippet


def test_rule_never_crashes_on_unmodelled_groovy():
    # A heavily scripted/closure-laden file must not raise; worst case []
    code = (
        "@Grab('x:y:1')\n"
        "class Foo { def m() { [1,2,3].collect { it * 2 } } }\n"
        "def t = params.FOO\n"
        'sh "run ${t}"\n'
    )
    hits = _fires(code)
    # The param->sh flow should still be found through the noise.
    assert any("params.FOO" in s for _, s in hits)


# ---------------------------------------------------------------------------
# Reconstructed CVE / incident-shaped multi-hop fixtures.
# ---------------------------------------------------------------------------


def test_cve_2025_53652_git_parameter_branch_into_checkout_style():
    # CVE-2025-53652 (Git Parameter plugin): a branch build-parameter
    # flows, via a local, into a git CLI invocation in a sh step.
    code = (
        "pipeline {\n"
        "  parameters { gitParameter(name: 'BRANCH', type: 'PT_BRANCH') }\n"
        "  stages { stage('co') { steps { script {\n"
        "    def branch = params.BRANCH\n"
        '    sh "git checkout ${branch}"\n'
        "  } } } }\n"
        "}\n"
    )
    hits = _fires(code)
    assert any("params.BRANCH" in s for _, s in hits)


def test_stawinski_pr_title_reformatted_through_local():
    # PR-title injection laundered through a message-building local before
    # reaching a deploy sh — the realistic shape single-hop misses.
    code = (
        "pipeline { agent any\n"
        "  stages { stage('notify') { steps { script {\n"
        "    def title = env.CHANGE_TITLE\n"
        '    def msg = "PR opened: ${title}"\n'
        '    sh "/opt/notify ${msg}"\n'
        "  } } } }\n"
        "}\n"
    )
    flows = _flows(code)
    assert len(flows) == 1
    assert flows[0].hops == ("env.CHANGE_TITLE", "title", "msg", "sh")

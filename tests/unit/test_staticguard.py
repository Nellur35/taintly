from __future__ import annotations

from taintly.staticguard import Verdict, WorkflowContext, evaluate_if, find_dead_line_ranges


def test_evaluate_if_static_true_cases():
    assert evaluate_if(None) is Verdict.STATIC_TRUE
    assert evaluate_if("true") is Verdict.STATIC_TRUE
    assert evaluate_if("${{ true }}") is Verdict.STATIC_TRUE
    assert evaluate_if("! false") is Verdict.STATIC_TRUE


def test_evaluate_if_static_false_cases():
    assert evaluate_if("false") is Verdict.STATIC_FALSE
    assert evaluate_if("${{ false }}") is Verdict.STATIC_FALSE
    assert evaluate_if("! true") is Verdict.STATIC_FALSE


def test_evaluate_if_repo_identity_comparison():
    ctx = WorkflowContext(repository="Nellur35/taintly", repository_owner="Nellur35")

    assert evaluate_if("github.repository == 'Nellur35/taintly'", ctx) is Verdict.STATIC_TRUE
    assert evaluate_if("github.repository == 'other/repo'", ctx) is Verdict.STATIC_FALSE
    assert evaluate_if("github.repository_owner != 'other'", ctx) is Verdict.STATIC_TRUE


def test_evaluate_if_runtime_fallback():
    ctx = WorkflowContext(repository="Nellur35/taintly", repository_owner="Nellur35")

    assert evaluate_if("github.event_name == 'pull_request'", ctx) is Verdict.RUNTIME
    assert evaluate_if("success() && github.repository == 'Nellur35/taintly'", ctx) is Verdict.RUNTIME
    assert evaluate_if("${{ inputs.deploy == 'prod' }}", ctx) is Verdict.RUNTIME


def test_find_dead_line_ranges_for_dead_job_and_step():
    content = (
        "on:\n"
        "  pull_request:\n"
        "jobs:\n"
        "  dead_job:\n"
        "    if: false\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo dead job\n"
        "  live_job:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - if: ${{ false }}\n"
        "        run: echo dead step\n"
        "      - if: github.event_name == 'pull_request'\n"
        "        run: echo runtime step\n"
    )

    assert find_dead_line_ranges(content) == [(4, 8), (12, 13)]


def test_find_dead_line_ranges_for_repo_mismatch():
    content = (
        "on:\n"
        "  push:\n"
        "jobs:\n"
        "  release:\n"
        "    if: github.repository == 'other/repo'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo dead\n"
    )
    ctx = WorkflowContext(repository="Nellur35/taintly", repository_owner="Nellur35")

    assert find_dead_line_ranges(content, ctx) == [(4, 8)]


def test_yaml_quoted_expression_evaluates():
    """YAML-quoted ${{ }} expressions must be evaluated, not treated as opaque strings.

    Some style guides recommend the outer quotes to disambiguate from
    ``${{`` syntax for YAML linters.  The strip helper must unwrap the
    outer quotes before evaluating the inner Actions expression.
    """
    assert evaluate_if('"${{ false }}"') is Verdict.STATIC_FALSE
    assert evaluate_if("'${{ false }}'") is Verdict.STATIC_FALSE
    assert evaluate_if('"${{ true }}"') is Verdict.STATIC_TRUE


def test_bare_quoted_string_stays_runtime():
    """Bare YAML-quoted strings stay RUNTIME.

    Whether GHA evaluates ``"false"`` as a non-empty truthy string or
    as the boolean keyword is a semantic edge the conservative
    evaluator does not attempt to settle: only quoted strings whose
    inner content is a ``${{ }}`` expression are unwrapped.
    """
    assert evaluate_if('"false"') is Verdict.RUNTIME
    assert evaluate_if("'false'") is Verdict.RUNTIME
    # Sanity: bare unquoted boolean still evaluates.
    assert evaluate_if("false") is Verdict.STATIC_FALSE


def test_yaml_quoted_repo_comparison():
    """YAML-quoted repo comparison must evaluate against ctx."""
    ctx = WorkflowContext(repository="me/myrepo", repository_owner="me")
    assert (
        evaluate_if(
            "\"${{ github.repository_owner == 'someone-else' }}\"", ctx
        )
        is Verdict.STATIC_FALSE
    )
    assert (
        evaluate_if(
            "\"${{ github.repository_owner == 'me' }}\"", ctx
        )
        is Verdict.STATIC_TRUE
    )


def test_empty_yaml_string_stays_runtime():
    """``if: ""`` has no boolean meaning; must stay RUNTIME."""
    assert evaluate_if('""') is Verdict.RUNTIME
    assert evaluate_if("''") is Verdict.RUNTIME


def test_anchor_defined_if_resolves():
    """A job inheriting ``if: false`` via merge-key is dead."""
    content = (
        "defaults: &dead\n"
        "  if: false\n"
        "  runs-on: ubuntu-latest\n"
        "\n"
        "jobs:\n"
        "  build:\n"
        "    <<: *dead\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    ranges = find_dead_line_ranges(content)
    assert ranges, "Anchor-inherited if: false must produce a dead range"
    assert any(start <= 9 <= end for start, end in ranges), (
        f"Dead range must cover line 9 (the run inside the dead job); got {ranges}"
    )


def test_anchor_defined_if_runtime_does_not_suppress():
    """A merge-key-inherited ``if`` that's RUNTIME does not suppress."""
    content = (
        "defaults: &cfg\n"
        "  if: ${{ inputs.deploy }}\n"
        "\n"
        "jobs:\n"
        "  build:\n"
        "    <<: *cfg\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    assert find_dead_line_ranges(content) == []

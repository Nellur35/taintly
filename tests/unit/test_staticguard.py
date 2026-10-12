from __future__ import annotations

import pytest

from taintly.staticguard import (
    Verdict,
    WorkflowContext,
    evaluate_if,
    find_dead_line_ranges,
    is_workflow_whole_dead,
)


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


def test_comparison_ignores_ascii_case():
    """Actions string equality ignores case, including repository guards."""
    ctx = WorkflowContext(repository="MyOrg/MyRepo", repository_owner="MyOrg")
    # Exact match → STATIC_TRUE
    assert evaluate_if("github.repository_owner == 'MyOrg'", ctx) is Verdict.STATIC_TRUE
    assert evaluate_if("github.repository_owner == 'myorg'", ctx) is Verdict.STATIC_TRUE
    assert evaluate_if("github.repository_owner == 'MYORG'", ctx) is Verdict.STATIC_TRUE


def test_comparison_case_variant_keeps_workflow_live():
    """A differently cased spelling of the same owner cannot hide a live job."""
    ctx = WorkflowContext(repository="MyOrg/MyRepo", repository_owner="MyOrg")
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  a:\n"
        "    if: github.repository_owner == 'myorg'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    assert is_workflow_whole_dead(content, ctx) is False
    assert find_dead_line_ranges(content, ctx) == []


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("github.repository == 'myorg/myrepo'", Verdict.STATIC_TRUE),
        ("'MYORG/MYREPO' == github.repository", Verdict.STATIC_TRUE),
        ("github.repository != 'myorg/myrepo'", Verdict.STATIC_FALSE),
        ("'MYORG' != github.repository_owner", Verdict.STATIC_FALSE),
        ("github.repository_owner != 'OtherOrg'", Verdict.STATIC_TRUE),
        ("github.repository_owner == 'OtherOrg'", Verdict.STATIC_FALSE),
        ("'Release' == 'release'", Verdict.STATIC_TRUE),
        ("'Release' != 'release'", Verdict.STATIC_FALSE),
        ("'01' == '1'", Verdict.STATIC_FALSE),
        ("' MyOrg' == 'myorg'", Verdict.STATIC_FALSE),
        ("${{ github.repository_owner == 'MYORG' }}", Verdict.STATIC_TRUE),
    ],
)
def test_case_comparison_direction_operator_and_literal(expression, expected):
    ctx = WorkflowContext(repository="MyOrg/MyRepo", repository_owner="MyOrg")
    assert evaluate_if(expression, ctx) is expected


@pytest.mark.parametrize(
    "expression",
    [
        "'straße' == 'STRASSE'",
        "'straße' != 'STRASSE'",
        "'İ' == 'i'",
        "'é' != 'É'",
        "github.repository_owner == 'MýOrg'",
        "github.repository_owner != 'MýOrg'",
    ],
)
def test_unicode_comparison_cannot_prove_suppression(expression):
    ctx = WorkflowContext(repository="MyOrg/MyRepo", repository_owner="MyOrg")
    assert evaluate_if(expression, ctx) is Verdict.RUNTIME


def test_non_ascii_context_and_missing_context_stay_unknown():
    for operator in ("==", "!="):
        expression = f"github.repository_owner {operator} 'myorg'"
        assert evaluate_if(expression, WorkflowContext(repository_owner="MýOrg")) is Verdict.RUNTIME
        assert evaluate_if(expression, WorkflowContext()) is Verdict.RUNTIME
        assert evaluate_if(expression) is Verdict.RUNTIME


@pytest.mark.parametrize(
    ("operator", "expected"), [("==", Verdict.STATIC_TRUE), ("!=", Verdict.STATIC_FALSE)]
)
def test_identical_unicode_strings_preserve_known_truth(operator, expected):
    # Identity needs no Unicode case mapping and must not introduce dead-job FPs.
    assert evaluate_if(f"'é' {operator} 'é'") is expected
    assert (
        evaluate_if(
            f"github.repository_owner {operator} 'MýOrg'",
            WorkflowContext(repository_owner="MýOrg"),
        )
        is expected
    )


@pytest.mark.parametrize(("operator", "dead"), [("==", False), ("!=", True)])
def test_step_case_comparison_controls_only_owning_step(operator, dead):
    ctx = WorkflowContext(repository="MyOrg/MyRepo", repository_owner="MyOrg")
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - if: github.repository_owner {operator} 'myorg'\n"
        "        run: echo conditional\n"
        "      - run: echo unconditional\n"
    )
    assert find_dead_line_ranges(content, ctx) == ([(6, 7)] if dead else [])
    assert is_workflow_whole_dead(content, ctx) is False


def test_literal_case_equality_needs_no_repository_context():
    assert evaluate_if("'Release' == 'release'") is Verdict.STATIC_TRUE
    assert evaluate_if("'Release' != 'release'") is Verdict.STATIC_FALSE


def test_evaluate_if_runtime_fallback():
    ctx = WorkflowContext(repository="Nellur35/taintly", repository_owner="Nellur35")

    assert evaluate_if("github.event_name == 'pull_request'", ctx) is Verdict.RUNTIME
    assert (
        evaluate_if("success() && github.repository == 'Nellur35/taintly'", ctx) is Verdict.RUNTIME
    )
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
        evaluate_if("\"${{ github.repository_owner == 'someone-else' }}\"", ctx)
        is Verdict.STATIC_FALSE
    )
    assert evaluate_if("\"${{ github.repository_owner == 'me' }}\"", ctx) is Verdict.STATIC_TRUE


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


def test_whole_dead_all_jobs_literal_false():
    """Every job has ``if: false`` -> whole workflow is dead."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  a:\n"
        "    if: false\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo a\n"
        "  b:\n"
        "    if: false\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo b\n"
    )
    assert is_workflow_whole_dead(content) is True


def test_whole_dead_some_jobs_live():
    """One unconditional job -> not whole-dead."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  dead:\n"
        "    if: false\n"
        "    steps:\n"
        "      - run: echo dead\n"
        "  live:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo live\n"
    )
    assert is_workflow_whole_dead(content) is False


def test_whole_dead_runtime_guard_blocks():
    """A job with a RUNTIME guard prevents whole-dead classification."""
    content = (
        "on: workflow_dispatch\n"
        "jobs:\n"
        "  conditional:\n"
        "    if: ${{ inputs.deploy }}\n"
        "    steps:\n"
        "      - run: echo deploy\n"
        "  always_dead:\n"
        "    if: false\n"
        "    steps:\n"
        "      - run: echo dead\n"
    )
    assert is_workflow_whole_dead(content) is False


def test_whole_dead_repo_mismatch_with_ctx():
    """Repo-mismatch guards count as STATIC_FALSE when ctx mismatches."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  a:\n"
        "    if: github.repository_owner == 'someone-else'\n"
        "    steps:\n"
        "      - run: echo a\n"
        "  b:\n"
        "    if: false\n"
        "    steps:\n"
        "      - run: echo b\n"
    )
    ctx = WorkflowContext(repository="me/myrepo", repository_owner="me")
    assert is_workflow_whole_dead(content, ctx) is True


def test_whole_dead_repo_match_with_ctx_blocks():
    """A repo-match guard evaluates STATIC_TRUE -> not whole-dead."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  a:\n"
        "    if: github.repository_owner == 'me'\n"
        "    steps:\n"
        "      - run: echo a\n"
    )
    ctx = WorkflowContext(repository="me/myrepo", repository_owner="me")
    assert is_workflow_whole_dead(content, ctx) is False


def test_whole_dead_no_jobs_block():
    """A file with no ``jobs:`` block is not 'whole-dead'."""
    content = "on:\n  workflow_call: {}\n"
    assert is_workflow_whole_dead(content) is False


def test_evaluate_if_block_scalar_value():
    """Block-scalar ``if`` values (``|`` / ``>``) carry a trailing
    newline.  The strip helper tolerates it so suppression still
    fires; lock that behaviour in."""
    assert evaluate_if("false\n") is Verdict.STATIC_FALSE
    assert evaluate_if("false\n\n") is Verdict.STATIC_FALSE
    assert evaluate_if("  false  ") is Verdict.STATIC_FALSE


def test_find_dead_line_ranges_block_scalar_if():
    """A job whose ``if:`` is a block-scalar literal of ``false``
    is dead.  Real-world workflows don't usually write this shape,
    but neither the structural reader nor the strip helper should
    mis-handle it."""
    content = (
        "on: push\n"
        "jobs:\n"
        "  job:\n"
        "    if: |\n"
        "      false\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo dead\n"
    )
    ranges = find_dead_line_ranges(content)
    assert ranges, "Block-scalar if: false must produce a dead range"
    assert any(8 in range(start, end + 1) for start, end in ranges), (
        f"Dead range must cover the run line; got {ranges}"
    )


def test_find_dead_line_ranges_tab_indentation_does_not_crash():
    """Tabs are invalid YAML; the structural reader handles them
    gracefully.  ``_job_key_line_map`` returns no keys (its regex
    only matches space indentation) but the leaf-line fallback
    keeps suppression working with slightly tighter range bounds.
    """
    content = "jobs:\n\tdead:\n\t\tif: false\n\t\trun: echo dead\n"
    # Should not raise; the precise range bounds are
    # implementation-defined (leaf-line fallback when the key-line
    # map is empty).  The contract this test locks in is "no crash,
    # behaviour is conservative."
    ranges = find_dead_line_ranges(content)
    assert isinstance(ranges, list)


def test_whole_dead_inherited_via_anchor():
    """Merge-key-inherited ``if: false`` counts toward whole-dead.

    The structural reader resolves merge keys (verified at file
    scope by the per-job suppression tests); whole-dead inherits
    that capability for free.
    """
    content = (
        "defaults: &dead\n"
        "  if: false\n"
        "  runs-on: ubuntu-latest\n"
        "\n"
        "jobs:\n"
        "  a:\n"
        "    <<: *dead\n"
        "    steps:\n"
        "      - run: echo a\n"
        "  b:\n"
        "    <<: *dead\n"
        "    steps:\n"
        "      - run: echo b\n"
    )
    assert is_workflow_whole_dead(content) is True

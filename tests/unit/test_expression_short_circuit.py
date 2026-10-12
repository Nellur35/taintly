"""Literal-selected expressions must preserve only reachable value provenance."""

import pytest

from taintly.cross_workflow_facts import find_cross_file_taint
from taintly.parsers.gha_expr import context_paths, result_provenance_paths
from taintly.workflow_corpus import build_corpus


@pytest.mark.parametrize(
    ("expression", "reachable"),
    [
        ("false && inputs.payload", False),
        ("true || inputs.payload", False),
        ("'fixed' || inputs.payload", False),
        ("'false' || inputs.payload", False),
        ("'' && inputs.payload", False),
        ("null && inputs.payload", False),
        ("!null || inputs.payload", False),
        ("(runtime.flag || true) || inputs.payload", False),
        ("(runtime.flag && false) && inputs.payload", False),
        ("true && inputs.payload", True),
        ("false || inputs.payload", True),
        ("'' || inputs.payload", True),
        ("null || inputs.payload", True),
        ("runtime.flag || inputs.payload", True),
        ("runtime.flag && inputs.payload", True),
        ("unknown_function() || inputs.payload", True),
        ("(runtime.flag && true) || inputs.payload", True),
        ("(runtime.flag || false) && inputs.payload", True),
        ("0 && inputs.payload", True),  # numeric coercion is deliberately unknown
        ("1 || inputs.payload", True),
        ("contains('fixed', 'f') || inputs.payload", True),
        ("('a' == 'a') || inputs.payload", True),
    ],
)
def test_reachable_result_paths_remain_separate_from_syntactic_references(expression, reachable):
    assert "inputs.payload" in context_paths(expression)
    assert ("inputs.payload" in result_provenance_paths(expression)) is reachable


def test_analysis_budget_exhaustion_retains_possible_payload():
    # Left-associated chains parse without nesting. The distant decisive
    # literal lies beyond the analysis budget, so it must not erase a source.
    left = " || ".join(["false"] * 70 + ["true"])
    expression = "(" + left + ") || inputs.payload"
    assert "inputs.payload" in result_provenance_paths(expression)


@pytest.mark.parametrize(
    ("expression", "reachable"),
    [
        ("false && github.event.issue.title", False),
        ("'fixed' || github.event.issue.title", False),
        ("true && github.event.issue.title", True),
        ("'' || github.event.issue.title", True),
        ("github.event.issue.body || github.event.issue.title", True),
    ],
)
def test_reusable_invocation_follows_only_possible_payload_values(tmp_path, expression, reachable):
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    (directory / "caller.yml").write_text(
        "on: issues\njobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n"
        "    with:\n      payload: ${{ " + expression + " }}\n",
        encoding="utf-8",
    )
    (directory / "reusable.yml").write_text(
        "on:\n  workflow_call:\n    inputs:\n      payload:\n        type: string\n"
        "jobs:\n  consume:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - run: eval "${{ inputs.payload }}"\n',
        encoding="utf-8",
    )
    flows = find_cross_file_taint(build_corpus(str(tmp_path)))
    assert bool(flows) is reachable

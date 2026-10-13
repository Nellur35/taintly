"""Reachability-aware expression source extraction without losing source inventory."""

from __future__ import annotations

import pytest
from taintly.parsers.gha_expr import context_paths

try:
    from taintly.parsers.gha_expr import reachable_context_paths
except ImportError:  # The retained pre-patch parser has no reachability API.
    reachable_context_paths = None
from taintly.taint import _extract_tainted_source, analyze, analyze_job_outputs, clear_analyze_cache

TITLE = "github.event.pull_request.title"
BODY = "github.event.pull_request.body"


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("false && github.event.pull_request.title", None),
        ("true || github.event.pull_request.title", None),
        ("'fixed' || github.event.pull_request.title", None),
        ("'false' || github.event.pull_request.title", None),
        ("'' && github.event.pull_request.title", None),
        ("null && github.event.pull_request.title", None),
        ("!null || github.event.pull_request.title", None),
        ("!!'false' || github.event.pull_request.title", None),
        ("true && github.event.pull_request.title", TITLE),
        ("false || github.event.pull_request.title", TITLE),
        ("'' || github.event.pull_request.title", TITLE),
        ("null || github.event.pull_request.title", TITLE),
        ("'false' && github.event.pull_request.title", TITLE),
        ("!null && github.event.pull_request.title", TITLE),
        ("unknown.flag && github.event.pull_request.title", TITLE),
        ("unknown.flag || github.event.pull_request.title", TITLE),
        ("(unknown.flag || false) && github.event.pull_request.title", TITLE),
        ("false && github.event.pull_request.title || github.event.pull_request.body", BODY),
    ],
)
def test_source_extraction_tracks_reachable_short_circuit_values(expression, expected):
    assert _extract_tainted_source("${{ " + expression + " }}") == expected


def test_dead_context_remains_in_syntactic_inventory():
    expression = "false && github.event.pull_request.title || github.event.pull_request.body"
    assert context_paths(expression) == [TITLE, BODY]
    assert _extract_tainted_source("${{ " + expression + " }}") == BODY


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("false && inputs.payload", None),
        ("true || inputs.payload", None),
        ("false || inputs.payload", "inputs.payload"),
        ("unknown.flag && inputs.payload", "inputs.payload"),
        ("false && INPUTS['payload']", None),
        ("false || INPUTS['payload']", "inputs.payload"),
    ],
)
def test_reusable_caller_input_is_tainted_only_when_its_value_is_reachable(expression, expected):
    wrapped = "${{ " + expression + " }}"
    assert _extract_tainted_source(wrapped, include_inputs=True) == expected
    assert "inputs.payload" in context_paths(expression)


def test_multiple_expression_substitutions_are_evaluated_independently():
    value = "${{ false && github.event.pull_request.title }}-${{ false || github.event.pull_request.body }}"
    assert _extract_tainted_source(value) == BODY


def test_dead_first_match_does_not_hide_later_live_same_context():
    value = "${{ false && github.event.pull_request.title }}-${{ github.event.pull_request.title }}"
    assert _extract_tainted_source(value) == TITLE


def test_dead_and_live_same_context_in_one_expression_preserves_source():
    expression = "false && github.event.pull_request.title || github.event.pull_request.title"
    assert _extract_tainted_source("${{ " + expression + " }}") == TITLE


@pytest.mark.skipif(
    reachable_context_paths is None, reason="pre-patch parser has no reachability API"
)
def test_reachable_paths_keep_controls_and_canonicalize_contexts():
    assert reachable_context_paths(
        "github.event.issue.state && GITHUB['event']['pull_request']['title']"
    ) == [
        "github.event.issue.state",
        TITLE,
    ]
    assert reachable_context_paths(
        "contains(GITHUB['event']['pull_request']['title'], 'release')"
    ) == [TITLE]


@pytest.mark.skipif(
    reachable_context_paths is None, reason="pre-patch parser has no reachability API"
)
def test_reachable_paths_keep_unknown_branches_and_budget_exhaustion():
    assert reachable_context_paths("unknown.flag && github.event.pull_request.title") == [
        "unknown.flag",
        TITLE,
    ]
    long_left = " || ".join(["false"] * 70 + ["true"])
    expr = "(" + long_left + ") || inputs.payload"
    assert "inputs.payload" in reachable_context_paths(expr)


def test_bracket_and_context_case_canonicalization_respects_reachability():
    dead = "${{ false && GITHUB['event']['pull_request']['title'] }}"
    live = "${{ false || GITHUB['event']['pull_request']['title'] }}"
    assert _extract_tainted_source(dead) is None
    assert _extract_tainted_source(live) == TITLE
    assert context_paths("false && GITHUB['event']['pull_request']['title']") == [TITLE]


def test_malformed_expression_keeps_legacy_regex_source_fallback():
    malformed = "${{ false && github.event.pull_request.title !!! }}"
    assert _extract_tainted_source(malformed) == TITLE


def test_disabling_structural_augmentation_keeps_reachability_and_legacy_scope(monkeypatch):
    monkeypatch.setenv("TAINTLY_STRUCTURAL_EXPR", "0")
    # Disabling structural augmentation preserves the legacy literal-regex result.
    assert _extract_tainted_source("${{ false && github.event.pull_request.title }}") == TITLE
    assert _extract_tainted_source("${{ false || github.event.pull_request.title }}") == TITLE
    assert (
        _extract_tainted_source("${{ false || GITHUB['event']['pull_request']['title'] }}") is None
    )
    assert context_paths("false && GITHUB['event']['pull_request']['title']") == [TITLE]


def test_function_arguments_remain_conservatively_inventoried_as_sources():
    expression = "contains(GITHUB['event']['pull_request']['title'], 'release')"
    assert context_paths(expression) == [TITLE]
    assert _extract_tainted_source("${{ " + expression + " }}") == TITLE


def _workflow_with_env(expression: str) -> str:
    return (
        "on: [pull_request_target]\njobs:\n  build:\n    steps:\n"
        "      - env:\n          VALUE: ${{ " + expression + " }}\n"
        '        run: eval "$VALUE"\n'
    )


@pytest.mark.parametrize("backend", ["line", "structural"])
@pytest.mark.parametrize(
    ("expression", "expected_count"),
    [
        ("false && github.event.pull_request.title", 0),
        ("false || github.event.pull_request.title", 1),
    ],
)
def test_analyze_env_reachability_on_both_backends(
    monkeypatch, backend, expression, expected_count
):
    monkeypatch.setenv("TAINTLY_TAINT_BACKEND", backend)
    clear_analyze_cache()
    content = _workflow_with_env(expression)
    paths = analyze(content, content.splitlines())
    assert len(paths) == expected_count, paths
    if expected_count:
        assert paths[0].source_expr == TITLE


@pytest.mark.parametrize("backend", ["line", "structural"])
@pytest.mark.parametrize(
    ("expression", "expected_count"),
    [
        ("false && github.event.pull_request.title", 0),
        ("false || github.event.pull_request.title", 1),
    ],
)
def test_analyze_dynamic_github_env_reachability_on_both_backends(
    monkeypatch, backend, expression, expected_count
):
    monkeypatch.setenv("TAINTLY_TAINT_BACKEND", backend)
    clear_analyze_cache()
    content = (
        "on: [pull_request_target]\njobs:\n  build:\n    steps:\n"
        '      - run: echo "VALUE=${{ ' + expression + ' }}" >> "$GITHUB_ENV"\n'
        '      - run: eval "$VALUE"\n'
    )
    paths = analyze(content, content.splitlines())
    assert len(paths) == expected_count, paths
    if expected_count:
        assert paths[0].source_expr == TITLE


@pytest.mark.parametrize("backend", ["line", "structural"])
@pytest.mark.parametrize(
    ("expression", "expected_count"),
    [
        ("false && github.event.pull_request.title", 0),
        ("false || github.event.pull_request.title", 1),
    ],
)
def test_job_output_source_reachability_on_both_backends(
    monkeypatch, backend, expression, expected_count
):
    monkeypatch.setenv("TAINTLY_TAINT_BACKEND", backend)
    clear_analyze_cache()
    content = (
        "on: [pull_request_target]\njobs:\n  build:\n"
        "    outputs:\n      result: ${{ " + expression + " }}\n"
        "    steps:\n      - run: echo done\n"
    )
    outputs = analyze_job_outputs(content, content.splitlines())
    assert len(outputs.bindings) == expected_count, outputs.bindings
    if expected_count:
        assert outputs.bindings[0].source_expr == TITLE


@pytest.mark.parametrize("backend", ["line", "structural"])
@pytest.mark.parametrize(
    ("expression", "expected_count"),
    [
        ("false && github.event.pull_request.title", 0),
        ("false || github.event.pull_request.title", 1),
    ],
)
def test_step_output_source_reachability_on_both_backends(
    monkeypatch, backend, expression, expected_count
):
    monkeypatch.setenv("TAINTLY_TAINT_BACKEND", backend)
    clear_analyze_cache()
    content = (
        "on: [pull_request_target]\njobs:\n  build:\n    steps:\n"
        "      - id: write\n"
        '        run: echo "name=${{ ' + expression + ' }}" >> "$GITHUB_OUTPUT"\n'
        "      - env:\n          VALUE: ${{ steps.write.outputs.name }}\n"
        '        run: eval "$VALUE"\n'
    )
    paths = analyze(content, content.splitlines())
    assert len(paths) == expected_count, paths
    if expected_count:
        assert paths[0].source_expr == TITLE

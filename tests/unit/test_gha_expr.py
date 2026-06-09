"""Unit tests for the GitHub Actions ``${{ }}`` expression parser."""

from __future__ import annotations

import pytest

from taintly.parsers.gha_expr import (
    ExprSyntaxError,
    canonical_path,
    context_paths,
    iter_expression_bodies,
    parse,
)

_CANONICAL = "github.event.pull_request.title"


@pytest.mark.parametrize(
    "expr",
    [
        "github.event.pull_request.title",  # dot (canonical)
        "github.event.pull_request['title']",  # single-quote index
        "github['event']['pull_request']['title']",  # full bracket chain
        "github.event['pull_request'].title",  # mixed chain
        "GITHUB.event.pull_request.title",  # context-name upcase
        "GitHub.Event.Pull_Request.Title",  # all-segment case variation
        "  github . event . pull_request['title']  ",  # whitespace
    ],
)
def test_obfuscations_collapse_to_canonical(expr: str) -> None:
    assert context_paths(expr) == [_CANONICAL]


def test_function_args_are_extracted_passthrough() -> None:
    assert context_paths("format('{0}', github.event.pull_request.title)") == [_CANONICAL]
    assert context_paths("contains(github.event.pull_request.title, 'x')") == [_CANONICAL]


def test_comparison_yields_both_operands() -> None:
    paths = context_paths("github.event_name == 'push' && github.event.pull_request.title")
    assert set(paths) == {"github.event_name", _CANONICAL}


def test_fromjson_roundtrip_yields_only_call_args_not_postcall_chain() -> None:
    # fromJSON(toJSON(github.event)).pull_request.title — the post-call member
    # chain needs builtin dataflow; we only see the argument path.
    assert context_paths("fromJSON(toJSON(github.event)).pull_request.title") == ["github.event"]


def test_object_filter_yields_spine_before_star() -> None:
    assert context_paths("github.event.commits.*.message") == ["github.event.commits"]


def test_dynamic_index_path_is_dropped_but_inner_survives() -> None:
    # matrix[github.event.number] — the receiver `matrix` is a context ref, and
    # the attacker-controlled dynamic index path survives too.
    assert set(context_paths("matrix[github.event.number]")) == {"matrix", "github.event.number"}


def test_canonical_path_none_for_call_rooted_spine() -> None:
    node = parse("fromJSON(x).y")
    assert canonical_path(node) is None


@pytest.mark.parametrize(
    "bad",
    [
        "github.event.",  # trailing dot
        "a[",  # unterminated index
        "unterminated'string",  # unterminated string
        'github.event["title"]',  # double-quote string (invalid GHA)
        "a && && b",  # double operator
        "1 +",  # unsupported operator / trailing
    ],
)
def test_malformed_raises(bad: str) -> None:
    with pytest.raises(ExprSyntaxError):
        context_paths(bad)


def test_iter_expression_bodies() -> None:
    text = 'echo "${{ github.event.pull_request.title }}" and ${{ secrets.TOKEN }}'
    bodies = list(iter_expression_bodies(text))
    assert bodies == [" github.event.pull_request.title ", " secrets.TOKEN "]


def test_secrets_and_inputs_paths() -> None:
    assert context_paths("secrets.GH_TOKEN") == ["secrets.gh_token"]
    assert context_paths("inputs['my-input']") == ["inputs.my-input"]

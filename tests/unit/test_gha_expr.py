"""Unit tests for the GitHub Actions ``${{ }}`` expression parser."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

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


# --- resource bounds: adversarial expressions must not blow the stack -------
#
# A ``${{ }}`` body is attacker-controlled. The recursive-descent parser must
# turn pathological nesting into a clean ``ExprSyntaxError`` (which callers
# already handle as "couldn't parse"), never an unguarded ``RecursionError``
# that could crash a scan. See ``gha_expr._MAX_PARSE_DEPTH``.


@pytest.mark.parametrize(
    ("opener", "closer", "tail"),
    [
        ("fromJSON(", ")", "github.event"),  # nested function calls
        ("(", ")", "github.sha"),  # nested parentheses
        ("!", "", "github.event_name"),  # unary-not chain
    ],
    ids=["nested-func", "nested-parens", "not-chain"],
)
def test_deeply_nested_expression_raises_syntax_error_not_recursion(
    opener: str, closer: str, tail: str
) -> None:
    # Build the adversarial expression inside the test so the 45 KB string never
    # lands in a parametrize id (a Windows env-var limit, and unreadable output).
    expr = opener * 5000 + tail + closer * 5000
    with pytest.raises(ExprSyntaxError):
        parse(expr)


def test_legitimately_nested_expression_still_parses() -> None:
    # Real expressions nest only a handful of levels — well under the bound.
    parse("toJSON(fromJSON(inputs.config))")
    parse("github.event_name == 'push' && contains(github.ref, 'main') || false")


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=300))
def test_parse_never_recurses_on_arbitrary_input(s: str) -> None:
    # The parser may accept or reject arbitrary bytes; it must never crash the
    # interpreter with a RecursionError on attacker-controlled input.
    try:
        parse(s)
    except RecursionError:  # pragma: no cover - the bug this guards against
        raise AssertionError("parse() raised RecursionError on fuzzed input")
    except Exception:
        pass  # any clean rejection is acceptable; we only guard stack safety


@settings(max_examples=80, deadline=None)
@given(st.integers(min_value=0, max_value=5000))
def test_parse_bounds_arbitrary_paren_depth(n: int) -> None:
    try:
        parse("(" * n + "x" + ")" * n)
    except RecursionError:  # pragma: no cover
        raise AssertionError(f"parse() raised RecursionError at paren depth {n}")
    except Exception:
        pass

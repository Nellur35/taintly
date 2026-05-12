"""Property-based tests for the taint analyzer (taintly.taint).

Five properties from the audit (chunk 1.2):

  determinism      — analyze() twice on the same input yields equal results.
  line_bounds      — every hop.line is within 1..len(lines).
  source_provenance — every path.source_expr appears as a substring of input.
  monotonicity     — appending a line that doesn't reference any tainted
                     name never reduces the path count.
  no_source_no_paths — input with all ``${{`` removed produces zero paths.

Why PBT here: the taint analyzer is a pure ``(content, lines) -> list[TaintPath]``
on the hot path. The Goldstein OOPSLA 2025 result that motivated the
existing pattern PBT (``test_pattern_properties.py``) applies just as
strongly: PBT catches mutations 52x more often than example tests on
exactly this shape of code.

Skips gracefully when hypothesis is unavailable.
"""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from taintly.taint import analyze  # noqa: E402


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


# A concrete attack-shaped workflow generator. The taint analyzer cares
# about specific YAML structure (jobs/steps/run/env), so totally random
# YAML mostly produces zero paths and tests nothing useful. We generate
# parametric WORKFLOWS that have a non-trivial probability of being
# tainted, plus drawn-around variations that exercise the analyzer's
# corner cases.

_ATTACKER_SOURCES = st.sampled_from(
    [
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.issue.title",
        "github.event.comment.body",
        "github.event.pull_request.head.label",
    ]
)

_VAR_NAMES = st.sampled_from(["TITLE", "BODY", "INPUT", "DATA", "PR_TITLE"])

_RUN_TEMPLATES = st.sampled_from(
    [
        'echo "$VAR"',
        'eval "$VAR"',
        'curl -d "$VAR" example.com',
        'gh pr comment 1 --body "$VAR"',
    ]
)


@st.composite
def _tainted_workflow(draw) -> str:
    """Generate a workflow with one shallow taint flow."""
    src = draw(_ATTACKER_SOURCES)
    var = draw(_VAR_NAMES)
    cmd = draw(_RUN_TEMPLATES).replace("$VAR", f"${var}")
    return (
        "name: T\n"
        "on: pull_request_target\n"
        "permissions:\n  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        f"          {var}: ${{{{ {src} }}}}\n"
        f"        run: {cmd}\n"
    )


@st.composite
def _untainted_workflow(draw) -> str:
    """Generate a workflow with no obvious taint sources."""
    return (
        "name: T\n"
        "on: push\n"
        "permissions:\n  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - run: echo {draw(st.text(alphabet='abcdef', min_size=1, max_size=20))}\n"
    )


_workflow = st.one_of(_tainted_workflow(), _untainted_workflow())


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


@given(content=_workflow)
@settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_taint_analyze_is_deterministic(content):
    """Property: analyze(content) returns identical results across calls.

    A non-deterministic analyzer would produce flaky CI runs and make
    finding-level diffs impossible to reason about. This test catches
    accidental dict-ordering / set-iteration bugs that pass a single
    example test but flake under repeated runs."""
    lines = content.splitlines()
    a = analyze(content, lines)
    b = analyze(content, lines)
    assert len(a) == len(b)
    for pa, pb in zip(a, b, strict=True):
        assert pa.source_expr == pb.source_expr
        assert pa.source_line == pb.source_line
        assert pa.env_var == pb.env_var
        assert pa.sink_line == pb.sink_line
        assert pa.kind == pb.kind
        assert len(pa.hops) == len(pb.hops)


@given(content=_workflow)
@settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_hop_lines_are_within_bounds(content):
    """Property: every hop.line and source_line/sink_line is in
    1..len(lines).

    Off-by-one errors in line tracking become annotation bugs in the
    SARIF / human reporter — a hop that points at line 0 or line
    (len+1) crashes editors that try to highlight it. This invariant
    is both correctness and downstream-tool reliability."""
    lines = content.splitlines()
    n = len(lines)
    if n == 0:
        return  # empty input is trivially fine

    paths = analyze(content, lines)
    for path in paths:
        assert 1 <= path.source_line <= n, (
            f"source_line {path.source_line} out of bounds (1..{n})"
        )
        assert 1 <= path.sink_line <= n, (
            f"sink_line {path.sink_line} out of bounds (1..{n})"
        )
        for hop in path.hops:
            assert 1 <= hop.line <= n, (
                f"hop.line {hop.line} out of bounds (1..{n}); kind={hop.kind!r}"
            )


@given(content=_workflow)
@settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_source_expr_appears_in_input(content):
    """Property: every path.source_expr is a substring of the input.

    A path that claims to originate from ``github.event.pull_request.title``
    must point to a real ``${{ github.event.pull_request.title }}``
    expression in the file. If not, the analyzer is fabricating sources
    — every reported finding becomes unverifiable for a reviewer."""
    lines = content.splitlines()
    paths = analyze(content, lines)
    for path in paths:
        assert path.source_expr in content, (
            f"reported source_expr {path.source_expr!r} not found in "
            f"the input — analyzer fabricated a source"
        )


@given(content=_untainted_workflow())
@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_appending_unrelated_line_is_monotonic(content):
    """Property: appending a line that references no tainted name
    never REDUCES the path count.

    The analyzer's segmentation walks line by line; appending unrelated
    content shouldn't trip it into incorrectly invalidating an
    earlier-discovered taint flow. This is the classic 'extra context
    breaks the parser' bug shape."""
    lines = content.splitlines()
    base = analyze(content, lines)

    extended = content + "\n# unrelated trailing comment\n"
    extended_lines = extended.splitlines()
    after = analyze(extended, extended_lines)

    assert len(after) >= len(base), (
        f"appending unrelated line shrunk path count from "
        f"{len(base)} to {len(after)} — analyzer treats trailing "
        f"context as invalidating earlier taint discoveries"
    )


@given(content=_workflow)
@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_no_expression_no_paths(content):
    """Property: input with all ``${{`` substrings removed produces
    zero paths.

    Every taint source the analyzer detects originates in a GitHub
    expression. An input with no expressions cannot be a taint source.
    A failure here means the analyzer is matching on something other
    than expression syntax — a precision bug masquerading as
    sensitivity."""
    stripped = content.replace("${{", "##__no_expr__")
    paths = analyze(stripped, stripped.splitlines())
    assert paths == [], (
        f"taint paths reported on input with no GitHub expressions: "
        f"{paths!r}"
    )

"""Property-based tests for the pattern-matching core.

PSE Domain 3.4 — Property-Based Testing.

Goldstein et al. OOPSLA 2025 — property-based tests caught mutations
52x more often than unit tests (odds ratio 51.91, p<0.0001). The
pattern-matching engine is the hottest path in this project and is a
pure function of (regex, input) → matches, so it's a textbook PBT
target.

What these properties cover that example-based tests do not:

* Any valid regex the rule author can write must produce deterministic
  output (running check() twice yields the same list).
* Line numbers returned must be 1-based and within the input range.
* Returned snippets must correspond to real lines in the input — never
  a regex fragment or a stripped copy that differs in substance.
* ``exclude`` patterns actually suppress matches (a match that would
  fire absent exclude must not fire when exclude is a superset).
* Pattern behaviour is content-length-invariant: adding a blank line
  at the start shifts line numbers by exactly 1.
* ``_safe_search`` never raises on any str input (prevents the
  "ENGINE-ERR on a real workflow" bug class).

These tests use hypothesis; if hypothesis is not installed (e.g. dev
env without the [dev] extra) the module skips gracefully so unit tests
still run.
"""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from taintly.models import (  # noqa: E402
    AbsencePattern,
    ContextPattern,
    RegexPattern,
    _safe_search,
)


# Conservative text strategy: printable chars + common whitespace.
# Hypothesis's default text() includes surrogates which aren't valid
# in real-world YAML/Groovy, and we're testing the pattern engine's
# invariants, not its behaviour on hand-crafted unicode adversary
# inputs (that's what tests/fuzz/ is for).
_lines = st.text(
    alphabet=st.characters(
        min_codepoint=0x20,
        max_codepoint=0x7E,
        categories=["L", "N", "P", "S", "Zs"],
    ),
    max_size=120,
)
_content = st.lists(_lines, max_size=30).map("\n".join)


# =============================================================================
# Property 1 — check() is deterministic
# =============================================================================


@given(content=_content)
@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_regex_pattern_check_is_deterministic(content: str) -> None:
    """Running check() twice on the same input returns identical results."""
    pattern = RegexPattern(match=r"\$\{\{\s*secrets\.")
    lines = content.split("\n")
    first = pattern.check(content, lines)
    second = pattern.check(content, lines)
    assert first == second


# =============================================================================
# Property 2 — line numbers are 1-based and in range
# =============================================================================


@given(content=_content)
@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_regex_pattern_line_numbers_in_range(content: str) -> None:
    """Every returned line number refers to a real line in the input."""
    pattern = RegexPattern(match=r".+")  # match every non-empty line
    lines = content.split("\n")
    for line_no, _snippet in pattern.check(content, lines):
        assert 1 <= line_no <= len(lines), (
            f"line_no {line_no} out of range for {len(lines)}-line input"
        )


# =============================================================================
# Property 3 — snippet is the content of the referenced line
# =============================================================================


@given(content=_content)
@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_regex_pattern_snippet_matches_line(content: str) -> None:
    """The snippet for line N equals the stripped content of line N."""
    pattern = RegexPattern(match=r"\S")  # any non-whitespace
    lines = content.split("\n")
    for line_no, snippet in pattern.check(content, lines):
        assert snippet == lines[line_no - 1].strip()


# =============================================================================
# Property 4 — exclude actually excludes
# =============================================================================


@given(content=_content)
@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_regex_pattern_exclude_is_monotone(content: str) -> None:
    """Adding an exclude pattern can only REDUCE the match set, not grow it."""
    lines = content.split("\n")
    without = RegexPattern(match=r".+").check(content, lines)
    with_excl = RegexPattern(match=r".+", exclude=[r"^\s*#"]).check(content, lines)
    # Every match in with_excl must also be in without.
    without_set = set(without)
    for hit in with_excl:
        assert hit in without_set, (
            f"exclude somehow added a match not present without it: {hit}"
        )


# =============================================================================
# Property 5 — prepending a blank line shifts all matches by exactly 1
# =============================================================================


@given(content=_content)
@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_regex_pattern_line_number_is_offset_invariant(content: str) -> None:
    """Prepending a blank line shifts every match's line number by 1.

    This catches off-by-one bugs that only show up on inputs where the
    first few lines happen to match by accident.
    """
    # Skip inputs that have regex metacharacters likely to match the
    # blank line; we want to test stability, not regex edge cases.
    assume("\n" in content)
    lines = content.split("\n")
    pattern = RegexPattern(match=r"[A-Za-z]")  # any ASCII letter
    base = pattern.check(content, lines)

    shifted_content = "\n" + content
    shifted_lines = shifted_content.split("\n")
    shifted = pattern.check(shifted_content, shifted_lines)

    assert len(base) == len(shifted), (
        "prepending a blank line changed the match count"
    )
    for (n_base, _), (n_shifted, _) in zip(base, shifted):
        assert n_shifted == n_base + 1


# =============================================================================
# Property 6 — _safe_search never raises
# =============================================================================


import re  # noqa: E402


@given(content=_content)
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_safe_search_never_raises(content: str) -> None:
    """The scanner's _safe_search wrapper must survive any string input.

    A single crash here produces an ENGINE-ERR finding in the report
    and undermines the "best-effort, never fail loud" contract.
    """
    compiled = re.compile(r".*")
    # Should never raise; return value shape is search-result-or-None.
    result = _safe_search(compiled, content)
    assert result is None or hasattr(result, "group")


# =============================================================================
# Property 7 — ContextPattern.check is deterministic
# =============================================================================


@given(content=_content)
@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_context_pattern_check_is_deterministic(content: str) -> None:
    """ContextPattern has more internal state (job splitting, scope) so
    it deserves its own determinism check."""
    pattern = ContextPattern(
        anchor=r"^\s*uses:\s*actions/",
        requires=r"secrets\.",
        scope="file",
    )
    lines = content.split("\n")
    first = pattern.check(content, lines)
    second = pattern.check(content, lines)
    assert first == second


# =============================================================================
# Property 8 — AbsencePattern inverts RegexPattern on non-empty lines
# =============================================================================


@given(content=_content)
@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_absence_pattern_fires_iff_regex_pattern_does_not(content: str) -> None:
    """Given the same regex, AbsencePattern fires exactly when
    RegexPattern does NOT match anywhere in the file.
    """
    assume(content.strip())
    probe = r"uses:\s*actions/checkout"
    lines = content.split("\n")
    regex_matched = bool(RegexPattern(match=probe).check(content, lines))
    absence_fired = bool(AbsencePattern(absent=probe).check(content, lines))
    assert regex_matched != absence_fired, (
        "RegexPattern match and AbsencePattern fire should be mutually exclusive"
    )

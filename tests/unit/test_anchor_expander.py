"""Tests for the anchor-merge expander."""

from __future__ import annotations

from taintly.parsers.anchor_expander import expand_anchors


def test_expand_simple_merge_key():
    src = """\
defaults: &defs
  persist-credentials: false
  fetch-depth: 0

steps:
  - uses: actions/checkout@v4
    with:
      <<: *defs
"""
    out = expand_anchors(src)
    # Inlined body should appear under `with:`.
    assert "persist-credentials: false" in out
    # Both occurrences should be present (definition + inline).
    assert out.count("persist-credentials: false") == 2


def test_expand_no_anchors_unchanged():
    src = "name: x\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    assert expand_anchors(src) == src


def test_expand_unknown_anchor_unchanged():
    src = """\
steps:
  - with:
      <<: *unknown
"""
    out = expand_anchors(src)
    # Unknown references pass through.
    assert "<<: *unknown" in out


def test_expand_double_anchor_skipped():
    """Anchor name defined twice — ambiguous, expander declines to expand."""
    src = """\
a: &foo
  x: 1

b: &foo
  y: 2

c:
  <<: *foo
"""
    out = expand_anchors(src)
    assert "<<: *foo" in out  # Not expanded.


def test_expand_handles_garbage_input():
    """Defensive: bad input must not raise."""
    assert expand_anchors("\x00\x01\x02") == "\x00\x01\x02"
    assert expand_anchors("") == ""


# --- soundness boundary: unsupported shapes decline cleanly (golden) -------
#
# The expander handles block-mapping merges; every OTHER shape documented as
# out-of-scope must be left SEMANTICALLY UNCHANGED (declined), never partially
# expanded — partial expansion is strictly worse than none (it can move a
# finding's line or drop a guard the rule needed to see). The decline path is
# part of the soundness boundary, so it is pinned here. (.splitlines() ignores
# the trailing-newline artifact of splitlines()/join().)


def _semantically_unchanged(src: str) -> bool:
    return expand_anchors(src).splitlines() == src.splitlines()


def test_decline_twice_defined_anchor():
    # Ambiguous: the same anchor name defined twice -> reference left untouched.
    src = "a: &x\n  run: echo 1\nb: &x\n  run: echo 2\njobs:\n  j:\n    <<: *x\n"
    assert _semantically_unchanged(src)


def test_decline_recursive_anchor():
    # Recursive: the body references its own name. Must decline, NOT partially
    # expand (which would inline once and leave a dangling inner alias).
    src = "a: &r\n  nest: *r\nuse:\n  <<: *r\n"
    assert _semantically_unchanged(src)


def test_decline_sequence_merge():
    # Sequence-style merge `<<: [*b]` is out of scope -> reference left untouched.
    src = "base: &b\n  run: echo hi\njob:\n  <<: [*b]\n"
    assert _semantically_unchanged(src)


def test_decline_exotic_anchor_name():
    # Anchor name with a char outside [A-Za-z0-9_-] (a dot) -> not matched.
    src = "a: &my.anchor\n  run: echo hi\njob:\n  <<: *my.anchor\n"
    assert _semantically_unchanged(src)


def test_supported_block_merge_still_expands():
    # Control: the supported block-mapping merge IS expanded — the inner value
    # is inlined where the merge key sat.
    src = "base: &b\n  run: echo ${{ github.event.issue.title }}\njob:\n  <<: *b\n"
    out = expand_anchors(src)
    assert out != src
    assert "github.event.issue.title" in out

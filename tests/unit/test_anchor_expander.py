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

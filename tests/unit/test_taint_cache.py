"""T1 — per-content taint-analysis cache (``taint.analyze``).

Guards that the content-keyed LRU added to ``taint.analyze`` (1) returns results
identical to the uncached fixpoint (byte-identical findings) and (2) computes the
fixpoint ONCE per file instead of once per TaintPattern rule (the ~12x redundancy
this cache removes — mirrors walk-once, #163).
"""

from __future__ import annotations

import taintly.taint as t
from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_all_rules
from taintly.taint import analyze, clear_analyze_cache

_WF = """name: ci
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "$TITLE"
"""


def test_cache_result_equals_uncached_and_is_reused():
    clear_analyze_cache()
    lines = _WF.splitlines()
    cached = analyze(_WF, lines)
    uncached = t._analyze_uncached(_WF, lines)
    assert cached == uncached  # same paths, same order — byte-identical
    assert cached  # the fixture really exercises taint (a shallow flow)
    # A second call hits the cache and returns the very same object.
    assert analyze(_WF, lines) is cached


def test_scan_file_computes_taint_once_not_per_rule():
    clear_analyze_cache()
    rules = [r for r in load_all_rules() if r.platform == Platform.GITHUB]
    n_taint = sum(1 for r in rules if type(r.pattern).__name__ == "TaintPattern")
    assert n_taint >= 2  # several taint rules would each have re-run analyze pre-cache

    calls = {"n": 0}
    orig = t._analyze_uncached

    def counting(content, lines):
        calls["n"] += 1
        return orig(content, lines)

    t._analyze_uncached = counting
    try:
        scan_file("wf.yml", rules, _content=_WF)
    finally:
        t._analyze_uncached = orig
    # All taint rules on one file share ONE fixpoint, not n_taint of them.
    assert calls["n"] <= 2, f"expected ~1 taint computation per file, got {calls['n']}"


def test_content_keyed_and_clearable():
    clear_analyze_cache()
    analyze(_WF, _WF.splitlines())
    other = _WF.replace("build", "renamed")
    # Different content -> its own entry, still equal to the uncached result.
    assert analyze(other, other.splitlines()) == t._analyze_uncached(other, other.splitlines())
    clear_analyze_cache()
    assert len(t._analyze_cache) == 0

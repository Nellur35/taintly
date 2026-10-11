"""T1 — per-content taint-analysis cache (``taint.analyze``).

Guards that the content-keyed LRU added to ``taint.analyze`` (1) returns results
identical to the uncached fixpoint (byte-identical findings) and (2) computes the
fixpoint ONCE per file instead of once per TaintPattern rule (the ~12x redundancy
this cache removes — mirrors walk-once, #163).
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
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


def test_symbolic_output_witness_quotes_actual_declaration_without_changing_legacy():
    content = """on: issue_comment
jobs:
  produce:
    runs-on: ubuntu-latest
    outputs:
      payload: ${{ steps.capture.outputs.payload }}
    steps:
      - id: capture
        env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "payload=$TITLE" >> "$GITHUB_OUTPUT"
  consume:
    needs: produce
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ needs.produce.outputs.payload }}'
"""
    lines = content.splitlines()
    legacy = analyze(content, lines)
    symbolic = t.analyze_job_outputs(content, lines)
    assert legacy
    binding = symbolic.bindings[0]
    hop = next(h for h in binding.hops if h.kind == "job_output")
    assert binding.declaration in hop.detail
    assert "steps.capture.outputs.payload" in hop.detail
    assert lines[hop.line - 1].strip() == f"payload: {binding.declaration}"
    assert analyze(content, lines) is legacy
    assert legacy == t._analyze_uncached(content, lines)


def test_scan_file_computes_taint_once_not_per_rule():
    clear_analyze_cache()
    rules = [r for r in load_all_rules() if r.platform == Platform.GITHUB]
    n_taint = sum(1 for r in rules if type(r.pattern).__name__ == "TaintPattern")
    assert n_taint >= 2  # several taint rules would each have re-run analyze pre-cache

    calls = {"n": 0}
    orig = t._build_analysis

    def counting(content, lines):
        calls["n"] += 1
        return orig(content, lines)

    t._build_analysis = counting
    try:
        scan_file("wf.yml", rules, _content=_WF)
    finally:
        t._build_analysis = orig
    # All taint rules on one file share ONE fixpoint, not n_taint of them.
    assert calls["n"] == 1, f"expected one taint computation per file, got {calls['n']}"


@pytest.mark.parametrize("outputs_first", [True, False])
def test_output_and_path_apis_share_actual_solver_and_immutable_symbols(monkeypatch, outputs_first):
    content = _WF.replace("    steps:", "    outputs:\n      title: ${{ github.event.pull_request.title }}\n    steps:")
    clear_analyze_cache()
    calls = []
    original = t._build_facts_structural

    def count(*args):
        calls.append(1)
        return original(*args)

    monkeypatch.setattr(t, "_build_facts_structural", count)
    monkeypatch.setenv("TAINTLY_TAINT_BACKEND", "structural")
    apis = [t.analyze_job_outputs, t.analyze] if outputs_first else [t.analyze, t.analyze_job_outputs]
    for api in apis:
        api(content, content.splitlines())
    outputs = t.analyze_job_outputs(content, content.splitlines())
    assert len(calls) == 1
    assert outputs.bindings[0].source_expr == "github.event.pull_request.title"
    assert isinstance(outputs.bindings[0].hops, tuple)
    with pytest.raises(FrozenInstanceError):
        outputs.bindings[0].source_expr = "fixed"
    with pytest.raises(FrozenInstanceError):
        outputs.bindings[0].hops[0].line = 0
    clear_analyze_cache()
    t.analyze_job_outputs(content, content.splitlines())
    assert len(calls) == 2


def test_content_keyed_and_clearable():
    clear_analyze_cache()
    analyze(_WF, _WF.splitlines())
    other = _WF.replace("build", "renamed")
    # Different content -> its own entry, still equal to the uncached result.
    assert analyze(other, other.splitlines()) == t._analyze_uncached(other, other.splitlines())
    clear_analyze_cache()
    assert len(t._analyze_cache) == 0


def test_output_cache_keys_backend_and_retains_legacy_path_equality(monkeypatch):
    content = _WF.replace("    steps:", "    outputs:\n      title: ${{ github.event.pull_request.title }}\n    steps:")
    clear_analyze_cache()
    for backend in ("line", "structural"):
        monkeypatch.setenv("TAINTLY_TAINT_BACKEND", backend)
        assert t.analyze(content, content.splitlines()) == t._analyze_uncached(content, content.splitlines())
        assert t.analyze_job_outputs(content, content.splitlines()).bindings
    assert len(t._analyze_cache) == 2

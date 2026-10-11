"""ReDoS canary for the ``${{ ... }}`` injection rules.

SEC4-GH-006/007/019 and TAINT-GH-013 share the shape
``\\${{[^}]*<token>[^}]*}}`` — two unbounded negated-class spans around a
required middle token.  On an adversarial ``${{``-heavy blob that never
closes, the two greedy spans drive quadratic backtracking (measured
~0.9 s per pattern per file at the 64 KiB scan cap before the spans were
bounded).  The spans are now capped (``[^}]{0,512}``), which is
behavior-preserving on real Actions expressions (far shorter than 512
chars) while making the match linear in input length.

These tests pull the *shipped* pattern from the loaded rules, so they
track the real rule, not a hand-copied duplicate that could drift.  Each
rule is asserted on two axes: it must stay fast on the adversarial
payload, and it must still fire on a canonical true positive.
"""

from __future__ import annotations

import re
import time

import pytest

from taintly.rules.github.taint import _GITHUB_SCRIPT_SOURCE_RE
from taintly.rules.registry import load_all_rules

# rule_id -> (adversarial payload that stresses backtracking,
#             canonical true-positive payload that MUST still match)
_CASES = {
    "SEC4-GH-006": (
        "${{" + "head_ref" * 6000 + "}}" + "A" * 40000 + ">> $GITHUB_XXX",
        'echo "T=${{ github.event.issue.title }}" >> $GITHUB_ENV',
    ),
    "SEC4-GH-007": (
        "${{" + "head_ref" * 6000 + "}}" + "A" * 40000 + ">> $GITHUB_XXX",
        'echo "x=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT',
    ),
    "SEC4-GH-019": (
        "${{" + "head_ref" * 6000 + "}}" + "A" * 40000 + ">> $GITHUB_XXX",
        'echo "${{ github.event.issue.title }}" >> $GITHUB_PATH',
    ),
    "TAINT-GH-013": (
        "${{" + "github.event." * 4000 + "A" * 40000,
        "const t = `${{ github.event.pull_request.title }}`",
    ),
}

# Generous ceiling: the bounded patterns run in <10 ms; the old unbounded
# quadratic exceeded 2 s on these ~90 KiB payloads.  A wide margin keeps
# the test non-flaky on slow CI while still catching a regression that
# removes the bound.
_MAX_MS = 500.0


@pytest.fixture(scope="module")
def shipped_patterns() -> dict[str, str]:
    rules = {r.id: r for r in load_all_rules()}
    # GH-013 now owns its source scalar structurally; the predicate retains
    # this exact shipped compiled regex rather than a BlockPattern.match.
    return {
        rid: _GITHUB_SCRIPT_SOURCE_RE.pattern if rid == "TAINT-GH-013" else rules[rid].pattern.match
        for rid in _CASES
    }


@pytest.mark.parametrize("rule_id", list(_CASES))
def test_pattern_is_bounded_and_linear(rule_id: str, shipped_patterns: dict[str, str]):
    rx = shipped_patterns[rule_id]
    assert "[^}]*" not in rx, f"{rule_id}: unbounded [^}}]* span reintroduced — ReDoS risk"
    compiled = re.compile(rx)
    adversarial, _ = _CASES[rule_id]
    start = time.perf_counter()
    compiled.search(adversarial)
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < _MAX_MS, f"{rule_id}: {elapsed_ms:.0f} ms on adversarial input (quadratic?)"


@pytest.mark.parametrize("rule_id", list(_CASES))
def test_true_positive_still_matches(rule_id: str, shipped_patterns: dict[str, str]):
    rx = shipped_patterns[rule_id]
    _, tp = _CASES[rule_id]
    assert re.search(rx, tp), f"{rule_id}: bounding the span dropped a true positive"


@pytest.mark.parametrize("unsafe", [False, True])
def test_github_script_structural_rule_retains_redos_contract(unsafe: bool):
    """Exercise the real structural entrypoint as well as its shipped source regex."""
    rule = next(r for r in load_all_rules() if r.id == "TAINT-GH-013")
    adversarial, positive = _CASES[rule.id]
    value = positive if unsafe else adversarial
    source = (
        "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/github-script@v7\n"
        "        with:\n          script: |\n            " + value + "\n"
    )
    start = time.perf_counter()
    findings = rule.pattern.check(source, source.splitlines())
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert bool(findings) is unsafe
    assert elapsed_ms < _MAX_MS, f"GH-013 structural scan took {elapsed_ms:.0f} ms"

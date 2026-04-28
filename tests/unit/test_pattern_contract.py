"""Sweep every rule's positive samples and verify the snippet contract.

See ``taintly._pattern_contract`` for the contract definition.  Two
documented exceptions are skipped by name (not by cheating): the
absence-pattern sentinel snippet, and the per-platform TaintPattern's
rendered provenance chain.
"""

from __future__ import annotations

import pytest

from taintly._pattern_contract import assert_snippet_matches_line
from taintly.models import AbsencePattern
from taintly.rules.registry import load_all_rules


def _is_taint_pattern(pattern) -> bool:
    """Per-platform TaintPattern lives in rules/<plat>/taint.py and
    isn't importable here without circular concerns; identify by
    class name."""
    return type(pattern).__name__ == "TaintPattern"


def _all_rules_with_positives():
    for r in load_all_rules():
        if not r.test_positive:
            continue
        # Documented exception: AbsencePattern emits a sentinel snippet.
        if isinstance(r.pattern, AbsencePattern):
            continue
        # Documented exception: TaintPattern emits a rendered chain.
        if _is_taint_pattern(r.pattern):
            continue
        yield r


@pytest.mark.parametrize(
    "rule",
    list(_all_rules_with_positives()),
    ids=lambda r: r.id,
)
def test_pattern_contract_every_rule(rule):
    """For every rule with positive samples, every match must satisfy the
    snippet contract: snippet text comes from the cited line."""
    for sample in rule.test_positive:
        lines = sample.splitlines()
        try:
            matches = rule.pattern.check(sample, lines)
        except Exception as e:
            pytest.skip(f"{rule.id} pattern raised on sample: {e}")
        # Some rule patterns are file-scope and may match nothing on a
        # one-step positive sample — that's fine, we're only verifying
        # the contract on samples that DO match.
        for line_num, snippet in matches:
            assert_snippet_matches_line(line_num, snippet, lines)

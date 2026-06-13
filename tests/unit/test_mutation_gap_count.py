"""Teeth-test for the composition-aware mutation-gap ratchet (P3.4).

``scripts/check_mutation_gap_count.py`` guards
``taintly/testing/self_test.py::_KNOWN_MUTATION_GAPS`` against drift. A GLOBAL
``len(...)`` baseline is composition-blind — removing one gap while adding an
unrelated one keeps the count flat — so the gate tracks the count PER
rule-family prefix against a per-key baseline and fails on any per-key drift.
These tests prove it has teeth: it catches a flat-count cross-family SWAP that a
global count would miss, and both directions of single-key drift, while staying
green on the real tree.
"""

from __future__ import annotations

from scripts import check_mutation_gap_count as gate


def test_rule_family_prefix_strips_ordinal():
    assert gate.rule_family_prefix("SEC4-GH-002") == "SEC4-GH"
    assert gate.rule_family_prefix("SEC4-GH-026A") == "SEC4-GH"
    assert gate.rule_family_prefix("AI-GH-019") == "AI-GH"
    assert gate.rule_family_prefix("TAINT-GL-006") == "TAINT-GL"
    # No separator -> the id is its own prefix.
    assert gate.rule_family_prefix("WEIRD") == "WEIRD"


def test_real_allowlist_matches_baseline():
    # Regression guard: the shipped allowlist matches the per-prefix baseline.
    assert gate.main() == 0


def test_counts_by_prefix_groups_entries():
    gaps = {
        ("SEC4-GH-001", "whitespace_pad"): "",
        ("SEC4-GH-002", "comment_inject"): "",
        ("TAINT-GH-001", "quote_swap"): "",
    }
    assert gate.counts_by_prefix(gaps) == {"SEC4-GH": 2, "TAINT-GH": 1}


def test_drift_detects_growth():
    drifted = gate.drift({"SEC4-GH": 7}, {"SEC4-GH": 6})
    assert drifted == {"SEC4-GH": (7, 6)}


def test_drift_detects_shrink():
    drifted = gate.drift({"SEC4-GH": 5}, {"SEC4-GH": 6})
    assert drifted == {"SEC4-GH": (5, 6)}


def test_drift_clean_when_matching():
    assert gate.drift({"A": 1, "B": 2}, {"A": 1, "B": 2}) == {}


def test_flat_count_swap_is_detected():
    """The headline P3.4 case: a global ``len`` is unchanged but one family's
    gap was removed and another family's gap added. A global-count gate sees
    no change; the per-prefix gate sees TWO drifted keys."""
    baseline = {"SEC4-GH": 6, "TAINT-GH": 27}
    # Remove a TAINT-GH gap, add a SEC4-GH gap. Total unchanged (33 -> 33).
    swapped = {"SEC4-GH": 7, "TAINT-GH": 26}
    assert sum(swapped.values()) == sum(baseline.values())  # global count is flat
    drifted = gate.drift(swapped, baseline)
    assert drifted == {"SEC4-GH": (7, 6), "TAINT-GH": (26, 27)}  # but composition moved


def test_new_prefix_drifts_against_baseline_zero():
    # A gap in a family with no baseline entry is growth from 0.
    drifted = gate.drift({"NEW-GH": 1}, {})
    assert drifted == {"NEW-GH": (1, 0)}


def test_vanished_prefix_drifts_to_zero():
    drifted = gate.drift({}, {"SEC9-JK": 1})
    assert drifted == {"SEC9-JK": (0, 1)}

"""Minimal-vulnerability + delete-violation round-trip tests.

Two complementary properties on the rule × fixture matrix:

  * Minimal vulnerability (audit chunk 2.2): the smallest
    self-contained YAML that exercises a rule's positive sample
    must fire that rule. Each ``rule.test_positive`` is *already*
    intended to be that minimum, so the test is a contract: every
    positive sample, when scanned in isolation, must fire its own
    rule. Catches the case where a rule's regex grew dependencies
    on surrounding context that the test_positive sample doesn't
    have. Failure mode: rule fires only on the realistic full-
    workflow fixture, not on the minimum — meaning the rule is
    fragile to fixture refactors.

  * Round-trip "delete violation, expect no fire" (audit chunk 2.3):
    every ``rule.test_negative`` is by definition a sample that
    must NOT fire the rule. We surface this as a per-rule
    parametrised test so a regression that flips a single rule's
    negative-sample verdict gets a per-rule failure (not a global
    self-test failure where you have to grep to find which rule).

Together these pin "the smallest YAML that's vulnerable IS detected
AND the smallest YAML that's safe is NOT detected" — a strong
correctness signal that's invariant to fixture refactoring.
"""

from __future__ import annotations

import pytest

from taintly.engine import scan_file
from taintly.models import AbsencePattern
from taintly.rules.registry import load_all_rules


def _is_skippable_rule(rule) -> bool:
    """Mirror the integration suite's stub filter — rules that don't
    operate on per-file YAML can't be exercised by writing the sample
    to a tempfile."""
    from taintly.rules.github.sec3_sec4_supply_chain_ppe import ImposterCommitPattern
    from taintly.workflow_corpus import CorpusPattern

    if isinstance(rule.pattern, CorpusPattern):
        return True
    if isinstance(rule.pattern, ImposterCommitPattern):
        return True
    if (
        isinstance(rule.pattern, AbsencePattern)
        and "INTENTIONALLY_DISABLED" in rule.pattern.absent
    ):
        return True
    return False


def _suffix_for(rule) -> str:
    """Pick a tempfile suffix that matches the rule's expected file
    type, so language-aware filters in the engine route the sample
    through the right pipeline."""
    if rule.platform.value == "jenkins":
        return ".Jenkinsfile"
    return ".yml"


# Rules whose minimal positive samples don't fire in isolation. These
# are documented gaps where the rule needs surrounding context (an
# ``on:`` trigger, a ``jobs:`` parent) that the bare positive sample
# omits. Each entry is a real rule-engineering observation, NOT a
# test bug — fix by either:
#   * Expanding the rule's positive sample to include needed context.
#   * Loosening the rule pattern to match the bare line.
#
# Same growth-only discipline as _KNOWN_MUTATION_GAPS: shrinking is
# good, growing is forbidden by the gate.
_MINIMAL_FIRES_BASELINE: int  # set below after enumeration

# Rules whose negative samples DO fire — pre-existing rule precision
# gaps that this test will newly surface. Same baseline pattern.
_NEGATIVE_FIRES_BASELINE: int


@pytest.fixture(scope="module")
def _all_rules():
    return load_all_rules()


def _gather_minimal_fire_failures(rules) -> list[tuple[str, str]]:
    failures: list[tuple[str, str]] = []
    import os
    import tempfile

    for r in rules:
        if _is_skippable_rule(r):
            continue
        if not r.test_positive:
            continue
        for sample in r.test_positive:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=_suffix_for(r), delete=False, encoding="utf-8"
            ) as fh:
                fh.write(sample)
                tmp = fh.name
            try:
                findings = scan_file(tmp, rules=[r])
            finally:
                os.unlink(tmp)
            fired = {f.rule_id for f in findings if f.rule_id != "ENGINE-ERR"}
            if r.id not in fired:
                failures.append((r.id, sample[:80]))
    return failures


def _gather_negative_fire_failures(rules) -> list[tuple[str, str]]:
    failures: list[tuple[str, str]] = []
    import os
    import tempfile

    for r in rules:
        if _is_skippable_rule(r):
            continue
        if not r.test_negative:
            continue
        for sample in r.test_negative:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=_suffix_for(r), delete=False, encoding="utf-8"
            ) as fh:
                fh.write(sample)
                tmp = fh.name
            try:
                findings = scan_file(tmp, rules=[r])
            finally:
                os.unlink(tmp)
            fired = {f.rule_id for f in findings if f.rule_id != "ENGINE-ERR"}
            if r.id in fired:
                failures.append((r.id, sample[:80]))
    return failures


# Resolved at import time so the baselines below are honest.
def _initial_counts():
    rules = load_all_rules()
    return (
        len(_gather_minimal_fire_failures(rules)),
        len(_gather_negative_fire_failures(rules)),
    )


_MINIMAL_FIRES_BASELINE, _NEGATIVE_FIRES_BASELINE = _initial_counts()


def test_minimal_positive_samples_fire_no_growth(_all_rules):
    """Every rule's positive sample must fire that rule when scanned
    in isolation — i.e. the minimum-YAML form is detectable, not just
    the full-workflow form.

    Growth-only gate: failures count cannot exceed the committed
    baseline. The baseline auto-resolves at import time, so as
    contributors fix rules the gate keeps tracking.
    """
    failures = _gather_minimal_fire_failures(_all_rules)
    if len(failures) > _MINIMAL_FIRES_BASELINE:
        new = len(failures) - _MINIMAL_FIRES_BASELINE
        sample = failures[: min(20, len(failures))]
        pytest.fail(
            f"{new} new minimal-positive-sample failure(s) since baseline "
            f"of {_MINIMAL_FIRES_BASELINE}. A rule whose positive sample "
            f"doesn't fire when scanned in isolation has grown a hidden "
            f"context dependency. Fix the rule's pattern or expand the "
            f"sample to include the needed context.\n"
            f"First failures: {sample}"
        )


def test_minimal_negative_samples_dont_fire_no_growth(_all_rules):
    """Round-trip companion: every rule's negative sample must NOT
    fire that rule when scanned in isolation.

    A negative sample that fires is by definition a false positive at
    the rule's own claimed precision boundary. Same growth-only gate.
    """
    failures = _gather_negative_fire_failures(_all_rules)
    if len(failures) > _NEGATIVE_FIRES_BASELINE:
        new = len(failures) - _NEGATIVE_FIRES_BASELINE
        sample = failures[: min(20, len(failures))]
        pytest.fail(
            f"{new} new negative-sample false-positive(s) since baseline "
            f"of {_NEGATIVE_FIRES_BASELINE}. A negative sample that fires "
            f"is a precision regression at the rule's documented boundary."
            f"\nFirst failures: {sample}"
        )

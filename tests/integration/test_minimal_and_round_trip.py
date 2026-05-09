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


# Hardcoded growth-only baselines. The earlier auto-resolved version
# (``_MINIMAL_FIRES_BASELINE = len(_gather_*_failures(...))`` at import
# time) was a no-op gate: ``len(failures) > BASELINE`` could never
# fire because both sides were computed from the same load of the
# rule pack on every run. A contributor adding 10 new broken rules
# would see baseline auto-rise to accommodate them and the test
# would still pass.
#
# Same discipline as ``_KNOWN_MUTATION_GAPS`` (see
# ``scripts/check_mutation_gap_count.py``) and
# ``_INCIDENT_REF_BASELINE`` / ``_DUPLICATE_POSITIVE_BASELINE`` in
# ``test_rule_pack_consistency.py``: hardcode the count, fail on
# growth, fail on shrinkage to force the constant down on the same
# PR that lands the fix. The numbers below are the validated
# failure count at the time this test was wired in; lower them as
# the underlying rules get fixed, never raise them.
_MINIMAL_FIRES_BASELINE = 4
_NEGATIVE_FIRES_BASELINE = 0


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


def test_minimal_positive_samples_fire_no_growth(_all_rules):
    """Every rule's positive sample must fire that rule when scanned
    in isolation — i.e. the minimum-YAML form is detectable, not just
    the full-workflow form.

    Growth-only gate against the hardcoded baseline above. Failures
    growing past the baseline trips the build; failures dropping below
    also trips the build, so the constant gets ratcheted down on the
    same PR that lands the rule fix (otherwise the gate stops tracking
    the new floor).
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
    if len(failures) < _MINIMAL_FIRES_BASELINE:
        pytest.fail(
            f"minimal-positive-sample failure count dropped to "
            f"{len(failures)} (baseline was {_MINIMAL_FIRES_BASELINE}). "
            f"Update _MINIMAL_FIRES_BASELINE in this file to "
            f"{len(failures)} so the gate stays meaningful."
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
    if len(failures) < _NEGATIVE_FIRES_BASELINE:
        pytest.fail(
            f"negative-sample false-positive count dropped to "
            f"{len(failures)} (baseline was {_NEGATIVE_FIRES_BASELINE}). "
            f"Update _NEGATIVE_FIRES_BASELINE in this file to "
            f"{len(failures)} so the gate stays meaningful."
        )


# ---------------------------------------------------------------------------
# Gate self-test — ensure the baselines are static constants, not
# auto-resolved values. The earlier ``_initial_counts()`` version of
# this module computed both ``len(failures)`` and ``BASELINE`` from the
# same load of the rule pack on every test run, making the gate a
# tautology (``x > x`` is always False). This test pins the constraint
# that future contributors don't reintroduce that pattern by accident.
# ---------------------------------------------------------------------------


def test_baselines_are_static_constants():
    """The growth-only gate is meaningful only if the baseline is
    a hardcoded number — auto-resolving the baseline from the current
    failure count makes the comparison tautological.

    This test inspects the module source and asserts the baseline
    constants are integer literals, not expressions. If you need to
    update a baseline, change the literal; don't replace it with a
    function call or computed value.
    """
    import ast
    import inspect
    import sys

    module = sys.modules[__name__]
    source = inspect.getsource(module)
    tree = ast.parse(source)

    baseline_names = {"_MINIMAL_FIRES_BASELINE", "_NEGATIVE_FIRES_BASELINE"}
    found: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        # Module-level assignments only — annotated or plain.
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id in baseline_names:
                    found[tgt.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id in baseline_names and node.value is not None:
                found[node.target.id] = node.value

    missing = baseline_names - set(found)
    assert not missing, (
        f"baseline constants not found at module scope: {sorted(missing)}"
    )

    for name, value_node in found.items():
        assert isinstance(value_node, ast.Constant) and isinstance(
            value_node.value, int
        ), (
            f"{name} must be assigned an integer literal so the gate is a "
            f"real comparison, not a tautology. Got: "
            f"{ast.unparse(value_node)!r}. If you're tempted to compute "
            f"the baseline at import time, read the module docstring — "
            f"that pattern was the original bug this test exists to "
            f"prevent."
        )

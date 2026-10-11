"""Groovy quote swaps may remove the only executable PR-context reference."""

import pytest

from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform
from taintly.testing.mutations import mutate_quote_swap
from taintly.testing.self_test import run_mutation_tests


def _rule():
    return next(r for r in load_rules_for_platform(Platform.JENKINS) if r.id == "LOTP-JK-003")


def test_context_quote_swap_changes_meaning_and_is_counted_as_known_survival():
    rule = _rule()
    assert len(rule.test_positive) == 3
    for sample in rule.test_positive:
        assert rule.pattern.check(sample, sample.splitlines())
        live = sample.replace("'", '"')
        inert = sample.replace('"', "'")
        assert live in mutate_quote_swap(sample)
        assert inert in mutate_quote_swap(sample)
        assert rule.pattern.check(live, live.splitlines())
        assert not rule.pattern.check(inert, inert.splitlines())
    results = run_mutation_tests([rule])
    survivors = [r for r in results if r.known_gap]
    assert len(survivors) == 3
    assert all(r.mutation_op == "quote_swap" and r.passed for r in survivors)
    assert all(r.passed for r in results)


@pytest.mark.parametrize("quote", ["'", '"'])
@pytest.mark.parametrize("guard", ["", " --ignore-scripts"])
def test_installer_quote_swap_keeps_executable_context_obligation(quote, guard):
    rule = _rule()
    sample = f"if (env.CHANGE_ID) {{ sh {quote}npm ci{guard}{quote} }}"
    assert bool(rule.pattern.check(sample, sample.splitlines())) is (not guard)

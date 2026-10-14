"""LOTP-JK-001 quote swaps that erase live PR evidence are conditional gaps."""

from types import SimpleNamespace

import pytest

from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform
from taintly.testing.mutations import mutate_quote_swap
from taintly.testing.self_test import run_mutation_tests


def _rule():
    return next(r for r in load_rules_for_platform(Platform.JENKINS) if r.id == "LOTP-JK-001")


def test_only_live_gstring_quote_swap_positive_survivors_are_known_gaps():
    rule = _rule()
    assert len(rule.test_positive) == 3
    for sample in rule.test_positive:
        assert rule.pattern.check(sample, sample.splitlines())

    results = run_mutation_tests([rule])
    known = [result for result in results if result.known_gap]
    assert len(known) == 2
    assert all(
        result.rule_id == "LOTP-JK-001"
        and result.test_type == "mutation_positive"
        and result.mutation_op == "quote_swap"
        and result.expected == "trigger"
        and result.actual == "no_trigger"
        and result.passed
        for result in known
    )
    assert all(result.passed for result in results)


def test_live_code_context_and_nonapplicable_or_unknown_mutants_are_not_excused():
    real_rule = _rule()
    live_code = "if (env.CHANGE_ID) { sh 'npm install' }"
    assert real_rule.pattern.check(live_code, live_code.splitlines())
    mutant = mutate_quote_swap(live_code)[0]
    assert mutant != live_code
    assert real_rule.pattern.check(mutant, mutant.splitlines())

    class AlwaysMiss:
        @staticmethod
        def check(_content, _lines):
            return []

    broken = SimpleNamespace(
        id="LOTP-JK-001", pattern=AlwaysMiss(), test_positive=[live_code], test_negative=[]
    )
    quote_result = next(
        result
        for result in run_mutation_tests([broken])
        if result.mutation_op == "quote_swap" and result.sample == mutant[:80]
    )
    assert quote_result.actual == "no_trigger"
    assert quote_result.passed is False
    assert quote_result.known_gap is False
    assert all(
        not result.known_gap
        for result in run_mutation_tests([broken])
        if result.mutation_op != "quote_swap"
    )

    class AlwaysMatch:
        @staticmethod
        def check(_content, _lines):
            return [(1, "forced false-positive control")]

    negative = SimpleNamespace(
        id="LOTP-JK-001",
        pattern=AlwaysMatch(),
        test_positive=[],
        test_negative=['echo "PR ${env.CHANGE_ID}"'],
    )
    negative_results = run_mutation_tests([negative])
    assert negative_results
    assert all(not result.known_gap for result in negative_results)
    assert all(not result.passed for result in negative_results)

    malformed = 'sh "npm install"\necho "PR ${env.CHANGE_ID"'
    unsupported = SimpleNamespace(
        id="LOTP-JK-001", pattern=AlwaysMiss(), test_positive=[malformed], test_negative=[]
    )
    unsupported_quotes = [
        result for result in run_mutation_tests([unsupported]) if result.mutation_op == "quote_swap"
    ]
    assert unsupported_quotes
    assert all(not result.known_gap and not result.passed for result in unsupported_quotes)

    malformed_structure = "node { echo \"${env.CHANGE_ID}\"; sh 'npm install'"
    assert mutate_quote_swap(malformed_structure)
    malformed_result = SimpleNamespace(
        id="LOTP-JK-001",
        pattern=AlwaysMiss(),
        test_positive=[malformed_structure],
        test_negative=[],
    )
    malformed_gaps = [
        result
        for result in run_mutation_tests([malformed_result])
        if result.mutation_op == "quote_swap"
    ]
    assert malformed_gaps
    assert all(not result.known_gap and not result.passed for result in malformed_gaps)

    unterminated_comment = "node { echo \"${env.CHANGE_ID}\"; sh 'npm install' } /* unfinished"
    assert mutate_quote_swap(unterminated_comment)
    comment_result = SimpleNamespace(
        id="LOTP-JK-001",
        pattern=AlwaysMiss(),
        test_positive=[unterminated_comment],
        test_negative=[],
    )
    comment_gaps = [
        result
        for result in run_mutation_tests([comment_result])
        if result.mutation_op == "quote_swap"
    ]
    assert comment_gaps
    assert all(not result.known_gap and not result.passed for result in comment_gaps)

    retained_dynamic_access = (
        "if (env['CHANGE_ID']) { echo \"${env.CHANGE_ID}\"; sh 'npm install' }"
    )
    assert mutate_quote_swap(retained_dynamic_access)
    dynamic_result = SimpleNamespace(
        id="LOTP-JK-001",
        pattern=AlwaysMiss(),
        test_positive=[retained_dynamic_access],
        test_negative=[],
    )
    dynamic_gaps = [
        result
        for result in run_mutation_tests([dynamic_result])
        if result.mutation_op == "quote_swap"
    ]
    assert dynamic_gaps
    assert all(not result.known_gap and not result.passed for result in dynamic_gaps)

    spaced_expression = "node { echo \"${env . CHANGE_ID}\"; sh 'npm install' }"
    assert mutate_quote_swap(spaced_expression)
    spaced_result = SimpleNamespace(
        id="LOTP-JK-001",
        pattern=AlwaysMiss(),
        test_positive=[spaced_expression],
        test_negative=[],
    )
    spaced_gaps = [
        result
        for result in run_mutation_tests([spaced_result])
        if result.mutation_op == "quote_swap"
    ]
    assert spaced_gaps
    assert all(not result.known_gap and not result.passed for result in spaced_gaps)


@pytest.mark.parametrize(
    "retained_access",
    ["env.'CHANGE_ID'", "env.getProperty('CHANGE_ID')"],
    ids=["quoted-property", "method-access"],
)
def test_unmodeled_retained_pr_access_prevents_gap_exemption(retained_access):
    source = "if (" + retained_access + ") { echo \"${env.CHANGE_ID}\"; sh 'npm install' }"
    mutants = mutate_quote_swap(source)
    assert mutants
    mutant = next(candidate for candidate in mutants if "echo '${env.CHANGE_ID}'" in candidate)
    assert mutant != source

    class AlwaysMiss:
        @staticmethod
        def check(_content, _lines):
            return []

    broken = SimpleNamespace(
        id="LOTP-JK-001", pattern=AlwaysMiss(), test_positive=[source], test_negative=[]
    )
    results = [
        result
        for result in run_mutation_tests([broken])
        if result.mutation_op == "quote_swap" and result.sample == mutant[:80]
    ]
    assert results
    assert all(result.actual == "no_trigger" for result in results)
    assert all(not result.known_gap and not result.passed for result in results)

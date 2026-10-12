"""Balanced YAML quoting does not imply valid Actions expression quoting."""

import pytest

from taintly.parsers.gha_expr import ExprSyntaxError, parse
from taintly.rules.github.ai import RULES
from taintly.testing.mutations import mutate_quote_swap
from taintly.testing.self_test import run_mutation_tests

RULE = next(rule for rule in RULES if rule.id == "AI-GH-006")


def test_quote_mutation_cannot_claim_invalid_actions_string_is_equivalent():
    sample = RULE.test_negative[-1]
    original_guard = "github.event.comment.author_association == 'MEMBER'"
    invalid_guard = original_guard.replace("'", '"')
    parse(original_guard)
    with pytest.raises(ExprSyntaxError):
        parse(invalid_guard)
    mutated = sample.replace("'", '"')
    # Invalid input still keeps the detector's uncertainty visible.
    assert RULE.pattern.check(mutated, mutated.splitlines())
    assert mutated not in mutate_quote_swap(sample)
    results = run_mutation_tests([RULE])
    assert results
    assert all(row.passed for row in results)


def test_valid_yaml_quote_swap_is_still_exercised():
    original = 'on: pull_request_target\njobs:\n  review:\n    name: "Review"\n'
    assert original.replace('"', "'") in mutate_quote_swap(original)


def test_unrelated_guard_does_not_remove_an_independent_quote_mutation():
    original = (
        'on: pull_request_target\njobs:\n  review:\n    if: inputs.run_agent\n    name: "Review"\n'
    )
    assert original.replace('"', "'") in mutate_quote_swap(original)


def test_already_unsupported_guard_is_not_a_new_exclusion_proof():
    original = 'jobs:\n  review:\n    if: "broken guard"\n'
    assert original.replace('"', "'") in mutate_quote_swap(original)


@pytest.mark.parametrize(
    "prefix",
    [
        "jobs:\n  - if:",
        "jobs:\n  review:\n    steps:\n      named:\n        if:",
    ],
)
def test_malformed_job_or_step_owner_cannot_discard_mutation(prefix):
    original = prefix + " github.event.comment.author_association == 'MEMBER'\n"
    assert original.replace("'", '"') in mutate_quote_swap(original)

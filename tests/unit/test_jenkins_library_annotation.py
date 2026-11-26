"""The requested ref belongs to one Groovy annotation operand."""

import pytest

from taintly.models import IncompletePatternMatches
from taintly.rules.jenkins.library_annotation import LibraryAnnotationPinPattern

COMMIT = "abcdef1234567890abcdef1234567890abcdef12"


def assess(source):
    return LibraryAnnotationPinPattern().check(source, source.splitlines())


@pytest.mark.parametrize(
    "source",
    [
        "echo \"Example: @Library('demo@main')\"",
        "/*\n@Library('demo@main') _\n*/\necho 'check'",
        f"@Library('demo@{COMMIT.upper()}') _",
    ],
)
def test_no_symbolic_request_in_data_or_literal_git_commit(source):
    outcome = assess(source)
    assert not isinstance(outcome, IncompletePatternMatches)
    assert outcome == []


def test_operand_on_another_line_keeps_its_own_ref_and_location():
    source = f"@Library(['fixed@{COMMIT}',\n  'moving@main',\n]) _"
    assert assess(source) == [(2, "'moving@main'")]


def test_provider_default_remains_unresolved_with_symbolic_sibling():
    outcome = assess("@Library(['configured', 'moving@main']) _")
    assert outcome == [(1, "'moving@main'")]
    assert isinstance(outcome, IncompletePatternMatches)
    assert "configured default version" in outcome.reason


@pytest.mark.parametrize("source", ["@Library(", "@Library(['demo@main'", "@Library(selector) _"])
def test_unsupported_or_bounded_operand_remains_unresolved(source):
    outcome = assess(source)
    assert not outcome
    assert isinstance(outcome, IncompletePatternMatches)
    assert "unsupported @Library argument syntax" in outcome.reason

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


def test_github_library_name_keeps_its_own_explicit_ref():
    source = (
        f"@Library(['github.com/example/fixed@{COMMIT}',\n"
        "  'github.com/example/selected@release']) _"
    )
    assert assess(source) == [(2, "'github.com/example/selected@release'")]
    assert assess(f"@Library('github.com/example/fixed@{COMMIT}') _") == []


def test_github_library_without_ref_still_requires_controller_default():
    outcome = assess("@Library('github.com/example/default') _")
    assert isinstance(outcome, IncompletePatternMatches)
    assert "configured default version" in outcome.reason


def test_unmodeled_retriever_name_remains_unresolved():
    outcome = assess("@Library('gitlab.com/example/library@release') _")
    assert isinstance(outcome, IncompletePatternMatches)
    assert not outcome
    assert "unresolved @Library revision argument" in outcome.reason


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

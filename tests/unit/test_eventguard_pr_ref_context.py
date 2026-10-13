"""Same-invocation correlation for pull-request-only ref context fields."""

import pytest

from taintly.eventguard import UNCONSTRAINED, guard_constraints


@pytest.mark.parametrize("event", ["pull_request", "pull_request_target"])
@pytest.mark.parametrize("field", ["base_ref", "head_ref"])
def test_pr_ref_fields_correlate_direct_ascii_string_comparisons(event, field):
    path = f"github.{field}"
    assert not guard_constraints([f"{path} == 'feature-a'", f"{path} == 'feature-b'"], event)
    assert not guard_constraints([f"{path} == 'feature-a'", f"{path} != 'FEATURE-A'"], event)
    assert guard_constraints([f"{path} == 'feature-a'", f"{path} != 'feature-b'"], event)


@pytest.mark.parametrize("event", ["pull_request", "pull_request_target"])
def test_pr_ref_fields_accept_reversed_and_static_index_operands(event):
    assert not guard_constraints(
        ["github.head_ref == 'feature-a'", "'feature-b' == github['head_ref']"], event
    )
    assert not guard_constraints(
        ["github.base_ref != 'release'", "github['base_ref'] == 'release'"], event
    )


def test_pr_ref_constraints_push_negation_and_or_alternatives_into_dnf():
    assert not guard_constraints(
        ["!(github.base_ref == 'release')", "github.base_ref == 'release'"],
        "pull_request_target",
    )
    assert guard_constraints(
        [
            "(github.head_ref == 'topic-a' || github.head_ref == 'topic-b')",
            "github.head_ref == 'topic-b'",
        ],
        "pull_request",
    )


def test_pr_ref_fields_remain_independent_from_each_other_and_github_ref():
    assert guard_constraints(
        [
            "github.head_ref == 'same'",
            "github.base_ref == 'same'",
            "github.ref == 'refs/heads/same'",
        ],
        "pull_request_target",
    )
    assert guard_constraints(
        ["github.head_ref == 'source'", "github.base_ref == 'target'"],
        "pull_request_target",
    )


@pytest.mark.parametrize(
    "event",
    ["push", "issues", "workflow_run", "workflow_call", "pull_request_review"],
)
def test_pr_ref_fields_are_unknown_outside_the_two_supported_pr_events(event):
    assert (
        guard_constraints(["github.head_ref == 'source'", "github.head_ref == 'target'"], event)
        == UNCONSTRAINED
    )
    assert (
        guard_constraints(["github.base_ref == 'source'", "github.base_ref == 'target'"], event)
        == UNCONSTRAINED
    )


@pytest.mark.parametrize(
    "unknown",
    [
        f"github.head_ref == '{chr(0x212A)}'",
        "github.base_ref == inputs.branch",
        "github.head_ref || 'fallback' == 'source'",
        "fromJSON(toJSON(github)).head_ref == 'source'",
        "github[inputs.key] == 'source'",
        "github.head_ref ==",
    ],
)
def test_transformed_dynamic_unicode_and_malformed_pr_ref_comparisons_stay_unknown(unknown):
    assert guard_constraints([unknown], "pull_request_target") == UNCONSTRAINED
    assert guard_constraints([f"!({unknown})"], "pull_request_target") == UNCONSTRAINED

"""Conservative satisfiability of same-invocation string guards."""

from itertools import product

import pytest

from taintly.eventguard import (
    UNCONSTRAINED,
    guard_constraints,
    intersect_constraints,
    union_constraints,
)


@pytest.mark.parametrize(
    ("guards", "possible"),
    [
        (["github.ref == 'main'", "github.ref == 'dev'"], False),
        (["github.ref == 'main'", "github.ref != 'main'"], False),
        (["github.ref == 'main'", "github.ref != 'dev'"], True),
        (["github.ref != 'main'", "github.ref != 'dev'"], True),
        (["github.ref == 'MAIN'", "'main' == github['ref']"], True),
        (["github.ref == 'MAIN'", "'main' != github['ref']"], False),
        (["github.ref == 'main' || github.ref == 'dev'", "github.ref == 'dev'"], True),
        (["github.ref == 'main' || github.ref == 'dev'", "github.ref == 'other'"], False),
        (["!(github.ref == 'main' || github.ref == 'dev')", "github.ref == 'dev'"], False),
        (["!(github.ref == 'main' && github.ref == 'dev')"], True),
        (["!((github.ref == 'main') || inputs.unknown)", "github.ref == 'main'"], False),
        (["!((github.ref == 'main') && inputs.unknown)", "github.ref == 'main'"], True),
        (["github.event_name == 'push'"], False),
        (["github.event_name != 'push'", "github.ref == 'dev'"], True),
        (["${{ github.ref == 'main' }}", "github.ref != 'MAIN'"], False),
    ],
)
def test_joint_guards(guards, possible):
    assert bool(guard_constraints(guards, "pull_request_target")) is possible


@pytest.mark.parametrize(
    "unknown",
    [
        "env.VALUE == 'dev'",
        "needs.build.outputs.ref == 'dev'",
        "github.ref == 0",
        "github.ref == null",
        "github.ref == true",
        "github.ref == '\u212a'",
        "fromJSON(toJSON(github)).ref == 'dev'",
        "fromJSON(toJSON(github.ref)) == 'dev'",
        "github[inputs.key] == 'dev'",
        "github.ref == 'dev' trailing",
        "contains(github.ref, 'dev')",
        "github.actor == 'dependabot[bot]'",
    ],
)
def test_unknown_guard_or_its_negation_cannot_exclude(unknown):
    assert guard_constraints([unknown], "issues") == UNCONSTRAINED
    assert guard_constraints([f"!({unknown})"], "issues") == UNCONSTRAINED
    assert guard_constraints(["github.ref == 'main'", unknown], "issues")


def test_constraints_match_independent_finite_boolean_semantics():
    # Ref equality has exactly three equivalence classes for these literals;
    # unknown runtime predicates range over both booleans. This oracle uses
    # concrete Boolean evaluation, independently of the DNF implementation.
    atoms = [
        ("github.ref == 'main'", lambda ref, _unknown: ref == "main"),
        ("github.ref != 'dev'", lambda ref, _unknown: ref != "dev"),
        ("inputs.unknown", lambda _ref, unknown: unknown),
    ]
    for (left, left_eval), (right, right_eval), op, negate in product(
        atoms, atoms, ("&&", "||"), (False, True)
    ):
        body = f"({left}) {op} ({right})"
        if negate:
            body = f"!({body})"
        for required_ref in ("main", "dev", "other"):
            actual = []
            for unknown in (False, True):
                first = left_eval(required_ref, unknown)
                second = right_eval(required_ref, unknown)
                value = (first and second) if op == "&&" else (first or second)
                actual.append(not value if negate else value)
            may_hold = guard_constraints([body, f"github.ref == '{required_ref}'"], "issues")
            # Unknowns may widen, but no concretely possible execution is lost.
            if any(actual):
                assert may_hold, (body, required_ref)
            if "inputs." not in body:
                assert bool(may_hold) is any(actual), (body, required_ref)


def test_alternative_authorities_are_or_and_unknown_retains_path():
    main = guard_constraints(["github.ref == 'main'"], "issues")
    dev = guard_constraints(["github.ref == 'dev'"], "issues")
    assert not intersect_constraints(main, dev)
    assert intersect_constraints(main, union_constraints((main, dev)))
    assert union_constraints((dev, UNCONSTRAINED)) == UNCONSTRAINED
    assert intersect_constraints(main, union_constraints((dev, UNCONSTRAINED)))


def test_bounds_widen_instead_of_discarding_possible_branches():
    alternatives = [guard_constraints([f"github.ref == 'ref{i}'"], "issues") for i in range(65)]
    assert union_constraints(alternatives) == UNCONSTRAINED
    assert guard_constraints(["x" * 8193], "issues") == UNCONSTRAINED
    assert guard_constraints(["github.ref == 'main'"] * 17, "issues") == UNCONSTRAINED
    oversized = " || ".join(f"github.ref == 'ref{i}'" for i in range(100))
    assert guard_constraints([oversized], "issues")
    assert guard_constraints([f"!({oversized})", "github.ref == 'unlisted'"], "issues")


def test_join_work_budget_widens_and_preserves_a_late_compatible_alternative():
    alternatives = union_constraints(
        guard_constraints([f"github.ref == 'ref{i}'"], "issues") for i in range(64)
    )
    assert len(alternatives) == 64
    joined = intersect_constraints(alternatives, alternatives)
    late = guard_constraints(["github.ref == 'ref63'"], "issues")
    assert joined == UNCONSTRAINED
    assert intersect_constraints(joined, late)

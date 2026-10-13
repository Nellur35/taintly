"""Bounded syntactic absorption for guard-domain alternatives."""

import taintly.eventguard as eventguard
from taintly.eventguard import UNCONSTRAINED, intersect_constraints, union_constraints

Atom = tuple[str, str, bool]
Branch = frozenset[Atom]
Domain = tuple[Branch, ...]


def _branch(ref: str, *, equal: bool = True, extra: Atom | None = None) -> Branch:
    atoms = {("github.ref", ref, equal)}
    if extra is not None:
        atoms.add(extra)
    return frozenset(atoms)


def _holds(branch: Branch, ref: str) -> bool:
    return all((ref == value) is equal for _path, value, equal in branch)


def _domain_holds(domain: Domain, ref: str) -> bool:
    return any(_holds(branch, ref) for branch in domain)


def _boolean_minterm(value: int) -> Branch:
    return frozenset((f"boolean.{index}", "true", bool(value & (1 << index))) for index in range(3))


def _boolean_domain_holds(domain: Domain, value: int) -> bool:
    return any(
        all(
            (
                (
                    True
                    if path == "boolean.extra"
                    else bool(value & (1 << int(path.rsplit(".", 1)[1])))
                )
                is expected
            )
            for path, _literal, expected in branch
        )
        for branch in domain
    )


def test_union_absorbs_supersets_in_both_orders_and_keeps_stable_order() -> None:
    main = _branch("main")
    restricted = _branch("main", extra=("github.ref", "dev", False))
    dev = _branch("dev")
    feature = _branch("feature")

    assert union_constraints(((main,), (restricted,))) == (main,)
    assert union_constraints(((restricted,), (main,))) == (main,)
    assert union_constraints(((dev,), (main,), (feature,), (restricted,))) == (
        dev,
        main,
        feature,
    )


def test_union_and_intersection_preserve_all_256_three_boolean_functions() -> None:
    minterms = tuple(_boolean_minterm(value) for value in range(8))
    for truth_table in range(256):
        original = tuple(
            minterm for value, minterm in enumerate(minterms) if truth_table & (1 << value)
        )
        # Each extended term is a strict subset of its matching minterm's
        # satisfying assignments, so the base DNF should absorb it.
        extended = tuple(
            branch | frozenset({("boolean.extra", "enabled", True)}) for branch in original
        )
        reduced = union_constraints((original + extended,))
        self_intersection = intersect_constraints(reduced, reduced)
        complement = tuple(
            minterm for value, minterm in enumerate(minterms) if not truth_table & (1 << value)
        )
        disjoint_intersection = intersect_constraints(reduced, complement)
        for value in range(8):
            expected = bool(truth_table & (1 << value))
            assert _boolean_domain_holds(original, value) is expected
            assert _boolean_domain_holds(reduced, value) is expected
            assert _boolean_domain_holds(self_intersection, value) is expected
            assert not _boolean_domain_holds(disjoint_intersection, value)


def test_intersection_absorbs_only_after_contradictory_pairs_are_removed() -> None:
    main = _branch("main")
    dev = _branch("dev")
    main_restricted = _branch("main", extra=("github.ref", "dev", False))

    assert intersect_constraints((main, main_restricted), (main,)) == (main,)
    assert intersect_constraints((main, dev), (main, dev)) == (main, dev)
    assert not intersect_constraints((main,), (dev,))


def test_union_keeps_incomparable_overflow_and_unknown_conservative() -> None:
    alternatives = tuple(_branch(f"ref-{index}") for index in range(65))
    assert union_constraints((alternatives,)) == UNCONSTRAINED

    oversized = frozenset(("path", str(index), True) for index in range(65))
    assert union_constraints(((oversized,),)) == UNCONSTRAINED
    assert union_constraints(((_branch("main"),), UNCONSTRAINED)) == UNCONSTRAINED


def test_union_bounds_empty_domain_streams() -> None:
    pulled = 0

    def empty_domains():
        nonlocal pulled
        while True:
            pulled += 1
            yield ()

    assert union_constraints(empty_domains()) == UNCONSTRAINED
    assert pulled == 1025  # One lookahead detects the 1025th domain.
    assert union_constraints(((), ())) == ()


def test_union_bounds_duplicate_branch_streams() -> None:
    pulled = 0
    branch = _branch("main")

    def repeated_branches():
        nonlocal pulled
        while True:
            pulled += 1
            yield branch

    assert union_constraints((repeated_branches(),)) == UNCONSTRAINED
    assert pulled == 1025  # The 1025th branch is observed but not processed.


def test_union_widens_when_actual_subset_comparison_budget_is_exhausted(monkeypatch) -> None:
    monkeypatch.setattr(eventguard, "_MAX_CONSTRAINT_SUBSET_CHECKS", 1)
    assert union_constraints(((_branch("main"), _branch("dev")),)) == UNCONSTRAINED

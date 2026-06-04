"""Direct unit tests for the taint-facts fixed-point solver's guarantees.

The closure evaluator (:mod:`taintly.taint_facts.closure`) and its
relation store (:mod:`taintly.taint_facts.relations`) document three
internal correctness properties in their module docstrings.  Until now
they were exercised only INDIRECTLY, through the composer / CHAIN-GH
rule tests — no test asserted the solver's invariants by name.  A
refactor of the store or the loop could therefore break a guarantee the
whole rule layer relies on while every higher-level test stayed green.

This module closes that gap.  The three properties, each asserted
directly below:

  1. **Termination.** A monotone rule set always reaches a fixed point;
     cyclic taint (``A := env.B`` / ``B := env.A``) converges on the key
     set rather than looping.  A genuinely non-monotone rule trips the
     ``_MAX_PASSES`` backstop with a loud ``RuntimeError`` instead of
     hanging.
  2. **Shortest-proof retention.** On a key collision the lower-ranked
     derivation wins, where rank is hop-chain length — so the stored
     provenance is always the shortest proof, independent of insertion
     order.
  3. **Order-independence.** The saturated database (facts AND their
     retained provenance) is identical regardless of the order the
     rules fire.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass

import pytest

from taintly.taint_facts.closure import solve
from taintly.taint_facts.relations import Database


@dataclass(frozen=True)
class HopFact:
    """Minimal taint-style fact: keyed by name, ranked by hop count.

    Mirrors the real derived taint relations, whose ``fact_rank`` is the
    length of the provenance hop chain — so a shorter chain (a shorter
    proof) outranks a longer one for the same key.
    """

    name: str
    hops: tuple[str, ...]

    def fact_key(self):
        return self.name

    def fact_rank(self):
        return (len(self.hops),)


# ---------------------------------------------------------------------------
# Property 2 — shortest-proof retention (Database.add)
# ---------------------------------------------------------------------------


def test_lower_rank_wins_regardless_of_insertion_order():
    """The lower-ranked (shorter-proof) fact is retained whether it is
    inserted before or after its longer-proof competitor, and ``add``
    reports ``changed`` correctly in both directions."""
    short_proof = HopFact("A", ("src", "A"))  # rank (2,)
    long_proof = HopFact("A", ("src", "x", "y", "A"))  # rank (4,)

    # Long first, then short: short is strictly better -> it displaces.
    db = Database()
    assert db.add("taint", long_proof) is True  # new key
    assert db.add("taint", short_proof) is True  # strictly better -> change
    assert db.get("taint", "A") is short_proof

    # Short first, then long: long is not better -> rejected, short kept.
    db = Database()
    assert db.add("taint", short_proof) is True  # new key
    assert db.add("taint", long_proof) is False  # worse -> no change
    assert db.get("taint", "A") is short_proof


def test_equal_rank_does_not_displace():
    """A competing derivation of EQUAL rank is not strictly better, so
    the first-seen fact is retained and ``add`` reports no change — the
    store only ever moves to a strictly shorter proof."""
    first = HopFact("A", ("src", "A"))  # rank (2,)
    other = HopFact("A", ("alt", "A"))  # rank (2,), different payload
    db = Database()
    assert db.add("taint", first) is True
    assert db.add("taint", other) is False  # equal rank is not better
    assert db.get("taint", "A") is first


# ---------------------------------------------------------------------------
# Property 1 — termination (closure.solve)
# ---------------------------------------------------------------------------


def _cycle_rules():
    """Two rules forming a cycle: B is derived from A and A from B, each
    adding a hop.  Rank can only decrease, so the cycle converges."""

    def derive_b_from_a(db):
        a = db.get("taint", "A")
        if a is not None:
            yield ("taint", HopFact("B", a.hops + ("B",)))

    def derive_a_from_b(db):
        b = db.get("taint", "B")
        if b is not None:
            yield ("taint", HopFact("A", b.hops + ("A",)))

    return [derive_b_from_a, derive_a_from_b]


def test_cyclic_taint_converges():
    """``A := env.B`` / ``B := env.A`` reaches a fixed point: ``solve``
    returns, both keys are present, and each is retained at its shortest
    derivation (the longer way round the cycle never displaces it)."""
    db = Database()
    db.add("taint", HopFact("A", ("src", "A")))  # rank (2,)

    result = solve(db, _cycle_rules())  # must return, not loop / raise

    assert {f.fact_key() for f in result.all("taint")} == {"A", "B"}
    a = result.get("taint", "A")
    b = result.get("taint", "B")
    assert a is not None
    assert b is not None
    # A keeps its seed proof (2 hops); B is exactly one hop further out.
    # Re-deriving A around the cycle (4 hops) is worse and is rejected.
    assert a.fact_rank() == (2,)
    assert b.fact_rank() == (3,)


def test_nonconvergent_rule_trips_backstop():
    """A pathological non-monotone rule that invents a fresh key every
    pass never reaches a fixed point; the ``_MAX_PASSES`` guard turns
    the would-be infinite loop into an explicit ``RuntimeError`` rather
    than hanging CI."""
    counter = {"n": 0}

    def ever_growing(db):
        counter["n"] += 1
        yield ("taint", HopFact(f"k{counter['n']}", ("x",)))

    with pytest.raises(RuntimeError, match="did not converge"):
        solve(Database(), [ever_growing])


# ---------------------------------------------------------------------------
# Property 3 — order-independence of the saturated database
# ---------------------------------------------------------------------------


def _diamond_rules():
    """A diamond where key ``T`` is derivable two ways from seed ``S``:
    a short path (S -> T) and a long path (S -> A -> T).  Whichever
    order these fire, the shortest proof of ``T`` must be retained."""

    def s_to_a(db):
        s = db.get("r", "S")
        if s is not None:
            yield ("r", HopFact("A", s.hops + ("A",)))

    def a_to_t_long(db):
        a = db.get("r", "A")
        if a is not None:
            yield ("r", HopFact("T", a.hops + ("T",)))

    def s_to_t_short(db):
        s = db.get("r", "S")
        if s is not None:
            yield ("r", HopFact("T", s.hops + ("T",)))

    return [s_to_a, a_to_t_long, s_to_t_short]


def _saturate(rule_order):
    db = Database()
    db.add("r", HopFact("S", ("S",)))
    solve(db, rule_order)
    return {f.fact_key(): f.fact_rank() for f in db.all("r")}


def test_saturated_db_is_order_independent():
    """Running the same rule set in every possible order yields an
    identical saturated database — same keys AND same retained provenance
    ranks — and ``T`` is always kept at its SHORT proof (S -> T), never
    the longer S -> A -> T derivation."""
    rules = _diamond_rules()
    results = [_saturate(list(perm)) for perm in itertools.permutations(rules)]

    baseline = results[0]
    for other in results[1:]:
        assert other == baseline

    assert baseline["S"] == (1,)
    assert baseline["A"] == (2,)
    assert baseline["T"] == (2,)  # short proof S -> T, not the 3-hop path

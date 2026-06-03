"""Naive fixed-point evaluator for the taint facts model.

A *rule* is any callable that reads the current :class:`Database` and
yields ``(relation_name, fact)`` pairs to assert.  :func:`solve` runs
the whole rule set repeatedly until a full pass asserts nothing new —
i.e. the database has reached its least fixed point.

Naive evaluation (re-run every rule each pass) is deliberate: CI
files are small and bounded, so the cost is irrelevant and semi-naive
bookkeeping would only add surface area.

Termination.  Two monotone quantities bound the loop:

* the set of ``(relation, fact_key)`` pairs only ever grows, over a
  finite domain (keys are built from the file's jobs / steps /
  identifiers); and
* for a fixed key, the stored fact's ``fact_rank`` only ever
  decreases, along a well-founded order (hop-chain length ≥ 0).

A pass that adds no key and improves no rank makes no change, so the
loop exits.  Cyclic taint (``A := env.B`` / ``B := env.A``) is fine —
it converges on the key set and then stops.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from .relations import Database, Fact

Rule = Callable[[Database], Iterable[tuple[str, Fact]]]

# A generous upper bound on closure passes.  The loop terminates on
# its own (see module docstring); this only stops a hypothetical
# pathological input from spinning, mirroring the explicit cap the
# old hand-rolled cross-job loop carried.
_MAX_PASSES = 1000


def solve(db: Database, rules: list[Rule]) -> Database:
    """Saturate ``db`` under ``rules`` and return it.

    ``db`` is mutated in place (and also returned for convenience).
    Seed any extensional facts before calling.
    """
    for _ in range(_MAX_PASSES):
        changed = False
        for rule in rules:
            for relation, fact in rule(db):
                if db.add(relation, fact):
                    changed = True
        if not changed:
            return db
    raise RuntimeError(
        "taint closure did not converge within "
        f"{_MAX_PASSES} passes — this should be impossible for a "
        "monotone rule set; please file a bug with the input file"
    )

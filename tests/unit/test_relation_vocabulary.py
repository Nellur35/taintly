"""Teeth-test for the relation-vocabulary lint.

The lint (``scripts/check_relation_vocabulary.py``) exists to catch a relation
consumed by a closure rule but produced by nothing — a silent dead rule. These
tests prove it actually has teeth (flags an orphan / a bare-string typo, doesn't
false-positive on yield-produced relations) and guard that the shipped engine
stays clean.
"""

from __future__ import annotations

from scripts import check_relation_vocabulary as gate


def test_clean_module_has_no_orphans():
    src = (
        '_R_FOO = "foo"\n'
        "def rule(db):\n"
        "    for x in db.all(_R_FOO):\n"
        "        yield (_R_FOO, x)\n"
        "def build(db):\n"
        "    db.add(_R_FOO, 1)\n"
    )
    orphans, produced, consumed = gate.check_source(src)
    assert orphans == {}
    assert "foo" in produced
    assert "foo" in consumed


def test_orphan_consumed_relation_is_flagged():
    # _R_FOO is consumed but only _R_BAR is produced -> orphan.
    src = (
        '_R_FOO = "foo"\n'
        '_R_BAR = "bar"\n'
        "def rule(db):\n"
        "    return db.all(_R_FOO)\n"
        "def build(db):\n"
        "    db.add(_R_BAR, 1)\n"
    )
    orphans, _produced, _consumed = gate.check_source(src)
    assert "foo" in orphans
    assert "bar" not in orphans


def test_bare_string_typo_is_flagged():
    # The canonical bug: consume "taint_env", produce "tainted_env".
    src = (
        "def rule(db):\n"
        '    return db.all("taint_env")\n'
        "def build(db):\n"
        '    db.add("tainted_env", 1)\n'
    )
    orphans, _produced, _consumed = gate.check_source(src)
    assert "taint_env" in orphans


def test_yield_tuple_counts_as_produced():
    # A relation produced only via `yield (rel, fact)` must NOT be a false orphan.
    src = (
        '_R_X = "x"\n'
        "def rule(db):\n"
        "    if db.has(_R_X, 1):\n"
        "        yield (_R_X, 2)\n"
    )
    orphans, produced, _consumed = gate.check_source(src)
    assert orphans == {}
    assert "x" in produced


def test_real_closure_modules_are_clean():
    # Regression guard: the shipped engine keeps every consumed relation produced.
    assert gate.main() == 0


# --- Inverse direction (P3.3): produced but never consumed = dead extraction ---


def test_dead_extraction_relation_is_reported():
    # _R_LIVE is produced AND consumed; _R_DEAD is only produced -> dead.
    src = (
        '_R_LIVE = "live"\n'
        '_R_DEAD = "dead"\n'
        "def rule(db):\n"
        "    return db.all(_R_LIVE)\n"
        "def build(db):\n"
        "    db.add(_R_LIVE, 1)\n"
        "    db.add(_R_DEAD, 2)\n"  # produced, nothing ever reads it
    )
    orphans, produced, consumed = gate.check_source(src)
    # The orphan (consumed-unproduced) direction stays clean...
    assert orphans == {}
    # ...and the inverse direction flags the dead extraction.
    dead = gate.dead_extractions(produced, consumed)
    assert dead == {"dead"}
    assert "live" not in dead


def test_no_dead_extraction_when_all_produced_are_consumed():
    src = (
        '_R_X = "x"\n'
        "def rule(db):\n"
        "    if db.has(_R_X, 1):\n"
        "        return None\n"
        "def build(db):\n"
        "    db.add(_R_X, 1)\n"
    )
    _orphans, produced, consumed = gate.check_source(src)
    assert gate.dead_extractions(produced, consumed) == set()


def test_dead_extraction_is_advisory_not_a_build_failure():
    # Dead extractions never fail the build; the exit code is governed solely by
    # the consumed-⊆-produced direction. The public closure pack ships clean on
    # both directions, so the gate must still exit 0.
    assert gate.main() == 0


def test_public_dead_extraction_allowlist_is_empty():
    # Public-repo divergence guard: the only upstream allowlist entry is for
    # ``taintly/cross_workflow_facts.py`` (``call_edge``), a closure module the
    # public repo does not ship. Listing an entry for an absent module would
    # emit a spurious "stale — prune it" NOTE every run, so the allowlist is
    # intentionally empty here. If a public closure module ever needs an entry,
    # this guard documents why it was empty before.
    assert gate._KNOWN_DEAD_EXTRACTIONS == {}

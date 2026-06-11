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

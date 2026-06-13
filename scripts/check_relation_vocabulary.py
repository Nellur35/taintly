#!/usr/bin/env python
"""CI lint: every relation a closure rule CONSUMES must be PRODUCED.

The fact engine (``taintly.taint_facts``) is a small Datalog: rules read relations
via ``db.all/get/has(<relation>)`` and assert facts via ``db.add(<relation>, …)``
or by yielding ``(<relation>, fact)`` tuples for the closure to add.  A relation
that is *consumed but never produced* is a silent dead rule — it can never fire,
there is no error, and it presents as zero findings.  A relation-name typo (a
bare-string mismatch, or a constant whose value drifted from its producer) is the
canonical way that happens, and nothing else in the suite catches it.

This statically checks, per closure module, that

    { relations consumed via db.all/get/has }  ⊆  { relations produced via db.add or yield }

resolving relations through module-level ``NAME = "literal"`` constants (the
``_R_*`` convention) and bare string literals.  Exit non-zero — naming the orphan
relation and the line that consumes it — on any violation.

It ALSO reports the inverse: a relation *produced but never consumed* (a dead
extraction).  Unlike a consumed-but-unproduced orphan — which is a silent dead
rule and a hard failure — a produced-unconsumed relation is not a correctness
bug.  It is wasted ``solve()`` work (facts asserted that nothing joins on) and is
often intentional or transitional: a documented EDB relation modelling part of
the schema before the joining rule lands.  So dead extractions are a REPORTED
WARNING, not a build failure; the exit code is governed solely by the
consumed-⊆-produced direction.  Known-intentional dead extractions are recorded
in ``_KNOWN_DEAD_EXTRACTIONS`` so the warning highlights only NEW ones; a stale
allowlist entry (now consumed) is surfaced for pruning.

Usage:  python scripts/check_relation_vocabulary.py
"""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

# Modules whose rules run on the in-house closure (db = Database()).  Each builds
# and solves its own Database, so the consumed-subset-of-produced check is
# module-scoped.
_MODULES = [
    "taintly/taint.py",
    "taintly/gitlab_taint.py",
    "taintly/attack_path.py",
    "taintly/combination_facts.py",
    "taintly/cross_workflow_facts.py",
    "taintly/permissions_facts.py",
    "taintly/validation_facts.py",
]

_CONSUME_METHODS = {"all", "get", "has"}
_PRODUCE_METHODS = {"add"}
# The conventional name the Database instance is bound to in every closure module.
_DB_RECEIVERS = {"db"}

# (module_path, relation) -> rationale.  A relation produced but never consumed
# is wasted solve() work, but some are deliberate: an EDB relation that models
# part of the relational schema (and is documented as such) before the rule that
# joins on it lands.  Recording it here keeps the dead-extraction WARNING signal
# clean — only NEW, unexplained dead extractions are flagged for review.  Remove
# an entry once the relation is consumed (the gate will tell you it's stale).
#
# Public-repo note: the only allowlisted entry upstream is for
# ``taintly/cross_workflow_facts.py`` (``call_edge``), a closure module the
# public repo does not ship.  Listing an entry for an absent module would emit a
# spurious "stale — prune it" NOTE on every run (the module is skipped, so its
# dead extraction is never observed), so the allowlist is intentionally empty
# here.  Add an entry only for a module that is actually present in this repo.
_KNOWN_DEAD_EXTRACTIONS: dict[tuple[str, str], str] = {}


def _string_consts(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = "literal"`` / ``NAME: str = "literal"`` -> {name: value}."""
    out: dict[str, str] = {}
    for node in tree.body:
        target = value = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        if (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        ):
            out[target.id] = value.value
    return out


def _resolve(arg: ast.expr, consts: dict[str, str]) -> str | None:
    """A relation argument -> its string value (literal or via a known constant)."""
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.Name):
        return consts.get(arg.id)
    return None


def check_source(src: str) -> tuple[dict[str, int], set[str], dict[str, int]]:
    """Analyse one module's source. Returns (orphans, produced, consumed) where
    ``orphans`` maps a consumed-but-never-produced relation to the line that
    consumes it."""
    tree = ast.parse(src)
    consts = _string_consts(tree)
    consumed: dict[str, int] = {}
    produced: set[str] = set()
    for node in ast.walk(tree):
        # db.<method>(<relation>, ...)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in _DB_RECEIVERS
            and node.args
        ):
            rel = _resolve(node.args[0], consts)
            if rel is None:
                continue
            if node.func.attr in _CONSUME_METHODS:
                consumed.setdefault(rel, node.lineno)
            elif node.func.attr in _PRODUCE_METHODS:
                produced.add(rel)
        # yield (<relation>, fact)  /  yield <relation>, fact
        if isinstance(node, ast.Yield) and isinstance(node.value, ast.Tuple) and node.value.elts:
            rel = _resolve(node.value.elts[0], consts)
            if rel is not None:
                produced.add(rel)
    orphans = {r: ln for r, ln in consumed.items() if r not in produced}
    return orphans, produced, consumed


def check_module(path: str) -> tuple[dict[str, int], set[str], dict[str, int]]:
    return check_source((_ROOT / path).read_text(encoding="utf-8"))


def dead_extractions(produced: set[str], consumed: dict[str, int]) -> set[str]:
    """Relations PRODUCED (db.add / yield) but never CONSUMED (db.all/get/has) —
    a dead extraction: facts asserted that no rule joins on, wasting solve()
    cycles.  The inverse of the orphan (consumed-but-unproduced) check."""
    return produced - set(consumed)


def main() -> int:
    violations = 0
    # (module_path, relation) for every dead extraction found this run.
    found_dead: list[tuple[str, str]] = []
    print("relation-vocabulary lint (consumed ⊆ produced, per closure module):\n")
    for path in _MODULES:
        # The public repo ships a curated subset of the closure modules; skip any
        # that aren't present so the same lint runs in both repos.
        if not (_ROOT / path).exists():
            print(f"  {path:38s} (absent — skipped)")
            continue
        orphans, produced, consumed = check_module(path)
        dead = dead_extractions(produced, consumed)
        flag = "OK" if not orphans else "ORPHAN"
        if dead:
            flag = f"{flag} (+{len(dead)} dead)"
        print(f"  {path:38s} consumed={len(consumed):2d} produced={len(produced):2d}  {flag}")
        for rel, ln in sorted(orphans.items()):
            print(f"      consumed but never produced: {rel!r} (line {ln})")
            violations += 1
        for rel in sorted(dead):
            found_dead.append((path, rel))

    # Inverse direction — a REPORTED WARNING, never a hard failure (the exit
    # code is governed solely by the consumed-⊆-produced orphans above). A
    # produced-unconsumed relation is wasted solve() work, often intentional
    # or transitional, so we surface it for review rather than block the build.
    new_dead = [(p, r) for (p, r) in found_dead if (p, r) not in _KNOWN_DEAD_EXTRACTIONS]
    known_dead = [(p, r) for (p, r) in found_dead if (p, r) in _KNOWN_DEAD_EXTRACTIONS]
    stale_allowlist = sorted(set(_KNOWN_DEAD_EXTRACTIONS) - set(found_dead))
    if new_dead or known_dead or stale_allowlist:
        print("\ndead-extraction report (produced but never consumed — advisory):")
        for path, rel in new_dead:
            print(f"  WARNING {path}: {rel!r} produced but never consumed (new — review).")
        for path, rel in known_dead:
            print(f"  known   {path}: {rel!r} produced but never consumed (allowlisted).")
        for path, rel in stale_allowlist:
            print(
                f"  NOTE    {path}: {rel!r} is now consumed — "
                "prune it from _KNOWN_DEAD_EXTRACTIONS."
            )
        if new_dead:
            print(
                f"\n  {len(new_dead)} NEW dead extraction(s) — either consume the "
                "relation, drop the producer, or (if intentional/transitional) add "
                "it to _KNOWN_DEAD_EXTRACTIONS with a rationale. Advisory only."
            )

    if violations:
        print(f"\nFAIL: {violations} relation(s) consumed but never produced — a silent dead rule.")
        return 1
    print("\nOK: every consumed relation is produced within its module.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

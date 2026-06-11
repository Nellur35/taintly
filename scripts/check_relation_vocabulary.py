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

Usage:  python scripts/check_relation_vocabulary.py
"""
from __future__ import annotations

import ast
import sys
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


def main() -> int:
    violations = 0
    print("relation-vocabulary lint (consumed ⊆ produced, per closure module):\n")
    for path in _MODULES:
        # The public repo ships a curated subset of the closure modules; skip any
        # that aren't present so the same lint runs in both repos.
        if not (_ROOT / path).exists():
            print(f"  {path:38s} (absent — skipped)")
            continue
        orphans, produced, consumed = check_module(path)
        flag = "OK" if not orphans else "ORPHAN"
        print(f"  {path:38s} consumed={len(consumed):2d} produced={len(produced):2d}  {flag}")
        for rel, ln in sorted(orphans.items()):
            print(f"      consumed but never produced: {rel!r} (line {ln})")
            violations += 1
    if violations:
        print(f"\nFAIL: {violations} relation(s) consumed but never produced — a silent dead rule.")
        return 1
    print("\nOK: every consumed relation is produced within its module.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

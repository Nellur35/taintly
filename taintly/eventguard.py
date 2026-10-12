"""Conservative event-specific truth proofs over the existing Actions AST.

Only literal booleans, event-name comparisons and supplied path equalities are known. Runtime values,
unsupported operations and malformed input stay unknown. This is a truth
abstraction for reachability, not an evaluator for arbitrary Actions values.
"""

import json
from collections.abc import Mapping

from taintly.parsers.gha_expr import (
    Binary,
    Call,
    ExprSyntaxError,
    Lit,
    Unary,
    canonical_path,
    parse,
)


def event_guard_verdict(
    guard: str | None,
    event: str,
    *,
    path_equalities: Mapping[frozenset[str], bool] | None = None,
    path_string_exclusions: Mapping[str, frozenset[str]] | None = None,
) -> bool | None:
    """Return true/false/unknown for one declared event and supplied facts.

    ``path_string_exclusions`` is opt-in: canonical paths map to lowercase
    ASCII strings proved impossible in the caller's specific threat profile.
    It is not a global assumption about workflow inputs or triggering actors.
    """
    if guard is None:
        return True
    source = guard.strip()
    if source.startswith("${{") and source.endswith("}}"):
        source = source[3:-2].strip()
    if not source or len(source) > 8192:
        return None
    try:
        return _truth(parse(source), event, 64, path_equalities or {}, path_string_exclusions or {})
    except (ExprSyntaxError, RecursionError):
        return None


def _truth(
    node: object,
    event: str,
    budget: int,
    equalities: Mapping[frozenset[str], bool],
    exclusions: Mapping[str, frozenset[str]],
) -> bool | None:
    if budget <= 0:
        return None
    if isinstance(node, Lit) and node.kind == "bool":
        return bool(node.value)
    if isinstance(node, Unary) and node.op == "!":
        value = _truth(node.operand, event, budget - 1, equalities, exclusions)
        return None if value is None else not value
    # Only fixed arrays of strings, never substring contains or runtime JSON.
    if isinstance(node, Call) and node.name.lower() == "contains" and len(node.args) == 2:
        array, subject = node.args
        excluded = exclusions.get(canonical_path(subject) or "", frozenset())
        if (
            isinstance(array, Call)
            and array.name.lower() == "fromjson"
            and len(array.args) == 1
            and isinstance(array.args[0], Lit)
            and array.args[0].kind == "string"
            and isinstance(array.args[0].value, str)
        ):
            try:
                values = json.loads(array.args[0].value)
            except (ValueError, RecursionError):
                return None
            if (
                excluded
                and isinstance(values, list)
                and all(
                    isinstance(value, str) and value.isascii() and value.lower() in excluded
                    for value in values
                )
            ):
                return False
        return None
    if not isinstance(node, Binary):
        return None
    if node.op in {"&&", "||"}:
        left = _truth(node.left, event, budget - 1, equalities, exclusions)
        right = _truth(node.right, event, budget - 1, equalities, exclusions)
        if node.op == "&&":
            if left is False or right is False:
                return False
            return True if left is True and right is True else None
        if left is True or right is True:
            return True
        return False if left is False and right is False else None
    if node.op in {"==", "!="}:
        paths = (canonical_path(node.left), canonical_path(node.right))
        if all(paths):
            equal = equalities.get(frozenset(p for p in paths if p is not None))
            if equal is not None:
                return equal if node.op == "==" else not equal
        for subject, literal in ((node.left, node.right), (node.right, node.left)):
            excluded = exclusions.get(canonical_path(subject) or "", frozenset())
            if (
                isinstance(literal, Lit)
                and literal.kind == "string"
                and isinstance(literal.value, str)
                and literal.value.isascii()
                and literal.value.lower() in excluded
            ):
                return node.op == "!="
            if (
                canonical_path(subject) == "github.event_name"
                and isinstance(literal, Lit)
                and literal.kind == "string"
                and isinstance(literal.value, str)
            ):
                equal = event.casefold() == literal.value.casefold()
                return equal if node.op == "==" else not equal
    return None

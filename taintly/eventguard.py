"""Conservative event-specific truth proofs over the existing Actions AST.

Only literal booleans and event-name comparisons are known. Runtime values,
unsupported operations and malformed input stay unknown. This is a truth
abstraction for reachability, not an evaluator for arbitrary Actions values.
"""

from taintly.parsers.gha_expr import (
    Binary,
    ExprSyntaxError,
    Lit,
    Unary,
    canonical_path,
    parse,
)


def event_guard_verdict(guard: str | None, event: str) -> bool | None:
    """Return true/false/unknown for a guard on one declared workflow event."""
    if guard is None:
        return True
    source = guard.strip()
    if source.startswith("${{") and source.endswith("}}"):
        source = source[3:-2].strip()
    if not source or len(source) > 8192:
        return None
    try:
        return _truth(parse(source), event, 64)
    except (ExprSyntaxError, RecursionError):
        return None


def _truth(node: object, event: str, budget: int) -> bool | None:
    if budget <= 0:
        return None
    if isinstance(node, Lit) and node.kind == "bool":
        return bool(node.value)
    if isinstance(node, Unary) and node.op == "!":
        value = _truth(node.operand, event, budget - 1)
        return None if value is None else not value
    if not isinstance(node, Binary):
        return None
    if node.op in {"&&", "||"}:
        left = _truth(node.left, event, budget - 1)
        right = _truth(node.right, event, budget - 1)
        if node.op == "&&":
            if left is False or right is False:
                return False
            return True if left is True and right is True else None
        if left is True or right is True:
            return True
        return False if left is False and right is False else None
    if node.op in {"==", "!="}:
        for subject, literal in ((node.left, node.right), (node.right, node.left)):
            if (
                canonical_path(subject) == "github.event_name"
                and isinstance(literal, Lit)
                and literal.kind == "string"
                and isinstance(literal.value, str)
            ):
                equal = event.casefold() == literal.value.casefold()
                return equal if node.op == "==" else not equal
    return None

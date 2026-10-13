"""Conservative event-specific truth proofs over the existing Actions AST.

The truth verdict admits literal booleans, event-name comparisons and supplied
path facts. A separate bounded constraint domain also correlates direct ASCII
string comparisons on one invocation's ref. Runtime values, unsupported
operations and malformed input stay unknown. Neither is a general evaluator.
"""

import json
from collections.abc import Iterable, Mapping

from taintly.parsers.gha_expr import (
    Binary,
    Call,
    Deref,
    ExprSyntaxError,
    Index,
    Lit,
    Unary,
    Var,
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


# A disjunction of conjunctions. Empty outer tuple is impossible; an empty
# conjunction is unconstrained. These are may-satisfy constraints, not proofs
# of execution, input integrity or effective authority.
GuardConstraints = tuple[frozenset[tuple[str, str, bool]], ...]
UNCONSTRAINED: GuardConstraints = (frozenset(),)
_MAX_CONSTRAINT_BRANCHES = 64
_MAX_CONSTRAINT_JOINS = 1024
_MAX_CONSTRAINT_DOMAINS = 1024
_MAX_CONSTRAINT_PROCESSED_BRANCHES = 1024
_MAX_CONSTRAINT_SUBSET_CHECKS = 2 * _MAX_CONSTRAINT_BRANCHES * _MAX_CONSTRAINT_PROCESSED_BRANCHES


def _insert_constraint_branch(
    branches: list[frozenset[tuple[str, str, bool]]],
    branch: frozenset[tuple[str, str, bool]],
    subset_checks: list[int],
) -> bool:
    """Insert into a bounded antichain using syntactic set inclusion only."""
    remove_indices: list[int] = []
    for index, existing in enumerate(branches):
        if subset_checks[0] >= _MAX_CONSTRAINT_SUBSET_CHECKS:
            return False
        subset_checks[0] += 1
        if existing <= branch:
            return True
        if subset_checks[0] >= _MAX_CONSTRAINT_SUBSET_CHECKS:
            return False
        subset_checks[0] += 1
        if branch < existing:
            remove_indices.append(index)

    if remove_indices:
        insertion_index = remove_indices[0]
        for index in reversed(remove_indices):
            del branches[index]
        branches.insert(insertion_index, branch)
    else:
        branches.append(branch)
    return True


def union_constraints(domains: Iterable[GuardConstraints]) -> GuardConstraints:
    """Alternative owners are OR, including any unknown alternative."""
    out: list[frozenset[tuple[str, str, bool]]] = []
    subset_checks = [0]
    processed_branches = 0
    for processed_domains, domain in enumerate(domains):
        if processed_domains >= _MAX_CONSTRAINT_DOMAINS:
            return UNCONSTRAINED
        for branch in domain:
            if processed_branches >= _MAX_CONSTRAINT_PROCESSED_BRANCHES:
                return UNCONSTRAINED
            processed_branches += 1
            if not branch:
                return UNCONSTRAINED
            if len(branch) > 64:
                return UNCONSTRAINED
            if not _insert_constraint_branch(out, branch, subset_checks):
                return UNCONSTRAINED
            if len(out) > _MAX_CONSTRAINT_BRANCHES:
                return UNCONSTRAINED
    return tuple(out)


def intersect_constraints(left: GuardConstraints, right: GuardConstraints) -> GuardConstraints:
    """Conjoin constraints; resource exhaustion widens to unknown."""
    out: list[frozenset[tuple[str, str, bool]]] = []
    subset_checks = [0]
    joins = 0
    for first in left:
        for second in right:
            joins += 1
            if joins > _MAX_CONSTRAINT_JOINS:
                return UNCONSTRAINED
            branch = first | second
            if len(branch) > 64:
                return UNCONSTRAINED
            equals: dict[str, str] = {}
            possible = True
            for path, value, equal in branch:
                if equal:
                    if path in equals and equals[path] != value:
                        possible = False
                        break
                    equals[path] = value
            if possible and any(
                not equal and equals.get(path) == value for path, value, equal in branch
            ):
                possible = False
            if possible:
                if not _insert_constraint_branch(out, branch, subset_checks):
                    return UNCONSTRAINED
                if len(out) > _MAX_CONSTRAINT_BRANCHES:
                    return UNCONSTRAINED
    return tuple(out)


def guard_constraints(guards: Iterable[str | None], event: str) -> GuardConstraints:
    """Possible joint guards on one invocation's ref and event name.

    Only ASCII string comparisons on ``github.ref`` and the PR-only
    ``github.base_ref``/``github.head_ref`` fields are correlated. Other
    invocation fields remain unknown, including step/job-varying env and
    outputs.
    Negation is pushed into the expression, never applied to a widened set.
    """
    result = UNCONSTRAINED
    for count, guard in enumerate(guards):
        if count >= 16:
            return UNCONSTRAINED
        if guard is None:
            continue
        source = guard.strip()
        if source.startswith("${{") and source.endswith("}}"):
            source = source[3:-2].strip()
        if not source or len(source) > 8192:
            domain = UNCONSTRAINED
        else:
            try:
                domain = _possible_constraints(parse(source), event, True, [64])
            except (ExprSyntaxError, RecursionError):
                domain = UNCONSTRAINED
        result = intersect_constraints(result, domain)
    return result


def _possible_constraints(
    node: object, event: str, positive: bool, budget: list[int]
) -> GuardConstraints:
    budget[0] -= 1
    if budget[0] < 0:
        return UNCONSTRAINED
    if isinstance(node, Lit) and node.kind == "bool":
        return UNCONSTRAINED if bool(node.value) is positive else ()
    if isinstance(node, Unary) and node.op == "!":
        return _possible_constraints(node.operand, event, not positive, budget)
    if not isinstance(node, Binary):
        return UNCONSTRAINED
    if node.op in {"&&", "||"}:
        left = _possible_constraints(node.left, event, positive, budget)
        right = _possible_constraints(node.right, event, positive, budget)
        if (node.op == "&&") is positive:
            return intersect_constraints(left, right)
        return union_constraints((left, right))
    if node.op in {"==", "!="}:
        for subject, literal in ((node.left, node.right), (node.right, node.left)):
            if not (
                isinstance(literal, Lit)
                and literal.kind == "string"
                and isinstance(literal.value, str)
            ):
                continue
            path = _direct_invocation_path(subject)
            equal = (node.op == "==") is positive
            if path == "github.event_name":
                matches = event.casefold() == literal.value.casefold()
                return UNCONSTRAINED if matches is equal else ()
            pr_ref_context = path in {"github.base_ref", "github.head_ref"} and (
                event.casefold() in {"pull_request", "pull_request_target"}
            )
            if path is not None and (path == "github.ref" or pr_ref_context):
                if literal.value.isascii():
                    return (frozenset({(path, literal.value.lower(), equal)}),)
    return UNCONSTRAINED


def _direct_invocation_path(node: object) -> str | None:
    """Admit only a direct provider field, never a transformed call spine."""
    if isinstance(node, Deref) and isinstance(node.recv, Var):
        return f"{node.recv.name}.{node.prop}".lower()
    if (
        isinstance(node, Index)
        and isinstance(node.recv, Var)
        and isinstance(node.index, Lit)
        and node.index.kind == "string"
        and isinstance(node.index.value, str)
    ):
        return f"{node.recv.name}.{node.index.value}".lower()
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

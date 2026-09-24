"""Shared executable-sink model for GitHub workflow inputs.

Both workflow-dispatch inputs and reusable-workflow inputs become dangerous
when Actions substitutes them into code.  Keep that classification in one
place so rules do not disagree about which YAML fields execute text.
"""

from __future__ import annotations

import re
from pathlib import Path

from taintly.parsers.gha_expr import (
    ExprSyntaxError,
    iter_expression_bodies,
    result_provenance_paths,
)
from taintly.parsers.structural import EventKind, walk_workflow
from taintly.workflow_aware_pattern import PredicateContext

_INPUTS_REF_FALLBACK_RE = re.compile(
    r"\b(?P<namespace>github\s*\.\s*event\s*\.\s*inputs|inputs)\s*"
    r"(?:\.\s*(?P<dot>[a-zA-Z_][a-zA-Z0-9_-]*)|"
    r"\[\s*['\"](?P<bracket>[^'\"]+)['\"]\s*\])",
    re.IGNORECASE,
)

_SAFE_INPUT_TYPES = frozenset({"boolean", "choice", "environment", "number"})

# Action inputs whose values are interpreted as shell or script source.  This
# is deliberately action-specific: a generic ``with.command`` or
# ``with.script`` key is data unless the action's contract says it executes it.
SHELL_EXECUTING_ACTION_SLOTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("actions/github-script", "script"),
        ("nick-fields/retry", "command"),
        ("nick-fields/retry", "new_command"),
        ("nick-fields/retry", "on_retry_command"),
        ("azure/cli", "inlinescript"),
        ("azure/powershell", "inlinescript"),
        ("appleboy/ssh-action", "script"),
        ("garygrossgarten/github-action-ssh", "command"),
    }
)


def _action_name(uses_value: str) -> str:
    if not uses_value:
        return ""
    head = uses_value.split("@", 1)[0].strip()
    parts = head.split("/")
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}".lower()
    return head.lower()


def _declared_input_types(
    ctx: PredicateContext,
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Return lower-cased dispatch and reusable-workflow input type maps."""
    by_namespace: dict[str, dict[str, set[str]]] = {
        "workflow_dispatch": {},
        "workflow_call": {},
    }
    for leaf in ctx.leaves:
        leaf_path = leaf.path
        if (
            len(leaf_path) == 5
            and leaf_path[0] == "on"
            and leaf_path[1] in by_namespace
            and leaf_path[2] == "inputs"
            and isinstance(leaf_path[3], str)
            and leaf_path[4] == "type"
            and leaf.value
        ):
            by_namespace[leaf_path[1]].setdefault(leaf_path[3].lower(), set()).add(
                leaf.value.lower()
            )
    return by_namespace["workflow_dispatch"], by_namespace["workflow_call"]


def _input_source_is_safe(
    source: str,
    dispatch_types: dict[str, set[str]],
    call_types: dict[str, set[str]],
) -> bool:
    """Whether every applicable declaration constrains this input's bytes."""
    source = source.lower()
    event_prefix = "github.event.inputs."
    if source.startswith(event_prefix):
        name = source[len(event_prefix) :].split(".", 1)[0]
        types = dispatch_types.get(name, set())
    elif source.startswith("inputs."):
        name = source[len("inputs.") :].split(".", 1)[0]
        types = dispatch_types.get(name, set()) | call_types.get(name, set())
    else:
        return False
    return bool(types) and types <= _SAFE_INPUT_TYPES


def _input_sources(value: str) -> list[str]:
    sources: list[str] = []
    for body in iter_expression_bodies(value or ""):
        try:
            sources.extend(result_provenance_paths(body))
        except ExprSyntaxError:
            for match in _INPUTS_REF_FALLBACK_RE.finditer(body):
                namespace = match.group("namespace").replace(" ", "").lower()
                name = match.group("dot") or match.group("bracket")
                sources.append(f"{namespace}.{name}")
    return [
        source
        for source in sources
        if source in {"inputs", "github.event.inputs"}
        or source.startswith("inputs.")
        or source.startswith("github.event.inputs.")
    ]


def has_data_bearing_input(value: str, ctx: PredicateContext) -> bool:
    """Return true when executable text contains an unconstrained input."""
    input_sources = _input_sources(value)
    if not input_sources:
        return False
    if any(source in {"inputs", "github.event.inputs"} for source in input_sources):
        return True

    dispatch_types, call_types = _declared_input_types(ctx)
    return any(
        not _input_source_is_safe(source, dispatch_types, call_types) for source in input_sources
    )


def _references_input(value: str, input_name: str) -> bool:
    expected = f"inputs.{input_name}".lower()
    return any(
        source.lower() in {"inputs", expected} or source.lower().startswith(expected + ".")
        for source in _input_sources(value)
    )


def _is_step_execution_path(path: tuple[object, ...], ctx: PredicateContext) -> bool:
    if (
        len(path) >= 5
        and path[0] == "jobs"
        and path[2] == "steps"
        and isinstance(path[3], int)
        and path[-1] == "run"
    ):
        return True
    if (
        len(path) == 6
        and path[0] == "jobs"
        and path[2] == "steps"
        and isinstance(path[3], int)
        and path[4] == "with"
        and isinstance(path[5], str)
    ):
        slot = (_action_name(ctx.step_uses(path) or ""), path[5].lower())
        return slot in SHELL_EXECUTING_ACTION_SLOTS
    return False


def _resolve_local_workflow(
    ctx: PredicateContext, job_id: object, visited: frozenset[Path]
) -> Path | None:
    if not isinstance(job_id, str):
        return None
    uses = ctx.get_value(("jobs", job_id, "uses")) or ""
    if not uses.startswith("./.github/workflows/"):
        return None
    root = ctx.repo_root()
    if root is None:
        return None
    try:
        root = root.resolve()
        target = (root / uses[2:]).resolve()
        if not target.is_relative_to(root) or target in visited:
            return None
        if not target.is_file() or target.stat().st_size > 2 * 1024 * 1024:
            return None
    except (OSError, ValueError):
        return None
    return target


def _read_workflow_context(path: Path) -> PredicateContext | None:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None
    leaves = []
    for event in walk_workflow(str(path), content=content, recover=True):
        if event.kind == EventKind.CUTOFF:
            return None
        if event.kind == EventKind.LEAF_SCALAR:
            leaves.append(event)
    return PredicateContext(tuple(leaves), filepath=str(path))


def _callee_input_reaches_execution(
    target: Path,
    input_name: str,
    visited: frozenset[Path],
    depth: int,
) -> bool:
    """Follow a named input through local reusable workflows, with hard caps."""
    if depth > 3:
        return False
    callee = _read_workflow_context(target)
    if callee is None or not callee.is_reusable_workflow():
        return False
    next_visited = visited | {target}
    for leaf in callee.leaves:
        if not _references_input(leaf.value or "", input_name):
            continue
        if _is_step_execution_path(leaf.path, callee) and has_data_bearing_input(
            leaf.value or "", callee
        ):
            return True
        path = leaf.path
        if (
            len(path) == 4
            and path[0] == "jobs"
            and path[2] == "with"
            and isinstance(path[3], str)
            and has_data_bearing_input(leaf.value or "", callee)
        ):
            nested = _resolve_local_workflow(callee, path[1], next_visited)
            if nested and _callee_input_reaches_execution(nested, path[3], next_visited, depth + 1):
                return True
    return False


def is_workflow_input_executable_sink(
    value: str,
    _value_kind: str,
    path: tuple[object, ...],
    ctx: PredicateContext,
) -> bool:
    """Classify direct shell bodies and known action-owned code slots."""
    meaningful_lines = [line.lstrip() for line in value.splitlines() if line.strip()]
    if meaningful_lines and all(line.startswith("#") for line in meaningful_lines):
        return False
    if _is_step_execution_path(path, ctx):
        return has_data_bearing_input(value, ctx)
    if (
        len(path) == 4
        and path[0] == "jobs"
        and path[2] == "with"
        and isinstance(path[3], str)
        and has_data_bearing_input(value, ctx)
    ):
        target = _resolve_local_workflow(ctx, path[1], frozenset())
        if target is None:
            return False
        cache_key = (str(target), path[3].lower())
        if cache_key not in ctx._workflow_input_sink_cache:
            ctx._workflow_input_sink_cache[cache_key] = _callee_input_reaches_execution(
                target, path[3], frozenset(), depth=1
            )
        return ctx._workflow_input_sink_cache[cache_key]
    return False

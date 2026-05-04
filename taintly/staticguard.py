"""Conservative static guard evaluation for GitHub Actions workflows.

This module intentionally evaluates only expressions whose result can be
known from literals or explicit repository identity. Anything that might
depend on runtime event payloads, matrix expansion, secrets, inputs, or
functions returns RUNTIME.
"""

from __future__ import annotations

import re
import subprocess
from enum import Enum
from typing import Any, NamedTuple


class Verdict(Enum):
    STATIC_TRUE = "static_true"
    STATIC_FALSE = "static_false"
    RUNTIME = "runtime"


class WorkflowContext(NamedTuple):
    repository: str | None = None
    repository_owner: str | None = None


_BOOL_TRUE_RE = re.compile(r"^(?:true|\$\{\{\s*true\s*\}\})$", re.IGNORECASE)
_BOOL_FALSE_RE = re.compile(r"^(?:false|\$\{\{\s*false\s*\}\})$", re.IGNORECASE)
_NOT_TRUE_RE = re.compile(r"^!\s*true$", re.IGNORECASE)
_NOT_FALSE_RE = re.compile(r"^!\s*false$", re.IGNORECASE)
_COMPARISON_RE = re.compile(
    r"^(github\.repository|github\.repository_owner|['\"][^'\"]+['\"])\s*"
    r"(==|!=)\s*"
    r"(github\.repository|github\.repository_owner|['\"][^'\"]+['\"])\s*$",
    re.IGNORECASE,
)
_GITHUB_REMOTE_RE = re.compile(
    r"github\.com[:/](?P<owner>[^/\s]+)/(?P<repo>[^/\s]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


def evaluate_if(expr: str | None, ctx: WorkflowContext | None = None) -> Verdict:
    """Return a static verdict for a tiny safe subset of Actions ``if:``.

    Runtime is the default. That is the important part of the contract:
    unsupported syntax is not "best effort" evaluated.
    """
    if expr is None:
        return Verdict.STATIC_TRUE

    s = _strip_expression_wrapper(expr.strip())
    if not s:
        return Verdict.RUNTIME

    if _BOOL_TRUE_RE.fullmatch(s):
        return Verdict.STATIC_TRUE
    if _BOOL_FALSE_RE.fullmatch(s):
        return Verdict.STATIC_FALSE
    if _NOT_TRUE_RE.fullmatch(s):
        return Verdict.STATIC_FALSE
    if _NOT_FALSE_RE.fullmatch(s):
        return Verdict.STATIC_TRUE

    comparison = _COMPARISON_RE.fullmatch(s)
    if comparison is None:
        return Verdict.RUNTIME

    left = _comparison_value(comparison.group(1), ctx)
    right = _comparison_value(comparison.group(3), ctx)
    if left is None or right is None:
        return Verdict.RUNTIME

    # GitHub Actions' ``==`` operator is case-sensitive on string
    # comparisons.  Coercing both sides with ``.lower()`` would
    # cause false negatives on suppression when ctx and literal
    # differ only in case (conservative — never over-suppresses,
    # but misses dead-job suppression on case-mismatched literals
    # that GHA would have evaluated false at runtime).
    equal = left == right
    if comparison.group(2) == "!=":
        equal = not equal
    return Verdict.STATIC_TRUE if equal else Verdict.STATIC_FALSE


def find_dead_line_ranges(
    content: str, ctx: WorkflowContext | None = None
) -> list[tuple[int, int]]:
    """Return 1-based inclusive line ranges for statically dead jobs/steps.

    Walks the workflow with the structural reader, which resolves YAML
    anchors and merge keys: a job inheriting ``if: false`` via
    ``<<: *anchor`` is recognised as dead even though the literal
    ``if:`` line lives in the anchor body.  Job-key declaration lines
    are recovered from the source via :func:`_job_key_line_map` so the
    returned range covers the full job block, including the key line.
    """
    from .parsers.structural import EventKind, walk_workflow

    job_key_lines = _job_key_line_map(content)

    # Heterogeneous nested dict: top-level keys are str (job IDs);
    # inner dicts mix str ("if"), int ("start"/"end"), and dict
    # ("steps") values.  TypedDict would require restructuring; Any
    # for the inner type is the minimal annotation that satisfies
    # mypy's `Missing type parameters for generic type "dict"` check
    # without changing runtime behaviour.
    job_data: dict[str, dict[str, Any]] = {}
    for event in walk_workflow(filepath="anonymous.yml", content=content, recover=True):
        if event.kind is not EventKind.LEAF_SCALAR:
            continue
        path = event.path
        if not path or path[0] != "jobs" or len(path) < 2:
            continue
        job_id = path[1]
        if not isinstance(job_id, str):
            continue

        slot = job_data.setdefault(
            job_id,
            {"if": None, "start": event.line, "end": event.line, "steps": {}},
        )
        slot["start"] = min(slot["start"], event.line)
        slot["end"] = max(slot["end"], event.line)

        if len(path) == 3 and path[2] == "if":
            slot["if"] = event.value

        if len(path) >= 5 and path[2] == "steps" and isinstance(path[3], int):
            step_idx = path[3]
            step_slot = slot["steps"].setdefault(
                step_idx,
                {"if": None, "start": event.line, "end": event.line},
            )
            step_slot["start"] = min(step_slot["start"], event.line)
            step_slot["end"] = max(step_slot["end"], event.line)
            if len(path) == 5 and path[4] == "if":
                step_slot["if"] = event.value

    ranges: list[tuple[int, int]] = []
    for job_id, slot in job_data.items():
        start = job_key_lines.get(job_id, slot["start"])
        if evaluate_if(slot["if"], ctx) is Verdict.STATIC_FALSE:
            ranges.append((start, slot["end"]))
            continue
        for step_slot in slot["steps"].values():
            if evaluate_if(step_slot["if"], ctx) is Verdict.STATIC_FALSE:
                ranges.append((step_slot["start"], step_slot["end"]))

    return ranges


def is_workflow_whole_dead(content: str, ctx: WorkflowContext | None = None) -> bool:
    """Return ``True`` if every job in the workflow is statically dead.

    Walks the workflow via the structural reader, collects each job's
    ``if:`` guard (or ``None`` when the job is unconditional), evaluates
    each guard with :func:`evaluate_if`, and returns ``True`` iff:

    1. The workflow has at least one job (an empty ``jobs:`` map is
       not "whole-dead", it's "no jobs to suppress").
    2. Every job's guard evaluates to STATIC_FALSE.

    A workflow with no ``jobs:`` block (e.g., ``workflow_call``-only
    definitions, or syntactically incomplete files) returns ``False``
    — there is nothing to call dead.

    Conservatism: any RUNTIME or STATIC_TRUE job means ``False`` is
    returned and the existing per-job suppression path handles the
    file normally.  The static evaluator's literal-only / repo-match
    semantics carry through.
    """
    from .parsers.structural import EventKind, walk_workflow

    job_ifs: dict[str, str | None] = {}
    for event in walk_workflow(filepath="anonymous.yml", content=content, recover=True):
        if event.kind is not EventKind.LEAF_SCALAR:
            continue
        path = event.path
        if not path or path[0] != "jobs" or len(path) < 2:
            continue
        job_id = path[1]
        if not isinstance(job_id, str):
            continue
        if job_id not in job_ifs:
            job_ifs[job_id] = None
        if len(path) == 3 and path[2] == "if":
            job_ifs[job_id] = event.value

    if not job_ifs:
        return False

    return all(evaluate_if(if_expr, ctx) is Verdict.STATIC_FALSE for if_expr in job_ifs.values())


def detect_github_workflow_context(repo_path: str) -> WorkflowContext:
    """Best-effort repository identity from ``git remote get-url origin``."""
    try:
        result = subprocess.run(  # nosec B603 B607 - fixed git command, no shell.
            ["git", "-C", repo_path, "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return WorkflowContext()
    if result.returncode != 0:
        return WorkflowContext()
    match = _GITHUB_REMOTE_RE.search(result.stdout.strip())
    if match is None:
        return WorkflowContext()
    owner = match.group("owner")
    repo = match.group("repo")
    return WorkflowContext(repository=f"{owner}/{repo}", repository_owner=owner)


def _strip_expression_wrapper(expr: str) -> str:
    s = expr.strip()
    # Unwrap a YAML-quoted ``${{ … }}`` expression (some style guides
    # recommend the outer quotes to disambiguate from ``${{`` syntax
    # for YAML linters).  Bare YAML-quoted strings are left untouched
    # so the conservative evaluator falls through to RUNTIME instead
    # of pretending to know GHA's truthy-string semantics.
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        inner = s[1:-1].strip()
        if inner.startswith("${{") and inner.endswith("}}"):
            s = inner
    if s.startswith("${{") and s.endswith("}}"):
        return s[3:-2].strip()
    return s


def _comparison_value(raw: str, ctx: WorkflowContext | None) -> str | None:
    token = raw.strip()
    if (token.startswith("'") and token.endswith("'")) or (
        token.startswith('"') and token.endswith('"')
    ):
        return token[1:-1]
    if ctx is None:
        return None
    lowered = token.lower()
    if lowered == "github.repository":
        return ctx.repository
    if lowered == "github.repository_owner":
        return ctx.repository_owner
    return None


def _job_key_line_map(content: str) -> dict[str, int]:
    """Map ``job_id`` -> 1-based line of its ``<id>:`` declaration.

    Used as the upper bound of a dead-job range so suppression ranges
    cover the job key line (matching the engine's existing contract),
    not just the job's leaf-scalar lines.  The structural reader emits
    leaves at child paths but not at the parent key, so this small
    line scan is the supplement; everything else (``if:`` resolution,
    merge-key inheritance, step bookkeeping) goes through the
    structural reader.
    """
    lines = content.splitlines()
    in_jobs = False
    jobs_indent = -1
    child_indent: int | None = None
    out: dict[str, int] = {}
    job_pattern = re.compile(r"^\s*([\w.-]+)\s*:\s*(?:#.*)?$")
    for idx, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if not in_jobs:
            if re.match(r"^jobs\s*:\s*(?:#.*)?$", raw):
                in_jobs = True
                jobs_indent = indent
            continue
        if indent <= jobs_indent:
            break
        if child_indent is None:
            child_indent = indent
        if indent == child_indent:
            m = job_pattern.match(raw)
            if m and m.group(1) not in out:
                out[m.group(1)] = idx + 1
    return out

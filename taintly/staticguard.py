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
from typing import NamedTuple


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

    equal = left.lower() == right.lower()
    if comparison.group(2) == "!=":
        equal = not equal
    return Verdict.STATIC_TRUE if equal else Verdict.STATIC_FALSE


def find_dead_line_ranges(
    content: str, ctx: WorkflowContext | None = None
) -> list[tuple[int, int]]:
    """Return 1-based inclusive line ranges for statically dead jobs/steps."""
    lines = content.splitlines()
    jobs_range = _find_mapping_item(lines, 0, len(lines), 0, "jobs")
    if jobs_range is None:
        return []

    ranges: list[tuple[int, int]] = []
    jobs_start, jobs_end, jobs_indent = jobs_range
    for job_start, job_end, job_indent in _child_mapping_ranges(
        lines, jobs_start + 1, jobs_end, jobs_indent
    ):
        job_if = _find_direct_if(lines, job_start + 1, job_end, job_indent)
        if evaluate_if(job_if, ctx) is Verdict.STATIC_FALSE:
            ranges.append((job_start + 1, job_end))
            continue

        steps_range = _find_mapping_item(lines, job_start + 1, job_end, job_indent + 1, "steps")
        if steps_range is None:
            continue
        steps_start, steps_end, steps_indent = steps_range
        for step_start, step_end, step_indent in _list_item_ranges(
            lines, steps_start + 1, steps_end, steps_indent
        ):
            step_if = _find_step_if(lines, step_start, step_end, step_indent)
            if evaluate_if(step_if, ctx) is Verdict.STATIC_FALSE:
                ranges.append((step_start + 1, step_end))

    return ranges


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
    if expr.startswith("${{") and expr.endswith("}}"):
        return expr[3:-2].strip()
    return expr


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


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_ignorable(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _range_end(lines: list[str], start: int, limit: int, indent: int) -> int:
    end = start + 1
    while end < limit:
        if not _is_ignorable(lines[end]) and _indent(lines[end]) <= indent:
            break
        end += 1
    return end


def _find_mapping_item(
    lines: list[str], start: int, end: int, min_indent: int, key: str
) -> tuple[int, int, int] | None:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:\s*(?:#.*)?$")
    for idx in range(start, end):
        if _is_ignorable(lines[idx]) or _indent(lines[idx]) < min_indent:
            continue
        if pattern.match(lines[idx]):
            indent = _indent(lines[idx])
            return idx, _range_end(lines, idx, end, indent), indent
    return None


def _child_mapping_ranges(
    lines: list[str], start: int, end: int, parent_indent: int
) -> list[tuple[int, int, int]]:
    ranges: list[tuple[int, int, int]] = []
    pattern = re.compile(r"^\s*[\w.-]+\s*:\s*(?:#.*)?$")
    idx = start
    while idx < end:
        if _is_ignorable(lines[idx]) or _indent(lines[idx]) <= parent_indent:
            idx += 1
            continue
        indent = _indent(lines[idx])
        if pattern.match(lines[idx]):
            child_end = _range_end(lines, idx, end, indent)
            ranges.append((idx, child_end, indent))
            idx = child_end
            continue
        idx += 1
    return ranges


def _list_item_ranges(
    lines: list[str], start: int, end: int, parent_indent: int
) -> list[tuple[int, int, int]]:
    ranges: list[tuple[int, int, int]] = []
    idx = start
    while idx < end:
        line = lines[idx]
        if _is_ignorable(line) or _indent(line) <= parent_indent:
            idx += 1
            continue
        if re.match(r"^\s*-\s+", line):
            indent = _indent(line)
            item_end = idx + 1
            while item_end < end:
                if not _is_ignorable(lines[item_end]):
                    item_indent = _indent(lines[item_end])
                    if item_indent < indent:
                        break
                    if item_indent == indent and re.match(r"^\s*-\s+", lines[item_end]):
                        break
                    if item_indent <= parent_indent:
                        break
                item_end += 1
            ranges.append((idx, item_end, indent))
            idx = item_end
            continue
        idx += 1
    return ranges


def _find_direct_if(lines: list[str], start: int, end: int, parent_indent: int) -> str | None:
    child_indent: int | None = None
    for idx in range(start, end):
        if not _is_ignorable(lines[idx]) and _indent(lines[idx]) > parent_indent:
            child_indent = _indent(lines[idx])
            break
    if child_indent is None:
        return None
    for idx in range(start, end):
        if _is_ignorable(lines[idx]):
            continue
        indent = _indent(lines[idx])
        if indent <= parent_indent:
            break
        if indent != child_indent:
            continue
        match = re.match(r"^\s*if\s*:\s*(.+?)\s*$", lines[idx])
        if match is not None:
            return match.group(1).strip()
    return None


def _find_step_if(lines: list[str], start: int, end: int, item_indent: int) -> str | None:
    inline = re.match(r"^\s*-\s*if\s*:\s*(.+?)\s*$", lines[start])
    if inline is not None:
        return inline.group(1).strip()
    for idx in range(start + 1, end):
        if _is_ignorable(lines[idx]):
            continue
        indent = _indent(lines[idx])
        if indent <= item_indent:
            break
        match = re.match(r"^\s*if\s*:\s*(.+?)\s*$", lines[idx])
        if match is not None:
            return match.group(1).strip()
    return None

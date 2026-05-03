"""Conservative GitLab CI dead-job evaluation."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum


class GuardVerdict(Enum):
    LIVE = "live"
    DEAD = "dead"
    RUNTIME = "runtime"


class ExprVerdict(Enum):
    STATIC_TRUE = "static_true"
    STATIC_FALSE = "static_false"
    RUNTIME = "runtime"


@dataclass(frozen=True)
class GitLabContext:
    """Pipeline context for context-aware GitLab CI rule evaluation.

    Populated fields let :func:`evaluate_gitlab_if` resolve
    comparisons such as ``$CI_PIPELINE_SOURCE == 'schedule'`` to
    STATIC_TRUE / STATIC_FALSE instead of falling through to RUNTIME.
    When taintly runs *inside* a GitLab CI pipeline,
    :func:`detect_gitlab_context` reads the corresponding predefined
    variables from the environment so the conservative-by-default
    suppression naturally upgrades to context-aware on real
    pipelines without any flag.  Outside a CI context all fields
    stay ``None`` and the conservative path is preserved.
    """

    pipeline_source: str | None = None
    commit_branch: str | None = None
    default_branch: str | None = None


def detect_gitlab_context() -> GitLabContext:
    """Best-effort GitLab CI context from the process environment.

    Populates fields from the standard GitLab CI predefined
    variables when present (i.e. when taintly itself runs inside a
    GitLab CI job).  Outside that environment every field stays
    ``None`` and the result is indistinguishable from
    ``GitLabContext()``.
    """
    return GitLabContext(
        pipeline_source=os.environ.get("CI_PIPELINE_SOURCE") or None,
        commit_branch=os.environ.get("CI_COMMIT_BRANCH") or None,
        default_branch=os.environ.get("CI_DEFAULT_BRANCH") or None,
    )


_RESERVED_TOP_LEVEL = {
    "stages",
    "variables",
    "include",
    "workflow",
    "default",
    "image",
    "services",
    "before_script",
    "after_script",
    "cache",
}
_COMPARE_RE = re.compile(
    r"^\$?(CI_PIPELINE_SOURCE|CI_COMMIT_BRANCH|CI_DEFAULT_BRANCH)\s*(==|!=)\s*"
    r"('([^']*)'|\"([^\"]*)\"|\$?(CI_PIPELINE_SOURCE|CI_COMMIT_BRANCH|CI_DEFAULT_BRANCH))$"
)


def evaluate_gitlab_rules(job: dict[str, object], ctx: GitLabContext | None = None) -> GuardVerdict:
    rules = job.get("rules", [])
    if not isinstance(rules, list):
        return GuardVerdict.RUNTIME
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if str(rule.get("when", "")).strip().lower() != "never":
            continue
        verdict = evaluate_gitlab_if(rule.get("if"), ctx)
        if verdict is ExprVerdict.STATIC_TRUE:
            return GuardVerdict.DEAD
        if verdict is ExprVerdict.RUNTIME:
            return GuardVerdict.RUNTIME
    return GuardVerdict.RUNTIME


def evaluate_gitlab_if(expr: object, ctx: GitLabContext | None = None) -> ExprVerdict:
    if expr is None:
        return ExprVerdict.STATIC_TRUE
    s = _strip_quotes(str(expr).strip())
    lower = s.lower()
    if lower == "true":
        return ExprVerdict.STATIC_TRUE
    if lower == "false":
        return ExprVerdict.STATIC_FALSE

    match = _COMPARE_RE.fullmatch(s)
    if match is None:
        return ExprVerdict.RUNTIME

    left = _value_for(match.group(1), ctx)
    right_token = match.group(4) or match.group(5) or match.group(6)
    right = (
        _value_for(right_token, ctx)
        if right_token and right_token.startswith("CI_")
        else right_token
    )
    if left is None or right is None:
        return ExprVerdict.RUNTIME
    equal = left == right
    if match.group(2) == "!=":
        equal = not equal
    return ExprVerdict.STATIC_TRUE if equal else ExprVerdict.STATIC_FALSE


def find_dead_gitlab_job_ranges(
    content: str, ctx: GitLabContext | None = None
) -> list[tuple[int, int]]:
    lines = content.splitlines()
    ranges: list[tuple[int, int]] = []
    for start, end, _name in _top_level_jobs(lines):
        job = _extract_job_rules(lines, start, end)
        if evaluate_gitlab_rules(job, ctx) is GuardVerdict.DEAD:
            ranges.append((start + 1, end))
    return ranges


def is_pipeline_whole_dead(
    content: str, ctx: GitLabContext | None = None
) -> bool:
    """Return ``True`` if every job in the pipeline is statically dead.

    Walks the pipeline, evaluates each job's ``rules`` chain with
    :func:`evaluate_gitlab_rules`, and returns ``True`` iff:

    1. The pipeline has at least one job (an empty file or a file
       with no jobs is not "whole-dead").
    2. Every job evaluates to ``GuardVerdict.DEAD``.

    Conservatism: any RUNTIME job (the default for rules that depend
    on runtime variables like ``$CI_PIPELINE_SOURCE`` when the
    context is not populated) prevents whole-dead classification.
    """
    lines = content.splitlines()
    jobs = list(_top_level_jobs(lines))
    if not jobs:
        return False
    for start, end, _name in jobs:
        job = _extract_job_rules(lines, start, end)
        if evaluate_gitlab_rules(job, ctx) is not GuardVerdict.DEAD:
            return False
    return True


def _value_for(token: str, ctx: GitLabContext | None) -> str | None:
    if ctx is None:
        return None
    if token == "CI_PIPELINE_SOURCE":  # nosec B105 - GitLab env var name, not a credential.
        return ctx.pipeline_source
    if token == "CI_COMMIT_BRANCH":  # nosec B105 - GitLab env var name, not a credential.
        return ctx.commit_branch
    if token == "CI_DEFAULT_BRANCH":  # nosec B105 - GitLab env var name, not a credential.
        return ctx.default_branch
    return token


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_ignorable(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _top_level_jobs(lines: list[str]) -> list[tuple[int, int, str]]:
    jobs: list[tuple[int, int, str]] = []
    starts: list[tuple[int, str]] = []
    for idx, line in enumerate(lines):
        if _is_ignorable(line) or _indent(line) != 0:
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*(?:#.*)?$", line)
        if match is None:
            continue
        name = match.group(1)
        if name in _RESERVED_TOP_LEVEL:
            continue
        starts.append((idx, name))
    for pos, (start, name) in enumerate(starts):
        end = starts[pos + 1][0] if pos + 1 < len(starts) else len(lines)
        while end > start + 1 and _is_ignorable(lines[end - 1]):
            end -= 1
        jobs.append((start, end, name))
    return jobs


def _extract_job_rules(lines: list[str], start: int, end: int) -> dict[str, object]:
    rules: list[dict[str, str]] = []
    idx = start + 1
    while idx < end:
        if re.match(r"^\s+rules\s*:\s*(?:#.*)?$", lines[idx]):
            rules_indent = _indent(lines[idx])
            idx += 1
            while idx < end:
                if not _is_ignorable(lines[idx]) and _indent(lines[idx]) <= rules_indent:
                    break
                if re.match(r"^\s*-\s+", lines[idx]):
                    item_start = idx
                    item_end = idx + 1
                    item_indent = _indent(lines[idx])
                    while item_end < end:
                        if not _is_ignorable(lines[item_end]):
                            indent = _indent(lines[item_end])
                            if indent <= rules_indent:
                                break
                            if indent == item_indent and re.match(r"^\s*-\s+", lines[item_end]):
                                break
                        item_end += 1
                    rules.append(_parse_rule_item(lines[item_start:item_end]))
                    idx = item_end
                    continue
                idx += 1
            break
        idx += 1
    return {"rules": rules}


def _parse_rule_item(lines: list[str]) -> dict[str, str]:
    rule: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if line.startswith("- "):
            line = line[2:].strip()
        for key in ("if", "when"):
            match = re.match(rf"^{key}\s*:\s*(.+?)\s*$", line)
            if match is not None:
                rule[key] = _strip_quotes(match.group(1).strip())
    return rule

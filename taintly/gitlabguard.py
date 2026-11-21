"""Conservative GitLab CI dead-job evaluation."""

from __future__ import annotations

import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum

from .parsers.structural import Event, EventKind, walk_workflow
from .parsers.structural.tokenizer import TokenizerError, TokenKind, tokenize
from .parsers.yaml_command_scalar import decode_single_line_command_scalar


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
            return GuardVerdict.RUNTIME
        if "if" in rule and rule["if"] is None:
            return GuardVerdict.RUNTIME
        verdict = evaluate_gitlab_if(rule.get("if"), ctx)
        if verdict is ExprVerdict.STATIC_FALSE:
            continue
        # Rules are ordered decisions. A possible earlier admission cannot
        # be skipped in order to reach a later denial. Extra match clauses
        # (changes/exists, etc.) are conjunctions, never unconditional true.
        if verdict is ExprVerdict.RUNTIME or set(rule) - {"if", "when"}:
            return GuardVerdict.RUNTIME
        return (
            GuardVerdict.DEAD
            if str(rule.get("when", "")).strip().lower() == "never"
            else GuardVerdict.RUNTIME
        )
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
    literal = match.group(4) if match.group(4) is not None else match.group(5)
    variable = match.group(6)
    right = _value_for(variable, ctx) if variable else literal
    if left is None or right is None:
        return ExprVerdict.RUNTIME
    equal = left == right
    if match.group(2) == "!=":
        equal = not equal
    return ExprVerdict.STATIC_TRUE if equal else ExprVerdict.STATIC_FALSE


def find_dead_gitlab_job_ranges(
    content: str, ctx: GitLabContext | None = None
) -> list[tuple[int, int]]:
    return analyze_gitlab_deadness(content, ctx)[0]


def is_pipeline_whole_dead(content: str, ctx: GitLabContext | None = None) -> bool:
    """Return ``True`` if every job in the pipeline is statically dead.

    Walks the pipeline, evaluates each job's ``rules`` chain with
    :func:`evaluate_gitlab_rules`, and returns ``True`` iff:

    1. The pipeline has at least one job (an empty file or a file
       with no jobs is not "whole-dead").
    2. Every job evaluates to ``GuardVerdict.DEAD``.
    3. The source has a complete literal job inventory without an include
       declaration or unresolved structural ownership. Hidden templates do
       not count as executable jobs.

    Conservatism: any RUNTIME job (the default for rules that depend
    on runtime variables like ``$CI_PIPELINE_SOURCE`` when the
    context is not populated) prevents whole-dead classification.
    """
    return analyze_gitlab_deadness(content, ctx)[1]


def analyze_gitlab_deadness(
    content: str, ctx: GitLabContext | None = None
) -> tuple[list[tuple[int, int]], bool]:
    """One source-owned proof for job filtering and whole-file suppression.

    RUNTIME means deadness is unproven, not that execution was observed.
    Unknown includes prevent a whole-pipeline proof, while a direct local
    literal denial can still exclude its own source job.
    """
    # This is only an applicability shortcut for suppression. A spelling we
    # cannot identify keeps findings and cannot prove whole-file deadness.
    if "never" not in content:
        return [], False
    jobs, records, complete = _source_jobs(content)
    dead = [
        (start + 1, end)
        for start, end, name in jobs
        if evaluate_gitlab_rules(records[name], ctx) is GuardVerdict.DEAD
    ]
    if dead and not _flow_ownership_supported(content):
        return [], False
    return dead, bool(jobs) and complete and len(dead) == len(jobs)


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


def _is_ignorable(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _owned_rule_record(
    branch: list[Event],
    keys: Counter[tuple[object, ...]],
    lines: list[str],
    name: str,
) -> dict[str, object]:
    """Materialize existing rule fields; callers establish owner/context policy.

    No activation, inheritance or container-kind conclusion is made here.
    An empty record does not establish a sequence schema.
    """
    root = (name, "rules")
    rule_events = [e for e in branch if e.path[:2] == root]
    if not keys[root]:
        return {}
    if any(
        len(e.path) < 3 or not isinstance(e.path[2], int)
        for e in rule_events
        if e.kind is not EventKind.MAP_KEY or e.path != root
    ):
        return {"rules": None}
    items: dict[int, list[Event]] = defaultdict(list)
    for event in rule_events:
        if len(event.path) >= 3 and isinstance(event.path[2], int):
            items[event.path[2]].append(event)
    indexes = sorted(items)
    rules: list[object] = []
    for expected, index in enumerate(indexes):
        if expected != index:
            rules.append(None)
            break
        item = root + (index,)
        item_events = items[index]
        fields = {str(e.path[3]) for e in item_events if len(e.path) >= 4 and e.path[:3] == item}
        if not fields or any(
            e.kind is EventKind.LEAF_SCALAR and e.path == item for e in item_events
        ):
            rules.append(None)
            break
        record: dict[str, object] = {}
        for field in fields:
            path = item + (field,)
            values = [e for e in item_events if e.kind is EventKind.LEAF_SCALAR and e.path == path]
            if field not in {"if", "when"}:
                record[field] = None  # Present, with unresolved matching/modifier semantics.
                continue
            if keys[path] != 1 or len(values) != 1:
                record["if"] = None
                break
            value = values[0]
            text = value.value if value.value_kind == "plain" else None
            if value.value_kind == "quoted" and 0 < value.line <= len(lines):
                text = decode_single_line_command_scalar(lines[value.line - 1], value)
            if text is None or not text.strip() or text.strip() in {"null", "~"}:
                record["if"] = None
                break
            record[field] = text
        rules.append(record)
    return {"rules": rules}


def _source_jobs(
    content: str,
) -> tuple[list[tuple[int, int, str]], dict[str, dict[str, object]], bool]:
    """Literal owned rule records; unknown fields survive as proof barriers."""
    lines = content.splitlines()
    events = tuple(
        walk_workflow(
            ".gitlab-ci.yml", content=content, include_keys=True, include_merge_origins=True
        )
    )
    keys = Counter(e.path for e in events if e.kind is EventKind.MAP_KEY)
    top = [e for e in events if e.kind is EventKind.MAP_KEY and len(e.path) == 1]
    if (
        any(e.kind is EventKind.CUTOFF for e in events)
        or any("\\" in (e.value or "") for e in top)
        or any(e.kind is EventKind.ERROR and (not e.path or not keys[e.path[:1]]) for e in events)
    ):
        return [], {}, False
    owned: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.path and isinstance(event.path[0], str):
            owned[event.path[0]].append(event)
    jobs: list[tuple[int, int, str]] = []
    records: dict[str, dict[str, object]] = {}
    complete = not keys[("include",)] and not any(e.kind is EventKind.ERROR for e in events)
    complete &= not any(e.path and not keys[e.path[:1]] for e in events)
    for pos, header in enumerate(top):
        name = str(header.path[0])
        if name in _RESERVED_TOP_LEVEL or name.startswith("."):
            continue
        start = header.line - 1
        end = top[pos + 1].line - 1 if pos + 1 < len(top) else len(lines)
        if end <= start or (pos and top[pos - 1].line == header.line):
            complete = False
            continue
        while end > start + 1 and _is_ignorable(lines[end - 1]):
            end -= 1
        jobs.append((start, end, name))
        records[name] = {"rules": None}
        branch = owned[name]
        if (
            keys[(name,)] != 1
            or keys[(name, "extends")]
            or any(e.kind is EventKind.ERROR or e.merge_origins for e in branch)
            or any(
                e.kind is EventKind.MAP_KEY and (keys[e.path] != 1 or "\\" in (e.value or ""))
                for e in branch
            )
            or any(
                e.kind is EventKind.LEAF_SCALAR
                and e.path
                and isinstance(e.path[-1], str)
                and not keys[e.path]
                for e in branch
            )
        ):
            continue
        records[name] = _owned_rule_record(branch, keys, lines, name)
    return jobs, records, complete


def _flow_ownership_supported(content: str) -> bool:
    """The structural walk alone cannot certify malformed flow or flow aliases."""
    expected_close = {
        TokenKind.FLOW_OPEN_SEQ: TokenKind.FLOW_CLOSE_SEQ,
        TokenKind.FLOW_OPEN_MAP: TokenKind.FLOW_CLOSE_MAP,
    }
    closures = set(expected_close.values())
    stack: list[TokenKind] = []
    try:
        for token in tokenize(content):
            if token.kind in expected_close:
                stack.append(expected_close[token.kind])
            elif token.kind in closures:
                if not stack or stack.pop() is not token.kind:
                    return False
            elif stack and token.kind in {TokenKind.ANCHOR, TokenKind.ALIAS, TokenKind.MERGE_KEY}:
                return False
    except TokenizerError:
        return False
    return not stack

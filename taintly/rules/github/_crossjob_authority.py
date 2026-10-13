"""Owner-keyed, fail-open authority indicators for CHAIN-GH-105."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import Token, TokenizerError, TokenKind, tokenize

_MAX_CONTENT_CHARS = 1_000_000
_TOKEN_INPUT = re.compile(r"^(?:github[_-]?token|token)$", re.IGNORECASE)
_TOKEN_VALUE = re.compile(
    r"^\s*['\"]?\$\{\{\s*(?:secrets\.[A-Za-z_][A-Za-z0-9_]*|github\.token)\s*\}\}['\"]?\s*$",
    re.IGNORECASE,
)
_EXPRESSION_VALUE = re.compile(r"\$\{\{[^{}]*\}\}")
_DOC_MARKER = re.compile(r"(?:---|\.\.\.)(?:[ \t].*)?\Z")


@dataclass(frozen=True)
class AuthorityEvidence:
    """One direct indicator or unresolved possible input, tied to a source line."""

    line: int
    kind: str


@dataclass(frozen=True)
class AuthorityView:
    """Candidate evidence indexed by exact workflow job and step owners."""

    complete: bool
    by_step: dict[tuple[str, int], tuple[AuthorityEvidence, ...]]
    by_job: dict[str, tuple[AuthorityEvidence, ...]]

    def step_evidence(self, job: str, step: int) -> tuple[AuthorityEvidence, ...]:
        return self.by_step.get((job, step), ())

    def job_evidence(self, job: str) -> tuple[AuthorityEvidence, ...]:
        return self.by_job.get(job, ())

    @staticmethod
    def describe(evidence: tuple[AuthorityEvidence, ...]) -> str:
        if not evidence:
            return ""
        item = min(evidence, key=lambda value: (value.line, value.kind))
        if item.kind == "operation":
            return f"executable authority text at line {item.line}"
        if item.kind == "token":
            return f"explicit action token input at line {item.line}"
        return f"possible authority-bearing input (unresolved) at line {item.line}"


def _header_is_mapping(lines: list[str], event: Event, key: str) -> bool:
    if not 1 <= event.line <= len(lines):
        return False
    return re.fullmatch(rf" *{re.escape(key)}\s*:\s*(?:#.*)?", lines[event.line - 1]) is not None


def _owning_value_span(tokens: tuple[Token, ...], line: int, key_name: str) -> list[Token] | None:
    starts = [
        position
        for position, token in enumerate(tokens)
        if token.kind is TokenKind.KEY and token.value == key_name and token.line == line
    ]
    if len(starts) != 1:
        return None
    start = starts[0]
    key = tokens[start]
    end = next(
        (
            position
            for position in range(start + 1, len(tokens))
            if tokens[position].line > key.line
            and (
                (
                    tokens[position].kind is TokenKind.KEY
                    and tokens[position].indent <= key.column - 1
                )
                or (
                    tokens[position].kind is TokenKind.SEQUENCE_DASH
                    and tokens[position].indent <= key.indent
                )
            )
        ),
        len(tokens),
    )
    return list(tokens[start + 1 : end])


def _certified_scalar(
    event: Event,
    path: tuple[object, ...],
    keys: dict[tuple[object, ...], list[Event]],
    leaves: dict[tuple[object, ...], list[Event]],
    tokens: tuple[Token, ...],
) -> bool:
    if len(keys.get(path, ())) != 1 or len(leaves.get(path, ())) != 1 or event.merge_origins:
        return False
    key = keys[path][0]
    span = _owning_value_span(tokens, key.line, str(path[-1]))
    if not span:
        return False
    if span[0].kind in {TokenKind.SCALAR_PLAIN, TokenKind.SCALAR_QUOTED}:
        return len(span) == 1
    if span[0].kind is TokenKind.SCALAR_BLOCK_HEADER:
        return all(token.kind is TokenKind.SCALAR_BLOCK_LINE for token in span[1:])
    return False


def _complete_events(content: str):
    """Return a bounded unique structural/token view or None for fail-open use."""
    if len(content) > _MAX_CONTENT_CHARS or any(
        _DOC_MARKER.fullmatch(line.strip()) for line in content.splitlines()
    ):
        return None
    try:
        tokens = tuple(
            token
            for token in tokenize(content)
            if token.kind not in {TokenKind.INDENT, TokenKind.COMMENT, TokenKind.EOF}
        )
        if any(
            token.kind in {TokenKind.ANCHOR, TokenKind.ALIAS, TokenKind.MERGE_KEY}
            for token in tokens
        ):
            return None
        flow_stack: list[TokenKind] = []
        for token in tokens:
            if token.kind in {TokenKind.FLOW_OPEN_MAP, TokenKind.FLOW_OPEN_SEQ}:
                if flow_stack:
                    return None
                flow_stack.append(
                    TokenKind.FLOW_CLOSE_MAP
                    if token.kind is TokenKind.FLOW_OPEN_MAP
                    else TokenKind.FLOW_CLOSE_SEQ
                )
            elif token.kind in {TokenKind.FLOW_CLOSE_MAP, TokenKind.FLOW_CLOSE_SEQ}:
                if not flow_stack or flow_stack.pop() is not token.kind:
                    return None
        if flow_stack:
            return None
        events = tuple(
            walk_workflow(
                "workflow.yml",
                content=content,
                include_keys=True,
                include_merge_origins=True,
            )
        )
    except (RecursionError, TokenizerError, TypeError, ValueError):
        return None
    if any(
        event.kind in {EventKind.ERROR, EventKind.CUTOFF} or event.merge_origins for event in events
    ):
        return None
    keys: dict[tuple[object, ...], list[Event]] = {}
    leaves: dict[tuple[object, ...], list[Event]] = {}
    for event in events:
        if event.kind is EventKind.MAP_KEY:
            keys.setdefault(event.path, []).append(event)
        elif event.kind is EventKind.LEAF_SCALAR:
            leaves.setdefault(event.path, []).append(event)
    if any(len(items) != 1 for items in keys.values()) or any(
        len(items) != 1 for items in leaves.values()
    ):
        return None
    return events, tokens, keys, leaves


def build_authority_view(
    content: str,
    operation_matches: Callable[[str], bool],
) -> AuthorityView:
    """Extract source-owned operation/token evidence, else return incomplete.

    The supported negative certificate is intentionally block-YAML only. Any
    uncertain owner shape is left to the caller's conservative legacy path.
    """
    parsed = _complete_events(content)
    if parsed is None:
        return AuthorityView(False, {}, {})
    _events, tokens, keys, leaves = parsed
    lines = content.splitlines()
    jobs_key = keys.get(("jobs",), [])
    if len(jobs_key) != 1 or not _header_is_mapping(lines, jobs_key[0], "jobs"):
        return AuthorityView(False, {}, {})

    values = {path: rows[0] for path, rows in leaves.items() if rows[0].value is not None}
    jobs = {
        str(path[1])
        for path in keys
        if len(path) == 2 and path[0] == "jobs" and isinstance(path[1], str)
    }
    if not jobs:
        return AuthorityView(False, {}, {})

    step_owners: set[tuple[str, int]] = set()
    for path in (*keys.keys(), *leaves.keys()):
        if (
            len(path) >= 5
            and path[0] == "jobs"
            and isinstance(path[1], str)
            and path[2] == "steps"
            and isinstance(path[3], int)
        ):
            step_owners.add((path[1], path[3]))

    # Every job and steps collection must have one literal block owner. Each
    # sequence item must be one supported scalar run or uses step, never both.
    for job in jobs:
        job_path = ("jobs", job)
        steps_path = job_path + ("steps",)
        job_event = keys.get(job_path, [None])[0]
        steps_event = keys.get(steps_path, [None])[0]
        if (
            job_event is None
            or steps_event is None
            or job_path in leaves
            or steps_path in leaves
            or not _header_is_mapping(lines, job_event, job)
            or not _header_is_mapping(lines, steps_event, "steps")
        ):
            return AuthorityView(False, {}, {})
        owners = sorted((owner for owner in step_owners if owner[0] == job), key=lambda x: x[1])
        if not owners:
            return AuthorityView(False, {}, {})
        next_job_line = min(
            (
                rows[0].line
                for path, rows in keys.items()
                if len(path) == 2 and path[0] == "jobs" and rows[0].line > job_event.line
            ),
            default=len(lines) + 1,
        )
        steps_indent = steps_event.column - 1
        step_dashes = [
            token
            for token in tokens
            if token.kind is TokenKind.SEQUENCE_DASH
            and token.line > steps_event.line
            and token.line < next_job_line
            and token.indent == steps_indent + 2
        ]
        if len(step_dashes) != len(owners):
            return AuthorityView(False, {}, {})
        for position, (_, index) in enumerate(owners):
            owner = steps_path + (index,)
            run_path, uses_path = owner + ("run",), owner + ("uses",)
            has_run, has_uses = run_path in leaves, uses_path in leaves
            if has_run == has_uses:
                return AuthorityView(False, {}, {})
            dash_line = step_dashes[position].line
            item_end = (
                step_dashes[position + 1].line if position + 1 < len(step_dashes) else next_job_line
            )
            executable_event = leaves[run_path][0] if has_run else leaves[uses_path][0]
            if not dash_line <= executable_event.line < item_end:
                return AuthorityView(False, {}, {})
            if (run_path in keys and not has_run) or (uses_path in keys and not has_uses):
                return AuthorityView(False, {}, {})
            executable_path = run_path if has_run else uses_path
            if not _certified_scalar(
                leaves[executable_path][0], executable_path, keys, leaves, tokens
            ):
                return AuthorityView(False, {}, {})
            # Nested input/env values are ambiguous. Ordinary scalar maps are
            # supported, but a collection-valued input is not a negative proof.
            for prefix in (owner + ("env",), owner + ("with",)):
                if prefix in leaves:
                    return AuthorityView(False, {}, {})
                prefix_event = keys.get(prefix, [None])[0]
                if prefix_event is not None and any(
                    token.line == prefix_event.line
                    and token.kind in {TokenKind.FLOW_OPEN_MAP, TokenKind.FLOW_OPEN_SEQ}
                    for token in tokens
                ):
                    return AuthorityView(False, {}, {})
                for child in keys:
                    if len(child) > len(prefix) and child[: len(prefix)] == prefix:
                        if child not in leaves or not _certified_scalar(
                            leaves[child][0], child, keys, leaves, tokens
                        ):
                            return AuthorityView(False, {}, {})

    # Ensure workflow/job env maps contain only scalar leaves; preserve their
    # values as unresolved possible inputs for executable owners.
    env_paths = [
        path
        for path in keys
        if path == ("env",) or (len(path) == 3 and path[0] == "jobs" and path[2] == "env")
    ]
    for prefix in env_paths:
        if prefix in leaves:
            return AuthorityView(False, {}, {})
        prefix_event = keys.get(prefix, [None])[0]
        if prefix_event is not None and any(
            token.line == prefix_event.line
            and token.kind in {TokenKind.FLOW_OPEN_MAP, TokenKind.FLOW_OPEN_SEQ}
            for token in tokens
        ):
            return AuthorityView(False, {}, {})
        for child in keys:
            if len(child) > len(prefix) and child[: len(prefix)] == prefix:
                if child not in leaves or not _certified_scalar(
                    leaves[child][0], child, keys, leaves, tokens
                ):
                    return AuthorityView(False, {}, {})

    by_step: dict[tuple[str, int], list[AuthorityEvidence]] = {owner: [] for owner in step_owners}
    by_job: dict[str, list[AuthorityEvidence]] = {job: [] for job in jobs}
    workflow_env: list[AuthorityEvidence] = []
    job_env: dict[str, list[AuthorityEvidence]] = {job: [] for job in jobs}

    for path, event in values.items():
        if path == ("env",) or path[:1] == ("env",):
            if operation_matches(event.value or ""):
                workflow_env.append(AuthorityEvidence(event.line, "possible-input"))
            elif path and _TOKEN_INPUT.fullmatch(str(path[-1])):
                if _TOKEN_VALUE.fullmatch(event.value or ""):
                    workflow_env.append(AuthorityEvidence(event.line, "token"))
                elif _EXPRESSION_VALUE.search(event.value or ""):
                    workflow_env.append(AuthorityEvidence(event.line, "possible-token"))
        elif len(path) >= 3 and path[0] == "jobs" and path[2] == "env":
            if operation_matches(event.value or ""):
                job_env[str(path[1])].append(AuthorityEvidence(event.line, "possible-input"))
            elif _TOKEN_INPUT.fullmatch(str(path[-1])):
                if _TOKEN_VALUE.fullmatch(event.value or ""):
                    job_env[str(path[1])].append(AuthorityEvidence(event.line, "token"))
                elif _EXPRESSION_VALUE.search(event.value or ""):
                    job_env[str(path[1])].append(AuthorityEvidence(event.line, "possible-token"))

    for job, index in step_owners:
        owner = ("jobs", job, "steps", index)
        items = by_step[(job, index)]
        run_event = values.get(owner + ("run",))
        uses_event = values.get(owner + ("uses",))
        uses_value = uses_event.value if uses_event is not None else None
        if run_event is not None and operation_matches(run_event.value or ""):
            items.append(AuthorityEvidence(run_event.line, "operation"))
        for path, event in values.items():
            if path[:4] != owner:
                continue
            suffix = path[4:]
            if (
                suffix == ("with", "script")
                and uses_value is not None
                and uses_value.split("@", 1)[0].lower() == "actions/github-script"
                and operation_matches(event.value or "")
            ):
                items.append(AuthorityEvidence(event.line, "operation"))
            elif suffix and suffix[0] in {"env", "with"} and operation_matches(event.value or ""):
                items.append(AuthorityEvidence(event.line, "possible-input"))
            if (
                uses_event is not None
                and len(suffix) == 2
                and suffix[0] in {"env", "with"}
                and _TOKEN_INPUT.fullmatch(str(suffix[1]))
            ):
                if _TOKEN_VALUE.fullmatch(event.value or ""):
                    items.append(AuthorityEvidence(event.line, "token"))
                elif _EXPRESSION_VALUE.search(event.value or ""):
                    items.append(AuthorityEvidence(event.line, "possible-input"))
        # Job/workflow env may be consumed through indirect execution; preserve
        # it as unresolved evidence for each executable step in that scope.
        if run_event is not None or uses_event is not None:
            for inherited in (*job_env.get(job, ()), *workflow_env):
                if inherited.kind in {"token", "possible-token"} and uses_event is None:
                    continue
                if inherited.kind in {"token", "possible-token"}:
                    # A job/workflow env value can be overridden by a
                    # step-level env assignment. Preserve the possible action
                    # handoff without claiming its effective value is known.
                    items.append(AuthorityEvidence(inherited.line, "possible-input"))
                else:
                    items.append(inherited)
        by_job[job].extend(items)

    return AuthorityView(
        True,
        {owner: tuple(items) for owner, items in by_step.items() if items},
        {job: tuple(items) for job, items in by_job.items() if items},
    )

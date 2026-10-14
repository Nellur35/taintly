"""Conservative availability facts for selected GitHub event fields.

This module proves only that direct ``github.event.issue.title`` and
``github.event.issue.body`` sources are absent for a structurally supported
candidate when the explicit workflow trigger profile is push-only, or when a
unique owning job/step guard excludes the ``issues`` invocation. The latter
remains a source-availability result even when no declared event can execute
that candidate. GitHub documents missing context properties as empty strings
and the push payload without an issue root; see
https://docs.github.com/en/actions/reference/workflows-and-actions/contexts and
https://docs.github.com/en/webhooks/webhook-events-and-payloads#push.

Every other event/field pair remains unknown. This is source availability,
not a claim about runtime execution or exploitability.
"""

from __future__ import annotations

import re
from enum import Enum

from .eventguard import event_guard_verdict
from .parsers.gha_expr import ExprSyntaxError, canonical_path, context_paths, parse
from .parsers.structural import Event, EventKind, walk_workflow
from .parsers.structural.tokenizer import Token, TokenizerError, TokenKind, tokenize


class EventSourceAvailability(Enum):
    """Whether this bounded profile can prove an event field absent."""

    ABSENT = "absent"
    MAY_BE_PRESENT = "may_be_present"
    UNKNOWN = "unknown"


_SUPPORTED_ISSUE_FIELDS = frozenset({"title", "body"})
_STRING_KINDS = frozenset({"plain", "quoted"})
_ROOT_ON_KEY_RE = re.compile(r"^(?:on|'on'|\"on\")\s*:")
_DISALLOWED_ON_TOKENS = frozenset(
    {
        TokenKind.ANCHOR,
        TokenKind.ALIAS,
        TokenKind.MERGE_KEY,
        TokenKind.SCALAR_BLOCK_HEADER,
        TokenKind.SCALAR_BLOCK_LINE,
    }
)
_FLOW_PAIRS = {
    TokenKind.FLOW_OPEN_SEQ: TokenKind.FLOW_CLOSE_SEQ,
    TokenKind.FLOW_OPEN_MAP: TokenKind.FLOW_CLOSE_MAP,
}


def _flow_structure(tokens: list[Token]) -> tuple[dict[int, int], list[int]] | None:
    stack: list[tuple[TokenKind, int]] = []
    matching: dict[int, int] = {}
    depths: list[int] = []
    for index, token in enumerate(tokens):
        depths.append(len(stack))
        if token.kind in _FLOW_PAIRS:
            stack.append((token.kind, index))
        elif token.kind in {TokenKind.FLOW_CLOSE_SEQ, TokenKind.FLOW_CLOSE_MAP}:
            if not stack or _FLOW_PAIRS[stack[-1][0]] is not token.kind:
                return None
            _, opening = stack.pop()
            matching[opening] = index
    if stack:
        return None
    return matching, depths


def _on_value_tokens(tokens: list[Token], root_index: int) -> list[Token] | None:
    root = tokens[root_index]
    index = root_index + 1
    while index < len(tokens) and tokens[index].kind in {TokenKind.INDENT, TokenKind.COMMENT}:
        if tokens[index].line > root.line:
            break
        index += 1
    if index < len(tokens) and tokens[index].line == root.line:
        first = tokens[index]
        if first.kind in _FLOW_PAIRS:
            structure = _flow_structure(tokens[index:])
            if structure is None:
                return None
            matching, _ = structure
            relative_end = matching.get(0)
            if relative_end is None:
                return None
            end = index + relative_end
            tail = [
                token
                for token in tokens[end + 1 :]
                if token.line == root.line
                and token.kind not in {TokenKind.INDENT, TokenKind.COMMENT, TokenKind.EOF}
            ]
            return None if tail else tokens[index : end + 1]
        if first.kind in {TokenKind.SCALAR_PLAIN, TokenKind.SCALAR_QUOTED}:
            tail = [
                token
                for token in tokens[index + 1 :]
                if token.line == root.line
                and token.kind not in {TokenKind.INDENT, TokenKind.COMMENT, TokenKind.EOF}
            ]
            return None if tail else [first]
        return None

    subtree: list[Token] = []
    for token in tokens[index:]:
        if token.kind is TokenKind.EOF:
            break
        if (
            token.line > root.line
            and token.kind is TokenKind.INDENT
            and token.indent <= root.indent
        ):
            break
        if (
            token.line > root.line
            and token.kind not in {TokenKind.INDENT, TokenKind.COMMENT}
            and token.indent <= root.indent
        ):
            break
        subtree.append(token)
    core = [token for token in subtree if token.kind not in {TokenKind.INDENT, TokenKind.COMMENT}]
    return core or None


def _walker_matches_scalars(
    events: tuple[Event, ...], tokens: list[Token], *, sequence: bool
) -> tuple[str, ...] | None:
    leaves = [
        event
        for event in events
        if event.kind is EventKind.LEAF_SCALAR
        and (
            len(event.path) == 2 and event.path[0] == "on" and isinstance(event.path[1], int)
            if sequence
            else event.path == ("on",)
        )
    ]
    if len(leaves) != len(tokens):
        return None
    names: list[str] = []
    for index, (event, token) in enumerate(zip(leaves, tokens, strict=True)):
        if (
            event.value_kind not in _STRING_KINDS
            or token.kind not in {TokenKind.SCALAR_PLAIN, TokenKind.SCALAR_QUOTED}
            or (event.line, event.column, event.value) != (token.line, token.column, token.value)
            or (sequence and event.path[1] != index)
        ):
            return None
        names.append(event.value or "")
    return tuple(names)


def _simple_flow_list(tokens: list[Token]) -> list[Token] | None:
    core = [token for token in tokens if token.kind not in {TokenKind.INDENT, TokenKind.COMMENT}]
    if (
        len(core) < 3
        or core[0].kind is not TokenKind.FLOW_OPEN_SEQ
        or core[-1].kind is not TokenKind.FLOW_CLOSE_SEQ
    ):
        return None
    items: list[Token] = []
    index = 1
    while index < len(core) - 1:
        token = core[index]
        if token.kind not in {TokenKind.SCALAR_PLAIN, TokenKind.SCALAR_QUOTED}:
            return None
        items.append(token)
        index += 1
        if index == len(core) - 1:
            break
        if core[index].kind is not TokenKind.FLOW_COMMA:
            return None
        index += 1
        if index == len(core) - 1:
            break  # one optional trailing comma
    return items or None


def _simple_block_list(tokens: list[Token]) -> list[Token] | None:
    core = [token for token in tokens if token.kind not in {TokenKind.INDENT, TokenKind.COMMENT}]
    if not core or len(core) % 2:
        return None
    items: list[Token] = []
    for dash, scalar in zip(core[::2], core[1::2], strict=True):
        if (
            dash.kind is not TokenKind.SEQUENCE_DASH
            or scalar.kind not in {TokenKind.SCALAR_PLAIN, TokenKind.SCALAR_QUOTED}
            or (dash.line, dash.indent) != (scalar.line, scalar.indent)
        ):
            return None
        items.append(scalar)
    return items


def _flow_map_keys(tokens: list[Token]) -> list[Token] | None:
    core = [token for token in tokens if token.kind not in {TokenKind.INDENT, TokenKind.COMMENT}]
    structure = _flow_structure(core)
    if (
        structure is None
        or len(core) < 3
        or core[0].kind is not TokenKind.FLOW_OPEN_MAP
        or core[-1].kind is not TokenKind.FLOW_CLOSE_MAP
    ):
        return None
    matching, depths = structure
    keys: list[Token] = []
    index = 1
    while index < len(core) - 1:
        if core[index].kind is not TokenKind.KEY or depths[index] != 1:
            return None
        key_index = index
        keys.append(core[index])
        index += 1
        value_tokens: list[Token] = []
        while index < len(core) - 1:
            token = core[index]
            if token.kind is TokenKind.FLOW_COMMA and depths[index] == 1:
                break
            if token.kind is TokenKind.FLOW_OPEN_MAP and depths[index] == 1:
                end = matching.get(index)
                if end is None:
                    return None
                value_tokens.append(token)
                value_tokens.extend(core[index + 1 : end + 1])
                index = end + 1
                continue
            if token.kind in _FLOW_PAIRS:
                return None
            value_tokens.append(token)
            index += 1
        if value_tokens and not (
            len(value_tokens) == 1
            and value_tokens[0].kind is TokenKind.SCALAR_PLAIN
            and value_tokens[0].value.lower() == "null"
        ):
            if not (
                value_tokens[0].kind is TokenKind.FLOW_OPEN_MAP
                and matching.get(key_index + 1) == index - 1
            ):
                return None
        if index == len(core) - 1:
            break
        index += 1  # entry comma
        if index == len(core) - 1:
            break  # optional trailing comma
    return keys or None


def _block_map_keys(tokens: list[Token]) -> list[Token] | None:
    core = [token for token in tokens if token.kind not in {TokenKind.INDENT, TokenKind.COMMENT}]
    if not core:
        return None
    structure = _flow_structure(core)
    if structure is None:
        return None
    matching, depths = structure
    direct_indent = min(token.indent for token in core)
    keys = [
        index
        for index, token in enumerate(core)
        if token.kind is TokenKind.KEY and token.indent == direct_indent and depths[index] == 0
    ]
    if not keys or keys[0] != 0:
        return None
    for position, key_index in enumerate(keys):
        end = keys[position + 1] if position + 1 < len(keys) else len(core)
        following = core[key_index + 1 : end]
        if not following:
            continue  # empty/null event option
        first = following[0]
        if first.indent == direct_indent and depths[key_index + 1] == 0:
            if first.kind is TokenKind.SCALAR_PLAIN and first.value.lower() == "null":
                if len(following) != 1:
                    return None
                continue
            if first.kind is TokenKind.FLOW_OPEN_MAP:
                if matching.get(key_index + 1) != end - 1:
                    return None
                continue
            return None
        if first.kind is not TokenKind.KEY or first.indent <= direct_indent:
            return None
    return [core[index] for index in keys]


def _walker_matches_map_keys(
    events: tuple[Event, ...], tokens: list[Token]
) -> tuple[str, ...] | None:
    keys = [
        event
        for event in events
        if event.kind is EventKind.MAP_KEY
        and len(event.path) == 2
        and event.path[0] == "on"
        and event.value_kind == "key"
    ]
    if len(keys) != len(tokens):
        return None
    names: list[str] = []
    for event, token in zip(keys, tokens, strict=True):
        if (event.line, event.column) != (token.line, token.column) or not event.value:
            return None
        names.append(event.value)
    if len(set(names)) != len(names):
        return None
    return tuple(names)


def _explicit_trigger_names(content: str) -> tuple[str, ...] | None:
    events = tuple(
        walk_workflow(
            "workflow.yml",
            content=content,
            recover=True,
            include_keys=True,
            include_merge_origins=True,
        )
    )
    if any(ev.kind in {EventKind.ERROR, EventKind.CUTOFF} for ev in events):
        return None
    roots = [
        ev
        for ev in events
        if ev.kind is EventKind.MAP_KEY and ev.path == ("on",) and ev.value == "on"
    ]
    if len(roots) != 1 or roots[0].merge_origins or roots[0].column != 1:
        return None
    try:
        tokens = list(tokenize(content))
    except TokenizerError:
        return None
    root_tokens = [
        index
        for index, token in enumerate(tokens)
        if token.kind is TokenKind.KEY
        and token.value == "on"
        and (token.line, token.column) == (roots[0].line, roots[0].column)
    ]
    if len(root_tokens) != 1:
        return None
    value_tokens = _on_value_tokens(tokens, root_tokens[0])
    if not value_tokens or any(token.kind in _DISALLOWED_ON_TOKENS for token in value_tokens):
        return None
    core = [
        token for token in value_tokens if token.kind not in {TokenKind.INDENT, TokenKind.COMMENT}
    ]
    if not core:
        return None
    if len(core) == 1 and core[0].kind in {TokenKind.SCALAR_PLAIN, TokenKind.SCALAR_QUOTED}:
        names = _walker_matches_scalars(events, core, sequence=False)
    elif core[0].kind is TokenKind.FLOW_OPEN_SEQ:
        items = _simple_flow_list(core)
        names = None if items is None else _walker_matches_scalars(events, items, sequence=True)
    elif core[0].kind is TokenKind.SEQUENCE_DASH:
        items = _simple_block_list(core)
        names = None if items is None else _walker_matches_scalars(events, items, sequence=True)
    elif core[0].kind is TokenKind.FLOW_OPEN_MAP:
        keys = _flow_map_keys(core)
        names = None if keys is None else _walker_matches_map_keys(events, keys)
    elif core[0].kind is TokenKind.KEY:
        keys = _block_map_keys(core)
        names = None if keys is None else _walker_matches_map_keys(events, keys)
    else:
        return None
    if not names or any(name not in {"push", "issues"} for name in names):
        return None
    return names


def issue_field_availability(content: str, field: str) -> EventSourceAvailability:
    """Return the bounded availability state for ``github.event.issue.FIELD``."""
    return IssueContextAvailability(content).issue_field(field)


class IssueContextAvailability:
    """One lazily-created per-file profile for the supported issue fields."""

    def __init__(self, content: str) -> None:
        self._triggers = _explicit_trigger_names(content)
        self._content = content
        self._owner_events: list[Event] | None = None

    def issue_field(self, field: str) -> EventSourceAvailability:
        """Classify a supported issue field without generalizing other paths."""
        if field not in _SUPPORTED_ISSUE_FIELDS:
            return EventSourceAvailability.UNKNOWN
        triggers = self._triggers
        if triggers is None or not triggers:
            return EventSourceAvailability.UNKNOWN
        if triggers == ("push",):
            return EventSourceAvailability.ABSENT
        if "issues" in triggers:
            return EventSourceAvailability.MAY_BE_PRESENT
        return EventSourceAvailability.UNKNOWN

    def issue_field_at(self, field: str, owner_path: tuple[object, ...]) -> EventSourceAvailability:
        """Classify issue availability using this candidate's owning guards."""
        base = self.issue_field(field)
        if base is not EventSourceAvailability.MAY_BE_PRESENT:
            return base
        try:
            return self._issue_field_at_proven_owner(owner_path, base)
        except Exception:
            # Pattern predicates treat exceptions as a miss. Preserve the
            # candidate whenever an ownership proof cannot be completed.
            return base

    def _issue_field_at_proven_owner(
        self,
        owner_path: tuple[object, ...],
        base: EventSourceAvailability,
    ) -> EventSourceAvailability:
        if self._owner_events is None:
            self._owner_events = list(
                walk_workflow(
                    "workflow.yml",
                    content=self._content,
                    include_keys=True,
                    include_merge_origins=True,
                )
            )
        events = self._owner_events
        # Any structural ambiguity can hide an owner or guard, so keep the
        # source candidate. YAML aliases/merges also obscure direct ownership.
        if any(
            event.kind in {EventKind.ERROR, EventKind.CUTOFF} or event.merge_origins
            for event in events
        ) or _contains_alias_or_anchor(self._content):
            return base
        if (
            len(owner_path) != 5
            or owner_path[0] != "jobs"
            or not isinstance(owner_path[1], str)
            or owner_path[2] != "steps"
            or not isinstance(owner_path[3], int)
            or owner_path[4] not in {"run", "script"}
        ):
            return base
        job_path = owner_path[:2]
        step_path = owner_path[:4]
        structural_paths = [("jobs",), job_path, job_path + ("steps",)]
        if owner_path[4] == "run":
            structural_paths.append(owner_path)
        for structural_path in structural_paths:
            if (
                sum(
                    event.kind is EventKind.MAP_KEY and event.path == structural_path
                    for event in events
                )
                != 1
            ):
                return base
        guard_values: list[str | None] = []
        for path in (job_path, step_path):
            keys = [
                event
                for event in events
                if event.kind is EventKind.MAP_KEY and event.path == path + ("if",)
            ]
            values = [
                event
                for event in events
                if event.kind is EventKind.LEAF_SCALAR and event.path == path + ("if",)
            ]
            if len(keys) > 1 or (keys and len(values) != 1):
                return base
            if keys:
                if values[0].value is None or values[0].value_kind not in {"plain", "quoted"}:
                    return base
                if values[0].value.strip().casefold() in {"", "null", "~"}:
                    return base
                guard_values.append(values[0].value)
        if not guard_values:
            return base
        # Push lacks the issue root, so only the issues invocation must be
        # excluded by this candidate's owning conditions.
        if any(event_guard_verdict(guard, "issues") is False for guard in guard_values):
            return EventSourceAvailability.ABSENT
        return base

    def script_owner_at_line(self, line: int) -> tuple[object, ...] | None:
        """Return a unique direct github-script owner for a physical line."""
        try:
            return self._script_owner_at_line(line)
        except Exception:
            return None

    def _script_owner_at_line(self, line: int) -> tuple[object, ...] | None:
        if self._owner_events is None:
            self._owner_events = list(
                walk_workflow(
                    "workflow.yml",
                    content=self._content,
                    include_keys=True,
                    include_merge_origins=True,
                )
            )
        events = self._owner_events
        if any(
            event.kind in {EventKind.ERROR, EventKind.CUTOFF} or event.merge_origins
            for event in events
        ) or _contains_alias_or_anchor(self._content):
            return None
        line_owners: set[tuple[object, ...] | None] = set()
        for item in events:
            if item.kind not in {EventKind.LEAF_SCALAR, EventKind.MAP_KEY}:
                continue
            source_lines = {item.line}
            if item.block_lines:
                source_lines.update(source_line for source_line, _ in item.block_lines)
            if line not in source_lines:
                continue
            path = item.path
            step_owner = (
                path[:4]
                if len(path) >= 4
                and path[0] == "jobs"
                and isinstance(path[1], str)
                and path[2] == "steps"
                and isinstance(path[3], int)
                else None
            )
            line_owners.add(step_owner)
        if len(line_owners) != 1:
            return None
        owners: set[tuple[object, ...]] = set()
        for event in events:
            if event.kind is not EventKind.LEAF_SCALAR or event.path[-1:] != ("script",):
                continue
            source_lines = {event.line}
            if event.block_lines:
                source_lines.update(source_line for source_line, _ in event.block_lines)
            if line not in source_lines:
                continue
            script_path = event.path
            if (
                len(script_path) != 6
                or script_path[0] != "jobs"
                or not isinstance(script_path[1], str)
                or script_path[2] != "steps"
                or not isinstance(script_path[3], int)
                or script_path[4:] != ("with", "script")
            ):
                continue
            step_path = script_path[:4]
            job_path = script_path[:2]
            structural_paths = (
                ("jobs",),
                job_path,
                job_path + ("steps",),
                step_path + ("with",),
            )
            if any(
                sum(
                    item.kind is EventKind.MAP_KEY and item.path == structural_path
                    for item in events
                )
                != 1
                for structural_path in structural_paths
            ):
                continue
            if (
                sum(item.kind is EventKind.MAP_KEY and item.path == script_path for item in events)
                != 1
                or sum(
                    item.kind is EventKind.LEAF_SCALAR and item.path == script_path
                    for item in events
                )
                != 1
            ):
                continue
            uses_path = step_path + ("uses",)
            uses = [
                item
                for item in events
                if item.kind is EventKind.LEAF_SCALAR and item.path == uses_path
            ]
            uses_keys = [
                item for item in events if item.kind is EventKind.MAP_KEY and item.path == uses_path
            ]
            if (
                len(uses) == 1
                and len(uses_keys) == 1
                and uses[0].value is not None
                and uses[0]
                .value.strip()
                .startswith(("actions/github-script@", "actions/github-script/"))
            ):
                owners.add(step_path + ("script",))
        return next(iter(owners)) if len(owners) == 1 else None

    def issue_field_at_script_line(self, field: str, line: int) -> EventSourceAvailability:
        base = self.issue_field(field)
        if base is not EventSourceAvailability.MAY_BE_PRESENT:
            return base
        owner = self.script_owner_at_line(line)
        if owner is None:
            return base
        return self.issue_field_at(field, owner)


def _contains_alias_or_anchor(content: str) -> bool:
    try:
        tokens = list(tokenize(content))
    except Exception:
        return True
    return any(
        token.kind in {TokenKind.ANCHOR, TokenKind.ALIAS, TokenKind.MERGE_KEY} for token in tokens
    )


def direct_issue_expression_paths(text: str) -> tuple[tuple[str, ...], str] | None:
    """Return direct issue-field expression paths and text outside expressions.

    Only fully delimited expressions that resolve to a direct issue-field AST
    path and reference only that field are eligible. Parser-supported exact
    ``fromJSON(toJSON(...))`` round trips may canonicalize to that path.
    Fallbacks, other calls, dynamic access, compound expressions, and
    unfinished expressions return ``None`` so callers retain their finding.
    """
    spans: list[tuple[int, int, str]] = []
    cursor = 0
    while True:
        start = text.find("${{", cursor)
        if start < 0:
            break
        index = start + 3
        in_string = False
        while index < len(text):
            if in_string:
                if text[index] == "'":
                    if index + 1 < len(text) and text[index + 1] == "'":
                        index += 2
                        continue
                    in_string = False
                index += 1
                continue
            if text[index] == "'":
                in_string = True
                index += 1
                continue
            if text.startswith("}}", index):
                spans.append((start, index + 2, text[start + 3 : index]))
                cursor = index + 2
                break
            index += 1
        else:
            return None

    if not spans:
        return None

    paths: list[str] = []
    outside: list[str] = []
    cursor = 0
    for start, end, body in spans:
        outside.append(text[cursor:start])
        try:
            expression = parse(body)
            path = canonical_path(expression)
            references = context_paths(body)
        except ExprSyntaxError:
            return None
        if path not in {"github.event.issue.title", "github.event.issue.body"}:
            return None
        if references != [path]:
            return None
        paths.append(path)
        cursor = end
    outside.append(text[cursor:])
    return tuple(paths), "".join(outside)


__all__ = [
    "EventSourceAvailability",
    "IssueContextAvailability",
    "direct_issue_expression_paths",
    "issue_field_availability",
]

"""Conservative availability facts for selected GitHub event fields.

This module intentionally proves only one absence fact: an explicit,
unambiguous ``push``-only workflow does not provide ``github.event.issue.title``
or ``github.event.issue.body``. GitHub documents missing context properties as
empty strings and the push payload without an issue root; see
https://docs.github.com/en/actions/reference/workflows-and-actions/contexts and
https://docs.github.com/en/webhooks/webhook-events-and-payloads#push.

Every other event/field pair remains unknown. This is source availability,
not a claim about runtime execution or exploitability.
"""

from __future__ import annotations

import re
from enum import Enum

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


def direct_issue_expression_paths(text: str) -> tuple[tuple[str, ...], str] | None:
    """Return direct issue-field expression paths and text outside expressions.

    Only fully delimited direct AST paths are eligible. Fallbacks, calls,
    dynamic access, compound expressions, and unfinished expressions return
    ``None`` so callers retain their existing finding.
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

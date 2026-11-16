"""Recognize literal checkout script references in a CodeBuild Bash profile."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenizerError, TokenKind, tokenize

_PHASES = {"install", "pre_build", "build", "post_build"}
_PART = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
_SOURCE = re.compile(
    rf"""(?:[A-Za-z_][A-Za-z0-9_]*=(?:[-A-Za-z0-9_./]+|"[-A-Za-z0-9_./=]+")[ \t]+)*"""
    rf"nix[ \t]+develop[ \t]+\.\#{_PART}[ \t]+--command[ \t]+bash[ \t]+-c[ \t]+"
    rf"'(?:source|\.)[ \t]+\./(?P<path>(?:{_PART}/)*{_PART})"
    r"(?:[ \t]+&&[ \t]+[A-Za-z_][A-Za-z0-9_-]*)*[ \t]*'"
)
_MAX_REFERENCES = 8
_MAX_COMMAND_LENGTH = 2048


@dataclass(frozen=True)
class CheckoutScriptReference:
    phase: str
    command_index: int
    line: int
    column: int
    path: str


def unambiguous_checkout_events(path: str, content: str) -> list[Event]:
    """Read source ownership without admitting aliases or ambiguous keys."""
    events = list(walk_workflow(path, content=content, include_keys=True))
    if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
        return []
    for kind in (EventKind.MAP_KEY, EventKind.LEAF_SCALAR):
        counts = Counter(event.path for event in events if event.kind is kind)
        if any(count != 1 for count in counts.values()):
            return []
    try:
        if any(
            token.kind in {TokenKind.ALIAS, TokenKind.MERGE_KEY}
            or (token.kind is TokenKind.KEY and "\\" in token.value)
            for token in tokenize(content)
        ):
            return []
    except TokenizerError:
        return []
    return events


def checkout_script_references(path: str, content: str) -> tuple[CheckoutScriptReference, ...]:
    """Find configured relative source operands, independent of runtime shell state."""
    events = unambiguous_checkout_events(path, content)
    leaves = [event for event in events if event.kind is EventKind.LEAF_SCALAR]
    values = {event.path: event.value for event in leaves}
    if values.get(("version",)) != "0.2" or values.get(("env", "shell")) != "bash":
        return ()

    references = []
    lines = content.splitlines()
    for event in leaves:
        owner = event.path
        if (
            len(owner) != 4
            or owner[0] != "phases"
            or owner[1] not in _PHASES
            or owner[2] != "commands"
            or type(owner[3]) is not int
            or event.value_kind != "plain"
            or not event.value
            or len(event.value) > _MAX_COMMAND_LENGTH
            or not 0 < event.line <= len(lines)
        ):
            continue
        command = event.value
        raw = lines[event.line - 1]
        if (
            not re.fullmatch(r"[ \t]*-[ \t]+", raw[: event.column - 1])
            or raw[event.column - 1 :].rstrip() != command
        ):
            continue
        match = _SOURCE.fullmatch(command)
        if match:
            references.append(
                CheckoutScriptReference(
                    str(owner[1]), owner[3], event.line, event.column, match["path"]
                )
            )
            if len(references) > _MAX_REFERENCES:
                return ()
    return tuple(references)

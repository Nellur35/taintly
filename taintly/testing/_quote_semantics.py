"""Narrow source premise for a quote mutation that disables shell expansion.

This is not a detector or a general shell/YAML equivalence checker. Refusal
means the caller must retain the mutant. No rule identity is consulted.
"""

from __future__ import annotations

import re

from taintly.github_event_availability import _explicit_trigger_names
from taintly.parsers.structural import EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenizerError, TokenKind, tokenize

_EVENTS = frozenset(
    {
        "push",
        "pull_request",
        "pull_request_target",
        "workflow_dispatch",
        "workflow_run",
        "schedule",
    }
)
_RUNNERS = frozenset(
    {
        "ubuntu-latest",
        "ubuntu-22.04",
        "ubuntu-24.04",
        "macos-latest",
        "macos-14",
        "macos-15",
    }
)
_PATH = r"[A-Za-z0-9_./-]+"
_PRINTF = re.compile(
    r"(?P<prefix>[ \t]*printf[ \t]+)'(?P<fmt>[^'\"$`\\\r\n]*(?:\\n[^'\"$`\\\r\n]*)*)'"
    r"(?P<gap>[ \t]+)(?P<quote>['\"])(?P<var>\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\}))"
    r"(?P=quote)(?P<tail>(?:[ \t]+>[ \t]*" + _PATH + r")?[ \t]*)"
)
_MKDIR = re.compile(r"[ \t]*mkdir[ \t]+-p[ \t]+" + _PATH + r"[ \t]*")


def _snapshot(source: str):
    try:
        if not _explicit_trigger_names(source, supported_events=_EVENTS):
            return None
        tokens = tuple(tokenize(source))
        if any(t.kind in {TokenKind.ANCHOR, TokenKind.ALIAS, TokenKind.MERGE_KEY} for t in tokens):
            return None
        events = tuple(
            walk_workflow(
                "workflow.yml",
                content=source,
                recover=True,
                include_keys=True,
                include_merge_origins=True,
            )
        )
    except (ValueError, RecursionError, TokenizerError):
        return None
    keys = set()
    leaves = {}
    runs = {}
    for event in events:
        if event.kind in {EventKind.ERROR, EventKind.CUTOFF} or event.merge_origins:
            return None
        if event.kind is EventKind.MAP_KEY:
            if event.path in keys:
                return None
            keys.add(event.path)
            # Intentionally refuse even unrelated defaults/container settings.
            if event.path[-1:] in {("defaults",), ("container",)}:
                return None
        elif event.kind is EventKind.LEAF_SCALAR:
            if event.path in leaves:
                return None
            if not isinstance(event.value, str):
                return None
            leaves[event.path] = (event.value, event.value_kind)
            path = event.path
            if (
                len(path) == 5
                and path[0] == "jobs"
                and isinstance(path[1], str)
                and path[2] == "steps"
                and isinstance(path[3], int)
                and path[4] == "run"
            ):
                if event.value_kind != "block_literal" or not event.block_lines:
                    return None
                runs[path] = tuple(text for _line, text in event.block_lines)
            elif event.value_kind == "quoted" and any(c in event.value for c in "\\'\""):
                # The structural reader does not establish all YAML escape
                # equivalences. Never equate such quoted non-run values.
                return None
    if ("jobs",) not in keys or not runs:
        return None
    return keys, leaves, runs


def _owned_shell(snapshot, path) -> bool:
    keys, leaves, _runs = snapshot
    step = path[:-1]
    if any(path[:depth] not in keys for depth in (1, 2, 3, 5)):
        return False
    if step + ("uses",) in keys:
        return False
    if any(len(p) > len(path) and p[: len(path)] == path for p in keys | leaves.keys()):
        return False
    runner = ("jobs", path[1], "runs-on")
    if runner not in leaves or leaves[runner][0] not in _RUNNERS:
        return False
    if any(len(p) > len(runner) and p[: len(runner)] == runner for p in keys | leaves.keys()):
        return False
    shell = step + ("shell",)
    if shell not in keys:
        return True  # Known hosted Linux/macOS default Bash profile.
    return (
        shell in leaves
        and leaves[shell][0] in {"bash", "sh"}
        and not any(len(p) > len(shell) and p[: len(shell)] == shell for p in keys | leaves.keys())
    )


def _script_pair(before, after) -> bool:
    if len(before) != len(after):
        return False
    saw_printf = False
    changed = False
    for left, right in zip(before, after, strict=True):
        if left == right and (not left.strip() or left.lstrip().startswith("#")):
            continue
        if left == right and not saw_printf and _MKDIR.fullmatch(left):
            continue
        a, b = _PRINTF.fullmatch(left), _PRINTF.fullmatch(right)
        if saw_printf or a is None or b is None:
            return False
        saw_printf = True
        fmt = a.group("fmt")
        if (
            fmt.startswith("-")
            or fmt.count("%s") != 1
            or "%" in fmt.replace("%s", "")
            or any(ord(c) < 32 or ord(c) > 126 for c in fmt)
        ):
            return False
        if any(a.group(k) != b.group(k) for k in ("prefix", "fmt", "gap", "var", "tail")):
            return False
        if a.group("quote") != '"' or b.group("quote") != "'":
            return False
        changed = True
    return saw_printf and changed


def invalidates_owned_printf_expansion(original: str, mutated: str) -> bool:
    """True only for a proved double-to-single variable-argument change.

    False includes unsupported/ambiguous sources; the caller keeps those
    mutants. Static format quote changes are deliberately not excluded.
    """
    before, after = _snapshot(original), _snapshot(mutated)
    if before is None or after is None:
        return False
    bk, bl, br = before
    ak, al, ar = after
    if bk != ak or bl.keys() != al.keys() or br.keys() != ar.keys():
        return False
    changed = [path for path in br if br[path] != ar[path]]
    if len(changed) != 1:
        return False
    path = changed[0]
    if any(bl[p] != al[p] for p in bl if p != path):
        return False
    return (
        _owned_shell(before, path)
        and _owned_shell(after, path)
        and _script_pair(br[path], ar[path])
    )

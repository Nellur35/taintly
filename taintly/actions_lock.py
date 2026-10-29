"""Bounded, source-bound evidence for GitHub Actions workflow lockfiles.

Only the documented v0.0.2/v0.0.3 direct workflow/dependency shape is supported.
Unknown formats, ambiguous keys, and unavailable source leave the original
mutable-reference finding in place.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

from .models import IncompletePatternMatches
from .parsers.structural import EventKind, walk_workflow

_SOURCE_USES = re.compile(
    r"^\s*(?:-\s*)?uses:\s*(?P<quote>['\"]?)(?P<value>[^\s'\"]+)(?P=quote)\s*(?:#.*)?$"
)
_COMMIT = re.compile(r"sha1-[0-9a-fA-F]{40}\Z")
_POSITIVE_ID = re.compile(r"[1-9][0-9]*\Z")
_MAX_LOCK_BYTES = 2_000_000


class _Pattern(Protocol):
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]: ...


def _direct_uses(content: str, lines: list[str], filepath: str, line: int) -> str | None:
    """Require a physical direct scalar at the candidate's own source line."""
    if line < 1 or line > len(lines):
        return None
    physical = _SOURCE_USES.fullmatch(lines[line - 1])
    if physical is None:
        return None
    value = physical.group("value")
    events = tuple(walk_workflow(filepath, content=content))
    if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
        return None
    matches = [
        event
        for event in events
        if event.kind is EventKind.LEAF_SCALAR
        and event.line == line
        and event.path
        and event.path[-1] == "uses"
        and event.value == value
    ]
    return value if len(matches) == 1 else None


def _lock_evidence(filepath: str, reference: str) -> bool:
    source = Path(filepath)
    if source.parent.name != "workflows" or source.parent.parent.name != ".github":
        return False
    if source.is_symlink() or source.parent.is_symlink() or source.parent.parent.is_symlink():
        return False
    lock = source.parent / "actions.lock"
    try:
        if lock.is_symlink() or not lock.is_file() or lock.stat().st_size > _MAX_LOCK_BYTES:
            return False
        text = lock.read_bytes().decode("utf-8")
    except (OSError, UnicodeError):
        return False
    events = tuple(walk_workflow(str(lock), content=text, include_keys=True))
    if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
        return False
    workflow = f".github/workflows/{source.name}"
    ref = reference.rpartition("@")[2]
    version = []
    workflow_keys = 0
    dependency_keys = 0
    listed: list[int] = []
    fields: dict[str, list[str]] = {}
    for event in events:
        path = event.path
        if event.kind is EventKind.MAP_KEY:
            if path == ("workflows", workflow):
                workflow_keys += 1
            elif path == ("dependencies", reference):
                dependency_keys += 1
        elif event.kind is EventKind.LEAF_SCALAR:
            if path == ("version",) and event.value is not None:
                version.append(event.value)
            elif len(path) == 3 and path[:2] == ("workflows", workflow):
                if isinstance(path[2], int) and event.value == reference:
                    listed.append(event.line)
            elif len(path) == 3 and path[:2] == ("dependencies", reference):
                if isinstance(path[2], str) and event.value is not None:
                    fields.setdefault(path[2], []).append(event.value)
    if version not in (["v0.0.2"], ["v0.0.3"]) or workflow_keys != 1 or dependency_keys != 1:
        return False
    if len(listed) != 1:
        return False
    required = ("ref", "commit", "owner_id", "repo_id")
    if any(len(fields.get(field, [])) != 1 for field in required):
        return False
    if fields["ref"][0] != ref or not _COMMIT.fullmatch(fields["commit"][0]):
        return False
    if version == ["v0.0.2"] and "hostname" in fields:
        return False
    if "hostname" in fields and fields["hostname"] != ["github.com"]:
        return False
    return all(_POSITIVE_ID.fullmatch(fields[field][0]) for field in ("owner_id", "repo_id"))


class ActionsLockAwarePattern:
    """Filter mutable-ref findings only with exact on-disk lockfile evidence."""

    def __init__(self, pattern: _Pattern) -> None:
        self._pattern = pattern

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        return self._pattern.check(content, lines)

    def check_with_filepath(
        self, content: str, lines: list[str], filepath: str
    ) -> list[tuple[int, str]]:
        candidates = self._pattern.check(content, lines)
        if isinstance(candidates, IncompletePatternMatches):
            # Preserve the scanner's coverage state. Partial matches are not
            # evidence that a missing reference was safely locked.
            return candidates
        try:
            source_agrees = Path(filepath).read_text(encoding="utf-8") == content
        except (OSError, UnicodeError):
            source_agrees = False
        if not source_agrees:
            return candidates
        remaining: list[tuple[int, str]] = []
        for line, snippet in candidates:
            reference = _direct_uses(content, lines, filepath, line)
            if reference is None or not _lock_evidence(filepath, reference):
                remaining.append((line, snippet))
        return remaining

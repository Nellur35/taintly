"""Conservative recognition of literal local-file command invocations."""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass

_INTERPRETERS = frozenset({"bash", "sh", "python", "python3", "node"})
_STATIC_LOCAL_PATH = re.compile(r"(?:\.{1,2}/)?[A-Za-z0-9._/-]+\Z")
_SHELL_META = re.compile(r"[\n\r;&|<>`$*?\[\]{}()]")


@dataclass(frozen=True)
class LocalFileInvocation:
    """A statically recognizable interpreter or direct local-file command."""

    command: str
    operand: str
    normalized_operand: str
    interpreter: str | None


def recognize_local_file_invocation(value: str) -> LocalFileInvocation | None:
    """Recognize one literal local-file invocation without evaluating shell code.

    The command must be a single decoded YAML scalar containing one direct
    invocation. Wrappers, shell operators, expansions, interpreter modes that
    do not name a file, and stdin execution stay outside this recognizer.
    """

    command = value.strip()
    if not command or _SHELL_META.search(command):
        return None
    try:
        words = shlex.split(command, posix=True, comments=True)
    except ValueError:
        return None
    if not words or not words[0]:
        return None

    interpreter: str | None = None
    operand_index = 0
    if words[0] in _INTERPRETERS:
        interpreter = words[0]
        if len(words) < 2 or words[1].startswith("-"):
            return None
        operand_index = 1
    elif not words[0].startswith("./"):
        return None

    operand = words[operand_index]
    if (
        operand.startswith("/")
        or not _STATIC_LOCAL_PATH.fullmatch(operand)
        or operand in {".", "..", "./", "../"}
    ):
        return None
    normalized = posixpath.normpath(operand)
    if normalized in {".", ".."}:
        return None

    # Any remaining words are static arguments. Reject option-like operands
    # above, while preserving safe arguments after the local file path.
    if any(not word or _SHELL_META.search(word) for word in words[operand_index + 1 :]):
        return None
    return LocalFileInvocation(
        command=command,
        operand=operand,
        normalized_operand=normalized,
        interpreter=interpreter,
    )

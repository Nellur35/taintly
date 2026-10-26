"""Bounded npm command and directory facts shared by CI provider rules."""

from __future__ import annotations

import posixpath
import re
import shlex

_NPM_START = re.compile(r"^\s*npm\s+(install|publish)\b")
_NPM_PUBLISH_ANY = re.compile(r"\bnpm\s+publish\b")
_SHELL_CONTROL = re.compile(r"[;&|<>\x60]|\$\(")
_SHELL_FLOW = re.compile(r"^\s*(?:if|then|else|elif|fi|case|esac|for|while|until|do|done)\b")
_SHELL_INDIRECTION = re.compile(r"<<|^\s*(?:function\s+\w+|\w+\s*\(\s*\)\s*\{|[{}]\s*$)")
_CWD_CHANGE = re.compile(r"^\s*(?:(?:cd|pushd|popd|source|eval)\b|\.\s+)")


def _directory(value: str) -> str | None:
    """Resolve a literal workspace-relative POSIX directory, or stay unknown."""
    candidate = value.strip()
    if not candidate or "$" in candidate or "\x60" in candidate:
        return None
    if candidate.startswith("/") or "\\" in candidate:
        return None
    result = posixpath.normpath(candidate)
    if result == ".." or result.startswith("../"):
        return None
    return result


def _classify_command(text: str) -> tuple[str, str | None] | None:
    """Return (verb, literal prefix) for a standalone npm install or publish."""
    match = _NPM_START.match(text)
    if not match:
        return None
    if _SHELL_CONTROL.search(text):
        return match.group(1), None
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        return match.group(1), None
    if len(tokens) < 2 or tokens[:2] != ["npm", match.group(1)]:
        return None
    if any(token in {"-g", "--global", "--package-lock-only", "--dry-run"} for token in tokens[2:]):
        return None
    prefix = "."
    for i, token in enumerate(tokens[2:], 2):
        if token == "--prefix":
            if i + 1 >= len(tokens):
                return match.group(1), None
            prefix = tokens[i + 1]
        elif token.startswith("--prefix="):
            prefix = token.partition("=")[2]
        elif token in {"--workspace", "-w"} or token.startswith("--workspace="):
            return match.group(1), None
    return match.group(1), _directory(prefix)

"""Regex-based shell-body recovery for Jenkinsfiles that tree-sitter
can't parse.

tree-sitter-groovy 0.1.2 has known parse failures on common Groovy
shapes — untyped ``def f(a, b) { ... }``, ``def f()`` with no
parameters, and the Elvis operator (``?:``) inside named arguments.
On real-world Jenkinsfiles that use these constructs (cassandra's
``.jenkins/Jenkinsfile`` is 100% ERROR-covered), the walker recovers
only a fraction of the actual ``sh '...'`` / ``bat '...'`` /
``powershell '...'`` invocations.

This fallback runs ONLY when the walker reports
``error_byte_ratio > _ERROR_RATIO_THRESHOLD`` and supplements the
walker's events with shell-body LEAFs found via a regex pass.  The
regex pass:

* Computes a Groovy code/string/comment mask (mirrors
  :func:`taintly.jenkinsguard._groovy_code_mask`) so the call name
  must start in CODE position — ``sh`` mentioned inside a string
  literal or a ``//`` comment is rejected.
* De-duplicates against the walker's existing LEAFs by (line, value).
* Emits each event with ``degraded=True`` so consumers can choose
  whether to act on them.

The fallback is intentionally restrictive: it covers the high-signal
single-, double-, and triple-quoted shell bodies and skips everything
else.  Better to miss a complex shape than to emit a string-internal
match.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from .events import Event, EventKind

# Walker invocation triggers the fallback when ``error_byte_ratio``
# exceeds this fraction.  At 0.5, jenkins.io / maven / jcasc (all
# under 33% error) skip the fallback entirely; cassandra (100%
# error) gets the lift.  Tuned conservatively to avoid double-walking
# files where the structural reader already captured most events.
_ERROR_RATIO_THRESHOLD: float = 0.5

# Shell call names whose first string argument is a shell body.
_SHELL_CALL_NAMES: frozenset[str] = frozenset({"sh", "bat", "powershell"})

# Compiled patterns.  Each anchors on a shell call name at a word
# boundary and captures the (quoted) body via the alternation:
#
#   triple-single | triple-double | single | double
#
# Order matters — triple variants must precede single-quote variants
# so ``'''…'''`` doesn't get truncated at the first inner ``'``.
_SHELL_CALL_RE = re.compile(
    r"\b(?P<call>sh|bat|powershell)\b"
    r"\s*\(?"  # optional ``(`` for parenthesised form
    r"\s*"
    r"(?:"
    r"'''(?P<triple_single>.*?)'''"
    r"|\"\"\"(?P<triple_double>.*?)\"\"\""
    r"|'(?P<single>(?:[^'\\\n]|\\.)*)'"
    r"|\"(?P<double>(?:[^\"\\\n]|\\.)*)\""
    r")",
    re.DOTALL,
)


def error_byte_ratio(root: Any) -> float:
    """Return ``error_bytes / total_bytes`` for the parse tree rooted
    at ``root``.

    Walks the tree once, summing the byte span of every ``ERROR`` node.
    Used by the walker to decide whether to invoke the regex fallback.
    """
    total = max(int(root.end_byte - root.start_byte), 1)
    return _sum_error_bytes(root) / total


def _sum_error_bytes(node: Any) -> int:
    if node.type == "ERROR":
        return int(node.end_byte - node.start_byte)
    return sum(_sum_error_bytes(c) for c in node.children)


def regex_fallback_leaves(
    content: str, *, exclude_keys: set[tuple[int, str]] | None = None
) -> Iterator[Event]:
    """Emit shell-body LEAF events from a regex scan of ``content``.

    Args:
        content: Jenkinsfile source as a string.
        exclude_keys: optional set of ``(line, value)`` tuples to skip
            — used by callers that already have walker output and
            want to suppress duplicates.

    Yields:
        :class:`Event` instances with ``kind=LEAF``, ``value_kind="shell"``,
        and ``degraded=True``.  ``path`` is ``("?", call)`` to mark the
        enclosing scope as unknown (the regex can't see structural
        nesting).
    """
    seen = exclude_keys if exclude_keys is not None else set()
    code_mask = _groovy_code_mask(content)
    for match in _SHELL_CALL_RE.finditer(content):
        # The call name's first character must start in CODE position.
        # If ``sh`` is itself inside a string or comment, skip — it's
        # a false positive (e.g., ``echo 'sh "hi"'``).
        start = match.start("call")
        if not code_mask[start]:
            continue
        # Word-boundary safety: an upstream prefix would have caused
        # \b to fail, but defend against ``ash`` / ``bash`` / ``pwsh``
        # explicitly because tree-sitter-groovy 0.1.2 ERROR-recovery
        # can produce overlapping token boundaries the regex engine
        # accepts.
        if start > 0 and (content[start - 1].isalnum() or content[start - 1] == "_"):
            continue
        # Extract the captured body — exactly one of the four groups
        # is non-None per match.
        body = (
            match.group("triple_single")
            or match.group("triple_double")
            or match.group("single")
            or match.group("double")
            or ""
        )
        line = content[: match.start("call")].count("\n") + 1
        key = (line, body)
        if key in seen:
            continue
        seen.add(key)
        yield Event(
            kind=EventKind.LEAF,
            path=("?", match.group("call")),
            value=body,
            value_kind="shell",
            line=line,
            detail="regex-fallback",
            degraded=True,
        )


def _groovy_code_mask(content: str) -> list[bool]:
    """Parallel ``list[bool]`` flagging code positions.

    Mirrors :func:`taintly.jenkinsguard._groovy_code_mask` — a
    standalone copy is kept here to keep the parser package
    self-contained (the parser must not import jenkinsguard, which
    is a higher-layer module).

    ``True`` means "this character is in Groovy code position";
    ``False`` means "inside a string literal, ``//`` line comment,
    or ``/* */`` block comment."
    """
    n = len(content)
    mask = [True] * n
    i = 0
    while i < n:
        ch = content[i]
        if ch == "/" and i + 1 < n:
            nxt = content[i + 1]
            if nxt == "/":
                end = content.find("\n", i)
                if end == -1:
                    end = n
                for k in range(i, end):
                    mask[k] = False
                i = end
                continue
            if nxt == "*":
                end = content.find("*/", i + 2)
                end = n if end == -1 else end + 2
                for k in range(i, end):
                    mask[k] = False
                i = end
                continue
        if ch in ("'", '"'):
            quote = ch
            triple = content.startswith(ch * 3, i)
            if triple:
                end_marker = quote * 3
                end = content.find(end_marker, i + 3)
                end = n if end == -1 else end + 3
            else:
                j = i + 1
                while j < n:
                    if content[j] == "\\" and j + 1 < n:
                        j += 2
                        continue
                    if content[j] == quote:
                        j += 1
                        break
                    if content[j] == "\n":
                        break
                    j += 1
                end = j
            for k in range(i, end):
                mask[k] = False
            i = end
            continue
        i += 1
    return mask

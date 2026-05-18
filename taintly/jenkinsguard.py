"""Conservative Jenkins Declarative Pipeline stage evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class GuardVerdict(Enum):
    LIVE = "live"
    DEAD = "dead"
    RUNTIME = "runtime"


@dataclass(frozen=True)
class JenkinsContext:
    """Pipeline context for context-aware Jenkins ``when`` evaluation.

    The ``parameter_values`` field exists for extensibility: when
    populated with the actual build-parameter values, an evaluator
    could resolve ``when { expression { return params.FOO == 'bar' } }``
    against the live values.  The engine does not currently populate
    this field on the scan path; conservatism therefore applies and
    only literal ``when { expression { return false } }`` (and the
    ``not { expression { return true } }`` variant) suppress.  Populate
    when corpus evidence demands context-aware suppression and a
    concrete source for the parameter values is settled.
    """

    parameter_values: dict[str, str] | None = None


def evaluate_jenkins_when(
    stage: dict[str, object], ctx: JenkinsContext | None = None
) -> GuardVerdict:
    del ctx
    when_block = stage.get("when")
    if when_block is None:
        return GuardVerdict.LIVE
    if not isinstance(when_block, str):
        return GuardVerdict.RUNTIME
    if is_literal_false_when(when_block):
        return GuardVerdict.DEAD
    return GuardVerdict.RUNTIME


def is_literal_false_when(when_block: str) -> bool:
    body = _normalize_when_body(when_block)
    return bool(
        re.fullmatch(r"expression\s*\{\s*(?:return\s+)?false\s*;?\s*\}", body)
        or re.fullmatch(
            r"not\s*\{\s*expression\s*\{\s*(?:return\s+)?true\s*;?\s*\}\s*\}",
            body,
        )
    )


def find_dead_jenkins_stage_ranges(
    content: str, ctx: JenkinsContext | None = None
) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    line_starts = _line_starts(content)
    for stage_start, stage_end in _stage_blocks(content):
        stage_body = content[stage_start:stage_end]
        when_block = _extract_when_block(stage_body)
        stage: dict[str, object] = {"when": when_block} if when_block is not None else {}
        if evaluate_jenkins_when(stage, ctx) is GuardVerdict.DEAD:
            ranges.append(
                (
                    _line_for(stage_start, line_starts),
                    _line_for(stage_end - 1, line_starts),
                )
            )
    return ranges


def is_jenkinsfile_whole_dead(content: str, ctx: JenkinsContext | None = None) -> bool:
    """Return ``True`` if every stage in the Jenkinsfile is statically dead.

    Walks the pipeline's stages, evaluates each stage's ``when`` block
    with :func:`evaluate_jenkins_when`, and returns ``True`` iff:

    1. The Jenkinsfile has at least one stage.
    2. Every stage evaluates to ``GuardVerdict.DEAD``.

    Pipelines without an explicit ``stages { ... }`` block (e.g.,
    scripted Groovy) return ``False`` — there is no structural
    enumeration target.
    """
    stages = list(_stage_blocks(content))
    if not stages:
        return False
    for stage_start, stage_end in stages:
        stage_body = content[stage_start:stage_end]
        when_block = _extract_when_block(stage_body)
        stage: dict[str, object] = {"when": when_block} if when_block is not None else {}
        if evaluate_jenkins_when(stage, ctx) is not GuardVerdict.DEAD:
            return False
    return True


def _normalize_when_body(when_block: str) -> str:
    body = when_block.strip()
    body = re.sub(r"\bbeforeAgent\s+(?:true|false)\s*;?", "", body)
    body = re.sub(r"\bbeforeInput\s+(?:true|false)\s*;?", "", body)
    body = re.sub(r"\bbeforeOptions\s+(?:true|false)\s*;?", "", body)
    return re.sub(r"\s+", " ", body).strip()


def _stage_blocks(content: str) -> list[tuple[int, int]]:
    """Find declarative-pipeline ``stage("name") { ... }`` blocks.

    Walks ``content`` directly, consulting the Groovy code/string mask
    to skip ``stage`` tokens that appear inside string literals or
    ``//`` / ``/* */`` comments.  Returns ``(start, end)`` byte ranges
    covering each ``stage(...) {...}`` block (inclusive of the
    ``stage`` keyword, exclusive of the byte after the closing
    brace).

    Done positionally rather than via ``re.finditer`` because a regex
    with non-greedy ``.*?`` can extend a match across a commented-out
    ``stage("Fake")`` and a later real ``stage("Real") {``.  The
    in-comment match position is rejected, but ``finditer`` then
    resumes past the (consumed) real stage — silently dropping it.
    """
    n = len(content)
    code_mask = _groovy_code_mask(content)
    blocks: list[tuple[int, int]] = []
    i = 0
    while i < n:
        idx = content.find("stage", i)
        if idx == -1:
            break
        if not code_mask[idx]:
            i = idx + 1
            continue
        if idx > 0 and (content[idx - 1].isalnum() or content[idx - 1] == "_"):
            i = idx + 1
            continue
        end_kw = idx + len("stage")
        if end_kw >= n or content[end_kw].isalnum() or content[end_kw] == "_":
            i = idx + 1
            continue
        j = end_kw
        while j < n and content[j] in " \t":
            j += 1
        if j >= n or content[j] != "(":
            i = idx + 1
            continue
        close_paren = _find_matching_paren(content, j, code_mask)
        if close_paren is None:
            i = idx + 1
            continue
        k = close_paren + 1
        while k < n and content[k] in " \t\r\n":
            k += 1
        if k >= n or content[k] != "{":
            i = idx + 1
            continue
        close_brace = _find_matching_brace(content, k)
        if close_brace is None:
            i = idx + 1
            continue
        blocks.append((idx, close_brace + 1))
        i = close_brace + 1
    return blocks


def _find_matching_paren(content: str, open_paren: int, code_mask: list[bool]) -> int | None:
    """Return the index of the ``)`` matching ``content[open_paren] == '('``.

    Parentheses inside string-literal or comment positions (per
    ``code_mask``) don't affect depth — that's how a ``stage("foo)bar")``
    name remains parsable.
    """
    depth = 0
    n = len(content)
    idx = open_paren
    while idx < n:
        ch = content[idx]
        if code_mask[idx]:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return idx
        idx += 1
    return None


def _groovy_code_mask(content: str) -> list[bool]:
    """Return a parallel ``list[bool]`` the size of ``content`` where
    ``True`` means "this character is in Groovy code position" and
    ``False`` means "this character is inside a string-literal or
    a ``//`` / ``/* */`` comment".

    Handles Groovy:
      - single-quoted ``'...'``
      - double-quoted ``"..."``
      - triple-single-quoted ``'''...'''``
      - triple-double-quoted ``\"\"\"...\"\"\"``
      - line comments ``// ... \\n``
      - block comments ``/* ... */``

    The opening delimiter of a string is considered IN-string (False)
    so ``stage("foo")`` shows the ``s`` of ``stage`` as code (True)
    and the ``"`` / ``foo`` / ``"`` as not-code (False).  This is the
    right granularity for "is this regex match starting in real
    code?" — the regex's anchor is the ``s`` of ``stage``, not the
    quote.
    """
    mask = [True] * len(content)
    i = 0
    n = len(content)
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
                if end == -1:
                    end = n
                else:
                    end += 2
                for k in range(i, end):
                    mask[k] = False
                i = end
                continue
        if ch in ("'", '"'):
            triple = content.startswith(ch * 3, i)
            quote = ch
            if triple:
                end_marker = quote * 3
                end = content.find(end_marker, i + 3)
                if end == -1:
                    end = n
                else:
                    end += 3
            else:
                j = i + 1
                while j < n:
                    if content[j] == "\\" and j + 1 < n:
                        j += 2
                        continue
                    if content[j] == quote:
                        j += 1
                        break
                    if content[j] == "\n" and not triple:
                        break
                    j += 1
                end = j
            for k in range(i, end):
                mask[k] = False
            i = end
            continue
        i += 1
    return mask


def _extract_when_block(stage_body: str) -> str | None:
    match = re.search(r"\bwhen\s*\{", stage_body)
    if match is None:
        return None
    open_brace = match.end() - 1
    close_brace = _find_matching_brace(stage_body, open_brace)
    if close_brace is None:
        return None
    return stage_body[open_brace + 1 : close_brace]


def _find_matching_brace(content: str, open_brace: int) -> int | None:
    depth = 0
    quote: str | None = None
    triple = False
    escaped = False
    idx = open_brace
    while idx < len(content):
        ch = content[idx]
        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif triple and content.startswith(quote * 3, idx):
                quote = None
                triple = False
                idx += 2
            elif not triple and ch == quote:
                quote = None
            idx += 1
            continue

        if ch in {"'", '"'}:
            quote = ch
            triple = content.startswith(ch * 3, idx)
            if triple:
                idx += 2
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
        idx += 1
    return None


def _line_starts(content: str) -> list[int]:
    starts = [0]
    for match in re.finditer(r"\n", content):
        starts.append(match.end())
    return starts


def _line_for(offset: int, starts: list[int]) -> int:
    line = 1
    for start in starts:
        if start > offset:
            break
        line += 1
    return line - 1

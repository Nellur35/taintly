"""Path-tracking walker for the structural CI YAML reader.

Consumes the tokenizer's output, maintains a key/index stack, and
emits a stream of high-level events.  Public event types (per the
Phase 1 contract):

  * ``LEAF_SCALAR`` — a scalar value at a fully-resolved path.
  * ``CUTOFF`` — the tokenizer hit an unsupported construct in
    ``recover=True`` mode; events for what was parsed before this
    point are valid, no further events follow.
  * ``ERROR`` — a recoverable parse-time problem the walker chose
    to surface but continue past (e.g., dangling alias).

ENTER_MAPPING / LEAVE_MAPPING / ENTER_SEQUENCE / LEAVE_SEQUENCE are
internal walker state and intentionally NOT exposed in Phase 1.
Phase 1.5 reconsiders if Phase 2 migrations need them.

Cutoff-recovery contract (load-bearing for the
``coverage warning`` exit-11 path):

  When ``recover=True`` and the tokenizer raises
  ``TokenizerError``, the walker yields events for every leaf it
  resolved BEFORE the cutoff line, then yields a single CUTOFF
  event whose ``line`` is the cutoff point's line number, then
  stops.  Consumers (rules) interpret CUTOFF as "structural
  coverage degraded for this file; my finding is
  could-not-evaluate, not no-finding-here".

Anchor merge-key behaviour: when a ``<<: *anchor`` reference
expands to a mapping, every merged leaf is emitted at the alias
line (not the anchor-definition line).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator, Optional

from .tokenizer import Token, TokenKind, TokenizerError, tokenize


class EventKind(Enum):
    LEAF_SCALAR = "leaf_scalar"
    CUTOFF = "cutoff"
    ERROR = "error"


@dataclass(frozen=True)
class Event:
    kind: EventKind
    path: tuple[object, ...]
    line: int
    column: int
    value: Optional[str] = None
    value_kind: Optional[str] = None
    message: Optional[str] = None


# ---------------------------------------------------------------------------
# Path glob matcher
# ---------------------------------------------------------------------------


_GLOB_INDEX_RE = re.compile(r"\[\*\]")


def _glob_to_segments(glob: str) -> list[str]:
    normalised = _GLOB_INDEX_RE.sub(".[*]", glob)
    return [s for s in normalised.split(".") if s]


def _path_match_recursive(
    path: tuple[object, ...], pi: int, segs: list[str], si: int
) -> bool:
    while si < len(segs) and pi < len(path):
        seg = segs[si]
        if seg == "**":
            if si + 1 == len(segs):
                return True
            for j in range(pi, len(path) + 1):
                if _path_match_recursive(path, j, segs, si + 1):
                    return True
            return False
        comp = path[pi]
        if seg == "*":
            if not isinstance(comp, str):
                return False
        elif seg == "[*]":
            if not isinstance(comp, int):
                return False
        else:
            if not (isinstance(comp, str) and fnmatch.fnmatchcase(comp, seg)):
                return False
        pi += 1
        si += 1
    while si < len(segs) and segs[si] == "**":
        si += 1
    return pi == len(path) and si == len(segs)


def _path_matches(path: tuple[object, ...], segments: list[str]) -> bool:
    return _path_match_recursive(path, 0, segments, 0)


# ---------------------------------------------------------------------------
# Walker
# ---------------------------------------------------------------------------


@dataclass
class _Frame:
    """One level of the active path stack.

    ``key``: for mapping levels, the key whose value the frame
    represents.  ``None`` for the implicit root and for sequence
    levels.
    ``indent``: the indent level whose KEY tokens belong to THIS
    frame (so a deeper-indent KEY pushes a child frame).
    ``container``: ``"mapping"`` or ``"sequence"``.
    ``next_index``: for sequence frames, the next free index.
    """

    key: object
    indent: int
    container: str
    next_index: int = 0


@dataclass
class _Anchor:
    """Captured leaves under an anchor.

    Each entry is ``(relative_path_from_anchor_root, value, value_kind, line_relative_to_anchor)``.
    When a ``<<: *anchor`` merge-key fires, leaves are replayed at
    the alias's line under the alias's current path.
    """

    leaves: list[tuple[tuple[object, ...], str, str]] = field(default_factory=list)
    root_indent: int = -1


def walk(
    content: str,
    *,
    query: Optional[str] = None,
    recover: bool = True,
) -> Iterator[Event]:
    glob_segments = _glob_to_segments(query) if query else None
    walker = _Walker(content, recover=recover)
    for ev in walker.run():
        if ev.kind != EventKind.LEAF_SCALAR or glob_segments is None:
            yield ev
            continue
        if _path_matches(ev.path, glob_segments):
            yield ev


class _Walker:
    """Walker with explicit indent-driven frame management.

    State machine:
      * On KEY at indent > top.indent: push a mapping frame keyed
        by the open key (if any), then save this KEY as the open
        one for indent.
      * On KEY at indent == top.indent: replace the frame's key
        (siblings of the previous key at this level).
      * On scalar value: emit a leaf for the open key, clear it.
      * On SEQUENCE_DASH: convert / open a sequence frame at this
        indent; reserve the next index; the next KEY at deeper
        indent nests under it.
      * On SCALAR_BLOCK_HEADER: open a buffer; subsequent
        SCALAR_BLOCK_LINE tokens accumulate; flush at next
        non-block token or EOF.
    """

    def __init__(self, content: str, *, recover: bool) -> None:
        self._content = content
        self._recover = recover
        self._stack: list[_Frame] = [
            _Frame(key=None, indent=-1, container="mapping")
        ]
        self._open_key: Optional[Token] = None
        # Block-scalar state.
        self._block_buffer: Optional[list[str]] = None
        self._block_anchor_line = 0
        self._block_path: tuple[object, ...] = ()
        # Anchor capture.
        self._anchors: dict[str, _Anchor] = {}
        self._capturing: Optional[str] = None
        self._capture_root_path_len = 0
        # Set immediately after a SEQUENCE_DASH: the next KEY (on
        # the same line as the dash) attaches to the element frame
        # regardless of its line-indent.  Cleared by the next
        # non-KEY non-COMMENT token.
        self._post_dash_attach: bool = False

    # ------------------------------------------------------------------

    def run(self) -> Iterator[Event]:
        try:
            tokens = list(tokenize(self._content))
        except TokenizerError as e:
            if not self._recover:
                raise
            yield Event(
                EventKind.CUTOFF, (), e.line, 1, message=str(e)
            )
            return

        # Group tokens by line so per-line semantics (e.g.
        # block-scalar header at end of line) are easy to detect.
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok.kind == TokenKind.EOF:
                if self._block_buffer is not None:
                    yield self._flush_block()
                break
            if tok.kind == TokenKind.COMMENT:
                i += 1
                continue
            if tok.kind == TokenKind.INDENT:
                # Block-scalar buffer ends when indent dips below
                # its anchor.
                if self._block_buffer is not None:
                    yield self._flush_block()
                self._adjust_to_indent(tok.indent)
                i += 1
                continue

            if tok.kind == TokenKind.SEQUENCE_DASH:
                self._enter_sequence(tok.indent)
                i += 1
                continue

            if tok.kind == TokenKind.KEY:
                yield from self._handle_key(tok)
                i += 1
                continue

            if tok.kind in (TokenKind.SCALAR_PLAIN, TokenKind.SCALAR_QUOTED):
                kind = "plain" if tok.kind == TokenKind.SCALAR_PLAIN else "quoted"
                ev = self._emit_value(tok, tok.value, kind)
                if ev is not None:
                    yield ev
                i += 1
                continue

            if tok.kind == TokenKind.SCALAR_BLOCK_HEADER:
                # Open a buffer; the path is the open-key's path.
                self._open_block_buffer(tok)
                i += 1
                continue

            if tok.kind == TokenKind.SCALAR_BLOCK_LINE:
                if self._block_buffer is not None:
                    self._block_buffer.append(tok.value)
                i += 1
                continue

            if tok.kind == TokenKind.ANCHOR:
                # Begin capture rooted at the current open-key's
                # path (or the current frame if no open key).
                name = tok.value.lstrip("&")
                self._capturing = name
                self._anchors[name] = _Anchor(
                    root_indent=tok.indent
                )
                self._capture_root_path_len = len(self._current_path())
                if self._open_key is not None:
                    self._capture_root_path_len += 1
                i += 1
                continue

            if tok.kind == TokenKind.MERGE_KEY:
                # ``<<:`` followed by an alias.
                j = i + 1
                while j < len(tokens) and tokens[j].kind in (
                    TokenKind.INDENT,
                    TokenKind.COMMENT,
                ):
                    j += 1
                if j < len(tokens) and tokens[j].kind == TokenKind.ALIAS:
                    name = tokens[j].value.lstrip("*")
                    anchor = self._anchors.get(name)
                    if anchor is None:
                        yield Event(
                            EventKind.ERROR,
                            self._current_path(),
                            tok.line,
                            tok.column,
                            message=f"unresolved merge alias: *{name}",
                        )
                    else:
                        # The merge key's effective path includes
                        # the surrounding open key (the key whose
                        # value is the merged mapping).  Push a
                        # frame for that open key so the replay
                        # base reflects what the maintainer
                        # actually wrote.
                        if (
                            self._open_key is not None
                            and tok.indent > self._open_key.indent
                        ):
                            self._stack.append(
                                _Frame(
                                    key=self._open_key.value,
                                    indent=tok.indent,
                                    container="mapping",
                                )
                            )
                            self._open_key = None
                        base = self._current_path()
                        for rel_path, value, value_kind in anchor.leaves:
                            full = base + rel_path
                            yield Event(
                                EventKind.LEAF_SCALAR,
                                full,
                                tok.line,
                                tok.column,
                                value=value,
                                value_kind=value_kind,
                            )
                    i = j + 1
                    continue
                yield Event(
                    EventKind.ERROR,
                    self._current_path(),
                    tok.line,
                    tok.column,
                    message="merge key not followed by an alias",
                )
                i += 1
                continue

            if tok.kind == TokenKind.ALIAS:
                yield Event(
                    EventKind.ERROR,
                    self._current_path(),
                    tok.line,
                    tok.column,
                    message=f"bare alias not expanded: {tok.value}",
                )
                i += 1
                continue

            if tok.kind in (
                TokenKind.FLOW_OPEN_SEQ,
                TokenKind.FLOW_OPEN_MAP,
            ):
                # Phase 1 flow handling: consume the bracketed run
                # and emit indexed/keyed leaves.
                yield from self._consume_flow(tokens, i)
                # Move past the matching close bracket.
                depth = 1 if tok.kind == TokenKind.FLOW_OPEN_SEQ else 1
                j = i + 1
                while j < len(tokens) and depth > 0:
                    k = tokens[j].kind
                    if k in (TokenKind.FLOW_OPEN_SEQ, TokenKind.FLOW_OPEN_MAP):
                        depth += 1
                    elif k in (TokenKind.FLOW_CLOSE_SEQ, TokenKind.FLOW_CLOSE_MAP):
                        depth -= 1
                    j += 1
                i = j
                continue

            i += 1

    # ------------------------------------------------------------------
    # Stack management
    # ------------------------------------------------------------------

    def _current_path(self) -> tuple[object, ...]:
        out: list[object] = []
        for f in self._stack[1:]:
            if f.key is not None:
                out.append(f.key)
        return tuple(out)

    def _adjust_to_indent(self, indent: int) -> None:
        # Pop frames whose indent is STRICTLY DEEPER than the new
        # one.  A frame at indent N holds keys at indent N (its
        # children); a sibling KEY at the same indent stays inside
        # the same frame.  An open key without a value at the
        # dropping level becomes an implicit-null leaf; for Phase
        # 1 we simply drop it.
        while len(self._stack) > 1 and self._stack[-1].indent > indent:
            self._stack.pop()
        # Stop capturing under an anchor when we've returned to an
        # indent at or shallower than the anchor's defining line.
        # The anchor's body lives at deeper indents; once we reach
        # the anchor's level (or an ancestor), the body is over.
        if self._capturing is not None:
            anchor = self._anchors.get(self._capturing)
            if anchor is not None and indent <= anchor.root_indent:
                self._capturing = None

    def _handle_key(self, tok: Token) -> Iterator[Event]:
        # Same-line-as-dash case: the dash just pushed an element
        # frame, and this KEY belongs INSIDE that element regardless
        # of its line-indent (which equals the dash's indent).
        if self._post_dash_attach:
            self._post_dash_attach = False
            self._open_key = tok
            return iter(())

        # If there's an open key whose value side hasn't been seen,
        # the previous key's value is a mapping at deeper indent.
        if self._open_key is not None and tok.indent > self._open_key.indent:
            self._stack.append(
                _Frame(
                    key=self._open_key.value,
                    indent=tok.indent,
                    container="mapping",
                )
            )
            self._open_key = None
        else:
            # Same-indent KEY — pop frames deeper than this and
            # update the current frame's key for the new sibling.
            self._adjust_to_indent(tok.indent)
            self._open_key = None

        self._open_key = tok
        return iter(())  # explicitly empty generator

    def _enter_sequence(self, indent: int) -> None:
        # If a previous element's mapping frame is open at deeper
        # indent than the new dash, pop it (the new dash starts a
        # sibling element).  An element frame's indent is dash+1
        # so any indent > dash pops it; sequence frames at indent
        # equal to the dash stay.
        while (
            len(self._stack) > 1
            and self._stack[-1].indent > indent
            and self._stack[-1].container != "sequence"
        ):
            self._stack.pop()

        # Open a sequence frame if we're not already inside one at
        # this indent.
        top = self._stack[-1]
        if not (top.container == "sequence" and top.indent == indent):
            if (
                self._open_key is not None
                and indent > self._open_key.indent
            ):
                self._stack.append(
                    _Frame(
                        key=self._open_key.value,
                        indent=indent,
                        container="sequence",
                    )
                )
                self._open_key = None
            else:
                self._stack.append(
                    _Frame(key=None, indent=indent, container="sequence")
                )
            top = self._stack[-1]

        # Reserve the next sequence index and push a mapping
        # element frame.  Indent = dash+1 so KEYs at any indent >
        # dash nest under this element; same-line KEYs (with
        # tok.indent == dash) attach via the ``_post_dash_attach``
        # flag.
        idx = top.next_index
        top.next_index += 1
        self._stack.append(
            _Frame(key=idx, indent=indent + 1, container="mapping")
        )
        self._post_dash_attach = True

    def _emit_value(
        self, tok: Token, value: str, value_kind: str
    ) -> Optional[Event]:
        # Sequence-element scalar: when there's no open key and the
        # top frame is a mapping that was just opened at a sequence
        # element index whose body is a single bare scalar (e.g.,
        # ``- foo``), emit at the integer-indexed path.
        if self._open_key is None:
            top = self._stack[-1]
            if isinstance(top.key, int) and top.container == "mapping":
                # The mapping frame was opened speculatively for
                # the sequence element's body; if no key was seen,
                # this bare scalar IS the element's value.  Replace
                # the frame's key with the index path and emit.
                path = self._current_path()
                self._record_anchor_leaf(path, value, value_kind)
                return Event(
                    EventKind.LEAF_SCALAR,
                    path,
                    tok.line,
                    tok.column,
                    value=value,
                    value_kind=value_kind,
                )
            return None

        path = self._current_path() + (self._open_key.value,)
        line = self._open_key.line
        self._open_key = None
        self._record_anchor_leaf(path, value, value_kind)
        return Event(
            EventKind.LEAF_SCALAR,
            path,
            line,
            tok.column,
            value=value,
            value_kind=value_kind,
        )

    # ------------------------------------------------------------------
    # Block scalars
    # ------------------------------------------------------------------

    def _open_block_buffer(self, tok: Token) -> None:
        if self._open_key is not None:
            self._block_path = self._current_path() + (self._open_key.value,)
            self._block_anchor_line = self._open_key.line
            self._open_key = None
        else:
            self._block_path = self._current_path()
            self._block_anchor_line = tok.line
        self._block_buffer = []

    def _flush_block(self) -> Event:
        body = "\n".join(self._block_buffer or [])
        # Trim trailing empty lines that come from the splitlines
        # artefact at end-of-file.
        body = body.rstrip("\n")
        if self._block_buffer:
            # Preserve a single trailing newline for ``|``-style
            # literal scalars (default chomping clip).
            if not body.endswith("\n"):
                body = body + "\n"
        path = self._block_path
        line = self._block_anchor_line
        self._block_buffer = None
        self._block_path = ()
        self._record_anchor_leaf(path, body, "block_literal")
        return Event(
            EventKind.LEAF_SCALAR,
            path,
            line,
            1,
            value=body,
            value_kind="block_literal",
        )

    # ------------------------------------------------------------------
    # Anchors
    # ------------------------------------------------------------------

    def _record_anchor_leaf(
        self,
        path: tuple[object, ...],
        value: str,
        value_kind: str,
    ) -> None:
        if self._capturing is None:
            return
        anchor = self._anchors.get(self._capturing)
        if anchor is None:
            return
        # Capture relative to the anchor's root.
        if len(path) >= self._capture_root_path_len:
            rel = path[self._capture_root_path_len:]
        else:
            rel = path
        if rel:
            anchor.leaves.append((rel, value, value_kind))
        # If we've left the anchor's frame depth, stop capturing.

    # ------------------------------------------------------------------
    # Flow style
    # ------------------------------------------------------------------

    def _consume_flow(self, tokens: list[Token], start: int) -> Iterator[Event]:
        """Consume a flow sequence / mapping starting at tokens[start]
        (which is FLOW_OPEN_SEQ or FLOW_OPEN_MAP).  Yields LEAF_SCALAR
        events with indexed (sequence) or keyed (mapping) paths.
        """
        first = tokens[start]
        # Open a frame for the flow container, keyed by the open key.
        if self._open_key is not None:
            base_key: object = self._open_key.value
            self._open_key = None
        else:
            base_key = None

        container = "sequence" if first.kind == TokenKind.FLOW_OPEN_SEQ else "mapping"
        self._stack.append(
            _Frame(key=base_key, indent=first.indent, container=container)
        )
        seq_frame = self._stack[-1]
        depth = 1
        i = start + 1
        flow_pending_key: Optional[str] = None

        while i < len(tokens) and depth > 0:
            t = tokens[i]
            if t.kind in (TokenKind.INDENT, TokenKind.COMMENT):
                i += 1
                continue
            if t.kind in (TokenKind.FLOW_OPEN_SEQ, TokenKind.FLOW_OPEN_MAP):
                depth += 1
                i += 1
                continue
            if t.kind in (TokenKind.FLOW_CLOSE_SEQ, TokenKind.FLOW_CLOSE_MAP):
                depth -= 1
                i += 1
                continue
            if t.kind == TokenKind.FLOW_COMMA:
                i += 1
                continue
            if t.kind == TokenKind.KEY:
                flow_pending_key = t.value
                i += 1
                continue
            if t.kind in (TokenKind.SCALAR_PLAIN, TokenKind.SCALAR_QUOTED):
                vk = "plain" if t.kind == TokenKind.SCALAR_PLAIN else "quoted"
                if container == "sequence":
                    idx = seq_frame.next_index
                    seq_frame.next_index += 1
                    path = self._current_path() + (idx,)
                else:
                    if flow_pending_key is None:
                        i += 1
                        continue
                    path = self._current_path() + (flow_pending_key,)
                    flow_pending_key = None
                yield Event(
                    EventKind.LEAF_SCALAR,
                    path,
                    t.line,
                    t.column,
                    value=t.value,
                    value_kind=vk,
                )
                self._record_anchor_leaf(path, t.value, vk)
            i += 1

        # Pop the flow container frame.
        if self._stack and self._stack[-1] is seq_frame:
            self._stack.pop()

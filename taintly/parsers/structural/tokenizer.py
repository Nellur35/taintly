"""Line-based tokenizer for CI YAML.

NOT a full YAML lexer.  Scope-limited to the structural shapes
GitHub Actions and GitLab CI workflow files actually produce.
Output is a stream of :class:`Token` records with 1-based ``line``
and ``column``.  String decoding (escape-sequence resolution, type
coercion) happens in a higher layer; this module's correctness is
structural only.

Supported features (by named test in ``test_structural_tokenizer``):
  * mappings, sequences (block + flow), nested combinations
  * plain scalars including the colon-in-value case
    (``key: foo:bar`` — value is ``foo:bar``)
  * single-quoted and double-quoted scalars
  * block scalars: ``|``, ``>``, with chomping indicators
    (``|+``, ``|-``, ``>+``, ``>-``) and explicit indentation
    indicators (``|2``, ``>3-``)
  * multi-line plain scalars (folded on continuation indent)
  * quoted keys (``'key': value``)
  * Norway problem: ``no``/``NO``/``yes``/``YES`` etc are preserved
    as plain scalars; type coercion is the schema layer's job
  * comments to end-of-line
  * anchors (``&name``), aliases (``*name``), merge keys (``<<:``)

Rejected (raises :class:`TokenizerError` — caller should fall back
to regex):
  * directives (``%YAML 1.2``)
  * document separators (``---``, ``...``)
  * multi-document files
  * custom tags (``!!str``, ``!CustomTag``)
  * complex keys (mapping-as-key)
  * set notation (``!!set``, ``? `` keys)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterator


class TokenKind(Enum):
    INDENT = "indent"
    KEY = "key"
    SEQUENCE_DASH = "dash"
    SCALAR_PLAIN = "scalar_plain"
    SCALAR_QUOTED = "scalar_quoted"
    SCALAR_BLOCK_HEADER = "scalar_block_header"
    SCALAR_BLOCK_LINE = "scalar_block_line"
    FLOW_OPEN_SEQ = "flow_open_seq"
    FLOW_OPEN_MAP = "flow_open_map"
    FLOW_CLOSE_SEQ = "flow_close_seq"
    FLOW_CLOSE_MAP = "flow_close_map"
    FLOW_COMMA = "flow_comma"
    COMMENT = "comment"
    ANCHOR = "anchor"
    ALIAS = "alias"
    MERGE_KEY = "merge_key"
    EOF = "eof"


@dataclass(frozen=True)
class Token:
    kind: TokenKind
    line: int
    column: int
    value: str
    indent: int


class TokenizerError(Exception):
    """Recoverable tokenization error.

    Raised when the input contains a YAML feature this tokenizer
    intentionally doesn't support.  The caller should catch and
    degrade gracefully — emit a CUTOFF event from the walker, or
    fall back to regex-based scanning of this file.
    """

    def __init__(self, line: int, message: str) -> None:
        super().__init__(f"line {line}: {message}")
        self.line = line


def tokenize(content: str) -> Iterator[Token]:
    """Yield Token records for the input.

    Raises :class:`TokenizerError` for unsupported features.
    Callers should catch and degrade gracefully.
    """
    yield from _Tokenizer(content).run()


# ---------------------------------------------------------------------------
# Implementation
# ---------------------------------------------------------------------------


class _Tokenizer:
    """Stateful tokenizer.  Lifetime is one ``run()`` call per file."""

    def __init__(self, content: str) -> None:
        # Normalise CRLF / CR line endings to LF before splitting so
        # the line numbers we emit match what a developer's editor
        # shows, regardless of the file's checkout-line-ending
        # convention.  ``splitlines()`` drops the trailing-newline
        # artefact ``split("\\n")`` produces for files that end with
        # a newline (the editor sees N lines, not N+1).
        normalised = content.replace("\r\n", "\n").replace("\r", "\n")
        self._lines = normalised.splitlines()
        self._line_idx = 0
        self._flow_depth = 0
        # Block-scalar state — when in_block_scalar is True, lines
        # at indent >= block_scalar_indent are body lines of a
        # ``|`` / ``>`` scalar rather than tokens.
        self._in_block_scalar = False
        self._block_scalar_indent = 0
        self._block_scalar_min_indent_seen = -1

    def run(self) -> Iterator[Token]:
        while self._line_idx < len(self._lines):
            line_no = self._line_idx + 1
            raw = self._lines[self._line_idx]

            # Block-scalar continuation handling.
            if self._in_block_scalar:
                yield from self._tokenize_block_scalar_continuation(raw, line_no)
                if self._in_block_scalar:
                    # Still inside the block scalar — advance and
                    # iterate.
                    self._line_idx += 1
                    continue
                # Block scalar ended on this line; fall through and
                # tokenise the line as ordinary content.

            # Reject directives and document separators.
            stripped_full = raw.lstrip()
            if stripped_full.startswith("%"):
                raise TokenizerError(
                    line_no, f"directive not supported: {stripped_full[:20]!r}"
                )
            if stripped_full.startswith("---") and stripped_full[3:4] in ("", " ", "\t"):
                raise TokenizerError(line_no, "document separator '---' not supported")
            if stripped_full.startswith("..."):
                raise TokenizerError(line_no, "document end '...' not supported")

            if not stripped_full:
                self._line_idx += 1
                continue

            yield from self._tokenize_line(raw, line_no)
            self._line_idx += 1

        yield Token(TokenKind.EOF, line=0, column=0, value="", indent=0)

    # ------------------------------------------------------------------
    # Block scalar continuation
    # ------------------------------------------------------------------

    def _tokenize_block_scalar_continuation(
        self, raw: str, line_no: int
    ) -> Iterator[Token]:
        # Empty / blank lines belong to the block scalar regardless
        # of indent.
        if not raw.strip():
            yield Token(
                TokenKind.SCALAR_BLOCK_LINE,
                line=line_no,
                column=1,
                value="",
                indent=0,
            )
            return

        this_indent = len(raw) - len(raw.lstrip())

        # First non-blank body line establishes the block-scalar
        # indent if the header didn't pin it explicitly.
        if self._block_scalar_min_indent_seen < 0:
            self._block_scalar_min_indent_seen = this_indent
            if self._block_scalar_indent <= 0:
                self._block_scalar_indent = this_indent

        if this_indent < self._block_scalar_indent:
            # Dedent ends the block scalar; the line will be
            # re-tokenised as ordinary content by the caller.
            self._in_block_scalar = False
            self._block_scalar_indent = 0
            self._block_scalar_min_indent_seen = -1
            return

        body = raw[self._block_scalar_indent:]
        yield Token(
            TokenKind.SCALAR_BLOCK_LINE,
            line=line_no,
            column=self._block_scalar_indent + 1,
            value=body,
            indent=this_indent,
        )

    # ------------------------------------------------------------------
    # Per-line tokenisation
    # ------------------------------------------------------------------

    def _tokenize_line(self, raw: str, line_no: int) -> Iterator[Token]:
        indent = len(raw) - len(raw.lstrip())
        yield Token(
            TokenKind.INDENT, line_no, column=1, value=" " * indent, indent=indent
        )
        pos = indent
        n = len(raw)

        while pos < n:
            ch = raw[pos]

            # Comments — rest of line.
            if ch == "#":
                # ``#`` only starts a comment when preceded by a
                # space or at line-start.  Inside a quoted scalar
                # this branch is unreachable because the scalar
                # reader consumes the whole quoted run.
                yield Token(
                    TokenKind.COMMENT,
                    line_no,
                    column=pos + 1,
                    value=raw[pos:],
                    indent=indent,
                )
                return

            if ch == " " or ch == "\t":
                pos += 1
                continue

            # Sequence dash: ``- `` at the current position, with a
            # following space or end-of-line.
            if ch == "-" and (pos + 1 == n or raw[pos + 1] in (" ", "\t")):
                yield Token(
                    TokenKind.SEQUENCE_DASH,
                    line_no,
                    column=pos + 1,
                    value="-",
                    indent=indent,
                )
                pos += 1
                continue

            # Flow open / close.
            if ch == "[":
                self._flow_depth += 1
                yield Token(
                    TokenKind.FLOW_OPEN_SEQ, line_no, pos + 1, "[", indent
                )
                pos += 1
                continue
            if ch == "{":
                self._flow_depth += 1
                yield Token(
                    TokenKind.FLOW_OPEN_MAP, line_no, pos + 1, "{", indent
                )
                pos += 1
                continue
            if ch == "]":
                self._flow_depth = max(0, self._flow_depth - 1)
                yield Token(
                    TokenKind.FLOW_CLOSE_SEQ, line_no, pos + 1, "]", indent
                )
                pos += 1
                continue
            if ch == "}":
                self._flow_depth = max(0, self._flow_depth - 1)
                yield Token(
                    TokenKind.FLOW_CLOSE_MAP, line_no, pos + 1, "}", indent
                )
                pos += 1
                continue
            if ch == ",":
                yield Token(
                    TokenKind.FLOW_COMMA, line_no, pos + 1, ",", indent
                )
                pos += 1
                continue

            # Anchor: ``&name``.
            if ch == "&":
                end = pos + 1
                while end < n and raw[end] not in " \t,]}":
                    end += 1
                yield Token(
                    TokenKind.ANCHOR, line_no, pos + 1, raw[pos:end], indent
                )
                pos = end
                continue

            # Alias: ``*name``.
            if ch == "*":
                end = pos + 1
                while end < n and raw[end] not in " \t,]}":
                    end += 1
                yield Token(
                    TokenKind.ALIAS, line_no, pos + 1, raw[pos:end], indent
                )
                pos = end
                continue

            # Merge key: ``<<:`` (only valid as a mapping key).
            if ch == "<" and raw[pos:pos + 3] == "<<:":
                yield Token(
                    TokenKind.MERGE_KEY, line_no, pos + 1, "<<", indent
                )
                # Consume the ``<<`` and the trailing ``:`` plus any
                # following whitespace.  The merge key has no
                # implicit "key" identity beyond its marker — the
                # next ALIAS token is what the merge resolves to.
                pos += 3
                while pos < n and raw[pos] in " \t":
                    pos += 1
                continue

            # Reject custom tags: ``!`` / ``!!``.
            if ch == "!":
                raise TokenizerError(
                    line_no, "custom tags ('!') not supported"
                )

            # Reject complex keys: ``? `` at start of value position.
            if ch == "?" and (pos + 1 == n or raw[pos + 1] in (" ", "\t")):
                raise TokenizerError(
                    line_no, "explicit/complex keys ('?') not supported"
                )

            # Block-scalar header: ``|`` or ``>`` at end of line
            # (possibly with chomping/indent indicators) — but only
            # when the immediate context is "after a key:".  Without
            # full state tracking we accept the header inline; the
            # walker disambiguates via its key-stack.
            if ch in "|>" and self._is_block_scalar_header(raw, pos):
                header = self._read_block_scalar_header(raw, pos)
                yield Token(
                    TokenKind.SCALAR_BLOCK_HEADER,
                    line_no,
                    pos + 1,
                    header,
                    indent,
                )
                self._enter_block_scalar(header, indent)
                # Header consumes the rest of the line.
                return

            # Quoted scalar.
            if ch in ("'", '"'):
                end, value = self._read_quoted_scalar(raw, pos, line_no)
                # Look ahead: if followed by ``:``, this was a quoted
                # key.  Otherwise it's a quoted scalar value.
                trailing = end
                while trailing < n and raw[trailing] == " ":
                    trailing += 1
                if trailing < n and raw[trailing] == ":" and (
                    trailing + 1 == n or raw[trailing + 1] in (" ", "\t")
                ):
                    yield Token(
                        TokenKind.KEY,
                        line_no,
                        column=pos + 1,
                        value=value,
                        indent=indent,
                    )
                    pos = trailing + 1
                    continue
                yield Token(
                    TokenKind.SCALAR_QUOTED,
                    line_no,
                    column=pos + 1,
                    value=value,
                    indent=indent,
                )
                pos = end
                continue

            # Plain scalar or key.
            pos = yield from self._read_plain_token(raw, pos, line_no, indent)

    # ------------------------------------------------------------------
    # Quoted scalar
    # ------------------------------------------------------------------

    def _read_quoted_scalar(
        self, raw: str, start: int, line_no: int
    ) -> tuple[int, str]:
        quote = raw[start]
        pos = start + 1
        n = len(raw)
        out: list[str] = []
        while pos < n:
            ch = raw[pos]
            if quote == "'":
                # Single quote — only escape is doubled ``''``.
                if ch == "'":
                    if pos + 1 < n and raw[pos + 1] == "'":
                        out.append("'")
                        pos += 2
                        continue
                    return pos + 1, "".join(out)
                out.append(ch)
                pos += 1
                continue
            # Double quote — backslash escapes (decoding still
            # leaves them as raw text; the value-coercion layer
            # owns interpretation).
            if ch == "\\" and pos + 1 < n:
                out.append(raw[pos:pos + 2])
                pos += 2
                continue
            if ch == '"':
                return pos + 1, "".join(out)
            out.append(ch)
            pos += 1
        raise TokenizerError(
            line_no,
            f"unterminated {quote!r}-quoted scalar",
        )

    # ------------------------------------------------------------------
    # Plain scalar / key disambiguation
    # ------------------------------------------------------------------

    def _read_plain_token(
        self, raw: str, start: int, line_no: int, indent: int
    ) -> Iterator[Token]:
        """Read a plain-scalar token, disambiguating key vs scalar.

        Key detection: a plain run terminated by ``:`` followed by
        whitespace or end-of-line is a mapping key.  Otherwise the
        run (including any ``:`` characters inside it) is a plain
        scalar — that's the colon-in-value case (``foo:bar:baz``).

        Returns the position immediately after the consumed run.
        """
        n = len(raw)
        pos = start

        # Scan forward until we find a structural delimiter.
        # Inside flow context, ``,]}`` terminate.  Outside flow,
        # only a key-marker colon (``: `` / ``:<EOL>``) or a
        # comment marker preceded by space terminates.
        in_flow = self._flow_depth > 0
        last_non_space = pos - 1
        while pos < n:
            ch = raw[pos]
            if in_flow and ch in ",]}":
                break
            if ch == "#" and pos > 0 and raw[pos - 1] == " ":
                break
            if ch == ":" and (
                pos + 1 == n or raw[pos + 1] in (" ", "\t")
            ):
                # Key-marker colon found.
                key_end = pos
                key_value = raw[start:key_end].rstrip()
                yield Token(
                    TokenKind.KEY,
                    line_no,
                    column=start + 1,
                    value=key_value,
                    indent=indent,
                )
                # Skip the colon and any following whitespace.
                pos += 1
                while pos < n and raw[pos] in (" ", "\t"):
                    pos += 1
                return pos
            if ch != " " and ch != "\t":
                last_non_space = pos
            pos += 1

        # No key marker found.  This is a plain-scalar value.
        end = last_non_space + 1
        value = raw[start:end].rstrip()
        if value:
            yield Token(
                TokenKind.SCALAR_PLAIN,
                line_no,
                column=start + 1,
                value=value,
                indent=indent,
            )
        return pos

    # ------------------------------------------------------------------
    # Block scalar header parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _is_block_scalar_header(raw: str, pos: int) -> bool:
        # ``|`` or ``>`` followed by optional chomping/indent
        # indicators and end-of-line (or only whitespace + comment).
        n = len(raw)
        i = pos + 1
        # Optional indicators in any order: digit OR + OR -.
        while i < n and raw[i] in "0123456789+-":
            i += 1
        # Skip trailing whitespace.
        while i < n and raw[i] in " \t":
            i += 1
        # End-of-line, or comment.
        return i == n or raw[i] == "#"

    def _read_block_scalar_header(self, raw: str, pos: int) -> str:
        n = len(raw)
        end = pos + 1
        while end < n and raw[end] in "0123456789+-":
            end += 1
        return raw[pos:end]

    def _enter_block_scalar(self, header: str, header_indent: int) -> None:
        self._in_block_scalar = True
        # Explicit indent indicator overrides indent inference.
        explicit_indent = 0
        for ch in header[1:]:
            if ch.isdigit():
                explicit_indent = explicit_indent * 10 + int(ch)
        if explicit_indent > 0:
            self._block_scalar_indent = header_indent + explicit_indent
        else:
            # Inferred from first body line on next pass.
            self._block_scalar_indent = 0
        self._block_scalar_min_indent_seen = -1

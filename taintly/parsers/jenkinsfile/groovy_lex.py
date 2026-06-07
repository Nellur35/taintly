"""Zero-dependency, tolerant Groovy tokenizer for the island reader.

This is the lexer layer of the default (zero-dep) Jenkinsfile reader.
It classifies Groovy source bytes into a flat stream of :class:`Token`
records.  It is deliberately *not* a full Groovy lexer — it recognises
exactly the lexical shapes the island walker needs to find the sink/
config surface of a Jenkinsfile (identifiers, the four string forms,
brace/paren/bracket structure, comments, statement separators) and
classifies everything else as an opaque ``OP`` token.

THE LOAD-BEARING DIVERGENCE FROM THE YAML TOKENIZER
---------------------------------------------------
``parsers/structural/tokenizer.py`` RAISES :class:`TokenizerError` on any
construct it does not model, which is exactly why the current tree-sitter
Jenkins reader cuts off on 100% of the real corpus (real Jenkinsfiles are
full of unmodelled Groovy).  This tokenizer **never raises** — it only
classifies bytes.  An unrecognised byte becomes an opaque ``OP`` token,
not an error.  The only thing it cannot do is *finish* an unterminated
triple-quoted string at EOF; it records that as ``unterminated=True`` on
the token (the walker turns it into a CUTOFF, but still after emitting
everything that came before).

The string/comment scanner is lifted from
``fallback.py:_groovy_code_mask`` (already correct and tested) so quote/
comment boundaries are handled identically to the regex fallback.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum


class TokKind(Enum):
    """Lexical token kinds emitted by :func:`tokenize`."""

    IDENT = "ident"
    STRING = "string"
    LBRACE = "lbrace"
    RBRACE = "rbrace"
    LPAREN = "lparen"
    RPAREN = "rparen"
    LBRACKET = "lbracket"
    RBRACKET = "rbracket"
    COMMENT = "comment"
    NEWLINE = "newline"
    SEMI = "semi"
    OP = "op"
    EOF = "eof"


# String quote kinds — preserved so the walker can reason about whether
# GString interpolation is possible.
QUOTE_SINGLE = "'"
QUOTE_DOUBLE = '"'
QUOTE_TRIPLE_SINGLE = "'''"
QUOTE_TRIPLE_DOUBLE = '"""'
QUOTE_SLASHY = "/"  # Groovy slashy string  /.../  (interpolating)
QUOTE_DOLLAR_SLASHY = "$/"  # Groovy dollar-slashy string  $/.../$


@dataclass(frozen=True)
class GStringSpan:
    """One interpolation span inside a GString body.

    ``expr`` is the raw text between the delimiters (for ``${...}`` the
    text inside the braces; for the ``$ident.path`` short form the dotted
    path).  ``brace_form`` distinguishes ``${...}`` from ``$ident``.
    Offsets are relative to the decoded string *body* (quotes stripped).
    """

    expr: str
    start: int
    end: int
    brace_form: bool


@dataclass(frozen=True)
class Token:
    """One lexical token.

    Fields:
      kind: see :class:`TokKind`.
      value: for IDENT the identifier text; for STRING the *decoded body*
        (quotes stripped, no escape resolution); for OP/COMMENT the raw
        text; for structural tokens the literal delimiter.
      line: 1-based source line of the token's first byte.
      col: 1-based column of the token's first byte.
      quote: for STRING tokens, the opening quote kind (one of the
        ``QUOTE_*`` constants); ``None`` otherwise.
      raw: for STRING tokens, the raw source including quotes; ``None``
        otherwise.
      interpolations: for double/triple-double/slashy STRING tokens, the
        list of GString interpolation spans found in the body (may be
        empty); ``None`` for non-interpolating string kinds.
      unterminated: True for a STRING token whose closing delimiter was
        never found before EOF (the walker turns this into a CUTOFF).
    """

    kind: TokKind
    value: str = ""
    line: int = 1
    col: int = 1
    quote: str | None = None
    raw: str | None = None
    interpolations: list[GStringSpan] | None = None
    unterminated: bool = False


_IDENT_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$")
_IDENT_CONT = _IDENT_START | set("0123456789")

# Interpolating string kinds: GString interpolation (${...}, $ident.path)
# is live inside these.
_INTERP_QUOTES = frozenset({QUOTE_DOUBLE, QUOTE_TRIPLE_DOUBLE, QUOTE_SLASHY, QUOTE_DOLLAR_SLASHY})


def tokenize(content: str) -> Iterator[Token]:
    """Yield :class:`Token` records for ``content``.

    Never raises.  Always terminates with an EOF token.  Unrecognised
    bytes are emitted as opaque ``OP`` tokens.
    """
    yield from _Tokenizer(content).run()


class _Tokenizer:
    """Stateful, single-pass Groovy lexer.  Lifetime: one ``run()``."""

    def __init__(self, content: str) -> None:
        # Normalise line endings so emitted line numbers match an editor's
        # view regardless of checkout convention (mirrors the YAML lexer).
        self._src = content.replace("\r\n", "\n").replace("\r", "\n")
        self._n = len(self._src)
        self._i = 0
        self._line = 1
        self._col = 1
        # When True, the previous significant token can be a divisor, so a
        # ``/`` starts division rather than a slashy string.  Slashy
        # strings only begin where an expression/value is expected.
        self._prev_value_like = False

    # -- position bookkeeping ------------------------------------------------

    def _advance(self, count: int) -> str:
        """Consume ``count`` chars, updating line/col, return the slice."""
        chunk = self._src[self._i : self._i + count]
        for ch in chunk:
            if ch == "\n":
                self._line += 1
                self._col = 1
            else:
                self._col += 1
        self._i += count
        return chunk

    def run(self) -> Iterator[Token]:
        src = self._src
        n = self._n
        while self._i < n:
            ch = src[self._i]
            line, col = self._line, self._col

            # Whitespace (not newline) — skip.
            if ch == " " or ch == "\t" or ch == "\f" or ch == "\v":
                self._advance(1)
                continue

            # Newline — significant as a statement terminator in Groovy.
            if ch == "\n":
                self._advance(1)
                yield Token(TokKind.NEWLINE, "\n", line, col)
                self._prev_value_like = False
                continue

            # Comments — reuse the same boundary logic as _groovy_code_mask.
            if ch == "/" and self._i + 1 < n and src[self._i + 1] == "/":
                end = src.find("\n", self._i)
                if end == -1:
                    end = n
                text = self._advance(end - self._i)
                yield Token(TokKind.COMMENT, text, line, col)
                continue
            if ch == "/" and self._i + 1 < n and src[self._i + 1] == "*":
                end = src.find("*/", self._i + 2)
                end = n if end == -1 else end + 2
                text = self._advance(end - self._i)
                yield Token(TokKind.COMMENT, text, line, col)
                continue

            # Shebang line (`#!`) at file start — treat as a comment so the
            # hybrid_shebang shape doesn't poison the stream.
            if ch == "#" and self._i + 1 < n and src[self._i + 1] == "!":
                end = src.find("\n", self._i)
                if end == -1:
                    end = n
                text = self._advance(end - self._i)
                yield Token(TokKind.COMMENT, text, line, col)
                continue

            # Strings.
            if ch in ("'", '"'):
                yield self._read_quoted(ch, line, col)
                self._prev_value_like = True
                continue

            # Dollar-slashy string  $/ ... /$  — only when a value is
            # expected (otherwise ``$`` is an opaque op).
            if (
                ch == "$"
                and self._i + 1 < n
                and src[self._i + 1] == "/"
                and not self._prev_value_like
            ):
                yield self._read_dollar_slashy(line, col)
                self._prev_value_like = True
                continue

            # Slashy string  / ... /  — only in value position (else it's
            # the division operator or part of a comment, handled above).
            if ch == "/" and not self._prev_value_like:
                yield self._read_slashy(line, col)
                self._prev_value_like = True
                continue

            # Identifier / keyword.
            if ch in _IDENT_START:
                start = self._i
                j = self._i + 1
                while j < n and src[j] in _IDENT_CONT:
                    j += 1
                text = self._advance(j - start)
                yield Token(TokKind.IDENT, text, line, col)
                self._prev_value_like = True
                continue

            # Numbers — opaque, but value-like (so a following ``/`` is
            # division, not a slashy string).
            if ch.isdigit():
                start = self._i
                j = self._i + 1
                while j < n and (src[j].isalnum() or src[j] in "._"):
                    j += 1
                self._advance(j - start)
                yield Token(TokKind.OP, src[start:j], line, col)
                self._prev_value_like = True
                continue

            # Structural delimiters.
            if ch == "{":
                self._advance(1)
                yield Token(TokKind.LBRACE, "{", line, col)
                self._prev_value_like = False
                continue
            if ch == "}":
                self._advance(1)
                yield Token(TokKind.RBRACE, "}", line, col)
                self._prev_value_like = True
                continue
            if ch == "(":
                self._advance(1)
                yield Token(TokKind.LPAREN, "(", line, col)
                self._prev_value_like = False
                continue
            if ch == ")":
                self._advance(1)
                yield Token(TokKind.RPAREN, ")", line, col)
                self._prev_value_like = True
                continue
            if ch == "[":
                self._advance(1)
                yield Token(TokKind.LBRACKET, "[", line, col)
                self._prev_value_like = False
                continue
            if ch == "]":
                self._advance(1)
                yield Token(TokKind.RBRACKET, "]", line, col)
                self._prev_value_like = True
                continue
            if ch == ";":
                self._advance(1)
                yield Token(TokKind.SEMI, ";", line, col)
                self._prev_value_like = False
                continue

            # Everything else — opaque operator/punctuation.  A trailing
            # operator (``=``, ``,``, ``:``, ``.``, ``+`` ...) leaves the
            # scanner expecting a value next (so ``/`` after it is slashy).
            self._advance(1)
            yield Token(TokKind.OP, ch, line, col)
            self._prev_value_like = ch in ")]}"

        yield Token(TokKind.EOF, "", self._line, self._col)

    # -- string readers ------------------------------------------------------

    def _read_quoted(self, quote: str, line: int, col: int) -> Token:
        """Read a single/double/triple-single/triple-double string.

        Decodes the *body* (quotes stripped); does not resolve escapes.
        For interpolating kinds, captures GString spans.  Sets
        ``unterminated=True`` if EOF is reached before the closer.
        """
        src = self._src
        n = self._n
        triple = src.startswith(quote * 3, self._i)
        opener = quote * 3 if triple else quote
        body_start = self._i + len(opener)

        if triple:
            marker = quote * 3
            end = src.find(marker, body_start)
            if end == -1:
                # Unterminated triple string — consume the rest, flag it.
                body = src[body_start:n]
                raw = self._advance(n - self._i)
                return self._make_string_token(opener, body, raw, line, col, unterminated=True)
            body = src[body_start:end]
            raw_len = (end + len(marker)) - self._i
            raw = self._advance(raw_len)
            return self._make_string_token(opener, body, raw, line, col)

        # Single-line quote: respects backslash escapes; ends at the
        # matching quote OR at a newline (Groovy single-line strings can't
        # span lines).  A newline terminates tolerantly (no raise).
        j = body_start
        while j < n:
            c = src[j]
            if c == "\\" and j + 1 < n:
                j += 2
                continue
            if c == quote:
                body = src[body_start:j]
                raw = self._advance((j + 1) - self._i)
                return self._make_string_token(opener, body, raw, line, col)
            if c == "\n":
                break
            j += 1
        # Unterminated single-line string (hit newline or EOF).  Consume up
        # to the break point; tolerate (the rest of the line is the body).
        body = src[body_start:j]
        raw = self._advance(j - self._i)
        # An unterminated single-line string at a newline is recoverable
        # (next line re-syncs); only flag EOF as truly unterminated.
        return self._make_string_token(opener, body, raw, line, col, unterminated=(j >= n))

    def _read_slashy(self, line: int, col: int) -> Token:
        """Read a slashy string  /.../  (single-line, interpolating)."""
        src = self._src
        n = self._n
        body_start = self._i + 1
        j = body_start
        while j < n:
            c = src[j]
            if c == "\\" and j + 1 < n:
                j += 2
                continue
            if c == "/":
                body = src[body_start:j]
                raw = self._advance((j + 1) - self._i)
                return self._make_string_token(QUOTE_SLASHY, body, raw, line, col)
            if c == "\n":
                break
            j += 1
        body = src[body_start:j]
        raw = self._advance(j - self._i)
        return self._make_string_token(QUOTE_SLASHY, body, raw, line, col, unterminated=(j >= n))

    def _read_dollar_slashy(self, line: int, col: int) -> Token:
        """Read a dollar-slashy string  $/ ... /$  (multi-line)."""
        src = self._src
        n = self._n
        body_start = self._i + 2
        end = src.find("/$", body_start)
        if end == -1:
            body = src[body_start:n]
            raw = self._advance(n - self._i)
            return self._make_string_token(
                QUOTE_DOLLAR_SLASHY, body, raw, line, col, unterminated=True
            )
        body = src[body_start:end]
        raw = self._advance((end + 2) - self._i)
        return self._make_string_token(QUOTE_DOLLAR_SLASHY, body, raw, line, col)

    def _make_string_token(
        self,
        quote: str,
        body: str,
        raw: str,
        line: int,
        col: int,
        *,
        unterminated: bool = False,
    ) -> Token:
        interps: list[GStringSpan] | None = None
        if quote in _INTERP_QUOTES:
            interps = _scan_gstring(body)
        return Token(
            kind=TokKind.STRING,
            value=body,
            line=line,
            col=col,
            quote=quote,
            raw=raw,
            interpolations=interps,
            unterminated=unterminated,
        )


def _scan_gstring(body: str) -> list[GStringSpan]:
    """Find GString interpolation spans in a (double/triple-double/slashy)
    body: ``${ ... }`` (brace form, nestable) and ``$ident.path`` (dotted
    short form).  Offsets are body-relative.  A backslash escapes ``$``.
    """
    spans: list[GStringSpan] = []
    n = len(body)
    i = 0
    while i < n:
        ch = body[i]
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch != "$":
            i += 1
            continue
        # ``${ ... }`` — track brace depth (the inner expression may
        # itself contain braces, e.g. closures).
        if i + 1 < n and body[i + 1] == "{":
            depth = 0
            j = i + 1
            while j < n:
                if body[j] == "{":
                    depth += 1
                elif body[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            expr = body[i + 2 : j] if j < n else body[i + 2 : n]
            end = j + 1 if j < n else n
            spans.append(GStringSpan(expr=expr, start=i, end=end, brace_form=True))
            i = end
            continue
        # ``$ident.path`` — bare identifier with optional dotted accessors.
        if i + 1 < n and body[i + 1] in _IDENT_START:
            j = i + 1
            while j < n and body[j] in _IDENT_CONT:
                j += 1
            # Allow dotted continuation: $env.CHANGE_TITLE
            while j < n and body[j] == "." and j + 1 < n and body[j + 1] in _IDENT_START:
                j += 1
                while j < n and body[j] in _IDENT_CONT:
                    j += 1
            spans.append(GStringSpan(expr=body[i + 1 : j], start=i, end=j, brace_form=False))
            i = j
            continue
        i += 1
    return spans

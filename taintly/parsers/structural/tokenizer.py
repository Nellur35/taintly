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

import re
from collections.abc import Generator, Iterator
from dataclasses import dataclass
from enum import Enum


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


# Bare-key plain-scalar fold helpers (see ``_Tokenizer.run``).
#
# A child mapping key has the shape ``<word>:`` (optionally with a
# value).  YAML keys may include ``-``, ``_``, ``$``, dots in
# extended forms; this regex is intentionally narrow to the common
# CI-config shapes and is paired with positive evidence (the line is
# indented deeper than the bare key) before being trusted.
_CHILD_KEY_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_.\-]*\s*:(\s|$)")

# A quoted child key has the shape ``'foo':`` / ``"foo":`` —
# closing quote followed by ``:``.  ``'failure'`` alone (without
# the trailing ``:``) is a plain-scalar value continuation, not a
# structural key, and must NOT block the multi-line plain-scalar
# fold.  Surfaced by SalesforceDX-VSCode E2E workflows where a
# multi-line ``if:`` value continues with ``          'failure'``
# at deeper indent.
_QUOTED_KEY_RE = re.compile(r"""^(?:'[^']*'|"[^"]*")\s*:(\s|$)""")

# Token kinds whose presence on the bare-key line proves we are NOT
# looking at the ``<key>:`` (no inline value) shape — anchors and
# aliases sit between the key and the value in some YAML, and a flow-
# open token means the value lives in a flow collection (handled
# elsewhere).  Keep this set tight: every kind added here silently
# disables the bare-key fold for that shape.
_NON_FOLD_TOKEN_KINDS = frozenset(
    {
        TokenKind.SCALAR_PLAIN,
        TokenKind.SCALAR_QUOTED,
        TokenKind.SCALAR_BLOCK_HEADER,
        TokenKind.FLOW_OPEN_SEQ,
        TokenKind.FLOW_OPEN_MAP,
        TokenKind.SEQUENCE_DASH,
        TokenKind.ANCHOR,
        TokenKind.ALIAS,
    }
)


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
        # True once a mapping KEY has been emitted on the current line
        # (block context) or since the last flow delimiter: everything
        # after a ``key:`` is the *value*, so a ``: `` inside it (e.g.
        # ``run: echo "Status: ok"``) must NOT be re-read as a nested
        # key.  Reset at line start, on ``- ``, and on flow ``[]{},``.
        self._value_position = False

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

            # Reject directives.  Document separators (--- and ...) are
            # valid YAML markers commonly used at the top of workflow
            # files (`---\nname: ...`) and at multi-document boundaries.
            # We scan single-document content, so the markers are no-
            # ops; skip them rather than aborting the tokenization.
            stripped_full = raw.lstrip()
            if stripped_full.startswith("%"):
                raise TokenizerError(line_no, f"directive not supported: {stripped_full[:20]!r}")
            if stripped_full.startswith("---") and stripped_full[3:4] in ("", " ", "\t"):
                self._line_idx += 1
                continue
            if stripped_full.startswith("...") and stripped_full[3:4] in ("", " ", "\t"):
                self._line_idx += 1
                continue

            if not stripped_full:
                self._line_idx += 1
                continue

            # Comment-only lines (``# foo`` after optional indent)
            # carry no structural content.  Emitting their INDENT
            # token would drive the walker's frame-management to pop
            # back to the comment's indent — which closes any open
            # parent mapping (e.g. ``jobs:`` at indent 0) when a
            # commented-out fragment sits between two real children.
            # Surfaced on tokio-rs/tokio ci.yml where ~400+ events
            # mis-pathed because two commented-out lines popped the
            # ``jobs:`` frame mid-file.  Skip the line entirely.
            if stripped_full.startswith("#"):
                self._line_idx += 1
                continue

            line_tokens = list(self._tokenize_line(raw, line_no))
            self._line_idx += 1

            # Multi-line plain scalar folding.  When a line is
            # ``<key>: <plain scalar>`` (a KEY immediately followed by
            # a trailing SCALAR_PLAIN value), any following lines
            # indented strictly MORE than the *key's column* are a
            # continuation of that scalar — a key that already has an
            # inline scalar value cannot also have child
            # mappings/sequences, so a deeper-indented next line can
            # only be a fold.  Consume them into the scalar's value
            # instead of re-tokenising them as structure: this is what
            # stops a multi-line ``if: contains(fromJSON('[ ... ]'),
            # ...)`` value from spilling stray ``'`` / ``[`` / ``,``
            # tokens (or a CUTOFF) onto the lines that follow it.
            #
            # The threshold is the key's *column*, not the line
            # indent: in compact notation (``- id: write``) the key
            # sits at dash+2, and its sibling keys (``env:``, ``run:``)
            # share that column — they must NOT be folded.
            if (
                len(line_tokens) >= 2
                and line_tokens[-1].kind == TokenKind.SCALAR_PLAIN
                and line_tokens[-2].kind == TokenKind.KEY
                and self._flow_depth == 0
                and not self._in_block_scalar
            ):
                key_col = line_tokens[-2].column - 1
                folded: list[str] = []
                while self._line_idx < len(self._lines):
                    nxt = self._lines[self._line_idx]
                    s = nxt.strip()
                    if not s or s.startswith("#"):
                        self._line_idx += 1
                        continue
                    if (len(nxt) - len(nxt.lstrip())) <= key_col:
                        break
                    # Stop folding if the next line LOOKS like YAML
                    # structure (sibling key, sequence item, flow
                    # open, anchor/alias/tag, merge key, block-scalar
                    # header).  The key-column threshold above is the
                    # primary stop, but in compact-dash notation under
                    # 2x-scaled indents (e.g. mutation testing), a
                    # sibling key like ``with:`` can sit at a column
                    # deeper than the parent ``uses:`` key — the
                    # column threshold then wrongly allows it to fold
                    # and the entire child mapping disappears into the
                    # scalar value.  Same exclusion set as the
                    # bare-key fold below.
                    # ``'`` and ``"`` are EXCLUDED via the precise
                    # _QUOTED_KEY_RE check (quoted-key shape with
                    # trailing colon) rather than the broad prefix
                    # check — a continuation line like
                    # ``          'failure'`` is plain-scalar text,
                    # not a quoted key, and must keep folding.
                    if (
                        s.startswith(("- ", "[", "{", "&", "*", "!", "<<", "?", "|", ">"))
                        or s == "-"
                        or _CHILD_KEY_RE.match(s)
                        or _QUOTED_KEY_RE.match(s)
                    ):
                        break
                    folded.append(s)
                    self._line_idx += 1
                if folded:
                    last = line_tokens[-1]
                    line_tokens[-1] = Token(
                        last.kind,
                        last.line,
                        last.column,
                        last.value + " " + " ".join(folded),
                        last.indent,
                    )

            # Multi-line plain scalar folding — bare-key form.
            # When a line is ``<key>:`` with NO inline value (only a
            # KEY token, no trailing SCALAR_PLAIN), the value may still
            # be a multi-line plain scalar starting on the *next* line:
            #
            #     run:
            #       dotnet run scan --Verbosity Verbose
            #       --DockerImagesToScan "..."
            #       --DetectorArgs ...
            #
            # YAML treats this as ``run: dotnet run scan ... ...``
            # (single folded scalar).  Without this fold, the in-house
            # walker tokenises each continuation line as structure and
            # emits LEAF_SCALAR events with an EMPTY PATH TUPLE, which
            # makes downstream path-glob filters (``jobs.*.steps[*].run``)
            # miss the events entirely — silent under-reporting on
            # every TAINT/SEC rule that filters on ``run:`` slots.
            #
            # Distinguishing value-continuation from child structure
            # at the first following non-empty line:
            #   - sequence (``- foo``)            → NOT a continuation
            #   - child mapping (``KEY: value``)  → NOT a continuation
            #   - block-scalar indicator (``|``)  → NOT a continuation
            #     (block scalars are handled elsewhere and start on the
            #     header line, not the line after)
            #   - anything else (no colon-key shape, no dash, no `|`/`>`)
            #     at deeper indent → a value continuation.
            #
            # If the first following line qualifies, synthesise a
            # SCALAR_PLAIN value for the key and consume all continuation
            # lines (same indent envelope as the inline-value fold above).
            elif (
                len(line_tokens) >= 1
                and line_tokens[-1].kind == TokenKind.KEY
                and not any(t.kind in _NON_FOLD_TOKEN_KINDS for t in line_tokens)
                and self._flow_depth == 0
                and not self._in_block_scalar
            ):
                key = line_tokens[-1]
                key_col = key.column - 1
                # Peek at the next non-empty/non-comment line to decide
                # whether what follows is a value continuation or real
                # nested structure.
                peek_idx = self._line_idx
                while peek_idx < len(self._lines):
                    cand = self._lines[peek_idx]
                    cand_s = cand.strip()
                    if cand_s and not cand_s.startswith("#"):
                        break
                    peek_idx += 1
                else:
                    cand = ""
                    cand_s = ""
                cand_indent = len(cand) - len(cand.lstrip()) if cand else 0
                # Anything looking like YAML structure on the next
                # line is NOT a value continuation:
                #   ``'key':`` / ``"key":``  → quoted child key
                #   ``"..."`` / ``'...'``    → quoted scalar value
                #     (real but rare as multi-line plain; treat as
                #     structural to stay conservative)
                #   ``[``, ``{``             → multi-line flow open
                #   ``&``, ``*``, ``!``      → anchor / alias / tag
                #   ``<<:``                  → merge key (the canonical
                #     defaults-and-jobs pattern in CI YAML)
                #   ``?``                    → complex-key marker
                #   ``|``, ``>``             → block-scalar header
                #     (block scalars start on the same line as the
                #     key in legal YAML, so a bare ``|`` here is
                #     malformed; either way, not a plain-scalar fold)
                is_continuation = (
                    bool(cand_s)
                    and cand_indent > key_col
                    and not cand_s.startswith("- ")
                    and cand_s != "-"
                    and not _CHILD_KEY_RE.match(cand_s)
                    and not _QUOTED_KEY_RE.match(cand_s)
                    and not cand_s.startswith(("|", ">", "[", "{", "&", "*", "!", "<<", "?"))
                )
                if is_continuation:
                    folded2: list[str] = []
                    while self._line_idx < len(self._lines):
                        nxt = self._lines[self._line_idx]
                        s = nxt.strip()
                        if not s or s.startswith("#"):
                            self._line_idx += 1
                            continue
                        if (len(nxt) - len(nxt.lstrip())) <= key_col:
                            break
                        folded2.append(s)
                        self._line_idx += 1
                    if folded2:
                        line_tokens.append(
                            Token(
                                TokenKind.SCALAR_PLAIN,
                                line=key.line,
                                column=key.column + len(key.value) + 2,
                                value=" ".join(folded2),
                                indent=key.indent,
                            )
                        )

            # Multi-line plain scalar folding — sequence-item form.
            # ``- <plain scalar>`` followed by deeper-indented
            # continuation lines is a multi-line plain scalar value of
            # the list element.  Canonical CI shape: a multi-line
            # shell command as a list item under ``script:`` /
            # ``run:``:
            #
            #     - git grep -I -l "" -- . | while IFS= read -r i; do
            #           if [ -n "$(tail -c 1 "$i")" ]; then
            #               echo "No newline at end of $i";
            #               exit 1;
            #           fi;
            #       done
            #
            # ruamel parses this as ONE folded plain scalar value at
            # ``parent.<idx>``.  Without this fold, the in-house walker
            # emits each continuation line as its own LEAF_SCALAR
            # event at the same path — N events at ``('script', 7)``
            # instead of 1 — silently inflating leaf counts and giving
            # downstream rules a multi-event view of what should be a
            # single shell command.  Surfaced by the GitLab corpus
            # oracle on memorysafety/rav1d/.gitlab-ci.yml (delta=110
            # leaves across ~20 script items).
            #
            # The dash's column is the indent threshold; same
            # structure-detection break as the other two forms.
            if (
                len(line_tokens) >= 2
                and line_tokens[-1].kind == TokenKind.SCALAR_PLAIN
                and line_tokens[-2].kind == TokenKind.SEQUENCE_DASH
                and self._flow_depth == 0
                and not self._in_block_scalar
            ):
                dash = line_tokens[-2]
                dash_col = dash.column - 1
                folded3: list[str] = []
                while self._line_idx < len(self._lines):
                    nxt = self._lines[self._line_idx]
                    s = nxt.strip()
                    if not s or s.startswith("#"):
                        self._line_idx += 1
                        continue
                    if (len(nxt) - len(nxt.lstrip())) <= dash_col:
                        break
                    if (
                        s.startswith(("- ", "[", "{", "&", "*", "!", "<<", "?", "|", ">"))
                        or s == "-"
                        or _CHILD_KEY_RE.match(s)
                        or _QUOTED_KEY_RE.match(s)
                    ):
                        break
                    folded3.append(s)
                    self._line_idx += 1
                if folded3:
                    last = line_tokens[-1]
                    line_tokens[-1] = Token(
                        last.kind,
                        last.line,
                        last.column,
                        last.value + " " + " ".join(folded3),
                        last.indent,
                    )

            yield from line_tokens

        yield Token(TokenKind.EOF, line=0, column=0, value="", indent=0)

    # ------------------------------------------------------------------
    # Block scalar continuation
    # ------------------------------------------------------------------

    def _tokenize_block_scalar_continuation(self, raw: str, line_no: int) -> Iterator[Token]:
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

        body = raw[self._block_scalar_indent :]
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
        yield Token(TokenKind.INDENT, line_no, column=1, value=" " * indent, indent=indent)
        pos = indent
        n = len(raw)
        # A new line starts in key position (block context).
        self._value_position = False

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
                # A ``- `` opens a fresh element: the next plain run
                # is a key (``- key: val``) or a bare scalar.
                self._value_position = False
                pos += 1
                continue

            # Flow open / close.  Each delimiter returns the scanner to
            # key position for the next flow entry.
            if ch == "[":
                self._flow_depth += 1
                yield Token(TokenKind.FLOW_OPEN_SEQ, line_no, pos + 1, "[", indent)
                self._value_position = False
                pos += 1
                continue
            if ch == "{":
                self._flow_depth += 1
                yield Token(TokenKind.FLOW_OPEN_MAP, line_no, pos + 1, "{", indent)
                self._value_position = False
                pos += 1
                continue
            if ch == "]":
                self._flow_depth = max(0, self._flow_depth - 1)
                yield Token(TokenKind.FLOW_CLOSE_SEQ, line_no, pos + 1, "]", indent)
                self._value_position = False
                pos += 1
                continue
            if ch == "}":
                self._flow_depth = max(0, self._flow_depth - 1)
                yield Token(TokenKind.FLOW_CLOSE_MAP, line_no, pos + 1, "}", indent)
                self._value_position = False
                pos += 1
                continue
            if ch == ",":
                yield Token(TokenKind.FLOW_COMMA, line_no, pos + 1, ",", indent)
                self._value_position = False
                pos += 1
                continue

            # Anchor: ``&name``.
            if ch == "&":
                end = pos + 1
                while end < n and raw[end] not in " \t,]}":
                    end += 1
                yield Token(TokenKind.ANCHOR, line_no, pos + 1, raw[pos:end], indent)
                pos = end
                continue

            # Alias: ``*name``.
            if ch == "*":
                end = pos + 1
                while end < n and raw[end] not in " \t,]}":
                    end += 1
                yield Token(TokenKind.ALIAS, line_no, pos + 1, raw[pos:end], indent)
                pos = end
                continue

            # Merge key: ``<<:`` (only valid as a mapping key).
            if ch == "<" and raw[pos : pos + 3] == "<<:":
                yield Token(TokenKind.MERGE_KEY, line_no, pos + 1, "<<", indent)
                # Consume the ``<<`` and the trailing ``:`` plus any
                # following whitespace.  The merge key has no
                # implicit "key" identity beyond its marker — the
                # next ALIAS token is what the merge resolves to.
                pos += 3
                while pos < n and raw[pos] in " \t":
                    pos += 1
                continue

            # GitLab CI: ``!reference [section, key]`` is a cross-section
            # value reference.  The structural reader can't expand the
            # reference (would require resolving the target path against
            # the rest of the document), but emitting CUTOFF here breaks
            # every rule on every gitlab-org/gitlab subpath file, since
            # ``!reference`` appears in nearly all of them.  Instead,
            # consume the entire ``!reference [...]`` as one opaque
            # scalar value: per-line rules see the source text, the
            # walker continues, and structural-only rules degrade to
            # "this leaf has an unexpanded reference value" rather
            # than "the file is unreadable past line N."
            if ch == "!" and raw[pos : pos + 10] == "!reference":
                # Skip past "!reference" + optional whitespace.
                end = pos + 10
                while end < n and raw[end] in " \t":
                    end += 1
                if end < n and raw[end] == "[":
                    depth = 0
                    scan = end
                    while scan < n:
                        if raw[scan] == "[":
                            depth += 1
                        elif raw[scan] == "]":
                            depth -= 1
                            if depth == 0:
                                scan += 1
                                break
                        scan += 1
                    if depth > 0:
                        raise TokenizerError(line_no, "unterminated !reference tag")
                    # Closed bracket: take everything from ! to here as
                    # the opaque value.
                    yield Token(
                        TokenKind.SCALAR_PLAIN,
                        line_no,
                        column=pos + 1,
                        value=raw[pos:scan],
                        indent=indent,
                    )
                    pos = scan
                    continue
                # ``!reference`` not followed by ``[`` — not the GitLab
                # form; fall through to the generic-tag rejection so
                # the caller still gets a clear signal.
            # Reject other custom tags: ``!`` / ``!!``.
            if ch == "!":
                raise TokenizerError(line_no, "custom tags ('!') not supported")

            # Reject complex keys: ``? `` at start of value position.
            if ch == "?" and (pos + 1 == n or raw[pos + 1] in (" ", "\t")):
                raise TokenizerError(line_no, "explicit/complex keys ('?') not supported")

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
                end, value = self._read_quoted_scalar_across_lines(raw, pos, line_no)
                # Look ahead: if followed by ``:``, this was a quoted
                # key.  Otherwise it's a quoted scalar value.
                trailing = end
                while trailing < n and raw[trailing] == " ":
                    trailing += 1
                if (
                    not self._value_position
                    and trailing < n
                    and raw[trailing] == ":"
                    and (trailing + 1 == n or raw[trailing + 1] in (" ", "\t"))
                ):
                    yield Token(
                        TokenKind.KEY,
                        line_no,
                        column=pos + 1,
                        value=value,
                        indent=indent,
                    )
                    self._value_position = True
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

    def _read_quoted_scalar_across_lines(
        self, raw: str, start: int, line_no: int
    ) -> tuple[int, str]:
        try:
            return self._read_quoted_scalar(raw, start, line_no)
        except TokenizerError:
            pass

        quote = raw[start]
        line_idx = self._line_idx
        value_parts = [raw[start + 1 :]]
        while True:
            line_idx += 1
            if line_idx >= len(self._lines):
                raise TokenizerError(
                    line_no,
                    f"unterminated {quote!r}-quoted scalar",
                )

            continuation = self._lines[line_idx]
            try:
                _end, value = self._read_quoted_scalar(quote + continuation, 0, line_idx + 1)
            except TokenizerError:
                value_parts.append(continuation)
                continue
            value_parts.append(value)
            self._line_idx = line_idx
            return len(raw), "\n".join(value_parts)

    def _read_quoted_scalar(self, raw: str, start: int, line_no: int) -> tuple[int, str]:
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
                out.append(raw[pos : pos + 2])
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
    ) -> Generator[Token, None, int]:
        """Read a plain-scalar token, disambiguating key vs scalar.

        Key detection: a plain run terminated by ``:`` followed by
        whitespace or end-of-line is a mapping key.  Otherwise the
        run (including any ``:`` characters inside it) is a plain
        scalar — that's the colon-in-value case (``foo:bar:baz``).

        Key detection is suppressed in *value position*
        (``self._value_position`` — set once a ``key:`` has been
        consumed on this line).  Everything after ``run:`` is the
        value, so a ``: `` inside it (``run: echo "Status: ok"``) is
        part of the scalar, not a nested key.

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
            if (
                not self._value_position
                and ch == ":"
                and (pos + 1 == n or raw[pos + 1] in (" ", "\t"))
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
                self._value_position = True
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

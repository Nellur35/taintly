"""Zero-dependency tolerant island-grammar walker for Jenkinsfiles.

Consumes the flat :class:`~taintly.parsers.jenkinsfile.groovy_lex.Token`
stream and emits the **existing** structural :class:`Event` records
(``events.py``) so the rule consumer contract is unchanged.

The "island grammar" idea: real Jenkinsfiles are arbitrary Groovy with a
small set of *recognisable* DSL islands (pipeline/stage/steps blocks,
``sh``/``bat``/``powershell`` calls, ``withCredentials`` lists,
``environment`` assignments).  We recognise those islands and, on
anything we don't model (classes, lambdas, ``.collect{}``, ternaries,
``@Grab``, Job-DSL), we **skip to the next island** by tracking brace/
paren/bracket depth and emit nothing — we NEVER cut off the whole file.
A CUTOFF is reserved for a truly unrecoverable lexer state (an
unterminated triple-quoted string at EOF), and even then everything
parsed before it is still emitted.

Shape catalogue (intent ported from the tree-sitter walker:120-279):
  * command call  ``IDENT STRING``                     → LEAF
  * method call   ``IDENT ( args ) {closure}?``         → LEAF (first
        string arg AND named args ``script:`` / ``credentialsId:`` /
        ``variable:`` / ``passwordVariable:`` / ...)  — this is what
        catches ``sh(script: "...")``, the measured recall gap.
  * block         ``IDENT { closure }``                 → push name, recurse
  * stage         ``stage('Name') { ... }``             → LEAF for name +
        push ``stage:Name``
  * assignment    ``IDENT = STRING``                    → LEAF at key
  * list / map    ``[ ... ]`` (withCredentials etc.)    → recurse for
        nested method-call named-arg strings
  * agent         ``agent any`` / ``agent none``        → identifier LEAF
"""

from __future__ import annotations

from collections.abc import Iterator

from .events import Event, EventKind
from .groovy_lex import Token, TokKind, tokenize

# Calls whose string argument is a shell body (the primary sink).
_SHELL_CALLS = frozenset({"sh", "bat", "powershell", "pwsh"})

# Calls whose first string argument is a plain string we still surface.
_STRING_FIRST_ARG_CALLS = frozenset({"tool", "stage", "echo"})

# Named-argument keys inside a shell call whose value is the shell body.
_SHELL_SCRIPT_KEYS = frozenset({"script"})

# Named-argument keys (anywhere) whose string value we surface as a
# plain-string LEAF at a path ending in the key — credential bindings,
# parameter ids, etc. (ported from the tree-sitter withCredentials path).
_INTERESTING_NAMED_KEYS = frozenset(
    {
        "credentialsId",
        "variable",
        "passwordVariable",
        "usernameVariable",
        "keyFileVariable",
        "secretVariable",
        "name",
        "defaultValue",
    }
)

# Block directive names whose closure we push onto the path and recurse
# into.  Any other ``IDENT { ... }`` is also treated as a block (pushed by
# name) — this set just documents the canonical declarative directives.
# The walker is structural, not allowlist-gated, so unknown blocks recurse
# too (that's what keeps scripted/helper shapes from cutting off).


def iter_island_leaves(content: str) -> Iterator[Event]:
    """Yield Events for ``content`` using the zero-dep island reader."""
    walker = _IslandWalker(list(tokenize(content)))
    yield from walker.walk()


class _IslandWalker:
    """Recursive-descent-ish walker over a buffered token list.

    Holds the token buffer + a cursor.  Blocks recurse by calling
    ``_walk_block`` with an updated path; the cursor is shared so brace
    matching is exact.
    """

    def __init__(self, tokens: list[Token]) -> None:
        self._toks = tokens
        self._n = len(tokens)
        self._i = 0
        self._cutoff: Event | None = None

    # -- token cursor helpers -----------------------------------------------

    def _next_significant(self, offset: int = 0) -> int:
        """Index of the next non-trivia (skip COMMENT/NEWLINE/SEMI) token
        at or after ``self._i + offset``, or ``self._n`` if none."""
        j = self._i + offset
        while j < self._n and self._toks[j].kind in (
            TokKind.COMMENT,
            TokKind.NEWLINE,
            TokKind.SEMI,
        ):
            j += 1
        return j

    # -- entry --------------------------------------------------------------

    def walk(self) -> Iterator[Event]:
        yield from self._walk_block(end_kind=TokKind.EOF, path=())
        if self._cutoff is not None:
            yield self._cutoff

    # -- core block walk ----------------------------------------------------

    def _walk_block(self, end_kind: TokKind, path: tuple[object, ...]) -> Iterator[Event]:
        """Walk statements until ``end_kind`` (RBRACE or EOF).

        Emits LEAFs for recognised islands at ``path``; recurses into
        nested blocks with an extended path; skips anything unmodelled.
        """
        while self._i < self._n:
            tok = self._toks[self._i]

            if tok.kind == end_kind:
                # Consume the closing brace (caller handles EOF itself).
                if end_kind == TokKind.RBRACE:
                    self._i += 1
                return

            if tok.kind == TokKind.EOF:
                return

            # Flag-and-stop on an unterminated string at EOF.
            if tok.kind == TokKind.STRING and tok.unterminated:
                if self._cutoff is None:
                    self._cutoff = Event(
                        kind=EventKind.CUTOFF,
                        line=tok.line,
                        detail="unterminated string at EOF",
                    )
                self._i += 1
                continue

            # Trivia.
            if tok.kind in (TokKind.COMMENT, TokKind.NEWLINE, TokKind.SEMI):
                self._i += 1
                continue

            # A stray opening brace that isn't attached to an IDENT (a bare
            # closure, ``{ -> ... }``).  Recurse into it at the same path so
            # nested sinks still surface, then continue.
            if tok.kind == TokKind.LBRACE:
                self._i += 1
                yield from self._walk_block(TokKind.RBRACE, path)
                continue

            # A bracket literal at statement level — recurse for nested
            # strings/named args (rare at statement level; common as args).
            if tok.kind == TokKind.LBRACKET:
                yield from self._walk_bracket(path, "")
                continue

            # An identifier — the head of a call / block / assignment.
            if tok.kind == TokKind.IDENT:
                yield from self._handle_ident_statement(path)
                continue

            # Anything else (opaque op, stray paren/bracket close) — skip.
            self._i += 1

    # -- identifier-headed statement ----------------------------------------

    def _handle_ident_statement(self, path: tuple[object, ...]) -> Iterator[Event]:
        """Dispatch an ``IDENT ...`` statement.

        We look at the *next significant* token after the identifier to
        decide the shape:
          IDENT (          → method call
          IDENT {          → block
          IDENT =          → assignment
          IDENT STRING     → command call (juxtaposition)
          IDENT IDENT      → typed decl / command-with-ident (agent any)
          otherwise        → bare reference; skip the identifier.
        """
        name = self._toks[self._i].value
        nxt = self._next_significant(1)
        nxt_tok = self._toks[nxt] if nxt < self._n else self._toks[-1]

        # Dotted call head: ``foo.bar(...)`` / ``obj.method '...'`` — the
        # real call name is the last identifier.  Walk the dotted chain and
        # re-dispatch on the final segment.  ``params.X`` etc. are handled
        # here too (they fall through to "bare reference" and are skipped).
        if nxt_tok.kind == TokKind.OP and nxt_tok.value == ".":
            yield from self._handle_dotted(path)
            return

        if nxt_tok.kind == TokKind.LPAREN:
            self._i = nxt  # position on '('
            yield from self._handle_method_call(name, path)
            return

        if nxt_tok.kind == TokKind.LBRACE:
            # ``IDENT { ... }`` — a block.  Push the name and recurse.
            self._i = nxt + 1  # consume '{'
            yield from self._walk_block(TokKind.RBRACE, path + (name,))
            return

        if nxt_tok.kind == TokKind.OP and nxt_tok.value == "=":
            self._i = nxt + 1  # consume '='
            yield from self._handle_assignment(name, path)
            return

        if nxt_tok.kind == TokKind.STRING:
            # ``IDENT STRING`` — command-style call (juxtaposition), the
            # ``sh 'cmd'`` shape.  May be followed by a trailing closure
            # (rare for these).
            self._i = nxt  # position on the string
            yield from self._emit_command_call(name, path)
            return

        if nxt_tok.kind == TokKind.LBRACKET:
            # ``IDENT [ ... ] {closure}?`` — e.g. ``withCredentials([...]) {}``
            # WITHOUT parens around the list (Groovy command form).  Recurse
            # the bracket for nested named-arg strings, then handle a
            # trailing closure as the block body.
            self._i = nxt
            yield from self._walk_bracket(path, name)
            after = self._next_significant(0)
            after_tok = self._toks[after] if after < self._n else self._toks[-1]
            if after_tok.kind == TokKind.LBRACE:
                self._i = after + 1
                yield from self._walk_block(TokKind.RBRACE, path + (name,))
            return

        if nxt_tok.kind == TokKind.IDENT:
            # ``agent any`` / ``agent none`` / ``tool jdk`` — directive with
            # a bareword argument.
            if name in ("agent", "tool"):
                yield Event(
                    kind=EventKind.LEAF,
                    path=path + (name,),
                    value=nxt_tok.value,
                    value_kind="identifier",
                    line=nxt_tok.line,
                )
                self._i = nxt + 1
                return
            # Otherwise a typed-decl / two-word statement we don't model;
            # skip just the head identifier and let the next token reparse.
            self._i += 1
            return

        # Bare reference (``cleanWs``, ``deleteDir``, a variable) — skip it.
        self._i += 1

    def _handle_dotted(self, path: tuple[object, ...]) -> Iterator[Event]:
        """Consume a dotted chain ``a.b.c`` and re-dispatch on the tail.

        For ``a.b.c(...)`` we treat ``c`` as the call name; for
        ``a.b.c '...'`` likewise.  For a plain ``a.b.c`` reference we skip.
        """
        # Walk identifier (.identifier)* .
        last_ident = self._toks[self._i]
        self._i += 1  # past first ident
        while True:
            j = self._next_significant(0)
            tj = self._toks[j] if j < self._n else self._toks[-1]
            if tj.kind == TokKind.OP and tj.value == ".":
                k = self._next_significant(j - self._i + 1)
                tk = self._toks[k] if k < self._n else self._toks[-1]
                if tk.kind == TokKind.IDENT:
                    last_ident = tk
                    self._i = k + 1
                    continue
            break
        # Re-dispatch on the tail identifier shape.
        nxt = self._next_significant(0)
        nxt_tok = self._toks[nxt] if nxt < self._n else self._toks[-1]
        if nxt_tok.kind == TokKind.LPAREN:
            self._i = nxt
            yield from self._handle_method_call(last_ident.value, path)
            return
        if nxt_tok.kind == TokKind.STRING:
            self._i = nxt
            yield from self._emit_command_call(last_ident.value, path)
            return
        if nxt_tok.kind == TokKind.LBRACE:
            self._i = nxt + 1
            yield from self._walk_block(TokKind.RBRACE, path + (last_ident.value,))
            return
        # plain dotted reference — already consumed; nothing to emit.
        return

    # -- command call (juxtaposition: IDENT STRING) -------------------------

    def _emit_command_call(self, name: str, path: tuple[object, ...]) -> Iterator[Event]:
        """``IDENT STRING`` — cursor is on the STRING token."""
        s = self._toks[self._i]
        self._i += 1  # consume the string
        if s.unterminated and self._cutoff is None:
            self._cutoff = Event(
                kind=EventKind.CUTOFF, line=s.line, detail="unterminated string at EOF"
            )

        if name in _SHELL_CALLS:
            yield Event(
                kind=EventKind.LEAF,
                path=path + (name,),
                value=s.value,
                value_kind="shell",
                line=s.line,
                interpolated=s.interpolations is not None,
                spans=tuple(s.interpolations) if s.interpolations else None,
            )
            return

        if name == "stage":
            yield Event(
                kind=EventKind.LEAF,
                path=path + ("stage",),
                value=s.value,
                value_kind="string",
                line=s.line,
            )
            # A stage almost always has a trailing closure body.
            after = self._next_significant(0)
            after_tok = self._toks[after] if after < self._n else self._toks[-1]
            if after_tok.kind == TokKind.LBRACE:
                self._i = after + 1
                yield from self._walk_block(TokKind.RBRACE, path + (f"stage:{s.value}",))
            return

        if name in _STRING_FIRST_ARG_CALLS:
            yield Event(
                kind=EventKind.LEAF,
                path=path + (name,),
                value=s.value,
                value_kind="string",
                line=s.line,
            )
            return

        # Unmodelled command call with a string arg — surface nothing, but
        # consume a trailing closure if present so we don't lose its body.
        after = self._next_significant(0)
        after_tok = self._toks[after] if after < self._n else self._toks[-1]
        if after_tok.kind == TokKind.LBRACE:
            self._i = after + 1
            yield from self._walk_block(TokKind.RBRACE, path + (name,))

    # -- method call: IDENT ( args ) {closure}? -----------------------------

    def _handle_method_call(self, name: str, path: tuple[object, ...]) -> Iterator[Event]:
        """Cursor is on ``(``.  Parse the arg list, emit LEAFs, then a
        trailing closure if present.

        Emits:
          * shell LEAF for the first positional string OR a ``script:``
            named arg when ``name`` is a shell call;
          * string LEAF for a first positional string when ``name`` is a
            string-first-arg call (tool/stage/echo);
          * string LEAF for every interesting named arg
            (``credentialsId:`` etc.) anywhere in the arg list, regardless
            of call name (covers nested ``string(credentialsId: ...)``).
        """
        args = self._parse_arg_list()  # consumes through the matching ')'

        is_shell = name in _SHELL_CALLS
        emitted_primary = False

        # Shell call: prefer the ``script:`` named arg, else first positional.
        if is_shell:
            script_arg = _named(args, _SHELL_SCRIPT_KEYS)
            primary = script_arg if script_arg is not None else _first_positional_string(args)
            if primary is not None:
                yield Event(
                    kind=EventKind.LEAF,
                    path=path + (name,),
                    value=primary.value,
                    value_kind="shell",
                    line=primary.line,
                    interpolated=primary.tok is not None and primary.tok.interpolations is not None,
                    spans=(
                        tuple(primary.tok.interpolations)
                        if primary.tok is not None and primary.tok.interpolations
                        else None
                    ),
                )
                emitted_primary = True

        elif name == "stage":
            first = _first_positional_string(args)
            if first is not None:
                yield Event(
                    kind=EventKind.LEAF,
                    path=path + ("stage",),
                    value=first.value,
                    value_kind="string",
                    line=first.line,
                )
                emitted_primary = True
            # Trailing closure handled below pushes stage:<name>.
            stage_name = first.value if first is not None else ""
            after = self._next_significant(0)
            after_tok = self._toks[after] if after < self._n else self._toks[-1]
            if after_tok.kind == TokKind.LBRACE:
                self._i = after + 1
                yield from self._walk_block(TokKind.RBRACE, path + (f"stage:{stage_name}",))
            # Named args inside stage(...) are rare; still surface them.
            yield from _named_arg_leaves(args, path, name)
            return

        elif name in _STRING_FIRST_ARG_CALLS:
            first = _first_positional_string(args)
            if first is not None:
                yield Event(
                    kind=EventKind.LEAF,
                    path=path + (name,),
                    value=first.value,
                    value_kind="string",
                    line=first.line,
                )
                emitted_primary = True

        # Interesting named args (credentialsId/variable/name/...) at any
        # call — this is the withCredentials / parameters surface.  Skip the
        # ``script:`` arg we already emitted for shell calls.
        for key, sval in _named_args(args):
            if is_shell and key in _SHELL_SCRIPT_KEYS:
                continue
            if key in _INTERESTING_NAMED_KEYS:
                yield Event(
                    kind=EventKind.LEAF,
                    path=path + (name, key),
                    value=sval.value,
                    value_kind="string",
                    line=sval.line,
                )

        # Recurse into any nested bracket/method-call args (e.g.
        # ``withCredentials([string(credentialsId: ...), ...])``) so deeply
        # nested credential bindings still surface.
        yield from self._emit_nested_arg_calls(args, path, name)

        # Trailing closure body: ``foo(args) { ... }`` — push the call name
        # and recurse.  (For shell calls there's no closure body, but
        # harmless to check.)
        after = self._next_significant(0)
        after_tok = self._toks[after] if after < self._n else self._toks[-1]
        if after_tok.kind == TokKind.LBRACE and not is_shell:
            self._i = after + 1
            yield from self._walk_block(TokKind.RBRACE, path + (name,))

        _ = emitted_primary  # documented intent; no further use

    # -- argument list parsing ----------------------------------------------

    def _parse_arg_list(self) -> list[_Arg]:
        """Cursor is on ``(``.  Consume through the matching ``)``.

        Returns a flat list of :class:`_Arg` (positional strings, named
        ``key: value`` pairs where value is a string, and nested bracket/
        call markers).  Non-string positional args are recorded as opaque.
        """
        assert self._toks[self._i].kind == TokKind.LPAREN
        self._i += 1
        args: list[_Arg] = []
        pending_key: str | None = None
        while self._i < self._n:
            tok = self._toks[self._i]
            if tok.kind == TokKind.RPAREN:
                self._i += 1
                break
            if tok.kind == TokKind.EOF:
                break
            if tok.kind in (TokKind.COMMENT, TokKind.NEWLINE):
                self._i += 1
                continue
            if tok.kind == TokKind.OP and tok.value == ",":
                self._i += 1
                pending_key = None
                continue
            # ``key :`` — record the key, expect a value next.
            if tok.kind == TokKind.IDENT:
                after = self._next_significant(1)
                after_tok = self._toks[after] if after < self._n else self._toks[-1]
                if after_tok.kind == TokKind.OP and after_tok.value == ":":
                    pending_key = tok.value
                    self._i = after + 1
                    continue
                # IDENT that's actually a nested call: ``string(credentialsId:..)``
                after2 = after_tok
                if after2.kind == TokKind.LPAREN:
                    # Record a nested-call marker spanning this call so the
                    # outer walker can recurse for its named args.
                    start = self._i
                    self._i = after
                    nested = self._parse_arg_list()
                    args.append(_Arg(kind="call", name=tok.value, nested=nested, tok=tok))
                    pending_key = None
                    _ = start
                    continue
                if after2.kind == TokKind.LBRACKET:
                    self._i = after
                    nested = self._parse_bracket_args()
                    args.append(_Arg(kind="call", name=tok.value, nested=nested, tok=tok))
                    pending_key = None
                    continue
                # Bareword value (e.g. ``returnStdout: true`` → true ident).
                args.append(
                    _Arg(
                        kind="named" if pending_key else "ident",
                        key=pending_key,
                        value=tok.value,
                        tok=tok,
                        is_string=False,
                    )
                )
                pending_key = None
                self._i += 1
                continue
            if tok.kind == TokKind.STRING:
                if tok.unterminated and self._cutoff is None:
                    self._cutoff = Event(
                        kind=EventKind.CUTOFF, line=tok.line, detail="unterminated string at EOF"
                    )
                args.append(
                    _Arg(
                        kind="named" if pending_key else "positional",
                        key=pending_key,
                        value=tok.value,
                        tok=tok,
                        is_string=True,
                    )
                )
                pending_key = None
                self._i += 1
                continue
            if tok.kind == TokKind.LBRACKET:
                nested = self._parse_bracket_args()
                args.append(_Arg(kind="bracket", nested=nested, tok=tok))
                pending_key = None
                continue
            if tok.kind == TokKind.LBRACE:
                # A closure passed as an argument — skip its body via depth.
                self._skip_balanced(TokKind.LBRACE, TokKind.RBRACE)
                pending_key = None
                continue
            if tok.kind == TokKind.LPAREN:
                self._skip_balanced(TokKind.LPAREN, TokKind.RPAREN)
                pending_key = None
                continue
            # Opaque token inside args — record nothing, keep scanning.
            self._i += 1
            pending_key = None
        return args

    def _parse_bracket_args(self) -> list[_Arg]:
        """Cursor is on ``[``.  Consume through the matching ``]``; same arg
        grammar as ``_parse_arg_list`` (list/map literal)."""
        assert self._toks[self._i].kind == TokKind.LBRACKET
        self._i += 1
        args: list[_Arg] = []
        pending_key: str | None = None
        while self._i < self._n:
            tok = self._toks[self._i]
            if tok.kind == TokKind.RBRACKET:
                self._i += 1
                break
            if tok.kind == TokKind.EOF:
                break
            if tok.kind in (TokKind.COMMENT, TokKind.NEWLINE):
                self._i += 1
                continue
            if tok.kind == TokKind.OP and tok.value in (",", ":"):
                if tok.value == ",":
                    pending_key = None
                self._i += 1
                continue
            if tok.kind == TokKind.IDENT:
                after = self._next_significant(1)
                after_tok = self._toks[after] if after < self._n else self._toks[-1]
                if after_tok.kind == TokKind.OP and after_tok.value == ":":
                    pending_key = tok.value
                    self._i = after + 1
                    continue
                if after_tok.kind == TokKind.LPAREN:
                    self._i = after
                    nested = self._parse_arg_list()
                    args.append(_Arg(kind="call", name=tok.value, nested=nested, tok=tok))
                    pending_key = None
                    continue
                if after_tok.kind == TokKind.LBRACKET:
                    self._i = after
                    nested = self._parse_bracket_args()
                    args.append(_Arg(kind="call", name=tok.value, nested=nested, tok=tok))
                    pending_key = None
                    continue
                args.append(
                    _Arg(
                        kind="named" if pending_key else "ident",
                        key=pending_key,
                        value=tok.value,
                        tok=tok,
                        is_string=False,
                    )
                )
                pending_key = None
                self._i += 1
                continue
            if tok.kind == TokKind.STRING:
                if tok.unterminated and self._cutoff is None:
                    self._cutoff = Event(
                        kind=EventKind.CUTOFF, line=tok.line, detail="unterminated string at EOF"
                    )
                args.append(
                    _Arg(
                        kind="named" if pending_key else "positional",
                        key=pending_key,
                        value=tok.value,
                        tok=tok,
                        is_string=True,
                    )
                )
                pending_key = None
                self._i += 1
                continue
            if tok.kind == TokKind.LBRACKET:
                nested = self._parse_bracket_args()
                args.append(_Arg(kind="bracket", nested=nested, tok=tok))
                pending_key = None
                continue
            if tok.kind == TokKind.LBRACE:
                self._skip_balanced(TokKind.LBRACE, TokKind.RBRACE)
                pending_key = None
                continue
            if tok.kind == TokKind.LPAREN:
                self._skip_balanced(TokKind.LPAREN, TokKind.RPAREN)
                pending_key = None
                continue
            self._i += 1
            pending_key = None
        return args

    def _walk_bracket(self, path: tuple[object, ...], call_name: str) -> Iterator[Event]:
        """Statement/command-position ``[ ... ]`` — parse it and surface any
        interesting named args / nested calls (withCredentials command form
        without parens).  ``call_name`` is the directive the bracket belongs
        to (e.g. ``withCredentials``); empty for a bare bracket literal."""
        args = self._parse_bracket_args()
        yield from _named_arg_leaves(args, path, call_name)
        yield from self._emit_nested_arg_calls(args, path, call_name)

    def _emit_nested_arg_calls(
        self, args: list[_Arg], path: tuple[object, ...], call_name: str
    ) -> Iterator[Event]:
        """Recurse into nested call/bracket args, surfacing interesting
        named-arg strings (the ``withCredentials([string(credentialsId:...)])``
        surface)."""
        base = path + (call_name,) if call_name else path
        for arg in args:
            if arg.nested is None:
                continue
            if arg.kind == "bracket":
                # A list/map literal is not a named scope — pass the path
                # through unchanged so nested calls attribute correctly.
                yield from _named_arg_leaves(arg.nested, path, call_name)
                yield from self._emit_nested_arg_calls(arg.nested, path, call_name)
            elif arg.kind == "call":
                inner_name = arg.name or call_name
                yield from _named_arg_leaves(arg.nested, base, inner_name)
                yield from self._emit_nested_arg_calls(arg.nested, base, inner_name)

    # -- assignment: IDENT = STRING -----------------------------------------

    def _handle_assignment(self, key: str, path: tuple[object, ...]) -> Iterator[Event]:
        """Cursor is just past ``=``.  Emit a LEAF if the rhs is a string;
        otherwise skip (e.g. ``KEY = credentials('id')`` is a call rhs —
        we leave that to the call walker by NOT consuming it as a value)."""
        nxt = self._next_significant(0)
        nxt_tok = self._toks[nxt] if nxt < self._n else self._toks[-1]
        if nxt_tok.kind == TokKind.STRING:
            self._i = nxt + 1
            if nxt_tok.unterminated and self._cutoff is None:
                self._cutoff = Event(
                    kind=EventKind.CUTOFF, line=nxt_tok.line, detail="unterminated string at EOF"
                )
            yield Event(
                kind=EventKind.LEAF,
                path=path + (key,),
                value=nxt_tok.value,
                value_kind="string",
                line=nxt_tok.line,
            )
            return
        # Non-string rhs — leave the cursor where it is so the rhs (which
        # may be a ``credentials('id')`` call) is walked as a normal stmt.

    # -- low-level skip ------------------------------------------------------

    def _skip_balanced(self, open_kind: TokKind, close_kind: TokKind) -> None:
        """Cursor is on an ``open_kind`` token; advance past its match,
        tracking nesting.  Tolerant: stops at EOF."""
        depth = 0
        while self._i < self._n:
            k = self._toks[self._i].kind
            if k == open_kind:
                depth += 1
            elif k == close_kind:
                depth -= 1
                if depth == 0:
                    self._i += 1
                    return
            elif k == TokKind.EOF:
                return
            self._i += 1


# ---------------------------------------------------------------------------
# Argument record + helpers
# ---------------------------------------------------------------------------


class _Arg:
    """A parsed call/bracket argument.

    kind:
      ``positional`` — a positional string literal value
      ``named``      — a ``key: value`` pair (value is string or ident)
      ``ident``      — a bareword positional value (true/false/var)
      ``call``       — a nested call ``name(...)`` (has ``nested`` args)
      ``bracket``    — a nested ``[...]`` literal (has ``nested`` args)
    """

    __slots__ = ("is_string", "key", "kind", "name", "nested", "tok", "value")

    def __init__(
        self,
        kind: str,
        key: str | None = None,
        value: str = "",
        tok: Token | None = None,
        is_string: bool = False,
        name: str | None = None,
        nested: list[_Arg] | None = None,
    ) -> None:
        self.kind = kind
        self.key = key
        self.value = value
        self.tok = tok
        self.is_string = is_string
        self.name = name
        self.nested = nested

    @property
    def line(self) -> int:
        return self.tok.line if self.tok is not None else 0


def _first_positional_string(args: list[_Arg]) -> _Arg | None:
    """First positional string argument, if the leading non-named arg is a
    string (mirrors tree-sitter ``_first_string_arg``: the first arg must
    be a string for a juxtaposition-style match)."""
    for arg in args:
        if arg.kind == "named":
            # A leading named arg means there's no positional first string;
            # but keep scanning — ``echo(message: 'x')`` still has none.
            continue
        if arg.kind == "positional" and arg.is_string:
            return arg
        # First positional non-string arg → no first-string match.
        if arg.kind in ("positional", "ident", "call", "bracket"):
            return None
    return None


def _named(args: list[_Arg], keys: frozenset[str]) -> _Arg | None:
    """First named-string arg whose key is in ``keys``."""
    for arg in args:
        if arg.kind == "named" and arg.is_string and arg.key in keys:
            return arg
    return None


def _named_args(args: list[_Arg]) -> Iterator[tuple[str, _Arg]]:
    """Yield ``(key, arg)`` for every named *string* arg."""
    for arg in args:
        if arg.kind == "named" and arg.is_string and arg.key:
            yield arg.key, arg


def _named_arg_leaves(
    args: list[_Arg], path: tuple[object, ...], call_name: str
) -> Iterator[Event]:
    """Emit string LEAFs for interesting named args in ``args`` at
    ``path + (call_name, key)``."""
    for key, arg in _named_args(args):
        if key in _INTERESTING_NAMED_KEYS:
            yield Event(
                kind=EventKind.LEAF,
                path=path + (call_name, key),
                value=arg.value,
                value_kind="string",
                line=arg.line,
            )

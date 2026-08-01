"""Minimal GitHub Actions ``${{ }}`` expression parser (zero-dependency).

The regex taint detection matches attacker-controlled
contexts as dot-literal substrings (``github\\.event\\.pull_request\\.title``),
so it is blind to the documented-equivalent encodings an attacker can use:

    github.event.pull_request.title          (canonical — detected)
    github.event.pull_request['title']        (index access — MISSED by regex)
    github['event']['pull_request']['title']  (bracket chain — MISSED)
    GITHUB.event.pull_request.title           (context case  — MISSED)

This module parses the expression body into a small AST and normalises every
context reference to a canonical lowercased dotted path, so all of the above
collapse to ``github.event.pull_request.title`` — which the existing taint
list then matches unchanged.

Modelled on actionlint's ``expr_{lexer,parser,ast,sema}.go``. Deliberately NOT
a type-checker or evaluator: it extracts *provenance reachability* (which
context paths appear in an expression), which is all taint analysis needs.

Grammar facts (GitHub docs + actionlint):
  * ``a.b`` ≡ ``a['b']`` ≡ ``a["b"]`` for string-literal members; index
    normalisation happens after parsing, in :func:`canonical_path`.
  * Context root + property names are case-insensitive → the canonical path is
    fully lower-cased (safe for a taint tool: it can only normalise an
    attacker's casing, never invent a new sink — matching is against the curated
    taint list).
  * Strings are single-quoted with ``''`` escaping; ``"`` is not a string
    delimiter in the expression language.
  * Functions (``fromJSON``, ``toJSON``, ``format``, ``contains``, …) are
    opaque for path extraction, except the exact identity round trip
    ``fromJSON(toJSON(value))``. That form preserves ``value``'s object shape,
    so a post-call member chain is canonicalized. All other call-rooted spines
    yield only paths inside their arguments; modelling their member chains
    would need builtin dataflow and remains out of scope here.

On any malformed / unsupported input the tokenizer or parser raises
:class:`ExprSyntaxError`; callers fall back to the legacy regex so there is no
recall regression.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

__all__ = [
    "ExprSyntaxError",
    "canonical_path",
    "context_paths",
    "iter_expression_bodies",
    "parse",
    "result_provenance_paths",
    "structural_expr_enabled",
]


class ExprSyntaxError(ValueError):
    """Raised on un-lexable / un-parseable expression text."""


def structural_expr_enabled() -> bool:
    """Whether consumers should augment their dot-literal context regexes with
    this structural ``${{ }}`` parser. Default on; set
    ``TAINTLY_STRUCTURAL_EXPR=0`` for a regex-only escape hatch (mirrors
    ``TAINTLY_TAINT_BACKEND``). One reader so the two consumers — SEC4-GH-004
    and the taint engine — never drift."""
    return os.environ.get("TAINTLY_STRUCTURAL_EXPR", "1") != "0"


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

# Identifiers: GitHub allows letters, digits, ``_`` and ``-`` (step ids etc.),
# must start with a letter or underscore.
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
# Numbers: int / hex / float-with-exponent. Captured but unused by taint.
_NUM_RE = re.compile(
    r"-?(?:0[xX][0-9a-fA-F]+|\d+\.\d*(?:[eE][+-]?\d+)?|\.\d+|\d+(?:[eE][+-]?\d+)?)"
)
_TWO_CHAR = {"==", "!=", "<=", ">=", "&&", "||"}
_ONE_CHAR = set(".[](),*<>!")


@dataclass(frozen=True)
class _Token:
    kind: str  # IDENT STRING NUMBER OP EOF
    value: str


def tokenize(s: str) -> list[_Token]:
    toks: list[_Token] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "'":
            # single-quoted string; '' is an escaped quote
            j = i + 1
            buf: list[str] = []
            while j < n:
                if s[j] == "'":
                    if j + 1 < n and s[j + 1] == "'":
                        buf.append("'")
                        j += 2
                        continue
                    break
                buf.append(s[j])
                j += 1
            if j >= n:
                raise ExprSyntaxError("unterminated string literal")
            toks.append(_Token("STRING", "".join(buf)))
            i = j + 1
            continue
        if s[i : i + 2] in _TWO_CHAR:
            toks.append(_Token("OP", s[i : i + 2]))
            i += 2
            continue
        m = _IDENT_RE.match(s, i)
        if m:
            toks.append(_Token("IDENT", m.group()))
            i = m.end()
            continue
        m = _NUM_RE.match(s, i)
        if m and not (c == "-" and toks and toks[-1].kind in ("IDENT", "STRING", "NUMBER")):
            # a leading '-' is a number sign only when not a binary minus; the
            # expression grammar has no '-' operator we care about, so treat a
            # bare '-' elsewhere as unsupported below.
            toks.append(_Token("NUMBER", m.group()))
            i = m.end()
            continue
        if c in _ONE_CHAR:
            toks.append(_Token("OP", c))
            i += 1
            continue
        raise ExprSyntaxError(f"unexpected character {c!r} at {i}")
    toks.append(_Token("EOF", ""))
    return toks


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Lit:
    value: object
    kind: str  # "string" | "number" | "bool" | "null"


@dataclass(frozen=True)
class Var:
    name: str


@dataclass(frozen=True)
class Deref:
    recv: object
    prop: str


@dataclass(frozen=True)
class Index:
    recv: object
    index: object


@dataclass(frozen=True)
class Filter:  # ``a.*``
    recv: object


@dataclass(frozen=True)
class Call:
    name: str
    args: list[object] = field(default_factory=list)


@dataclass(frozen=True)
class Unary:
    op: str
    operand: object


@dataclass(frozen=True)
class Binary:
    op: str
    left: object
    right: object


_KEYWORD_LITERALS = {
    "true": Lit(True, "bool"),
    "false": Lit(False, "bool"),
    "null": Lit(None, "null"),
}


# ---------------------------------------------------------------------------
# Parser — recursive descent, actionlint precedence chain
#   or -> and -> compare -> unary -> postfix -> primary
# ---------------------------------------------------------------------------


# Maximum expression nesting depth. Real GitHub ``${{ }}`` expressions are
# shallow (< 10 levels); this bound is ~10x generous yet well under CPython's
# recursion limit (each nesting level costs several parser frames). It turns an
# adversarial deeply-nested expression from an attacker-controlled workflow —
# e.g. ``fromJSON(fromJSON(...))`` x1000, or ``!!!!...`` — into a clean
# ``ExprSyntaxError`` (which callers already handle as "couldn't parse") instead
# of an unguarded ``RecursionError`` that could crash the scan.
_MAX_PARSE_DEPTH = 100


class _Parser:
    def __init__(self, toks: list[_Token]) -> None:
        self._toks = toks
        self._i = 0
        self._depth = 0

    def _peek(self) -> _Token:
        return self._toks[self._i]

    def _next(self) -> _Token:
        t = self._toks[self._i]
        self._i += 1
        return t

    def _eat_op(self, op: str) -> None:
        t = self._next()
        if t.kind != "OP" or t.value != op:
            raise ExprSyntaxError(f"expected {op!r}, got {t.value!r}")

    def parse(self) -> object:
        node = self._or()
        if self._peek().kind != "EOF":
            raise ExprSyntaxError(f"trailing tokens at {self._peek().value!r}")
        return node

    def _or(self) -> object:
        # The recursion re-entry point for every nested sub-expression (parens,
        # brackets, function arguments all descend through here). Bound it.
        self._depth += 1
        if self._depth > _MAX_PARSE_DEPTH:
            raise ExprSyntaxError("expression nesting exceeds the supported depth")
        try:
            node = self._and()
            while self._peek().kind == "OP" and self._peek().value == "||":
                self._next()
                node = Binary("||", node, self._and())
            return node
        finally:
            self._depth -= 1

    def _and(self) -> object:
        node = self._compare()
        while self._peek().kind == "OP" and self._peek().value == "&&":
            self._next()
            node = Binary("&&", node, self._compare())
        return node

    def _compare(self) -> object:
        node = self._unary()
        if self._peek().kind == "OP" and self._peek().value in ("==", "!=", "<", "<=", ">", ">="):
            op = self._next().value
            node = Binary(op, node, self._unary())
        return node

    def _unary(self) -> object:
        if self._peek().kind == "OP" and self._peek().value == "!":
            # A ``!!!!...`` chain recurses here without passing through _or().
            self._depth += 1
            if self._depth > _MAX_PARSE_DEPTH:
                raise ExprSyntaxError("expression nesting exceeds the supported depth")
            self._next()
            try:
                return Unary("!", self._unary())
            finally:
                self._depth -= 1
        return self._postfix()

    def _postfix(self) -> object:
        node = self._primary()
        while True:
            t = self._peek()
            if t.kind == "OP" and t.value == ".":
                self._next()
                nxt = self._next()
                if nxt.kind == "OP" and nxt.value == "*":
                    node = Filter(node)
                elif nxt.kind == "IDENT":
                    node = Deref(node, nxt.value)
                else:
                    raise ExprSyntaxError(f"expected property after '.', got {nxt.value!r}")
            elif t.kind == "OP" and t.value == "[":
                self._next()
                idx = self._or()
                self._eat_op("]")
                node = Index(node, idx)
            else:
                break
        return node

    def _primary(self) -> object:
        t = self._next()
        if t.kind == "OP" and t.value == "(":
            node = self._or()
            self._eat_op(")")
            return node
        if t.kind == "STRING":
            return Lit(t.value, "string")
        if t.kind == "NUMBER":
            return Lit(t.value, "number")
        if t.kind == "IDENT":
            low = t.value.lower()
            if low in _KEYWORD_LITERALS:
                return _KEYWORD_LITERALS[low]
            # function call?
            if self._peek().kind == "OP" and self._peek().value == "(":
                self._next()
                args: list[object] = []
                if not (self._peek().kind == "OP" and self._peek().value == ")"):
                    args.append(self._or())
                    while self._peek().kind == "OP" and self._peek().value == ",":
                        self._next()
                        args.append(self._or())
                self._eat_op(")")
                return Call(t.value, args)
            return Var(t.value)
        raise ExprSyntaxError(f"unexpected token {t.value!r}")


def parse(body: str) -> object:
    """Parse one ``${{ }}`` body (without the braces) into an AST node.

    Raises :class:`ExprSyntaxError` on malformed input.
    """
    return _Parser(tokenize(body)).parse()


# ---------------------------------------------------------------------------
# Normalisation + path extraction
# ---------------------------------------------------------------------------


def canonical_path(node: object) -> str | None:
    """Collapse a ``Var``-rooted property/index spine to a canonical lowercased
    dotted path (``github.event.pull_request.title``), or ``None`` when the
    spine contains a dynamic index, an object filter (``.*``), or is rooted in
    anything other than a plain context variable (e.g. a function call)."""
    parts: list[str] = []
    cur = node
    while True:
        if isinstance(cur, Var):
            parts.append(cur.name)
            break
        if isinstance(cur, Deref):
            parts.append(cur.prop)
            cur = cur.recv
        elif isinstance(cur, Index) and isinstance(cur.index, Lit) and cur.index.kind == "string":
            parts.append(str(cur.index.value))
            cur = cur.recv
        elif (roundtrip_value := _json_roundtrip_value(cur)) is not None:
            # ``fromJSON(toJSON(x))`` preserves x's JSON object shape. This is
            # the one call-rooted spine we can normalize without guessing about
            # builtin semantics or inventing a path.
            cur = roundtrip_value
        else:
            return None
    return ".".join(reversed(parts)).lower()


def _json_roundtrip_value(node: object) -> object | None:
    """Return the value in an exact ``fromJSON(toJSON(value))`` round trip.

    Other function calls remain opaque. In particular, this does not treat
    ``fromJSON(inputs.payload)`` as a property-preserving operation.
    """
    if (
        isinstance(node, Call)
        and node.name.lower() == "fromjson"
        and len(node.args) == 1
        and isinstance(node.args[0], Call)
        and node.args[0].name.lower() == "tojson"
        and len(node.args[0].args) == 1
    ):
        return node.args[0].args[0]
    return None


def _iter_paths(node: object) -> Iterator[str]:
    cp = canonical_path(node)
    if cp is not None:
        yield cp
        return  # the maximal spine is one path; do not also yield prefixes
    if isinstance(node, Deref | Filter | Index):
        # spine broken by a dynamic segment — recurse into the receiver and any
        # dynamic index so paths inside survive (e.g. ``a[github.event.x]``).
        yield from _iter_paths(node.recv)
        if isinstance(node, Index):
            yield from _iter_paths(node.index)
    elif isinstance(node, Call):
        for a in node.args:
            yield from _iter_paths(a)
    elif isinstance(node, Unary):
        yield from _iter_paths(node.operand)
    elif isinstance(node, Binary):
        yield from _iter_paths(node.left)
        yield from _iter_paths(node.right)


def context_paths(body: str) -> list[str]:
    """Parse one ``${{ }}`` body and return every canonical context path it
    references (deduped, order-stable). Raises :class:`ExprSyntaxError`."""
    seen: dict[str, None] = {}
    for p in _iter_paths(parse(body)):
        seen.setdefault(p, None)
    return list(seen)


_BOOLEAN_RESULT_FUNCTIONS = frozenset(
    {
        "always",
        "cancelled",
        "contains",
        "endswith",
        "failure",
        "startswith",
        "success",
    }
)
_COMPARISON_OPERATORS = frozenset({"==", "!=", "<", "<=", ">", ">="})


def _iter_result_provenance(node: object) -> Iterator[str]:
    """Yield paths whose bytes can contribute to ``node``'s result value.

    This is narrower than :func:`_iter_paths`: references used only as boolean
    conditions do not taint the resulting string. Unknown value-returning
    functions are conservative and propagate their arguments.
    """
    cp = canonical_path(node)
    if cp is not None:
        yield cp
        return
    if isinstance(node, Lit):
        return
    if isinstance(node, Deref | Filter | Index):
        yield from _iter_result_provenance(node.recv)
        if isinstance(node, Index):
            yield from _iter_result_provenance(node.index)
        return
    if isinstance(node, Call):
        if node.name.lower() in _BOOLEAN_RESULT_FUNCTIONS:
            return
        for arg in node.args:
            yield from _iter_result_provenance(arg)
        return
    if isinstance(node, Unary):
        # The only supported unary operator is ``!``; its result is boolean.
        return
    if isinstance(node, Binary):
        if node.op in _COMPARISON_OPERATORS:
            return
        if node.op == "&&":
            # The left side controls selection. Only the right side can become
            # the value returned by GitHub's short-circuit expression.
            yield from _iter_result_provenance(node.right)
            return
        if node.op == "||":
            yield from _iter_result_provenance(node.left)
            yield from _iter_result_provenance(node.right)


def result_provenance_paths(body: str) -> list[str]:
    """Return context paths whose values can reach the expression result.

    Comparisons, negation, and boolean-returning functions are control-only.
    Fallbacks and value transforms such as ``format()``, ``join()``,
    ``toJSON()``, and ``fromJSON()`` preserve argument provenance.
    """
    seen: dict[str, None] = {}
    for path in _iter_result_provenance(parse(body)):
        seen.setdefault(path, None)
    return list(seen)


_EXPR_BODY_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)


def iter_expression_bodies(text: str) -> Iterator[str]:
    """Yield the inner body of every ``${{ ... }}`` occurrence in ``text``."""
    for m in _EXPR_BODY_RE.finditer(text):
        yield m.group(1)

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
    opaque for path extraction: a spine rooted in a call (e.g.
    ``fromJSON(toJSON(github.event)).pull_request.title``) yields only the
    paths inside the call's arguments (``github.event``), never the post-call
    member chain — modelling that needs builtin dataflow, out of scope here.

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


class _Parser:
    def __init__(self, toks: list[_Token]) -> None:
        self._toks = toks
        self._i = 0

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
        node = self._and()
        while self._peek().kind == "OP" and self._peek().value == "||":
            self._next()
            node = Binary("||", node, self._and())
        return node

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
            self._next()
            return Unary("!", self._unary())
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
        else:
            return None
    return ".".join(reversed(parts)).lower()


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


_EXPR_BODY_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)


def iter_expression_bodies(text: str) -> Iterator[str]:
    """Yield the inner body of every ``${{ ... }}`` occurrence in ``text``."""
    for m in _EXPR_BODY_RE.finditer(text):
        yield m.group(1)

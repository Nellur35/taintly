"""Within-file multi-hop taint resolver for Jenkins pipelines.

The Jenkins TAINT-JK-001 rule is single-body: it fires only when an
attacker-controlled binding (``${env.CHANGE_TITLE}``, ``${params.X}``,
the well-namespaced GWT names, …) is interpolated **directly** into a
double-quoted shell sink.  Any one hop of Groovy indirection is a false
negative today::

    def t = params.FOO            // hop 1: source -> local
    sh "deploy ${t}"              // sink reached via the local, NOT direct

    def url = "${env.CHANGE_BRANCH}/x"   // hop 1: source -> GString local
    def cmd = "curl ${url}"              // hop 2: local -> local
    sh "${cmd}"                          // sink reached at hop 3

This module is the analogue of the GitHub ``taintly.taint`` fixed point,
scoped to **within one file** (cross-file / shared-library taint is the
measured-deferred #19).  It reuses the zero-dependency Groovy tokenizer
(``groovy_lex.tokenize``) — the same lexer the island walker reads — so
it inherits the walker's GString-span and quote-kind awareness without a
second parser.

SOUNDNESS (the load-bearing design constraint, established verify-first
on the corpus): taint propagates **only through value-preserving RHS
shapes** — a bare reference to a tainted name/var, or a GString that
interpolates a tainted name/var.  It does **NOT** propagate through a
method-call return where the tainted value is merely an *argument*
(``def x = lookup(env.CHANGE_ID)`` returns ``lookup``'s value, not the
attacker bytes).  The naive "RHS contains a tainted name → tainted"
heuristic over-fired 3:1 on the corpus (method-return + cross-function
name collisions); this scoped propagation kept the one real flow and
dropped all three false positives.

Output: :class:`MultiHopFlow` records — one per (tainted var → shell
sink) reaching the sink via **N≥1** local hops (the N==0 direct case is
already TAINT-JK-001's, and is excluded so the two rules don't co-fire).
Each flow carries the ordered hop chain for provenance rendering.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .groovy_lex import Token, TokKind, tokenize

# Shell-body sinks — the same set the island walker recognises.
_SHELL_CALLS = frozenset({"sh", "bat", "powershell", "pwsh"})

# Leading identifier of a GString interpolation expression: ``url`` from
# ``url``, ``u`` from ``u.trim()`` / ``u[0]`` / ``u + x``.  A transform of a
# tainted value (``${u.trim()}``) is still tainted, so we key on the head
# identifier of the dotted/indexed/operator expression.
_LEAD_IDENT_RE = re.compile(r"\s*([A-Za-z_$][A-Za-z0-9_$]*)")

# Groovy keywords that can sit where ``def`` does but are NOT a binding
# target (so ``return foo`` / ``if (x)`` don't get mistaken for ``def``-less
# assignments handled elsewhere).  Only ``def`` introduces a fresh local in
# the shapes we model; typed decls (``String x = ...``) are handled by the
# bare ``IDENT IDENT = `` path.
_TYPE_DECL_HEADS = frozenset({"def", "String", "final", "var", "Object", "GString"})


@dataclass(frozen=True)
class _Assign:
    """One ``def x = <expr>`` / ``x = <expr>`` binding."""

    var: str
    rhs: tuple[Token, ...]
    line: int


@dataclass(frozen=True)
class _Sink:
    """One shell-body sink occurrence."""

    call: str
    body: str
    line: int
    interpolated: bool
    # Leading identifiers of the body's GString interpolation spans.
    refs: frozenset[str]


@dataclass(frozen=True)
class MultiHopFlow:
    """A resolved multi-hop taint flow ending at a shell sink.

    ``hops`` is the ordered provenance chain: the source name first
    (e.g. ``env.CHANGE_BRANCH``), then each intermediate local variable,
    then the sink call (``sh``).  ``var`` is the tainted local that
    reached the sink; ``sink_line`` / ``sink_body`` locate it.
    """

    var: str
    sink_call: str
    sink_line: int
    sink_body: str
    hops: tuple[str, ...]


def _lead_ident(expr: str) -> str | None:
    m = _LEAD_IDENT_RE.match(expr)
    return m.group(1) if m else None


def _next_significant(toks: list[Token], i: int) -> int:
    """Index of the next non-trivia token at or after ``i``."""
    n = len(toks)
    while i < n and toks[i].kind in (TokKind.COMMENT, TokKind.NEWLINE, TokKind.SEMI):
        i += 1
    return i


def _span_refs(tok: Token) -> set[str]:
    """Leading identifiers of every GString interpolation span in ``tok``."""
    refs: set[str] = set()
    if tok.kind == TokKind.STRING and tok.interpolations:
        for span in tok.interpolations:
            li = _lead_ident(span.expr)
            if li:
                refs.add(li)
    return refs


def _collect(content: str) -> tuple[list[_Assign], list[_Sink]]:
    """Single pass over the token stream collecting assignments and sinks.

    Brace depth is NOT tracked for scope here — propagation soundness is
    enforced by the value-preserving RHS rule, and the corpus verify-first
    showed function-local name reuse is rare enough that a file-flat model
    plus the RHS rule is precise.  (Cross-function over-taint was the FP
    that the *naive* propagation produced; the RHS rule removes it.)
    """
    toks = list(tokenize(content))
    n = len(toks)
    assigns: list[_Assign] = []
    sinks: list[_Sink] = []
    i = 0
    while i < n:
        tok = toks[i]

        if tok.kind == TokKind.IDENT:
            # Shell sink: ``sh "..."`` / ``sh(script: "...")`` / ``sh("...")``.
            if tok.value in _SHELL_CALLS:
                sink = _read_sink(toks, i)
                if sink is not None:
                    sinks.append(sink)
                # fall through to also consider this token as an assignment
                # target only if it were ``sh = ...`` (never happens); advance.

            # Assignment target resolution.
            target_idx = i
            name = tok.value
            if name in _TYPE_DECL_HEADS:
                k = _next_significant(toks, i + 1)
                if k < n and toks[k].kind == TokKind.IDENT:
                    name = toks[k].value
                    target_idx = k
                else:
                    i += 1
                    continue
            # ``target =`` (single '=', not '==' / '+=' etc.)
            k = _next_significant(toks, target_idx + 1)
            if (
                k < n
                and toks[k].kind == TokKind.OP
                and toks[k].value == "="
                and (k + 1 >= n or toks[k + 1].value != "=")
            ):
                rhs, end = _read_rhs(toks, k + 1)
                if rhs:
                    assigns.append(_Assign(var=name, rhs=tuple(rhs), line=tok.line))
                i = end
                continue

        i += 1
    return assigns, sinks


def _read_sink(toks: list[Token], i: int) -> _Sink | None:
    """``toks[i]`` is a shell-call IDENT; find its body string.

    Recognises the juxtaposition (``sh "..."``), parenthesised
    (``sh("...")``), and named-arg (``sh(script: "...")``) forms by
    scanning a short window for the first STRING, mirroring the island
    walker's shell-leaf extraction.
    """
    n = len(toks)
    call = toks[i].value
    j = i + 1
    steps = 0
    while j < n and steps < 10:
        tk = toks[j]
        if tk.kind == TokKind.STRING:
            return _Sink(
                call=call,
                body=tk.value,
                line=tk.line,
                interpolated=tk.interpolations is not None,
                refs=frozenset(_span_refs(tk)),
            )
        if tk.kind in (TokKind.NEWLINE, TokKind.RBRACE, TokKind.SEMI):
            break
        j += 1
        steps += 1
    return None


def _read_rhs(toks: list[Token], start: int) -> tuple[list[Token], int]:
    """Collect RHS tokens from ``start`` until the statement terminator.

    Stops at a depth-0 NEWLINE / SEMI / closing bracket.  Returns the RHS
    token list and the cursor position just past it.
    """
    n = len(toks)
    rhs: list[Token] = []
    depth = 0
    k = start
    # Skip leading trivia.
    while k < n and toks[k].kind in (TokKind.COMMENT, TokKind.NEWLINE):
        k += 1
    while k < n:
        tk = toks[k]
        if tk.kind in (TokKind.LPAREN, TokKind.LBRACE, TokKind.LBRACKET):
            depth += 1
        elif tk.kind in (TokKind.RPAREN, TokKind.RBRACE, TokKind.RBRACKET):
            if depth == 0:
                break
            depth -= 1
        elif tk.kind in (TokKind.NEWLINE, TokKind.SEMI) and depth == 0:
            break
        rhs.append(tk)
        k += 1
    return rhs, k


def _rhs_depth0_text(rhs: tuple[Token, ...]) -> str:
    """Text of RHS tokens that sit at paren-depth 0, with dotted access
    re-joined tightly (no spaces around ``.``).

    A tainted name at depth 0 is a value-preserving reference / concatenation
    (``params.FOO``, ``params.FOO ?: 'x'``, ``"a" + env.CHANGE_TITLE``).  A
    tainted name only *inside* parens is an argument to a call — its taint
    does NOT flow to the call's return value, so we exclude it.

    STRING token bodies are EXCLUDED here: a source that appears as text
    inside a string literal is only a real source if the string interpolates
    (a GString), and that path is handled by the interpolation-span check.
    Including the decoded body would wrongly treat a SINGLE-quoted literal
    ``'${env.CHANGE_BRANCH}'`` (which Groovy does NOT substitute) as a source.

    The tokenizer splits ``params.FOO`` into ``params`` ``.`` ``FOO``; the
    source vocabulary (``params\\.\\w+``, ``env\\.CHANGE_*``) is written
    against the dotted form, so a ``.`` is concatenated with no surrounding
    space and every other token is space-separated.
    """
    parts: list[str] = []
    depth = 0
    for tk in rhs:
        if tk.kind == TokKind.LPAREN:
            depth += 1
        elif tk.kind == TokKind.RPAREN:
            depth -= 1
        if depth != 0:
            continue
        if tk.kind == TokKind.STRING:
            # A string body is not a bare reference; break any dotted glue so
            # ``a.'b'`` can't accidentally reconstruct across a literal.
            parts.append("\x00")
            continue
        is_dot = tk.kind == TokKind.OP and tk.value == "."
        if is_dot:
            # Glue the dot onto the previous token (no leading space) so a
            # following IDENT can also glue, reconstructing ``params.FOO``.
            if parts:
                parts[-1] = parts[-1] + "."
            else:
                parts.append(".")
        elif parts and parts[-1].endswith("."):
            parts[-1] = parts[-1] + tk.value
        else:
            parts.append(tk.value)
    return " ".join(parts)


def _rhs_is_direct_source(rhs: tuple[Token, ...], source_re: re.Pattern[str]) -> bool:
    """RHS is a direct attacker-controlled source (the seed of a chain).

    Two value-preserving shapes:
      * a bare tainted reference at paren-depth 0
        (``def t = params.FOO``, ``def b = env.CHANGE_BRANCH ?: 'main'``);
      * a GString that interpolates a tainted source
        (``def url = "${env.CHANGE_BRANCH}/x"``).
    A tainted name appearing only as a *call argument* is NOT a source.
    """
    if source_re.search(_rhs_depth0_text(rhs)):
        return True
    for tk in rhs:
        if tk.kind == TokKind.STRING and tk.interpolations:
            for span in tk.interpolations:
                if source_re.search(span.expr):
                    return True
    return False


def _rhs_propagates_from(rhs: tuple[Token, ...], tainted: dict[str, list[str]]) -> str | None:
    """Return the tainted var this RHS value-preservingly derives from, or None.

    Value-preserving shapes that carry an existing tainted local forward:
      * bare reference / transform at depth 0 (``def y = x`` / ``y = x.trim()``
        / ``y = x + suffix``);
      * GString interpolation of the tainted var (``def y = "p/${x}"``).
    """
    # Bare reference / transform at depth 0.
    depth = 0
    for tk in rhs:
        if tk.kind == TokKind.LPAREN:
            depth += 1
        elif tk.kind == TokKind.RPAREN:
            depth -= 1
            continue
        if depth == 0 and tk.kind == TokKind.IDENT and tk.value in tainted:
            return tk.value
    # GString interpolation of a tainted var.
    for tk in rhs:
        if tk.kind == TokKind.STRING and tk.interpolations:
            for span in tk.interpolations:
                li = _lead_ident(span.expr)
                if li and li in tainted:
                    return li
    return None


def resolve_multihop_flows(content: str, source_re: re.Pattern[str]) -> list[MultiHopFlow]:
    """Resolve within-file multi-hop taint flows to shell sinks.

    Args:
        content: Jenkinsfile / Groovy pipeline source.
        source_re: compiled regex matching an attacker-controlled source
            reference (``env.CHANGE_*`` / ``params.X`` / GWT names / …).
            The rule layer owns this vocabulary (``_TAINTED_NAMES``) so the
            resolver stays source-set-agnostic.

    Returns:
        A list of :class:`MultiHopFlow`, one per (tainted local → shell
        sink) flow reaching the sink through **N≥1** local hops.  Direct
        source-in-sink flows (TAINT-JK-001's job) are excluded so the two
        rules do not co-fire on one line.  Only interpolating (GString)
        sink bodies qualify — a single-quoted body leaves ``${x}`` literal
        (Groovy does not substitute), the same quote-awareness TAINT-JK-001
        applies.
    """
    assigns, sinks = _collect(content)
    if not assigns or not sinks:
        return []

    # ---- fixed point over value-preserving assignments -------------------
    # tainted[var] = ordered hop chain (source name, then each intermediate
    # local) ending at this var.
    tainted: dict[str, list[str]] = {}

    for a in assigns:
        if _rhs_is_direct_source(a.rhs, source_re):
            # Seed: the source token text (first depth-0 match or first span).
            src = _first_source_label(a.rhs, source_re)
            tainted.setdefault(a.var, [src, a.var])

    changed = True
    # Bound the iteration by the assignment count (a chain can be at most
    # len(assigns) hops long); the `changed` flag terminates earlier in
    # practice, the bound is a hard stop against any pathological input.
    for _ in range(len(assigns) + 1):
        if not changed:
            break
        changed = False
        for a in assigns:
            if a.var in tainted:
                continue
            src_var = _rhs_propagates_from(a.rhs, tainted)
            if src_var is not None:
                tainted[a.var] = tainted[src_var] + [a.var]
                changed = True

    if not tainted:
        return []

    # ---- match tainted locals into sinks --------------------------------
    flows: list[MultiHopFlow] = []
    seen: set[tuple[int, str]] = set()
    for sink in sinks:
        if not sink.interpolated:
            continue
        # Skip the direct case: a source interpolated straight into the body
        # is TAINT-JK-001's finding, not a multi-hop one.
        if source_re.search(sink.body):
            continue
        for ref in sink.refs:
            if ref in tainted:
                key = (sink.line, sink.body)
                if key in seen:
                    break
                seen.add(key)
                hops = tuple(tainted[ref] + [sink.call])
                flows.append(
                    MultiHopFlow(
                        var=ref,
                        sink_call=sink.call,
                        sink_line=sink.line,
                        sink_body=sink.body,
                        hops=hops,
                    )
                )
                break
    return flows


def _first_source_label(rhs: tuple[Token, ...], source_re: re.Pattern[str]) -> str:
    """A readable label for the seeding source (for the hop chain).

    Returns the matched source token text (``env.CHANGE_BRANCH``,
    ``params.FOO``) when found at depth 0, else the first GString span that
    matches, else a generic ``"<source>"``.
    """
    d0 = _rhs_depth0_text(rhs)
    m = source_re.search(d0)
    if m:
        return m.group(0)
    for tk in rhs:
        if tk.kind == TokKind.STRING and tk.interpolations:
            for span in tk.interpolations:
                sm = source_re.search(span.expr)
                if sm:
                    return sm.group(0)
    return "<source>"

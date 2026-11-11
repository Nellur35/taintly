"""Recognize an explicit TLS option on a source-owned Jenkins step call."""

from itertools import pairwise

from taintly.models import _MAX_SAFE_TEXT_LEN, IncompletePatternMatches
from taintly.parsers.jenkinsfile.groovy_lex import Token, TokKind, tokenize

_STEP = "httpRequest"
_OPTION = "ignoreSslErrors"
_MAX_CALLS = 256
_MAX_ARGUMENT_TOKENS = 4096
_CLOSE = {
    TokKind.LPAREN: TokKind.RPAREN,
    TokKind.LBRACKET: TokKind.RBRACKET,
    TokKind.LBRACE: TokKind.RBRACE,
}
_ENDS = {TokKind.SEMI, TokKind.RBRACE, TokKind.EOF}
_RECEIVER_HOOKS = {
    "metaClass",
    "getMetaClass",
    "setMetaClass",
    "methodMissing",
    "invokeMethod",
    "getProperty",
    "setProperty",
    "propertyMissing",
    "binding",
    "getBinding",
    "setBinding",
    "delegate",
    "setDelegate",
    "resolveStrategy",
    "setResolveStrategy",
}


def _pairs(tokens: list[Token]) -> dict[int, int] | None:
    stack: list[tuple[TokKind, int]] = []
    pairs: dict[int, int] = {}
    for i, token in enumerate(tokens):
        if token.kind in _CLOSE:
            stack.append((_CLOSE[token.kind], i))
        elif token.kind in _CLOSE.values():
            if not stack or stack[-1][0] != token.kind:
                return None
            pairs[stack.pop()[1]] = i
    return None if stack else pairs


def _command_end(tokens: list[Token], start: int, pairs: dict[int, int]) -> int:
    i = start
    while tokens[i].kind not in _ENDS:
        if i - start >= _MAX_ARGUMENT_TOKENS:
            raise ValueError("Jenkins HTTP Request arguments exceed analysis limit")
        if tokens[i].kind == TokKind.NEWLINE:
            if tokens[i - 1].value != ",":
                return i
            while tokens[i].kind == TokKind.NEWLINE:
                i += 1
            continue
        i = pairs.get(i, i) + 1
    return i


def _option(
    tokens: list[Token], start: int, end: int, pairs: dict[int, int], *, parenthesized: bool
) -> Token | None:
    """Return the option key for literal true. Raise on unsupported argument shapes."""
    if end - start >= _MAX_ARGUMENT_TOKENS:
        raise ValueError("Jenkins HTTP Request arguments exceed analysis limit")
    indexes = [i for i in range(start, end) if tokens[i].kind != TokKind.NEWLINE]
    if not indexes:
        return None
    # The plugin also accepts a positional URL string.
    if len(indexes) == 1 and tokens[indexes[0]].kind == TokKind.STRING:
        return None
    if tokens[indexes[0]].kind == TokKind.LBRACKET and pairs[indexes[0]] == indexes[-1]:
        start, end = indexes[0] + 1, indexes[-1]
    elif (
        not parenthesized
        and tokens[indexes[-1]].kind == TokKind.OP
        and tokens[indexes[-1]].value == ","
    ):
        raise ValueError("unresolved command-style argument boundary")
    seen: set[str] = set()
    setting = None
    fields = [i for i in range(start, end) if tokens[i].kind != TokKind.NEWLINE]
    cursor = 0
    while cursor < len(fields):
        part: list[Token] = []
        while cursor < len(fields):
            i = fields[cursor]
            token = tokens[i]
            cursor += 1
            if token.kind == TokKind.OP and token.value == ",":
                break
            part.append(token)
            if i in pairs:
                while cursor < len(fields) and fields[cursor] <= pairs[i]:
                    cursor += 1
        if (
            len(part) < 3
            or part[0].kind not in {TokKind.IDENT, TokKind.STRING}
            or part[0].interpolations
            or "\\" in part[0].value
            or part[0].value in seen
            or part[1].kind != TokKind.OP
            or part[1].value != ":"
            or any(t.kind == TokKind.OP and t.value == ":" for t in part[2:])
        ):
            raise ValueError("unsupported named arguments")
        key, value = part[0], part[2]
        seen.add(key.value)
        if key.value == _OPTION:
            if (
                len(part) != 3
                or value.kind != TokKind.IDENT
                or value.value not in {"true", "false"}
            ):
                raise ValueError("unresolved ignoreSslErrors value")
            if value.value == "true":
                setting = key
    return setting


def _in_interpolation(token: Token) -> bool:
    return any(
        _STEP in span.expr
        and any(t.kind == TokKind.IDENT and t.value == _STEP for t in tokenize(span.expr))
        for span in token.interpolations or ()
    )


def _statement_head(previous: Token | None) -> bool:
    return (
        previous is None
        or previous.kind in {TokKind.NEWLINE, TokKind.LBRACE, TokKind.RBRACE, TokKind.SEMI}
        or (previous.kind == TokKind.OP and previous.value == "=")
        or (previous.kind == TokKind.IDENT and previous.value == "return")
    )


class HttpRequestTLSOptionPattern:
    """A literal named option on a direct call in bounded Groovy source."""

    @staticmethod
    def self_test_mutation_applicable(source: str, mutant: str, operator: str) -> bool:
        """Reject only proved Groovy syntax or value changes in generic probes."""
        if operator == "case_change":
            original = list(tokenize(source))
            changed = list(tokenize(mutant))
            if len(original) == len(changed):
                differences = [(a, b) for a, b in zip(original, changed, strict=True) if a != b]
                if differences and all(
                    a.kind == b.kind == TokKind.IDENT
                    and a.value in {"true", "false"}
                    and b.value == a.value.capitalize()
                    for a, b in differences
                ):
                    return False  # Uppercase spelling is an identifier, not a Boolean.
        if operator == "comment_inject":
            rows, mutated_rows = source.splitlines(), mutant.splitlines()
            for token in tokenize(mutant):
                if token.kind == TokKind.OP and token.value == "#" and token.line <= len(rows):
                    i = token.line - 1
                    if token.col == len(rows[i]) + 3 and mutated_rows == [
                        *rows[:i],
                        rows[i] + "  # comment",
                        *rows[i + 1 :],
                    ]:
                        return False  # The injected hash is code outside a string.
        return True

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if _STEP not in content and _OPTION not in content:
            return []
        if len(content) >= _MAX_SAFE_TEXT_LEN:
            return IncompletePatternMatches(
                [], reason="Jenkins HTTP Request source exceeds analysis limit"
            )
        tokens = [t for t in tokenize(content) if t.kind != TokKind.COMMENT]
        next_code = [len(tokens) - 1] * len(tokens)
        for i in range(len(tokens) - 2, -1, -1):
            next_code[i] = next_code[i + 1] if tokens[i + 1].kind == TokKind.NEWLINE else i + 1
        named = [
            i
            for i, t in enumerate(tokens)
            if (t.kind == TokKind.IDENT and t.value == _STEP)
            or (
                t.kind == TokKind.STRING
                and t.value == _STEP
                and tokens[next_code[i]].kind == TokKind.LPAREN
            )
        ]
        gaps = {t.line: "call inside Groovy interpolation" for t in tokens if _in_interpolation(t)}
        computed = [
            i
            for i, t in enumerate(tokens)
            if t.kind == TokKind.STRING
            and t.interpolations
            and (not i or _statement_head(tokens[i - 1]) or tokens[i - 1].value == ".")
            and tokens[next_code[i]].kind == TokKind.LPAREN
        ]
        if not named and not gaps and not computed:
            return []
        pairs = _pairs(tokens)
        if pairs is None or any(t.unterminated for t in tokens):
            return IncompletePatternMatches(
                [], reason="Jenkins HTTP Request source has unbalanced Groovy"
            )

        # Source-visible rebinding contradicts the native step premise. The
        # public parser does not resolve lexical binding lifetimes, so use
        # file-wide uncertainty for those bindings and for dispatch hooks.
        uncertain_receiver = any(
            (t.kind == TokKind.IDENT and t.value in _RECEIVER_HOOKS)
            or (t.kind == TokKind.OP and t.value in {"/", "\\"})
            or any(
                s.brace_form and t.value[s.end - 1 : s.end] != "}" for s in t.interpolations or ()
            )
            for t in tokens
        )
        uncertain_source = any(
            a.kind == b.kind == TokKind.OP and a.value == ":" and b.value in {"|", ">"}
            for a, b in pairwise(tokens)
        )
        calls: list[tuple[int, bool]] = []
        preceding: Token | None = None
        before_newline: dict[int, Token] = {}
        for i, token in enumerate(tokens):
            if token.kind == TokKind.NEWLINE:
                if preceding is not None:
                    before_newline[i + 1] = preceding
            else:
                preceding = token
        for i in named:
            token, following = tokens[i], tokens[next_code[i]]
            previous = tokens[i - 1] if i else None
            if following.kind == TokKind.OP and following.value == ":":
                continue  # A map key or label is not a call.
            if previous is not None and previous.kind == TokKind.IDENT and previous.value == "new":
                continue  # Constructor, not a Pipeline step.
            prior = before_newline.get(i, previous)
            qualified = prior is not None and prior.kind == TokKind.OP and prior.value in {".", "&"}
            if following.kind == TokKind.LPAREN:
                tail = tokens[next_code[pairs[next_code[i]]]]
                if (
                    prior is not None
                    and prior.kind == TokKind.IDENT
                    and prior.value not in {"return", "else"}
                    and (
                        prior.value == "def"
                        or tail.kind == TokKind.LBRACE
                        or tail.value == "throws"
                    )
                ):
                    uncertain_receiver = True
                    continue  # A method declaration cannot supply a call.
            elif tokens[i + 1].kind == TokKind.NEWLINE:
                if not qualified:
                    uncertain_receiver = True
                continue
            elif following.kind != TokKind.STRING and (
                following.kind != TokKind.IDENT and following.kind != TokKind.LBRACKET
            ):
                if not qualified or following.value == "=":
                    uncertain_receiver = True
                continue
            direct = _statement_head(previous) and next_code[i] == i + 1
            calls.append((i, direct and not qualified and token.kind == TokKind.IDENT))

        # Static imports may supply the same name without a local declaration.
        for i, token in enumerate(tokens):
            if token.kind != TokKind.IDENT or token.value != "import":
                continue
            try:
                end = _command_end(tokens, i + 1, pairs)
            except ValueError:
                uncertain_receiver = True
                continue
            parts = [t.value for t in tokens[i + 1 : end]]
            if parts and (parts[-1] == _STEP or (parts[0] == "static" and parts[-1] == "*")):
                uncertain_receiver = True

        matches = []
        candidates = sorted(calls + [(i, False) for i in computed])
        if len(candidates) > _MAX_CALLS:
            gaps[tokens[candidates[_MAX_CALLS][0]].line] = "HTTP Request call budget exceeded"
        for i, direct in candidates[:_MAX_CALLS]:
            token, following = tokens[i], tokens[next_code[i]]
            try:
                if following.kind == TokKind.LPAREN:
                    start, end = next_code[i] + 1, pairs[next_code[i]]
                    direct = direct and tokens[next_code[end]].kind != TokKind.LBRACE
                else:
                    start, end = i + 1, _command_end(tokens, i + 1, pairs)
                key = _option(
                    tokens, start, end, pairs, parenthesized=following.kind == TokKind.LPAREN
                )
            except ValueError as error:
                gaps[token.line] = str(error)
                continue
            if key is None:
                continue
            if uncertain_source or uncertain_receiver or not direct:
                gaps[token.line] = "source ownership or Pipeline step binding is unresolved"
            else:
                matches.append((key.line, lines[key.line - 1].strip()))
        if gaps:
            reason = "; ".join(f"line {line}: {gaps[line]}" for line in sorted(gaps))
            return IncompletePatternMatches(matches, reason=reason[:2048])
        return matches

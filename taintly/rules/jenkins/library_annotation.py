"""Source-level revision requests in Jenkins @Library annotations."""

from __future__ import annotations

import re

from taintly.models import IncompletePatternMatches
from taintly.parsers.jenkinsfile.groovy_lex import Token, TokKind, tokenize

# The automatic GitHub retriever accepts github.com/owner/repository names.
# This classifies the declared request without asserting a retriever is installed.
_NAME = re.compile(r"(?:github[.]com/[a-zA-Z0-9-]+/)?[a-zA-Z0-9_.-]+")
_COMMIT = re.compile(r"[0-9a-fA-F]{40}")


def _literal_arguments(tokens: list[Token], start: int) -> list[Token] | None:
    first = tokens[start]
    if first.kind == TokKind.STRING:
        return [first] if tokens[start + 1].kind == TokKind.RPAREN else None
    if first.kind != TokKind.LBRACKET:
        return None

    arguments = []
    cursor = start + 1
    while tokens[cursor].kind == TokKind.STRING:
        arguments.append(tokens[cursor])
        cursor += 1
        separator = tokens[cursor]
        comma = separator.kind == TokKind.OP and separator.value == ","
        if comma:
            cursor += 1
        if tokens[cursor].kind == TokKind.RBRACKET:
            return arguments if tokens[cursor + 1].kind == TokKind.RPAREN else None
        if not comma:
            break
    return None


class LibraryAnnotationPinPattern:
    """Inspect literal single or list arguments without borrowing nearby refs."""

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if "Library" not in content:
            return []
        tokens = [
            token
            for token in tokenize(content)
            if token.kind not in (TokKind.COMMENT, TokKind.NEWLINE)
        ]
        matches = []
        reasons = []
        for index, token in enumerate(tokens):
            if token.kind != TokKind.OP or token.value != "@":
                continue
            identifier = tokens[index + 1]
            if identifier.kind != TokKind.IDENT or identifier.value != "Library":
                continue
            opening = tokens[index + 2]
            arguments = (
                _literal_arguments(tokens, index + 3) if opening.kind == TokKind.LPAREN else None
            )
            if arguments is None:
                reasons.append(f"line {token.line}: unsupported @Library argument syntax")
                continue
            for argument in arguments:
                name, at, ref = argument.value.partition("@")
                if (
                    argument.unterminated
                    or argument.interpolations
                    or not _NAME.fullmatch(name)
                    or (at and (not ref or any(c.isspace() or c in "@\\" for c in ref)))
                ):
                    reasons.append(f"line {argument.line}: unresolved @Library revision argument")
                elif not at:
                    reasons.append(
                        f"line {argument.line}: @Library revision depends on Jenkins configured default version"
                    )
                elif not _COMMIT.fullmatch(ref):
                    snippet = (
                        lines[argument.line - 1].strip()
                        if len(arguments) == 1 and argument.line == token.line
                        else argument.raw or argument.value
                    )
                    matches.append((argument.line, snippet))

        if reasons:
            reason = "; ".join(reasons[:5])
            if len(reasons) > 5:
                reason += f"; {len(reasons) - 5} more unresolved arguments"
            return IncompletePatternMatches(matches, reason=reason)
        return matches

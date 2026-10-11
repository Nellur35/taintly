"""Bounded shell word lexer shared by CI source-to-command profiles.

This recognizes words, expansion and separators; it is not a shell interpreter.
"""

import re


def shell_words_with_expansion(
    line: str, variable_pattern: re.Pattern[str]
) -> list[tuple[str, bool, bool]]:
    """Split shell words, marking expanded variables and real separators."""

    words: list[tuple[str, bool, bool]] = []
    value: list[str] = []
    expanded = False
    started = False
    quote: str | None = None
    index = 0

    def flush() -> None:
        nonlocal value, expanded, started
        if started:
            words.append(("".join(value), expanded, False))
        value = []
        expanded = False
        started = False

    while index < len(line):
        char = line[index]
        if quote == "'":
            if char == "'":
                quote = None
            else:
                value.append(char)
            started = True
            index += 1
            continue
        if char == "\\" and quote != "'":
            if index + 1 < len(line):
                value.append(line[index + 1])
                started = True
                index += 2
            else:
                index += 1
            continue
        if char == "'" and quote is None:
            quote = "'"
            started = True
            index += 1
            continue
        if char == '"':
            quote = None if quote == '"' else '"'
            started = True
            index += 1
            continue
        if quote is None and char == "#" and (not started or line[index - 1].isspace()):
            break
        if quote != "'" and char == "$":
            match = variable_pattern.match(line, index)
            if match:
                expanded = True
                value.append(match.group(0))
                index = match.end()
                started = True
                continue
        if quote is None and char.isspace():
            flush()
            index += 1
            continue
        if quote is None and char in ";|&":
            flush()
            operator = char
            if index + 1 < len(line) and line[index + 1] == char and char in "|&":
                operator += char
                index += 1
            words.append((operator, False, True))
            index += 1
            continue
        value.append(char)
        started = True
        index += 1
    flush()
    return words

"""Bounded YAML command-scalar decoder shared by CI provider analyzers."""

from __future__ import annotations

import unicodedata

_YAML_DOUBLE_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    "N": "\x85",
    "_": "\xa0",
    "L": "\u2028",
    "P": "\u2029",
}


def decode_single_line_command_scalar(line: str, event: object) -> str | None:
    """Decode a complete, one-physical-line YAML command scalar.

    Structural events establish scalar ownership and kind, but the YAML
    tokenizer deliberately leaves double-quoted escapes raw. Decode only the
    bounded one-line subset here; unsupported escapes and multiline scalars
    remain on the legacy source-text path rather than being treated as known.
    """
    kind = getattr(event, "value_kind", None)
    value = getattr(event, "value", None)
    column = getattr(event, "column", 0)
    if kind != "quoted" or not isinstance(value, str) or column < 1:
        return None
    start = column - 1
    if start >= len(line) or line[start] not in "'\"":
        return None
    quote = line[start]
    index = start + 1
    decoded: list[str] = []
    while index < len(line):
        char = line[index]
        if quote == "'":
            if char == "'":
                if index + 1 < len(line) and line[index + 1] == "'":
                    decoded.append("'")
                    index += 2
                    continue
                index += 1
                break
            decoded.append(char)
            index += 1
            continue
        if char == '"':
            index += 1
            break
        if char != "\\":
            decoded.append(char)
            index += 1
            continue
        index += 1
        if index >= len(line):
            return None
        escape = line[index]
        index += 1
        if escape in _YAML_DOUBLE_ESCAPES:
            decoded.append(_YAML_DOUBLE_ESCAPES[escape])
            continue
        widths = {"x": 2, "u": 4, "U": 8}
        width = widths.get(escape)
        if width is None:
            return None
        digits = line[index : index + width]
        if len(digits) != width or any(ch not in "0123456789abcdefABCDEF" for ch in digits):
            return None
        codepoint = int(digits, 16)
        if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
            return None
        decoded.append(chr(codepoint))
        index += width
    else:
        return None
    # The scalar must end here, apart from YAML whitespace or a comment. A
    # single sequence item may also be followed by its flow-sequence closer.
    suffix = line[index:].lstrip()
    if suffix and not suffix.startswith("#"):
        path = getattr(event, "path", ())
        sequence_indexes = sum(isinstance(part, int) for part in path)
        if sequence_indexes != 1 or not suffix.startswith("]"):
            return None
        suffix = suffix[1:].lstrip()
        if suffix and not suffix.startswith("#"):
            return None
    result = "".join(decoded)
    if "\n" in result or "\r" in result or "\0" in result:
        return None
    if any(
        (char.isspace() and char not in " \t")
        or (unicodedata.category(char).startswith("C") and char != "\t")
        or (unicodedata.category(char) == "Zs" and char != " ")
        for char in result
    ):
        return None
    # For single quotes, the tokenizer already performs the YAML doubled-quote
    # rule. For double quotes it intentionally preserves escape pairs verbatim.
    raw_inner = line[start + 1 : index - 1]
    if quote == "'":
        return result if result == value else None
    if raw_inner != value:
        return None
    return result

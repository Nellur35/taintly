"""Redact credential-shaped values in user-visible source evidence."""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

# These detectors can return a value-oriented snippet with no assignment.
_LITERAL_CREDENTIAL_RULES = frozenset(
    {
        "SEC2-GH-003",
        "SEC2-GH-004",
        "SEC2-GL-003",
        "SEC2-JK-003",
        "SEC6-CB-001",
        "SEC6-GH-001",
        "SEC6-GL-001",
        "SEC6-JK-001",
        "SEC8-GH-009",
    }
)
_FIELD = re.compile(
    r"(?i)(?<![\w.-])(?P<key>(?:[a-z0-9_-]+[_-])?"
    r"(?:passwd|password|pass|secret(?:_access_key)?|token|api[_-]?key|"
    r"access[_-]key|private[_-]key|credentials?|authorization))"
    r"""['"]?[ \t]*[:=][ \t]*"""
)
_OPTION = re.compile(r"(?i)(?<!\S)--(?:password|token|api-key)(?:[ \t]+|=)")
_DOCKER_LOGIN = re.compile(r"\bdocker[ \t]+login\b")
_DOCKER_SHORT_PASSWORD = re.compile(r"(?<!\S)-p[ \t]+")
_CURL_COMMAND = re.compile(r"(?<![\w.-])curl[ \t]+")
_CURL_USER = re.compile(r"(?<!\S)(?:-u[ \t]+|--user(?:[ \t]+|=))")
_SLACK_WEBHOOK = re.compile(
    r"(?i)(https://hooks\.slack\.com/services/)[A-Z0-9_-]+/[A-Z0-9_-]+/[A-Z0-9_-]+"
)
_URI_USERINFO = re.compile(r"(https?://[^/\s:@]+:)([^/\s@]+)(@)")
_GITHUB_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")
_QUOTED = re.compile(r""""(?:\\[^\r\n]|[^"\\\r\n])*"|'(?:''|\\[^\r\n]|[^'\\\r\n])*'""")
_REFERENCE = re.compile(
    r"\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*\}|"
    r"\{\{[ \t]*(?:secrets|env|vars|inputs)\.[A-Za-z_][\w.-]*[ \t]*\}\})"
)
_BLOCK = re.compile(r"[|>](?:[1-9][+-]?|[+-][1-9]?)?(?:[ \t]+#.*)?\s*")
_PLACEHOLDERS = frozenset({"", "''", '""', "null", "~", REDACTED})
_VALUE_DELIMITERS = " \t,;|>&)]}"
_FLOW_PERMISSIONS = re.compile(r"""^\s*['"]?permissions['"]?\s*:\s*\{""")
_FLOW_OIDC_GRANT = re.compile(r"(?:write|none)[ \t]*(?=[,}])")


def _redact_line(line: str) -> str:
    matches = list(_FIELD.finditer(line))
    matches.extend(_OPTION.finditer(line))
    if _DOCKER_LOGIN.search(line):
        matches.extend(_DOCKER_SHORT_PASSWORD.finditer(line))
    if curl := _CURL_COMMAND.search(line):
        # Authentication material can be passed as the username, too.
        matches.extend(_CURL_USER.finditer(line, curl.end()))
    for match in sorted(matches, key=lambda item: item.end(), reverse=True):
        start = match.end()
        tail = line[start:]
        # The GitHub OIDC permission value describes a grant, not a token.
        allowed = _PLACEHOLDERS
        if match.re is _FIELD and match["key"].lower() == "id-token":
            allowed |= {"write", "none"}
            if _FLOW_PERMISSIONS.match(line) and _FLOW_OIDC_GRANT.match(tail):
                continue
        if tail.strip() in allowed:
            continue
        quoted = _QUOTED.match(tail)
        if quoted and (quoted.end() == len(tail) or tail[quoted.end()] in _VALUE_DELIMITERS):
            value = quoted[0][1:-1]
            if value in allowed or _REFERENCE.fullmatch(value):
                continue
            line = line[:start] + tail[0] + REDACTED + tail[0] + tail[quoted.end() :]
            continue
        ref = _REFERENCE.match(tail)
        if ref:
            rest = tail[ref.end() :]
            suffix = rest.lstrip()
            if (
                not suffix
                or suffix[0] in ";|>&)"
                or (match.re is not _CURL_USER and suffix[0] in ",]}")
            ):
                continue
            if rest[0] in " \t" and (match.re is _CURL_USER or suffix.startswith("#")):
                continue
        # A plain or ambiguous scalar can contain whitespace and punctuation.
        # Stop the preview here instead of guessing where the value ends.
        line = line[:start] + REDACTED
    return line


def redact_snippet(snippet: str, rule_id: str = "") -> str:
    """Show source labels while withholding recognized literal values."""
    lines = snippet.split("\n")
    for index, line in enumerate(lines):
        match = _FIELD.search(line)
        if match and index + 1 < len(lines):
            tail = line[match.end() :]
            open_quote = tail.startswith(('"', "'")) and not _QUOTED.match(tail)
            if _BLOCK.fullmatch(tail) or open_quote:
                lines[index:] = [line[: match.end()] + REDACTED]
                break
        lines[index] = _redact_line(line)
    result = "\n".join(lines)
    result = _URI_USERINFO.sub(lambda match: match[1] + REDACTED + match[3], result)
    result = _SLACK_WEBHOOK.sub(lambda match: match[1] + REDACTED, result)
    result = _GITHUB_TOKEN.sub(REDACTED, result)
    if result == snippet and snippet and rule_id in _LITERAL_CREDENTIAL_RULES:
        return REDACTED
    return result

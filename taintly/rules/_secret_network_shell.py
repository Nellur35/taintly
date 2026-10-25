"""Bounded POSIX-shell secret-to-HTTP-body transfer primitives."""

from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_FILE = r"(?:/[A-Za-z0-9_.-]+)+|[A-Za-z0-9_.-]+"
_SECRET = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}\Z")
_VARIABLE = re.compile(rf"\$(?:({_NAME})|\{{({_NAME})\}})")
_ECHO = re.compile(rf"echo\s+(\"[^\"`]*\"|'[^']*'|[^;&|<>`]+?)\s*(>>?)\s*({_FILE})\s*\Z")
_BASE64 = re.compile(rf"base64\s+(?:-w0\s+)?({_FILE})\s*>\s*({_FILE})\s*\Z")
_ASSIGN = re.compile(rf"({_NAME})=(\"[^\"`]*\"|'[^']*'|[^\s;&|<>`]+)\s*\Z")
_SIMPLE_FILE = re.compile(rf"{_FILE}\Z")
_URL = re.compile(r"https?://[^\s]+\Z")
_BODY_FLAGS = frozenset({"--data", "--data-binary", "--data-raw", "-d"})
_VALUE_FLAGS = frozenset(
    {"-X", "--request", "-H", "--header", "-m", "--max-time", "-A", "--user-agent", "-u", "--user"}
)
_NO_VALUE_FLAGS = frozenset(
    {"-s", "--silent", "-S", "--show-error", "-f", "--fail", "-L", "--location"}
)
_BODY_CANDIDATE = re.compile(r"\bcurl\s+[^\n]*(?:--data(?:-binary|-raw)?\b|\s-d\b)")


@dataclass(frozen=True)
class _Flow:
    secrets: frozenset[str]
    hops: tuple[tuple[int, str], ...]


def _joined(flows: list[_Flow], line: int, kind: str) -> _Flow:
    names: set[str] = set()
    hops: list[tuple[int, str]] = []
    for flow in flows:
        names.update(flow.secrets)
        for hop in flow.hops:
            if hop not in hops:
                hops.append(hop)
    if (line, kind) not in hops:
        hops.append((line, kind))
    return _Flow(frozenset(names), tuple(hops))


def _expanded(text: str, values: dict[str, _Flow], line: int, kind: str) -> _Flow | None:
    if text.startswith("'") and text.endswith("'"):
        return _Flow(frozenset(), ((line, kind),))
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    if any(mark in text for mark in ("`", "$(", "${{", "\\")):
        return None
    matches = list(_VARIABLE.finditer(text))
    if "$" in _VARIABLE.sub("", text):
        return None
    flows: list[_Flow] = []
    for match in matches:
        name = match.group(1) or match.group(2)
        if name not in values:
            return None
        flows.append(values[name])
    return _joined(flows, line, kind)


def _curl_body(
    command: str, values: dict[str, _Flow], files: dict[str, _Flow], line: int
) -> _Flow | None:
    command = re.sub(r"\s*\|\|\s*true\s*\Z", "", command)
    if any(mark in command for mark in ("`", "$(", "${{", "\n", ";", "&&", "|", ">", "<")):
        return None
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return None
    if not words or words[0] != "curl" or len(words) > 64:
        return None
    bodies: list[tuple[str, str]] = []
    urls: list[str] = []
    index = 1
    while index < len(words):
        word = words[index]
        if word in _BODY_FLAGS | _VALUE_FLAGS:
            if index + 1 >= len(words):
                return None
            if word in _BODY_FLAGS:
                bodies.append((word, words[index + 1]))
            index += 2
        elif any(word.startswith(flag + "=") for flag in _BODY_FLAGS):
            flag, value = word.split("=", 1)
            bodies.append((flag, value))
            index += 1
        elif word in _NO_VALUE_FLAGS:
            index += 1
        elif _URL.fullmatch(word):
            urls.append(word)
            index += 1
        else:
            return None
    if len(urls) != 1 or len(bodies) != 1:
        return None
    body_flag, body = bodies[0]
    if body_flag != "--data-raw" and body.startswith("@") and _SIMPLE_FILE.fullmatch(body[1:]):
        flow = files.get(body[1:])
        if flow is None:
            return None
    else:
        # shlex discards the quote kind; recover the original body token.
        direct = re.search(
            r"(?:--data|--data-binary|--data-raw|-d)\s+(\"[^\"]*\"|'[^']*'|[^\s'\"]+)", command
        )
        if direct is None or direct.group(1).strip("\"'") != body:
            return None
        if direct.group(1).startswith("'"):
            return _Flow(frozenset(), ())
        flow = _expanded(body, values, line, "request-body")
        if flow is None:
            return None
    return _joined([flow], line, "http-request-body")


def _physical_source(filepath: str, content: str) -> str | None:
    """Bind a scan to the exact on-disk file, including a dirty checkout."""
    if len(content.encode("utf8")) > 65_536:
        return None
    try:
        raw = Path(filepath).read_bytes()
    except (OSError, ValueError):
        return None
    if len(raw) > 65_536:
        return None
    try:
        decoded = raw.decode("utf8")
    except UnicodeError:
        return None
    if decoded not in {content, content.replace("\n", "\r\n")}:
        return None
    return hashlib.sha256(raw).hexdigest()


def analyze_shell_rows(
    rows: tuple[tuple[int, str], ...], initial: dict[str, _Flow]
) -> tuple[list[tuple[int, str, _Flow]], bool]:
    """Trace a small straight-line shell program; unknown effects stop the path."""
    values = dict(initial)
    files: dict[str, _Flow] = {}
    findings: list[tuple[int, str, _Flow]] = []
    for index, (line, raw) in enumerate(rows):
        command = raw.strip()
        if not command or command.startswith("#") or command in {"set +x", "set -e", "set -eu"}:
            continue
        remaining_body = any(_BODY_CANDIDATE.search(item) for _, item in rows[index:])
        if match := _ASSIGN.fullmatch(command):
            flow = _expanded(match.group(2), values, line, "shell-assignment")
            if flow is None:
                return findings, remaining_body
            values[match.group(1)] = flow
            continue
        if match := _ECHO.fullmatch(command):
            flow = _expanded(match.group(1), values, line, "file-write")
            if flow is None:
                return findings, remaining_body
            name = match.group(3)
            files[name] = (
                flow
                if match.group(2) == ">" or name not in files
                else _joined([files[name], flow], line, "file-append")
            )
            continue
        if match := _BASE64.fullmatch(command):
            prior = files.get(match.group(1))
            if prior is None:
                return findings, remaining_body
            files[match.group(2)] = _joined([prior], line, "base64-file-transform")
            continue
        if command.startswith("curl "):
            flow = _curl_body(command, values, files, line)
            if flow is None:
                return findings, remaining_body
            if flow.secrets:
                findings.append((line, command, flow))
            continue
        return findings, remaining_body
    return findings, False

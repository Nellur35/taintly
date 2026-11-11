"""Review a short curl TLS option in a source-owned GitLab command."""

from __future__ import annotations

import re
import shlex
from collections import Counter
from dataclasses import dataclass

from taintly.models import _MAX_SAFE_TEXT_LEN, IncompletePatternMatches, Platform, Rule, Severity
from taintly.parsers.shell_words import shell_words_with_expansion
from taintly.parsers.structural import Event, EventKind, walk_workflow

_SHORT = re.compile(r"-[fsSLIk]+\Z")
_HINT = re.compile(r"""(?<![\w./-])-[fsSLIk]+(?=$|[\s'";&|])""")
_EXPANSION = re.compile(r"\$(?:\{[^{}]*\}|[A-Za-z_][A-Za-z_0-9]*|.)")
_PHASES = {"before_script", "script", "after_script"}
_RESERVED = _PHASES | {
    "default",
    "include",
    "variables",
    "workflow",
    "stages",
    "image",
    "services",
    "cache",
}
_ENV = {"PATH", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "IFS", "CURL_HOME", "HOME"}
_FLAGS = {"--silent", "--show-error", "--fail", "--fail-with-body", "--location", "--head"}
_VALUES = {
    "-X",
    "--request",
    "-H",
    "--header",
    "-u",
    "--user",
    "-d",
    "--data",
    "--data-binary",
    "--data-raw",
    "-o",
    "--output",
    "--cacert",
    "--capath",
    "--connect-timeout",
    "--max-time",
}
_LAUNCHERS = {"env", "command", "builtin", "time", "if", "then", "else", "do", "!"}


@dataclass(frozen=True)
class _Notes:
    notes: tuple[str, ...]


def _short_bypass(word: str) -> bool:
    return "k" in word and _SHORT.fullmatch(word) is not None


def _candidate(text: str) -> bool:
    return "curl" in text and any("k" in hit[0] for hit in _HINT.finditer(text))


def _nested_curl(words: list[tuple[str, bool, bool]]) -> bool:
    """Identify a possible curl behind an unsupported execution boundary."""
    head = True
    for word, expanded, separator in words:
        if separator:
            head = True
        elif head:
            if word == "curl" and not expanded:
                return True
            if word not in _LAUNCHERS and not re.match(r"[A-Za-z_]\w*=", word):
                head = False
    return any(expanded and re.search(r"\$\(\s*curl\b", word) for word, expanded, _ in words)


def _curl_short_prefix(text: str) -> tuple[bool, bool]:
    """Return (owned short bypass, incomplete arguments) under native curl semantics."""
    words = shell_words_with_expansion(text, _EXPANSION)
    if not words or words[0] != ("curl", False, False):
        return False, _nested_curl(words)
    if not any(_short_bypass(word) and not expanded for word, expanded, _ in words):
        return False, False
    if (
        len(text) > 4096
        or len(words) > 128
        or any(mark in text for mark in ("\\", "`", "$(", "${{"))
    ):
        return False, True
    # Corroborate quoting and reject shell operators and redirections before
    # interpreting the argument roles.
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        if list(lexer) != [word for word, _, _ in words]:
            return False, True
    except ValueError:
        return False, True
    if any(separator or word in {"<", ">", "(", ")"} for word, _, separator in words):
        return False, True
    dynamic = False
    enabled = False
    possible = False
    positional = False
    urls: list[str] = []
    index = 1
    while index < len(words):
        word, expanded, _ = words[index]
        unknown = expanded or any(char in word for char in "*?[")
        if not positional and not expanded and word in {"--help", "-h", "--version", "-V"}:
            return False, dynamic and (possible or enabled)
        if not positional and not expanded and word == "--no-insecure":
            enabled = False
            possible |= dynamic
        elif not positional and not expanded and word == "--insecure":
            # The existing long-option rule covers this explicit setting.
            return False, dynamic
        elif not positional and not expanded and word == "--":
            positional = True
        elif not positional and not expanded and _SHORT.fullmatch(word):
            if _short_bypass(word):
                enabled |= not dynamic
                possible = True
        elif not positional and not expanded and word in _FLAGS:
            pass
        elif not positional and not expanded and word.partition("=")[0] in _VALUES:
            if "=" in word:
                if not word.startswith("--"):
                    return False, True
                dynamic |= unknown
            else:
                index += 1
                if index == len(words):
                    return False, True
                value, expanded_value, _ = words[index]
                possible |= dynamic and _short_bypass(value) and not expanded_value
                dynamic |= expanded_value or any(char in value for char in "*?[")
        elif unknown and not positional and not word.startswith("https://"):
            dynamic = True
        elif not word.startswith(("http://", "https://")):
            return False, True
        else:
            urls.append(word)
            dynamic |= unknown
        index += 1
    if not enabled:
        return False, dynamic and possible
    if len(urls) != 1:
        return False, True
    return urls[0].startswith("https://"), dynamic


def _command(event: Event, lines: list[str]) -> tuple[str, int] | None:
    """Decode only physically corroborated one-command scalars."""
    value = (event.value or "").rstrip("\n")
    if not value or "\n" in value or not 0 < event.line <= len(lines):
        return None
    raw = lines[event.line - 1]
    if event.block_lines is not None:
        if not re.fullmatch(
            r" *(?:- +|(?:before_script|script|after_script): +)[|>][-+]? *(?:#.*)?", raw
        ):
            return None
        rows = event.block_lines
        if not rows or len(rows) > 40 or " ".join(text for _, text in rows) != value:
            return None
        if not all(
            0 < line <= len(lines)
            and text
            and lines[line - 1].endswith(text)
            and not lines[line - 1][: -len(text)].strip()
            for line, text in rows
        ):
            return None
        return value, rows[0][0]
    if not 0 < event.column <= len(raw):
        return None
    prefix = raw[: event.column - 1]
    if not re.fullmatch(r" *(?:- +|(?:before_script|script|after_script): +)", prefix):
        return None
    if event.value_kind == "plain":
        indent = len(raw) - len(raw.lstrip(" "))
        following = next(
            (
                row
                for row in lines[event.line :]
                if row.strip() and not row.lstrip().startswith("#")
            ),
            "",
        )
        if following and len(following) - len(following.lstrip(" ")) > indent:
            return None
    return value, event.line


def _review(
    content: str, lines: list[str]
) -> tuple[list[tuple[int, str]], dict[tuple[int, str], _Notes], list[str]]:
    if not _candidate(content):
        return [], {}, []
    if len(content) >= _MAX_SAFE_TEXT_LEN:
        return [], {}, ["GitLab curl candidate exceeds analysis limit"]
    events = tuple(
        walk_workflow(".gitlab-ci.yml", content=content, include_keys=True, recover=True)
    )
    keys = Counter(e.path for e in events if e.kind == EventKind.MAP_KEY)
    leaves = Counter(e.path for e in events if e.kind == EventKind.LEAF_SCALAR)
    broken = any(
        e.kind == EventKind.CUTOFF
        or (
            e.kind == EventKind.ERROR
            and not (e.message or "").startswith("bare alias not expanded: ")
        )
        for e in events
    )
    rebound = {
        e.path[:-2]
        for e in events
        if e.kind == EventKind.MAP_KEY
        and len(e.path) in {2, 3}
        and e.path[-2] == "variables"
        and (e.path[-1] in _ENV or str(e.path[-1]).startswith(("BASH_FUNC_", "LD_", "DYLD_")))
    }
    opaque = {
        e.path[:1]
        for e in events
        if e.value_kind == "merge_key"
        or (e.kind == EventKind.ERROR and (e.message or "").startswith("bare alias not expanded: "))
    }
    matches = []
    notes = {}
    gaps = []
    for event in events:
        path, value = event.path, event.value or ""
        if (
            event.kind != EventKind.LEAF_SCALAR
            or len(path) < 2
            or path[1] not in _PHASES
            or not isinstance(path[0], str)
            or path[0] in _RESERVED
            or path[0].startswith(".")
            or not _candidate(value)
        ):
            continue
        job, phase = path[:2]
        gap = f"job {job!r}, {phase}, line {event.line}"
        command = _command(event, lines)
        if command is None:
            gaps.append(f"{gap}: physical command scalar is unresolved")
            continue
        text, line = command
        active, dynamic = _curl_short_prefix(text)
        if not active and not dynamic:
            continue
        if (
            broken
            or keys[("include",)]
            or keys[(job,)] != 1
            or keys[(job, phase)] != 1
            or leaves[path] != 1
            or event.merge_origins
            or bool(opaque & {(job,), (), ("default",), ("variables",)})
            or keys[(job, "extends")]
            or keys[(job, "inherit")]
            or () in rebound
            or (job,) in rebound
            or path[2:] not in {(), (0,)}
            or (
                phase == "script"
                and (
                    keys[(job, "before_script")]
                    or keys[("default", "before_script")]
                    or keys[("before_script",)]
                )
            )
        ):
            gaps.append(f"{gap}: effective owner or preceding shell context is unresolved")
            continue
        if dynamic:
            gaps.append(f"job {job!r}, {phase}, line {line}: final curl arguments are unresolved")
        if active:
            match = (line, lines[line - 1].strip())
            matches.append(match)
            notes[match] = _Notes(
                (
                    f"GitLab job {job!r}, {phase}, command at line {line} supplies a short curl TLS-bypass option.",
                    "Dynamic shell arguments can alter the final option state."
                    if dynamic
                    else "The bypass remains in the modeled literal source arguments.",
                    "Effective runner, tool configuration, execution, connection and endpoint trust are unverified.",
                )
            )
    if broken and not gaps:
        gaps.append("GitLab curl command ownership could not be resolved from the YAML")
    return matches, notes, gaps


class GitLabCurlShortTLSPattern:
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        matches, _, gaps = _review(content, lines)
        if gaps:
            return IncompletePatternMatches(matches, reason="; ".join(gaps)[:2048])
        return matches

    def context_notes_for_matches(
        self, content: str, _filepath: str, matches: list[tuple[int, str]]
    ) -> list[_Notes | None]:
        if not matches:
            return []
        _, notes, _ = _review(content, content.splitlines())
        return [notes.get(match) for match in matches]


RULES = [
    Rule(
        id="SEC6-GL-012",
        title="Review curl short TLS verification bypass in a GitLab command",
        severity=Severity.MEDIUM,
        confidence="medium",
        review_needed=True,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        finding_family="insecure_transport",
        pattern=GitLabCurlShortTLSPattern(),
        description="A source-owned GitLab command supplies curl's short -k option for an HTTPS-shaped request. Dynamic arguments can change its final setting. Review the effective arguments and trust configuration.",
        remediation="Remove -k and configure the approved CA or server certificate. Check the effective runner, curl configuration and actual connection when validating the change.",
        reference="https://curl.se/docs/manpage.html#-k",
        test_positive=[
            "deploy:\n  script:\n    - curl -k https://example.invalid/status",
            "deploy:\n  after_script:\n    - curl -sk https://${HOST}/status",
        ],
        test_negative=[
            "deploy:\n  script:\n    - echo 'curl -k https://example.invalid/status'",
            "deploy:\n  script:\n    - curl -H '-k' https://example.invalid/status",
            "deploy:\n  script:\n    - curl -k --no-insecure https://example.invalid/status",
        ],
    )
]

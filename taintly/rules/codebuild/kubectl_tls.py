"""Review explicit kubectl TLS configuration requests in CodeBuild commands."""

from __future__ import annotations

import re
import shlex
from collections import Counter
from dataclasses import dataclass

from taintly.models import _MAX_SAFE_TEXT_LEN, IncompletePatternMatches, Platform, Rule, Severity
from taintly.parsers.shell_words import shell_words_with_expansion
from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenizerError, TokenKind, tokenize

_FLAG = "--insecure-skip-tls-verify"
_TRUE = {"1", "t", "T", "TRUE", "true", "True"}
_FALSE = {"0", "f", "F", "FALSE", "false", "False"}
_CLUSTER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_VAR = r"\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)"
_EXPANSION = re.compile(_VAR + r"|\$(?:\{[^}]*\}|.)")
_QUOTED_VAR = re.compile(r'"' + _VAR + r'"\Z')
_VALUES = {
    "--server",
    "--tls-server-name",
    "--kubeconfig",
    "--proxy-url",
    "--certificate-authority",
}
_PHASES = {
    phase: index for index, phase in enumerate(("install", "pre_build", "build", "post_build"))
}
_ENV = {"PATH", "ENV", "BASH_ENV", "IFS", "SHELLOPTS", "BASHOPTS", "KUBECONFIG", "HOME"}


@dataclass(frozen=True)
class _Notes:
    notes: tuple[str, ...]


def _candidate(text: str) -> bool:
    return _FLAG in text and "kubectl" in text


def _raw_words(command: str, values: list[str]) -> list[str] | None:
    """Keep original quoting only when the two bounded word readers agree."""
    lexer = shlex.shlex(command, posix=False, punctuation_chars=";&|<>()")
    lexer.whitespace_split = True
    try:
        raw = list(lexer)
        if len(raw) == len(values) and all(
            shlex.split(word, comments=False) == [value]
            for word, value in zip(raw, values, strict=True)
        ):
            return raw
    except ValueError:
        pass
    return None


def _request(command: str) -> tuple[str | None, bool]:
    """Return a named cluster requesting a bypass, with an unresolved flag."""
    words = shell_words_with_expansion(command, _EXPANSION)
    if not words:
        return None, False
    if words[0] != ("kubectl", False, False):
        printed = (
            words[0][0] in {"echo", "printf"}
            and not any(separator for _, _, separator in words)
            and "$(" not in command
            and "`" not in command
        )
        return None, not printed
    if (
        len(command) > 4096
        or len(words) > 64
        or any(mark in command for mark in ("\\", "`", "$(", "\n"))
    ):
        return None, True
    values = [word for word, _, _ in words]
    if values[:3] != ["kubectl", "config", "set-cluster"]:
        return None, True
    if (
        len(words) < 4
        or not _CLUSTER.fullmatch(values[3])
        or any(separator or word in {"<", ">", "(", ")", "{", "}"} for word, _, separator in words)
    ):
        return None, True
    raw = _raw_words(command, values)
    if raw is None:
        return None, True
    requested = None
    ca = False
    index = 4
    while index < len(words):
        word, expanded, _ = words[index]
        option, equals, value = word.partition("=")
        if option == _FLAG:
            if requested is not None or expanded or (equals and value not in _TRUE | _FALSE):
                return None, True
            requested = not equals or value in _TRUE
        elif option in _VALUES:
            raw_value = raw[index].partition("=")[2]
            if not equals:
                index += 1
                if index == len(words):
                    return None, True
                value, expanded, _ = words[index]
                raw_value = raw[index]
            if expanded and not _QUOTED_VAR.fullmatch(raw_value):
                return None, True
            quoted = (
                len(raw_value) >= 2 and raw_value[0] in {"'", '"'} and raw_value[-1] == raw_value[0]
            )
            if not value or (not quoted and any(char in value for char in "*?[]{}~")):
                return None, True
            ca |= option == "--certificate-authority"
        elif word in {"--help", "-h"}:
            return None, False
        else:
            return None, True
        index += 1
    if requested and ca:
        return None, True
    return (values[3] if requested else None), False


def _rebinds_kubectl(command: str) -> bool:
    words = shell_words_with_expansion(command, _EXPANSION)
    # Shell word decoding preserves the function name even when parts of
    # its spelling are quoted or escaped.
    segment: list[str] = []
    for word, _, separator in [*words, ("", False, True)]:
        if not separator:
            segment.append(word)
            continue
        while segment and segment[0] in {"then", "do", "else", "{"}:
            segment.pop(0)
        if (
            segment
            and segment[0] == "alias"
            and any(item.startswith("kubectl=") for item in segment[1:])
        ):
            return True
        if re.match(r"(?:function\s+kubectl(?=\s|\(|$)|kubectl\s*\(\s*\))", " ".join(segment[:4])):
            return True
        segment.clear()
    return False


def _owned_command(event: Event, lines: list[str]) -> str | None:
    """Bind the walker leaf to a single physical sequence item."""
    command = event.value or ""
    if event.block_lines is not None or not 0 < event.line <= len(lines) or "\n" in command:
        return None
    raw = lines[event.line - 1]
    if event.column <= 0 or not re.fullmatch(r"[ \t]*-[ \t]+", raw[: event.column - 1]):
        return None
    if event.value_kind == "plain":
        tail = raw[event.column - 1 :]
        if not tail.startswith(command) or not re.fullmatch(
            r"[ \t]*(?:#.*)?", tail[len(command) :]
        ):
            return None
    return command.strip()


def _review(
    content: str, lines: list[str]
) -> tuple[list[tuple[int, str]], dict[tuple[int, str], _Notes], list[str]]:
    if not _candidate(content):
        return [], {}, []
    if len(content) >= _MAX_SAFE_TEXT_LEN:
        return [], {}, ["CodeBuild configuration candidate exceeds analysis limit"]
    events = tuple(walk_workflow("buildspec.yml", content=content, include_keys=True, recover=True))
    keys = Counter(event.path for event in events if event.kind == EventKind.MAP_KEY)
    leaves = [event for event in events if event.kind == EventKind.LEAF_SCALAR]
    counts = Counter(event.path for event in leaves)
    values = {event.path: event.value for event in leaves}
    try:
        aliases = any(
            token.kind in {TokenKind.ALIAS, TokenKind.MERGE_KEY} for token in tokenize(content)
        )
    except TokenizerError:
        aliases = True
    ambiguous = (
        aliases
        or any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events)
        or any(count > 1 for count in (*keys.values(), *counts.values()))
        or values.get(("version",)) != "0.2"
        or values.get(("env", "shell")) not in {None, "bash", "/bin/sh"}
    )
    scoped = [
        event
        for event in leaves
        if len(event.path) >= 3
        and event.path[0] == "phases"
        and event.path[2] in {"commands", "finally"}
    ]
    commands = [
        event
        for event in scoped
        if len(event.path) == 4 and event.path[1] in _PHASES and type(event.path[3]) is int
    ]
    commands.sort(
        key=lambda event: (
            _PHASES[str(event.path[1])],
            event.path[2] == "finally",
            int(str(event.path[3])),
        )
    )
    command_paths = {event.path for event in commands}
    matches: list[tuple[int, str]] = []
    notes: dict[tuple[int, str], _Notes] = {}
    gaps = [
        f"line {event.line}: command is outside the supported phase sequence"
        for event in scoped
        if event.path not in command_paths and _candidate(event.value or "")
    ]
    if ambiguous and not scoped:
        gaps.append("CodeBuild candidate ownership or shell is unresolved")
    opaque = any(
        len(event.path) == 3
        and event.path[0] == "env"
        and (event.path[2] in _ENV or str(event.path[2]).startswith(("BASH_FUNC_", "LD_", "DYLD_")))
        for event in leaves
    )
    rebound = False
    for event in commands:
        candidate = _candidate(event.value or "")
        command = _owned_command(event, lines)
        if command is None:
            opaque = True
            if candidate:
                gaps.append(f"line {event.line}: command is outside the supported scalar profile")
            continue
        rebind = _rebinds_kubectl(command)
        if candidate:
            cluster, unresolved = _request(command)
            if ambiguous or rebound or rebind:
                unresolved |= cluster is not None
                cluster = None
            if cluster is not None:
                match = (event.line, lines[event.line - 1].strip())
                matches.append(match)
                owner = ".".join(map(str, event.path[:3])) + f"[{event.path[3]}]"
                notes[match] = _Notes(
                    (
                        f"CodeBuild {owner} at line {event.line} requests certificate verification bypass for cluster {cluster}.",
                        "The effective tool, kubeconfig write, selected context and subsequent connection are unverified.",
                    )
                )
            if unresolved:
                gaps.append(
                    f"line {event.line}: kubectl arguments or native command ownership are unresolved"
                )
            elif cluster is not None and opaque:
                gaps.append(
                    f"line {event.line}: prior commands or environment leave the effective tool or kubeconfig unresolved"
                )
        rebound |= rebind
        opaque |= bool(command and not command.startswith("#"))
    return matches, notes, gaps


class KubectlTLSConfigurationPattern:
    def self_test_mutation_applicable(self, source: str, mutant: str, operator: str) -> bool:
        if operator != "whitespace_pad":
            return True
        # Dropping the separating space in a required YAML mapping changes
        # the version key into a plain scalar. It is not a layout mutation.
        return not ("version: 0.2" in source.splitlines() and "version:0.2" in mutant.splitlines())

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        matches, _, gaps = _review(content, lines)
        return IncompletePatternMatches(matches, reason="; ".join(gaps)[:2048]) if gaps else matches

    def context_notes_for_matches(
        self, content: str, _filepath: str, matches: list[tuple[int, str]]
    ) -> list[_Notes | None]:
        if not matches:
            return []
        _, notes, _ = _review(content, content.splitlines())
        return [notes.get(match) for match in matches]


_SAMPLE = (
    "version: 0.2\nphases:\n  post_build:\n    commands:\n"
    "      - kubectl config set-cluster prod --server=https://example.invalid "
    "--insecure-skip-tls-verify=true\n"
)

RULES = [
    Rule(
        id="SEC6-CB-005",
        title="Review kubectl request to skip server certificate verification",
        severity=Severity.MEDIUM,
        confidence="medium",
        review_needed=True,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-6",
        finding_family="insecure_transport",
        pattern=KubectlTLSConfigurationPattern(),
        description=(
            "A source-owned CodeBuild command requests that kubectl skip server certificate "
            "verification in a named cluster configuration. A later TLS connection using "
            "that setting would be unable to rely on certificate verification."
        ),
        remediation=(
            "Explicitly configure verification and the approved CA. Removing the flag can "
            "preserve an existing setting because set-cluster merges fields. Verify the "
            "effective kubeconfig and selected deployment context."
        ),
        reference="https://kubernetes.io/docs/reference/kubectl/generated/kubectl_config/kubectl_config_set-cluster/",
        test_positive=[_SAMPLE],
        test_negative=[
            _SAMPLE.replace("verify=true", "verify=false"),
            _SAMPLE.replace("- kubectl", "- echo kubectl"),
        ],
    )
]

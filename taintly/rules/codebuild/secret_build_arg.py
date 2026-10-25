"""Review a source-bound CodeBuild secret passed to Docker as a build argument."""

from __future__ import annotations

import re
import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path

from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenKind, tokenize
from taintly.rules._secret_network_shell import _physical_source

_ARG = re.compile(r"(?:^|\s)--build-arg\s+(\"[^\"`]*\"|'[^']*'|[^\s'\"`]+)")
_DIRECT = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)=\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})\Z"
)
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_VALUE_FLAGS = frozenset(
    {"-t", "--tag", "-f", "--file", "--cache-from", "--target", "--platform", "--build-arg"}
)
_NO_VALUE_FLAGS = frozenset({"--pull", "--no-cache"})
_PHASE_ORDER = {"install": 0, "pre_build": 1, "build": 2, "post_build": 3}


@dataclass(frozen=True)
class _Notes:
    notes: tuple[str, ...]


def _candidate(content: str) -> bool:
    live = [line for line in content.splitlines() if not line.lstrip().startswith("#")]
    return (
        any("secrets-manager" in line for line in live)
        and any("docker build" in line for line in live)
        and any("--build-arg" in line for line in live)
    )


def _direct_build_args(
    command: str, names: frozenset[str]
) -> tuple[list[tuple[str, str]], bool] | None:
    """Return (source, argument) witnesses and unresolved-form status."""
    if not command.startswith("docker build "):
        return None
    if len(command) > 2048 or any(
        mark in command for mark in ("`", "$(", "\\", "\n", ";", "&&", "|", ">", "<")
    ):
        return None
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return None
    if words[:2] != ["docker", "build"] or len(words) > 96:
        return None
    args: list[str] = []
    contexts: list[str] = []
    index = 2
    while index < len(words):
        word = words[index]
        if word in _VALUE_FLAGS:
            if index + 1 >= len(words):
                return None
            if word == "--build-arg":
                args.append(words[index + 1])
            index += 2
        elif word in _NO_VALUE_FLAGS:
            index += 1
        elif word == ".":
            contexts.append(word)
            index += 1
        else:
            return None
    if contexts != ["."] or not args:
        return None
    raw_args = [match.group(1) for match in _ARG.finditer(command)]
    if len(raw_args) != len(args):
        return None
    result: list[tuple[str, str]] = []
    unresolved = False
    for raw, cooked in zip(raw_args, args, strict=True):
        if raw.startswith("'"):
            continue  # The shell passes a literal dollar sign to Docker.
        if raw.strip('"') != cooked:
            return None
        direct = _DIRECT.fullmatch(cooked)
        if direct:
            arg_name, simple, braced = direct.groups()
            source = simple or braced
            if source in names:
                result.append((source, arg_name))
            continue
        # Docker also inherits the environment value for a bare --build-arg NAME.
        if _IDENT.fullmatch(cooked) and cooked in names:
            result.append((cooked, cooked))
            continue
        if any(re.search(r"\$\{?" + re.escape(name) + r"(?:\b|\})", cooked) for name in names):
            unresolved = True
    return result, unresolved


def _prior_override(commands: list[Event], target: Event, name: str) -> bool:
    target_phase = _PHASE_ORDER[str(target.path[1])]
    for event in commands:
        phase = _PHASE_ORDER.get(str(event.path[1]))
        if phase is None or (phase, event.path[3]) >= (target_phase, target.path[3]):
            continue
        value = event.value or ""
        if re.search(r"(?:^|\s)(?:export\s+)?" + re.escape(name) + r"\s*=", value):
            return True
        if re.search(r"(?:^|\s)unset\s+" + re.escape(name) + r"\b", value):
            return True
    return False


class CodeBuildSecretBuildArgPattern:
    def check(self, content: str, _lines: list[str]):
        if _candidate(content):
            return IncompletePatternMatches(
                [], reason="SEC6-CB-004 physical buildspec source is required"
            )
        return []

    def self_test_check(self, sample: str):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "buildspec.yml"
            path.write_text(sample, encoding="utf8")
            return self.check_with_filepath(sample, sample.splitlines(), str(path))

    def self_test_mutation_applicable(self, source: str, mutant: str, operator: str) -> bool:
        if operator != "whitespace_pad":
            return True

        def owners(text: str) -> set[tuple[object, ...]] | None:
            events = tuple(walk_workflow("buildspec.yml", content=text, include_keys=True))
            if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
                return None
            return {
                event.path
                for event in events
                if event.kind is EventKind.LEAF_SCALAR
                and (
                    event.path == ("version",)
                    or event.path[:2] == ("env", "secrets-manager")
                    or (
                        len(event.path) == 4
                        and event.path[0] == "phases"
                        and event.path[2] == "commands"
                    )
                )
            }

        before, after = owners(source), owners(mutant)
        return not before or (after is not None and before <= after)

    def _analyze(self, content: str, filepath: str):
        if not _candidate(content):
            return [], {}, None
        digest = _physical_source(filepath, content)
        if digest is None:
            return [], {}, "SEC6-CB-004 source identity is unavailable"
        events = tuple(walk_workflow(filepath, content=content, include_keys=True, recover=True))
        try:
            tokens = tuple(tokenize(content))
        except Exception:
            return [], {}, "SEC6-CB-004 YAML tokenization is incomplete"
        if any(
            e.kind in {EventKind.ERROR, EventKind.CUTOFF} or e.merge_origins for e in events
        ) or any(
            t.kind in {TokenKind.ALIAS, TokenKind.ANCHOR, TokenKind.MERGE_KEY} for t in tokens
        ):
            return [], {}, "SEC6-CB-004 candidate structure is ambiguous"
        leaves = [e for e in events if e.kind is EventKind.LEAF_SCALAR]
        if len({e.path for e in leaves}) != len(leaves):
            return [], {}, "SEC6-CB-004 duplicate source paths"
        values = {e.path: e for e in leaves}
        if ("version",) not in values or values[("version",)].value != "0.2":
            return [], {}, "SEC6-CB-004 buildspec version 0.2 is required"
        shell = values.get(("env", "shell"))
        if shell is not None and shell.value not in {"bash", "/bin/sh"}:
            return [], {}, "SEC6-CB-004 POSIX shell profile is required"
        sources = {
            str(e.path[2]): e
            for e in leaves
            if len(e.path) == 3
            and e.path[:2] == ("env", "secrets-manager")
            and isinstance(e.path[2], str)
            and _IDENT.fullmatch(e.path[2])
            and e.value
        }
        if not sources:
            return [], {}, "SEC6-CB-004 Secrets Manager binding is unresolved"
        if any(
            ("env", other, name) in values
            for name in sources
            for other in ("variables", "parameter-store")
        ):
            return [], {}, "SEC6-CB-004 variable source is explicitly ambiguous"
        commands = [
            e
            for e in leaves
            if len(e.path) == 4
            and e.path[0] == "phases"
            and e.path[1] in _PHASE_ORDER
            and e.path[2] == "commands"
            and type(e.path[3]) is int
        ]
        source_lines = content.splitlines()
        matches: list[tuple[int, str]] = []
        notes: dict[tuple[int, str], _Notes] = {}
        incomplete = False
        for event in commands:
            value = (event.value or "").strip()
            if "docker build" not in value or "--build-arg" not in value:
                continue
            if value.startswith(("echo ", "printf ")):
                continue
            if event.line < 1 or event.line > len(source_lines):
                incomplete = True
                continue
            if not all(
                part in source_lines[event.line - 1] for part in ("docker build", "--build-arg")
            ):
                incomplete = True
                continue
            parsed = _direct_build_args(value, frozenset(sources))
            if parsed is None:
                incomplete = True
                continue
            paths, partial = parsed
            incomplete |= partial
            if not paths:
                continue
            supported = [
                (name, arg) for name, arg in paths if not _prior_override(commands, event, name)
            ]
            if len(supported) != len(paths):
                incomplete = True
            if not supported:
                continue
            witnesses = ", ".join(
                f"Secrets Manager {name} (line {sources[name].line}) -> Docker --build-arg {arg}"
                for name, arg in supported
            )
            item = (event.line, value)
            matches.append(item)
            notes[item] = _Notes(
                (
                    f"Source SHA256 {digest}; CodeBuild {event.path[1]} command item {event.path[3]} "
                    f"configures {witnesses} at line {event.line}. "
                    "A POSIX shell is required for $VAR expansion when env.shell is absent. "
                    "Unquoted expansion may split or glob the value; exact Docker argv is unknown. "
                    "Project/start-build overrides, prior unmodeled command effects, secret retrieval, "
                    "Dockerfile use, image metadata, build execution and publication are unknown.",
                )
            )
        return (
            matches,
            notes,
            "SEC6-CB-004 candidate build-argument path is outside the direct profile"
            if incomplete
            else None,
        )

    def check_with_filepath(self, content: str, _lines: list[str], filepath: str):
        matches, _notes, incomplete = self._analyze(content, filepath)
        return IncompletePatternMatches(matches, reason=incomplete) if incomplete else matches

    def context_notes_for_matches(
        self, content: str, filepath: str, matches: list[tuple[int, str]]
    ):
        _matches, notes, _incomplete = self._analyze(content, filepath)
        return [notes.get(item) for item in matches]


_SAMPLE = (
    "version: 0.2\nenv:\n  secrets-manager:\n    TOKEN: prod/token\n"
    "phases:\n  build:\n    commands:\n"
    "      - docker build --build-arg TOKEN=$TOKEN -t app:latest .\n"
)

RULES = [
    Rule(
        id="SEC6-CB-004",
        title="CodeBuild secret passed as a Docker build argument",
        severity=Severity.MEDIUM,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-6",
        description="A source-bound Secrets Manager variable is referenced in a direct Docker build argument. Docker advises against passing secrets this way; runtime delivery and image exposure remain unverified.",
        pattern=CodeBuildSecretBuildArgPattern(),
        remediation="If the build needs this secret, pass it with a Docker secret mount instead of --build-arg. Review the Dockerfile and any existing image history, provenance or logs for exposure; consider credential rotation according to that evidence and your incident policy.",
        reference="https://docs.docker.com/build/building/variables/",
        test_positive=[_SAMPLE],
        test_negative=[_SAMPLE.replace("TOKEN=$TOKEN", "TOKEN=public")],
        finding_family="credential_exposure",
        confidence="medium",
        review_needed=True,
    )
]

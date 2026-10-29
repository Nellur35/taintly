"""Bound Jenkins credentials placed in a direct curl URL query."""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from taintly.models import (
    EvidenceStep,
    EvidenceTrace,
    IncompletePatternMatches,
    Platform,
    Rule,
    Severity,
)
from taintly.parsers.jenkinsfile import EventKind, walk_jenkinsfile
from taintly.rules._secret_network_shell import _physical_source

_CURL_FIRST_URL = re.compile(r"^curl\s+(?P<quote>\\?[\"']?)(?P<url>https?://\S+)")
# A small additional profile: recognized curl options with their own operands
# before the one direct URL operand. Do not search arbitrary later text for a
# URL; an occurrence in --data or -H is not the request destination.
_CURL_OPTION_URL = re.compile(
    r"^curl\s+(?:"
    r"-X(?:POST|GET|PUT|PATCH|DELETE)\s+|"
    r"-X\s+(?:POST|GET|PUT|PATCH|DELETE)\s+|"
    r"--data(?:-raw|-binary)?\s+(?:'[^'\n]*'|\"[^\"\n]*\"|[^\s'\";|&]+)\s+|"
    r"-sS?\s+"
    r")+(?P<quote>\\?[\"']?)(?P<url>https?://\S+)"
)
_QUERY_REFERENCE = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})")
_SIMPLE_PREFIX = frozenset({"set -x", "set +x", "set -e", "set -eu"})


def _query_mentions(line: str, variable: str) -> bool:
    """Lexical fallback for an unresolved URL; never a positive proof."""
    for url in re.finditer(r"https?://\S+", line):
        if "?" not in url.group():
            continue
        query = url.group().split("?", 1)[1]
        if any(
            (match.group(1) or match.group(2)) == variable
            for match in _QUERY_REFERENCE.finditer(query)
        ):
            return True
    return False


@dataclass(frozen=True)
class _Notes:
    notes: tuple[str, ...]
    evidence_trace: EvidenceTrace | None = None


class JenkinsCredentialQueryPattern:
    """Direct binding and directly owned shell curl, with exact source identity.

    A parser path without an invocation index is not enough to join repeated
    credential blocks. A nontrivial shell command before curl may overwrite a
    variable, so that path stays unresolved. This is a possible configured
    credential-to-query path, not proof of request delivery or misuse.
    """

    def check(self, content: str, _lines: list[str]):
        if "withCredentials" in content and "curl" in content and "?" in content:
            return IncompletePatternMatches(
                [], reason="SEC6-JK-013 physical Jenkinsfile source is required"
            )
        return []

    def self_test_check(self, sample: str):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "Jenkinsfile"
            path.write_text(sample, encoding="utf8")
            return self.check_with_filepath(sample, sample.splitlines(), str(path))

    def _analyze(self, content: str, filepath: str):
        if not ("withCredentials" in content and "curl" in content and "?" in content):
            return [], {}, {}, None
        digest = _physical_source(filepath, content)
        if digest is None:
            return [], {}, {}, "SEC6-JK-013 source identity is unavailable"
        events = tuple(walk_jenkinsfile(content, recover=True))
        if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
            return [], {}, {}, "SEC6-JK-013 Jenkinsfile structure is incomplete"
        invocation_count = len(re.findall(r"\bwithCredentials\s*\(", content))
        attested_owners = {
            event.path[: event.path.index("withCredentials") + 1]
            for event in events
            if "withCredentials" in event.path and not event.degraded
        }
        if invocation_count > len(attested_owners):
            # The reader omits an invocation index. Two sibling calls at the
            # same path cannot safely share one binding-to-shell owner.
            return [], {}, {}, "SEC6-JK-013 credential invocation identity is ambiguous"

        # Only direct string, usernamePassword and structurally attested
        # UsernamePasswordMultiBinding map bindings are in the profile.
        # Path alone does not identify two sequential calls at the same owner.
        bindings: dict[tuple[object, ...], list[tuple[str, int]]] = {}
        for event in events:
            if event.kind is not EventKind.LEAF or event.degraded or not event.value:
                continue
            if event.path[-3:] not in {
                ("withCredentials", "string", "variable"),
                ("withCredentials", "usernamePassword", "passwordVariable"),
                ("withCredentials", "UsernamePasswordMultiBinding", "passwordVariable"),
            }:
                continue
            bindings.setdefault(event.path[:-2], []).append((event.value, event.line))

        matches: list[tuple[int, str]] = []
        notes: dict[tuple[int, str], str] = {}
        traces: dict[tuple[int, str], EvidenceTrace] = {}
        incomplete = False
        source_lines = content.splitlines()
        for event in events:
            if (
                event.kind is not EventKind.LEAF
                or event.degraded
                or event.value_kind != "shell"
                or event.path[-2:] != ("withCredentials", "sh")
                or not event.value
            ):
                continue
            owners = bindings.get(event.path[:-1], [])
            if not owners:
                continue
            if len(owners) != 1 or len(event.value.splitlines()) > 128:
                incomplete = True
                continue
            variable, binding_line = owners[0]
            prefix_is_simple = True
            for offset, raw in enumerate(event.value.splitlines()):
                command = raw.strip()
                if not command or command.startswith("#") or command in _SIMPLE_PREFIX:
                    continue
                url_match = _CURL_FIRST_URL.match(command) or _CURL_OPTION_URL.match(command)
                if url_match is None:
                    prefix_is_simple = False
                    continue
                apparent_url = url_match.group("url").rstrip("\\\"'")
                if "?" not in apparent_url:
                    prefix_is_simple = False
                    continue
                query = apparent_url.split("?", 1)[1]
                references = [
                    match
                    for match in _QUERY_REFERENCE.finditer(query)
                    if (match.group(1) or match.group(2)) == variable
                ]
                if not references:
                    prefix_is_simple = False
                    continue
                if (
                    any(character in apparent_url for character in "&;|`")
                    and not url_match.group("quote")
                ) or ("#" in query and query.index("#") < references[0].start()):
                    # Shell operators can split an unquoted URL before the
                    # credential reaches curl; a URL fragment is not sent.
                    incomplete = True
                    continue
                if not prefix_is_simple:
                    incomplete = True
                    continue
                if re.search(rf"(?m)^\s*(?:def\s+)?{re.escape(variable)}\s*=", content):
                    # A Groovy or shell assignment might shadow the binding.
                    incomplete = True
                    continue
                # An escaped dollar changes the evaluation stage. The rule
                # cannot claim either stage expanded it in this profile.
                if any(
                    match.start() > 0 and query[match.start() - 1] == "\\" for match in references
                ):
                    incomplete = True
                    continue
                # A shell single quote stops shell expansion, but Groovy may
                # already have interpolated a GString before shell execution.
                if not event.interpolated and url_match.group("quote") == "'":
                    continue
                if not event.interpolated and url_match.group("quote") == '\\"':
                    # In a literal Groovy string, the backslash reaches the
                    # shell: \" is a literal quote, not a grouping quote.
                    # This is not an attested curl URL argument.
                    incomplete = True
                    continue
                line = event.line + offset
                if not (0 < line <= len(source_lines)):
                    incomplete = True
                    continue
                item = (line, source_lines[line - 1].strip())
                matches.append(item)
                stage = "Groovy GString interpolation" if event.interpolated else "shell expansion"
                notes[item] = (
                    f"Source SHA256 {digest}; Jenkins withCredentials binding {variable} "
                    f"at line {binding_line} reaches a curl URL query at line {line} "
                    f"through {stage}. Credential availability, execution, endpoint trust, "
                    "delivery and disclosure beyond the intended endpoint are unknown."
                )
                traces[item] = EvidenceTrace(
                    basis="static configuration",
                    context="/".join(str(part) for part in event.path[:-1]),
                    steps=(
                        EvidenceStep(
                            f"withCredentials binding {variable}",
                            filepath,
                            binding_line,
                            f"{stage} in sh" if event.interpolated else "bound environment for sh",
                        ),
                        EvidenceStep(
                            "sh command",
                            filepath,
                            event.line,
                            "curl URL query"
                            if event.interpolated
                            else "shell expansion into curl URL query",
                        ),
                        EvidenceStep("curl URL query", filepath, line),
                    ),
                    unknowns=(
                        "credential availability",
                        "execution",
                        "endpoint trust",
                        "delivery",
                        "disclosure beyond intended endpoint",
                    ),
                    runtime_status="not verified",
                )
                prefix_is_simple = False

        # If source text suggests a bound variable in a curl query but the
        # reader did not attest an owned shell operand, retain uncertainty.
        if not matches and any(
            "curl" in line
            and any(
                _query_mentions(line, name) for values in bindings.values() for name, _ in values
            )
            for line in source_lines
        ):
            incomplete = True
        return (
            matches,
            notes,
            traces,
            "SEC6-JK-013 candidate query is outside the supported owned curl profile"
            if incomplete
            else None,
        )

    def check_with_filepath(self, content: str, _lines: list[str], filepath: str):
        matches, _notes, _traces, incomplete = self._analyze(content, filepath)
        return IncompletePatternMatches(matches, reason=incomplete) if incomplete else matches

    def context_notes_for_matches(
        self, content: str, filepath: str, matches: list[tuple[int, str]]
    ):
        _matches, notes, traces, _incomplete = self._analyze(content, filepath)
        return [
            _Notes((notes[item],), traces[item]) if item in notes and item in traces else None
            for item in matches
        ]


_SAMPLE = (
    "node {\n"
    "  withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {\n"
    "    sh '''curl https://example.test/api?key=$TOKEN -X POST'''\n"
    "  }\n"
    "}\n"
)

RULES = [
    Rule(
        id="SEC6-JK-013",
        title="Jenkins bound credential appears in a curl URL query",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A directly scoped Jenkins credential is referenced in the query of a curl URL. "
            "This is a configured possible transfer, not proof of request delivery or misuse."
        ),
        pattern=JenkinsCredentialQueryPattern(),
        remediation=(
            "If the endpoint accepts it, move the credential to an Authorization header "
            "and avoid logging request URLs. Review the actual endpoint and relevant logs; "
            "rotate the credential if exposure is confirmed."
        ),
        reference="https://www.jenkins.io/doc/pipeline/steps/credentials-binding/",
        test_positive=[_SAMPLE],
        test_negative=[
            _SAMPLE.replace("?key=$TOKEN", "").replace(
                " -X POST", ' -H "Authorization: Bearer $TOKEN" -X POST'
            ),
        ],
        finding_family="credential_exposure",
        confidence="medium",
        review_needed=True,
    )
]

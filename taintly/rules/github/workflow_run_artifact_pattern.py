from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from taintly.models import IncompletePatternMatches
from taintly.parsers.structural import triggers as structural_triggers
from taintly.rules.github._workflow_run_artifact import CoverageIssue, _analyze_workflow
from taintly.workflow_corpus import CorpusEvidence, WorkflowSummary, _extract_raw_events


@dataclass(frozen=True)
class _OccurrenceNotes:
    notes: tuple[str, ...]


class WorkflowRunArtifactConsumerPattern:
    """Per-file adapter for bounded workflow_run artifact-consumer analysis.

    The underlying proof is consumer-only. Producer identity, artifact member
    mapping, file bytes, transfer/execution success, PR origin, and effective
    credentials remain unresolved and are stated as such in occurrence notes.
    """

    def _analyze(
        self, content: str, filepath: str
    ) -> tuple[list[CorpusEvidence], list[CoverageIssue]]:
        raw_events = set(structural_triggers(content)) or _extract_raw_events(content)
        workflow = WorkflowSummary(
            filepath=filepath,
            content=content,
            lines=content.splitlines(),
            raw_event_names=frozenset(raw_events),
        )
        return _analyze_workflow(workflow)

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        del lines
        findings, issues = self._analyze(content, "workflow.yml")
        matches = [(item.line, item.snippet) for item in findings]
        if issues:
            reason = "; ".join(dict.fromkeys(issue.reason for issue in issues))
            return IncompletePatternMatches(matches, reason=reason)
        return matches

    def check_with_filepath(
        self, content: str, lines: list[str], filepath: str
    ) -> list[tuple[int, str]]:
        del lines
        findings, issues = self._analyze(content, filepath)
        matches = [(item.line, item.snippet) for item in findings]
        if issues:
            reason = "; ".join(dict.fromkeys(issue.reason for issue in issues))
            return IncompletePatternMatches(matches, reason=reason)
        return matches

    def context_notes_for_matches(
        self, content: str, filepath: str, matches: list[tuple[int, str]]
    ) -> list[_OccurrenceNotes | None]:
        findings, _issues = self._analyze(content, filepath)
        by_occurrence = {(item.line, item.snippet): item for item in findings}
        counts = Counter((item.line, item.snippet) for item in findings)
        match_counts = Counter(matches)
        result: list[_OccurrenceNotes | None] = []
        for occurrence in matches:
            item = by_occurrence.get(occurrence)
            if item is None:
                result.append(None)
            elif counts[occurrence] != 1 or match_counts[occurrence] != 1:
                result.append(
                    _OccurrenceNotes(
                        (
                            "Occurrence identity is ambiguous; artifact origin and execution context remain unknown.",
                        )
                    )
                )
            else:
                result.append(_OccurrenceNotes(item.context_notes))
        return result

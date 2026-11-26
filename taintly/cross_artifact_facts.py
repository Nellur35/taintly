"""Caller-to-composite-action flows through the shared local call graph."""

from __future__ import annotations

from dataclasses import dataclass

from .local_call_graph import LocalFlow, local_flows_for_rule
from .workflow_corpus import CorpusAnalysisGap, WorkflowCorpus


@dataclass(frozen=True)
class CrossArtifactFlow(LocalFlow):
    """Configured local-action input flow with complete caller/source evidence."""


def find_cross_artifact_taint(
    corpus: WorkflowCorpus, *, action_source_gaps: set[CorpusAnalysisGap] | None = None
) -> list[CrossArtifactFlow]:
    """Return action sinks, including reusable-workflow-to-action chains."""
    return [
        CrossArtifactFlow(**flow.__dict__)
        for flow in local_flows_for_rule(corpus, source_gaps=action_source_gaps)
        if flow.callee_kind == "action"
    ]

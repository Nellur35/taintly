"""Caller-to-reusable-workflow flows through the shared local call graph."""

from __future__ import annotations

from dataclasses import dataclass

from .local_call_graph import LocalFlow, local_flows_for_rule
from .workflow_corpus import CorpusAnalysisGap, WorkflowCorpus


@dataclass(frozen=True)
class CrossFileFlow(LocalFlow):
    """Configured input flow to a reusable workflow sink, with review evidence."""


def find_cross_file_taint(
    corpus: WorkflowCorpus, *, source_gaps: set[CorpusAnalysisGap] | None = None
) -> list[CrossFileFlow]:
    """Return workflow sinks across invocation-isolated local call chains."""
    return [
        CrossFileFlow(**flow.__dict__)
        for flow in local_flows_for_rule(corpus, source_gaps=source_gaps)
        if flow.callee_kind == "workflow"
    ]

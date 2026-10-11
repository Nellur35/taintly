"""Caller-to-composite-action flows through the shared local call graph."""

from __future__ import annotations

from dataclasses import dataclass

from .local_call_graph import LocalFlow, find_local_flows
from .workflow_corpus import WorkflowCorpus


@dataclass(frozen=True)
class CrossArtifactFlow(LocalFlow):
    """Configured local-action input flow with complete caller/source evidence."""


def find_cross_artifact_taint(corpus: WorkflowCorpus) -> list[CrossArtifactFlow]:
    """Return action sinks, including reusable-workflow-to-action chains."""
    return [
        CrossArtifactFlow(**flow.__dict__)
        for flow in find_local_flows(corpus)
        if flow.callee_kind == "action"
    ]

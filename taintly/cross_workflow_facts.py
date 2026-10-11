"""Caller-to-reusable-workflow flows through the shared local call graph."""

from __future__ import annotations

from dataclasses import dataclass

from .local_call_graph import LocalFlow, find_local_flows
from .workflow_corpus import WorkflowCorpus


@dataclass(frozen=True)
class CrossFileFlow(LocalFlow):
    """Configured input flow to a reusable workflow sink, with review evidence."""


def find_cross_file_taint(corpus: WorkflowCorpus) -> list[CrossFileFlow]:
    """Return workflow sinks across invocation-isolated local call chains."""
    return [
        CrossFileFlow(**flow.__dict__)
        for flow in find_local_flows(corpus)
        if flow.callee_kind == "workflow"
    ]

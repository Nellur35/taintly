"""Configured input flows through local composite actions, with source evidence.

The composite-action sibling of ``XF-GH-005`` (reusable workflows). Built on
:func:`taintly.cross_artifact_facts.find_cross_artifact_taint` adapts the shared
invocation traversal, including mixed workflow/action chains. Runtime action
bytes and unsupported execution semantics retain explicit review state.
"""

from __future__ import annotations

import os

from taintly.cross_artifact_facts import find_cross_artifact_taint
from taintly.local_call_graph import flow_evidence
from taintly.models import Platform, Rule, Severity
from taintly.workflow_corpus import CorpusFindings, CorpusPattern, WorkflowCorpus

RULES: list[Rule] = []


def _label(path: str) -> str:
    """Action files are identified by their dir (``greet``); workflows and
    everything else by filename (``ci.yml``)."""
    bn = os.path.basename(path)
    if bn in ("action.yml", "action.yaml"):
        return os.path.basename(os.path.dirname(path)) or bn
    return bn


def _xf_gh_006_callback(corpus: WorkflowCorpus) -> CorpusFindings:
    findings: CorpusFindings = []
    for flow in find_cross_artifact_taint(corpus):
        chain = " -> ".join(f"{_label(c)}:{ln}" for c, ln, _ in flow.hop_chain)
        action = _label(flow.callee)
        snippet = (
            f"{flow.source_expr} forwarded via {chain} into local action "
            f"'{action}' input '{flow.input}', reaching shell sink "
            f"{action}:{flow.sink_line}: {flow.sink_snippet}"
        )
        findings.append(flow_evidence(flow, snippet))
    return findings


RULES.append(
    Rule(
        id="XF-GH-006",
        title="Configured cross-file input flow through a local composite action",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A workflow (or another local action) passes an "
            "attacker-controlled GitHub context "
            "(`github.event.*`, `github.head_ref`, `github.actor`, or a "
            "tainted upstream input) as a `with:` input to a local "
            "composite action (`uses: ./...`), and that action "
            "interpolates the input into a `run:` shell step.\n"
            "\n"
            "Neither file alone proves the bug: the workflow shells "
            "nothing, and the action does not know its input is "
            "attacker-fed. This rule joins them across the repo — the "
            "caller forwards an attacker context and the configured "
            "action body contains a shell-source or argument-use candidate. "
            "Invocation-specific inputs propagate through reusable workflows "
            "and nested actions. Unknown guards, command reinterpretation "
            "and runtime checkout/workspace correspondence remain review-needed; "
            "resource limits produce incomplete-scan diagnostics. The per-file scan "
            "does not cover action.yml, so this flow is otherwise "
            "invisible."
        ),
        pattern=CorpusPattern(callback=_xf_gh_006_callback),
        remediation=(
            "Treat the forwarded context as untrusted at the call site:\n"
            "do not pass `github.event.*` / `github.head_ref` directly\n"
            "into a local action's `with:` inputs. Either sanitise /\n"
            "allow-list the value before the call, or change the action\n"
            "to consume the input as quoted data via an intermediate\n"
            '`env:` var (`env: X: ${{ inputs.x }}` then `"$X"`) rather\n'
            "than interpolating it straight into the shell command."
        ),
        reference="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
        # CorpusPattern rule — exercised by multi-file fixtures in
        # tests/unit/test_cross_artifact.py, not single-YAML self-test samples.
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens an issue or PR whose title is a shell "
            "payload. A workflow forwards `github.event.issue.title` "
            "into a local composite action's `with:` input, and the "
            "action interpolates that input into a `run:` block. The "
            "payload may execute if the configured action bytes and guards "
            "permit this path. Impact depends on the effective token grants "
            "and secrets available to that invocation. "
            "The source and sink evidence spans the workflow and action metadata."
        ),
        finding_family="User-controlled input reaching shell execution",
        confidence="medium",
    )
)

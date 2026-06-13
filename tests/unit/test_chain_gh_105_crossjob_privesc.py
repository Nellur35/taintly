"""CHAIN-GH-105 — cross-job privilege-escalation composer rule (P1.3).

CHAIN-GH-105 fires when a LOW-privilege producer job (read-only token)
declares an output that a HIGH-privilege consumer job (write-capable
token) reads via ``${{ needs.<producer>.outputs.<name> }}``. The
producer is the attacker-influenceable surface; its output crossing
the job boundary into a write-capable job is a privilege-escalation
gradient.

CorpusPattern composer rules don't fit the single-file self-test
harness (the join spans jobs and per-job permission context), so they
are exercised here against ``tmp_path`` repos with realistic
``.github/workflows/`` layouts — the same convention as
``test_cross_workflow_rules.py``.

The rule depends on per-job ``permissions:`` attribution: when both
jobs inherit the workflow default, the gradient is unobservable and
the rule conservatively does not fire (a documented precision choice,
pinned by ``test_negative_workflow_default_only``).
"""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform, Severity
from taintly.rules.registry import load_all_rules


def _write_workflow(tmp_path: Path, name: str, content: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / name
    p.write_text(content, encoding="utf-8")
    return p


def _fires(tmp_path: Path) -> list:
    rules = load_all_rules()
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)
    return [f for r in reports for f in r.findings if f.rule_id == "CHAIN-GH-105"]


# ---------------------------------------------------------------------------
# Positive — read-only producer output flows into a write-capable consumer
# ---------------------------------------------------------------------------

_POSITIVE = (
    "on: pull_request_target\n"
    "jobs:\n"
    "  produce:\n"
    "    runs-on: ubuntu-latest\n"
    "    permissions:\n"
    "      contents: read\n"
    "    outputs:\n"
    "      val: ${{ steps.s.outputs.v }}\n"
    "    steps:\n"
    "      - id: s\n"
    '        run: echo "v=hi" >> $GITHUB_OUTPUT\n'
    "  consume:\n"
    "    needs: produce\n"
    "    runs-on: ubuntu-latest\n"
    "    permissions:\n"
    "      contents: write\n"
    "      id-token: write\n"
    "    steps:\n"
    "      - run: echo ${{ needs.produce.outputs.val }}\n"
)


def test_positive_read_producer_into_write_consumer(tmp_path: Path) -> None:
    _write_workflow(tmp_path, "w.yml", _POSITIVE)
    fires = _fires(tmp_path)
    assert len(fires) == 1
    f = fires[0]
    # Anchored on the consumer's escalation point (the needs-output ref).
    assert f.line == 19
    assert f.severity == Severity.MEDIUM
    # Provenance names the producer -> consumer gradient.
    assert "produce" in f.snippet
    assert "consume" in f.snippet
    assert "needs.produce.outputs.val" in f.snippet


# ---------------------------------------------------------------------------
# Negatives
# ---------------------------------------------------------------------------


def test_negative_same_privilege(tmp_path: Path) -> None:
    """Both jobs read-only: no gradient, no fire."""
    content = _POSITIVE.replace(
        "      contents: write\n      id-token: write\n",
        "      contents: read\n",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_negative_high_to_low(tmp_path: Path) -> None:
    """Producer write, consumer read: the gradient runs the safe
    direction (privileged data into an unprivileged job), no fire."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "    outputs:\n"
        "      val: ${{ steps.s.outputs.v }}\n"
        "    steps:\n"
        "      - id: s\n"
        '        run: echo "v=hi" >> $GITHUB_OUTPUT\n'
        "  consume:\n"
        "    needs: produce\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "    steps:\n"
        "      - run: echo ${{ needs.produce.outputs.val }}\n"
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_negative_no_crossjob_edge(tmp_path: Path) -> None:
    """A write-capable job exists, but it never reads the read-only
    job's output via needs.*.outputs — no cross-job data edge, no fire."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "    outputs:\n"
        "      val: x\n"
        "    steps:\n"
        "      - run: echo hi\n"
        "  consume:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "    steps:\n"
        "      - run: echo standalone\n"
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_negative_workflow_default_only(tmp_path: Path) -> None:
    """Neither job declares its own permissions: block. The gradient
    is unobservable (both inherit the workflow default) and the rule
    conservatively does NOT fire — the documented precision choice."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    outputs:\n"
        "      val: ${{ steps.s.outputs.v }}\n"
        "    steps:\n"
        "      - id: s\n"
        '        run: echo "v=hi" >> $GITHUB_OUTPUT\n'
        "  consume:\n"
        "    needs: produce\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ${{ needs.produce.outputs.val }}\n"
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_negative_trusted_bot_gate(tmp_path: Path) -> None:
    """A dependabot-gated consumer suppresses the chain: the producer
    surface is not externally attacker-controllable."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "    outputs:\n"
        "      val: ${{ steps.s.outputs.v }}\n"
        "    steps:\n"
        "      - id: s\n"
        '        run: echo "v=hi" >> $GITHUB_OUTPUT\n'
        "  consume:\n"
        "    needs: produce\n"
        "    if: github.actor == 'dependabot[bot]'\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "    steps:\n"
        "      - run: echo ${{ needs.produce.outputs.val }}\n"
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []

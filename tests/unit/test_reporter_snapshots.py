"""Snapshot tests for the five reporter formats.

The structural tests in :mod:`tests.unit.test_reporters` verify that
specific fields exist (SARIF version, JSON keys, CSV headers).  They
miss output-shape regressions: a reporter that silently drops a column,
reorders fields, or changes a delimiter will pass every structural
test while breaking downstream tooling that depends on the exact form.

Snapshot tests close that gap.  Each format is rendered against a
canonical AuditReport fixture and compared against a stored snapshot
under ``tests/unit/_snapshots/reporters/``.  When a reporter's output
changes intentionally, regenerate with::

    python -m pytest tests/unit/test_reporter_snapshots.py \
        --snapshot-update

Then commit the regenerated snapshot files alongside the reporter
change so the next CI run sees the new baseline.

Determinism guards:
  * The canonical report uses fixed strings — no paths, hostnames,
    or system-dependent values.
  * SARIF embeds ``taintly.__version__`` which can drift in untagged
    checkouts (setuptools-scm fallback); we monkeypatch the SARIF
    module's ``_TOOL_VERSION`` constant to a stable literal.
  * HTML embeds ``datetime.now()`` in the cover header; we
    monkeypatch the module's ``datetime`` import to a frozen clock.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.models import AuditReport, Finding, Severity

# pytest-snapshot ships the ``snapshot`` fixture; if it's not installed
# (CI matrix that strips dev deps) skip the whole module rather than
# error noisily.  Re-running locally with ``pip install -e ".[dev]"``
# pulls in the dependency.
pytest.importorskip("pytest_snapshot", reason="pytest-snapshot not installed")


SNAPSHOT_DIR = Path(__file__).parent / "_snapshots" / "reporters"


_FROZEN_TIMESTAMP = "2026-01-01T00:00:00"
_FROZEN_VERSION = "9.9.9-test"


@pytest.fixture
def canonical_report() -> AuditReport:
    """An AuditReport with a deterministic mix of findings.

    Carries:
      * One CRITICAL pinning finding with a STRIDE category and an
        incident citation (covers richest reporter rendering paths).
      * One HIGH PSE-GH-001 with a long multi-line remediation
        (exercises the text reporter's collapse behaviour and the
        CSV reporter's first-line-of-remediation truncation).
      * One MEDIUM finding with a multi-stride list (exercises the
        SARIF tags assembly).
      * One LOW finding flagged review_needed=True (exercises the
        v2 family/confidence/review channels).
      * One ENGINE-ERR (exercises the JSON ``errors`` array and the
        SARIF ``invocations[*].toolExecutionNotifications`` channel).

    Repo path is a fixed POSIX literal so Windows path separators
    don't perturb the snapshot.
    """
    report = AuditReport(repo_path="/snapshot/repo", platform="github")
    report.files_scanned = 4
    report.rules_loaded = 215

    report.add(
        Finding(
            rule_id="SEC3-GH-001",
            severity=Severity.CRITICAL,
            title="Action referenced by mutable tag",
            description=(
                "An external action is referenced by a mutable tag (e.g. "
                "@v4) instead of a 40-character commit SHA.  An attacker "
                "who compromises the action's repo can move the tag to a "
                "malicious commit; every consumer pinned by tag picks up "
                "the new code on the next workflow run."
            ),
            file=".github/workflows/ci.yml",
            line=12,
            snippet="      - uses: actions/checkout@v4",
            remediation=(
                "Pin the action to a full 40-character commit SHA.\n"
                "Use `gh action pin` or `taintly --fix`."
            ),
            reference="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
            owasp_cicd="CICD-SEC-3",
            stride=["T"],
            threat_narrative=(
                "Tag-based pinning lets the upstream maintainer (or "
                "anyone who compromises their account) hot-swap the "
                "action contents without changing the workflow file."
            ),
            incidents=["tj-actions/changed-files (CVE-2025-30066)"],
            finding_family="supply_chain_immutability",
            confidence="high",
            exploitability="high",
            review_needed=False,
        )
    )

    report.add(
        Finding(
            rule_id="PSE-GH-001",
            severity=Severity.HIGH,
            title="AI agent with cloud-credential grant on a fork-reachable event",
            description=(
                "Permission Slip Effect: a fork-reachable trigger, an AI "
                "agent action, and a cloud-credential grant co-exist.  An "
                "attacker who steers the agent via prompt injection holds "
                "a valid OIDC token."
            ),
            file=".github/workflows/agent.yml",
            line=24,
            snippet="      - uses: anthropics/claude-code-action@v1",
            remediation=(
                "Break at least one leg of the triangle:\n"
                "1. Gate the agent job by same-repo identity.\n"
                "2. Drop the id-token: write grant from the agent job.\n"
                "3. Narrow the agent's allowedTools to forbid shell."
            ),
            reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
            owasp_cicd="CICD-SEC-4",
            stride=["E", "T", "I"],
            threat_narrative="Attacker mints OIDC token via prompt injection.",
            incidents=[],
            finding_family="agent_credential_chain",
            confidence="medium",
            exploitability="high",
            review_needed=False,
        )
    )

    report.add(
        Finding(
            rule_id="SEC2-GH-002",
            severity=Severity.MEDIUM,
            title="Missing top-level permissions block",
            description="Workflow does not declare a top-level permissions block.",
            file=".github/workflows/ci.yml",
            line=1,
            snippet="on: push",
            remediation="Add `permissions: contents: read` at the top level.",
            reference="https://docs.github.com/en/actions/security-guides/automatic-token-authentication",
            owasp_cicd="CICD-SEC-2",
            stride=["E", "T"],
            threat_narrative="A compromised step inherits the default token's full scope.",
            incidents=[],
            finding_family="excessive_permissions",
            confidence="high",
            exploitability="medium",
            review_needed=False,
        )
    )

    report.add(
        Finding(
            rule_id="TAINT-GH-001",
            severity=Severity.LOW,
            title="Possible taint flow",
            description="Untrusted context flows into a run: block via env.",
            file=".github/workflows/ci.yml",
            line=42,
            snippet='        run: echo "$PR_TITLE"',
            remediation="Quote the variable in the run: block.",
            reference="",
            owasp_cicd="CICD-SEC-1",
            stride=["T"],
            threat_narrative="",
            incidents=[],
            finding_family="taint_to_run_block",
            confidence="medium",
            exploitability="medium",
            review_needed=True,
        )
    )

    report.add(
        Finding(
            rule_id="ENGINE-ERR",
            severity=Severity.LOW,
            title="File size 60000 bytes exceeds scanner cap (50000)",
            description="Per-line rules still ran but file-scope coverage degraded.",
            file=".github/workflows/big.yml",
            line=0,
            snippet="",
            remediation="",
            reference="",
            owasp_cicd="",
            stride=[],
            threat_narrative="",
            incidents=[],
            finding_family="",
            confidence="high",
            exploitability="medium",
            review_needed=False,
        )
    )

    report.summarize()
    return report


# ---------------------------------------------------------------------------
# Per-format snapshot tests
# ---------------------------------------------------------------------------


def test_text_reporter_snapshot(canonical_report, snapshot):
    """Text reporter is the human-facing path; regressions on its
    layout (severity colour codes stripped, missing rule-ID column,
    summary block reorder) directly degrade the CLI experience.
    """
    from taintly.reporters.text import format_text

    rendered = format_text(canonical_report, use_color=False, score_report=None, verbose=True)
    snapshot.snapshot_dir = SNAPSHOT_DIR
    snapshot.assert_match(rendered, "report.txt")


def test_json_reporter_snapshot(canonical_report, snapshot):
    """JSON is the contract surface most consumed by downstream tooling
    (custom dashboards, baseline diffs, CI gates).  Any silent field
    rename or reorder shows up here.
    """
    from taintly.reporters.json_report import format_json

    rendered = format_json(canonical_report)
    snapshot.snapshot_dir = SNAPSHOT_DIR
    snapshot.assert_match(rendered + "\n", "report.json")


def test_csv_reporter_snapshot(canonical_report, snapshot):
    """CSV is consumed by spreadsheet exports and security-team
    workflows.  A header reorder breaks every saved filter / pivot.
    """
    from taintly.reporters.csv_report import format_csv

    rendered = format_csv(canonical_report)
    snapshot.snapshot_dir = SNAPSHOT_DIR
    snapshot.assert_match(rendered, "report.csv")


def test_sarif_reporter_snapshot(canonical_report, snapshot, monkeypatch):
    """SARIF is the GitHub Advanced Security and GitLab security-
    dashboard contract.  GHAS silently rejects malformed SARIF, so a
    regression here ships a green CI with zero findings posted.

    Pin ``_TOOL_VERSION`` to a stable literal so untagged checkouts
    (setuptools-scm fallback ``0.0.0+unknown``) don't perturb the
    snapshot.  Real releases publish a real version; the snapshot
    can be regenerated then.
    """
    from taintly.reporters import sarif as sarif_mod

    monkeypatch.setattr(sarif_mod, "_TOOL_VERSION", _FROZEN_VERSION)
    rendered = sarif_mod.format_sarif(canonical_report)
    snapshot.snapshot_dir = SNAPSHOT_DIR
    snapshot.assert_match(rendered + "\n", "report.sarif.json")


def test_html_reporter_snapshot(canonical_report, snapshot, monkeypatch):
    """HTML is what auditors / reviewers see when sharing a report.
    A CSS-class rename or template restructure breaks every linked
    artefact a security team has shipped.

    The HTML cover header embeds ``datetime.now()``; freeze it via
    monkeypatch so the snapshot is reproducible.
    """
    from datetime import datetime as real_datetime

    from taintly.reporters import html_report as html_mod

    class _FrozenDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ARG003
            return real_datetime.fromisoformat(_FROZEN_TIMESTAMP)

    monkeypatch.setattr(html_mod, "datetime", _FrozenDatetime)

    rendered = html_mod.format_html(canonical_report, score_report=None)
    snapshot.snapshot_dir = SNAPSHOT_DIR
    snapshot.assert_match(rendered + "\n", "report.html")

"""TD-025 headline contract for configured LOTP build steps.

The source-labeled checkout-v7 control intentionally leaves runtime reachability
unresolved. A finding describes configured workflow behavior, not a run log.
"""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_file
from taintly.models import Severity
from taintly.rules.registry import get_rule_by_id

_SOURCE_LABEL = "TD025: checkout-v7 privileged-fork block leaves execution unresolved"
_RULE_ID = "LOTP-GH-001"


def _workflow(checkout: str, permissions: str, persist_credentials: bool) -> str:
    return f"""name: headline context
on: pull_request_target
{permissions}
jobs:
  build:
    if: github.event.pull_request.head.repo.fork == true
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{checkout}
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          repository: ${{{{ github.event.pull_request.head.repo.full_name }}}}
          persist-credentials: {str(persist_credentials).lower()}
      - run: npm ci
"""


def _finding(tmp_path: Path, body: str, filename: str):
    path = tmp_path / filename
    path.write_text(body, encoding="utf-8")
    rule = get_rule_by_id(_RULE_ID)
    assert rule is not None
    findings = [finding for finding in scan_file(str(path), [rule]) if finding.rule_id == _RULE_ID]
    assert len(findings) == 1, _SOURCE_LABEL
    return findings[0]


def test_unresolved_v7_candidate_stays_visible_without_execution_claim(tmp_path):
    rule = get_rule_by_id(_RULE_ID)
    assert rule is not None
    finding = _finding(
        tmp_path,
        _workflow(
            "v7",
            "permissions:\n  contents: write",
            persist_credentials=True,
        ),
        "checkout-v7.yml",
    )

    assert finding.rule_id == _RULE_ID
    assert finding.severity == rule.severity == Severity.CRITICAL
    assert finding.review_needed is True
    assert "authority-unresolved" in finding.context_tags
    assert "may run" in finding.title.lower()
    assert "executed" not in finding.title.lower()


def test_evidenced_candidate_keeps_legacy_identity_and_configured_title(tmp_path):
    rule = get_rule_by_id(_RULE_ID)
    assert rule is not None
    finding = _finding(
        tmp_path,
        _workflow(
            "v4",
            "permissions:\n  contents: write",
            persist_credentials=True,
        ),
        "checkout-v4.yml",
    )

    assert finding.rule_id == _RULE_ID
    assert finding.severity == rule.severity == Severity.CRITICAL
    assert finding.title == rule.title
    assert finding.review_needed is False
    assert "may run" in finding.title.lower()
    assert "executed" not in finding.title.lower()

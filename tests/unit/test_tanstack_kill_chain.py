"""End-to-end TanStack-style kill-chain regression test.

The fixture in ``tests/fixtures/github/kill_chains/tanstack/`` is a
small synthetic workflow tree that exercises the public taintly coverage
for the TanStack-style cache + checkout + publish chain:

* ``pr-validate.yml`` uses ``pull_request_target``, bare checkout, and a
  cache write keyed by attacker-controlled PR state.
* ``pr-comment.yml`` uses ``issue_comment``, bare checkout, and a
  downstream ``git push``.
* ``release.yml`` restores the executable cache prefix written by the PR
  workflow.

This is intentionally pinned to public-repo semantics.  Public currently
does not flag SEC2-GH-002 when job-level permissions are present, and it
does not ship the lab-only CHAIN-GH-101 composition as a required fire.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform, Severity
from taintly.rules.registry import load_all_rules

KILL_CHAIN = (
    Path(__file__).parent.parent / "fixtures" / "github" / "kill_chains" / "tanstack"
)


@pytest.fixture(scope="module")
def kill_chain_findings():
    reports = scan_repo(str(KILL_CHAIN), load_all_rules(), Platform.GITHUB)
    return [finding for report in reports for finding in report.findings]


def _fires_of(findings, rule_id: str) -> list:
    return [finding for finding in findings if finding.rule_id == rule_id]


def test_kill_chain_fires_sec4_gh_005(kill_chain_findings):
    fires = _fires_of(kill_chain_findings, "SEC4-GH-005")

    assert len(fires) == 1
    assert "pr-comment.yml" in fires[0].file
    assert fires[0].severity == Severity.MEDIUM


def test_kill_chain_fires_sec4_gh_005b_posture_sibling(kill_chain_findings):
    fires = _fires_of(kill_chain_findings, "SEC4-GH-005B")

    assert len(fires) == 1
    assert "pr-validate.yml" in fires[0].file
    assert fires[0].severity == Severity.INFO
    assert [
        finding
        for finding in _fires_of(kill_chain_findings, "SEC4-GH-005")
        if "pr-validate.yml" in finding.file
    ] == []


def test_kill_chain_fires_sec4_gh_026a_not_026(kill_chain_findings):
    fires_a = _fires_of(kill_chain_findings, "SEC4-GH-026A")

    assert len(fires_a) == 1
    assert "pr-validate.yml" in fires_a[0].file
    assert fires_a[0].severity == Severity.MEDIUM
    assert [
        finding
        for finding in _fires_of(kill_chain_findings, "SEC4-GH-026")
        if "pr-validate.yml" in finding.file
    ] == []


def test_kill_chain_fires_sec9_gh_005(kill_chain_findings):
    fires = _fires_of(kill_chain_findings, "SEC9-GH-005")

    assert len(fires) == 1
    assert "pr-validate.yml" in fires[0].file
    assert fires[0].severity == Severity.HIGH


def test_kill_chain_fires_xf_gh_001a_not_001(kill_chain_findings):
    fires_a = _fires_of(kill_chain_findings, "XF-GH-001A")

    assert len(fires_a) >= 1
    assert any("release.yml" in finding.file for finding in fires_a)
    assert any(finding.severity == Severity.HIGH for finding in fires_a)
    assert _fires_of(kill_chain_findings, "XF-GH-001") == []


def test_kill_chain_public_inventory_stable(kill_chain_findings):
    expected = {
        "SEC4-GH-005",
        "SEC4-GH-005B",
        "SEC4-GH-026A",
        "SEC9-GH-005",
        "XF-GH-001A",
    }
    fired_target = {finding.rule_id for finding in kill_chain_findings if finding.rule_id in expected}

    assert fired_target == expected


def test_kill_chain_public_severity_distribution_pinned(kill_chain_findings):
    target_ids = {
        "SEC4-GH-005",
        "SEC4-GH-005B",
        "SEC4-GH-026A",
        "SEC9-GH-005",
        "XF-GH-001A",
    }
    target = [finding for finding in kill_chain_findings if finding.rule_id in target_ids]
    by_sev: dict[Severity, int] = {}
    for finding in target:
        by_sev[finding.severity] = by_sev.get(finding.severity, 0) + 1

    assert by_sev.get(Severity.HIGH, 0) >= 2
    assert by_sev.get(Severity.MEDIUM, 0) >= 2
    assert by_sev.get(Severity.INFO, 0) >= 1

"""Evasion corpus tests.

These tests assert that the tool CANNOT detect the documented bypasses.
A test PASSING here means the bypass is confirmed real.
A test FAILING here means a bypass was accidentally fixed — which is GOOD,
but the file should then be moved to fixtures/vulnerable/ and tested for detection.

Run with: pytest tests/evasion/ -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform

EVASION_DIR = Path(__file__).parent


@pytest.mark.parametrize(
    "filename, bypassed_rules, notes",
    [
        (
            "variable_indirection.yml",
            ["SEC4-GH-006"],
            "OUT=$GITHUB_ENV splits the pattern across lines",
        ),
        # NOTE: anchor_merge_inject.yml moved to fixtures/github/safe/ —
        # the anchor-merge expander pre-pass (Task 5) now suppresses the
        # SEC4-GH-005 false positive.  See tests/unit/test_anchor_expander.py
        # and tests/unit/test_engine.py::test_anchor_merge_does_not_fire_sec4_gh_005.
        (
            "cross_job_output_routing.yml",
            ["SEC6-GH-004", "SEC6-GH-005"],
            "Secret routed through job outputs — cross-job taint invisible to static analysis",
        ),
        (
            "base64_shell.yml",
            ["SEC6-GH-007"],
            "curl|bash encoded in base64 — literal pattern never appears",
        ),
        (
            "orphaned_sha.yml",
            ["SEC3-GH-001"],
            "40-char hex pointing to orphaned fork commit — indistinguishable from real SHA",
        ),
        (
            "shell_export_unsecure.yml",
            ["SEC4-GH-009"],
            "export ACTIONS_ALLOW_UNSECURE_COMMANDS=true in run: not detected",
        ),
        (
            "github_env_heredoc.yml",
            ["SEC4-GH-006"],
            "Heredoc write to $GITHUB_ENV splits the ${{ ... }} and `>> $GITHUB_ENV` "
            "across lines — SEC4-GH-006's per-line regex cannot bridge them. Note "
            "SEC4-GH-004 still fires on the general context-in-run: surface, so "
            "detection degrades gracefully rather than failing silently.",
        ),
    ],
)
def test_evasion_bypass_confirmed(filename, bypassed_rules, notes, github_rules):
    """Confirm that documented bypasses are not detected.

    If a rule here starts firing, it means the bypass was fixed.
    In that case: move the file to fixtures/vulnerable/, add a detection test,
    and remove it from this parametrize list.
    """
    filepath = EVASION_DIR / filename
    findings = scan_file(str(filepath), rules=github_rules)
    fired = {f.rule_id for f in findings if f.rule_id != "ENGINE-ERR"}

    for rule_id in bypassed_rules:
        assert rule_id not in fired, (
            f"BYPASS FIXED: {filename} now triggers {rule_id}!\n"
            f"This is good — move the file to fixtures/vulnerable/ and add a detection test.\n"
            f"Notes: {notes}"
        )

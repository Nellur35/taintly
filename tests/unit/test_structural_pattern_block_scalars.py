"""Line-level regression tests for StructuralPattern's block-scalar
per-line emission.

After Phase 2 shipped, multi-line ``run: |`` block scalars reported
findings at the block-scalar header line rather than the line
containing the dangerous interpolation.  The Subtask 2 fix added a
``block_lines`` field to LEAF_SCALAR events and taught
StructuralPattern to run the predicate per body line and emit
findings at the matched line's actual source coordinates.

This module pins that behaviour with line-exact assertions so a
future regression in the walker or pattern shows up as a test
failure, not as a triage-degraded report.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


@pytest.fixture(scope="module")
def gh_rules():
    return [r for r in load_all_rules() if r.platform == Platform.GITHUB]


def _rule(rules, rule_id: str):
    return [r for r in rules if r.id == rule_id]


def test_sec4_gh_004_lands_on_dangerous_line_not_block_header(
    tmp_path: Path, gh_rules
):
    """A multi-line ``run: |`` block scalar that contains exactly
    one dangerous GitHub-context interpolation must produce a
    SEC4-GH-004 finding at the source line containing the
    interpolation — not at the ``run: |`` header line.
    """
    src = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        '          echo "Processing..."\n'
        '          echo "Title: ${{ github.event.pull_request.title }}"\n'
        "          echo done\n"
    )
    fixture = tmp_path / "wf.yml"
    fixture.write_text(src)
    rules = _rule(gh_rules, "SEC4-GH-004")
    findings = scan_file(str(fixture), rules)
    sec4 = [f for f in findings if f.rule_id == "SEC4-GH-004"]
    assert len(sec4) == 1, (
        f"Expected one SEC4-GH-004 finding, got {len(sec4)}: "
        f"{[(f.line, f.snippet) for f in sec4]}"
    )
    assert sec4[0].line == 8, (
        f"Expected line 8 (the dangerous interpolation), "
        f"got line {sec4[0].line} with snippet {sec4[0].snippet!r}.  "
        "The structural form must emit at the body line, not the "
        "block-scalar header line."
    )


def test_sec4_gh_004_does_not_fire_on_clean_block_scalar(
    tmp_path: Path, gh_rules
):
    """The same multi-line block-scalar shape with no dangerous
    interpolation must produce no findings — symmetric assertion
    confirming the per-line emission isn't false-firing.
    """
    src = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        '          echo "Processing..."\n'
        '          echo "Title: pinned-title-here"\n'
        "          echo done\n"
    )
    fixture = tmp_path / "wf.yml"
    fixture.write_text(src)
    rules = _rule(gh_rules, "SEC4-GH-004")
    findings = scan_file(str(fixture), rules)
    sec4 = [f for f in findings if f.rule_id == "SEC4-GH-004"]
    assert not sec4, (
        f"Expected no SEC4-GH-004 findings on a clean block-scalar; "
        f"got: {[(f.line, f.snippet) for f in sec4]}"
    )


def test_sec4_gh_004_emits_per_dangerous_line_in_multi_match_block(
    tmp_path: Path, gh_rules
):
    """If a single block scalar contains TWO dangerous
    interpolations on different body lines, the structural form
    must produce two findings — one per body line — not one for
    the whole block.
    """
    src = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        '          echo "Title: ${{ github.event.pull_request.title }}"\n'
        '          echo "Body: ${{ github.event.pull_request.body }}"\n'
    )
    fixture = tmp_path / "wf.yml"
    fixture.write_text(src)
    rules = _rule(gh_rules, "SEC4-GH-004")
    findings = scan_file(str(fixture), rules)
    sec4 = sorted(
        [f for f in findings if f.rule_id == "SEC4-GH-004"],
        key=lambda f: f.line,
    )
    assert [f.line for f in sec4] == [7, 8], (
        f"Expected findings at lines 7 and 8 (one per dangerous "
        f"interpolation), got {[(f.line, f.snippet) for f in sec4]}"
    )

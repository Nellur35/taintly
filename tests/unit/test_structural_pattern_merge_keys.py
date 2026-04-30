"""Line-level regression test for the structural form's merge-key
handling on rules that query mapping leaves at jobs.*.runs-on.

The structural reader's anchor-merge-key behaviour is documented in
``docs/STRUCTURAL_READER_SCOPE.md``: ``<<: *anchor`` replays every
captured leaf at the alias's line under the alias's current path.
For SEC7-GH-001 (self-hosted runner detection), this means a YAML
file with a single anchor body defining ``runs-on: self-hosted``
and two jobs that merge-key the anchor produces three findings:
one at the anchor body's line, plus one at each merging job's
``<<:`` line.

The pre-Phase-2 RegexPattern form fires once on the anchor body
and misses both effectively-merged jobs.  The structural form
catches all three.  This test pins the line numbers so a future
walker regression that drops the merge-key replay will fail here
even when the file-level audit harness's "fires at least once"
semantics still pass.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


_FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "fixtures"
    / "github"
    / "edge_cases"
    / "runs_on_via_merge_key.yml"
)


@pytest.fixture(scope="module")
def gh_rules():
    return [r for r in load_all_rules() if r.platform == Platform.GITHUB]


def test_sec7_gh_001_fires_on_anchor_and_each_merged_job(gh_rules):
    """Anchor body + two merge-key sites = three findings.

    The fixture's structure pins the line numbers:

      line 8:  ``defaults: &job_defaults``
      line 9:  ``  runs-on: self-hosted``     ← anchor body leaf
      line 12: ``  build:``
      line 13: ``    <<: *job_defaults``      ← merge site 1
      line 16: ``  test:``
      line 17: ``    <<: *job_defaults``      ← merge site 2
    """
    rules = [r for r in gh_rules if r.id == "SEC7-GH-001"]
    findings = scan_file(str(_FIXTURE), rules)
    sec7 = sorted(
        [f for f in findings if f.rule_id == "SEC7-GH-001"],
        key=lambda f: f.line,
    )
    lines = [f.line for f in sec7]
    assert lines == [9, 13, 17], (
        f"Expected SEC7-GH-001 findings at lines 9 (anchor body), "
        f"13 (build merge site), and 17 (test merge site); got {lines}.  "
        "If only line 9 fires, the merge-key replay regressed; if a "
        "different set of lines fires, the fixture or the structural "
        "form's frame depth has shifted."
    )

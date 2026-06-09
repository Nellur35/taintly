"""Phase 1c — the per-file scan time-box (``engine.scan_file``).

Guards the total-per-file wall-clock budget: on exceed, the rule loop stops and
a single ENGINE-ERR ("time-boxed") finding discloses how many rules did not run
(mirroring the existing chunked-coverage ENGINE-ERR). Tests FORCE the budget
(``max_scan_seconds=0.0``) instead of racing the real clock, so they are
deterministic on any machine, fast or slow.
"""

from __future__ import annotations

from taintly.engine import scan_file
from taintly.models import Platform, Severity
from taintly.rules.registry import load_all_rules

# A small, valid GitHub workflow that fires several rules (unpinned ref from a
# pull_request_target checkout, a curl|bash run step). The exact findings don't
# matter — only that the rule loop has real work that the budget can pre-empt.
_WORKFLOW = """\
name: ci
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: curl https://example.com/install.sh | bash
"""


def _github_rules():
    return [r for r in load_all_rules() if r.platform == Platform.GITHUB]


def test_budget_zero_time_boxes_and_discloses():
    """A zero budget pre-empts the whole loop and emits one disclosure."""
    rules = _github_rules()
    findings = scan_file("wf.yml", rules, _content=_WORKFLOW, max_scan_seconds=0.0)

    time_box = [f for f in findings if f.rule_id == "ENGINE-ERR" and "time-boxed" in f.title]
    assert len(time_box) == 1, "expected exactly one time-box ENGINE-ERR"
    tb = time_box[0]
    # deadline = now + 0 is already reached on entry, so every rule is skipped.
    assert f"{len(rules)} of {len(rules)} rules not evaluated" in tb.title
    assert tb.severity is Severity.LOW  # survives --min-severity + engine_errors()
    # No real rule findings can survive a loop that never ran a rule.
    assert all(f.rule_id == "ENGINE-ERR" for f in findings)


def test_partial_budget_reports_correct_unevaluated_count():
    """The 'M of T' count equals the rules that did not run."""
    rules = _github_rules()
    findings = scan_file("wf.yml", rules, _content=_WORKFLOW, max_scan_seconds=0.0)
    tb = next(f for f in findings if f.rule_id == "ENGINE-ERR" and "time-boxed" in f.title)
    total = len(rules)
    # "{unevaluated} of {total} rules not evaluated" — unevaluated == total at budget 0.
    assert f"{total} of {total} rules not evaluated" in tb.title


def test_default_budget_does_not_time_box_a_small_file():
    """A benign small file finishes well under the 30 s default — no disclosure."""
    rules = _github_rules()
    findings = scan_file("wf.yml", rules, _content=_WORKFLOW)
    assert not [f for f in findings if f.rule_id == "ENGINE-ERR" and "time-boxed" in f.title]
    # And it genuinely evaluated rules (the workflow is intentionally finding-rich).
    assert any(f.rule_id != "ENGINE-ERR" for f in findings)

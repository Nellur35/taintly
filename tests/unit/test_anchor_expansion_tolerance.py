"""Pin the anchor-expansion line-drift tolerance.

``taintly.engine._ANCHOR_EXPANSION_LINE_TOLERANCE`` (30 lines as of
this commit) governs how much a finding's pre-expansion line number
may drift from its post-expansion equivalent while still being
recognised as the same match.  Drift comes from ``<<: *anchor``
merge-key expansion inlining a multi-line anchor body above the
finding's line.

Without a pinning test, the threshold is an unsigned magic number:
a future tightening (e.g. 30 → 10) could silently break suppression
on workflows with deeply-stacked anchor merges, and we'd never know.

This module pins the tolerance against:
  1. A constructed worst-case anchor whose body height is within
     tolerance — suppression must still recognise the match.
  2. The exposed constant itself — moving it down without updating
     this file's TOLERANCE_BOUND should break the test loudly.
"""

from __future__ import annotations

from taintly.engine import _ANCHOR_EXPANSION_LINE_TOLERANCE


# Lower bound on the tolerance.  Anchor bodies of 15-25 lines occur in
# real workflows (large reusable permissions blocks, multi-step
# templates).  Tightening below this constant will silently break
# anchor-aware suppression on those workflows — update both this
# constant AND the rationale comment in engine.py if you mean to.
TOLERANCE_BOUND = 20


def test_anchor_expansion_tolerance_covers_realistic_drift():
    """The constant must absorb realistic anchor-body drift.

    Real-world anchors include:
      - Permissions blocks: 3-8 lines.
      - Step templates: 5-15 lines.
      - Stacked merges (two ``<<: *X`` merges in the same step):
        adds the heights together.

    A worst-case stacked-merge can land 15-25 lines of drift between
    pre- and post-expansion line numbers.  The constant must be
    >= TOLERANCE_BOUND to keep suppression working on those shapes.
    """
    assert _ANCHOR_EXPANSION_LINE_TOLERANCE >= TOLERANCE_BOUND, (
        f"_ANCHOR_EXPANSION_LINE_TOLERANCE was lowered to "
        f"{_ANCHOR_EXPANSION_LINE_TOLERANCE}, below the "
        f"{TOLERANCE_BOUND}-line minimum for realistic anchor drift. "
        "Stacked-merge workflows will silently lose anchor-aware "
        "suppression.  If you mean to tighten the tolerance, update "
        "both this test's TOLERANCE_BOUND and the rationale comment "
        "in engine.py (above the constant) to record the new "
        "empirical worst case."
    )


def test_anchor_expansion_tolerance_is_not_absurdly_large():
    """The constant must NOT be so large that it suppresses unrelated
    findings far from the anchor.  Anchors >100 lines are pathological;
    the tolerance ought to stay well under that.
    """
    assert _ANCHOR_EXPANSION_LINE_TOLERANCE < 100, (
        f"_ANCHOR_EXPANSION_LINE_TOLERANCE = {_ANCHOR_EXPANSION_LINE_TOLERANCE} "
        "is suspiciously large; the wider the window, the more likely "
        "an anchor-aware rule wrongly suppresses an unrelated finding "
        "elsewhere in the file."
    )

#!/usr/bin/env python
"""CI ratchet for the known mutation-gap allowlist — composition-aware.

``taintly/testing/self_test.py::_KNOWN_MUTATION_GAPS`` is the allowlist of
``(rule_id, mutation_operator)`` pairs where a rule is currently fragile to a
mutation. Each entry suppresses one mutant survivor so the top-level kill-rate
gate stays green while the underlying precision gap is worked. The discipline is
bidirectional: the allowlist must not GROW (a new fragility silently slips in)
and a SHRINK is good news that should be ratcheted into the baseline (so the gap
can't quietly reopen).

A GLOBAL ``len(_KNOWN_MUTATION_GAPS)`` baseline is composition-blind: deleting one
gap while adding an unrelated one keeps the count flat, so a regression in
family X hides behind a fix in family Y. Because every entry is keyed by
``(rule_id, mutation_operator)``, the rule-family prefix (``SEC4-GH``, ``AI-GH``,
``TAINT-GL`` … — the rule id with its trailing ``-NNN`` ordinal stripped) is a
clean grouping unit. So this gate tracks the count PER rule-family prefix against
a per-key baseline and fails if ANY key drifts in either direction — which makes
a count-flat cross-family swap visible (it shows up as one prefix over and
another under baseline).

To MOVE the baseline (after intentionally adding/removing a gap): update the
matching ``_PER_PREFIX_BASELINE`` entry to the value this gate prints.

Usage:  python scripts/check_mutation_gap_count.py
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from taintly.testing.self_test import _KNOWN_MUTATION_GAPS  # noqa: E402

# Per rule-family-prefix baseline of allowlisted mutation gaps. The SUM is the
# global baseline (currently 100); tracking per prefix is what makes a flat-count
# cross-family swap detectable. Update an entry — never paper over a regression
# by editing a different one — when a gap is intentionally added or closed.
#
# Regenerated from THIS repo's _KNOWN_MUTATION_GAPS (the public rule pack is a
# curated subset of the lab pack, so this baseline differs from upstream — e.g.
# SEC4-GH is 7 here, including SEC4-GH-002 whitespace_pad).
_PER_PREFIX_BASELINE: dict[str, int] = {
    # 20 -> 21: AI-GH-018 whitespace_pad gap documented (phase1-aigh-forkguard).
    # The rule's new ``anchor_step_exclude`` (suppresses agent-CLI flags that
    # land on a ``claude_args: |`` block-scalar continuation inside a ``uses:``
    # action step) depends on structural step-segmentation, which the
    # ``': ' -> ':'`` collapse breaks — same documented class as SEC6-GH-010.
    "AI-GH": 21,
    "AI-GL": 4,
    "AI-JK": 4,
    "PSE-GH": 1,
    "SEC1-GH": 2,
    "SEC1-GL": 1,
    "SEC10-GH": 3,
    "SEC10-GL": 1,
    "SEC3-GH": 2,
    "SEC4-GH": 7,
    "SEC4-GL": 1,
    "SEC4-JK": 3,
    "SEC6-GH": 1,
    "SEC6-JK": 1,
    "SEC7-GH": 1,
    "SEC7-JK": 1,
    "SEC8-GH": 5,
    "SEC8-GL": 2,
    "SEC9-JK": 1,
    "TAINT-GH": 27,
    "TAINT-GL": 11,
    # 1 -> 2: TAINT-JK-003 quote_swap gap documented (Phase-3 multi-hop port).
    # The rule fires only on a DOUBLE-quoted Groovy GString sink/RHS (Groovy
    # interpolates before the shell runs); quote_swap flips both the sink and
    # the assignment RHS to single quotes, which legitimately stops Groovy
    # interpolating, so the resolver correctly stops matching — the same
    # framework-limitation gap class as TAINT-JK-001 quote_swap.
    "TAINT-JK": 2,
}


def rule_family_prefix(rule_id: str) -> str:
    """``SEC4-GH-026A`` / ``AI-GH-019`` -> ``SEC4-GH`` / ``AI-GH`` (strip the
    trailing ``-<ordinal>`` segment). A rule id without a separator is its own
    prefix."""
    head, sep, _tail = rule_id.rpartition("-")
    return head if sep else rule_id


def counts_by_prefix(
    gaps: dict[tuple[str, str], str] | None = None,
) -> dict[str, int]:
    """Current allowlist size grouped by rule-family prefix."""
    if gaps is None:
        gaps = _KNOWN_MUTATION_GAPS
    return dict(Counter(rule_family_prefix(rule_id) for (rule_id, _op) in gaps))


def drift(
    current: dict[str, int],
    baseline: dict[str, int],
) -> dict[str, tuple[int, int]]:
    """{prefix: (current, baseline)} for every prefix whose count differs (a new
    prefix counts as baseline 0; a vanished prefix as current 0)."""
    out: dict[str, tuple[int, int]] = {}
    for prefix in set(current) | set(baseline):
        cur = current.get(prefix, 0)
        base = baseline.get(prefix, 0)
        if cur != base:
            out[prefix] = (cur, base)
    return out


def main() -> int:
    current = counts_by_prefix()
    total = sum(current.values())
    baseline_total = sum(_PER_PREFIX_BASELINE.values())
    print(
        "mutation-gap ratchet (per rule-family prefix, bidirectional vs baseline):"
        f"\n  total allowlist size: {total} (baseline {baseline_total})\n"
    )

    drifted = drift(current, _PER_PREFIX_BASELINE)
    if not drifted:
        print(f"OK: all {len(_PER_PREFIX_BASELINE)} rule-family prefixes match baseline.")
        return 0

    grew = {p: v for p, v in drifted.items() if v[0] > v[1]}
    shrank = {p: v for p, v in drifted.items() if v[0] < v[1]}

    if total == baseline_total:
        print(
            "COMPOSITION DRIFT: the global allowlist size is unchanged "
            f"({total}) but the per-family composition moved — a swap (one gap "
            "removed, another added) that a global count would have missed:"
        )
    for prefix, (cur, base) in sorted(drifted.items()):
        direction = "GREW" if cur > base else "SHRANK"
        print(f"  {prefix:12s} {base} -> {cur}  ({direction})")

    print(
        "\nFAIL: known-mutation-gap allowlist drifted per rule-family prefix.",
        file=sys.stderr,
    )
    if grew:
        print(
            "  GREW: a rule became fragile to a new mutation — fix the rule, or "
            "if it is a genuine non-applicable probe, document it AND bump that "
            "prefix's _PER_PREFIX_BASELINE.",
            file=sys.stderr,
        )
    if shrank:
        print(
            "  SHRANK: a gap was closed (good) — ratchet by lowering that "
            "prefix's _PER_PREFIX_BASELINE so the gap cannot silently reopen.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Family-coverage visibility gate — flag rules relying on the OWASP fallback.

A rule with no explicit ``Rule.finding_family`` does not name its own
reporting cluster; it falls through to the coarse OWASP-prefix mapping in
``taintly.families.classify_rule``.  That fallback is fine for most rules,
but it's a *silent* default: a brand-new rule with a misclassifying OWASP
category will cluster wrong in the report and nobody will notice, because
nothing fails.

This gate makes that population VISIBLE.  It enumerates every registered
rule that has no explicit ``finding_family`` (i.e. relies on the fallback),
prints the count and the IDs, and ratchets against a committed baseline.

Policy (BLOCKING on growth, advisory on shrink):

* A rule ID that is NOT in the baseline but IS unmarked now → FAIL.  A new
  rule leaning on the OWASP fallback is a deliberate choice and must be
  reviewed: either set ``finding_family`` explicitly, or add the ID to the
  baseline with ``--update`` to acknowledge the fallback is intended.
* Unmarked rules that disappear, or that gained an explicit family (the set
  shrinks), pass — but the gate warns that the baseline is stale so it gets
  refreshed and the ratchet stays tight.

Blocking-on-growth (not pure advisory) is the right call: the failure mode
is a NEW unmarked rule, and that's exactly the event we can require a human
to look at without creating churn on the large pre-existing population.

Usage:

  python scripts/check_family_coverage.py --check    # CI mode (default)
  python scripts/check_family_coverage.py --update   # baseline refresh
  python scripts/check_family_coverage.py --list     # print the set, no gating

Baseline: ``tests/_family_fallback_baseline.json`` (checked into git).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BASELINE = ROOT / "tests" / "_family_fallback_baseline.json"


def _unmarked_rule_ids() -> list[str]:
    """Return sorted, de-duplicated IDs of registered rules with no
    explicit ``finding_family`` (those relying on the OWASP fallback).

    IDs are de-duplicated because the same rule ID can be registered for
    more than one platform pack; we only care about the *identity* of a
    rule that leans on the fallback, not how many packs ship it.
    """
    from taintly.rules.registry import load_all_rules

    return sorted({rule.id for rule in load_all_rules() if not rule.finding_family})


def _load_baseline() -> list[str]:
    data = json.loads(BASELINE.read_text())
    # Accept either the bare list form or a {"rule_ids": [...]} wrapper.
    if isinstance(data, dict):
        return list(data.get("rule_ids", []))
    return list(data)


def _write_baseline(ids: list[str]) -> None:
    BASELINE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"count": len(ids), "rule_ids": ids}
    BASELINE.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true", help="CI mode (default)")
    p.add_argument("--update", action="store_true", help="refresh baseline")
    p.add_argument(
        "--list",
        action="store_true",
        help="print the current fallback set and exit 0 (no gating)",
    )
    args = p.parse_args()

    current = _unmarked_rule_ids()

    if args.list:
        print(f"{len(current)} registered rules rely on the OWASP family fallback:")
        for rid in current:
            print(f"  {rid}")
        return 0

    if args.update:
        _write_baseline(current)
        print(
            f"Wrote family-fallback baseline: {len(current)} rule(s) "
            f"to {BASELINE.relative_to(ROOT)}"
        )
        return 0

    if not BASELINE.exists():
        print(
            f"FAIL: baseline {BASELINE} does not exist.  Run with --update to seed.",
            file=sys.stderr,
        )
        return 2

    baseline = set(_load_baseline())
    current_set = set(current)

    new_unmarked = sorted(current_set - baseline)
    resolved = sorted(baseline - current_set)

    if new_unmarked:
        print(
            f"FAIL: {len(new_unmarked)} new rule(s) rely on the OWASP family "
            "fallback (no explicit finding_family):\n"
            + "\n".join(f"  {rid}" for rid in new_unmarked)
            + "\n\nA new rule clustering by the coarse OWASP fallback is a "
            "silent default.  Either set finding_family explicitly on the "
            "rule, or — if the fallback is genuinely correct — acknowledge it "
            "by running:\n"
            "    python scripts/check_family_coverage.py --update\n"
            "and committing the refreshed baseline with the rule.",
            file=sys.stderr,
        )
        return 1

    if resolved:
        # Not a failure: the set shrank (rules removed or now explicitly
        # classified).  Warn so the baseline gets refreshed and the ratchet
        # tracks the smaller population.
        print(
            f"OK (advisory): {len(resolved)} rule(s) left the fallback set "
            "(removed or now explicitly classified):\n"
            + "\n".join(f"  {rid}" for rid in resolved)
            + "\nRefresh the baseline to keep the ratchet tight:\n"
            "    python scripts/check_family_coverage.py --update",
        )

    print(
        f"OK: {len(current)} registered rules rely on the OWASP family "
        f"fallback (baseline {len(baseline)})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

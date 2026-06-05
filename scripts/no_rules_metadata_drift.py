#!/usr/bin/env python3
"""Metadata-drift gate — guard against silent rule-definition changes.

The companion gate ``no_rules_change_gate.py`` hashes what each rule
*fires* on the fixtures.  It does NOT notice when a rule's *definition*
changes without changing its firing: a CRITICAL silently downgraded to
MEDIUM, a remediation rewritten, ``review_needed`` flipped, a title
reworded.  Those are user-facing guarantees, and a silent edit to them
is exactly the kind of drift the firing gate misses.

This gate hashes the meaning-bearing metadata of every rule and fails
when it changes against the committed baseline.  When the change is
intended, regenerate the baseline (``--update``) and commit it with the
rule edit so the diff is reviewed deliberately.

Usage:

  python scripts/no_rules_metadata_drift.py --check    # CI mode (default)
  python scripts/no_rules_metadata_drift.py --update   # baseline refresh

Baseline: ``tests/_rules_metadata_hashes.json`` (checked into git).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BASELINE = ROOT / "tests" / "_rules_metadata_hashes.json"

# Fields that carry a rule's user-facing meaning.  Deliberately EXCLUDES
# ``pattern`` and ``test_positive`` / ``test_negative`` — firing behaviour
# is the firing gate's job; this gate watches the *definition*.
_TRACKED_FIELDS = (
    "title",
    "severity",
    "platform",
    "owasp_cicd",
    "confidence",
    "review_needed",
    "finding_family",
    "remediation",
)


def _rule_metadata(rule) -> dict[str, object]:
    out: dict[str, object] = {}
    for field in _TRACKED_FIELDS:
        val = getattr(rule, field, None)
        # Severity / Platform are enums — use their value for a stable hash.
        out[field] = getattr(val, "value", val)
    return out


def _hash(meta: dict[str, object]) -> str:
    blob = json.dumps(meta, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _scan() -> dict[str, str]:
    from taintly.rules.registry import load_all_rules

    return {rule.id: _hash(_rule_metadata(rule)) for rule in load_all_rules()}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true", help="CI mode (default)")
    p.add_argument("--update", action="store_true", help="refresh baseline")
    args = p.parse_args()

    current = _scan()

    if args.update:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        print(f"Wrote {len(current)} rule-metadata hashes to {BASELINE.relative_to(ROOT)}")
        return 0

    if not BASELINE.exists():
        print(
            f"FAIL: baseline {BASELINE} does not exist.  Run with --update to seed.",
            file=sys.stderr,
        )
        return 2

    expected = json.loads(BASELINE.read_text())
    diffs: list[str] = []
    for rule_id, h in current.items():
        if rule_id not in expected:
            diffs.append(f"  {rule_id}: ADDED (new rule)")
        elif expected[rule_id] != h:
            diffs.append(f"  {rule_id}: METADATA CHANGED")
    for rule_id in expected:
        if rule_id not in current:
            diffs.append(f"  {rule_id}: REMOVED")

    if diffs:
        print(
            "FAIL: rule metadata drifted on these rules:\n"
            + "\n".join(sorted(diffs))
            + "\n\nA rule's title / severity / confidence / review_needed / "
            "remediation / family changing is a user-facing change and must be "
            "reviewed.  Revert it, or run --update if the change is deliberate "
            "and commit the refreshed baseline.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: {len(current)} rule-metadata hashes match baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

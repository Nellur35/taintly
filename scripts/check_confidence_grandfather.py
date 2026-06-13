#!/usr/bin/env python3
"""Confidence grandfather gate — advisory notice for un-validated new rules (P3.6).

``taintly/families.default_confidence`` grandfathers every rule id in
``tests/_confidence_grandfather_baseline.json`` at HIGH confidence and defaults
any OTHER un-overridden rule id to MEDIUM. That means a brand-new rule, added
without an explicit ``confidence=`` and without being added to the baseline,
will surface at MEDIUM until someone validates its precision.

This gate makes that visible. It is **advisory, not blocking** — it never exits
non-zero in ``--check`` mode — so an author who adds a new rule sees a clear
notice telling them the rule defaults to MEDIUM and how to promote it once they
have validated precision:

  * add the rule id to ``tests/_confidence_grandfather_baseline.json`` (via
    ``--update``) to validate-at-HIGH, OR
  * set an explicit ``confidence=`` on the Rule definition.

A rule that already carries an explicit ``confidence=`` is NOT reported — the
author has already made a deliberate confidence call.

Usage:

  python scripts/check_confidence_grandfather.py            # advisory check (default)
  python scripts/check_confidence_grandfather.py --check    # same, explicit
  python scripts/check_confidence_grandfather.py --update   # add current ids to baseline
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BASELINE = ROOT / "tests" / "_confidence_grandfather_baseline.json"


def _load_baseline() -> list[str]:
    if not BASELINE.exists():
        return []
    data = json.loads(BASELINE.read_text(encoding="utf-8"))
    return [str(x) for x in data] if isinstance(data, list) else []


def _registered_ids_without_override() -> list[str]:
    from taintly.families import _CONFIDENCE_OVERRIDES
    from taintly.rules.registry import load_all_rules

    ids = {r.id for r in load_all_rules()}
    return sorted(rid for rid in ids if rid not in _CONFIDENCE_OVERRIDES)


def _unvalidated_new_rules() -> list[str]:
    """Rule ids that default to MEDIUM purely because they are new.

    A rule is reported only when ALL of the following hold:
      * it is not in ``_CONFIDENCE_OVERRIDES`` (no explicit default), and
      * it is not in the grandfather baseline (not validated-at-HIGH), and
      * its Rule definition carries no explicit ``confidence=`` (i.e. it
        relies on the default), so the new-rule MEDIUM default actually bites.
    """
    from taintly.families import _CONFIDENCE_OVERRIDES
    from taintly.models import Rule
    from taintly.rules.registry import load_all_rules

    baseline = set(_load_baseline())
    # The Rule dataclass default for ``confidence`` — a rule still carrying it
    # is relying on the engine default, not making an explicit call.
    default_conf = Rule.__dataclass_fields__["confidence"].default
    out: list[str] = []
    for r in load_all_rules():
        if r.id in _CONFIDENCE_OVERRIDES or r.id in baseline:
            continue
        if r.confidence != default_conf:
            continue  # author set an explicit confidence — deliberate
        out.append(r.id)
    return sorted(set(out))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true", help="advisory check (default)")
    p.add_argument(
        "--update",
        action="store_true",
        help="add all currently-registered un-overridden rule ids to the baseline",
    )
    args = p.parse_args(argv)

    if args.update:
        ids = _registered_ids_without_override()
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(ids, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {len(ids)} validated-at-HIGH rule ids to {BASELINE.relative_to(ROOT)}")
        return 0

    new_rules = _unvalidated_new_rules()
    if new_rules:
        print(
            "NOTICE (advisory): these rule(s) are NEW (not in the confidence "
            "grandfather baseline) and carry no explicit confidence=, so they "
            "default to MEDIUM confidence until validated:\n"
            + "\n".join(f"  {rid}" for rid in new_rules)
            + "\n\nThis is intentional (P3.6): an un-validated detector should "
            "not score at full weight. Once you have validated precision, either "
            "set an explicit confidence= on the Rule, or add the id to the "
            "baseline with:\n"
            "  python scripts/check_confidence_grandfather.py --update\n"
            "(advisory only — this gate does not fail the build.)"
        )
    else:
        print("OK: no un-validated new rules defaulting to MEDIUM.")
    # Advisory: always succeed.
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

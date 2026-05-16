#!/usr/bin/env python3
"""Mutation gap-growth gate.

The mutation kill-rate gate (``--self-test --mutate``) tolerates every
entry in ``taintly.testing.self_test._KNOWN_MUTATION_GAPS`` as a kill,
which is the right policy WHILE a documented rule-engineering gap is
being worked — but it has a soft failure mode: someone can keep the
kill rate at 100% by ADDING a new entry to silence a freshly-broken
rule.

This script catches that. It compares the current allowlist size to a
committed baseline; growth fails the build, shrinkage fails the build
in the opposite direction (telling the maintainer to ratchet the
baseline down on the same PR so the gate stays meaningful).

Same discipline as scripts/check_per_module_coverage.py and the
``_INCIDENT_REF_BASELINE`` gate in
tests/unit/test_rule_pack_consistency.py.
"""

from __future__ import annotations

import sys
from pathlib import Path


# Baseline — current (validated) entry count in _KNOWN_MUTATION_GAPS.
# Lower this number when entries are removed (real fixes); never
# raise it to silence a regression.
#
_BASELINE = 74


def _count_entries() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from taintly.testing.self_test import _KNOWN_MUTATION_GAPS
    return len(_KNOWN_MUTATION_GAPS)


def main() -> int:
    actual = _count_entries()
    if actual > _BASELINE:
        print(
            f"FAIL: _KNOWN_MUTATION_GAPS has grown to {actual} entries "
            f"(baseline {_BASELINE}). Adding an entry silences a "
            f"freshly-broken rule and is forbidden by the discipline "
            f"in self_test.py — fix the rule precision instead.",
            file=sys.stderr,
        )
        return 1
    if actual < _BASELINE:
        print(
            f"FAIL: _KNOWN_MUTATION_GAPS shrank to {actual} entries "
            f"(baseline {_BASELINE}). Lower the _BASELINE constant in "
            f"scripts/check_mutation_gap_count.py to {actual} so the "
            f"gate keeps tracking the new floor.",
            file=sys.stderr,
        )
        return 1
    print(f"OK: _KNOWN_MUTATION_GAPS = {actual} (baseline {_BASELINE})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

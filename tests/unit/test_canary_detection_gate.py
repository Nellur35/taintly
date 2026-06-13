"""The locked-canary detection-regression gate, also enforced in pytest.

This mirrors ``scripts/check_canary_detections.py`` so the detection floor
is checked by the normal test suite too — not only by the dedicated
``e2e-canaries.yml`` job.  If a refactor zeroes a rule family, BOTH the CI
step and a plain ``pytest`` run go red, which is the point: per-rule unit
tests pass in isolation, but these fixtures assert end-to-end recall.

See the script docstring for the threat model and the re-baseline path.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_GATE_PATH = ROOT / "scripts" / "check_canary_detections.py"

# Load the gate script as a module without requiring scripts/ to be a package.
_spec = importlib.util.spec_from_file_location("_canary_gate", _GATE_PATH)
assert _spec is not None
assert _spec.loader is not None
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def test_snapshot_file_exists_and_lists_every_fixture():
    snap = gate._load_snapshot()
    fixtures = snap.get("fixtures", {})
    for fx in gate.FIXTURES:
        assert fx["name"] in fixtures, f"{fx['name']} missing from snapshot"
        assert fixtures[fx["name"]]["expected_rule_ids"], (
            f"{fx['name']} has an empty locked rule-ID set"
        )


@pytest.mark.parametrize("fx", gate.FIXTURES, ids=lambda f: f["name"])
def test_locked_rule_ids_still_fire(fx):
    snap = gate._load_snapshot()
    rec = snap["fixtures"][fx["name"]]
    live_ids, live_total = gate._scan_fixture(fx)

    missing = sorted(set(rec["expected_rule_ids"]) - set(live_ids))
    assert not missing, (
        f"{fx['name']}: locked rule-ID(s) stopped firing: {missing} "
        f"(defends {rec.get('cve')!r}). Live IDs: {live_ids}. "
        f"If intended, re-baseline with "
        f"`python scripts/check_canary_detections.py --update`."
    )

    floor = rec["min_total_findings"]
    assert live_total >= floor, (
        f"{fx['name']}: total findings {live_total} < locked floor {floor}."
    )


def test_gate_check_passes_on_baseline():
    assert gate.cmd_check() == 0

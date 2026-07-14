"""Scan-performance regression gate — methodology testing-domain 5.1.

Guards taintly's real failure mode: a rule/regex change that makes a scan
super-linear on adversarial input (the ReDoS class the ${{-span bounding
fixed). Complements the pattern-level ``test_redos_bounds`` by exercising
the *whole* scan path end-to-end through the CLI (discovery, the 64 KiB
cap, every rule), not just the isolated compiled patterns.

Budget is deliberately GENEROUS, per the methodology's §7.1 warning that a
flaky perf gate is worse than none: a healthy scan of these fixtures runs
in ~1-2s (dominated by interpreter + rule-load cold start); a quadratic
regression multiplies across the N adversarial files into tens of seconds,
so a ~15s ceiling separates "gross regression" from CI noise with wide
margin. This catches a >5x blow-up, not a 10% wobble.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

# Several ${{-heavy blobs whose paired-span patterns went quadratic before
# bounding. Spread across files so a per-file regression compounds into an
# unmistakable signal rather than hiding under cold-start.
_N_ADVERSARIAL = 8
_ADVERSARIAL_WF = (
    "on: [pull_request_target]\n"
    "jobs:\n"
    "  x:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    '      - run: echo "${{ ' + "head_ref " * 4000 + '}}"\n'
)
_NORMAL_WF = (
    "name: ci\n"
    "on: [push]\n"
    "permissions:\n"
    "  contents: read\n"
    "jobs:\n"
    "  b:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "      - run: make test\n"
)

# Wide margin over the healthy ~1-2s; a super-linear regression across 8
# files lands in the tens of seconds.
_ADVERSARIAL_BUDGET_S = 15.0
_NORMAL_BUDGET_S = 10.0


def _scan_seconds(repo: Path) -> float:
    start = time.perf_counter()
    subprocess.run(
        [sys.executable, "-m", "taintly", str(repo)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    return time.perf_counter() - start


def test_adversarial_input_scan_stays_fast(tmp_path: Path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    for i in range(_N_ADVERSARIAL):
        (wf / f"adversarial_{i}.yml").write_text(_ADVERSARIAL_WF, encoding="utf-8")
    dt = _scan_seconds(tmp_path)
    assert dt < _ADVERSARIAL_BUDGET_S, (
        f"scanning {_N_ADVERSARIAL} adversarial ${{{{-blobs took {dt:.1f}s "
        f"(budget {_ADVERSARIAL_BUDGET_S}s) — a super-linear regex regression? "
        "See test_redos_bounds for the pattern-level guard."
    )


def test_normal_workflow_scan_is_quick(tmp_path: Path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(_NORMAL_WF, encoding="utf-8")
    dt = _scan_seconds(tmp_path)
    assert dt < _NORMAL_BUDGET_S, (
        f"scanning one ordinary workflow took {dt:.1f}s (budget {_NORMAL_BUDGET_S}s) "
        "— unexpected slowdown in the common path."
    )

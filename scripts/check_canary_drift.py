#!/usr/bin/env python3
"""Drift guard for the LIVE external-repo canaries (review P1.4 / P3.5, secondary).

The locked-fixture gate (``check_canary_detections.py``) is the reliable
detection-regression barrier.  This is the secondary, coarser net over the
three live external canaries (astral-sh/uv, gitlab-org/gitlab-runner,
jenkinsci/plugin-installation-manager-tool) that ``e2e-canaries.yml``
clones at pinned SHAs.  Rule-IDs on whole real-world repos are too churny
to lock; total finding count is not.  A refactor that halves — or zeroes —
the findings on a real repo is a recall regression even when every unit
test passes, so this fails the build on a large drop.

Baseline lives in ``.github/canary-baselines/<canary>.json`` as::

    {"canary": "astral-sh/uv", "sha": "<pinned>", "findings": <int>}

A ``findings`` value of ``null`` means "not yet baselined": the check
emits a notice and does NOT fail (so the gate can be merged before the
first green CI run establishes real numbers).  Once a real integer is
committed, drift is enforced.

Contract (when baselined):
  * live count == 0           -> FAIL (canary went completely dark).
  * live count < floor        -> FAIL, where floor = baseline * (1 - TOL).
  * live count >= floor       -> OK (growth is never a failure).

Re-baseline after an intentional change (or a canary SHA bump):
    python scripts/check_canary_drift.py --update --canary astral-sh/uv \
        --sha <SHA> --findings <N>
  or just edit the JSON and commit it.

Usage (CI):
    python scripts/check_canary_drift.py --canary "$CANARY_NAME" \
        --sha "$CANARY_SHA" --count-file canary.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE_DIR = ROOT / ".github" / "canary-baselines"

# Allowed downward drift before the gate fails.  0.20 == a >20% drop fails.
DRIFT_TOLERANCE = 0.20


def _baseline_path(canary: str) -> Path:
    # "astral-sh/uv" -> "astral-sh__uv.json"; filesystem-safe, reversible.
    return BASELINE_DIR / (canary.replace("/", "__") + ".json")


def _load_baseline(canary: str) -> dict | None:
    p = _baseline_path(canary)
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def _write_baseline(canary: str, sha: str, findings: int | None) -> Path:
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    p = _baseline_path(canary)
    p.write_text(
        json.dumps(
            {"canary": canary, "sha": sha, "findings": findings},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return p


def _count_findings(count_file: Path) -> int:
    data = json.loads(count_file.read_text(encoding="utf-8"))
    # ``--platform <p>`` emits a single report object; bare scans wrap a
    # list under "reports".  Handle both so the script is robust to either.
    if isinstance(data, dict) and "reports" in data:
        return sum(len(r.get("findings", [])) for r in data["reports"])
    return len(data.get("findings", []))


def cmd_update(args: argparse.Namespace) -> int:
    findings = args.findings
    if findings is None and args.count_file:
        findings = _count_findings(Path(args.count_file))
    p = _write_baseline(args.canary, args.sha or "", findings)
    print(f"wrote baseline: {p} (findings={findings})")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    baseline = _load_baseline(args.canary)
    live = _count_findings(Path(args.count_file))

    if baseline is None:
        # No baseline file at all — emit a GitHub Actions notice but do not
        # fail; the locked-fixture gate is the hard barrier.
        print(
            f"::notice::canary drift: no baseline for {args.canary}; "
            f"live={live}. Seed it with --update to start enforcing."
        )
        return 0

    expected = baseline.get("findings")
    sha = baseline.get("sha", "")
    if args.sha and sha and args.sha != sha:
        print(
            f"::warning::canary drift: scanned SHA {args.sha[:7]} != baseline "
            f"SHA {sha[:7]} for {args.canary}; re-baseline with --update."
        )

    if expected is None:
        print(
            f"::notice::canary drift: {args.canary} not yet baselined "
            f"(findings=null); live={live}. Commit a real count to enforce."
        )
        return 0

    if live == 0:
        print(
            f"::error::canary drift: {args.canary} produced 0 findings "
            f"(baseline {expected}) — the scanner went dark on this repo.",
            file=sys.stderr,
        )
        return 1

    floor = int(expected * (1.0 - DRIFT_TOLERANCE))
    if live < floor:
        pct = 100.0 * (expected - live) / expected if expected else 0.0
        print(
            f"::error::canary drift: {args.canary} findings dropped "
            f"{expected} -> {live} ({pct:.0f}% below baseline; floor {floor}). "
            f"If intended, re-baseline with --update.",
            file=sys.stderr,
        )
        return 1

    print(
        f"::notice::canary drift OK: {args.canary} live={live} "
        f"(baseline {expected}, floor {floor})."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--canary", required=True, help="canary name, e.g. astral-sh/uv")
    ap.add_argument("--sha", default="", help="scanned pinned SHA (for drift warning)")
    ap.add_argument(
        "--count-file",
        help="taintly --format json output to count findings from",
    )
    ap.add_argument(
        "--findings",
        type=int,
        default=None,
        help="explicit finding count (for --update)",
    )
    ap.add_argument(
        "--update",
        action="store_true",
        help="write/refresh the baseline instead of checking it",
    )
    args = ap.parse_args(argv)

    if args.update:
        return cmd_update(args)
    if not args.count_file:
        ap.error("--count-file is required in check mode")
    return cmd_check(args)


if __name__ == "__main__":
    raise SystemExit(main())

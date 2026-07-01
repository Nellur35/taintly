#!/usr/bin/env python3
"""Detection-regression canary gate (review findings P1.4 / P3.5).

THE THREAT this closes: a parser or engine refactor silently zeroes a
whole rule family.  Every per-rule unit test still passes in isolation
(they call the rule's pattern directly), the in-repo corpus is author-
uniform, and recall on real-world configs quietly drops to zero with no
CI signal.  This gate is the deterministic floor under recall.

HOW it works.  ``tests/canaries/`` holds a handful of committed, public-
safe VULNERABLE CI configs, each reconstructed from a public CVE /
advisory shape and placed at its real repo-relative path
(``.github/workflows/*.yml`` / ``.gitlab-ci.yml`` / ``Jenkinsfile``) so
the gate exercises the SAME end-to-end discovery + scan + post-processor
path the shipped CLI uses — not a narrow
internal API a refactor could bypass.  ``expected_detections.json`` locks,
per fixture, the set of rule-IDs that MUST fire and a floor on the total
finding count.

The contract is intentionally asymmetric:

  * A locked rule-ID that STOPS firing  -> FAIL.  This is the regression
    we are guarding against (a family went dark).
  * The total finding count dropping below the recorded floor -> FAIL.
  * NEW rule-IDs appearing, or extra findings -> OK.  Tightening a rule
    or adding detections is not a regression, so the gate must not punish
    it.  (Re-baseline with ``--update`` if you want the new IDs locked.)

Re-baseline path (after an intentional detection change):
    python scripts/check_canary_detections.py --update
    # then eyeball the diff in tests/canaries/expected_detections.json and
    # commit it WITH the change that moved the detections.

Usage:
    python scripts/check_canary_detections.py            # CI mode (exit 1 on regression)
    python scripts/check_canary_detections.py --update   # regenerate the snapshot
    python scripts/check_canary_detections.py --show      # print live detections, don't gate
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CANARY_DIR = ROOT / "tests" / "canaries"
SNAPSHOT = CANARY_DIR / "expected_detections.json"

# The locked fixtures.  ``dir`` is the canary repo root (relative to
# CANARY_DIR); ``platform`` is the taintly platform to scan it as.  Adding
# a fixture here + running ``--update`` is all it takes to lock a new one.
FIXTURES: list[dict[str, str]] = [
    {
        "name": "github_tj_actions_changed_files",
        "dir": "github_tj_actions_changed_files",
        "platform": "github",
        "cve": "CVE-2025-30066 (tj-actions/changed-files compromise)",
    },
    {
        "name": "github_pwn_request_script_injection",
        "dir": "github_pwn_request_script_injection",
        "platform": "github",
        "cve": "Pwn Request class (pull_request_target + privileged checkout + script injection)",
    },
    {
        "name": "gitlab_cache_poison_mr",
        "dir": "gitlab_cache_poison_mr",
        "platform": "gitlab",
        "cve": "GitLab cache-poisoning class (static cross-boundary cache key in MR pipeline)",
    },
    {
        "name": "jenkins_scm_injection",
        "dir": "jenkins_scm_injection",
        "platform": "jenkins",
        "cve": "Jenkins SCM/param script-injection + LOTP class",
    },
]


def _scan_fixture(fixture: dict[str, str]) -> tuple[list[str], int]:
    """Scan one canary fixture; return (sorted distinct rule-IDs, total findings).

    Uses the public ``scan_repo`` entry point with the full rule pack so a
    regression anywhere in discovery / parsing / rule-loading / post-
    processing surfaces here exactly as it would for a real user.
    """
    from taintly.engine import scan_repo
    from taintly.models import Platform
    from taintly.rules.registry import load_all_rules

    repo = CANARY_DIR / fixture["dir"]
    if not repo.is_dir():
        raise SystemExit(f"canary fixture dir missing: {repo}")

    platform = Platform(fixture["platform"])
    reports = scan_repo(str(repo), load_all_rules(), platform=platform)
    report = next((r for r in reports if r.platform == platform.value), None)
    if report is None:
        return [], 0

    findings = list(report.findings)
    rule_ids = sorted({f.rule_id for f in findings})
    return rule_ids, len(findings)


def _build_snapshot() -> dict:
    fixtures = {}
    for fx in FIXTURES:
        rule_ids, total = _scan_fixture(fx)
        if not rule_ids:
            raise SystemExit(
                f"canary '{fx['name']}' produced NO findings — refusing to "
                f"snapshot an empty detection set (broken fixture or engine)."
            )
        fixtures[fx["name"]] = {
            "platform": fx["platform"],
            "dir": fx["dir"],
            "cve": fx["cve"],
            # Every rule-ID that fires is LOCKED: if any of these stops
            # firing the gate fails.  Extra/new IDs at check time are fine.
            "expected_rule_ids": rule_ids,
            # Floor on total findings; catches "engine returns almost
            # nothing" even if (improbably) the same IDs still appear once.
            "min_total_findings": total,
        }
    return {
        "_comment": (
            "LOCKED detection snapshot for the canary gate. Regenerate with "
            "`python scripts/check_canary_detections.py --update` ONLY when a "
            "detection change is intended, and commit the diff alongside it."
        ),
        "fixtures": fixtures,
    }


def _load_snapshot() -> dict:
    if not SNAPSHOT.is_file():
        raise SystemExit(
            f"snapshot missing: {SNAPSHOT}\n"
            f"create it with: python scripts/check_canary_detections.py --update"
        )
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


def _write_snapshot(snap: dict) -> None:
    SNAPSHOT.write_text(
        json.dumps(snap, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def cmd_update() -> int:
    snap = _build_snapshot()
    _write_snapshot(snap)
    print(f"wrote snapshot: {SNAPSHOT}")
    for name, rec in snap["fixtures"].items():
        print(
            f"  {name} [{rec['platform']}]: "
            f"{len(rec['expected_rule_ids'])} rule-IDs, "
            f"{rec['min_total_findings']} findings"
        )
        print(f"    locked: {', '.join(rec['expected_rule_ids'])}")
    return 0


def cmd_show() -> int:
    for fx in FIXTURES:
        rule_ids, total = _scan_fixture(fx)
        print(f"{fx['name']} [{fx['platform']}]: {total} findings")
        print(f"  rule-IDs: {', '.join(rule_ids) if rule_ids else '(none)'}")
    return 0


def cmd_check() -> int:
    snap = _load_snapshot()
    expected_fixtures = snap.get("fixtures", {})
    failures: list[str] = []

    # A fixture configured in FIXTURES but absent from the snapshot is a
    # mistake (someone added a fixture without re-baselining).
    for fx in FIXTURES:
        if fx["name"] not in expected_fixtures:
            failures.append(
                f"{fx['name']}: present in FIXTURES but not in the snapshot — "
                f"run --update to lock it."
            )

    for name, rec in expected_fixtures.items():
        fx = next((f for f in FIXTURES if f["name"] == name), None)
        if fx is None:
            failures.append(
                f"{name}: in the snapshot but not in FIXTURES — remove the "
                f"snapshot entry or restore the fixture config."
            )
            continue

        live_ids, live_total = _scan_fixture(fx)
        expected_ids = set(rec.get("expected_rule_ids", []))
        missing = sorted(expected_ids - set(live_ids))
        if missing:
            failures.append(
                f"{name} [{rec['platform']}]: locked rule-ID(s) STOPPED firing: "
                f"{', '.join(missing)}\n"
                f"    (these defend the {rec.get('cve', 'canary')} shape — a "
                f"family likely went dark)"
            )

        floor = rec.get("min_total_findings", 0)
        if live_total < floor:
            failures.append(
                f"{name} [{rec['platform']}]: total findings dropped "
                f"{floor} -> {live_total} (below locked floor)."
            )

    if failures:
        print(
            "FAIL: detection regression on locked canaries (review P1.4/P3.5):",
            file=sys.stderr,
        )
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print(
            "\nIf this detection change is INTENDED, re-baseline with\n"
            "  python scripts/check_canary_detections.py --update\n"
            "and commit the snapshot diff alongside the change.",
            file=sys.stderr,
        )
        return 1

    n = len(expected_fixtures)
    print(f"OK: all {n} locked canaries still detect their expected rule-IDs.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group()
    g.add_argument(
        "--update", action="store_true", help="regenerate the locked snapshot"
    )
    g.add_argument(
        "--show", action="store_true", help="print live detections without gating"
    )
    args = ap.parse_args(argv)

    if args.update:
        return cmd_update()
    if args.show:
        return cmd_show()
    return cmd_check()


if __name__ == "__main__":
    raise SystemExit(main())

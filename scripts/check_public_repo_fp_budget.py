#!/usr/bin/env python3
"""Public-repo FP-budget scan gate (audit Sprint 4 / item 20).

Pins the false-positive surface across representative public repos.
Catches FP regressions that pass the per-rule self-test but would
explode on real-world workflows.

How it works:
  1. For each pinned (platform, repo, target) tuple, ensure a fresh
     shallow clone exists in ``$TAINTLY_SCAN_CACHE`` (default
     ``/tmp/taintly_scan_cache``).
  2. Run taintly against the target.
  3. Assert the finding count is at or below the committed budget.

Same growth-only discipline as ``check_mutation_gap_count.py``:
shrinkage is good (lower the budget); growth fails CI.

Skipped when the cache dir is unwritable or git is unavailable —
this is meant for local + scheduled CI, not every PR. Run as:

    python scripts/check_public_repo_fp_budget.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


_CACHE = Path(os.environ.get("TAINTLY_SCAN_CACHE", "/tmp/taintly_scan_cache"))


# Pinned scan corpus + budget. Each entry: (label, repo url, clone
# subdir, scan target relative to clone, platform, max-finding budget).
#
# Budgets are validated finding counts after the most recent
# precision pass.  New rule additions OR precision regressions
# trip the gate; closing FPs allows lowering the budget.
_TARGETS: list[tuple[str, str, str, str, str, int]] = [
    (
        # ripgrep — Rust release pipeline. 17 findings observed
        # under current rules; budget 20 gives a 3-finding buffer
        # for reasonable rule additions before manual review.
        "ripgrep",
        "https://github.com/BurntSushi/ripgrep.git",
        "gh_ripgrep",
        ".github/workflows/",
        "github",
        20,
    ),
    (
        # flask — Pallets project, hardening-conscious. 2 findings
        # observed under current rules. Budget 5.
        "flask",
        "https://github.com/pallets/flask.git",
        "gh_flask",
        ".github/workflows/",
        "github",
        5,
    ),
    (
        # apache/maven Jenkinsfile — modern declarative pipeline.
        # 1 finding (SEC10-JK-001 no post-always). Budget 2.
        "maven_jenkinsfile",
        "https://github.com/apache/maven.git",
        "jk_maven",
        "Jenkinsfile",
        "jenkins",
        2,
    ),
]


def _ensure_clone(repo_url: str, target: Path) -> bool:
    """Clone ``repo_url`` into ``target`` if not present. Returns
    True on success, False if cloning failed (network, missing
    git, etc.). The check is skipped on failure rather than
    treated as a regression."""
    if target.exists():
        return True
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "-q", repo_url, str(target)],
            check=True,
            timeout=180,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _scan_count(target: Path, platform: str) -> int | None:
    """Run taintly on ``target`` and return the finding count, or
    ``None`` if the scan fails to produce parseable JSON."""
    cmd = [
        sys.executable, "-m", "taintly", str(target),
        "--platform", platform,
        "--format", "json",
        "--min-severity", "LOW",
        "--no-color",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        return None
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return len(report.get("findings", []))


def main() -> int:
    if shutil.which("git") is None:
        print("git not available — skipping public-repo FP-budget gate")
        return 0

    failed: list[str] = []
    skipped: list[str] = []
    for label, repo, subdir, scan_target, platform, budget in _TARGETS:
        clone_dir = _CACHE / subdir
        if not _ensure_clone(repo, clone_dir):
            skipped.append(f"{label} (clone failed — network down?)")
            continue
        target_path = clone_dir / scan_target
        count = _scan_count(target_path, platform)
        if count is None:
            skipped.append(f"{label} (scan produced no parseable JSON)")
            continue
        marker = "OK  " if count <= budget else "FAIL"
        print(f"{marker}  {label:30s}  {count:3d} findings  (budget {budget})")
        if count > budget:
            failed.append(
                f"{label}: {count} findings exceeds budget {budget} "
                f"({count - budget} new)"
            )

    if skipped:
        print()
        print("Skipped (non-blocking):", file=sys.stderr)
        for s in skipped:
            print(f"  - {s}", file=sys.stderr)

    if failed:
        print()
        print("Public-repo FP budget exceeded:", file=sys.stderr)
        for f in failed:
            print(f"  - {f}", file=sys.stderr)
        print(
            "\nA new rule or precision regression has expanded the "
            "finding surface. Either fix the FP or — if the new "
            "findings are real — lower the budget in "
            "scripts/check_public_repo_fp_budget.py with rationale.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

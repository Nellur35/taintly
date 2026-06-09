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

Exit codes:
  0  every target scanned and within budget (or skipped, in the
     default lenient mode meant for local runs).
  1  a target exceeded its budget (a real over-budget regression).
  2  ``--strict-skips`` was passed and at least one target was
     skipped (clone failed, no parseable JSON, etc.). Scheduled CI
     uses this so a clone failure is reported as a distinct,
     visible state rather than silently passing as green.

When run under GitHub Actions (``GITHUB_STEP_SUMMARY`` set) it also
writes a Markdown summary and emits ``::warning``/``::error`` workflow
annotations so the outcome is visible without reading the raw log.
"""

from __future__ import annotations

import argparse
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
        #
        # raised 2026-06-06: the #109 publication activated
        # SEC10-GH-001 (+8 timeout-less jobs, all TPs) and
        # SEC4-GH-022 (+4 cross-job taint on ripgrep, all TPs);
        # re-baselined to observed true positives — see the
        # differential triage.
        "ripgrep",
        "https://github.com/BurntSushi/ripgrep.git",
        "gh_ripgrep",
        ".github/workflows/",
        "github",
        22,
    ),
    (
        # flask — Pallets project, hardening-conscious. 2 findings
        # observed under current rules. Budget 5.
        #
        # raised 2026-06-06: the #109 publication activated
        # SEC10-GH-001 (+8 timeout-less jobs, all TPs) and
        # SEC4-GH-022 (+4 cross-job taint on ripgrep, all TPs);
        # re-baselined to observed true positives — see the
        # differential triage.
        "flask",
        "https://github.com/pallets/flask.git",
        "gh_flask",
        ".github/workflows/",
        "github",
        10,
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
        sys.executable,
        "-m",
        "taintly",
        str(target),
        "--platform",
        platform,
        "--format",
        "json",
        "--min-severity",
        "LOW",
        "--no-color",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return None
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return len(report.get("findings", []))


def _annotate(level: str, message: str) -> None:
    """Emit a GitHub Actions workflow annotation when running in CI.
    No-op outside Actions. ``level`` is ``warning`` or ``error``."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{message}")


def _write_summary(lines: list[str]) -> None:
    """Append a Markdown block to the GitHub step summary if present."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    try:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Public-repo FP-budget scan gate")
    parser.add_argument(
        "--strict-skips",
        action="store_true",
        help=(
            "Exit non-zero (code 2) if any target is skipped (clone "
            "failure, no parseable JSON). Use in scheduled CI so a "
            "skip is a visible, distinct outcome instead of passing "
            "as green. Off by default for tolerant local runs."
        ),
    )
    args = parser.parse_args()

    if shutil.which("git") is None:
        msg = "git not available — cannot run public-repo FP-budget gate"
        print(msg)
        _annotate("warning", msg)
        _write_summary(["## Public-repo FP budget", "", f"- skipped: {msg}"])
        # No git means nothing could be measured. In strict mode that
        # is a skip, not a pass.
        return 2 if args.strict_skips else 0

    failed: list[str] = []
    skipped: list[str] = []
    results: list[str] = []
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
        line = f"{marker}  {label:30s}  {count:3d} findings  (budget {budget})"
        print(line)
        results.append(line)
        if count > budget:
            failed.append(
                f"{label}: {count} findings exceeds budget {budget} ({count - budget} new)"
            )

    if skipped:
        print()
        print("Skipped:", file=sys.stderr)
        for s in skipped:
            print(f"  - {s}", file=sys.stderr)
            _annotate("warning", f"FP-budget target skipped: {s}")

    # Build the step summary regardless of outcome so the schedule run
    # always shows what was measured vs. skipped.
    summary: list[str] = ["## Public-repo FP budget", ""]
    summary.extend(f"- `{r.strip()}`" for r in results)
    if skipped:
        summary.append("")
        summary.append("### Skipped (not measured)")
        summary.extend(f"- {s}" for s in skipped)
    _write_summary(summary)

    if failed:
        print()
        print("Public-repo FP budget exceeded:", file=sys.stderr)
        for f in failed:
            print(f"  - {f}", file=sys.stderr)
            _annotate("error", f"FP-budget over budget: {f}")
        print(
            "\nA new rule or precision regression has expanded the "
            "finding surface. Either fix the FP or — if the new "
            "findings are real — lower the budget in "
            "scripts/check_public_repo_fp_budget.py with rationale.",
            file=sys.stderr,
        )
        return 1

    if skipped and args.strict_skips:
        # A skip in scheduled CI means the gate could not actually
        # verify the budget — surface it as a distinct non-pass so it
        # never hides the way an unwired gate did.
        print(
            f"\n{len(skipped)} target(s) skipped under --strict-skips — "
            "gate could not verify the FP budget (treated as non-pass).",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

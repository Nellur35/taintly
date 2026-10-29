#!/usr/bin/env python3
"""Public-repo FP-budget scan gate (audit Sprint 4 / item 20).

Pins the source revision and reviewed finding surface across representative
public repos. A finding count is a regression signal, not an accuracy metric.
Catches FP regressions that pass the per-rule self-test but would
explode on real-world workflows.

How it works:
  1. For each pinned (platform, repo, revision, target) tuple, ensure a
     checkout of that exact revision exists in ``$TAINTLY_SCAN_CACHE`` (default
     ``/tmp/taintly_scan_cache``).
  2. Run taintly against the target.
  3. Assert the reviewed per-rule or total ceiling for that target.

The ceiling controls regression review; a pass does not validate the security
meaning of each finding. Shrinkage is good after adjudication.

Skipped when the cache dir is unwritable or git is unavailable —
this is meant for local + scheduled CI, not every PR. Run as:

    python scripts/check_public_repo_fp_budget.py

Exit codes:
  0  every target scanned and within budget (or skipped, in the
     default lenient mode meant for local runs).
  1  a target exceeded its reviewed finding ceiling.
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


# Pinned scan corpus. Each entry: (label, repo URL, immutable commit, clone
# subdir, scan target relative to clone, platform, per-rule ceilings).
#
# The ripgrep ceilings describe reviewed observations on the Oct 23, 2026
# source revision, not 31 verified vulnerabilities. See the independent
# finding-by-finding triage in the field proof record. New rule IDs and growth
# within a rule both require review. Lower ceilings only after adjudication.
_TARGETS: list[tuple[str, str, str, str, str, str, dict[str, int] | int]] = [
    (
        "ripgrep",
        "https://github.com/BurntSushi/ripgrep.git",
        "6892bc2b7efe5909cbbeec8f757ed2c4c76b1d30",
        "gh_ripgrep",
        ".github/workflows/",
        "github",
        {
            "SEC10-GH-001": 9,  # timeout absence; hardening
            "SEC3-GH-002": 8,  # same mutable action branch at eight sites
            "SEC4-GH-022": 4,  # output-to-shell review; ancestry uncertain
            "SEC2-GH-005": 3,  # workflow-wide permissions
            "SEC1-GH-002": 3,  # draft release mutation; environment review
            "SEC9-GH-001": 2,  # unverified incoming archive
            "SEC3-GH-001": 1,  # action tag
            "SEC10-GH-002": 1,  # build output retention review
        },
    ),
    (
        # flask — the pinned workflow currently produces 10 findings.
        # This is a reviewed regression ceiling, not a count of verified
        # vulnerabilities or an accuracy measurement.
        "flask",
        "https://github.com/pallets/flask.git",
        "d086db856be187255b8ec61ef409357393020f32",
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
        "e4b9ca120a7f67c39e5e320b5ebb34327229e8c9",
        "jk_maven",
        "Jenkinsfile",
        "jenkins",
        2,
    ),
]


def _git_output(target: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(target), *args],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None
    return result.stdout.strip()


def _ensure_clone(repo_url: str, revision: str, target: Path, scan_target: str) -> str | None:
    """Return an error on a missing/mismatched checkout; never scan a moving ref.

    A bad existing cache is left intact for inspection. Fresh fetches select an
    immutable commit rather than the repository's current default branch.
    """
    if target.exists():
        actual_repo = _git_output(target, "remote", "get-url", "origin")
        actual_revision = _git_output(target, "rev-parse", "HEAD")
        dirty = _git_output(target, "status", "--porcelain")
        if (actual_repo, actual_revision, dirty) != (repo_url, revision, "") or not (
            target / scan_target
        ).exists():
            return f"cache identity mismatch (wanted {revision}; got {actual_revision})"
        return None
    target.mkdir(parents=True, exist_ok=False)
    for args, timeout in (
        (("init", "-q"), 30),
        (("remote", "add", "origin", repo_url), 30),
        (("fetch", "--depth", "1", "origin", revision), 180),
        # Only the scan subject is needed. Full Maven checkout exceeds the
        # Windows path limit in unrelated test resources.
        (("sparse-checkout", "set", "--no-cone", "--", scan_target), 30),
        (("checkout", "--detach", "-q", "FETCH_HEAD"), 60),
    ):
        try:
            subprocess.run(["git", "-C", str(target), *args], check=True, timeout=timeout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            return f"failed to obtain pinned revision {revision}"
    return _ensure_clone(repo_url, revision, target, scan_target)


def _scan_counts(target: Path, platform: str) -> dict[str, int] | None:
    """Run taintly on ``target`` and return counts by rule ID, or
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
    findings = report.get("findings")
    if not isinstance(findings, list) or report.get("engine_error_count"):
        return None
    counts: dict[str, int] = {}
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(finding.get("rule_id"), str):
            return None
        rule_id = finding["rule_id"]
        counts[rule_id] = counts.get(rule_id, 0) + 1
    return counts


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
    for label, repo, revision, subdir, scan_target, platform, budget in _TARGETS:
        clone_dir = _CACHE / subdir
        clone_error = _ensure_clone(repo, revision, clone_dir, scan_target)
        if clone_error:
            skipped.append(f"{label} ({clone_error})")
            continue
        target_path = clone_dir / scan_target
        counts = _scan_counts(target_path, platform)
        if counts is None:
            skipped.append(f"{label} (scan produced no parseable JSON)")
            continue
        ceiling = budget if isinstance(budget, dict) else dict.fromkeys(counts, budget)
        excess = {
            rule: (count, ceiling.get(rule, 0))
            for rule, count in counts.items()
            if count > ceiling.get(rule, 0)
        }
        if isinstance(budget, int) and sum(counts.values()) > budget:
            excess["total"] = (sum(counts.values()), budget)
        marker = "FAIL" if excess else "OK  "
        line = (
            f"{marker}  {label:30s}  {sum(counts.values()):3d} findings "
            f"at {revision[:12]} (reviewed ceiling {sum(ceiling.values()) if isinstance(budget, dict) else budget})"
        )
        print(line)
        results.append(line)
        for rule, (count, limit) in sorted(excess.items()):
            failed.append(f"{label} {rule}: {count} findings exceeds reviewed ceiling {limit}")

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
            "finding surface on pinned source. Review the new path before "
            "changing a ceiling; finding counts do not establish accuracy.",
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

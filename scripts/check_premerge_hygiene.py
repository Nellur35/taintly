#!/usr/bin/env python3
"""Pre-merge hygiene check: flag AI-assistant artifacts in changes.

Scans the diff between the merge base with ``origin/main`` and the
current HEAD for marker words that typically leak from AI-assisted
authoring tools (``Co-authored-by: Claude``, ``claude.ai/code``
session URLs, etc.).  Also scans every commit's subject and body in
the same range so squash-merge bodies don't accidentally carry the
trailers either.

The check is content-level, not metadata-level: it cares whether the
strings appear in committed text, not whether the commit was
mechanically produced by an AI.  Maintainers running the AI-assisted
workflow scrub these artifacts before pushing; the script is the
backstop.

The allowlist below names files whose subject IS AI assistance.  In
those files the marker words are the topic, not contamination, and
the regex would otherwise false-positive on every line.

Usage:

    python scripts/check_premerge_hygiene.py
    python scripts/check_premerge_hygiene.py --base origin/main

Exit codes:
    0 — no markers found in non-allowlisted lines or commit messages.
    1 — markers found; the script prints each hit and exits non-zero.
    2 — git invocation failed (not a repo, base ref doesn't exist,
        etc.); investigate before treating as a clean check.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Files whose subject is AI assistance.  Marker words inside these
# files are the topic, not contamination, so they're skipped by the
# diff scanner.  Add a one-line comment for each entry recording why
# it's allowlisted.
ALLOWLISTED_PATHS: dict[str, str] = {
    # doc whose subject is AI assistance — marker words are the topic, not contamination
    "docs/AI_TRIAGE.md": "doc whose subject is AI assistance",
    # decision file naming agent vendors by example for the "do not endorse" point
    "docs/decisions/ai-assisted-triage-pointer.md": "decision file naming systems by example",
    # this script itself defines the marker regex, so its source contains the markers
    "scripts/check_premerge_hygiene.py": "script source defines the marker regex",
}

# Marker words that typically leak from AI-assisted authoring.  Kept
# narrow on purpose: the goal is artifact detection, not surveillance
# of every mention of "AI" in the codebase.  Each pattern is a
# substring anchored on a recognisable AI-tooling shape.
_MARKER_PATTERNS = [
    re.compile(r"Co-authored-by:\s*Claude", re.IGNORECASE),
    re.compile(r"claude\.ai/code/session_", re.IGNORECASE),
    re.compile(r"Generated[- ]by[- ]Claude", re.IGNORECASE),
    re.compile(r"<assistant>|</assistant>"),
    re.compile(
        r"\bAI[- ]assistant\b(?!\s+(?:findings|triage|prompt|recalibration))", re.IGNORECASE
    ),
]


def _run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(f"git {' '.join(args)} failed: {result.stderr}")
        sys.exit(2)
    return result.stdout


def _changed_files(base: str) -> list[str]:
    out = _run_git(["diff", "--name-only", f"{base}...HEAD"])
    return [line for line in out.splitlines() if line.strip()]


def _diff_for_file(base: str, path: str) -> str:
    return _run_git(["diff", f"{base}...HEAD", "--", path])


def _commit_messages(base: str) -> str:
    return _run_git(["log", "--format=%B%n----COMMIT----", f"{base}..HEAD"])


def _scan_text(text: str, source: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for line in text.splitlines():
        for pattern in _MARKER_PATTERNS:
            if pattern.search(line):
                hits.append((source, line.strip()))
                break
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base",
        default="origin/main",
        help="Ref to compare against (default: origin/main).",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    if not (repo_root / ".git").exists():
        sys.stderr.write("not a git repository\n")
        return 2

    hits: list[tuple[str, str]] = []

    for path in _changed_files(args.base):
        if path in ALLOWLISTED_PATHS:
            continue
        diff = _diff_for_file(args.base, path)
        added = "\n".join(
            line[1:]
            for line in diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        hits.extend(_scan_text(added, f"diff:{path}"))

    hits.extend(_scan_text(_commit_messages(args.base), "commit-message"))

    if not hits:
        print(f"premerge hygiene: clean against {args.base}")
        return 0

    print(f"premerge hygiene: {len(hits)} marker hit(s) against {args.base}")
    for source, line in hits:
        print(f"  {source}: {line}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

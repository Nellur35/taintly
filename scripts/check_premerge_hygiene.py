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
from dataclasses import dataclass
from pathlib import Path

# Files whose subject is AI assistance.  Marker words inside these
# files are the topic, not contamination, so they're skipped by the
# diff scanner.  Add a one-line comment for each entry recording why
# it's allowlisted.
ALLOWLISTED_PATHS: dict[str, str] = {
    # doc whose subject is AI assistance — marker words are the topic, not contamination
    "docs/AI_TRIAGE.md": "doc whose subject is AI assistance",
    # this script itself defines the marker regex, so its source contains the markers
    "scripts/check_premerge_hygiene.py": "script source defines the marker regex",
    # tests for this script carry synthetic marker strings by design
    "tests/unit/test_premerge_hygiene.py": "hygiene tests contain synthetic marker strings",
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

_AUTHOR_IDENTITY_PATTERNS = [
    re.compile(r"claude", re.IGNORECASE),
    re.compile(r"anthropic\.com", re.IGNORECASE),
    re.compile(r"openai\.com", re.IGNORECASE),
    re.compile(r"copilot", re.IGNORECASE),
]


@dataclass(frozen=True)
class Hit:
    source: str
    line: str
    pattern: str


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


def _commit_identities(base: str) -> str:
    return _run_git(["log", "--format=%H%x09%an%x09%ae%x09%cn%x09%ce", f"{base}..HEAD"])


def _scan_text(text: str, source: str) -> list[Hit]:
    hits: list[Hit] = []
    for line in text.splitlines():
        for pattern in _MARKER_PATTERNS:
            if pattern.search(line):
                hits.append(Hit(source=source, line=line.strip(), pattern=pattern.pattern))
                break
    return hits


def _scan_author_identities(base: str) -> list[Hit]:
    hits: list[Hit] = []
    for line in _commit_identities(base).splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 5:
            hits.append(
                Hit(
                    source="commit-metadata",
                    line=f"malformed git log identity row: {line.strip()}",
                    pattern="git log --format=%H%x09%an%x09%ae%x09%cn%x09%ce",
                )
            )
            continue

        sha, author_name, author_email, committer_name, committer_email = parts
        identities = (
            ("author", author_name, author_email),
            ("committer", committer_name, committer_email),
        )
        for role, name, email in identities:
            rendered = f"{name} <{email}>"
            for pattern in _AUTHOR_IDENTITY_PATTERNS:
                if pattern.search(name) or pattern.search(email):
                    hits.append(
                        Hit(
                            source=f"commit {sha[:8]} {role} identity",
                            line=rendered,
                            pattern=pattern.pattern,
                        )
                    )
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

    hits: list[Hit] = []

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
    hits.extend(_scan_author_identities(args.base))

    if not hits:
        print(f"premerge hygiene: clean against {args.base}")
        return 0

    print(f"premerge hygiene: {len(hits)} marker hit(s) against {args.base}")
    for hit in hits:
        print(f"  {hit.source}: {hit.line}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

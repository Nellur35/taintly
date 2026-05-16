#!/usr/bin/env python3
"""Whole-tree scan for internal-narrative leakage.

Complement to ``check_premerge_hygiene.py``.  Hygiene checks the
*diff*; this one checks the *tree*.  It catches patterns that read as
internal log-fragments left in a public-tool codebase:

  * ``Phase 1`` / ``Phase 8 iter-4`` — internal milestone names that
    git history already records by date.
  * ``iter-6`` / ``iter 4`` — internal iteration names.
  * ``PR #104`` — internal PR refs in comments; the comment outlives
    the PR's relevance, and the rationale belongs in the commit
    message anyway.
  * ``F1 delta``, ``sunk cost``, ``decision-log entry``,
    ``phone-review`` — internal-deliberation jargon.

Why: a reader who lands in a rule file shouldn't have to decode
internal-roadmap shorthand to follow what the code does.  The rule's
behaviour, the threat shape, and the precision tradeoffs are
load-bearing; the milestone label that produced them is not.

Scope: walks every tracked file in the repo (``git ls-files``).
Honours the ``public-sync-exclude.txt`` list so lab-only files
(``docs/lab/``, ``tests/lab/``, etc.) are exempt — internal narrative
is fine there.

Exits 0 if clean, 1 with the line-by-line list if hits found.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_NARRATIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bPhase\s+\d+(?:\.\d+)?\b"), "Phase-N milestone label"),
    (re.compile(r"\biter[- ]?\d+\b(?!\w)"), "iter-N iteration label"),
    (re.compile(r"\bPR\s*#\s*\d+\b"), "internal PR ref"),
    (re.compile(r"\bF1\s*delta\b", re.IGNORECASE), "internal F1-delta metric"),
    (re.compile(r"\bsunk\s+cost\b", re.IGNORECASE), "internal sunk-cost framing"),
    (re.compile(r"\bdecision[- ]log\s+entry\b", re.IGNORECASE), "internal decision-log ref"),
    (re.compile(r"\bphone[- ]review\b", re.IGNORECASE), "internal phone-review label"),
    (re.compile(r"\bphone[- ]branch\b", re.IGNORECASE), "internal phone-branch label"),
]

# Files whose subject legitimately includes these terms.  Add a one-
# line reason for each entry.
_ALLOWLISTED_PATHS: dict[str, str] = {
    # this script itself defines the marker regexes
    "scripts/check_internal_narrative.py": "regex source",
    # tests for this script carry synthetic marker strings by design
    "tests/unit/test_internal_narrative.py": "test fixtures contain synthetic markers",
}

# Binary / generated file extensions that we skip entirely.
_SKIP_SUFFIXES: tuple[str, ...] = (
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
    ".pdf", ".zip", ".gz", ".tar",
)


@dataclass(frozen=True)
class Hit:
    path: str
    line_no: int
    line: str
    pattern_name: str


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _tracked_paths() -> list[str]:
    out = subprocess.check_output(["git", "ls-files"], text=True, encoding="utf-8")
    return [line.strip() for line in out.splitlines() if line.strip()]


def _manifest_paths() -> list[str]:
    """Read ``public-sync-manifest.txt`` (lab-only file).  Returns the
    list of paths permitted to publish to public.  Empty list if the
    manifest is absent (i.e., the script is running from the public
    clone where the manifest doesn't exist)."""
    manifest_file = _repo_root() / "public-sync-manifest.txt"
    if not manifest_file.exists():
        return []
    entries: list[str] = []
    for raw in manifest_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line.rstrip("/"))
    return entries


def _manifest_tracked_paths() -> list[str]:
    """Expand manifest entries into actual tracked files.  Each manifest
    entry is either a file (use as-is) or a directory (walk and emit
    every tracked file inside)."""
    manifest = _manifest_paths()
    if not manifest:
        return _tracked_paths()
    root = _repo_root()
    out: list[str] = []
    all_tracked = set(_tracked_paths())
    for entry in manifest:
        entry_path = root / entry
        if not entry_path.exists():
            continue
        if entry_path.is_file():
            if entry in all_tracked:
                out.append(entry)
            continue
        for tracked in all_tracked:
            if tracked == entry or tracked.startswith(f"{entry}/"):
                out.append(tracked)
    return out


def _load_excluded() -> list[str]:
    exclude_file = _repo_root() / "public-sync-exclude.txt"
    if not exclude_file.exists():
        return []
    entries: list[str] = []
    for raw in exclude_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line.rstrip("/"))
    return entries


def _is_excluded(path: str, excludes: list[str]) -> bool:
    return any(path == e or path.startswith(f"{e}/") for e in excludes)


def _scan_file(path: Path, rel: str) -> list[Hit]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    hits: list[Hit] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern, name in _NARRATIVE_PATTERNS:
            if pattern.search(line):
                hits.append(Hit(path=rel, line_no=line_no, line=line.rstrip(), pattern_name=name))
                break
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--all-tracked",
        action="store_true",
        help=(
            "Scan every tracked file (default in the public clone where "
            "no manifest exists).  In the lab clone, the default is to "
            "scan only files the manifest publishes to public, since "
            "internal narrative is fine in lab-only files."
        ),
    )
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    root = _repo_root()
    if not (root / ".git").exists():
        sys.stderr.write("not a git repository\n")
        return 2

    excludes = _load_excluded()
    hits: list[Hit] = []

    paths = _tracked_paths() if args.all_tracked else _manifest_tracked_paths()

    for rel in paths:
        if rel in _ALLOWLISTED_PATHS:
            continue
        if _is_excluded(rel, excludes):
            continue
        if rel.endswith(_SKIP_SUFFIXES):
            continue
        full = root / rel
        if not full.is_file():
            continue
        hits.extend(_scan_file(full, rel))

    if not hits:
        print("internal-narrative scan: clean")
        return 0

    by_path: dict[str, list[Hit]] = {}
    for h in hits:
        by_path.setdefault(h.path, []).append(h)

    print(f"internal-narrative scan: {len(hits)} hit(s) across {len(by_path)} file(s)")
    print()
    for path in sorted(by_path):
        print(f"{path}")
        for h in by_path[path]:
            print(f"  {h.line_no}: [{h.pattern_name}] {h.line.strip()}")
        print()
    return 1


if __name__ == "__main__":
    sys.exit(main())

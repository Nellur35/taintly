#!/usr/bin/env python3
"""Regenerate README.md's AUTOGEN:summary and AUTOGEN:coverage blocks.

Run from the repo root after adding/removing/renumbering rules:

    python scripts/update_readme_coverage.py

CI runs this in --check mode; the build fails if the README is out of
sync with the rule pack.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

# Allow running the script without ``pip install -e .`` — putting the
# repo root on sys.path here means CI / contributors don't have to
# install the package just to refresh the README numbers.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Categories listed in the README in row order.  Adding a new
# category means editing the README structure itself, which is a
# separate decision from "refresh the numbers."
_CATEGORIES = [
    ("SEC-1 — Insufficient Flow Control",        "SEC1"),
    ("SEC-2 — Inadequate IAM",                   "SEC2"),
    ("SEC-3 — Dependency Chain Abuse",           "SEC3"),
    ("SEC-4 — Poisoned Pipeline Execution",      "SEC4"),
    ("SEC-5 — Insufficient PBAC",                "SEC5"),
    ("SEC-6 — Insufficient Credential Hygiene",  "SEC6"),
    ("SEC-7 — Insecure System Configuration",    "SEC7"),
    ("SEC-8 — Ungoverned 3rd Party Services",    "SEC8"),
    ("SEC-9 — Improper Artifact Integrity",      "SEC9"),
    ("SEC-10 — Insufficient Logging",            "SEC10"),
    ("AI / ML",                                  "AI"),
    ("TAINT — Multi-stage taint flows",          "TAINT"),
]


def _platform_for(rule_id: str) -> str:
    if "-GH-" in rule_id:
        return "GitHub"
    if "-GL-" in rule_id:
        return "GitLab"
    if "-JK-" in rule_id:
        return "Jenkins"
    return "Other"


def _category_prefix(rule_id: str) -> str:
    return rule_id.split("-", 1)[0]


def _count_rules() -> tuple[int, dict[str, dict[str, int]]]:
    """Return (total file-based rule count, per-category × per-platform counts)."""
    from taintly.rules.registry import load_all_rules

    rules = load_all_rules()
    table: dict[str, Counter[str]] = {}
    for r in rules:
        prefix = _category_prefix(r.id)
        plat = _platform_for(r.id)
        table.setdefault(prefix, Counter())[plat] += 1
    return len(rules), {k: dict(v) for k, v in table.items()}


def _count_platform_checks() -> int:
    """Count platform-posture rule IDs across the platform_checks files.

    Both ``PLAT-*`` and ``ACCT-*`` prefixes are platform-posture rules
    — distinct categories the rule authors chose for repo-level vs
    account-level platform settings.
    """
    pattern = re.compile(r'"((?:PLAT|ACCT)-[A-Z]+-\d+)"')
    seen: set[str] = set()
    for plat in ("github", "gitlab", "jenkins"):
        path = ROOT / "taintly" / "platform" / f"{plat}_checks.py"
        if not path.exists():
            continue
        for match in pattern.finditer(path.read_text()):
            seen.add(match.group(1))
    return len(seen)


def render_summary(total_file: int, total_plat: int) -> str:
    return (
        f"{total_file} file-based rules and {total_plat} platform-posture "
        f"checks across GitHub Actions, GitLab CI, and Jenkins. "
        f"Includes a dedicated AI / ML category for workflows that load "
        f"models or run AI coding agents."
    )


def render_coverage_table(table: dict[str, dict[str, int]]) -> str:
    lines = [
        "| Category | GitHub | GitLab | Jenkins |",
        "|----------|--------|--------|---------|",
    ]
    for label, prefix in _CATEGORIES:
        row = table.get(prefix, {})
        lines.append(
            f"| {label} | {row.get('GitHub', 0)} | "
            f"{row.get('GitLab', 0)} | {row.get('Jenkins', 0)} |"
        )
    return "\n".join(lines)


def _replace_block(text: str, marker: str, new_content: str) -> str:
    open_tag = f"<!-- AUTOGEN:{marker} -->"
    close_tag = f"<!-- /AUTOGEN:{marker} -->"
    pattern = re.compile(
        rf"({re.escape(open_tag)})\s*\n.*?\n\s*({re.escape(close_tag)})",
        re.DOTALL,
    )
    replacement = f"\\1\n{new_content}\n\\2"
    new_text, n = pattern.subn(replacement, text)
    if n != 1:
        sys.exit(
            f"FAIL: expected exactly one {open_tag}...{close_tag} block, "
            f"found {n}"
        )
    return new_text


def _replace_postscript(text: str, total_plat: int) -> str:
    """Update the standalone ``Plus N platform-posture rules`` line that
    follows the autogen block.  Hand-maintained in the same edit so the
    two numbers don't drift.
    """
    pattern = re.compile(
        r"^Plus\s+\d+\s+platform-posture rules in `--platform-audit` mode\.$",
        re.MULTILINE,
    )
    replacement = f"Plus {total_plat} platform-posture rules in `--platform-audit` mode."
    new_text, n = pattern.subn(replacement, text)
    if n != 1:
        # Postscript line is optional — don't fail if absent, just skip.
        return text
    return new_text


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if README is out of sync; don't write.",
    )
    args = p.parse_args()

    total_file, table = _count_rules()
    total_plat = _count_platform_checks()
    summary = render_summary(total_file, total_plat)
    coverage = render_coverage_table(table)

    current = README.read_text()
    updated = _replace_block(current, "summary", summary)
    updated = _replace_block(updated, "coverage", coverage)
    updated = _replace_postscript(updated, total_plat)

    if args.check:
        if updated != current:
            sys.exit(
                "FAIL: README coverage numbers are out of sync.\n"
                "Run `python scripts/update_readme_coverage.py` and "
                "commit the result."
            )
        print("OK: README in sync")
        return 0

    if updated != current:
        README.write_text(updated)
        print("Updated README.md AUTOGEN blocks")
    else:
        print("README already in sync; no changes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

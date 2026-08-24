#!/usr/bin/env python3
"""Promote a fixed evasion to a detection test.

When a rule is hardened to detect a previously-documented bypass, the
fixture should move out of ``tests/evasion/`` and into
``tests/fixtures/<platform>/vulnerable/`` with a detection test added
to the integration suite.

This script automates the mechanical part of that promotion:

  1. Move ``tests/evasion/<filename>`` to
     ``tests/fixtures/<platform>/vulnerable/<filename>``.
  2. Print the diff stub for ``tests/integration/test_all_rules_clean.py``
     showing the new ``(fixture_path, [RULE_ID], [])`` entry to add.
  3. Print the line to remove from ``tests/evasion/test_evasion.py``.

It does NOT auto-edit the Python files because the parametrize lists
have rationale comments and per-row formatting choices the script
shouldn't second-guess.

Usage:

  python scripts/promote_evasion.py FILENAME RULE_ID [--platform PLATFORM]

Examples:

  python scripts/promote_evasion.py base64_shell.yml SEC6-GH-007
  python scripts/promote_evasion.py groovy_slashy.Jenkinsfile SEC4-JK-001 --platform jenkins
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[1]
_EVASION_DIR = _REPO_ROOT / "tests" / "evasion"
_FIXTURES_DIR = _REPO_ROOT / "tests" / "fixtures"


def _infer_platform(filename: str) -> str:
    """Best-effort platform inference from the filename. Override with
    --platform when the heuristic is wrong."""
    if filename.endswith(".Jenkinsfile") or "jenkins" in filename.lower():
        return "jenkins"
    if "gitlab" in filename.lower() or "_gl_" in filename.lower():
        return "gitlab"
    if "buildspec" in filename.lower() or "_cb_" in filename.lower():
        return "codebuild"
    return "github"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("filename", help="evasion fixture filename")
    parser.add_argument("rule_id", help="rule ID that now detects the bypass")
    parser.add_argument(
        "--platform",
        choices=("github", "gitlab", "jenkins", "codebuild"),
        help="override the inferred platform",
    )
    args = parser.parse_args(argv)

    src = _EVASION_DIR / args.filename
    if not src.exists():
        print(f"ERROR: {src} does not exist", file=sys.stderr)
        return 2

    platform = args.platform or _infer_platform(args.filename)
    dst_dir = _FIXTURES_DIR / platform / "vulnerable"
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / args.filename

    if dst.exists():
        print(f"ERROR: {dst} already exists; refusing to overwrite", file=sys.stderr)
        return 2

    shutil.move(str(src), str(dst))
    print(f"Moved: {src} -> {dst}")

    # Construct the relative fixture path the way test_all_rules_clean
    # parametrize expects (POSIX, relative to tests/fixtures).
    rel = dst.relative_to(_FIXTURES_DIR).as_posix()

    print()
    print("Next steps (manual):")
    print()
    print(
        f"  1. Add to tests/integration/test_all_rules_clean.py "
        f"under the {platform} section:"
    )
    print(f'        ("{rel}", ["{args.rule_id}"], []),')
    print()
    print(f"  2. Remove the matching entry from tests/evasion/test_evasion.py")
    print(f"     (the EvasionEntry whose filename={args.filename!r}).")
    print()
    print(
        "  3. Run tests/integration/ and tests/evasion/ to confirm the "
        "promotion is clean."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

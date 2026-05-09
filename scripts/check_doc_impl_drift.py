#!/usr/bin/env python3
"""Cross-cutting doc/impl drift gate (audit cross-cutting A).

Several documented contracts in this repo silently drifted from the
code that was supposed to enforce them — the audit found four:

  * Playground README documents ``fix_invariants`` schema; harness
    ignored it (chunk 6.1, now fixed).
  * Playground README mentions ``api-fixtures/gl/``; doesn't exist
    (chunk 6.3).
  * Project README claimed ``100% mutation kill rate``; allowlist had
    74 entries (chunk 5.1, now reconciled).
  * pyproject documents per-module coverage targets; CI didn't enforce
    them (chunk 1.6, now enforced).

This script catches the same shape of drift on future PRs. It looks
for prose-described contracts in READMEs and asserts each is wired
to a runtime check or test. It's a heuristic — false positives are
OK (the script prints warnings the maintainer can ignore); false
negatives are the real cost (a documented contract that's
unenforced).

Specific checks:

  1. ``fix_invariants`` keys named in tests/playground/README.md must
     be referenced in tests/playground/test_playground.py.
  2. Every ``--cov-fail-under`` value mentioned in pyproject.toml
     must match the value in .github/workflows/ci.yml.
  3. Every ``api-fixtures/<platform>/`` path mentioned in
     tests/playground/README.md must exist as a directory.

Usage:
  python scripts/check_doc_impl_drift.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[1]


def _check_fix_invariants_keys() -> list[str]:
    """The README documents fix_invariants keys; the harness must
    actually read them."""
    readme = _REPO_ROOT / "tests" / "playground" / "README.md"
    harness = _REPO_ROOT / "tests" / "playground" / "test_playground.py"
    if not (readme.exists() and harness.exists()):
        return []

    readme_text = readme.read_text(encoding="utf-8")
    harness_text = harness.read_text(encoding="utf-8")

    # Parse keys out of the README's documented JSON example
    in_block = False
    keys: list[str] = []
    for line in readme_text.splitlines():
        if "fix_invariants" in line and "{" in line:
            in_block = True
            continue
        if in_block:
            m = re.search(r'"([a-z_]+)"\s*:', line)
            if m and m.group(1) != "fix_invariants":
                keys.append(m.group(1))
            if "}" in line:
                break

    issues = []
    for key in keys:
        if key not in harness_text:
            issues.append(
                f"playground README documents fix_invariants.{key} but "
                f"test_playground.py never references the literal "
                f"string {key!r} — drift between schema and harness."
            )
    return issues


def _check_cov_fail_under_in_sync() -> list[str]:
    """pyproject's fail_under and CI's --cov-fail-under must match."""
    py = (_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    ci_path = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
    if not ci_path.exists():
        return []
    ci = ci_path.read_text(encoding="utf-8")

    py_match = re.search(r"^fail_under\s*=\s*(\d+)", py, re.MULTILINE)
    ci_matches = re.findall(r"--cov-fail-under=(\d+)", ci)

    issues = []
    if py_match and ci_matches:
        py_val = py_match.group(1)
        for ci_val in ci_matches:
            if py_val != ci_val:
                issues.append(
                    f"pyproject.toml fail_under={py_val} but CI uses "
                    f"--cov-fail-under={ci_val} — gates will diverge."
                )
    return issues


def _check_api_fixture_paths_exist() -> list[str]:
    """Every api-fixtures platform mentioned in the README must exist
    as a directory. The README documents a layout block of the form

        api-fixtures/
          gh/<endpoint-slug>.json
          gl/<endpoint-slug>.json

    Each child directory listed under that block must be present."""
    readme = _REPO_ROOT / "tests" / "playground" / "README.md"
    if not readme.exists():
        return []
    lines = readme.read_text(encoding="utf-8").splitlines()
    issues = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("api-fixtures/"):
            in_block = True
            continue
        if in_block:
            # Lines inside the layout block are indented; first
            # non-indented or empty line ends the block.
            if not line.startswith(" ") or not stripped:
                in_block = False
                continue
            m = re.match(r"([a-z]+)/<", stripped)
            if not m:
                continue
            platform = m.group(1)
            path = _REPO_ROOT / "tests" / "playground" / "api-fixtures" / platform
            if not path.exists():
                issues.append(
                    f"playground README documents api-fixtures/{platform}/ "
                    f"but {path.relative_to(_REPO_ROOT)} does not exist — "
                    f"record the fixtures or remove the README mention."
                )
    return issues


def main() -> int:
    issues: list[str] = []
    issues.extend(_check_fix_invariants_keys())
    issues.extend(_check_cov_fail_under_in_sync())
    issues.extend(_check_api_fixture_paths_exist())

    if issues:
        print("Doc/impl drift detected:", file=sys.stderr)
        for i in issues:
            print(f"  - {i}", file=sys.stderr)
        return 1

    print("OK: no doc/impl drift detected by current checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Allow-list gate against private-R&D-artifact leaks.

The public taintly repo is published from a separate lab repo via a
manifest of paths permitted to publish.  That manifest is the first
defence — but it lives in the lab, and history shows two ways it can
fail:

  1. the manifest can over-list (decision-log files, retrospectives,
     internal-review notes get whitelisted by accident); and
  2. files can land in the public repo *outside* the manifest entirely
     via direct edits or older publish paths.

This script is the second defence.  It runs from the public repo on
every PR/push.  It walks every tracked path and rejects anything that
isn't in the allow-list below.

Adding a new file is intentionally friction-y: you must edit the
allow-list, which forces a conscious decision about whether the file
belongs in the public-facing tool repo at all.

Usage: ``python scripts/check_public_no_leaks.py``.  Exits 0 on
clean, 1 with the list of disallowed paths on a leak.
"""

from __future__ import annotations

import subprocess
import sys

# Specific files allowed at any path.  Add a one-line note for each so
# the *why* is captured next to the entry.
ALLOWED_FILES: dict[str, str] = {
    # Top-level project metadata
    ".gitignore": "project gitignore",
    ".gitleaks.toml": "secret-scanning config",
    ".pre-commit-hooks.yaml": "pre-commit hooks manifest",
    "CHANGELOG.md": "user-facing changelog",
    "CONTRIBUTING.md": "user-facing contribution guide",
    "LICENSE": "license",
    "README.md": "user-facing readme",
    "SECURITY.md": "security policy",
    "action.yml": "GitHub Action manifest",
    "pyproject.toml": "Python project metadata",
    "requirements-dev.in": "dev/CI toolchain direct pins (source for the hashed lock)",
    "requirements-dev.lock": "hash-pinned dev/CI toolchain lock (uv-generated)",
    # User-facing docs (explicit allow-list — docs/ is NOT a free directory)
    "docs/AI_TRIAGE.md": "user-facing AI-triage guide",
    "docs/CO_FIRES.md": "user-facing co-fire matrix",
    "docs/CONTEXT.md": "user-facing context-file format reference",
    "docs/JENKINSFILE_READER_SCOPE.md": "user-facing parser-scope contract for the optional [jenkins-structural] extra",
    "docs/JENKINS_POSTURE_TESTING.md": "user-facing Jenkins runbook",
    "docs/SCORING.md": "user-facing scoring model",
    "docs/STRUCTURAL_READER_SCOPE.md": "user-facing parser-scope contract",
    # Ephemeral dev fixture (kept minimal)
    "dev/jenkins-test/docker-compose.yml": "Jenkins test-fixture compose file",
}

# Directories that may contain any number of files.  Anything outside
# these prefixes (and outside ALLOWED_FILES) is rejected.
ALLOWED_PREFIXES: tuple[str, ...] = (
    ".github/",
    "scripts/",
    "taintly/",
    "tests/",
)

# Specifically-banned prefixes — louder error message when these show
# up.  Catches the known "AI babble" leak shapes by name so a future
# author sees the exact reason it bounced.
BANNED_PREFIXES: dict[str, str] = {
    "docs/decisions/": (
        "decision-log / ADR / retrospective notes belong in the lab repo "
        "under docs/lab/decisions/, not in the public tool repo"
    ),
    "docs/lab/": (
        "anything under docs/lab/ is lab-private by definition"
    ),
}


def _tracked_paths() -> list[str]:
    out = subprocess.check_output(
        ["git", "ls-files"], text=True, encoding="utf-8"
    )
    return [line.strip() for line in out.splitlines() if line.strip()]


def _classify(path: str) -> tuple[str, str] | None:
    """Return ``(kind, reason)`` if ``path`` is disallowed, else ``None``."""
    for banned, reason in BANNED_PREFIXES.items():
        if path.startswith(banned):
            return ("banned", reason)
    if path in ALLOWED_FILES:
        return None
    for prefix in ALLOWED_PREFIXES:
        if path.startswith(prefix):
            return None
    return ("not in allow-list", "no rule covers this path")


def main() -> int:
    leaks: list[tuple[str, str, str]] = []
    for path in _tracked_paths():
        verdict = _classify(path)
        if verdict is not None:
            kind, reason = verdict
            leaks.append((path, kind, reason))

    if not leaks:
        print("OK: no disallowed paths in public taintly")
        return 0

    print("FAIL: disallowed paths in public taintly:")
    for path, kind, reason in leaks:
        print(f"  - {path}  [{kind}] {reason}")
    print()
    print(
        "To fix: either remove the path, or — if it is genuinely "
        "user-facing tool content — add it to ALLOWED_FILES (or extend "
        "ALLOWED_PREFIXES) in scripts/check_public_no_leaks.py with a "
        "one-line rationale.  Private R&D artifacts (ADRs, retros, "
        "internal-review notes, design rationale) belong in the lab repo, "
        "not here."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

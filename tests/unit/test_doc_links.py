"""Doc-link integrity gate — methodology testing-domain 7.4 (Link Validation).

Every *local* Markdown link in a tracked doc must resolve to a file that
exists.  External ``http(s)`` / ``mailto`` links are intentionally NOT
checked (network-dependent → flaky); this gate covers the deterministic,
high-value case a shareable repo actually suffers: a relative link to a
doc/file that was renamed, moved, or typo'd, silently rotting in the
README while CI stays green.

Covers inline links ``[text](target)`` and images ``![alt](target)``.
Reference-style links (``[text][ref]``) are out of scope for now.

Scope: the docs that ship / are user-facing. Lab-internal R&D notes
(``docs/lab/``, ``docs/LAB.md``) are excluded — they never reach users,
and they don't exist in the public repo at all (``docs/lab`` is a publish
exclude), so this same test guards the public README/docs there and the
shipped docs here. Rot in the lab notes is surfaced but not gated.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

# [text](target) and ![alt](target) — the target is group 1.
_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_SKIP_PREFIXES = ("http://", "https://", "mailto:", "tel:", "#", "<")


# Lab-internal R&D docs: never published, not user-facing, excluded from the
# gate (their rot is reported, not blocking). Kept in sync with the intent of
# public-sync-exclude.txt's docs/lab entry.
_EXCLUDED_PREFIXES = ("docs/lab/",)
_EXCLUDED_FILES = ("docs/LAB.md",)


def _is_shipped_doc(rel: str) -> bool:
    return not rel.startswith(_EXCLUDED_PREFIXES) and rel not in _EXCLUDED_FILES


def _tracked_markdown() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    return [
        ROOT / line
        for line in out.stdout.splitlines()
        if line.strip() and _is_shipped_doc(line.strip())
    ]


def _local_links(md: Path):
    """Yield (lineno, raw_target) for local links, skipping fenced code."""
    in_fence = False
    for lineno, line in enumerate(
        md.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in _LINK_RE.finditer(line):
            # Drop an optional title: [x](path "Title") / [x](path 'Title').
            target = match.group(1).strip().split(" ", 1)[0].split("\t", 1)[0]
            if not target or target.startswith(_SKIP_PREFIXES):
                continue
            yield lineno, target


def test_local_markdown_links_resolve():
    tracked = _tracked_markdown()
    assert tracked, "expected tracked Markdown files (is this a git checkout?)"
    broken: list[str] = []
    for md in tracked:
        for lineno, target in _local_links(md):
            path_part = target.split("#", 1)[0]  # drop any #anchor fragment
            if not path_part:  # pure in-page anchor — handled by _SKIP_PREFIXES
                continue
            if not (md.parent / path_part).resolve().exists():
                broken.append(f"{md.relative_to(ROOT).as_posix()}:{lineno} -> {target}")
    assert not broken, "Broken local doc links (target does not exist):\n  " + "\n  ".join(broken)

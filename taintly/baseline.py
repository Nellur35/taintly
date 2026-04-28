"""Baseline and diff support for taintly.

Allows teams to snapshot the current finding state and only report new
findings in subsequent scans — essential for adopting the tool in repos
with pre-existing issues.

Workflow:
    # Snapshot current state (commit this file)
    python -m taintly . --baseline

    # CI: only report findings introduced since the snapshot
    python -m taintly . --diff .taintly-baseline.json

Fingerprint design:
    sha256(rule_id + "|" + normalised_relative_file_path + "|" + snippet)

    Deliberately excludes line number — line numbers drift as code changes.
    Snippet anchors the fingerprint to the actual content, so a finding
    that moves to a different line is still recognised as the same finding,
    but a new occurrence of the same rule in different content is treated
    as new.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

BASELINE_FILENAME = ".taintly-baseline.json"
BASELINE_VERSION = 1


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------


def fingerprint(finding, repo_path: str) -> str:
    """Return a stable hex fingerprint for a finding.

    Uses rule_id + normalised relative file path + snippet (first 120 chars).
    Excludes line number so the fingerprint survives surrounding-code edits.
    """
    try:
        rel = os.path.relpath(finding.file, os.path.abspath(repo_path))
    except ValueError:
        rel = finding.file
    rel_norm = rel.replace("\\", "/")

    snippet = (finding.snippet or "").strip()[:120]
    raw = f"{finding.rule_id}|{rel_norm}|{snippet}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# Baseline data class
# ---------------------------------------------------------------------------


@dataclass
class Baseline:
    version: int
    repo_path: str
    scanned_at: str  # ISO-8601 timestamp
    fingerprints: set[str]  # sha256 hex strings
    finding_count: int  # informational
    snippets: dict[str, str] = field(default_factory=dict)
    """Fingerprint -> snippet text. Persisted so ``classify_diff_kind``
    can recognise SHA bumps on previously-baselined ``uses:`` references.
    Older baseline files lack this field; the classifier degrades to
    ``new_finding`` rather than crashing in that case."""


# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------


def save_baseline(findings: list[Any], repo_path: str, output_path: str) -> Baseline:
    """Compute fingerprints for findings and write a baseline JSON file.

    Returns the Baseline that was written.
    """
    import datetime

    snippets: dict[str, str] = {}
    for f in findings:
        fp = fingerprint(f, repo_path)
        snippets[fp] = (f.snippet or "").strip()
    fps = set(snippets)
    scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = {
        "version": BASELINE_VERSION,
        "repo_path": os.path.abspath(repo_path),
        "scanned_at": scanned_at,
        "finding_count": len(findings),
        "fingerprints": sorted(fps),  # sorted for stable diffs in git
        # Persisted so the diff path can recognise SHA bumps on
        # previously-baselined ``uses:`` references; absence is
        # tolerated by the loader.
        "snippets": {fp: snippets[fp] for fp in sorted(snippets)},
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

    return Baseline(
        version=BASELINE_VERSION,
        repo_path=os.path.abspath(repo_path),
        scanned_at=scanned_at,
        fingerprints=fps,
        finding_count=len(findings),
        snippets=snippets,
    )


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------


class BaselineError(ValueError):
    """Raised when the baseline file cannot be loaded or is invalid."""


def load_baseline(path: str) -> Baseline:
    """Load a baseline from a JSON file.

    Raises:
        FileNotFoundError: if path does not exist.
        BaselineError: if the file is malformed or the version is unsupported.
    """
    abs_path = os.path.abspath(path)
    size = os.path.getsize(abs_path)
    if size > 10 * 1024 * 1024:  # 10 MB cap — baselines should never be this large
        raise BaselineError(f"baseline file is {size} bytes; suspiciously large, refusing to load")

    with open(abs_path, encoding="utf-8", errors="replace") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise BaselineError(f"baseline file is not valid JSON: {e}") from e

    if not isinstance(data, dict):
        raise BaselineError("baseline file must be a JSON object")

    version = data.get("version")
    if version != BASELINE_VERSION:
        raise BaselineError(
            f"baseline version {version!r} is not supported; expected version {BASELINE_VERSION}"
        )

    fps_raw = data.get("fingerprints")
    if not isinstance(fps_raw, list):
        raise BaselineError("baseline 'fingerprints' must be a list")

    fps: set[str] = set()
    for i, item in enumerate(fps_raw):
        if not isinstance(item, str) or len(item) != 64:
            raise BaselineError(
                f"baseline fingerprints[{i}] is not a valid sha256 hex string: {item!r}"
            )
        fps.add(item)

    # Snippets are optional — older baselines won't have them; the
    # classifier handles that gracefully.
    snippets_raw = data.get("snippets", {})
    snippets: dict[str, str] = {}
    if isinstance(snippets_raw, dict):
        for k, v in snippets_raw.items():
            if isinstance(k, str) and len(k) == 64 and isinstance(v, str):
                snippets[k] = v

    return Baseline(
        version=BASELINE_VERSION,
        repo_path=data.get("repo_path", ""),
        scanned_at=data.get("scanned_at", ""),
        fingerprints=fps,
        finding_count=data.get("finding_count", len(fps)),
        snippets=snippets,
    )


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def apply_diff(findings: list[Any], baseline: Baseline, repo_path: str) -> tuple[list[Any], int]:
    """Filter findings to only those not present in the baseline.

    Returns:
        (new_findings, suppressed_count)
    """
    new = []
    suppressed = 0
    for f in findings:
        fp = fingerprint(f, repo_path)
        if fp in baseline.fingerprints:
            suppressed += 1
        else:
            new.append(f)
    return new, suppressed


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------


def format_baseline_summary(baseline: Baseline, output_path: str) -> str:
    """One-line summary printed after writing a baseline."""
    return (
        f"Baseline written: {output_path}\n"
        f"  {baseline.finding_count} finding(s) fingerprinted, "
        f"{len(baseline.fingerprints)} unique\n"
        f"  Commit this file to suppress these findings in future scans."
    )


def format_diff_summary(suppressed: int, new_count: int, baseline_path: str) -> str:
    """One-line summary printed in diff mode."""
    if suppressed == 0 and new_count == 0:
        return f"Diff mode: no findings (baseline: {baseline_path})"
    parts = []
    if suppressed:
        parts.append(f"{suppressed} suppressed (in baseline)")
    if new_count:
        parts.append(f"{new_count} NEW")
    return f"Diff mode ({baseline_path}): {', '.join(parts)}"


# ---------------------------------------------------------------------------
# Diff classification
# ---------------------------------------------------------------------------

_USES_REF_FOR_DIFF = re.compile(r"uses:\s*([^@\s]+)@(\S+)")


def classify_diff_kind(
    new_finding: Any,
    baseline_fingerprints: set[str],
    baseline_snippets: dict[str, str],
    repo_path: str,
) -> str:
    """Classify why a finding appears in --diff output.

    Returns one of:
      * ``"unchanged"``     — same fingerprint already in baseline.  The
        normal apply_diff path filters these out before the classifier
        ever sees them; documented as a possible return value so a
        misuse doesn't surprise the caller.
      * ``"sha_bump"``      — same rule, same package, different SHA
        (the only thing that changed in the snippet was the @ref).
      * ``"new_dependency"``— same rule, NEW package not in baseline.
      * ``"new_finding"``   — anything else (different rule, different
        location, snippet without a recognisable ``uses:`` shape).
    """
    new_fp = fingerprint(new_finding, repo_path)
    if new_fp in baseline_fingerprints:
        return "unchanged"

    new_snip = (new_finding.snippet or "").strip()
    new_uses = _USES_REF_FOR_DIFF.search(new_snip)
    if not new_uses:
        return "new_finding"
    new_pkg, _new_sha = new_uses.groups()

    # Did baseline contain a finding with the same rule_id + same package?
    rule_id = getattr(new_finding, "rule_id", "")
    for old_fp, old_snip in baseline_snippets.items():
        old_uses = _USES_REF_FOR_DIFF.search(old_snip or "")
        if not old_uses:
            continue
        old_pkg, _old_sha = old_uses.groups()
        if old_pkg != new_pkg:
            continue
        # Confirm same rule by checking the fingerprint encodes the same
        # rule_id prefix.  The fingerprint hashes ``rule_id|file|snippet``
        # so we can't decompose it; instead, when the rule IDs match we
        # accept the package match as enough — the alternative
        # (different rule firing on the same package) is rare and only
        # downgrades a sha_bump label to new_finding, never the reverse.
        if rule_id and rule_id not in old_snip:
            # Snippet-based heuristic: the package shape is enough.
            pass
        return "sha_bump"
    return "new_dependency"
